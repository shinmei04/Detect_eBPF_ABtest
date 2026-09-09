"""Offline paired evaluation of the existing window-level reproduction detector.

Packet CSV timestamps must be relative to an explicitly recorded run origin.
Training is separate and benign; neither labels nor future packets affect EMA.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import subprocess

import numpy as np
import pandas as pd

from .paper_reproduction_detector import PAPER_FEATURES, PaperDetectorConfig, PaperReproductionDetector, compute_paper_window_features
from .temporal_features import METHODS, TemporalConfig, describe_window


def grid_count(seconds: float, bucket_sec: float, name: str) -> int:
    if not np.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"{name} must be finite and positive")
    value = seconds / bucket_sec
    if not np.isclose(value, round(value), atol=1e-8, rtol=0):
        raise ValueError(f"{name} must be an exact multiple of bucket width")
    return int(round(value))


def validate_intervals(intervals: list, duration: float) -> list[tuple[float, float]]:
    result = []
    previous_end = -1.0
    for interval in intervals:
        start, end = map(float, interval)
        if not np.isfinite([start, end]).all() or not 0 <= start < end <= duration or start <= previous_end:
            raise ValueError("attack intervals must be finite, ordered, disjoint and within run duration")
        result.append((start, end))
        previous_end = end
    return result


def read_packets(path: Path, duration: float) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype={"flow_id": str})
    columns = ["timestamp_sec", "packet_size", "flow_id"]
    if not set(columns) <= set(frame):
        raise ValueError(f"{path}: require {columns}")
    frame = frame[columns].copy()
    for name in columns[:2]:
        frame[name] = pd.to_numeric(frame[name], errors="raise")
    if not np.isfinite(frame[columns[:2]].to_numpy(dtype=float)).all() or frame.isna().any().any():
        raise ValueError(f"{path}: missing/nonfinite packet values")
    if ((frame.timestamp_sec < 0) | (frame.timestamp_sec >= duration)).any():
        raise ValueError(f"{path}: timestamps outside declared capture duration")
    if (frame.packet_size < 0).any() or (frame.packet_size % 1 != 0).any() or frame.flow_id.eq("").any():
        raise ValueError(f"{path}: invalid size/flow_id")
    return frame.sort_values("timestamp_sec", kind="stable").reset_index(drop=True)


def extract_windows(packets: pd.DataFrame, duration: float, config: dict, intervals: list) -> tuple[pd.DataFrame, np.ndarray]:
    dt = config["bucket_ms"] / 1000.0
    if not np.isfinite(dt) or dt <= 0:
        raise ValueError("bucket_ms must be finite and positive")
    n = grid_count(duration, dt, "duration")
    w = grid_count(config["window_sec"], dt, "window")
    grid_count(config["step_sec"], dt, "step")
    if w > n:
        raise ValueError("window exceeds capture duration")
    counts = np.bincount(np.floor(packets.timestamp_sec.to_numpy() / dt).astype(int), minlength=n)
    frame = compute_paper_window_features(packets, counts.tolist(), config["bucket_ms"], config["window_sec"], config["step_sec"], "benign")
    frame["attack_overlap_sec"] = 0.0
    frame["event_id"] = -1
    frame["attack_start_sec"] = np.nan
    frame["attack_end_sec"] = np.nan
    for event_id, (a, b) in enumerate(intervals):
        overlap = np.maximum(0, np.minimum(frame.window_end_sec, b) - np.maximum(frame.window_start_sec, a))
        # A window crossing several events is transition and excluded from metrics.
        hit = overlap > 1e-10
        frame.loc[hit, "event_id"] = event_id
        frame.loc[hit, "attack_start_sec"] = a
        frame.loc[hit, "attack_end_sec"] = b
        frame["attack_overlap_sec"] += overlap
    overlap = frame.attack_overlap_sec
    frame["label"] = np.where(overlap <= 1e-10, "benign", np.where(np.isclose(overlap, config["window_sec"], atol=1e-10, rtol=0), "attack", "transition"))
    frame["metric_include"] = frame.label.ne("transition")
    frame["decision_time_sec"] = frame.window_end_sec
    frame["feature_profile"] = "paper_reproduction_window_aggregate"
    return frame, counts


def attach_temporal(frame: pd.DataFrame, counts: np.ndarray, packets: pd.DataFrame, config: dict) -> pd.DataFrame:
    cfg = TemporalConfig(**config.get("temporal", {}))
    dt = config["bucket_ms"] / 1000.0
    cfg.validate(dt)
    width = grid_count(cfg.window_sec, dt, "temporal window")
    rows = []
    for end_sec in frame.window_end_sec:
        end = int(round(end_sec / dt))
        if end < width:
            rows.append({"temporal_ready": False, **{name: None for name in METHODS},
                         "interval_count": 0, "burst_start_count": 0,
                         "duty_cycle": None, "peak_packets_per_sec": None,
                         "mean_packets_per_sec": None, "mean_complete_burst_duration_sec": None,
                         "temporal_start_sec": None, "temporal_end_sec": end_sec, "active_flow_count": None})
            continue
        start = end - width
        result = describe_window(counts, start, end, dt, cfg)
        selected = packets[(packets.timestamp_sec >= start * dt) & (packets.timestamp_sec < end_sec)]
        result.update(temporal_ready=True, temporal_start_sec=start * dt,
                      temporal_end_sec=end_sec, active_flow_count=int(selected.flow_id.nunique()))
        rows.append(result)
    return pd.concat([frame.reset_index(drop=True), pd.DataFrame(rows)], axis=1)


def temporal_decision(frame: pd.DataFrame, method: str, rule: dict) -> pd.Series:
    """Optional validation-fixed rule; never choose thresholds on test labels."""
    if method not in METHODS or not rule.get("calibration_reference"):
        raise ValueError("temporal rule requires a supported method and independent calibration_reference")
    threshold = rule["threshold"]
    if not np.isfinite(threshold) or rule["direction"] not in ("upper", "lower"):
        raise ValueError("invalid temporal decision rule")
    valid = frame.temporal_ready & frame[method].notna()
    # Strict comparisons, same convention as original detector.
    result = frame[method].gt(threshold) if rule["direction"] == "upper" else frame[method].lt(threshold)
    return valid & result


def evaluate(frame: pd.DataFrame, intervals: list, decision_column: str) -> dict:
    """Window metrics exclude transition/warmup, but include packet-gated misses.

    Event latency includes causal transition decisions overlapping that event,
    provided the decision is made before/at the event end. Misses remain null.
    """
    valid = frame.metric_include & frame.detection_enabled
    selected = frame[valid]
    actual = selected.label.eq("attack")
    predicted = selected[decision_column].astype(bool)
    tp, fp = int((actual & predicted).sum()), int((~actual & predicted).sum())
    tn, fn = int((~actual & ~predicted).sum()), int((actual & ~predicted).sum())
    divide = lambda a, b: float(a / b) if b else None
    events = []
    for event_id, (start, end) in enumerate(intervals):
        eligible = frame[(frame.window_start_sec < end - 1e-10) & (frame.window_end_sec > start + 1e-10)
                         & (frame.decision_time_sec <= end + 1e-10) & frame.detection_enabled]
        detections = eligible[eligible[decision_column].astype(bool)]
        first = float(detections.decision_time_sec.min()) if not detections.empty else None
        events.append({"event_id": event_id, "start_sec": start, "end_sec": end,
                       "eligible_windows": len(eligible), "detected": first is not None,
                       "latency_sec": first - start if first is not None else None})
    delays = [event["latency_sec"] for event in events if event["detected"]]
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, tpr=divide(tp, tp + fn), recall=divide(tp, tp + fn),
                fpr=divide(fp, fp + tn), precision=divide(tp, tp + fp), evaluated_windows=len(selected),
                excluded_transition_windows=int(frame.label.eq("transition").sum()),
                excluded_warmup_windows=int((~frame.detection_enabled).sum()),
                packet_gated_windows=int((valid & ~frame.enough_packets_for_detection).sum()),
                events=events, missed_events=sum(not e["detected"] for e in events),
                mean_detected_latency_sec=float(np.mean(delays)) if delays else None,
                costs={"cpu_sec": None, "peak_memory_bytes": None, "processing_time_sec": None})


def paired_predictions(training: pd.DataFrame, test: pd.DataFrame, detector_config: dict) -> tuple[pd.DataFrame, dict]:
    if training.empty or not training.label.eq("benign").all():
        raise ValueError("training must contain only explicit benign windows")
    detector = PaperReproductionDetector(PaperDetectorConfig(**detector_config))
    train_log = detector.predict_stream(training)
    if detector.total_windows_processed < detector.config.warmup_windows or not detector.total_windows_processed:
        raise ValueError("not enough packet-qualified benign training windows; change training, not labels")
    outputs = {}
    for mode in ("dynamic", "freeze"):
        branch = deepcopy(detector)
        output = branch.predict_stream(test, update_thresholds=mode == "dynamic")
        output["threshold_mode"] = mode
        gate = output.detection_enabled & output.enough_packets_for_detection
        output["original_attack"] = gate & output.suspicious_score.ge(2)
        output["relaxed_attack"] = gate & output.suspicious_score.ge(1)
        outputs[mode] = output
    return train_log, outputs


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump_json(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def run(config_path: Path, output: Path) -> None:
    config_path = config_path.resolve()
    config = json.loads(config_path.read_text())
    if config.get("schema_version") != 1 or config.get("input_scope") not in ("udp_dst_port", "tcp_udp_aggregate"):
        raise ValueError("require schema_version=1 and explicit input_scope")
    if not config.get("time_origin_description") or "REPLACE" in config["time_origin_description"]:
        raise ValueError("explicit time_origin_description required; never infer origin from first UDP")
    cases = config["cases"]
    if not cases or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("case ids must be unique and nonempty")
    for case in cases:
        if not case["id"] or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in case["id"]):
            raise ValueError("case id must contain only letters, numbers, underscore or hyphen")
        if case["scenario"] not in ("baseline", "random_microburst", "benign_periodic", "periodic_ldos"):
            raise ValueError("unsupported scenario")
        intervals = validate_intervals(case["attack_intervals"], case["duration_sec"])
        if bool(intervals) != (case["scenario"] == "periodic_ldos"):
            raise ValueError("benign cases need explicit []; periodic_ldos needs attack intervals")
    train = config["training"]
    if train.get("label") != "benign":
        raise ValueError("training label must be explicitly benign")
    train_path = config_path.parent / train["packets_csv"]
    if any((config_path.parent / c["packets_csv"]).resolve() == train_path.resolve() for c in cases):
        raise ValueError("training and test must use separate captures")
    if config.get("temporal_rules") and not config.get("enable_temporal", True):
        raise ValueError("temporal_rules require enable_temporal")
    train_packets = read_packets(train_path, train["duration_sec"])
    train_features, _ = extract_windows(train_packets, train["duration_sec"], config, [])
    output.mkdir(parents=True, exist_ok=False)
    dump_json(output / "config.json", config)
    files = {str(config_path): sha256(config_path), str(train_path.resolve()): sha256(train_path)}
    metrics = []
    for case in cases:
        path = config_path.parent / case["packets_csv"]
        files[str(path.resolve())] = sha256(path)
        packets = read_packets(path, case["duration_sec"])
        intervals = validate_intervals(case["attack_intervals"], case["duration_sec"])
        features, counts = extract_windows(packets, case["duration_sec"], config, intervals)
        # Baseline decisions are computed first, without temporal descriptors.
        train_log, predictions = paired_predictions(train_features, features, config.get("detector", {}))
        if not (output / "training_windows.csv").exists():
            train_log.to_csv(output / "training_windows.csv", index=False)
        for mode, frame in predictions.items():
            for method, column in (("original", "original_attack"), ("relaxed", "relaxed_attack")):
                metrics.append({"case_id": case["id"], "scenario": case["scenario"], "seed": case["seed"],
                                "threshold_mode": mode, "method": method, **evaluate(frame, intervals, column)})
            if config.get("enable_temporal", True):
                frame = attach_temporal(frame, counts, packets, config)
                for method, rule in config.get("temporal_rules", {}).items():
                    column = method + "_attack"
                    frame[column] = temporal_decision(frame, method, rule)
                    measured = evaluate(frame, intervals, column)
                    measured["temporal_ready_windows"] = int(frame.temporal_ready.sum())
                    measured["valid_descriptor_windows"] = int(frame[method].notna().sum())
                    metrics.append({"case_id": case["id"], "scenario": case["scenario"], "seed": case["seed"],
                                    "threshold_mode": mode, "method": method, **measured})
            frame["case_id"], frame["scenario"], frame["seed"] = case["id"], case["scenario"], case["seed"]
            frame.to_csv(output / f"{case['id']}_{mode}_windows.csv", index=False)
        pd.DataFrame({"bucket_index": np.arange(len(counts)), "packet_count": counts}).to_csv(output / f"{case['id']}_buckets.csv", index=False)
    dump_json(output / "metrics.json", metrics)
    pd.DataFrame([{k: v for k, v in m.items() if k not in ("events", "costs")} for m in metrics]).to_csv(output / "metrics.csv", index=False)
    root = Path(__file__).resolve().parents[1]
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=True).stdout.strip()
    source_hashes = {str(p.relative_to(root)): sha256(p) for directory in ("src", "scripts") for p in (root / directory).glob("*.py")}
    provenance = dict(python=platform.python_version(), numpy=np.__version__, pandas=pd.__version__,
                      input_sha256=files, source_sha256=source_hashes, detector=asdict(PaperDetectorConfig(**config.get("detector", {}))),
                      feature_profile="paper_reproduction_window_aggregate", synthetic=config.get("synthetic", False))
    try:
        provenance.update(git_head=git("rev-parse", "HEAD"), git_status=git("status", "--short"))
        (output / "source.diff").write_text(git("diff", "HEAD"), encoding="utf-8")
    except (OSError, subprocess.CalledProcessError):
        provenance["git_head"] = None
    dump_json(output / "provenance.json", provenance)
    (output / "COMPLETED").write_text("Offline analysis completed; no network traffic generated.\n")
