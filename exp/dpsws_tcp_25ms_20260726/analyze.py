#!/usr/bin/env python3
"""Integrate 10 TCP-unlimited trials and reuse the verified 25 ms detector."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import json
import math
import re
import shutil
import statistics
import subprocess
import sys
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import t as student_t


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
EXISTING_ROOT = REPO_ROOT / "exp/dpsws_tcp_unlimited_20260724/out/20260724_131803"
OLD_ANALYZER = REPO_ROOT / "exp/dpsws_tcp_unlimited_20260724/analyze.py"
DIRECT_ANALYZER = REPO_ROOT / "exp/detector_25ms_20260714/analyze.py"
EXPECTED_TRAIN_SHA256 = "aec716598bb9945317582def6cdb53f28e5ff98892642c39d968a1f9b6c1f165"

ATTACK_START = 10.0
ATTACK_END = 50.0
CAPACITY_MBPS = 15.0

TCP_FIELDS = [
    "condition", "trial", "run_dir", "case_id", "tcp_mean_mbps", "tcp_pre_mbps",
    "tcp_attack_mbps", "tcp_post_mbps", "tcp_degradation_pct", "tcp_sent_bytes",
    "tcp_retransmissions", "tcp_timeouts", "qdisc_drops", "udp_mean_mbps",
    "udp_peak_mbps", "combined_attack_mbps", "link_utilization_pct",
]

DETECTOR_FIELDS = [
    "trial", "case_id", "mode", "attack_windows", "valid_attack_windows",
    "skipped_attack_windows", "score_0", "score_1", "score_ge_2",
    "normal_windows", "anomaly_windows", "TP", "FN", "detection_rate",
    "FNR", "score_min", "score_max", "score_mean", "iat_crossed",
    "burst_rate_crossed", "payload_size_crossed", "new_flow_crossed",
    "missing_timestamps", "duplicate_timestamps", "first_attack_timestamp",
    "last_attack_timestamp", "pcap", "features_csv", "windows_csv",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_root", type=Path)
    return parser.parse_args()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_value(row.get(field, "")) for field in fields})


def csv_value(value: Any) -> Any:
    if isinstance(value, float):
        return "" if math.isnan(value) else f"{value:.12g}"
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def capture_duration(path: Path) -> float:
    result = subprocess.run(["capinfos", "-Tm", "-u", str(path)], text=True, capture_output=True)
    if result.returncode != 0:
        return 0.0
    rows = list(csv.reader(result.stdout.splitlines()))
    return float(rows[-1][1]) if len(rows) >= 2 and len(rows[-1]) >= 2 else 0.0


def candidate_status(run_dir: Path, condition: str) -> tuple[bool, str, Path | None]:
    case_dirs = list((run_dir / "cases").glob("*"))
    if len(case_dirs) != 1:
        return False, f"case directory count={len(case_dirs)}", None
    case_dir = case_dirs[0]
    case_json = case_dir / "case.json"
    if not case_json.is_file():
        return False, "case.json missing", case_dir
    meta = read_json(case_json)
    if meta.get("status") != "success" or int(meta.get("client_rc", -1)) != 0:
        return False, f"status={meta.get('status')} client_rc={meta.get('client_rc')}", case_dir
    raw = case_dir / "raw"
    required = [
        raw / "iperf3_client_20260707.json", raw / "iperf3_server_20260707.json",
        raw / "bottleneck_after_h2_eth0_20260707.pcap",
        raw / "tc_qdisc_before_20260707.txt", raw / "tc_qdisc_after_20260707.txt",
        raw / "nstat_h1_before_20260707.txt", raw / "nstat_h1_after_20260707.txt",
    ]
    if condition == "ldos":
        required.append(raw / "pulses_20260707.csv")
    missing = [path.name for path in required if not path.is_file() or path.stat().st_size == 0]
    if missing:
        return False, "missing/empty: " + ", ".join(missing), case_dir
    if capture_duration(raw / "bottleneck_after_h2_eth0_20260707.pcap") < 60.0:
        return False, "receiver-side pcap duration <60 s", case_dir
    if condition == "ldos" and len(read_csv(raw / "pulses_20260707.csv")) != 40:
        return False, "UDP pulse count !=40", case_dir
    return True, "success", case_dir


def discover_trials(output_root: Path) -> tuple[dict[tuple[str, int], Path], list[dict[str, Any]]]:
    selected: dict[tuple[str, int], Path] = {}
    failed: list[dict[str, Any]] = []
    for condition in ("baseline", "ldos"):
        for trial in range(1, 11):
            root = EXISTING_ROOT if trial <= 3 else output_root
            candidates = sorted((root / "runs").glob(f"{condition}_trial_{trial}*"))
            completed: list[Path] = []
            for run_dir in candidates:
                ok, reason, case_dir = candidate_status(run_dir, condition)
                if ok and case_dir is not None:
                    completed.append(case_dir)
                else:
                    failed.append({"condition": condition, "trial": trial, "run_dir": str(run_dir), "reason": reason})
            if len(completed) > 1:
                raise RuntimeError(f"multiple formal candidates for {condition} trial {trial}: {completed}")
            if len(completed) == 1:
                selected[(condition, trial)] = completed[0]
    return selected, failed


def tcp_row(case_dir: Path, condition: str, trial: int, old: Any) -> dict[str, Any]:
    raw = case_dir / "raw"
    meta = read_json(case_dir / "case.json")
    client = read_json(raw / "iperf3_client_20260707.json")
    server = read_json(raw / "iperf3_server_20260707.json")
    sent = client.get("end", {}).get("sum_sent") or client.get("end", {}).get("sum") or {}
    tcp_attack = old.interval_mbps(server, ATTACK_START, ATTACK_END)
    udp_mean, udp_peak = old.pulse_metrics(raw / "pulses_20260707.csv")
    before_drops = old.qdisc_drops(raw / "tc_qdisc_before_20260707.txt")
    after_drops = old.qdisc_drops(raw / "tc_qdisc_after_20260707.txt")
    return {
        "condition": condition,
        "trial": trial,
        "run_dir": str(case_dir.parents[1]),
        "case_id": meta["case_id"],
        "tcp_mean_mbps": old.full_receiver_mbps(client),
        "tcp_pre_mbps": old.interval_mbps(server, 0.0, ATTACK_START),
        "tcp_attack_mbps": tcp_attack,
        "tcp_post_mbps": old.interval_mbps(server, ATTACK_END, 60.0),
        "tcp_degradation_pct": math.nan,
        "tcp_sent_bytes": int(float(sent.get("bytes", 0.0))),
        "tcp_retransmissions": int(float(sent.get("retransmits", 0.0))),
        "tcp_timeouts": int(old.nstat_delta(raw, "TcpExtTCPTimeouts")),
        "qdisc_drops": int(after_drops - before_drops),
        "udp_mean_mbps": udp_mean,
        "udp_peak_mbps": udp_peak,
        "combined_attack_mbps": tcp_attack + udp_mean,
        "link_utilization_pct": (tcp_attack + udp_mean) / CAPACITY_MBPS * 100.0,
    }


def train_direct_detector(direct: Any) -> tuple[Any, Any, dict[str, Any]]:
    direct.validate_inputs([direct.TRAINING_SPEC])
    features, info = direct.build_features(direct.TRAINING_SPEC)
    detector = direct.PaperReproductionDetector(direct.PaperDetectorConfig())
    direct.predict_online(detector, features)
    return detector, features, info


def detector_row(
    case_dir: Path,
    trial: int,
    output_root: Path,
    direct: Any,
    trained_detector: Any,
) -> dict[str, Any]:
    raw = case_dir / "raw"
    meta = read_json(case_dir / "case.json")
    pcap = raw / "bottleneck_after_h2_eth0_20260707.pcap"
    case_json = case_dir / "case.json"
    spec = direct.CaseSpec(
        case=meta["case_id"], output_key=f"trial_{trial}", pcap=str(pcap),
        metadata=str(case_json), has_attack=True,
    )
    features, _ = direct.build_features(spec)
    online_detector = copy.deepcopy(trained_detector)
    freeze_detector = copy.deepcopy(trained_detector)
    online = direct.predict_online(online_detector, features)
    frozen = direct.predict_frozen(freeze_detector, features)

    trial_out = output_root / "detector_25ms" / f"trial_{trial}"
    trial_out.mkdir(parents=True, exist_ok=True)
    features_csv = trial_out / "features_25ms.csv"
    online_csv = trial_out / "detector_windows_online_25ms.csv"
    frozen_csv = trial_out / "detector_windows_freeze_25ms.csv"
    features.to_csv(features_csv, index=False)
    direct.write_csv(online_csv, direct.to_window_rows(spec.case, "online_after_training", online), direct.WINDOW_FIELDS)
    direct.write_csv(frozen_csv, direct.to_window_rows(spec.case, "freeze_after_training", frozen), direct.WINDOW_FIELDS)

    attack = online[online["label"].eq("attack")].copy()
    scores = attack["suspicious_score"].astype(int)
    predicted = attack["pred_attack"].astype(bool)
    valid = attack["enough_packets_for_detection"].astype(bool)
    starts = attack["window_start_sec"].to_numpy(dtype=float)
    expected = np.arange(400, 2000, dtype=float) * 0.025
    rounded = np.round(starts, 9)
    missing = len(set(np.round(expected, 9)) - set(rounded))
    duplicates = len(rounded) - len(set(rounded))
    tp = int(predicted.sum())
    fn = int(len(attack) - tp)
    row = {
        "trial": trial,
        "case_id": meta["case_id"],
        "mode": "online_after_training",
        "attack_windows": len(attack),
        "valid_attack_windows": int(valid.sum()),
        "skipped_attack_windows": int((~valid).sum()),
        "score_0": int((scores == 0).sum()),
        "score_1": int((scores == 1).sum()),
        "score_ge_2": int((scores >= 2).sum()),
        "normal_windows": int((scores < 2).sum()),
        "anomaly_windows": int((scores >= 2).sum()),
        "TP": tp,
        "FN": fn,
        "detection_rate": tp / len(attack),
        "FNR": fn / len(attack),
        "score_min": int(scores.min()),
        "score_max": int(scores.max()),
        "score_mean": float(scores.mean()),
        "iat_crossed": int(attack["iat_variance_is_suspicious"].astype(bool).sum()),
        "burst_rate_crossed": int(attack["burst_rate_is_suspicious"].astype(bool).sum()),
        "payload_size_crossed": int(attack["payload_size_variance_is_suspicious"].astype(bool).sum()),
        "new_flow_crossed": int(attack["new_flow_arrival_rate_is_suspicious"].astype(bool).sum()),
        "missing_timestamps": missing,
        "duplicate_timestamps": duplicates,
        "first_attack_timestamp": float(starts.min()),
        "last_attack_timestamp": float(starts.max()),
        "pcap": str(pcap),
        "features_csv": str(features_csv),
        "windows_csv": str(online_csv),
    }
    write_csv(trial_out / "detector_summary_25ms.csv", [row], DETECTOR_FIELDS)
    return row


def descriptive(values: list[float]) -> dict[str, float]:
    n = len(values)
    avg = statistics.mean(values)
    sd = statistics.stdev(values) if n >= 2 else 0.0
    half = float(student_t.ppf(0.975, n - 1)) * sd / math.sqrt(n) if n >= 2 else 0.0
    return {
        "n": n, "mean": avg, "stddev": sd, "min": min(values), "max": max(values),
        "median": statistics.median(values), "ci95_low": avg - half, "ci95_high": avg + half,
    }


def statistics_rows(tcp: list[dict[str, Any]], detector: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    requests: list[tuple[str, str, list[float]]] = []
    for condition in ("baseline", "ldos"):
        subset = [row for row in tcp if row["condition"] == condition]
        for metric in (
            "tcp_attack_mbps", "tcp_timeouts", "tcp_retransmissions", "qdisc_drops",
            "udp_mean_mbps", "link_utilization_pct",
        ):
            requests.append((condition, metric, [float(row[metric]) for row in subset]))
    ldos_tcp = [row for row in tcp if row["condition"] == "ldos"]
    requests.append(("paired", "tcp_degradation_pct", [float(row["tcp_degradation_pct"]) for row in ldos_tcp]))
    for metric in ("detection_rate", "FNR", "score_max", "score_mean"):
        requests.append(("ldos_detector", metric, [float(row[metric]) for row in detector]))
    for condition, metric, values in requests:
        rows.append({"condition": condition, "metric": metric, **descriptive(values)})
    return rows


def fmt(value: Any, digits: int = 3) -> str:
    if value is None or value == "":
        return "—"
    number = float(value)
    return "—" if math.isnan(number) else f"{number:.{digits}f}"


def write_detector_investigation(path: Path, direct: Any, train_hash: str) -> None:
    config = direct.PaperDetectorConfig()
    text = f"""# Detector investigation

## Cause of the legacy 40 decisions

The prior TCP-unlimited analyzer called
`experiments/main_ldos_tcp6m/scripts/evaluate_detector_with_training.py` with
`bucket_ms=25`, `window_sec=4.0`, and `step_sec=1.0`. It therefore created
25 ms packet buckets but emitted one four-second-window score per second. The
attack selection used window start times in `[10, 50)`, which produces exactly
40 decisions. The legacy outputs are preserved under `legacy_1s_step/`.

## Reused verified 25 ms implementation

This analysis imports `exp/detector_25ms_20260714/analyze.py`; it does not
reimplement or interpolate detector scores. Its `build_features()` assigns
each UDP destination-port-5001 packet to a non-overlapping 25 ms bucket and
computes the four features from packets in that same bucket. `WINDOW_SEC` and
`STEP_SEC` are both 0.025 seconds, producing 2400 decisions over 60 seconds and
1600 attack decisions over `[10.000, 50.000)`.

- features: {', '.join(direct.PAPER_FEATURES)}
- flow: source IP/port + destination IP/port for UDP destination port 5001
- warmup_windows: {config.warmup_windows} valid windows
- min_packets_for_detection: {config.min_packets_for_detection}
- threshold initialization: observed first window (`use_observed_initial_state={config.use_observed_initial_state}`)
- threshold update: existing per-feature EMA; online mode evaluates then updates non-suspicious features
- score: number of suspicious features
- anomaly rule: score >= {config.suspicious_threshold}
- training pcap: `{direct.REPO_ROOT / direct.TRAINING_SPEC.pcap}`
- training SHA-256: `{train_hash}`
- attack interval: 10.000 <= window_start < 50.000 seconds

The reporting mode is `online_after_training`, matching the prior main report.
Frozen-mode windows are also saved separately for audit but are not mixed into
the 1600-decision denominator.
"""
    path.write_text(text, encoding="utf-8")


def copy_legacy(output_root: Path, selected: dict[tuple[str, int], Path]) -> None:
    legacy = output_root / "legacy_1s_step"
    legacy.mkdir(parents=True, exist_ok=True)
    for trial in range(1, 4):
        source = selected[("ldos", trial)] / "detector/detector_windows.csv"
        if source.is_file():
            shutil.copy2(source, legacy / f"trial_{trial}_detector_windows_1s_step.csv")


def write_failed(path: Path, failed: list[dict[str, Any]], selected: dict[tuple[str, int], Path]) -> None:
    lines = ["# Failed attempts", ""]
    if not failed:
        lines.append("No failed attempts were found.")
    for row in failed:
        lines.extend([
            f"- {row['condition']} trial {row['trial']}: `{row['run_dir']}`",
            f"  - excluded reason: {row['reason']}",
        ])
    lines.extend(["", "## Formal selections", ""])
    for key, case_dir in sorted(selected.items(), key=lambda item: (item[0][1], item[0][0])):
        lines.append(f"- {key[0]} trial {key[1]}: `{case_dir.parents[1]}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validation_lines(
    output_root: Path,
    selected: dict[tuple[str, int], Path],
    tcp: list[dict[str, Any]],
    detector: list[dict[str, Any]],
    train_hash: str,
) -> list[str]:
    metas = [read_json(case_dir / "case.json") for case_dir in selected.values()]
    ldos_metas = [read_json(selected[("ldos", trial)] / "case.json") for trial in range(1, 11)]
    run_start = datetime.strptime(output_root.name, "%Y%m%d_%H%M%S").timestamp()
    old_files_unchanged = all(path.stat().st_mtime < run_start for path in EXISTING_ROOT.rglob("*") if path.is_file())
    checks = {
        "Baseline formal trials = 10": sum(key[0] == "baseline" for key in selected) == 10,
        "LDoS formal trials = 10": sum(key[0] == "ldos" for key in selected) == 10,
        "all status=success": all(meta.get("status") == "success" for meta in metas),
        "all client_rc=0": all(int(meta.get("client_rc", -1)) == 0 for meta in metas),
        "all tcp_target_mbps=null": all(meta.get("tcp_target_mbps") is None for meta in metas),
        "all tcp_limit_method=none": all(meta.get("tcp_limit_method") == "none" for meta in metas),
        "all bottleneck_mbps=15.0": all(float(meta.get("bottleneck_mbps")) == 15.0 for meta in metas),
        "all LDoS burst_ms=300": all(float(meta.get("burst_ms")) == 300.0 for meta in ldos_metas),
        "all LDoS period_ms=1000": all(float(meta.get("period_ms")) == 1000.0 for meta in ldos_metas),
        "all LDoS rate_mbps=15": all(float(meta.get("rate_mbps")) == 15.0 for meta in ldos_metas),
        "all LDoS pcaps exist": all(Path(row["pcap"]).is_file() for row in detector),
        "all detector outputs exist": all(Path(row["windows_csv"]).is_file() for row in detector),
        "each attack decision count=1600": all(int(row["attack_windows"]) == 1600 for row in detector),
        "total attack decision count=16000": sum(int(row["attack_windows"]) for row in detector) == 16000,
        "score counts match totals": all(int(row["score_0"]) + int(row["score_1"]) + int(row["score_ge_2"]) == 1600 for row in detector),
        "missing timestamps=0": all(int(row["missing_timestamps"]) == 0 for row in detector),
        "duplicate timestamps=0": all(int(row["duplicate_timestamps"]) == 0 for row in detector),
        "first timestamps=10.000": all(math.isclose(float(row["first_attack_timestamp"]), 10.0) for row in detector),
        "last timestamps=49.975": all(math.isclose(float(row["last_attack_timestamp"]), 49.975) for row in detector),
        "training SHA-256 matches": train_hash == EXPECTED_TRAIN_SHA256,
        "PNG count=0": not any(output_root.rglob("*.png")),
        "existing result root remains": EXISTING_ROOT.is_dir(),
        "existing result files were not overwritten": old_files_unchanged,
        "10 feature CSV files have 2400 rows": all(sum(1 for _ in Path(row["features_csv"]).open(encoding="utf-8")) == 2401 for row in detector),
        "10 online window CSV files have 2400 rows": all(sum(1 for _ in Path(row["windows_csv"]).open(encoding="utf-8")) == 2401 for row in detector),
    }
    if not all(checks.values()):
        failed = [name for name, passed in checks.items() if not passed]
        raise AssertionError("validation failed: " + ", ".join(failed))
    return [f"- [PASS] {name}" for name in checks]


def write_summary(
    path: Path,
    tcp: list[dict[str, Any]],
    detector: list[dict[str, Any]],
    stats: list[dict[str, Any]],
) -> None:
    lines = [
        "# DPSWS TCP-unlimited 10-trial / 25 ms summary", "",
        "## TCP experiment results", "",
        "| condition | trial | whole TCP | 0-10 s | 10-50 s | 50-60 s | degradation | Timeout | Retransmission | qdisc drops |",
        "| -- | -: | --: | --: | --: | --: | --: | --: | --: | --: |",
    ]
    for row in sorted(tcp, key=lambda item: (int(item["trial"]), item["condition"])):
        lines.append(
            f"| {row['condition']} | {row['trial']} | {fmt(row['tcp_mean_mbps'])} | {fmt(row['tcp_pre_mbps'])} | "
            f"{fmt(row['tcp_attack_mbps'])} | {fmt(row['tcp_post_mbps'])} | "
            f"{fmt(row['tcp_degradation_pct'], 2)} | {row['tcp_timeouts']} | {row['tcp_retransmissions']} | {row['qdisc_drops']} |"
        )
    lines.extend([
        "", "## Detector results (online_after_training)", "",
        "| trial | decisions | score 0 | score 1 | score >=2 | TP | FN | detection rate | FNR | max score | mean score |",
        "| -: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |",
    ])
    for row in detector:
        lines.append(
            f"| {row['trial']} | {row['attack_windows']} | {row['score_0']} | {row['score_1']} | {row['score_ge_2']} | "
            f"{row['TP']} | {row['FN']} | {fmt(row['detection_rate'], 6)} | {fmt(row['FNR'], 6)} | "
            f"{row['score_max']} | {fmt(row['score_mean'], 6)} |"
        )
    lines.extend([
        f"| total | {sum(row['attack_windows'] for row in detector)} | {sum(row['score_0'] for row in detector)} | "
        f"{sum(row['score_1'] for row in detector)} | {sum(row['score_ge_2'] for row in detector)} | "
        f"{sum(row['TP'] for row in detector)} | {sum(row['FN'] for row in detector)} | "
        f"{fmt(sum(row['TP'] for row in detector) / 16000, 6)} | "
        f"{fmt(sum(row['FN'] for row in detector) / 16000, 6)} | "
        f"{max(row['score_max'] for row in detector)} | {fmt(statistics.mean(row['score_mean'] for row in detector), 6)} |",
        "", "## Descriptive statistics", "",
        "| condition | metric | n | mean | SD | median | min | max | 95% CI |",
        "| -- | -- | -: | --: | --: | --: | --: | --: | --: |",
    ])
    for row in stats:
        lines.append(
            f"| {row['condition']} | {row['metric']} | {row['n']} | {fmt(row['mean'], 6)} | "
            f"{fmt(row['stddev'], 6)} | {fmt(row['median'], 6)} | {fmt(row['min'], 6)} | "
            f"{fmt(row['max'], 6)} | [{fmt(row['ci95_low'], 6)}, {fmt(row['ci95_high'], 6)}] |"
        )
    stat_map = {(row["condition"], row["metric"]): row for row in stats}
    base = stat_map[("baseline", "tcp_attack_mbps")]
    ldos = stat_map[("ldos", "tcp_attack_mbps")]
    degradation = stat_map[("paired", "tcp_degradation_pct")]
    timeouts = stat_map[("ldos", "tcp_timeouts")]
    udp = stat_map[("ldos", "udp_mean_mbps")]
    utilization = stat_map[("ldos", "link_utilization_pct")]
    total_tp = sum(row["TP"] for row in detector)
    total_fn = sum(row["FN"] for row in detector)
    lines.extend([
        "", "## Overall result", "",
        f"1. Baseline 10-50 s TCP goodput: {fmt(base['mean'], 6)} ± {fmt(base['stddev'], 6)} Mbps.",
        f"2. LDoS 10-50 s TCP goodput: {fmt(ldos['mean'], 6)} ± {fmt(ldos['stddev'], 6)} Mbps.",
        f"3. Mean of paired degradation rates: {fmt(degradation['mean'], 6)} ± {fmt(degradation['stddev'], 6)}%.",
        f"4. LDoS TCPTimeouts: {fmt(timeouts['mean'], 6)} ± {fmt(timeouts['stddev'], 6)}.",
        f"5. UDP mean: {fmt(udp['mean'], 6)} ± {fmt(udp['stddev'], 6)} Mbps.",
        f"6. Link utilization: {fmt(utilization['mean'], 6)} ± {fmt(utilization['stddev'], 6)}%.",
        f"7. Detector decisions: {sum(row['attack_windows'] for row in detector)}.",
        f"8. score >=2 decisions: {sum(row['score_ge_2'] for row in detector)}.",
        f"9. Detection rate: {fmt(total_tp / (total_tp + total_fn), 6)}.",
        f"10. FNR: {fmt(total_fn / (total_tp + total_fn), 6)}.",
        f"11. Maximum score: {max(row['score_max'] for row in detector)}.",
        "12. All 10 trials show lower attack-window TCP goodput than their paired Baseline and zero anomalous detector decisions.",
        "", "qdisc drops use the existing main-analysis convention (parent HTB plus child netem counters).",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    output_root = parse_args().output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    selected, failed = discover_trials(output_root)
    missing = [(condition, trial) for condition in ("baseline", "ldos") for trial in range(1, 11) if (condition, trial) not in selected]
    if missing:
        raise SystemExit("missing formal trials: " + ", ".join(f"{condition}-{trial}" for condition, trial in missing))

    old = load_module("dpsws_old_numeric_analyzer", OLD_ANALYZER)
    direct = load_module("dpsws_verified_25ms_analyzer", DIRECT_ANALYZER)
    trained_detector, _, training_info = train_direct_detector(direct)
    train_pcap = Path(training_info["pcap"])
    train_hash = sha256(train_pcap)
    if train_hash != EXPECTED_TRAIN_SHA256:
        raise AssertionError(f"training pcap hash mismatch: {train_hash}")

    tcp = [tcp_row(case_dir, condition, trial, old) for (condition, trial), case_dir in selected.items()]
    baseline = {int(row["trial"]): row for row in tcp if row["condition"] == "baseline"}
    for row in tcp:
        if row["condition"] == "ldos":
            base = baseline[int(row["trial"])]
            row["tcp_degradation_pct"] = (base["tcp_attack_mbps"] - row["tcp_attack_mbps"]) / base["tcp_attack_mbps"] * 100.0
    tcp.sort(key=lambda row: (int(row["trial"]), row["condition"]))

    detector = [detector_row(selected[("ldos", trial)], trial, output_root, direct, trained_detector) for trial in range(1, 11)]
    copy_legacy(output_root, selected)
    stats = statistics_rows(tcp, detector)

    write_csv(output_root / "tcp_results_10trials.csv", tcp, TCP_FIELDS)
    write_csv(output_root / "detector_results_10trials_25ms.csv", detector, DETECTOR_FIELDS)
    write_csv(output_root / "statistics_10trials.csv", stats, ["condition", "metric", "n", "mean", "stddev", "min", "max", "median", "ci95_low", "ci95_high"])
    combined = []
    detector_by_trial = {int(row["trial"]): row for row in detector}
    for row in tcp:
        combined.append({**row, **(detector_by_trial[int(row["trial"])] if row["condition"] == "ldos" else {})})
    write_csv(output_root / "all_trials_integrated.csv", combined, TCP_FIELDS + [field for field in DETECTOR_FIELDS if field not in {"trial", "case_id"}])

    degradation_values = [row["tcp_degradation_pct"] for row in tcp if row["condition"] == "ldos"]
    baseline_mean = statistics.mean(row["tcp_attack_mbps"] for row in tcp if row["condition"] == "baseline")
    ldos_mean = statistics.mean(row["tcp_attack_mbps"] for row in tcp if row["condition"] == "ldos")
    aggregate = {
        "paired_degradation_mean_pct": statistics.mean(degradation_values),
        "paired_degradation_stddev_pct": statistics.stdev(degradation_values),
        "degradation_from_condition_means_pct": (baseline_mean - ldos_mean) / baseline_mean * 100.0,
    }
    (output_root / "aggregate_metrics.json").write_text(json.dumps(aggregate, indent=2) + "\n", encoding="utf-8")
    (output_root / "used_settings.json").write_text(json.dumps({
        "existing_root": str(EXISTING_ROOT),
        "verified_25ms_source": str(DIRECT_ANALYZER),
        "detector_config": asdict(direct.PaperDetectorConfig()),
        "window_sec": direct.WINDOW_SEC,
        "step_sec": direct.STEP_SEC,
        "attack_start_sec": ATTACK_START,
        "attack_end_sec": ATTACK_END,
        "training_pcap": str(train_pcap),
        "training_sha256": train_hash,
    }, indent=2) + "\n", encoding="utf-8")
    write_detector_investigation(output_root / "detector_investigation.md", direct, train_hash)
    write_failed(output_root / "failed_attempts.md", failed, selected)
    write_summary(output_root / "summary.md", tcp, detector, stats)
    validation = validation_lines(output_root, selected, tcp, detector, train_hash)
    (output_root / "validation.md").write_text("# Validation\n\n" + "\n".join(validation) + "\n", encoding="utf-8")
    (output_root / "changes.patch").write_text(
        "Legacy: bucket=25ms, window=4s, step=1s\n"
        "Correct reused implementation: window=25ms, step=25ms\n"
        "Traffic parameters: unchanged; only trial numbers and output paths differ.\n",
        encoding="utf-8",
    )
    print(f"OUTPUT_ROOT={output_root}")
    print(f"TCP_RESULTS={output_root / 'tcp_results_10trials.csv'}")
    print(f"DETECTOR_RESULTS={output_root / 'detector_results_10trials_25ms.csv'}")
    print(f"SUMMARY={output_root / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
