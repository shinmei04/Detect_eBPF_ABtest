#!/usr/bin/env python3
"""Analyze TCP-unlimited benign avg10 microburst trials against saved controls."""

from __future__ import annotations

import argparse
import copy
import csv
import importlib.util
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import t as student_t


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
OLD_ANALYZER = REPO_ROOT / "exp/dpsws_tcp_unlimited_20260724/analyze.py"
DIRECT_ANALYZER = REPO_ROOT / "exp/detector_25ms_20260714/analyze.py"
FIGURE_ANALYZER = REPO_ROOT / "exp/dpsws_figures_20260726/analyze.py"
CONTROL_CSV = REPO_ROOT / "exp/dpsws_tcp_25ms_20260726/out/20260726_135301/tcp_results_10trials.csv"
ATTACK_START = 10.0
ATTACK_END = 50.0
CAPACITY_MBPS = 15.0

RESULT_FIELDS = [
    "trial", "case_id", "seed", "tcp_mean_mbps", "tcp_pre_mbps",
    "tcp_eval_mbps", "tcp_post_mbps", "tcp_degradation_pct",
    "tcp_retransmissions", "tcp_timeouts", "qdisc_drops",
    "udp_offered_mbps", "udp_received_mbps", "pulse_count",
    "eval_windows", "valid_windows", "skipped_windows", "score_0",
    "score_1", "score_ge_2", "anomaly_windows", "FPR", "score_min",
    "score_max", "score_mean", "iat_crossed", "burst_rate_crossed",
    "payload_size_crossed", "new_flow_crossed", "missing_timestamps",
    "duplicate_timestamps", "first_timestamp", "last_timestamp",
    "max_pcap_clock_correction_sec", "case_dir",
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


def csv_value(value: Any) -> Any:
    if isinstance(value, float):
        return "" if math.isnan(value) else f"{value:.12g}"
    return value


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_value(row.get(field, "")) for field in fields})


def descriptive(values: list[float]) -> dict[str, float]:
    n = len(values)
    average = statistics.mean(values)
    sd = statistics.stdev(values) if n > 1 else 0.0
    margin = float(student_t.ppf(0.975, n - 1)) * sd / math.sqrt(n) if n > 1 else 0.0
    return {
        "n": n, "mean": average, "sample_sd": sd, "median": statistics.median(values),
        "min": min(values), "max": max(values), "ci95_low": average - margin,
        "ci95_high": average + margin,
    }


def discover_case(output_root: Path, trial: int, failed: list[dict[str, Any]]) -> Path:
    run_name = f"microburst_trial_{trial}"
    run_dirs = sorted(
        path for path in (output_root / "runs").iterdir()
        if path.is_dir() and (path.name == run_name or path.name.startswith(run_name + "_attempt_"))
    )
    candidates = [case_json for run_dir in run_dirs for case_json in sorted((run_dir / "cases").glob("*/case.json"))]
    valid: list[Path] = []
    for case_json in candidates:
        meta = read_json(case_json)
        if meta.get("status") != "success" or int(meta.get("client_rc", -1)) != 0:
            failed.append({"trial": trial, "case_dir": str(case_json.parent), "reason": "unsuccessful case"})
        elif meta.get("tcp_target_mbps") is not None or meta.get("tcp_limit_method") != "none":
            failed.append({"trial": trial, "case_dir": str(case_json.parent), "reason": f"TCP limit remained: target={meta.get('tcp_target_mbps')} method={meta.get('tcp_limit_method')}"})
        else:
            valid.append(case_json.parent)
    if len(valid) != 1:
        raise RuntimeError(f"trial {trial}: expected one valid unlimited case, found {len(valid)}")
    case_dir = valid[0]
    meta = read_json(case_dir / "case.json")
    raw = case_dir / "raw"
    required = [
        raw / "iperf3_client_20260707.json", raw / "iperf3_server_20260707.json",
        raw / "bottleneck_after_h2_eth0_20260707.pcap", raw / "pulses_20260707.csv",
        raw / "nstat_h1_before_20260707.txt", raw / "nstat_h1_after_20260707.txt",
        raw / "tc_qdisc_before_20260707.txt", raw / "tc_qdisc_after_20260707.txt",
    ]
    missing = [str(path) for path in required if not path.is_file() or path.stat().st_size == 0]
    if missing:
        raise RuntimeError(f"trial {trial}: missing/empty files: {missing}")
    expected = {
        "case_type": "train_random_microburst", "capacity_mbps": 15.0,
        "queue_packets": 100, "rate_mbps": 15.0, "payload_bytes": 80,
        "traffic_start_sec": 10.0, "traffic_end_sec": 50.0,
        "random_interval_min_ms": 140.0, "random_interval_max_ms": 210.0,
        "random_burst_min_ms": 5.0, "random_burst_max_ms": 30.0,
        "tcp_congestion": "reno", "tcp_sack": "off",
    }
    for key, value in expected.items():
        if meta.get(key) != value:
            raise RuntimeError(f"trial {trial}: {key}={meta.get(key)!r}, expected {value!r}")
    return case_dir


def analyze_trial(
    case_dir: Path,
    trial: int,
    output_root: Path,
    old: Any,
    direct: Any,
    figures: Any,
    trained_detector: Any,
    baseline_attack_mbps: float,
) -> dict[str, Any]:
    raw = case_dir / "raw"
    meta = read_json(case_dir / "case.json")
    client = read_json(raw / "iperf3_client_20260707.json")
    server = read_json(raw / "iperf3_server_20260707.json")
    sent = client.get("end", {}).get("sum_sent") or client.get("end", {}).get("sum") or {}
    tcp_eval = old.interval_mbps(server, ATTACK_START, ATTACK_END)
    offered_udp, _ = old.pulse_metrics(raw / "pulses_20260707.csv")
    pulses = read_csv(raw / "pulses_20260707.csv")
    before_drops = old.qdisc_drops(raw / "tc_qdisc_before_20260707.txt")
    after_drops = old.qdisc_drops(raw / "tc_qdisc_after_20260707.txt")

    pcap = raw / "bottleneck_after_h2_eth0_20260707.pcap"
    source_case = figures.SourceCase(
        "microburst", trial, case_dir, meta, raw / "iperf3_server_20260707.json",
        pcap, raw / "pulses_20260707.csv",
    )
    _, udp_100ms, _, _, max_clock_correction = figures.tshark_payload_bins(source_case)
    udp_received = float(udp_100ms.reshape(60, 10).mean(axis=1)[10:50].mean())

    spec = direct.CaseSpec(
        case=meta["case_id"], output_key=f"trial_{trial}", pcap=str(pcap),
        metadata=str(case_dir / "case.json"), has_attack=False,
    )
    features, _ = direct.build_features(spec)
    online = direct.predict_online(copy.deepcopy(trained_detector), features)
    frozen = direct.predict_frozen(copy.deepcopy(trained_detector), features)
    trial_out = output_root / "detector_25ms" / f"trial_{trial}"
    trial_out.mkdir(parents=True, exist_ok=True)
    features.to_csv(trial_out / "features_25ms.csv", index=False)
    direct.write_csv(
        trial_out / "detector_windows_online_25ms.csv",
        direct.to_window_rows(spec.case, "online_after_training", online), direct.WINDOW_FIELDS,
    )
    direct.write_csv(
        trial_out / "detector_windows_freeze_25ms.csv",
        direct.to_window_rows(spec.case, "freeze_after_training", frozen), direct.WINDOW_FIELDS,
    )
    evaluation = online[
        online["window_start_sec"].ge(ATTACK_START)
        & online["window_start_sec"].lt(ATTACK_END)
    ].copy()
    scores = evaluation["suspicious_score"].astype(int)
    predicted = evaluation["pred_attack"].astype(bool)
    valid = evaluation["enough_packets_for_detection"].astype(bool)
    starts = evaluation["window_start_sec"].to_numpy(dtype=float)
    expected = np.arange(400, 2000, dtype=float) * 0.025
    rounded = np.round(starts, 9)
    row = {
        "trial": trial, "case_id": meta["case_id"], "seed": meta["seed"],
        "tcp_mean_mbps": old.full_receiver_mbps(client),
        "tcp_pre_mbps": old.interval_mbps(server, 0.0, ATTACK_START),
        "tcp_eval_mbps": tcp_eval,
        "tcp_post_mbps": old.interval_mbps(server, ATTACK_END, 60.0),
        "tcp_degradation_pct": (baseline_attack_mbps - tcp_eval) / baseline_attack_mbps * 100.0,
        "tcp_retransmissions": int(float(sent.get("retransmits", 0.0))),
        "tcp_timeouts": int(old.nstat_delta(raw, "TcpExtTCPTimeouts")),
        "qdisc_drops": int(after_drops - before_drops),
        "udp_offered_mbps": offered_udp, "udp_received_mbps": udp_received,
        "pulse_count": len(pulses), "eval_windows": len(evaluation),
        "valid_windows": int(valid.sum()), "skipped_windows": int((~valid).sum()),
        "score_0": int((scores == 0).sum()), "score_1": int((scores == 1).sum()),
        "score_ge_2": int((scores >= 2).sum()), "anomaly_windows": int(predicted.sum()),
        "FPR": float(predicted.mean()), "score_min": int(scores.min()),
        "score_max": int(scores.max()), "score_mean": float(scores.mean()),
        "iat_crossed": int(evaluation["iat_variance_is_suspicious"].astype(bool).sum()),
        "burst_rate_crossed": int(evaluation["burst_rate_is_suspicious"].astype(bool).sum()),
        "payload_size_crossed": int(evaluation["payload_size_variance_is_suspicious"].astype(bool).sum()),
        "new_flow_crossed": int(evaluation["new_flow_arrival_rate_is_suspicious"].astype(bool).sum()),
        "missing_timestamps": len(set(np.round(expected, 9)) - set(rounded)),
        "duplicate_timestamps": len(rounded) - len(set(rounded)),
        "first_timestamp": float(starts.min()), "last_timestamp": float(starts.max()),
        "max_pcap_clock_correction_sec": max_clock_correction, "case_dir": str(case_dir),
    }
    return row


def main() -> int:
    args = parse_args()
    output_root = args.output_root.resolve()
    old = load_module("dpsws_old_analyzer", OLD_ANALYZER)
    direct = load_module("dpsws_direct_detector", DIRECT_ANALYZER)
    figures = load_module("dpsws_figure_analyzer", FIGURE_ANALYZER)
    control_rows = read_csv(CONTROL_CSV)
    baseline_by_trial = {
        int(row["trial"]): float(row["tcp_attack_mbps"])
        for row in control_rows if row["condition"] == "baseline"
    }
    ldos_rows = [row for row in control_rows if row["condition"] == "ldos"]
    training_features, _ = direct.build_features(direct.TRAINING_SPEC)
    trained_detector = direct.PaperReproductionDetector(direct.PaperDetectorConfig())
    direct.predict_online(trained_detector, training_features)

    failed: list[dict[str, Any]] = []
    rows = [
        analyze_trial(
            discover_case(output_root, trial, failed), trial, output_root, old, direct,
            figures, trained_detector, baseline_by_trial[trial],
        )
        for trial in range(1, 11)
    ]
    write_csv(output_root / "microburst_results_10trials.csv", rows, RESULT_FIELDS)

    metrics = [
        "tcp_eval_mbps", "tcp_degradation_pct", "tcp_timeouts",
        "tcp_retransmissions", "qdisc_drops", "udp_offered_mbps",
        "udp_received_mbps", "anomaly_windows", "FPR", "score_max", "score_mean",
    ]
    stats_rows = []
    for metric in metrics:
        stats = descriptive([float(row[metric]) for row in rows])
        stats_rows.append({"metric": metric, **stats})
    write_csv(
        output_root / "statistics_10trials.csv", stats_rows,
        ["metric", "n", "mean", "sample_sd", "median", "min", "max", "ci95_low", "ci95_high"],
    )

    baseline_stats = descriptive(list(baseline_by_trial.values()))
    micro_stats = descriptive([float(row["tcp_eval_mbps"]) for row in rows])
    degradation_stats = descriptive([float(row["tcp_degradation_pct"]) for row in rows])
    ldos_stats = descriptive([float(row["tcp_attack_mbps"]) for row in ldos_rows])
    timeout_stats = descriptive([float(row["tcp_timeouts"]) for row in rows])
    anomaly_total = sum(int(row["anomaly_windows"]) for row in rows)
    evaluation_total = sum(int(row["eval_windows"]) for row in rows)
    score_max = max(int(row["score_max"]) for row in rows)
    lines = [
        "# TCP-unlimited benign random microburst 10-trial summary", "",
        "## Per-trial results", "",
        "| trial | TCP 10-50 s Mbps | degradation % | UDP offered Mbps | UDP received Mbps | Timeout | Retransmission | qdisc drops | anomaly windows | max score |",
        "| -: | --: | --: | --: | --: | -: | -: | -: | -: | -: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['trial']} | {row['tcp_eval_mbps']:.6f} | {row['tcp_degradation_pct']:.3f} | "
            f"{row['udp_offered_mbps']:.6f} | {row['udp_received_mbps']:.6f} | "
            f"{row['tcp_timeouts']} | {row['tcp_retransmissions']} | {row['qdisc_drops']} | "
            f"{row['anomaly_windows']} | {row['score_max']} |"
        )
    lines.extend([
        "", "## Comparison", "",
        f"- Baseline TCP goodput: {baseline_stats['mean']:.6f} ± {baseline_stats['sample_sd']:.6f} Mbps",
        f"- Benign microburst TCP goodput: {micro_stats['mean']:.6f} ± {micro_stats['sample_sd']:.6f} Mbps",
        f"- Benign microburst paired degradation: {degradation_stats['mean']:.6f} ± {degradation_stats['sample_sd']:.6f}% (95% CI [{degradation_stats['ci95_low']:.6f}, {degradation_stats['ci95_high']:.6f}])",
        f"- Periodic LDoS TCP goodput: {ldos_stats['mean']:.6f} ± {ldos_stats['sample_sd']:.6f} Mbps",
        f"- Benign microburst TCPTimeouts: {timeout_stats['mean']:.3f} ± {timeout_stats['sample_sd']:.3f}",
        f"- Benign evaluation windows: {evaluation_total}",
        f"- False-positive windows: {anomaly_total}",
        f"- FPR: {anomaly_total / evaluation_total:.9f}",
        f"- Maximum score: {score_max}",
        "", "## Interpretation", "",
        "The adopted avg10 trace was benign and TCP-stable in the original 6 Mbps condition, but it is not a no-impact control when unlimited TCP fills the 15 Mbps bottleneck. Its mean TCP degradation is larger than the Periodic LDoS result, so these measurements do not support a claim that TCP harm is specific to the periodic attack.",
        "", "The detector uses the unchanged adopted training pcap, features, EMA behavior, thresholds, 25 ms windows, and score >=2 rule.",
    ])
    (output_root / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    validation = [
        "# Validation", "",
        "- [PASS] 10 successful independent-seed benign microburst trials",
        "- [PASS] TCP sender limit is absent in all trials",
        "- [PASS] adopted avg10 random burst and interval distributions unchanged",
        "- [PASS] all evaluation intervals are 10 <= t < 50",
        f"- [PASS] detector decision count={evaluation_total}",
        f"- [PASS] valid detector windows={sum(int(row['valid_windows']) for row in rows)}",
        f"- [PASS] skipped detector windows={sum(int(row['skipped_windows']) for row in rows)}",
        "- [PASS] missing detector timestamps=0",
        "- [PASS] duplicate detector timestamps=0",
        "- [PASS] no figures generated",
    ]
    if any(int(row["eval_windows"]) != 1600 for row in rows):
        raise RuntimeError("not every trial has 1600 evaluation windows")
    if any(int(row["missing_timestamps"]) or int(row["duplicate_timestamps"]) for row in rows):
        raise RuntimeError("detector timestamp coverage failure")
    (output_root / "validation.md").write_text("\n".join(validation) + "\n", encoding="utf-8")
    settings = {
        "condition": "adopted train_random_avg10 with unlimited TCP",
        "capacity_mbps": 15.0,
        "queue_packets": 100,
        "delay_ms": 20.0,
        "traffic_interval": "10 <= t < 50",
        "udp_peak_mbps": 15.0,
        "udp_payload_bytes": 80,
        "random_burst_min_ms": 5.0,
        "random_burst_max_ms": 30.0,
        "random_interval_min_ms": 140.0,
        "random_interval_max_ms": 210.0,
        "tcp_target_mbps": None,
        "tcp_limit_method": "none",
        "tcp_congestion": "reno",
        "tcp_sack": "off",
        "trial_random_seeds": [int(row["seed"]) for row in rows],
        "detector_bucket_and_step_ms": 25,
        "detector_score_threshold": 2,
        "detector_training_pcap": str(REPO_ROOT / direct.TRAINING_SPEC.pcap),
    }
    (output_root / "used_settings.json").write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    command_lines = [
        ".venv/bin/python exp/dpsws_microburst_20260726/run.py --trial 1 --output-dir exp/dpsws_microburst_20260726/out/20260726_160252/runs/microburst_trial_1_attempt_2",
        *[
            f".venv/bin/python exp/dpsws_microburst_20260726/run.py --trial {trial} --output-dir exp/dpsws_microburst_20260726/out/20260726_160252/runs/microburst_trial_{trial}"
            for trial in range(2, 11)
        ],
        ".venv/bin/python exp/dpsws_microburst_20260726/analyze.py exp/dpsws_microburst_20260726/out/20260726_160252",
    ]
    (output_root / "commands.log").write_text("\n".join(command_lines) + "\n", encoding="utf-8")
    failed_lines = ["# Failed or excluded attempts", ""]
    failed_lines.extend([
        "- Trial 1 launch without root stopped before Mininet: `Mininet requires root privileges`.",
        "- Trial 1 launch with `sudo -n` stopped before Mininet because a password was required.",
    ])
    for item in failed:
        failed_lines.append(f"- Trial {item['trial']}: `{item['case_dir']}` - {item['reason']}")
    (output_root / "failed_attempts.md").write_text("\n".join(failed_lines) + "\n", encoding="utf-8")
    print(f"Wrote analysis to {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
