#!/usr/bin/env python3
"""Aggregate TCP-unlimited trials and run the unchanged main detector."""

from __future__ import annotations

import argparse
import copy
import csv
import importlib.util
import json
import math
import re
import statistics
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MAIN_DIR = REPO_ROOT / "experiments" / "main_ldos_tcp6m"
TRAIN_PCAP = MAIN_DIR / "raw_pcaps" / "random_benign_avg10.pcap"
TRAIN_META = (
    REPO_ROOT
    / "experiments"
    / "archive_unused"
    / "failed_training_candidates"
    / "random_interval_average_sweep_extra_files"
    / "train_random_avg10"
    / "case.json"
)
EVALUATOR = MAIN_DIR / "scripts" / "evaluate_detector_with_training.py"
CAPACITY_MBPS = 15.0
ATTACK_START = 10.0
ATTACK_END = 50.0
DURATION = 60.0

FIELDS = [
    "condition", "trial", "case_id", "tcp_mean_mbps", "tcp_pre_mbps",
    "tcp_attack_mbps", "tcp_post_mbps", "tcp_sent_bytes", "tcp_retransmissions",
    "tcp_timeouts", "qdisc_drops", "udp_mean_mbps", "udp_peak_mbps",
    "combined_attack_mbps", "link_utilization_pct", "tcp_degradation_pct",
    "attack_normal_windows", "attack_anomaly_windows", "attack_detection_rate_pct",
    "attack_score_min", "attack_score_max", "attack_score_mean",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_root", type=Path)
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


def interval_mbps(data: dict[str, Any], start: float, end: float) -> float:
    bits = 0.0
    covered = 0.0
    for item in data.get("intervals", []):
        summary = item.get("sum") or {}
        left = float(summary.get("start", 0.0))
        right = float(summary.get("end", left))
        overlap = max(0.0, min(right, end) - max(left, start))
        duration = right - left
        if overlap > 0.0 and duration > 0.0:
            bits += float(summary.get("bits_per_second", 0.0)) * overlap
            covered += overlap
    return bits / covered / 1_000_000.0 if covered else math.nan


def full_receiver_mbps(data: dict[str, Any]) -> float:
    receiver = data.get("end", {}).get("sum_received") or data.get("end", {}).get("sum") or {}
    return float(receiver.get("bits_per_second", 0.0)) / 1_000_000.0


def nstat_values(path: Path) -> dict[str, float]:
    values: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("#"):
            try:
                values[parts[0]] = float(parts[1])
            except ValueError:
                pass
    return values


def nstat_delta(raw_dir: Path, key: str) -> float:
    before = nstat_values(raw_dir / "nstat_h1_before_20260707.txt")
    after = nstat_values(raw_dir / "nstat_h1_after_20260707.txt")
    return after.get(key, 0.0) - before.get(key, 0.0)


def qdisc_drops(path: Path) -> float:
    text = path.read_text(encoding="utf-8", errors="replace")
    return sum(float(value) for value in re.findall(r"\bdropped\s+(\d+)", text))


def pulse_metrics(path: Path) -> tuple[float, float]:
    rows = read_csv(path)
    total_bytes = sum(float(row.get("bytes_sent") or 0.0) for row in rows)
    rates = []
    for row in rows:
        byte_count = float(row.get("bytes_sent") or 0.0)
        duration = float(row.get("actual_duration_sec") or 0.0)
        if byte_count > 0.0 and duration > 0.0:
            rates.append(byte_count * 8.0 / duration / 1_000_000.0)
    return total_bytes * 8.0 / (ATTACK_END - ATTACK_START) / 1_000_000.0, max(rates, default=0.0)


def detector_rows(meta: dict[str, Any], output_dir: Path) -> list[dict[str, Any]]:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    evaluator = load_module("dpsws_detector_evaluator", EVALUATOR)
    args = SimpleNamespace(bucket_ms=25, window_sec=4.0, step_sec=1.0, udp_port=5001)
    train_meta = read_json(TRAIN_META)
    train_meta["bottleneck_after_pcap"] = str(TRAIN_PCAP)
    train = evaluator.build_features(train_meta, label_mode="train_benign", args=args)
    test = evaluator.build_features(meta, label_mode="test_periodic", args=args)
    detector = evaluator.PaperReproductionDetector(evaluator.PaperDetectorConfig())
    detector.predict_stream(train)
    online = detector.predict_stream(test)
    online.insert(0, "mode", "online_after_training")
    online.insert(0, "case", meta["case_id"])
    rows = evaluator.to_window_rows(online)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "detector_windows.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=evaluator.WINDOW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def analyze_case(case_dir: Path, condition: str, trial: int) -> dict[str, Any]:
    raw = case_dir / "raw"
    meta = read_json(case_dir / "case.json")
    iperf = read_json(raw / "iperf3_client_20260707.json")
    receiver_intervals = read_json(raw / "iperf3_server_20260707.json")
    sent = iperf.get("end", {}).get("sum_sent") or iperf.get("end", {}).get("sum") or {}
    tcp_attack = interval_mbps(receiver_intervals, ATTACK_START, ATTACK_END)
    udp_mean, udp_peak = pulse_metrics(raw / "pulses_20260707.csv")
    attack_windows: list[dict[str, Any]] = []
    if condition == "ldos":
        rows = detector_rows(meta, case_dir / "detector")
        attack_windows = [
            row for row in rows
            if row.get("label") == "attack" and ATTACK_START <= float(row["window_start_sec"]) < ATTACK_END
        ]
    scores = [int(row["score"]) for row in attack_windows]
    anomalies = sum(score >= 2 for score in scores)
    before_drops = qdisc_drops(raw / "tc_qdisc_before_20260707.txt")
    after_drops = qdisc_drops(raw / "tc_qdisc_after_20260707.txt")
    row = {
        "condition": condition,
        "trial": trial,
        "case_id": meta["case_id"],
        "tcp_mean_mbps": full_receiver_mbps(iperf),
        "tcp_pre_mbps": interval_mbps(receiver_intervals, 0.0, ATTACK_START),
        "tcp_attack_mbps": tcp_attack,
        "tcp_post_mbps": interval_mbps(receiver_intervals, ATTACK_END, DURATION),
        "tcp_sent_bytes": int(float(sent.get("bytes", 0.0))),
        "tcp_retransmissions": int(float(sent.get("retransmits", 0.0))),
        "tcp_timeouts": int(nstat_delta(raw, "TcpExtTCPTimeouts")),
        "qdisc_drops": int(after_drops - before_drops),
        "udp_mean_mbps": udp_mean,
        "udp_peak_mbps": udp_peak,
        "combined_attack_mbps": tcp_attack + udp_mean,
        "link_utilization_pct": (tcp_attack + udp_mean) / CAPACITY_MBPS * 100.0,
        "tcp_degradation_pct": math.nan,
        "attack_normal_windows": len(scores) - anomalies if condition == "ldos" else math.nan,
        "attack_anomaly_windows": anomalies if condition == "ldos" else math.nan,
        "attack_detection_rate_pct": anomalies / len(scores) * 100.0 if scores else math.nan,
        "attack_score_min": min(scores) if scores else math.nan,
        "attack_score_max": max(scores) if scores else math.nan,
        "attack_score_mean": statistics.mean(scores) if scores else math.nan,
    }
    return row


def fmt(value: Any, digits: int = 6) -> str:
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:.{digits}f}"
    return str(value)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] = FIELDS) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: fmt(row.get(key, "")) for key in fields})


def stats_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    numeric = [field for field in FIELDS if field not in {"condition", "trial", "case_id"}]
    for condition in ("baseline", "ldos"):
        subset = [row for row in rows if row["condition"] == condition]
        if not subset:
            continue
        for field in numeric:
            values = [float(row[field]) for row in subset if not (isinstance(row[field], float) and math.isnan(row[field]))]
            if not values:
                continue
            output.append({
                "condition": condition,
                "metric": field,
                "n": len(values),
                "mean": statistics.mean(values),
                "stddev": statistics.stdev(values) if len(values) >= 2 else 0.0,
            })
    return output


def markdown(rows: list[dict[str, Any]], stat_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# DPSWS TCP-unlimited experiment summary", "",
        "| 条件 | 試行 | TCP平均goodput | 10～50秒TCP goodput | TCP低下率 | UDP平均 | リンク利用率 | Timeout | Retransmission | qdisc drops | 異常窓数 | 最大score |",
        "| -- | -: | -----------: | ----------------: | -----: | ----: | -----: | ------: | -------------: | ----------: | ---: | ------: |",
    ]
    for row in rows:
        lines.append(
            f"| {row['condition']} | {row['trial']} | {fmt(row['tcp_mean_mbps'], 3)} Mbps | "
            f"{fmt(row['tcp_attack_mbps'], 3)} Mbps | {fmt(row['tcp_degradation_pct'], 2)}% | "
            f"{fmt(row['udp_mean_mbps'], 3)} Mbps | {fmt(row['link_utilization_pct'], 2)}% | "
            f"{row['tcp_timeouts']} | {row['tcp_retransmissions']} | {row['qdisc_drops']} | "
            f"{fmt(row['attack_anomaly_windows'], 0)} | {fmt(row['attack_score_max'], 2)} |"
        )
    if any(sum(row["condition"] == condition for row in rows) >= 2 for condition in ("baseline", "ldos")):
        by_key = {(row["condition"], row["metric"]): row for row in stat_rows}
        for condition in ("baseline", "ldos"):
            subset = [row for row in rows if row["condition"] == condition]
            if len(subset) < 2:
                continue
            def ms(metric: str, digits: int = 3) -> str:
                item = by_key.get((condition, metric))
                if item is None:
                    return ""
                return f"{fmt(item['mean'], digits)} ± {fmt(item['stddev'], digits)}"
            lines.append(
                f"| {condition} | 平均±SD | {ms('tcp_mean_mbps')} Mbps | {ms('tcp_attack_mbps')} Mbps | "
                f"{ms('tcp_degradation_pct', 2)}% | {ms('udp_mean_mbps')} Mbps | {ms('link_utilization_pct', 2)}% | "
                f"{ms('tcp_timeouts', 2)} | {ms('tcp_retransmissions', 2)} | {ms('qdisc_drops', 2)} | "
                f"{ms('attack_anomaly_windows', 2)} | {ms('attack_score_max', 2)} |"
            )
    lines.extend([
        "",
        "標準偏差は試行間の標本標準偏差（n=1では0）です。goodputの区間値はiperf3サーバ（受信側）JSONから算出しています。",
        "",
        "## 試行別詳細",
        "",
        "| 条件 | 試行 | 0～10秒TCP | 10～50秒TCP | 50～60秒TCP | UDPピーク | TCP+UDP平均 | TCP送信bytes | 正常窓 | 異常窓 | 検知率 | score min/max/mean |",
        "| -- | -: | --: | --: | --: | --: | --: | --: | -: | -: | --: | --: |",
    ])
    for row in rows:
        if row["condition"] == "ldos":
            window_text = f"{fmt(row['attack_normal_windows'], 0)} | {fmt(row['attack_anomaly_windows'], 0)}"
            detection_text = f"{fmt(row['attack_detection_rate_pct'], 2)}%"
            score_text = f"{fmt(row['attack_score_min'], 2)}/{fmt(row['attack_score_max'], 2)}/{fmt(row['attack_score_mean'], 3)}"
        else:
            window_text = "— | —"
            detection_text = "—"
            score_text = "—"
        lines.append(
            f"| {row['condition']} | {row['trial']} | {fmt(row['tcp_pre_mbps'], 3)} Mbps | "
            f"{fmt(row['tcp_attack_mbps'], 3)} Mbps | {fmt(row['tcp_post_mbps'], 3)} Mbps | "
            f"{fmt(row['udp_peak_mbps'], 3)} Mbps | {fmt(row['combined_attack_mbps'], 3)} Mbps | "
            f"{row['tcp_sent_bytes']} | {window_text} | {detection_text} | {score_text} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    root = parse_args().run_root.resolve()
    rows = []
    pattern = re.compile(r"^(baseline|ldos)_trial_(\d+)(?:_attempt_(\d+))?$")
    completed: set[tuple[str, int]] = set()
    for run_dir in sorted((root / "runs").glob("*")):
        match = pattern.match(run_dir.name)
        if not match:
            continue
        case_dirs = list((run_dir / "cases").glob("*"))
        if len(case_dirs) != 1:
            raise RuntimeError(f"expected one case in {run_dir}, got {len(case_dirs)}")
        case_json = case_dirs[0] / "case.json"
        if not case_json.exists():
            continue
        key = (match.group(1), int(match.group(2)))
        if key in completed:
            raise RuntimeError(f"multiple completed attempts for {key}")
        completed.add(key)
        rows.append(analyze_case(case_dirs[0], key[0], key[1]))
    if not rows:
        raise SystemExit(f"no trials found under {root / 'runs'}")
    baseline = {row["trial"]: row for row in rows if row["condition"] == "baseline"}
    for row in rows:
        if row["condition"] != "ldos":
            row["tcp_degradation_pct"] = 0.0
            continue
        base = baseline.get(row["trial"])
        if base is None and baseline:
            base = baseline[min(baseline)]
        if base and base["tcp_attack_mbps"] > 0.0:
            row["tcp_degradation_pct"] = (
                base["tcp_attack_mbps"] - row["tcp_attack_mbps"]
            ) / base["tcp_attack_mbps"] * 100.0
    rows.sort(key=lambda row: (row["trial"], 0 if row["condition"] == "baseline" else 1))
    stat_rows = stats_rows(rows)
    write_csv(root / "trial_metrics.csv", rows)
    write_csv(root / "summary_stats.csv", stat_rows, ["condition", "metric", "n", "mean", "stddev"])
    (root / "summary.md").write_text(markdown(rows, stat_rows), encoding="utf-8")
    print((root / "summary.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
