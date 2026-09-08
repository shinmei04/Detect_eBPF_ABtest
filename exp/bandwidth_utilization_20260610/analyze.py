#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Analyze LDoS bandwidth utilization from per-case raw packet data or pcaps.
The bottleneck egress capture is split into normal TCP, attack UDP, other,
and idle capacity for each aggregation bucket.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from metrics import (
    aggregate_seed_stats,
    classify_packet,
    compute_capacity_breakdown,
    configured_average_attack_pct,
    excess_degradation_pp,
    normal_attack_idle_ratio,
    tcp_degradation_pct,
)


TIMESERIES_FIELDS = [
    "timestamp_sec",
    "scenario",
    "condition_id",
    "seed",
    "tcp_normal_mbps",
    "attack_offered_mbps",
    "attack_passed_mbps",
    "other_mbps",
    "total_passed_mbps",
    "idle_mbps",
    "capacity_excess_mbps",
    "capacity_excess_pct",
    "link_utilization_pct",
    "tcp_share_pct",
    "attack_share_pct",
    "other_share_pct",
    "idle_share_pct",
    "attack_active",
    "attack_burst_active",
    "detector_attack",
    "suspicious_score",
]

CASE_METRIC_FIELDS = [
    "timestamp",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "bottleneck_mbps",
    "peak_rate_mbps",
    "burst_ms",
    "period_ms",
    "duty_ratio",
    "configured_average_attack_mbps",
    "configured_average_attack_pct",
    "measured_attack_offered_mbps",
    "measured_attack_passed_mbps",
    "tcp_baseline_mbps",
    "tcp_mbps",
    "tcp_degradation_ratio",
    "tcp_degradation_pct",
    "excess_degradation_vs_random_pct",
    "excess_degradation_vs_constant_pct",
    "idle_mbps",
    "link_utilization_pct",
    "tcp_share_pct",
    "attack_share_pct",
    "other_share_pct",
    "idle_share_pct",
    "normal_attack_idle_ratio",
    "FNR",
    "FNR_period",
    "FNR_burst",
    "FPR",
    "detection_delay_ms",
    "mean_suspicious_score",
    "status",
    "error_message",
]

DETECTOR_METRIC_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "attack_windows",
    "detected_attack_windows",
    "missed_attack_windows",
    "burst_attack_windows",
    "detected_burst_windows",
    "missed_burst_windows",
    "FNR",
    "FNR_period",
    "FNR_burst",
    "FPR",
    "detection_delay_ms",
    "mean_suspicious_score",
    "mean_iat_variance",
    "mean_burst_rate",
    "mean_payload_size_variance",
    "mean_new_flow_rate",
    "rel_iat_variance_vs_no_attack",
    "rel_burst_rate_vs_no_attack",
    "rel_payload_size_variance_vs_no_attack",
    "rel_new_flow_rate_vs_no_attack",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--bucket-ms", type=float, default=25.0)
    parser.add_argument("--bottleneck-mbps", type=float, default=None)
    parser.add_argument("--evaluation-start-sec", type=float, default=None)
    parser.add_argument("--evaluation-end-sec", type=float, default=None)
    parser.add_argument("--tcp-sender-ip", default="10.0.0.1")
    parser.add_argument("--receiver-ip", default="10.0.0.2")
    parser.add_argument("--attacker-ips", nargs="*", default=["10.0.0.3", "10.0.0.4"])
    parser.add_argument("--iperf-port", type=int, default=5201)
    parser.add_argument("--attack-udp-port", type=int, default=5001)
    parser.add_argument("--pcap-length-source", choices=["ip", "ethernet", "payload"], default="ip")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: format_value(row.get(field, "")) for field in fields})


def format_value(value: Any) -> Any:
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:.9g}"
    return value


def safe_float(value: Any, default: float = math.nan) -> float:
    if value in ("", None):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    if value in ("", None):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def bucket_start(timestamp_sec: float, bucket_sec: float) -> float:
    return math.floor((timestamp_sec + 1e-12) / bucket_sec) * bucket_sec


def mbps_from_bytes(byte_count: float, bucket_sec: float) -> float:
    if bucket_sec <= 0:
        raise ValueError("bucket_sec must be positive")
    return 8.0 * byte_count / bucket_sec / 1_000_000.0


def read_synthetic_packet_rows(case_dir: Path) -> list[dict[str, Any]]:
    packet_path = case_dir / "raw" / "synthetic_packets_20260610.csv"
    if not packet_path.exists():
        return []
    with packet_path.open(newline="") as f:
        return list(csv.DictReader(f))


TCPDUMP_HEADER_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+"
    r".*?ethertype IPv4 \(0x0800\), length (?P<eth_len>\d+):\s+"
    r"\(.*?proto (?P<proto>[A-Z0-9]+) \((?P<proto_num>\d+)\), length (?P<ip_len>\d+)\)"
)
TCPDUMP_DETAIL_RE = re.compile(
    r"^\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\.(?P<src_port>\d+))?\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\.(?P<dst_port>\d+))?:\s+"
    r"(?P<body>.*?)(?:,\s+length\s+(?P<payload_len>\d+))?$"
)


def parse_tcpdump_records(lines: Iterable[str], length_source: str, time_origin_sec: float) -> Iterable[dict[str, Any]]:
    pending: dict[str, Any] | None = None
    for line in lines:
        header = TCPDUMP_HEADER_RE.match(line.rstrip())
        if header:
            pending = {
                "timestamp_sec": safe_float(header.group("ts")) - time_origin_sec,
                "eth_len": safe_int(header.group("eth_len")),
                "ip_len": safe_int(header.group("ip_len")),
                "proto": header.group("proto").upper(),
            }
            continue
        if pending is None:
            continue
        detail = TCPDUMP_DETAIL_RE.match(line.rstrip())
        if not detail:
            continue
        body = detail.group("body")
        proto = pending["proto"]
        if "UDP" in body:
            proto = "UDP"
        elif "Flags" in body:
            proto = "TCP"
        payload_len = safe_int(detail.group("payload_len"), 0)
        if length_source == "ethernet":
            byte_count = pending["eth_len"]
        elif length_source == "payload":
            byte_count = payload_len
        else:
            byte_count = pending["ip_len"]
        yield {
            "timestamp_sec": pending["timestamp_sec"],
            "proto": proto,
            "src_ip": detail.group("src_ip"),
            "dst_ip": detail.group("dst_ip"),
            "src_port": safe_int(detail.group("src_port")),
            "dst_port": safe_int(detail.group("dst_port")),
            "payload_bytes": payload_len,
            "wire_bytes": byte_count,
        }
        pending = None


def read_pcap_packet_rows(
    pcap_path: Path,
    capture: str,
    metadata: dict[str, Any],
    args: argparse.Namespace,
) -> list[dict[str, Any]]:
    if not pcap_path.exists():
        return []
    command = ["tcpdump", "-tt", "-e", "-n", "-vv", "-r", str(pcap_path), "ip"]
    try:
        proc = subprocess.run(command, text=True, capture_output=True, check=False)
    except FileNotFoundError:
        raise RuntimeError("tcpdump is required to analyze pcap files")
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"tcpdump failed for {pcap_path}: {proc.stderr.strip()}")

    rows: list[dict[str, Any]] = []
    time_origin_sec = safe_float(metadata.get("experiment_start_wall"), math.nan)
    if math.isnan(time_origin_sec):
        time_origin_sec = safe_float(metadata.get("case_start_epoch_ns"), 0.0) / 1_000_000_000.0
    receiver_ip = str(metadata.get("receiver_ip", args.receiver_ip))
    for packet in parse_tcpdump_records(proc.stdout.splitlines(), args.pcap_length_source, time_origin_sec):
        if capture == "egress" and packet["dst_ip"] != receiver_ip:
            continue
        packet_class = classify_packet(
            packet,
            tcp_sender_ip=args.tcp_sender_ip,
            receiver_ip=receiver_ip,
            attacker_ips=args.attacker_ips,
            iperf_port=args.iperf_port,
            attack_udp_port=args.attack_udp_port,
        )
        rows.append(
            {
                "timestamp_sec": packet["timestamp_sec"],
                "capture": capture,
                "class": packet_class,
                "bytes": packet["wire_bytes"],
            }
        )
    return rows


def read_case_packet_rows(case_dir: Path, metadata: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    synthetic_rows = read_synthetic_packet_rows(case_dir)
    if synthetic_rows:
        return synthetic_rows

    rows: list[dict[str, Any]] = []
    ingress_pcap = metadata.get("capture_ingress_pcap")
    egress_pcap = metadata.get("capture_egress_pcap")
    if ingress_pcap:
        rows.extend(read_pcap_packet_rows(Path(ingress_pcap), "ingress", metadata, args))
    if egress_pcap:
        rows.extend(read_pcap_packet_rows(Path(egress_pcap), "egress", metadata, args))
    return rows


def read_detector_rows(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "raw" / "detector" / "detector_windows_20260610.csv"
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def detector_by_bucket(detector_rows: list[dict[str, Any]], bucket_sec: float) -> dict[float, dict[str, Any]]:
    by_bucket: dict[float, dict[str, Any]] = {}
    for row in detector_rows:
        ts = safe_float(row.get("timestamp_sec", row.get("window_start_sec", 0.0)), 0.0)
        by_bucket[round(bucket_start(ts, bucket_sec), 9)] = row
    return by_bucket


def build_case_timeseries(
    case_dir: Path,
    metadata: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bucket_sec = args.bucket_ms / 1000.0
    bottleneck_mbps = safe_float(args.bottleneck_mbps, safe_float(metadata.get("bottleneck_mbps"), 15.0))
    duration_sec = safe_float(metadata.get("duration_sec"), 0.0)
    attack_start_sec = safe_float(metadata.get("attack_start_sec"), 0.0)
    period_ms = safe_float(metadata.get("period_ms"), 1000.0)
    burst_ms = safe_float(metadata.get("burst_ms"), 0.0)

    buckets: dict[float, dict[str, float]] = defaultdict(lambda: {"tcp": 0.0, "attack_passed": 0.0, "attack_offered": 0.0, "other": 0.0})
    packet_rows = read_case_packet_rows(case_dir, metadata, args)
    for packet in packet_rows:
        ts = safe_float(packet.get("timestamp_sec"), math.nan)
        if math.isnan(ts):
            continue
        key = round(bucket_start(ts, bucket_sec), 9)
        packet_class = str(packet.get("class", "other"))
        capture = str(packet.get("capture", "egress"))
        byte_count = safe_float(packet.get("bytes"), 0.0)
        if capture == "ingress" and packet_class == "attack":
            buckets[key]["attack_offered"] += byte_count
        elif capture == "egress" and packet_class == "attack":
            buckets[key]["attack_passed"] += byte_count
        elif capture == "egress" and packet_class == "tcp_normal":
            buckets[key]["tcp"] += byte_count
        elif capture == "egress":
            buckets[key]["other"] += byte_count

    detector_rows = read_detector_rows(case_dir)
    detector_map = detector_by_bucket(detector_rows, bucket_sec)
    if duration_sec > 0:
        steps = int(math.ceil(duration_sec / bucket_sec))
        for step in range(steps):
            buckets.setdefault(round(step * bucket_sec, 9), {"tcp": 0.0, "attack_passed": 0.0, "attack_offered": 0.0, "other": 0.0})

    rows: list[dict[str, Any]] = []
    for key in sorted(buckets):
        stats = buckets[key]
        tcp_mbps = mbps_from_bytes(stats["tcp"], bucket_sec)
        attack_passed_mbps = mbps_from_bytes(stats["attack_passed"], bucket_sec)
        attack_offered_mbps = mbps_from_bytes(stats["attack_offered"], bucket_sec)
        other_mbps = mbps_from_bytes(stats["other"], bucket_sec)
        breakdown = compute_capacity_breakdown(tcp_mbps, attack_passed_mbps, other_mbps, bottleneck_mbps)
        detector = detector_map.get(key, {})
        in_attack_period = key >= attack_start_sec and (duration_sec <= 0 or key < duration_sec)
        phase_ms = ((key - attack_start_sec) * 1000.0) % period_ms if in_attack_period and period_ms > 0 else math.inf
        attack_burst_active = in_attack_period and phase_ms < burst_ms
        rows.append(
            {
                "timestamp_sec": key,
                "scenario": metadata.get("scenario", ""),
                "condition_id": metadata.get("condition_id", ""),
                "seed": metadata.get("seed", ""),
                "tcp_normal_mbps": breakdown.tcp_normal_mbps,
                "attack_offered_mbps": attack_offered_mbps,
                "attack_passed_mbps": breakdown.attack_passed_mbps,
                "other_mbps": breakdown.other_mbps,
                "total_passed_mbps": breakdown.total_passed_mbps,
                "idle_mbps": breakdown.idle_mbps,
                "capacity_excess_mbps": breakdown.capacity_excess_mbps,
                "capacity_excess_pct": breakdown.capacity_excess_pct,
                "link_utilization_pct": breakdown.link_utilization_pct,
                "tcp_share_pct": breakdown.tcp_share_pct,
                "attack_share_pct": breakdown.attack_share_pct,
                "other_share_pct": breakdown.other_share_pct,
                "idle_share_pct": breakdown.idle_share_pct,
                "attack_active": int(in_attack_period and metadata.get("scenario") != "no_attack"),
                "attack_burst_active": int(attack_burst_active and metadata.get("scenario") != "no_attack"),
                "detector_attack": int(safe_float(detector.get("detector_attack", detector.get("is_attack", 0)), 0.0) >= 1.0),
                "suspicious_score": safe_float(detector.get("suspicious_score"), 0.0),
            }
        )
    return rows, detector_rows


def mean_field(rows: list[dict[str, Any]], field: str) -> float:
    values = [safe_float(row.get(field), math.nan) for row in rows]
    values = [value for value in values if not math.isnan(value)]
    return sum(values) / len(values) if values else math.nan


def detector_metrics(case_id: str, metadata: dict[str, Any], detector_rows: list[dict[str, Any]], attack_start_sec: float) -> dict[str, Any]:
    attack_rows = [row for row in detector_rows if safe_int(row.get("attack_active"), 0) == 1]
    period_rows = [row for row in detector_rows if safe_int(row.get("attack_period_active", row.get("attack_active")), 0) == 1]
    burst_rows = [row for row in detector_rows if safe_int(row.get("attack_burst_active"), 0) == 1]
    normal_rows = [row for row in detector_rows if safe_int(row.get("attack_active"), 0) == 0]

    def detected(row: dict[str, Any]) -> bool:
        return safe_float(row.get("detector_attack", row.get("is_attack", 0)), 0.0) >= 1.0

    def fnr(rows: list[dict[str, Any]]) -> float:
        if not rows:
            return math.nan
        missed = sum(1 for row in rows if not detected(row))
        return missed / len(rows)

    detected_attack = sum(1 for row in attack_rows if detected(row))
    missed_attack = len(attack_rows) - detected_attack
    detected_burst = sum(1 for row in burst_rows if detected(row))
    missed_burst = len(burst_rows) - detected_burst
    false_positive = sum(1 for row in normal_rows if detected(row))
    fpr = false_positive / len(normal_rows) if normal_rows else math.nan
    detection_times = [
        safe_float(row.get("timestamp_sec", row.get("window_start_sec")), math.nan)
        for row in attack_rows
        if detected(row)
    ]
    detection_times = [value for value in detection_times if not math.isnan(value)]
    delay_ms = (min(detection_times) - attack_start_sec) * 1000.0 if detection_times else math.nan

    return {
        "case_id": case_id,
        "scenario": metadata.get("scenario", ""),
        "condition_id": metadata.get("condition_id", ""),
        "seed": metadata.get("seed", ""),
        "attack_windows": len(attack_rows),
        "detected_attack_windows": detected_attack,
        "missed_attack_windows": missed_attack,
        "burst_attack_windows": len(burst_rows),
        "detected_burst_windows": detected_burst,
        "missed_burst_windows": missed_burst,
        "FNR": fnr(attack_rows),
        "FNR_period": fnr(period_rows),
        "FNR_burst": fnr(burst_rows),
        "FPR": fpr,
        "detection_delay_ms": delay_ms,
        "mean_suspicious_score": mean_field(detector_rows, "suspicious_score"),
        "mean_iat_variance": mean_field(detector_rows, "iat_variance"),
        "mean_burst_rate": mean_field(detector_rows, "burst_rate"),
        "mean_payload_size_variance": mean_field(detector_rows, "payload_size_variance"),
        "mean_new_flow_rate": mean_field(detector_rows, "new_flow_rate"),
    }


def add_detector_relative_differences(rows: list[dict[str, Any]]) -> None:
    baseline_by_seed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["scenario"] == "no_attack":
            baseline_by_seed[str(row["seed"])] = row
    feature_pairs = [
        ("mean_iat_variance", "rel_iat_variance_vs_no_attack"),
        ("mean_burst_rate", "rel_burst_rate_vs_no_attack"),
        ("mean_payload_size_variance", "rel_payload_size_variance_vs_no_attack"),
        ("mean_new_flow_rate", "rel_new_flow_rate_vs_no_attack"),
    ]
    for row in rows:
        baseline = baseline_by_seed.get(str(row["seed"]))
        for mean_key, rel_key in feature_pairs:
            base = safe_float(baseline.get(mean_key) if baseline else None, math.nan)
            value = safe_float(row.get(mean_key), math.nan)
            if math.isnan(base) or abs(base) < 1e-12 or math.isnan(value):
                row[rel_key] = math.nan
            else:
                row[rel_key] = abs(value - base) / abs(base)


def case_metrics_from_timeseries(
    case_id: str,
    metadata: dict[str, Any],
    timeseries: list[dict[str, Any]],
    detector_row: dict[str, Any],
    evaluation_start: float,
    evaluation_end: float,
) -> dict[str, Any]:
    eval_rows = [
        row
        for row in timeseries
        if safe_float(row.get("timestamp_sec"), math.nan) >= evaluation_start
        and safe_float(row.get("timestamp_sec"), math.nan) < evaluation_end
    ]
    if not eval_rows:
        eval_rows = timeseries
    bottleneck_mbps = safe_float(metadata.get("bottleneck_mbps"), 15.0)
    configured_avg = safe_float(metadata.get("configured_average_attack_mbps"), math.nan)
    if math.isnan(configured_avg):
        configured_avg_pct = math.nan
    else:
        configured_avg_pct = configured_average_attack_pct(configured_avg, bottleneck_mbps)
    tcp_mbps = mean_field(eval_rows, "tcp_normal_mbps")
    tcp_share = mean_field(eval_rows, "tcp_share_pct")
    attack_share = mean_field(eval_rows, "attack_share_pct")
    idle_share = mean_field(eval_rows, "idle_share_pct")
    return {
        "timestamp": metadata.get("timestamp", ""),
        "case_id": case_id,
        "scenario": metadata.get("scenario", ""),
        "condition_id": metadata.get("condition_id", ""),
        "seed": metadata.get("seed", ""),
        "bottleneck_mbps": bottleneck_mbps,
        "peak_rate_mbps": metadata.get("peak_rate_mbps", ""),
        "burst_ms": metadata.get("burst_ms", ""),
        "period_ms": metadata.get("period_ms", ""),
        "duty_ratio": metadata.get("duty_ratio", ""),
        "configured_average_attack_mbps": configured_avg,
        "configured_average_attack_pct": configured_avg_pct,
        "measured_attack_offered_mbps": mean_field(eval_rows, "attack_offered_mbps"),
        "measured_attack_passed_mbps": mean_field(eval_rows, "attack_passed_mbps"),
        "tcp_baseline_mbps": math.nan,
        "tcp_mbps": tcp_mbps,
        "tcp_degradation_ratio": math.nan,
        "tcp_degradation_pct": math.nan,
        "excess_degradation_vs_random_pct": math.nan,
        "excess_degradation_vs_constant_pct": math.nan,
        "idle_mbps": mean_field(eval_rows, "idle_mbps"),
        "link_utilization_pct": mean_field(eval_rows, "link_utilization_pct"),
        "tcp_share_pct": tcp_share,
        "attack_share_pct": attack_share,
        "other_share_pct": mean_field(eval_rows, "other_share_pct"),
        "idle_share_pct": idle_share,
        "normal_attack_idle_ratio": normal_attack_idle_ratio(tcp_share, attack_share, idle_share)
        if not any(math.isnan(v) for v in [tcp_share, attack_share, idle_share])
        else "",
        "FNR": detector_row.get("FNR", math.nan),
        "FNR_period": detector_row.get("FNR_period", math.nan),
        "FNR_burst": detector_row.get("FNR_burst", math.nan),
        "FPR": detector_row.get("FPR", math.nan),
        "detection_delay_ms": detector_row.get("detection_delay_ms", math.nan),
        "mean_suspicious_score": detector_row.get("mean_suspicious_score", math.nan),
        "status": metadata.get("status", "unknown"),
        "error_message": metadata.get("error_message", ""),
    }


def fill_degradation_columns(case_rows: list[dict[str, Any]]) -> None:
    baseline_by_seed: dict[str, float] = {}
    for row in case_rows:
        if row["scenario"] == "no_attack":
            baseline_by_seed[str(row["seed"])] = safe_float(row.get("tcp_mbps"), math.nan)
    for row in case_rows:
        baseline = baseline_by_seed.get(str(row["seed"]), math.nan)
        tcp = safe_float(row.get("tcp_mbps"), math.nan)
        row["tcp_baseline_mbps"] = baseline
        degradation = tcp_degradation_pct(baseline, tcp)
        row["tcp_degradation_pct"] = degradation
        row["tcp_degradation_ratio"] = degradation / 100.0 if not math.isnan(degradation) else math.nan

    reference: dict[tuple[str, str, str], float] = {}
    for row in case_rows:
        key = (str(row["condition_id"]), str(row["seed"]), str(row["scenario"]))
        reference[key] = safe_float(row.get("tcp_degradation_pct"), math.nan)
    for row in case_rows:
        condition = str(row["condition_id"])
        seed = str(row["seed"])
        degradation = safe_float(row.get("tcp_degradation_pct"), math.nan)
        row["excess_degradation_vs_random_pct"] = excess_degradation_pp(
            degradation, reference.get((condition, seed, "random_microburst"), math.nan)
        )
        row["excess_degradation_vs_constant_pct"] = excess_degradation_pp(
            degradation, reference.get((condition, seed, "constant_udp"), math.nan)
        )


def aggregate_case_metrics(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metric_fields = [
        "tcp_mbps",
        "tcp_degradation_pct",
        "measured_attack_offered_mbps",
        "measured_attack_passed_mbps",
        "idle_mbps",
        "link_utilization_pct",
        "tcp_share_pct",
        "attack_share_pct",
        "idle_share_pct",
        "FNR",
        "FNR_period",
        "FNR_burst",
        "FPR",
        "excess_degradation_vs_random_pct",
        "excess_degradation_vs_constant_pct",
    ]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        groups[(str(row["condition_id"]), str(row["scenario"]))].append(row)

    aggregate_rows: list[dict[str, Any]] = []
    for (condition_id, scenario), rows in sorted(groups.items()):
        out: dict[str, Any] = {
            "condition_id": condition_id,
            "scenario": scenario,
            "n_seeds": len({str(row["seed"]) for row in rows}),
        }
        for metric in metric_fields:
            stats = aggregate_seed_stats(safe_float(row.get(metric), math.nan) for row in rows)
            out[f"{metric}_mean"] = stats["mean"]
            out[f"{metric}_std"] = stats["std"]
            out[f"{metric}_ci95"] = stats["ci95"]
        aggregate_rows.append(out)
    return aggregate_rows


def discover_case_dirs(results_dir: Path) -> list[Path]:
    cases_dir = results_dir / "cases"
    if not cases_dir.exists():
        return []
    return sorted(path for path in cases_dir.iterdir() if path.is_dir() and (path / "metadata_20260610.json").exists())


def main() -> int:
    args = parse_args()
    results_dir: Path = args.results_dir
    csv_dir = results_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    all_timeseries: list[dict[str, Any]] = []
    detector_rows_out: list[dict[str, Any]] = []
    case_rows: list[dict[str, Any]] = []

    for case_dir in discover_case_dirs(results_dir):
        metadata = read_json(case_dir / "metadata_20260610.json")
        case_id = metadata.get("case_id", case_dir.name)
        timeseries, raw_detector_rows = build_case_timeseries(case_dir, metadata, args)
        all_timeseries.extend(timeseries)
        attack_start = safe_float(metadata.get("attack_start_sec"), 0.0)
        duration = safe_float(metadata.get("duration_sec"), 0.0)
        evaluation_start = args.evaluation_start_sec
        if evaluation_start is None:
            evaluation_start = safe_float(metadata.get("evaluation_start_sec"), attack_start + 5.0)
        evaluation_end = args.evaluation_end_sec
        if evaluation_end is None:
            evaluation_end = safe_float(metadata.get("evaluation_end_sec"), duration - 5.0)
        drow = detector_metrics(case_id, metadata, raw_detector_rows, attack_start)
        detector_rows_out.append(drow)
        case_rows.append(case_metrics_from_timeseries(case_id, metadata, timeseries, drow, evaluation_start, evaluation_end))

    add_detector_relative_differences(detector_rows_out)
    fill_degradation_columns(case_rows)
    aggregated_rows = aggregate_case_metrics(case_rows)

    write_csv(csv_dir / "bandwidth_timeseries_20260610.csv", TIMESERIES_FIELDS, all_timeseries)
    write_csv(csv_dir / "case_metrics_20260610.csv", CASE_METRIC_FIELDS, case_rows)
    write_csv(csv_dir / "detector_metrics_20260610.csv", DETECTOR_METRIC_FIELDS, detector_rows_out)
    if aggregated_rows:
        aggregate_fields = list(aggregated_rows[0].keys())
    else:
        aggregate_fields = ["condition_id", "scenario", "n_seeds"]
    write_csv(csv_dir / "aggregated_metrics_20260610.csv", aggregate_fields, aggregated_rows)
    print(f"Wrote CSV outputs to {csv_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
