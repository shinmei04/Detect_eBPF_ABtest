#!/usr/bin/env python3
"""
Analyze the 20260611 TCP=5 Mbps / attack average=5 Mbps LDoS mode.

Primary bandwidth accounting is the s2-side post-bottleneck pcap, receiver
direction only, using IPv4 total length.  The script also writes compact
figures and a ChatGPT upload bundle without pcap or raw tcpdump logs.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import subprocess
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from metrics import aggregate_seed_stats, classify_packet


TIMESERIES_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "timestamp_sec",
    "cycle_index",
    "cycle_phase_ms",
    "pulse_active",
    "tcp_mbps",
    "attack_mbps",
    "attack_offered_mbps",
    "other_ip_mbps",
    "total_ip_mbps",
    "idle_mbps",
    "detector_attack",
    "suspicious_score",
    "rto_event",
    "backoff",
    "cwnd",
]

CASE_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "status",
    "baseline_tcp_mbps",
    "tcp_mbps",
    "attack_passed_mbps",
    "attack_offered_mbps",
    "idle_mbps",
    "total_ip_mbps",
    "utilization_pct",
    "mean_tcp_during_pulse_mbps",
    "mean_attack_during_pulse_mbps",
    "mean_idle_during_pulse_mbps",
    "pulse_saturation_rate",
    "mean_tcp_outside_pulse_mbps",
    "mean_attack_outside_pulse_mbps",
    "mean_idle_outside_pulse_mbps",
    "tcp_degradation_pct",
    "tcp_goodput_loss_mbps",
    "damage_per_attack_mbps",
    "excess_idle_mbps",
    "FNR",
    "FNR_burst",
    "FPR",
    "rto_event_count",
    "max_backoff",
    "mean_cwnd",
    "tcp_rate_match_status",
    "attack_rate_match_status",
    "error_message",
]

CYCLE_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "cycle_index",
    "mean_tcp_mbps",
    "mean_attack_mbps",
    "mean_idle_mbps",
    "tcp_share_pct",
    "attack_share_pct",
    "idle_share_pct",
    "rto_event_count",
    "max_backoff",
    "mean_cwnd",
    "detector_attack_rate",
]

ATTACK_VALIDATION_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "configured_average_attack_mbps",
    "measured_total_attack_offered_mbps",
    "measured_total_attack_passed_mbps",
    "measured_pulse_attack_passed_mbps",
    "attack_rate_error_pct",
    "attack_rate_match_status",
]

TCP_VALIDATION_FIELDS = [
    "case_id",
    "seed",
    "target_tcp_mbps",
    "iperf_tcp_receiver_mbps",
    "pcap_tcp_mbps",
    "tcp_rate_error_pct",
    "tcp_rate_match_status",
]

DETECTOR_FIELDS = [
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
    "FNR_burst",
    "FPR",
    "detection_delay_ms",
    "mean_suspicious_score",
]

RTO_FIELDS = [
    "rto_event_id",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "timestamp_sec",
    "backoff",
    "rto_ms",
    "retransmits",
    "total_retrans",
    "cwnd",
    "pulse_active",
]

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--bucket-ms", type=float, default=25.0)
    parser.add_argument("--bottleneck-mbps", type=float, default=15.0)
    parser.add_argument("--evaluation-start-sec", type=float, required=True)
    parser.add_argument("--evaluation-end-sec", type=float, required=True)
    parser.add_argument("--tcp-target-mbps", type=float, default=5.0)
    parser.add_argument("--attack-target-mbps", type=float, default=5.0)
    parser.add_argument("--output-tag", default="20260611")
    parser.add_argument("--mode", default="")
    return parser.parse_args()


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


def format_value(value: Any) -> Any:
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:.9g}"
    return value


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: format_value(row.get(field, "")) for field in fields})


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def mean(values: Iterable[float]) -> float:
    vals = [value for value in values if not math.isnan(value)]
    return sum(vals) / len(vals) if vals else math.nan


def bucket_start(timestamp_sec: float, bucket_sec: float) -> float:
    return math.floor((timestamp_sec + 1e-12) / bucket_sec) * bucket_sec


def mbps_from_bytes(byte_count: float, bucket_sec: float) -> float:
    return 8.0 * byte_count / bucket_sec / 1_000_000.0 if bucket_sec > 0 else math.nan


def read_iperf_receiver_mbps(case_dir: Path, tag: str) -> float:
    path = case_dir / "raw" / "iperf" / f"iperf_client_{tag}.json"
    if not path.exists():
        return math.nan
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return math.nan
    end = data.get("end", {})
    candidates = [
        end.get("sum_received", {}).get("bits_per_second"),
        end.get("sum", {}).get("bits_per_second"),
    ]
    streams = end.get("streams") or []
    if streams:
        candidates.append(streams[0].get("receiver", {}).get("bits_per_second"))
    for value in candidates:
        if value is not None:
            return safe_float(value) / 1_000_000.0
    return math.nan


def parse_tcpdump_records(lines: Iterable[str], time_origin_sec: float) -> Iterable[dict[str, Any]]:
    pending: dict[str, Any] | None = None
    for line in lines:
        header = TCPDUMP_HEADER_RE.match(line.rstrip())
        if header:
            pending = {
                "timestamp_sec": safe_float(header.group("ts")) - time_origin_sec,
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
        yield {
            "timestamp_sec": pending["timestamp_sec"],
            "proto": proto,
            "src_ip": detail.group("src_ip"),
            "dst_ip": detail.group("dst_ip"),
            "src_port": safe_int(detail.group("src_port")),
            "dst_port": safe_int(detail.group("dst_port")),
            "payload_bytes": safe_int(detail.group("payload_len"), 0),
            "wire_bytes": pending["ip_len"],
        }
        pending = None


def read_pcap_packets(pcap_path: Path, metadata: dict[str, Any], capture: str) -> list[dict[str, Any]]:
    if not pcap_path.exists():
        return []
    proc = subprocess.run(
        ["tcpdump", "-tt", "-e", "-n", "-vv", "-r", str(pcap_path), "ip"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"tcpdump failed for {pcap_path}: {proc.stderr.strip()}")
    origin = safe_float(metadata.get("experiment_start_wall"), math.nan)
    if math.isnan(origin):
        origin = safe_float(metadata.get("case_start_epoch_ns"), 0.0) / 1_000_000_000.0
    receiver_ip = str(metadata.get("receiver_ip", "10.0.0.2"))
    rows: list[dict[str, Any]] = []
    for packet in parse_tcpdump_records(proc.stdout.splitlines(), origin):
        if capture == "egress" and packet["dst_ip"] != receiver_ip:
            continue
        packet_class = classify_packet(
            packet,
            tcp_sender_ip=str(metadata.get("tcp_sender_ip", "10.0.0.1")),
            receiver_ip=receiver_ip,
            attacker_ips=list(metadata.get("attacker_ips", ["10.0.0.3", "10.0.0.4"])),
            iperf_port=safe_int(metadata.get("iperf_port"), 5201),
            attack_udp_port=safe_int(metadata.get("attack_udp_port"), 5001),
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


def read_packet_rows(case_dir: Path, metadata: dict[str, Any], tag: str) -> list[dict[str, Any]]:
    synthetic = case_dir / "raw" / f"synthetic_packets_{tag}.csv"
    if synthetic.exists():
        return [dict(row) for row in read_csv(synthetic)]
    rows: list[dict[str, Any]] = []
    ingress = metadata.get("capture_ingress_pcap")
    egress = metadata.get("capture_egress_pcap")
    if ingress:
        rows.extend(read_pcap_packets(Path(ingress), metadata, "ingress"))
    if egress:
        rows.extend(read_pcap_packets(Path(egress), metadata, "egress"))
    return rows


def detector_by_bucket(case_dir: Path, tag: str, bucket_sec: float) -> tuple[dict[float, dict[str, str]], list[dict[str, str]]]:
    rows = read_csv(case_dir / "raw" / "detector" / f"detector_windows_{tag}.csv")
    by_bucket: dict[float, dict[str, str]] = {}
    for row in rows:
        ts = safe_float(row.get("timestamp_sec", row.get("window_start_sec")), 0.0)
        by_bucket[round(bucket_start(ts, bucket_sec), 9)] = row
    return by_bucket, rows


def read_pulses(case_dir: Path, tag: str) -> list[dict[str, str]]:
    return read_csv(case_dir / "raw" / "pulses" / f"attack_pulses_{tag}.csv")


def pulse_active_at(ts: float, pulses: list[dict[str, str]], metadata: dict[str, Any]) -> bool:
    scenario = str(metadata.get("scenario", ""))
    if scenario == "no_attack":
        return False
    for pulse in pulses:
        start = safe_float(pulse.get("pulse_start_sec"))
        end = safe_float(pulse.get("pulse_end_sec"))
        if start <= ts < end:
            return True
    if scenario == "constant_udp":
        return ts >= safe_float(metadata.get("attack_start_sec"), 0.0)
    return False


def read_tcp_info_rows(case_dir: Path, metadata: dict[str, Any], tag: str, bucket_sec: float) -> tuple[dict[float, dict[str, Any]], list[dict[str, Any]]]:
    case_id = str(metadata.get("case_id", case_dir.name))
    path = case_dir / "raw" / "tcp_info" / case_id / f"tcp_info_timeseries_{tag}.csv"
    rows = read_csv(path)
    receiver_ip = str(metadata.get("receiver_ip", "10.0.0.2"))
    receiver_port = str(metadata.get("iperf_port", 5201))
    valid = [
        row
        for row in rows
        if str(row.get("destination_ip")) == receiver_ip and str(row.get("destination_port")) == receiver_port
    ]
    by_bucket: dict[float, dict[str, Any]] = {}
    prev_total_retrans = 0
    event_id = 0
    rto_events: list[dict[str, Any]] = []
    for row in valid:
        ts = safe_float(row.get("timestamp_sec"))
        if math.isnan(ts):
            continue
        key = round(bucket_start(ts, bucket_sec), 9)
        backoff = safe_int(row.get("backoff"), 0)
        total_retrans = safe_int(row.get("total_retrans"), prev_total_retrans)
        retransmits = safe_int(row.get("retransmits"), 0)
        rto_event = int(backoff > 0 or total_retrans > prev_total_retrans or retransmits > 0)
        if rto_event:
            event_id += 1
            rto_events.append(
                {
                    "rto_event_id": event_id,
                    "case_id": case_id,
                    "scenario": metadata.get("scenario", ""),
                    "condition_id": metadata.get("condition_id", ""),
                    "seed": metadata.get("seed", ""),
                    "timestamp_sec": ts,
                    "backoff": backoff,
                    "rto_ms": safe_float(row.get("rto_ms")),
                    "retransmits": retransmits,
                    "total_retrans": total_retrans,
                    "cwnd": safe_float(row.get("cwnd")),
                    "pulse_active": "",
                }
            )
        prev_total_retrans = max(prev_total_retrans, total_retrans)
        current = by_bucket.setdefault(key, {"backoff": 0, "cwnd_values": [], "rto_event": 0})
        current["backoff"] = max(safe_int(current.get("backoff"), 0), backoff)
        cwnd = safe_float(row.get("cwnd"))
        if not math.isnan(cwnd):
            current["cwnd_values"].append(cwnd)
        current["rto_event"] = max(safe_int(current.get("rto_event"), 0), rto_event)
    for value in by_bucket.values():
        value["cwnd"] = mean(value.pop("cwnd_values", []))
    return by_bucket, rto_events


def detector_metrics(case_id: str, metadata: dict[str, Any], detector_rows: list[dict[str, str]]) -> dict[str, Any]:
    attack_rows = [row for row in detector_rows if safe_int(row.get("attack_active"), 0) == 1]
    burst_rows = [row for row in detector_rows if safe_int(row.get("attack_burst_active"), 0) == 1]
    normal_rows = [row for row in detector_rows if safe_int(row.get("attack_active"), 0) == 0]

    def detected(row: dict[str, str]) -> bool:
        return safe_float(row.get("detector_attack", row.get("is_attack", 0)), 0.0) >= 1.0

    def fnr(rows: list[dict[str, str]]) -> float:
        if not rows:
            return math.nan
        return sum(1 for row in rows if not detected(row)) / len(rows)

    detected_attack = sum(1 for row in attack_rows if detected(row))
    detected_burst = sum(1 for row in burst_rows if detected(row))
    false_positive = sum(1 for row in normal_rows if detected(row))
    detection_times = [
        safe_float(row.get("timestamp_sec", row.get("window_start_sec")))
        for row in attack_rows
        if detected(row)
    ]
    detection_times = [value for value in detection_times if not math.isnan(value)]
    attack_start = safe_float(metadata.get("attack_start_sec"), 0.0)
    return {
        "case_id": case_id,
        "scenario": metadata.get("scenario", ""),
        "condition_id": metadata.get("condition_id", ""),
        "seed": metadata.get("seed", ""),
        "attack_windows": len(attack_rows),
        "detected_attack_windows": detected_attack,
        "missed_attack_windows": len(attack_rows) - detected_attack,
        "burst_attack_windows": len(burst_rows),
        "detected_burst_windows": detected_burst,
        "missed_burst_windows": len(burst_rows) - detected_burst,
        "FNR": fnr(attack_rows),
        "FNR_burst": fnr(burst_rows),
        "FPR": false_positive / len(normal_rows) if normal_rows else math.nan,
        "detection_delay_ms": (min(detection_times) - attack_start) * 1000.0 if detection_times else math.nan,
        "mean_suspicious_score": mean(safe_float(row.get("suspicious_score")) for row in detector_rows),
    }


def build_timeseries(case_dir: Path, metadata: dict[str, Any], args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    bucket_sec = args.bucket_ms / 1000.0
    duration_sec = safe_float(metadata.get("duration_sec"), 0.0)
    attack_start = safe_float(metadata.get("attack_start_sec"), 0.0)
    period_ms = safe_float(metadata.get("period_ms"), 1000.0)
    period_sec = period_ms / 1000.0 if period_ms > 0 else 1.0
    case_id = str(metadata.get("case_id", case_dir.name))

    buckets: dict[float, dict[str, float]] = defaultdict(lambda: {"tcp": 0.0, "attack": 0.0, "attack_offered": 0.0, "other": 0.0})
    for packet in read_packet_rows(case_dir, metadata, args.output_tag):
        ts = safe_float(packet.get("timestamp_sec"))
        if math.isnan(ts):
            continue
        key = round(bucket_start(ts, bucket_sec), 9)
        packet_class = str(packet.get("class", "other"))
        capture = str(packet.get("capture", "egress"))
        byte_count = safe_float(packet.get("bytes"), 0.0)
        if capture == "ingress" and packet_class == "attack":
            buckets[key]["attack_offered"] += byte_count
        elif capture == "egress" and packet_class == "attack":
            buckets[key]["attack"] += byte_count
        elif capture == "egress" and packet_class == "tcp_normal":
            buckets[key]["tcp"] += byte_count
        elif capture == "egress":
            buckets[key]["other"] += byte_count
    for step in range(int(math.ceil(duration_sec / bucket_sec))):
        buckets.setdefault(round(step * bucket_sec, 9), {"tcp": 0.0, "attack": 0.0, "attack_offered": 0.0, "other": 0.0})

    detector_map, detector_rows = detector_by_bucket(case_dir, args.output_tag, bucket_sec)
    tcp_info_map, rto_events = read_tcp_info_rows(case_dir, metadata, args.output_tag, bucket_sec)
    pulses = read_pulses(case_dir, args.output_tag)
    rows: list[dict[str, Any]] = []
    for key in sorted(buckets):
        stats = buckets[key]
        tcp = mbps_from_bytes(stats["tcp"], bucket_sec)
        attack = mbps_from_bytes(stats["attack"], bucket_sec)
        attack_offered = mbps_from_bytes(stats["attack_offered"], bucket_sec)
        other = mbps_from_bytes(stats["other"], bucket_sec)
        total = tcp + attack + other
        idle = max(args.bottleneck_mbps - total, 0.0)
        in_attack_period = key >= attack_start
        cycle_index = int(math.floor((key - attack_start) / period_sec)) if in_attack_period else -1
        cycle_phase_ms = ((key - attack_start) * 1000.0) % period_ms if in_attack_period else math.nan
        pulse_active = int(pulse_active_at(key, pulses, metadata))
        detector = detector_map.get(key, {})
        tcp_info = tcp_info_map.get(key, {})
        rows.append(
            {
                "case_id": case_id,
                "scenario": metadata.get("scenario", ""),
                "condition_id": metadata.get("condition_id", ""),
                "seed": metadata.get("seed", ""),
                "timestamp_sec": key,
                "cycle_index": cycle_index,
                "cycle_phase_ms": cycle_phase_ms,
                "pulse_active": pulse_active,
                "tcp_mbps": tcp,
                "attack_mbps": attack,
                "attack_offered_mbps": attack_offered,
                "other_ip_mbps": other,
                "total_ip_mbps": total,
                "idle_mbps": idle,
                "detector_attack": int(safe_float(detector.get("detector_attack", 0), 0.0) >= 1.0),
                "suspicious_score": safe_float(detector.get("suspicious_score"), 0.0),
                "rto_event": safe_int(tcp_info.get("rto_event"), 0),
                "backoff": safe_int(tcp_info.get("backoff"), 0),
                "cwnd": safe_float(tcp_info.get("cwnd")),
            }
        )
    for event in rto_events:
        event["pulse_active"] = int(pulse_active_at(safe_float(event.get("timestamp_sec")), pulses, metadata))
    return rows, detector_metrics(case_id, metadata, detector_rows), rto_events


def eval_rows(rows: list[dict[str, Any]], start: float, end: float) -> list[dict[str, Any]]:
    selected = [row for row in rows if start <= safe_float(row.get("timestamp_sec")) < end]
    return selected or rows


def validation_status(error_pct: float) -> str:
    if math.isnan(error_pct):
        return "failed"
    if abs(error_pct) <= 5.0:
        return "matched"
    if abs(error_pct) <= 10.0:
        return "warning"
    return "failed"


def build_cycle_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        idx = safe_int(row.get("cycle_index"), -1)
        if idx >= 0:
            groups[(str(row.get("case_id")), idx)].append(row)
    out: list[dict[str, Any]] = []
    for (_case_id, cycle_index), group in sorted(groups.items()):
        tcp = mean(safe_float(row.get("tcp_mbps")) for row in group)
        attack = mean(safe_float(row.get("attack_mbps")) for row in group)
        idle = mean(safe_float(row.get("idle_mbps")) for row in group)
        total = tcp + attack + idle
        first = group[0]
        out.append(
            {
                "case_id": first.get("case_id", ""),
                "scenario": first.get("scenario", ""),
                "condition_id": first.get("condition_id", ""),
                "seed": first.get("seed", ""),
                "cycle_index": cycle_index,
                "mean_tcp_mbps": tcp,
                "mean_attack_mbps": attack,
                "mean_idle_mbps": idle,
                "tcp_share_pct": 100.0 * tcp / total if total > 0 else math.nan,
                "attack_share_pct": 100.0 * attack / total if total > 0 else math.nan,
                "idle_share_pct": 100.0 * idle / total if total > 0 else math.nan,
                "rto_event_count": sum(safe_int(row.get("rto_event"), 0) for row in group),
                "max_backoff": max((safe_int(row.get("backoff"), 0) for row in group), default=0),
                "mean_cwnd": mean(safe_float(row.get("cwnd")) for row in group),
                "detector_attack_rate": mean(safe_float(row.get("detector_attack"), 0.0) for row in group),
            }
        )
    return out


def build_case_outputs(
    case_dir: Path,
    metadata: dict[str, Any],
    rows: list[dict[str, Any]],
    detector_row: dict[str, Any],
    rto_events: list[dict[str, Any]],
    args: argparse.Namespace,
    baseline_by_seed: dict[str, float],
    no_attack_idle_by_seed: dict[str, float],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    selected = eval_rows(rows, args.evaluation_start_sec, args.evaluation_end_sec)
    pulse_rows = [row for row in selected if safe_int(row.get("pulse_active"), 0) == 1]
    outside_rows = [row for row in selected if safe_int(row.get("pulse_active"), 0) == 0]
    seed = str(metadata.get("seed", ""))
    scenario = str(metadata.get("scenario", ""))
    tcp_mbps = mean(safe_float(row.get("tcp_mbps")) for row in selected)
    attack_passed = mean(safe_float(row.get("attack_mbps")) for row in selected)
    attack_offered = mean(safe_float(row.get("attack_offered_mbps")) for row in selected)
    idle_mbps = mean(safe_float(row.get("idle_mbps")) for row in selected)
    total_ip = mean(safe_float(row.get("total_ip_mbps")) for row in selected)
    baseline = baseline_by_seed.get(seed, math.nan)
    no_attack_idle = no_attack_idle_by_seed.get(seed, math.nan)
    loss = baseline - tcp_mbps if not any(math.isnan(x) for x in [baseline, tcp_mbps]) else math.nan
    degradation = 100.0 * loss / baseline if baseline > 0 and not math.isnan(loss) else math.nan
    excess_idle = idle_mbps - no_attack_idle if not any(math.isnan(x) for x in [idle_mbps, no_attack_idle]) else math.nan
    attack_error = 100.0 * (attack_passed - args.attack_target_mbps) / args.attack_target_mbps if scenario != "no_attack" else math.nan
    attack_status = validation_status(attack_error) if scenario != "no_attack" else ""
    iperf_tcp = read_iperf_receiver_mbps(case_dir, args.output_tag)
    tcp_error = 100.0 * (iperf_tcp - args.tcp_target_mbps) / args.tcp_target_mbps if scenario == "no_attack" else math.nan
    tcp_status = validation_status(tcp_error) if scenario == "no_attack" else ""
    case_row = {
        "case_id": metadata.get("case_id", case_dir.name),
        "scenario": scenario,
        "condition_id": metadata.get("condition_id", ""),
        "seed": seed,
        "status": metadata.get("status", "unknown"),
        "baseline_tcp_mbps": baseline,
        "tcp_mbps": tcp_mbps,
        "attack_passed_mbps": attack_passed,
        "attack_offered_mbps": attack_offered,
        "idle_mbps": idle_mbps,
        "total_ip_mbps": total_ip,
        "utilization_pct": 100.0 * total_ip / args.bottleneck_mbps if args.bottleneck_mbps > 0 else math.nan,
        "mean_tcp_during_pulse_mbps": mean(safe_float(row.get("tcp_mbps")) for row in pulse_rows),
        "mean_attack_during_pulse_mbps": mean(safe_float(row.get("attack_mbps")) for row in pulse_rows),
        "mean_idle_during_pulse_mbps": mean(safe_float(row.get("idle_mbps")) for row in pulse_rows),
        "pulse_saturation_rate": mean(1.0 if safe_float(row.get("total_ip_mbps")) >= args.bottleneck_mbps * 0.95 else 0.0 for row in pulse_rows),
        "mean_tcp_outside_pulse_mbps": mean(safe_float(row.get("tcp_mbps")) for row in outside_rows),
        "mean_attack_outside_pulse_mbps": mean(safe_float(row.get("attack_mbps")) for row in outside_rows),
        "mean_idle_outside_pulse_mbps": mean(safe_float(row.get("idle_mbps")) for row in outside_rows),
        "tcp_degradation_pct": degradation,
        "tcp_goodput_loss_mbps": loss,
        "damage_per_attack_mbps": loss / attack_passed if attack_passed > 0 and not math.isnan(loss) else math.nan,
        "excess_idle_mbps": excess_idle,
        "FNR": detector_row.get("FNR", math.nan),
        "FNR_burst": detector_row.get("FNR_burst", math.nan),
        "FPR": detector_row.get("FPR", math.nan),
        "rto_event_count": len(rto_events),
        "max_backoff": max((safe_int(row.get("backoff"), 0) for row in selected), default=0),
        "mean_cwnd": mean(safe_float(row.get("cwnd")) for row in selected),
        "tcp_rate_match_status": tcp_status,
        "attack_rate_match_status": attack_status,
        "error_message": metadata.get("error_message", ""),
    }
    attack_row = {
        "case_id": case_row["case_id"],
        "scenario": scenario,
        "condition_id": case_row["condition_id"],
        "seed": seed,
        "configured_average_attack_mbps": safe_float(metadata.get("configured_average_attack_mbps"), args.attack_target_mbps),
        "measured_total_attack_offered_mbps": attack_offered,
        "measured_total_attack_passed_mbps": attack_passed,
        "measured_pulse_attack_passed_mbps": case_row["mean_attack_during_pulse_mbps"],
        "attack_rate_error_pct": attack_error,
        "attack_rate_match_status": attack_status,
    }
    tcp_row = {
        "case_id": case_row["case_id"],
        "seed": seed,
        "target_tcp_mbps": args.tcp_target_mbps,
        "iperf_tcp_receiver_mbps": iperf_tcp,
        "pcap_tcp_mbps": tcp_mbps,
        "tcp_rate_error_pct": tcp_error,
        "tcp_rate_match_status": tcp_status,
    }
    return case_row, attack_row, tcp_row


def aggregate_rows(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics = [
        "tcp_mbps",
        "attack_passed_mbps",
        "attack_offered_mbps",
        "idle_mbps",
        "total_ip_mbps",
        "utilization_pct",
        "mean_tcp_during_pulse_mbps",
        "mean_attack_during_pulse_mbps",
        "mean_idle_during_pulse_mbps",
        "mean_tcp_outside_pulse_mbps",
        "mean_attack_outside_pulse_mbps",
        "mean_idle_outside_pulse_mbps",
        "tcp_degradation_pct",
        "tcp_goodput_loss_mbps",
        "damage_per_attack_mbps",
        "excess_idle_mbps",
        "FNR",
        "FNR_burst",
        "FPR",
        "rto_event_count",
        "max_backoff",
        "mean_cwnd",
    ]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        groups[(str(row.get("condition_id", "")), str(row.get("scenario", "")))].append(row)
    output: list[dict[str, Any]] = []
    for (condition_id, scenario), group in sorted(groups.items()):
        out: dict[str, Any] = {
            "condition_id": condition_id,
            "scenario": scenario,
            "n_cases": len(group),
            "n_seeds": len({str(row.get("seed", "")) for row in group}),
        }
        for metric in metrics:
            stats = aggregate_seed_stats(safe_float(row.get(metric), math.nan) for row in group)
            out[f"{metric}_mean"] = stats["mean"]
            out[f"{metric}_std"] = stats["std"]
            out[f"{metric}_ci95"] = stats["ci95"]
        output.append(out)
    return output


def discover_cases(results_dir: Path, tag: str) -> list[tuple[Path, dict[str, Any]]]:
    cases_dir = results_dir / "cases"
    if not cases_dir.exists():
        return []
    out: list[tuple[Path, dict[str, Any]]] = []
    for case_dir in sorted(path for path in cases_dir.iterdir() if path.is_dir()):
        meta = case_dir / f"metadata_{tag}.json"
        if meta.exists():
            out.append((case_dir, read_json(meta)))
    return out


def get_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def save_figure(plt: Any, base: Path) -> None:
    if plt is None:
        return
    base.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(base.with_suffix(".png"), dpi=180)
    plt.savefig(base.with_suffix(".pdf"))
    plt.close()


def first_case_rows(timeseries: list[dict[str, Any]], scenario: str) -> list[dict[str, Any]]:
    ids = sorted({str(row.get("case_id")) for row in timeseries if row.get("scenario") == scenario})
    if not ids:
        return []
    return [row for row in timeseries if row.get("case_id") == ids[0]]


def write_figures(results_dir: Path, timeseries: list[dict[str, Any]], cycle_rows: list[dict[str, Any]], case_rows: list[dict[str, Any]], attack_rows: list[dict[str, Any]], tag: str) -> list[Path]:
    plt = get_matplotlib()
    if plt is None:
        return []
    figures = results_dir / "figures"
    paths: list[Path] = []

    rows = first_case_rows(timeseries, "periodic_ldos") or first_case_rows(timeseries, "random_microburst") or timeseries[:]
    if rows:
        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        x = [safe_float(row["timestamp_sec"]) for row in rows]
        ax.plot(x, [safe_float(row["tcp_mbps"]) for row in rows], label="TCP", color="#4C78A8", linewidth=1.0)
        ax.plot(x, [safe_float(row["attack_mbps"]) for row in rows], label="Attack", color="#E45756", linewidth=1.0)
        ax.plot(x, [safe_float(row["idle_mbps"]) for row in rows], label="Idle", color="#BAB0AC", linewidth=1.0)
        ax.set_title("25 ms bandwidth timeseries")
        ax.set_xlabel("time [s]")
        ax.set_ylabel("Mbps")
        ax.legend(frameon=False, ncol=3)
        ax.grid(alpha=0.25)
        base = figures / f"01_25ms_bandwidth_timeseries_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

    phase_groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in timeseries:
        phase = safe_float(row.get("cycle_phase_ms"))
        if not math.isnan(phase) and safe_int(row.get("cycle_index"), -1) >= 0:
            phase_groups[(str(row.get("scenario")), int(round(phase / 25.0)))].append(row)
    if phase_groups:
        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        for scenario, color in [
            ("constant_udp", "#4C78A8"),
            ("periodic_ldos", "#F58518"),
            ("random_microburst", "#54A24B"),
            ("stat_matched_ldos", "#B279A2"),
        ]:
            xs = []
            ys = []
            for idx in sorted({key[1] for key in phase_groups if key[0] == scenario}):
                group = phase_groups[(scenario, idx)]
                xs.append(idx * 25.0)
                ys.append(mean(safe_float(row.get("tcp_mbps")) for row in group))
            if xs:
                ax.plot(xs, ys, label=scenario, color=color)
        ax.set_title("Cycle phase average TCP throughput")
        ax.set_xlabel("cycle phase [ms]")
        ax.set_ylabel("TCP Mbps")
        ax.legend(frameon=False, ncol=2)
        ax.grid(alpha=0.25)
        base = figures / f"02_cycle_phase_average_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

    cycle_sample = [row for row in cycle_rows if row.get("scenario") == "periodic_ldos"]
    if cycle_sample:
        first_id = sorted({str(row.get("case_id")) for row in cycle_sample})[0]
        cycle_sample = [row for row in cycle_sample if row.get("case_id") == first_id]
        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        x = [safe_int(row.get("cycle_index")) for row in cycle_sample]
        tcp = [safe_float(row.get("mean_tcp_mbps")) for row in cycle_sample]
        attack = [safe_float(row.get("mean_attack_mbps")) for row in cycle_sample]
        idle = [safe_float(row.get("mean_idle_mbps")) for row in cycle_sample]
        ax.bar(x, tcp, label="TCP", color="#4C78A8")
        ax.bar(x, attack, bottom=tcp, label="Attack", color="#E45756")
        ax.bar(x, idle, bottom=[a + b for a, b in zip(tcp, attack)], label="Idle", color="#BAB0AC")
        ax.set_title("Per-cycle TCP/Attack/Idle stack")
        ax.set_xlabel("cycle index")
        ax.set_ylabel("Mbps")
        ax.legend(frameon=False, ncol=3)
        base = figures / f"03_per_cycle_stack_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

    scenario_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        scenario_groups[str(row.get("scenario"))].append(row)
    scenarios = [name for name in ["no_attack", "constant_udp", "periodic_ldos", "random_microburst", "stat_matched_ldos"] if name in scenario_groups]
    if scenarios:
        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        tcp = [mean(safe_float(row.get("tcp_mbps")) for row in scenario_groups[s]) for s in scenarios]
        attack = [mean(safe_float(row.get("attack_passed_mbps")) for row in scenario_groups[s]) for s in scenarios]
        idle = [mean(safe_float(row.get("idle_mbps")) for row in scenario_groups[s]) for s in scenarios]
        x = list(range(len(scenarios)))
        ax.bar(x, tcp, label="TCP", color="#4C78A8")
        ax.bar(x, attack, bottom=tcp, label="Attack", color="#E45756")
        ax.bar(x, idle, bottom=[a + b for a, b in zip(tcp, attack)], label="Idle", color="#BAB0AC")
        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, rotation=20, ha="right")
        ax.set_title("Scenario mean bandwidth breakdown")
        ax.set_ylabel("Mbps")
        ax.legend(frameon=False, ncol=3)
        base = figures / f"04_scenario_bandwidth_breakdown_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        deg = [mean(safe_float(row.get("tcp_degradation_pct")) for row in scenario_groups[s]) for s in scenarios if s != "no_attack"]
        labels = [s for s in scenarios if s != "no_attack"]
        ax.bar(labels, deg, color="#F58518")
        ax.set_title("TCP degradation vs same-seed no_attack")
        ax.set_ylabel("degradation [%]")
        ax.tick_params(axis="x", rotation=20)
        ax.grid(axis="y", alpha=0.25)
        base = figures / f"05_tcp_degradation_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        labels = [s for s in scenarios if s != "no_attack"]
        pulse_tcp = [mean(safe_float(row.get("mean_tcp_during_pulse_mbps")) for row in scenario_groups[s]) for s in labels]
        outside_tcp = [mean(safe_float(row.get("mean_tcp_outside_pulse_mbps")) for row in scenario_groups[s]) for s in labels]
        x = list(range(len(labels)))
        ax.bar([i - 0.18 for i in x], pulse_tcp, width=0.36, label="Pulse", color="#E45756")
        ax.bar([i + 0.18 for i in x], outside_tcp, width=0.36, label="Outside", color="#4C78A8")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_title("TCP during pulse vs outside pulse")
        ax.set_ylabel("TCP Mbps")
        ax.legend(frameon=False)
        ax.grid(axis="y", alpha=0.25)
        base = figures / f"06_pulse_outside_comparison_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

    if rows:
        fig, ax1 = plt.subplots(figsize=(10.5, 4.8))
        x = [safe_float(row["timestamp_sec"]) for row in rows]
        ax1.plot(x, [safe_float(row.get("cwnd")) for row in rows], label="cwnd", color="#4C78A8")
        ax1.fill_between(x, 0, [2.0 if safe_int(row.get("pulse_active")) else 0.0 for row in rows], color="#E45756", alpha=0.18, label="pulse")
        ax1.scatter([safe_float(row["timestamp_sec"]) for row in rows if safe_int(row.get("rto_event"))], [0 for row in rows if safe_int(row.get("rto_event"))], color="#111111", s=18, label="RTO event")
        ax1.set_title("RTO / cwnd / pulse integrated timeline")
        ax1.set_xlabel("time [s]")
        ax1.set_ylabel("cwnd")
        ax1.legend(frameon=False, ncol=3)
        ax1.grid(alpha=0.25)
        base = figures / f"07_rto_cwnd_pulse_timeline_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))

    if attack_rows:
        fig, ax = plt.subplots(figsize=(10.5, 4.8))
        rows_no_base = [row for row in attack_rows if row.get("scenario") != "no_attack"]
        labels = [str(row.get("scenario")) for row in rows_no_base]
        configured = [safe_float(row.get("configured_average_attack_mbps")) for row in rows_no_base]
        offered = [safe_float(row.get("measured_total_attack_offered_mbps")) for row in rows_no_base]
        passed = [safe_float(row.get("measured_total_attack_passed_mbps")) for row in rows_no_base]
        x = list(range(len(labels)))
        ax.bar([i - 0.25 for i in x], configured, width=0.25, label="configured", color="#BAB0AC")
        ax.bar(x, offered, width=0.25, label="offered", color="#F58518")
        ax.bar([i + 0.25 for i in x], passed, width=0.25, label="passed", color="#54A24B")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=25, ha="right")
        ax.set_title("Configured / offered / passed attack rate")
        ax.set_ylabel("Mbps")
        ax.legend(frameon=False, ncol=3)
        ax.grid(axis="y", alpha=0.25)
        base = figures / f"08_attack_rate_validation_{tag}"
        save_figure(plt, base)
        paths.append(base.with_suffix(".png"))
    return paths


def write_summary(
    results_dir: Path,
    case_rows: list[dict[str, Any]],
    attack_rows: list[dict[str, Any]],
    tcp_rows: list[dict[str, Any]],
    detector_rows: list[dict[str, Any]],
    rto_rows: list[dict[str, Any]],
    failed_cases: list[str],
    args: argparse.Namespace,
) -> Path:
    path = results_dir / "summary_for_chatgpt_20260611.md"
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        groups[str(row.get("scenario"))].append(row)
    lines = [
        "# TCP5 / Attack5 LDoS experiment summary 20260611",
        "",
        "## Config",
        "",
        f"- bottleneck: {args.bottleneck_mbps} Mbps",
        f"- normal TCP target: {args.tcp_target_mbps} Mbps, 1 flow, iperf3 bitrate",
        "- attack peak: 15 Mbps",
        "- attack average: about 5 Mbps",
        "- period: 1000 ms",
        "- burst length: 333.333 ms",
        f"- bucket: {args.bucket_ms} ms",
        f"- evaluation: {args.evaluation_start_sec} <= t < {args.evaluation_end_sec}",
        "- primary bandwidth metric: s2-side pcap, receiver direction, IPv4 total length",
        "",
        "## Scenario Means",
        "",
        "| scenario | n | TCP Mbps | attack Mbps | idle Mbps | TCP degradation % | pulse TCP | pulse attack | pulse idle | outside TCP | outside idle | FNR % | FPR % | RTO events |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for scenario in ["no_attack", "constant_udp", "periodic_ldos", "random_microburst", "stat_matched_ldos"]:
        group = groups.get(scenario, [])
        if not group:
            continue
        lines.append(
            "| {scenario} | {n} | {tcp:.2f} | {attack:.2f} | {idle:.2f} | {deg:.2f} | {ptcp:.2f} | {pattack:.2f} | {pidle:.2f} | {otcp:.2f} | {oidle:.2f} | {fnr:.2f} | {fpr:.2f} | {rto:.1f} |".format(
                scenario=scenario,
                n=len(group),
                tcp=mean(safe_float(row.get("tcp_mbps")) for row in group),
                attack=mean(safe_float(row.get("attack_passed_mbps")) for row in group),
                idle=mean(safe_float(row.get("idle_mbps")) for row in group),
                deg=mean(safe_float(row.get("tcp_degradation_pct")) for row in group),
                ptcp=mean(safe_float(row.get("mean_tcp_during_pulse_mbps")) for row in group),
                pattack=mean(safe_float(row.get("mean_attack_during_pulse_mbps")) for row in group),
                pidle=mean(safe_float(row.get("mean_idle_during_pulse_mbps")) for row in group),
                otcp=mean(safe_float(row.get("mean_tcp_outside_pulse_mbps")) for row in group),
                oidle=mean(safe_float(row.get("mean_idle_outside_pulse_mbps")) for row in group),
                fnr=100.0 * mean(safe_float(row.get("FNR")) for row in group),
                fpr=100.0 * mean(safe_float(row.get("FPR")) for row in group),
                rto=mean(safe_float(row.get("rto_event_count")) for row in group),
            )
        )
    lines.extend(
        [
            "",
            "## TCP validation",
            "",
            "| case | seed | target | iperf receiver | pcap TCP | error % | status |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in tcp_rows:
        lines.append(
            f"| {row.get('case_id')} | {row.get('seed')} | {format_value(row.get('target_tcp_mbps'))} | {format_value(row.get('iperf_tcp_receiver_mbps'))} | {format_value(row.get('pcap_tcp_mbps'))} | {format_value(row.get('tcp_rate_error_pct'))} | {row.get('tcp_rate_match_status')} |"
        )
    lines.extend(
        [
            "",
            "## Attack validation",
            "",
            "| case | scenario | configured | offered | passed | pulse passed | error % | status |",
            "|---|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for row in attack_rows:
        if row.get("scenario") == "no_attack":
            continue
        lines.append(
            f"| {row.get('case_id')} | {row.get('scenario')} | {format_value(row.get('configured_average_attack_mbps'))} | {format_value(row.get('measured_total_attack_offered_mbps'))} | {format_value(row.get('measured_total_attack_passed_mbps'))} | {format_value(row.get('measured_pulse_attack_passed_mbps'))} | {format_value(row.get('attack_rate_error_pct'))} | {row.get('attack_rate_match_status')} |"
        )
    lines.extend(
        [
            "",
            "## RTO and detector",
            "",
            f"- RTO event rows: {len(rto_rows)}",
            f"- failed cases: {len(failed_cases)}",
        ]
    )
    if failed_cases:
        lines.extend(f"- {case}" for case in failed_cases)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def compact_zip_path(results_dir: Path, tag: str) -> Path:
    timestamp = results_dir.name.split(f"{tag}_")[-1] if f"{tag}_" in results_dir.name else ""
    suffix = f"_{timestamp}" if timestamp else ""
    return results_dir / f"ldos_tcp5_attack5_chatgpt_compact_{tag}{suffix}.zip"


def write_compact_zip(results_dir: Path, tag: str, summary_path: Path, figure_paths: list[Path], zip_path: Path) -> Path:
    include = [
        summary_path,
        results_dir / f"experiment_config_{tag}.json",
        results_dir / f"manifest_{tag}.json",
        results_dir / f"failed_cases_{tag}.txt",
        results_dir / "csv" / f"case_metrics_{tag}.csv",
        results_dir / "csv" / f"cycle_bandwidth_metrics_{tag}.csv",
        results_dir / "csv" / f"attack_rate_validation_{tag}.csv",
        results_dir / "csv" / f"tcp_rate_validation_{tag}.csv",
        results_dir / "csv" / f"rto_events_{tag}.csv",
        results_dir / "csv" / f"detector_metrics_{tag}.csv",
        results_dir / "csv" / f"aggregated_metrics_{tag}.csv",
    ]
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in include:
            if path.exists():
                archive.write(path, path.relative_to(results_dir))
        for path in figure_paths:
            if path.exists() and path.suffix.lower() == ".png":
                archive.write(path, path.relative_to(results_dir))
    return zip_path


def main() -> int:
    args = parse_args()
    results_dir = args.results_dir
    csv_dir = results_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    cases = discover_cases(results_dir, args.output_tag)
    all_timeseries: list[dict[str, Any]] = []
    detector_rows: list[dict[str, Any]] = []
    rto_rows: list[dict[str, Any]] = []
    per_case_data: list[tuple[Path, dict[str, Any], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]] = []

    for case_dir, metadata in cases:
        rows, drow, events = build_timeseries(case_dir, metadata, args)
        all_timeseries.extend(rows)
        detector_rows.append(drow)
        rto_rows.extend(events)
        per_case_data.append((case_dir, metadata, rows, drow, events))

    baseline_by_seed: dict[str, float] = {}
    no_attack_idle_by_seed: dict[str, float] = {}
    for _case_dir, metadata, rows, _drow, _events in per_case_data:
        if metadata.get("scenario") == "no_attack":
            seed = str(metadata.get("seed", ""))
            selected = eval_rows(rows, args.evaluation_start_sec, args.evaluation_end_sec)
            baseline_by_seed[seed] = mean(safe_float(row.get("tcp_mbps")) for row in selected)
            no_attack_idle_by_seed[seed] = mean(safe_float(row.get("idle_mbps")) for row in selected)

    case_rows: list[dict[str, Any]] = []
    attack_rows: list[dict[str, Any]] = []
    tcp_rows: list[dict[str, Any]] = []
    for case_dir, metadata, rows, drow, events in per_case_data:
        case_row, attack_row, tcp_row = build_case_outputs(
            case_dir,
            metadata,
            rows,
            drow,
            events,
            args,
            baseline_by_seed,
            no_attack_idle_by_seed,
        )
        case_rows.append(case_row)
        attack_rows.append(attack_row)
        if metadata.get("scenario") == "no_attack":
            tcp_rows.append(tcp_row)

    cycle_rows = build_cycle_rows(all_timeseries)
    aggregated = aggregate_rows(case_rows)
    aggregate_fields = list(aggregated[0].keys()) if aggregated else ["condition_id", "scenario", "n_cases", "n_seeds"]

    write_csv(csv_dir / f"bandwidth_timeseries_{args.output_tag}.csv", TIMESERIES_FIELDS, all_timeseries)
    write_csv(csv_dir / f"case_metrics_{args.output_tag}.csv", CASE_FIELDS, case_rows)
    write_csv(csv_dir / f"cycle_bandwidth_metrics_{args.output_tag}.csv", CYCLE_FIELDS, cycle_rows)
    write_csv(csv_dir / f"attack_rate_validation_{args.output_tag}.csv", ATTACK_VALIDATION_FIELDS, attack_rows)
    write_csv(csv_dir / f"tcp_rate_validation_{args.output_tag}.csv", TCP_VALIDATION_FIELDS, tcp_rows)
    write_csv(csv_dir / f"rto_events_{args.output_tag}.csv", RTO_FIELDS, rto_rows)
    write_csv(csv_dir / f"detector_metrics_{args.output_tag}.csv", DETECTOR_FIELDS, detector_rows)
    write_csv(csv_dir / f"aggregated_metrics_{args.output_tag}.csv", aggregate_fields, aggregated)

    failed_path = results_dir / f"failed_cases_{args.output_tag}.txt"
    failed_cases = [line.strip() for line in failed_path.read_text(encoding="utf-8").splitlines()] if failed_path.exists() else []
    failed_cases.extend(
        f"{row['case_id']}: tcp_validation_failed"
        for row in tcp_rows
        if row.get("tcp_rate_match_status") == "failed"
    )
    failed_cases.extend(
        f"{row['case_id']}: attack_rate_{row.get('attack_rate_match_status')}"
        for row in attack_rows
        if row.get("scenario") != "no_attack" and row.get("attack_rate_match_status") == "failed"
    )
    if failed_cases:
        failed_path.write_text("\n".join(dict.fromkeys(failed_cases)) + "\n", encoding="utf-8")
    elif not failed_path.exists():
        failed_path.write_text("", encoding="utf-8")

    config = {
        "mode": args.mode,
        "output_tag": args.output_tag,
        "results_dir": str(results_dir),
        "bottleneck_mbps": args.bottleneck_mbps,
        "tcp_target_mbps": args.tcp_target_mbps,
        "attack_target_mbps": args.attack_target_mbps,
        "period_ms": 1000,
        "burst_ms": 1000 / 3,
        "bucket_ms": args.bucket_ms,
        "evaluation_start_sec": args.evaluation_start_sec,
        "evaluation_end_sec": args.evaluation_end_sec,
        "primary_metric": "s2 egress pcap, receiver direction, IPv4 total length",
    }
    (results_dir / f"experiment_config_{args.output_tag}.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    figure_paths = write_figures(results_dir, all_timeseries, cycle_rows, case_rows, attack_rows, args.output_tag)
    summary_path = write_summary(results_dir, case_rows, attack_rows, tcp_rows, detector_rows, rto_rows, failed_cases, args)
    zip_path = compact_zip_path(results_dir, args.output_tag)
    manifest = {
        "output_tag": args.output_tag,
        "results_dir": str(results_dir),
        "case_count": len(case_rows),
        "failed_cases": failed_cases,
        "csv_outputs": sorted(str(path.relative_to(results_dir)) for path in csv_dir.glob(f"*_{args.output_tag}.csv")),
        "figure_outputs": sorted(str(path.relative_to(results_dir)) for path in (results_dir / "figures").glob(f"*_{args.output_tag}.png")),
        "summary": str(summary_path.relative_to(results_dir)),
        "chatgpt_zip": str(zip_path),
    }
    (results_dir / f"manifest_{args.output_tag}.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write_compact_zip(results_dir, args.output_tag, summary_path, figure_paths, zip_path)
    print(f"Wrote TCP5/Attack5 20260611 outputs to {results_dir}")
    print(f"ChatGPT ZIP: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
