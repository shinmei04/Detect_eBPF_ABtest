#!/usr/bin/env python3
"""
Recompute 20260610 bandwidth utilization from raw pcaps.

Presentation metrics use the s2-side pcap and IPv4 total length (ip.len).
Ethernet frame length is kept only as a diagnostic L2 load.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Iterable, Iterator


HEADER_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+"
    r".*?ethertype IPv4 \(0x0800\), length (?P<l2_len>\d+):\s+"
    r"\(.*?proto (?P<proto>[A-Z0-9]+) \((?P<proto_num>\d+)\), length (?P<ip_len>\d+)\)"
)
DETAIL_RE = re.compile(
    r"^\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\.(?P<src_port>\d+))?\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\.(?P<dst_port>\d+))?:\s+"
    r"(?P<body>.*?)(?:,\s+length\s+(?P<payload_len>\d+))?$"
)

CASE_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "status",
    "eval_start_sec",
    "eval_end_sec",
    "receiver_ip",
    "bottleneck_mbps",
    "capture_ingress_iface",
    "capture_egress_iface",
    "capture_ingress_pcap",
    "capture_egress_pcap",
    "capture_validation_status",
    "s2_ip_tcp_mbps",
    "s2_ip_attack_mbps",
    "s2_ip_other_mbps",
    "s2_ip_total_mbps",
    "s2_ip_idle_mbps",
    "s2_ip_utilization_pct",
    "s2_ip_capacity_excess_mbps",
    "s2_ip_capacity_excess_pct",
    "capacity_excess_warning",
    "s2_l2_frame_mbps",
    "s2_l2_observed_load_pct",
    "s2_l2_minus_ip_mbps",
    "s1_ip_attack_offered_mbps",
    "s2_ip_attack_pass_rate_pct",
    "configured_total_attack_avg_mbps",
    "measured_total_attack_offered_mbps",
    "measured_total_attack_passed_mbps",
    "attack_rate_error_pct",
    "attack_rate_match_status",
    "iperf_tcp_received_mbps",
    "iperf_tcp_degradation_pct",
    "iperf_retransmits",
    "FNR",
    "FPR",
]

AGG_FIELDS = [
    "condition_id",
    "scenario",
    "n_seeds",
    "s2_ip_total_mbps_mean",
    "s2_ip_total_mbps_std",
    "s2_ip_utilization_pct_mean",
    "s2_ip_utilization_pct_std",
    "s2_ip_tcp_mbps_mean",
    "s2_ip_attack_mbps_mean",
    "s2_ip_other_mbps_mean",
    "s2_ip_idle_mbps_mean",
    "s2_l2_frame_mbps_mean",
    "s2_l2_minus_ip_mbps_mean",
    "s1_ip_attack_offered_mbps_mean",
    "s2_ip_attack_pass_rate_pct_mean",
    "configured_total_attack_avg_mbps_mean",
    "attack_rate_error_pct_mean",
    "iperf_tcp_received_mbps_mean",
    "iperf_tcp_degradation_pct_mean",
    "iperf_retransmits_mean",
    "FNR_mean",
    "FPR_mean",
]

SCENARIO_FIELDS = [
    "scenario",
    "n_cases",
    "s2_ip_total_mbps_mean",
    "s2_ip_utilization_pct_mean",
    "s2_ip_tcp_mbps_mean",
    "s2_ip_attack_mbps_mean",
    "s2_ip_other_mbps_mean",
    "s2_ip_idle_mbps_mean",
    "s2_l2_frame_mbps_mean",
    "s2_l2_minus_ip_mbps_mean",
    "s1_ip_attack_offered_mbps_mean",
    "s2_ip_attack_pass_rate_pct_mean",
    "iperf_tcp_received_mbps_mean",
    "iperf_tcp_degradation_pct_mean",
    "FNR_pct_mean",
    "FPR_pct_mean",
]

L2_FIELDS = [
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "bottleneck_mbps",
    "s2_l2_frame_mbps",
    "s2_l2_observed_load_pct",
    "s2_ip_total_mbps",
    "s2_l2_minus_ip_mbps",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--l2-output-dir", type=Path)
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument("--manifests-dir", type=Path)
    parser.add_argument("--figures-dir", type=Path)
    parser.add_argument("--evaluation-start-sec", type=float, default=None)
    parser.add_argument("--evaluation-end-sec", type=float, default=None)
    parser.add_argument("--tcp-sender-ip", default="10.0.0.1")
    parser.add_argument("--receiver-ip", default="10.0.0.2")
    parser.add_argument("--attacker-ips", nargs="*", default=["10.0.0.3", "10.0.0.4"])
    parser.add_argument("--iperf-port", type=int, default=5201)
    parser.add_argument("--attack-udp-port", type=int, default=5001)
    parser.add_argument("--attack-rate-error-ok-pct", type=float, default=20.0)
    parser.add_argument("--suffix", default="20260610")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


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
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: format_value(row.get(field, "")) for field in fields})


def read_original_case_metrics(results_dir: Path) -> dict[str, dict[str, str]]:
    path = results_dir / "csv" / "case_metrics_20260610.csv"
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as f:
        return {row["case_id"]: row for row in csv.DictReader(f)}


def parse_tcpdump_records(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    pending: dict[str, Any] | None = None
    for line in lines:
        header = HEADER_RE.match(line.rstrip())
        if header:
            pending = {
                "timestamp": safe_float(header.group("ts")),
                "l2_len": safe_int(header.group("l2_len")),
                "ip_len": safe_int(header.group("ip_len")),
                "proto": header.group("proto").upper(),
                "proto_num": safe_int(header.group("proto_num")),
            }
            continue
        if pending is None:
            continue
        detail = DETAIL_RE.match(line.rstrip())
        if not detail:
            continue
        body = detail.group("body")
        proto = pending["proto"]
        if "UDP" in body:
            proto = "UDP"
        elif "Flags" in body:
            proto = "TCP"
        packet = {
            **pending,
            "src_ip": detail.group("src_ip"),
            "dst_ip": detail.group("dst_ip"),
            "src_port": safe_int(detail.group("src_port")),
            "dst_port": safe_int(detail.group("dst_port")),
            "payload_len": safe_int(detail.group("payload_len")),
            "proto": proto,
        }
        pending = None
        yield packet


def iter_pcap_packets(pcap_path: Path) -> Iterator[dict[str, Any]]:
    if not pcap_path.exists():
        return
    command = ["tcpdump", "-tt", "-e", "-n", "-vv", "-r", str(pcap_path), "ip"]
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    yield from parse_tcpdump_records(proc.stdout)
    proc.wait()
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"tcpdump failed for {pcap_path} with exit {proc.returncode}")


def classify_packet(packet: dict[str, Any], receiver_ip: str, args: argparse.Namespace) -> str:
    if packet["dst_ip"] != receiver_ip:
        return "not_receiver_direction"
    attackers = set(args.attacker_ips)
    if (
        packet["proto"] == "TCP"
        and packet["src_ip"] == args.tcp_sender_ip
        and packet["dst_ip"] == receiver_ip
        and (packet["src_port"] == args.iperf_port or packet["dst_port"] == args.iperf_port)
        and packet["payload_len"] > 0
    ):
        return "tcp"
    if (
        packet["proto"] == "UDP"
        and packet["src_ip"] in attackers
        and packet["dst_ip"] == receiver_ip
        and (packet["dst_port"] == args.attack_udp_port or args.attack_udp_port == 0)
    ):
        return "attack"
    return "other"


def time_origin(metadata: dict[str, Any]) -> float:
    start_wall = safe_float(metadata.get("experiment_start_wall"))
    if not math.isnan(start_wall):
        return start_wall
    epoch_ns = safe_float(metadata.get("case_start_epoch_ns"))
    if not math.isnan(epoch_ns):
        return epoch_ns / 1_000_000_000.0
    return 0.0


def pcap_totals(
    pcap_path: Path,
    metadata: dict[str, Any],
    eval_start: float,
    eval_end: float,
    receiver_ip: str,
    args: argparse.Namespace,
    capture: str,
) -> dict[str, float]:
    origin = time_origin(metadata)
    totals: dict[str, float] = defaultdict(float)
    for packet in iter_pcap_packets(pcap_path):
        rel_ts = packet["timestamp"] - origin
        if rel_ts < eval_start or rel_ts >= eval_end:
            continue
        cls = classify_packet(packet, receiver_ip, args)
        if capture == "egress":
            if cls == "not_receiver_direction":
                continue
            totals["s2_l2_frame_bytes"] += packet["l2_len"]
            totals["s2_ip_total_bytes"] += packet["ip_len"]
            if cls == "tcp":
                totals["s2_ip_tcp_bytes"] += packet["ip_len"]
            elif cls == "attack":
                totals["s2_ip_attack_bytes"] += packet["ip_len"]
            else:
                totals["s2_ip_other_bytes"] += packet["ip_len"]
        elif capture == "ingress" and cls == "attack":
            totals["s1_ip_attack_offered_bytes"] += packet["ip_len"]
    return totals


def mbps(byte_count: float, duration_sec: float) -> float:
    if duration_sec <= 0:
        return math.nan
    return 8.0 * byte_count / duration_sec / 1_000_000.0


def read_iperf(case_dir: Path) -> dict[str, float]:
    path = case_dir / "raw" / "iperf" / "iperf_client_20260610.json"
    if not path.exists():
        return {"received_mbps": math.nan, "sent_mbps": math.nan, "retransmits": math.nan}
    data = read_json(path)
    end = data.get("end", {})
    received = safe_float(end.get("sum_received", {}).get("bits_per_second")) / 1_000_000.0
    sent = safe_float(end.get("sum_sent", {}).get("bits_per_second")) / 1_000_000.0
    retransmits = safe_float(end.get("sum_sent", {}).get("retransmits"))
    return {"received_mbps": received, "sent_mbps": sent, "retransmits": retransmits}


def avg(values: Iterable[float]) -> float:
    valid = [value for value in values if not math.isnan(value)]
    return mean(valid) if valid else math.nan


def sd(values: Iterable[float]) -> float:
    valid = [value for value in values if not math.isnan(value)]
    return stdev(valid) if len(valid) > 1 else math.nan


def validate_capture(metadata: dict[str, Any]) -> str:
    ingress = str(metadata.get("capture_ingress_iface", ""))
    egress = str(metadata.get("capture_egress_iface", ""))
    egress_pcap = str(metadata.get("capture_egress_pcap", ""))
    issues = []
    if not ingress.startswith("s1-"):
        issues.append("ingress_not_s1")
    if not egress.startswith("s2-"):
        issues.append("egress_not_s2")
    if "egress_after_bottleneck" not in egress_pcap:
        issues.append("unexpected_egress_pcap")
    return "ok" if not issues else ";".join(issues)


def capacity_warning(row: dict[str, Any]) -> str:
    util = safe_float(row.get("s2_ip_utilization_pct"))
    scenario = str(row.get("scenario", ""))
    if scenario == "no_attack" and util > 105.0:
        return "no_attack_ip_utilization_gt_105pct"
    if util > 100.0:
        return "ip_capacity_exceeded"
    return ""


def attack_match_status(error_pct: float, threshold: float) -> str:
    if math.isnan(error_pct):
        return ""
    return "ok" if abs(error_pct) <= threshold else "over_budget" if error_pct > 0 else "under_budget"


def recompute_case(case_dir: Path, original_metrics: dict[str, dict[str, str]], args: argparse.Namespace) -> dict[str, Any]:
    metadata = read_json(case_dir / "metadata_20260610.json")
    case_id = str(metadata["case_id"])
    receiver_ip = str(metadata.get("receiver_ip", args.receiver_ip))
    eval_start = args.evaluation_start_sec
    if eval_start is None:
        eval_start = safe_float(metadata.get("evaluation_start_sec"), 25.0)
    eval_end = args.evaluation_end_sec
    if eval_end is None:
        eval_end = safe_float(metadata.get("evaluation_end_sec"), 55.0)
    if eval_end <= eval_start:
        eval_start = 0.0
        eval_end = safe_float(metadata.get("duration_sec"), 0.0)
    duration = eval_end - eval_start
    bottleneck = safe_float(metadata.get("bottleneck_mbps"), 15.0)

    egress = pcap_totals(
        Path(metadata["capture_egress_pcap"]),
        metadata,
        eval_start,
        eval_end,
        receiver_ip,
        args,
        "egress",
    )
    ingress = pcap_totals(
        Path(metadata["capture_ingress_pcap"]),
        metadata,
        eval_start,
        eval_end,
        receiver_ip,
        args,
        "ingress",
    )
    original = original_metrics.get(case_id, {})
    ip_total = mbps(egress["s2_ip_total_bytes"], duration)
    ip_attack = mbps(egress["s2_ip_attack_bytes"], duration)
    attack_offered = mbps(ingress["s1_ip_attack_offered_bytes"], duration)
    configured_attack = safe_float(metadata.get("configured_total_attack_avg_mbps"), safe_float(metadata.get("configured_average_attack_mbps"), 0.0))
    attack_error = (
        100.0 * (attack_offered - configured_attack) / configured_attack
        if configured_attack > 0 and not math.isnan(attack_offered)
        else math.nan
    )
    row = {
        "case_id": case_id,
        "scenario": metadata.get("scenario", ""),
        "condition_id": metadata.get("condition_id", ""),
        "seed": metadata.get("seed", ""),
        "status": metadata.get("status", ""),
        "eval_start_sec": eval_start,
        "eval_end_sec": eval_end,
        "receiver_ip": receiver_ip,
        "bottleneck_mbps": bottleneck,
        "capture_ingress_iface": metadata.get("capture_ingress_iface", ""),
        "capture_egress_iface": metadata.get("capture_egress_iface", ""),
        "capture_ingress_pcap": metadata.get("capture_ingress_pcap", ""),
        "capture_egress_pcap": metadata.get("capture_egress_pcap", ""),
        "capture_validation_status": validate_capture(metadata),
        "s2_ip_tcp_mbps": mbps(egress["s2_ip_tcp_bytes"], duration),
        "s2_ip_attack_mbps": ip_attack,
        "s2_ip_other_mbps": mbps(egress["s2_ip_other_bytes"], duration),
        "s2_ip_total_mbps": ip_total,
        "s2_ip_idle_mbps": max(bottleneck - ip_total, 0.0),
        "s2_ip_utilization_pct": 100.0 * ip_total / bottleneck,
        "s2_ip_capacity_excess_mbps": max(ip_total - bottleneck, 0.0),
        "s2_ip_capacity_excess_pct": 100.0 * max(ip_total - bottleneck, 0.0) / bottleneck,
        "s2_l2_frame_mbps": mbps(egress["s2_l2_frame_bytes"], duration),
        "s2_l2_observed_load_pct": 100.0 * mbps(egress["s2_l2_frame_bytes"], duration) / bottleneck,
        "s2_l2_minus_ip_mbps": mbps(egress["s2_l2_frame_bytes"] - egress["s2_ip_total_bytes"], duration),
        "s1_ip_attack_offered_mbps": attack_offered,
        "s2_ip_attack_pass_rate_pct": 100.0 * ip_attack / attack_offered if attack_offered > 0 else math.nan,
        "configured_total_attack_avg_mbps": configured_attack,
        "measured_total_attack_offered_mbps": attack_offered,
        "measured_total_attack_passed_mbps": ip_attack,
        "attack_rate_error_pct": attack_error,
        "attack_rate_match_status": attack_match_status(attack_error, args.attack_rate_error_ok_pct),
        "iperf_tcp_received_mbps": math.nan,
        "iperf_tcp_degradation_pct": math.nan,
        "iperf_retransmits": math.nan,
        "FNR": safe_float(original.get("FNR")),
        "FPR": safe_float(original.get("FPR")),
    }
    row["capacity_excess_warning"] = capacity_warning(row)
    iperf = read_iperf(case_dir)
    row["iperf_tcp_received_mbps"] = iperf["received_mbps"]
    row["iperf_retransmits"] = iperf["retransmits"]
    return row


def fill_iperf_degradation(rows: list[dict[str, Any]]) -> None:
    baseline_by_seed: dict[str, float] = {}
    for row in rows:
        if row["scenario"] == "no_attack":
            baseline_by_seed[str(row["seed"])] = safe_float(row["iperf_tcp_received_mbps"])
    for row in rows:
        baseline = baseline_by_seed.get(str(row["seed"]), math.nan)
        tcp = safe_float(row["iperf_tcp_received_mbps"])
        if baseline > 0 and not math.isnan(tcp):
            row["iperf_tcp_degradation_pct"] = 100.0 * (1.0 - tcp / baseline)


def group_rows(rows: list[dict[str, Any]], fields: list[str]) -> dict[tuple[str, ...], list[dict[str, Any]]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[tuple(str(row.get(field, "")) for field in fields)].append(row)
    return groups


def aggregate_condition(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for (condition, scenario), group in sorted(group_rows(rows, ["condition_id", "scenario"]).items()):
        out.append(
            {
                "condition_id": condition,
                "scenario": scenario,
                "n_seeds": len(group),
                "s2_ip_total_mbps_mean": avg(safe_float(r["s2_ip_total_mbps"]) for r in group),
                "s2_ip_total_mbps_std": sd(safe_float(r["s2_ip_total_mbps"]) for r in group),
                "s2_ip_utilization_pct_mean": avg(safe_float(r["s2_ip_utilization_pct"]) for r in group),
                "s2_ip_utilization_pct_std": sd(safe_float(r["s2_ip_utilization_pct"]) for r in group),
                "s2_ip_tcp_mbps_mean": avg(safe_float(r["s2_ip_tcp_mbps"]) for r in group),
                "s2_ip_attack_mbps_mean": avg(safe_float(r["s2_ip_attack_mbps"]) for r in group),
                "s2_ip_other_mbps_mean": avg(safe_float(r["s2_ip_other_mbps"]) for r in group),
                "s2_ip_idle_mbps_mean": avg(safe_float(r["s2_ip_idle_mbps"]) for r in group),
                "s2_l2_frame_mbps_mean": avg(safe_float(r["s2_l2_frame_mbps"]) for r in group),
                "s2_l2_minus_ip_mbps_mean": avg(safe_float(r["s2_l2_minus_ip_mbps"]) for r in group),
                "s1_ip_attack_offered_mbps_mean": avg(safe_float(r["s1_ip_attack_offered_mbps"]) for r in group),
                "s2_ip_attack_pass_rate_pct_mean": avg(safe_float(r["s2_ip_attack_pass_rate_pct"]) for r in group),
                "configured_total_attack_avg_mbps_mean": avg(safe_float(r["configured_total_attack_avg_mbps"]) for r in group),
                "attack_rate_error_pct_mean": avg(safe_float(r["attack_rate_error_pct"]) for r in group),
                "iperf_tcp_received_mbps_mean": avg(safe_float(r["iperf_tcp_received_mbps"]) for r in group),
                "iperf_tcp_degradation_pct_mean": avg(safe_float(r["iperf_tcp_degradation_pct"]) for r in group),
                "iperf_retransmits_mean": avg(safe_float(r["iperf_retransmits"]) for r in group),
                "FNR_mean": avg(safe_float(r["FNR"]) for r in group),
                "FPR_mean": avg(safe_float(r["FPR"]) for r in group),
            }
        )
    return out


def aggregate_scenario(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for (scenario,), group in sorted(group_rows(rows, ["scenario"]).items()):
        fnr = avg(safe_float(r["FNR"]) for r in group)
        fpr = avg(safe_float(r["FPR"]) for r in group)
        out.append(
            {
                "scenario": scenario,
                "n_cases": len(group),
                "s2_ip_total_mbps_mean": avg(safe_float(r["s2_ip_total_mbps"]) for r in group),
                "s2_ip_utilization_pct_mean": avg(safe_float(r["s2_ip_utilization_pct"]) for r in group),
                "s2_ip_tcp_mbps_mean": avg(safe_float(r["s2_ip_tcp_mbps"]) for r in group),
                "s2_ip_attack_mbps_mean": avg(safe_float(r["s2_ip_attack_mbps"]) for r in group),
                "s2_ip_other_mbps_mean": avg(safe_float(r["s2_ip_other_mbps"]) for r in group),
                "s2_ip_idle_mbps_mean": avg(safe_float(r["s2_ip_idle_mbps"]) for r in group),
                "s2_l2_frame_mbps_mean": avg(safe_float(r["s2_l2_frame_mbps"]) for r in group),
                "s2_l2_minus_ip_mbps_mean": avg(safe_float(r["s2_l2_minus_ip_mbps"]) for r in group),
                "s1_ip_attack_offered_mbps_mean": avg(safe_float(r["s1_ip_attack_offered_mbps"]) for r in group),
                "s2_ip_attack_pass_rate_pct_mean": avg(safe_float(r["s2_ip_attack_pass_rate_pct"]) for r in group),
                "iperf_tcp_received_mbps_mean": avg(safe_float(r["iperf_tcp_received_mbps"]) for r in group),
                "iperf_tcp_degradation_pct_mean": avg(safe_float(r["iperf_tcp_degradation_pct"]) for r in group),
                "FNR_pct_mean": 100.0 * fnr if not math.isnan(fnr) else math.nan,
                "FPR_pct_mean": 100.0 * fpr if not math.isnan(fpr) else math.nan,
            }
        )
    return out


def write_l2_outputs(l2_dir: Path, rows: list[dict[str, Any]], aggregated: list[dict[str, Any]], scenario_rows: list[dict[str, Any]], suffix: str) -> None:
    write_csv(l2_dir / f"recomputed_pcap_case_bandwidth_l2_{suffix}.csv", L2_FIELDS, rows)
    l2_agg_fields = [
        "condition_id",
        "scenario",
        "n_seeds",
        "s2_l2_frame_mbps_mean",
        "s2_l2_minus_ip_mbps_mean",
        "s2_ip_total_mbps_mean",
    ]
    write_csv(l2_dir / f"recomputed_pcap_aggregated_bandwidth_l2_{suffix}.csv", l2_agg_fields, aggregated)
    l2_scenario_fields = [
        "scenario",
        "n_cases",
        "s2_l2_frame_mbps_mean",
        "s2_l2_minus_ip_mbps_mean",
        "s2_ip_total_mbps_mean",
    ]
    write_csv(l2_dir / f"recomputed_pcap_scenario_bandwidth_l2_{suffix}.csv", l2_scenario_fields, scenario_rows)


def get_matplotlib() -> Any:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def save_fig(plt: Any, base: Path, title: str) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    if plt is None:
        base.with_suffix(".txt").write_text(f"{title}\nmatplotlib unavailable\n", encoding="utf-8")
        return
    plt.tight_layout(rect=(0, 0.04, 1, 1))
    plt.savefig(base.with_suffix(".png"), dpi=180)
    plt.savefig(base.with_suffix(".pdf"))
    plt.close()


def plot_ip_share(aggregated: list[dict[str, Any]], figures_dir: Path) -> None:
    plt = get_matplotlib()
    base = figures_dir / "01_ip_bandwidth_share_stacked_20260610"
    title = "IPv4 capacity share at s2"
    if plt is None:
        save_fig(None, base, title)
        return
    labels = [f"{row['condition_id']}\n{row['scenario']}" for row in aggregated]
    tcp = [safe_float(row["s2_ip_tcp_mbps_mean"]) / 15.0 * 100.0 for row in aggregated]
    attack = [safe_float(row["s2_ip_attack_mbps_mean"]) / 15.0 * 100.0 for row in aggregated]
    other = [safe_float(row["s2_ip_other_mbps_mean"]) / 15.0 * 100.0 for row in aggregated]
    idle = [safe_float(row["s2_ip_idle_mbps_mean"]) / 15.0 * 100.0 for row in aggregated]
    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.55), 5.5))
    bottoms = [0.0] * len(labels)
    for values, name, color in [
        (tcp, "TCP", "#2563eb"),
        (attack, "Attack", "#dc2626"),
        (other, "Other", "#6b7280"),
        (idle, "Idle", "#d1d5db"),
    ]:
        ax.bar(range(len(labels)), values, bottom=bottoms, label=name, color=color)
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
    ax.axhline(100, color="black", linewidth=1, linestyle="--", label="Configured capacity")
    ax.set_ylabel("Capacity share [%]")
    ax.set_title(title)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend(fontsize=8)
    fig.text(0.01, 0.01, "Measured at the s2 side of the bottleneck using IPv4 total length", fontsize=8)
    save_fig(plt, base, title)


def plot_l2_ip_comparison(scenario_rows: list[dict[str, Any]], figures_dir: Path) -> None:
    plt = get_matplotlib()
    base = figures_dir / "02_ip_l2_load_comparison_20260610"
    title = "IP load vs L2 observed load"
    if plt is None:
        save_fig(None, base, title)
        return
    labels = [str(row["scenario"]) for row in scenario_rows]
    ip_load = [safe_float(row["s2_ip_total_mbps_mean"]) for row in scenario_rows]
    l2_load = [safe_float(row["s2_l2_frame_mbps_mean"]) for row in scenario_rows]
    x = list(range(len(labels)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar([v - width / 2 for v in x], ip_load, width=width, label="IP load", color="#2563eb")
    ax.bar([v + width / 2 for v in x], l2_load, width=width, label="L2 load", color="#f97316")
    ax.axhline(15.0, color="black", linewidth=1, linestyle="--", label="Configured capacity")
    ax.set_ylabel("Mbps")
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.legend(fontsize=8)
    fig.text(0.01, 0.01, "Measured at the s2 side of the bottleneck using IPv4 total length", fontsize=8)
    save_fig(plt, base, title)


def write_report(
    report_path: Path,
    rows: list[dict[str, Any]],
    scenario_rows: list[dict[str, Any]],
    source_results: Path,
    output_dir: Path,
) -> None:
    first = rows[0] if rows else {}
    validation_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        validation_counts[str(row["capture_validation_status"])] += 1
    no_attack = [row for row in scenario_rows if row["scenario"] == "no_attack"]
    stat = [row for row in scenario_rows if row["scenario"] == "stat_matched_ldos"]
    constant = [row for row in scenario_rows if row["scenario"] == "constant_udp"]

    lines = [
        "# Recomputed Bandwidth Validation 20260610",
        "",
        f"- source: `{source_results}`",
        f"- output: `{output_dir}`",
        f"- ingress iface: `{first.get('capture_ingress_iface', '')}`",
        f"- egress iface: `{first.get('capture_egress_iface', '')}`",
        f"- receiver IP: `{first.get('receiver_ip', '')}`",
        f"- validation: {dict(validation_counts)}",
        "- primary metric: s2-side pcap, receiver direction only, IPv4 total length (ip.len)",
        "- L2 frame length is retained only as diagnostic load.",
        "",
        "## No-Attack Check",
        "",
    ]
    if no_attack:
        row = no_attack[0]
        lines.append(
            f"- no_attack IP load: {safe_float(row['s2_ip_total_mbps_mean']):.3f} Mbps "
            f"({safe_float(row['s2_ip_utilization_pct_mean']):.2f}%)"
        )
        lines.append(
            f"- no_attack L2-IP delta: {safe_float(row['s2_l2_minus_ip_mbps_mean']):.3f} Mbps"
        )
    lines.extend(
        [
            "",
            "## Scenario Summary",
            "",
            "| scenario | IP total Mbps | IP util % | TCP Mbps | attack Mbps | idle Mbps | L2-IP Mbps | FNR % | FPR % |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in scenario_rows:
        lines.append(
            f"| {row['scenario']} | {safe_float(row['s2_ip_total_mbps_mean']):.3f} | "
            f"{safe_float(row['s2_ip_utilization_pct_mean']):.2f} | "
            f"{safe_float(row['s2_ip_tcp_mbps_mean']):.3f} | "
            f"{safe_float(row['s2_ip_attack_mbps_mean']):.3f} | "
            f"{safe_float(row['s2_ip_idle_mbps_mean']):.3f} | "
            f"{safe_float(row['s2_l2_minus_ip_mbps_mean']):.3f} | "
            f"{safe_float(row['FNR_pct_mean']):.2f} | {safe_float(row['FPR_pct_mean']):.2f} |"
        )
    lines.extend(
        [
            "",
            "## Stat-Matched Diagnosis",
            "",
            "The existing focused run over-budgeted `stat_matched_ldos`: it used the configured peak burst rate and then added a feint rate on top. The sender is now changed so target burst average plus feint average equals `configured_average_attack_mbps`.",
        ]
    )
    if stat and constant:
        lines.append(
            f"- stat_matched attack passed: {safe_float(stat[0]['s2_ip_attack_mbps_mean']):.3f} Mbps"
        )
        lines.append(
            f"- constant_udp attack passed: {safe_float(constant[0]['s2_ip_attack_mbps_mean']):.3f} Mbps"
        )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_manifest(path: Path, rows: list[dict[str, Any]], source_results: Path, output_dir: Path, files: list[Path]) -> None:
    manifest = {
        "created_date": "2026-06-10",
        "source_results": str(source_results),
        "output_dir": str(output_dir),
        "case_count": len(rows),
        "primary_capture": "capture_egress_pcap",
        "primary_capture_side": "s2",
        "primary_length": "IPv4 total length (ip.len)",
        "files": [str(path) for path in files],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    results_dir = args.results_dir.resolve()
    output_dir = args.output_dir.resolve()
    l2_output_dir = (args.l2_output_dir or output_dir.parent / "recomputed_l2").resolve()
    reports_dir = (args.reports_dir or output_dir.parent / "reports").resolve()
    manifests_dir = (args.manifests_dir or output_dir.parent / "manifests").resolve()
    figures_dir = (args.figures_dir or output_dir / "figures").resolve()

    cases_dir = results_dir / "cases"
    original_metrics = read_original_case_metrics(results_dir)
    case_dirs = sorted(path for path in cases_dir.iterdir() if (path / "metadata_20260610.json").exists())
    rows = [recompute_case(case_dir, original_metrics, args) for case_dir in case_dirs]
    fill_iperf_degradation(rows)
    aggregated = aggregate_condition(rows)
    scenario_rows = aggregate_scenario(rows)

    case_csv = output_dir / f"recomputed_pcap_case_bandwidth_ip_{args.suffix}.csv"
    aggregate_csv = output_dir / f"recomputed_pcap_aggregated_bandwidth_ip_{args.suffix}.csv"
    scenario_csv = output_dir / f"recomputed_pcap_scenario_bandwidth_ip_{args.suffix}.csv"
    report_path = output_dir / f"recomputed_bandwidth_validation_{args.suffix}.md"
    write_csv(case_csv, CASE_FIELDS, rows)
    write_csv(aggregate_csv, AGG_FIELDS, aggregated)
    write_csv(scenario_csv, SCENARIO_FIELDS, scenario_rows)
    write_l2_outputs(l2_output_dir, rows, aggregated, scenario_rows, args.suffix)
    plot_ip_share(aggregated, figures_dir)
    plot_l2_ip_comparison(scenario_rows, figures_dir)
    write_report(report_path, rows, scenario_rows, results_dir, output_dir)

    manifest_path = manifests_dir / f"recompute_manifest_{args.suffix}.json"
    files = [
        case_csv,
        aggregate_csv,
        scenario_csv,
        report_path,
        l2_output_dir / f"recomputed_pcap_case_bandwidth_l2_{args.suffix}.csv",
        figures_dir / "01_ip_bandwidth_share_stacked_20260610.png",
        figures_dir / "02_ip_l2_load_comparison_20260610.png",
    ]
    write_manifest(manifest_path, rows, results_dir, output_dir, files)
    print(f"Wrote {len(rows)} case rows, {len(aggregated)} aggregate rows, and report to {output_dir}")


if __name__ == "__main__":
    main()
