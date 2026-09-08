#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Run one LDoS bandwidth-utilization case.  Real mode reuses the existing
Mininet topology and composite LDoS sender.  Synthetic mode writes deterministic
raw artifacts for local smoke tests when Mininet is unavailable.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from metrics import (
    DEFAULT_BOTTLENECK_MBPS,
    average_attack_rate_mbps,
    configured_average_attack_pct,
)


SCENARIO_MAP = {
    "random_microburst": "random_microburst_only",
    "periodic_ldos": "composite_lddos",
    "stat_matched_ldos": "stat_matched_composite_lddos",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--scenario",
        required=True,
        choices=["no_attack", "constant_udp", "random_microburst", "periodic_ldos", "stat_matched_ldos"],
    )
    parser.add_argument("--condition-id", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--bottleneck-mbps", type=float, default=DEFAULT_BOTTLENECK_MBPS)
    parser.add_argument("--peak-rate-mbps", type=float, default=DEFAULT_BOTTLENECK_MBPS)
    parser.add_argument("--burst-ms", type=float, default=100.0)
    parser.add_argument("--period-ms", type=float, default=1000.0)
    parser.add_argument("--duty-ratio", type=float)
    parser.add_argument("--configured-average-attack-mbps", type=float)
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
    parser.add_argument("--bucket-ms", type=float, default=25.0)
    parser.add_argument("--evaluation-start-sec", type=float)
    parser.add_argument("--evaluation-end-sec", type=float)
    parser.add_argument("--payload-size", type=int, default=750)
    parser.add_argument("--num-attack-flows", type=int, default=8)
    parser.add_argument("--capture-ingress-iface")
    parser.add_argument("--capture-egress-iface")
    parser.add_argument("--tcp-info-interval-ms", type=float, default=50.0)
    parser.add_argument("--disable-tcp-info", action="store_true")
    parser.add_argument("--disable-offloads", action="store_true")
    parser.add_argument("--tcp-target-mbps", type=float)
    parser.add_argument("--tcp-pacing-timer-us", type=int)
    parser.add_argument("--queue-limit-packets", type=int)
    parser.add_argument("--output-tag", default="20260610")
    parser.add_argument("--existing-repo-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--synthetic-test", action="store_true")
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.duration_sec <= 0:
        raise SystemExit("--duration-sec must be positive")
    if not 0 <= args.attack_start_sec < args.duration_sec:
        raise SystemExit("--attack-start-sec must be in [0, duration-sec)")
    if args.bottleneck_mbps <= 0:
        raise SystemExit("--bottleneck-mbps must be positive")
    if args.period_ms <= 0 or args.burst_ms <= 0 or args.burst_ms > args.period_ms:
        raise SystemExit("require 0 < --burst-ms <= --period-ms")
    if args.num_attack_flows <= 0:
        raise SystemExit("--num-attack-flows must be positive")
    if args.payload_size <= 0:
        raise SystemExit("--payload-size must be positive")
    if args.tcp_info_interval_ms <= 0:
        raise SystemExit("--tcp-info-interval-ms must be positive")
    if args.tcp_target_mbps is not None and args.tcp_target_mbps <= 0:
        raise SystemExit("--tcp-target-mbps must be positive when supplied")
    if args.tcp_pacing_timer_us is not None and args.tcp_pacing_timer_us <= 0:
        raise SystemExit("--tcp-pacing-timer-us must be positive when supplied")
    if args.queue_limit_packets is not None and args.queue_limit_packets <= 0:
        raise SystemExit("--queue-limit-packets must be positive when supplied")
    if args.configured_average_attack_mbps is None:
        args.configured_average_attack_mbps = average_attack_rate_mbps(args.peak_rate_mbps, args.burst_ms, args.period_ms)
    if args.duty_ratio is None:
        args.duty_ratio = args.burst_ms / args.period_ms
    if args.evaluation_start_sec is None:
        args.evaluation_start_sec = args.attack_start_sec + 5.0
    if args.evaluation_end_sec is None:
        args.evaluation_end_sec = args.duration_sec - 5.0


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def shell_join(command: list[Any]) -> str:
    return " ".join(shlex.quote(str(item)) for item in command)


def ensure_case_dirs(output_dir: Path, case_id: str) -> Path:
    case_dir = output_dir / "cases" / case_id
    for subdir in [
        "raw",
        "raw/pcaps",
        "raw/iperf",
        "raw/detector",
        "raw/tcpdump",
        "raw/tcp_info",
        "raw/pulses",
        "logs",
    ]:
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)
    return case_dir


def write_metadata(case_dir: Path, metadata: dict[str, Any], output_tag: str = "20260610") -> None:
    (case_dir / f"metadata_{output_tag}.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def base_metadata(args: argparse.Namespace, case_dir: Path) -> dict[str, Any]:
    return {
        "created_date": "2026-06-10",
        "purpose": "25 ms detector window comparison experiment",
        "case_id": args.case_id,
        "timestamp": now_iso(),
        "scenario": args.scenario,
        "existing_scenario_name": SCENARIO_MAP.get(args.scenario, args.scenario),
        "condition_id": args.condition_id,
        "seed": args.seed,
        "bottleneck_mbps": args.bottleneck_mbps,
        "peak_rate_mbps": args.peak_rate_mbps,
        "burst_ms": args.burst_ms,
        "period_ms": args.period_ms,
        "duty_ratio": args.duty_ratio,
        "configured_average_attack_mbps": args.configured_average_attack_mbps,
        "configured_total_attack_avg_mbps": args.configured_average_attack_mbps,
        "configured_average_attack_pct": configured_average_attack_pct(
            args.configured_average_attack_mbps, args.bottleneck_mbps
        ),
        "duration_sec": args.duration_sec,
        "attack_start_sec": args.attack_start_sec,
        "bucket_ms": args.bucket_ms,
        "evaluation_start_sec": args.evaluation_start_sec,
        "evaluation_end_sec": args.evaluation_end_sec,
        "payload_size": args.payload_size,
        "num_attack_flows": args.num_attack_flows,
        "tcp_sender_ip": "10.0.0.1",
        "receiver_ip": "10.0.0.2",
        "attacker_ips": ["10.0.0.3", "10.0.0.4"],
        "iperf_port": 5201,
        "attack_udp_port": 5001,
        "tcp_info_interval_ms": args.tcp_info_interval_ms,
        "tcp_info_enabled": not args.disable_tcp_info,
        "disable_offloads": args.disable_offloads,
        "output_tag": args.output_tag,
        "tcp_target_mbps": args.tcp_target_mbps,
        "tcp_limit_method": "iperf3_bitrate" if args.tcp_target_mbps else "unlimited_iperf3_tcp",
        "tcp_pacing_timer_us": args.tcp_pacing_timer_us,
        "configured_queue_packets": args.queue_limit_packets,
        "command": shell_join(sys.argv),
        "cwd": str(Path.cwd()),
        "python_version": sys.version,
        "os": platform.platform(),
        "kernel": platform.release(),
        "case_dir": str(case_dir),
    }


def bytes_for_rate(rate_mbps: float, bucket_sec: float) -> int:
    return max(0, int(round(rate_mbps * 1_000_000.0 * bucket_sec / 8.0)))


def synthetic_rates(args: argparse.Namespace, bucket_start: float, rng: random.Random) -> tuple[float, float, float, bool]:
    baseline_tcp = args.tcp_target_mbps if args.tcp_target_mbps else args.bottleneck_mbps * 0.90
    avg_attack = args.configured_average_attack_mbps
    active = bucket_start >= args.attack_start_sec
    period_sec = args.period_ms / 1000.0
    burst_sec = args.burst_ms / 1000.0
    phase = (bucket_start - args.attack_start_sec) % period_sec if active else math.inf
    periodic_burst = active and phase < burst_sec
    if args.scenario == "no_attack" or not active:
        return baseline_tcp + rng.uniform(-0.08, 0.08), 0.0, 0.03, False
    if args.scenario == "constant_udp":
        attack = avg_attack
        tcp = baseline_tcp - min(avg_attack * 0.35, baseline_tcp * 0.45) + rng.uniform(-0.08, 0.08)
        return max(tcp, 0.2), attack, 0.04, False
    if args.scenario == "random_microburst":
        random_burst = rng.random() < args.duty_ratio
        attack = args.peak_rate_mbps if random_burst else 0.0
        tcp = baseline_tcp - min(avg_attack * 0.55, baseline_tcp * 0.65) - (args.peak_rate_mbps * 0.03 if random_burst else 0.0)
        return max(tcp + rng.uniform(-0.15, 0.15), 0.2), attack, 0.05, random_burst
    if args.scenario == "periodic_ldos":
        attack = args.peak_rate_mbps if periodic_burst else 0.0
        recovery_penalty = min(avg_attack * 0.75, baseline_tcp * 0.75)
        burst_penalty = args.peak_rate_mbps * 0.03 if periodic_burst else 0.0
        return max(baseline_tcp - recovery_penalty - burst_penalty + rng.uniform(-0.12, 0.12), 0.2), attack, 0.05, periodic_burst
    attack = args.peak_rate_mbps if periodic_burst else avg_attack * 0.08
    recovery_penalty = min(avg_attack * 0.65, baseline_tcp * 0.70)
    burst_penalty = args.peak_rate_mbps * 0.025 if periodic_burst else 0.0
    return max(baseline_tcp - recovery_penalty - burst_penalty + rng.uniform(-0.12, 0.12), 0.2), attack, 0.05, periodic_burst


def synthetic_suspicious_score(args: argparse.Namespace, attack_active: bool, burst_active: bool, index: int) -> int:
    if args.scenario == "no_attack" or not attack_active:
        return 0
    if args.scenario == "constant_udp":
        return 1 if index % 37 == 0 else 0
    if args.scenario == "random_microburst":
        return 2 if burst_active and index % 5 == 0 else (1 if burst_active else 0)
    if args.scenario == "periodic_ldos":
        return 2 if burst_active and index % 3 != 0 else (1 if burst_active else 0)
    return 2 if burst_active and index % 13 == 0 else (1 if burst_active else 0)


def synthetic_pulses(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.scenario in {"no_attack", "constant_udp"}:
        return []
    rng = random.Random(args.seed * 7919 + int(args.burst_ms * 13))
    period_sec = args.period_ms / 1000.0
    burst_sec = args.burst_ms / 1000.0
    pulses: list[dict[str, Any]] = []
    index = 0
    period_start = args.attack_start_sec
    case_start_epoch_ns = int(time.time_ns())
    while period_start < args.duration_sec:
        if args.scenario == "random_microburst":
            latest = max(period_start, min(period_start + period_sec, args.duration_sec) - burst_sec)
            start = rng.uniform(period_start, latest) if latest > period_start else period_start
        else:
            start = period_start
        end = min(start + burst_sec, args.duration_sec)
        pulses.append(
            {
                "pulse_index": index,
                "case_id": args.case_id,
                "scenario": args.scenario,
                "condition_id": args.condition_id,
                "seed": args.seed,
                "pulse_start_sec": start,
                "pulse_end_sec": end,
                "scheduled_start_epoch_ns": case_start_epoch_ns + int(start * 1_000_000_000),
                "actual_start_epoch_ns": case_start_epoch_ns + int(start * 1_000_000_000),
                "actual_end_epoch_ns": case_start_epoch_ns + int(end * 1_000_000_000),
                "configured_rate_mbps": args.peak_rate_mbps,
                "actual_sent_bytes": bytes_for_rate(args.peak_rate_mbps, max(end - start, 0.0)),
            }
        )
        index += 1
        period_start += period_sec
    return pulses


def write_pulses(case_dir: Path, pulses: list[dict[str, Any]], output_tag: str = "20260610") -> None:
    path = case_dir / "raw" / "pulses" / f"attack_pulses_{output_tag}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "pulse_index",
        "case_id",
        "scenario",
        "condition_id",
        "seed",
        "pulse_start_sec",
        "pulse_end_sec",
        "scheduled_start_epoch_ns",
        "actual_start_epoch_ns",
        "actual_end_epoch_ns",
        "configured_rate_mbps",
        "actual_sent_bytes",
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(pulses)


def synthetic_rto_state(args: argparse.Namespace, sample_sec: float, pulses: list[dict[str, Any]], cumulative_retrans: int) -> tuple[int, int, int, float, float, float]:
    backoff = 0
    retransmits = 0
    rto_ms = 200.0
    cwnd = 22.0
    rtt_ms = 28.0
    if args.scenario in {"periodic_ldos", "stat_matched_ldos", "random_microburst"}:
        for pulse in pulses:
            end = float(pulse["pulse_end_sec"])
            if end + 0.05 <= sample_sec <= end + (0.55 if args.scenario == "periodic_ldos" else 0.35):
                backoff = 2 if args.scenario == "periodic_ldos" and sample_sec >= end + 0.25 else 1
                retransmits = backoff
                rto_ms = 200.0 * (2 ** max(backoff - 1, 0))
                cwnd = 4.0 if backoff >= 2 else 7.0
                rtt_ms = 45.0 + 20.0 * backoff
                break
    elif args.scenario == "constant_udp" and sample_sec >= args.attack_start_sec:
        cwnd = 18.0
        rtt_ms = 35.0
    total_retrans = cumulative_retrans + retransmits
    rttvar_ms = max(2.0, rtt_ms * 0.18)
    return backoff, retransmits, total_retrans, rto_ms, cwnd, rtt_ms + rttvar_ms


def write_synthetic_tcp_info(case_dir: Path, args: argparse.Namespace, pulses: list[dict[str, Any]]) -> None:
    tcp_dir = case_dir / "raw" / "tcp_info" / args.case_id
    tcp_dir.mkdir(parents=True, exist_ok=True)
    csv_path = tcp_dir / f"tcp_info_timeseries_{args.output_tag}.csv"
    raw_path = tcp_dir / f"ss_raw_{args.output_tag}.log"
    metrics_path = tcp_dir / f"sampler_metrics_{args.output_tag}.txt"
    interval_sec = args.tcp_info_interval_ms / 1000.0
    steps = int(math.ceil(args.duration_sec / interval_sec))
    fields = [
        "timestamp_epoch_ns",
        "timestamp_sec",
        "sample_duration_ms",
        "scenario",
        "condition_id",
        "seed",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "tcp_state",
        "congestion_control",
        "rto_ms",
        "backoff",
        "retransmits",
        "total_retrans",
        "lost",
        "unacked",
        "sacked",
        "cwnd",
        "ssthresh",
        "rtt_ms",
        "rttvar_ms",
        "mss",
        "pacing_rate_mbps",
        "delivery_rate_mbps",
        "bytes_acked",
        "bytes_sent",
        "ca_state",
        "flow_id",
        "observation_source",
    ]
    start_epoch_ns = time.time_ns()
    rows: list[dict[str, Any]] = []
    cumulative_retrans = 0
    previous_backoff = 0
    bytes_acked = 0.0
    for step in range(steps):
        ts = round(step * interval_sec, 9)
        backoff, retransmits, total_retrans, rto_ms, cwnd, rtt_plus_var = synthetic_rto_state(args, ts, pulses, cumulative_retrans)
        if backoff > previous_backoff:
            cumulative_retrans += 1
        previous_backoff = backoff
        tcp_rate = max(0.4, args.bottleneck_mbps * 0.9 - (args.configured_average_attack_mbps * (2.0 if backoff else 0.5)))
        bytes_acked += tcp_rate * 1_000_000.0 * interval_sec / 8.0
        rtt_ms = rtt_plus_var / 1.18
        rows.append(
            {
                "timestamp_epoch_ns": start_epoch_ns + int(ts * 1_000_000_000),
                "timestamp_sec": ts,
                "sample_duration_ms": 1.0,
                "scenario": args.scenario,
                "condition_id": args.condition_id,
                "seed": args.seed,
                "source_ip": "10.0.0.1",
                "source_port": 43000,
                "destination_ip": "10.0.0.2",
                "destination_port": 5201,
                "tcp_state": "ESTAB",
                "congestion_control": "cubic",
                "rto_ms": rto_ms,
                "backoff": backoff,
                "retransmits": retransmits,
                "total_retrans": cumulative_retrans,
                "lost": retransmits,
                "unacked": 2 if backoff else 0,
                "sacked": 0,
                "cwnd": cwnd,
                "ssthresh": max(2.0, cwnd - 2.0),
                "rtt_ms": rtt_ms,
                "rttvar_ms": rtt_plus_var - rtt_ms,
                "mss": 1448,
                "pacing_rate_mbps": tcp_rate * 1.15,
                "delivery_rate_mbps": tcp_rate,
                "bytes_acked": bytes_acked,
                "bytes_sent": bytes_acked + cumulative_retrans * 1448,
                "ca_state": "Loss" if backoff else "Open",
                "flow_id": "10.0.0.1:43000>10.0.0.2:5201",
                "observation_source": "ss_tcp_info",
            }
        )
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    raw_path.write_text("synthetic ss -tin output placeholder for smoke test\n", encoding="utf-8")
    metrics_path.write_text(
        "\n".join(
            [
                f"created_date={args.output_tag[:4]}-{args.output_tag[4:6]}-{args.output_tag[6:8]}",
                "purpose=25 ms detector window comparison experiment",
                f"case_id={args.case_id}",
                f"sample_count={len(rows)}",
                f"interval_ms={args.tcp_info_interval_ms}",
                "mean_sample_duration_ms=1.0",
                "max_sample_duration_ms=1.0",
                "missed_deadline_count=0",
                "missed_deadline_rate=0.0",
                "sampler_cpu_user_system_pct=0.1",
                "observation_source=ss_tcp_info",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def write_synthetic_retransmissions(case_dir: Path, args: argparse.Namespace, pulses: list[dict[str, Any]]) -> None:
    path = case_dir / "raw" / f"tcp_retransmission_events_{args.output_tag}.csv"
    fields = [
        "timestamp_sec",
        "timestamp_epoch_ns",
        "case_id",
        "scenario",
        "condition_id",
        "seed",
        "capture",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "tcp_seq",
        "tcp_ack",
        "tcp_len",
        "event_type",
        "is_fast_retransmission",
        "is_spurious_retransmission",
        "is_duplicate_ack",
        "is_inferred_rto",
        "inference_confidence",
        "inference_reason",
        "observation_source",
    ]
    rows: list[dict[str, Any]] = []
    start_epoch_ns = time.time_ns()
    for pulse in pulses:
        if args.scenario == "random_microburst" and int(pulse["pulse_index"]) % 2 == 0:
            event_type = "fast_retransmission"
            offset = 0.08
        elif args.scenario in {"periodic_ldos", "stat_matched_ldos"}:
            event_type = "retransmission"
            offset = 0.16
        else:
            continue
        ts = float(pulse["pulse_end_sec"]) + offset
        rows.append(
            {
                "timestamp_sec": ts,
                "timestamp_epoch_ns": start_epoch_ns + int(ts * 1_000_000_000),
                "case_id": args.case_id,
                "scenario": args.scenario,
                "condition_id": args.condition_id,
                "seed": args.seed,
                "capture": "egress",
                "source_ip": "10.0.0.1",
                "source_port": 43000,
                "destination_ip": "10.0.0.2",
                "destination_port": 5201,
                "tcp_seq": int(1_000_000 + ts * 1000),
                "tcp_ack": 0,
                "tcp_len": 1448,
                "event_type": event_type,
                "is_fast_retransmission": int(event_type == "fast_retransmission"),
                "is_spurious_retransmission": 0,
                "is_duplicate_ack": 0,
                "is_inferred_rto": 0,
                "inference_confidence": "",
                "inference_reason": "synthetic pcap retransmission label; not direct RTO evidence",
                "observation_source": "pcap_inference",
            }
        )
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_synthetic_iperf_json(case_dir: Path, args: argparse.Namespace, tcp_mbps_values: list[float]) -> None:
    receiver_mbps = sum(tcp_mbps_values) / len(tcp_mbps_values) if tcp_mbps_values else 0.0
    path = case_dir / "raw" / "iperf" / f"iperf_client_{args.output_tag}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "start": {"test_start": {"protocol": "TCP", "num_streams": 1}},
        "end": {
            "sum_received": {"bits_per_second": receiver_mbps * 1_000_000.0},
            "sum_sent": {"bits_per_second": receiver_mbps * 1_000_000.0},
            "streams": [{"receiver": {"bits_per_second": receiver_mbps * 1_000_000.0}}],
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def run_synthetic_case(args: argparse.Namespace, case_dir: Path, metadata: dict[str, Any]) -> None:
    stable_case_hash = sum((idx + 1) * ord(ch) for idx, ch in enumerate(args.case_id)) % 9973
    rng = random.Random(args.seed * 100003 + stable_case_hash)
    bucket_sec = args.bucket_ms / 1000.0
    steps = int(math.ceil(args.duration_sec / bucket_sec))
    packet_rows: list[dict[str, Any]] = []
    detector_rows: list[dict[str, Any]] = []
    tcp_mbps_values: list[float] = []
    pulses = synthetic_pulses(args)
    for index in range(steps):
        ts = round(index * bucket_sec, 9)
        tcp_mbps, attack_mbps, other_mbps, burst_active = synthetic_rates(args, ts, rng)
        tcp_mbps_values.append(tcp_mbps)
        attack_active = int(ts >= args.attack_start_sec and args.scenario != "no_attack")
        passed_attack_mbps = min(attack_mbps * 0.94, max(args.bottleneck_mbps - 0.3, 0.0)) if attack_active else 0.0
        offered_attack_mbps = attack_mbps if attack_active else 0.0
        if attack_active and args.scenario == "constant_udp":
            passed_attack_mbps = attack_mbps * 0.96
        packet_rows.extend(
            [
                {
                    "timestamp_sec": ts,
                    "capture": "egress",
                    "class": "tcp_normal",
                    "bytes": bytes_for_rate(tcp_mbps, bucket_sec),
                },
                {
                    "timestamp_sec": ts,
                    "capture": "egress",
                    "class": "attack",
                    "bytes": bytes_for_rate(passed_attack_mbps, bucket_sec),
                },
                {
                    "timestamp_sec": ts,
                    "capture": "egress",
                    "class": "other",
                    "bytes": bytes_for_rate(other_mbps, bucket_sec),
                },
                {
                    "timestamp_sec": ts,
                    "capture": "ingress",
                    "class": "attack",
                    "bytes": bytes_for_rate(offered_attack_mbps, bucket_sec),
                },
            ]
        )
        score = synthetic_suspicious_score(args, bool(attack_active), burst_active, index)
        detector_rows.append(
            {
                "timestamp_sec": ts,
                "attack_active": attack_active,
                "attack_period_active": attack_active,
                "attack_burst_active": int(attack_active and burst_active),
                "detector_attack": int(score >= 2),
                "suspicious_score": score,
                "iat_variance": max(0.001, 1.0 - score * 0.08 + rng.uniform(-0.01, 0.01)),
                "burst_rate": max(0.0, offered_attack_mbps * (1.0 if burst_active else 0.15)),
                "payload_size_variance": 0.0 if args.scenario in {"constant_udp", "periodic_ldos"} else 120.0 * score,
                "new_flow_rate": 0.0 if args.scenario == "constant_udp" else min(args.num_attack_flows, score + 1),
            }
        )

    with (case_dir / "raw" / f"synthetic_packets_{args.output_tag}.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp_sec", "capture", "class", "bytes"])
        writer.writeheader()
        writer.writerows(packet_rows)
    with (case_dir / "raw" / "detector" / f"detector_windows_{args.output_tag}.csv").open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp_sec",
                "attack_active",
                "attack_period_active",
                "attack_burst_active",
                "detector_attack",
                "suspicious_score",
                "iat_variance",
                "burst_rate",
                "payload_size_variance",
                "new_flow_rate",
            ],
        )
        writer.writeheader()
        writer.writerows(detector_rows)
    write_pulses(case_dir, pulses, args.output_tag)
    if not args.disable_tcp_info:
        write_synthetic_tcp_info(case_dir, args, pulses)
    write_synthetic_retransmissions(case_dir, args, pulses)
    write_synthetic_iperf_json(case_dir, args, tcp_mbps_values)
    metadata.update(
        {
            "mode": "synthetic-test",
            "status": "success",
            "error_message": "",
            "capture_ingress_iface": args.capture_ingress_iface or "synthetic-ingress",
            "capture_egress_iface": args.capture_egress_iface or "synthetic-egress",
            "capture_ingress_pcap": "",
            "capture_egress_pcap": "",
            "case_start_epoch_ns": time.time_ns(),
            "case_start_monotonic_ns": time.monotonic_ns(),
            "rto_observation_source": "ss_tcp_info",
            "notes": [
                "synthetic-test mode: Mininet was not executed",
                "raw packet rows are deterministic smoke-test artifacts",
            ],
        }
    )


def find_existing_repo_dir(args: argparse.Namespace) -> Path:
    candidates = []
    if args.existing_repo_dir:
        candidates.append(args.existing_repo_dir)
    here = Path(__file__).resolve().parent
    candidates.extend(
        [
            here.parent / "Detect_eBPF_ABtest_mininet",
            Path.cwd() / "Detect_eBPF_ABtest_mininet",
            Path.cwd().parent / "Detect_eBPF_ABtest_mininet",
        ]
    )
    for candidate in candidates:
        if (candidate / "mininet_experiment" / "minimal_topo.py").exists():
            return candidate.resolve()
    raise FileNotFoundError("Could not find Detect_eBPF_ABtest_mininet with mininet_experiment/minimal_topo.py")


def assert_real_environment() -> None:
    if platform.system() != "Linux":
        raise SystemExit("Real Mininet execution requires WSL/Ubuntu Linux. Use --synthetic-test for local smoke tests.")
    if os.geteuid() != 0:
        raise SystemExit("Real Mininet execution requires root. Run with sudo.")
    missing = [cmd for cmd in ["mn", "tcpdump", "iperf3", "ip", "tc", "ovs-vsctl"] if shutil.which(cmd) is None]
    if not shutil.which("ss"):
        missing.append("ss")
    if missing:
        raise SystemExit("Missing required command(s): " + ", ".join(missing))


def start_root_tcpdump(iface: str, pcap_path: Path, log_path: Path) -> subprocess.Popen[Any]:
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w")
    return subprocess.Popen(["tcpdump", "-i", iface, "-U", "-w", str(pcap_path)], stdout=log, stderr=subprocess.STDOUT)


def stop_process(proc: Any) -> None:
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def find_bottleneck_ifaces(network: Any, args: argparse.Namespace) -> tuple[str, str]:
    if args.capture_ingress_iface and args.capture_egress_iface:
        return args.capture_ingress_iface, args.capture_egress_iface
    s1 = network.get("s1")
    s2 = network.get("s2")
    links = s1.connectionsTo(s2)
    if not links:
        raise RuntimeError("Could not find s1-s2 bottleneck interfaces")
    s1_intf, s2_intf = links[0]
    return args.capture_ingress_iface or s1_intf.name, args.capture_egress_iface or s2_intf.name


def run_host_background(host: Any, command: list[Any], log_path: Path) -> Any:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("w")
    return host.popen([str(item) for item in command], stdout=log, stderr=subprocess.STDOUT)


def collect_offload_settings(ifaces: list[str], case_dir: Path, disable_offloads: bool, output_tag: str = "20260610") -> dict[str, Any]:
    settings: dict[str, Any] = {}
    ethtool = shutil.which("ethtool")
    if ethtool is None:
        settings["ethtool_available"] = False
        return settings
    settings["ethtool_available"] = True
    offload_dir = case_dir / "raw" / "tcpdump"
    offload_dir.mkdir(parents=True, exist_ok=True)
    for iface in ifaces:
        before = subprocess.run([ethtool, "-k", iface], text=True, capture_output=True, check=False)
        (offload_dir / f"offload_{iface}_before_{output_tag}.txt").write_text(before.stdout + before.stderr, encoding="utf-8")
        if disable_offloads:
            subprocess.run([ethtool, "-K", iface, "tso", "off", "gso", "off", "gro", "off"], text=True, capture_output=True, check=False)
        after = subprocess.run([ethtool, "-k", iface], text=True, capture_output=True, check=False)
        (offload_dir / f"offload_{iface}_after_{output_tag}.txt").write_text(after.stdout + after.stderr, encoding="utf-8")
        settings[iface] = {
            "before_file": str(offload_dir / f"offload_{iface}_before_{output_tag}.txt"),
            "after_file": str(offload_dir / f"offload_{iface}_after_{output_tag}.txt"),
        }
    return settings


def parse_tc_summary(text: str) -> dict[str, Any]:
    qdisc_match = re.search(r"\bqdisc\s+(\S+)", text)
    rate_match = re.search(r"\brate\s+([0-9.]+\s*[kKmMgG]?bit)", text)
    dropped = sum(int(value) for value in re.findall(r"\bdropped\s+(\d+)", text))
    overlimits = sum(int(value) for value in re.findall(r"\boverlimits\s+(\d+)", text))
    requeues = sum(int(value) for value in re.findall(r"\brequeues\s+(\d+)\)", text))
    backlog_match = re.search(r"\bbacklog\s+([^\n]+)", text)
    return {
        "qdisc_kind": qdisc_match.group(1) if qdisc_match else "",
        "qdisc_rate": rate_match.group(1).replace(" ", "") if rate_match else "",
        "qdisc_dropped_packets": dropped,
        "qdisc_overlimits": overlimits,
        "qdisc_requeues": requeues,
        "backlog": backlog_match.group(1).strip() if backlog_match else "",
    }


def configure_bottleneck_qdisc(iface: str, bottleneck_mbps: float, queue_limit_packets: int | None) -> dict[str, Any]:
    if queue_limit_packets is None:
        return {"configured": False}
    commands = [
        (["tc", "qdisc", "del", "dev", iface, "root"], True),
        (["tc", "qdisc", "add", "dev", iface, "root", "handle", "5:", "htb", "default", "1"], False),
        (
            [
                "tc",
                "class",
                "add",
                "dev",
                iface,
                "parent",
                "5:",
                "classid",
                "5:1",
                "htb",
                "rate",
                f"{bottleneck_mbps}mbit",
                "ceil",
                f"{bottleneck_mbps}mbit",
            ],
            False,
        ),
        (
            [
                "tc",
                "qdisc",
                "add",
                "dev",
                iface,
                "parent",
                "5:1",
                "handle",
                "10:",
                "netem",
                "limit",
                str(queue_limit_packets),
                "delay",
                "20ms",
            ],
            False,
        ),
    ]
    outputs = []
    for command, allow_failure in commands:
        proc = subprocess.run(command, text=True, capture_output=True, check=False)
        outputs.append({"command": shell_join(command), "returncode": proc.returncode, "output": proc.stdout + proc.stderr})
        if proc.returncode != 0 and not allow_failure:
            raise RuntimeError(f"Failed to configure qdisc on {iface}: {proc.stdout}{proc.stderr}".strip())
    return {
        "configured": True,
        "interface": iface,
        "rate_mbps": bottleneck_mbps,
        "queue_limit_packets": queue_limit_packets,
        "commands": outputs,
    }


def collect_tc_qdisc_state(ifaces: list[str], case_dir: Path, bottleneck_mbps: float, label: str, output_tag: str = "20260610") -> dict[str, Any]:
    state_dir = case_dir / "raw" / "tc_qdisc"
    state_dir.mkdir(parents=True, exist_ok=True)
    commands = [
        ("tc_s_d_qdisc_show", ["tc", "-s", "-d", "qdisc", "show", "dev"]),
        ("tc_s_d_class_show", ["tc", "-s", "-d", "class", "show", "dev"]),
        ("tc_s_qdisc_show", ["tc", "-s", "qdisc", "show", "dev"]),
        ("tc_d_qdisc_show", ["tc", "-d", "qdisc", "show", "dev"]),
        ("tc_s_class_show", ["tc", "-s", "class", "show", "dev"]),
        ("tc_d_class_show", ["tc", "-d", "class", "show", "dev"]),
        ("ip_s_link_show", ["ip", "-s", "link", "show", "dev"]),
    ]
    output: dict[str, Any] = {
        "label": label,
        "configured_bottleneck_mbps": bottleneck_mbps,
        "interfaces": {},
    }
    for iface in ifaces:
        iface_summary: dict[str, Any] = {"files": {}}
        command_outputs: dict[str, str] = {}
        for name, prefix in commands:
            path = state_dir / f"{name}_{iface}_{label}_{output_tag}.txt"
            proc = subprocess.run([*prefix, iface], text=True, capture_output=True, check=False)
            text = proc.stdout + proc.stderr
            path.write_text(text, encoding="utf-8")
            iface_summary["files"][name] = str(path)
            command_outputs[name] = text
        qdisc_text = command_outputs.get("tc_s_d_qdisc_show") or command_outputs.get("tc_s_qdisc_show", "")
        class_text = command_outputs.get("tc_s_d_class_show") or command_outputs.get("tc_s_class_show", "")
        qdisc_summary = parse_tc_summary(qdisc_text)
        class_summary = parse_tc_summary(class_text)
        if class_summary.get("qdisc_rate"):
            qdisc_summary["qdisc_rate"] = class_summary["qdisc_rate"]
        iface_summary.update(qdisc_summary)
        output["interfaces"][iface] = iface_summary
    return output


def start_tcp_info_collector(host: Any, args: argparse.Namespace, case_dir: Path, start_epoch_ns: int) -> Any:
    tcp_dir = case_dir / "raw" / "tcp_info" / args.case_id
    tcp_dir.mkdir(parents=True, exist_ok=True)
    return run_host_background(
        host,
        [
            sys.executable,
            str(Path(__file__).resolve().with_name("collect_tcp_rto.py")),
            "--case-id",
            args.case_id,
            "--scenario",
            args.scenario,
            "--condition-id",
            args.condition_id,
            "--seed",
            args.seed,
            "--receiver-ip",
            "10.0.0.2",
            "--receiver-port",
            "5201",
            "--duration-sec",
            args.duration_sec + 2.0,
            "--interval-ms",
            args.tcp_info_interval_ms,
            "--time-origin-epoch-ns",
            start_epoch_ns,
            "--csv-output",
            tcp_dir / f"tcp_info_timeseries_{args.output_tag}.csv",
            "--raw-log",
            tcp_dir / f"ss_raw_{args.output_tag}.log",
            "--sampler-metrics-output",
            tcp_dir / f"sampler_metrics_{args.output_tag}.txt",
            "--allow-unfiltered-fallback",
        ],
        case_dir / "logs" / f"tcp_info_collector_{args.output_tag}.log",
    )


def write_real_pulses_from_sender_logs(case_dir: Path, args: argparse.Namespace, experiment_start_wall: float) -> None:
    if args.scenario in {"no_attack", "constant_udp"}:
        if args.scenario == "constant_udp":
            write_pulses(
                case_dir,
                [
                    {
                        "pulse_index": 0,
                        "case_id": args.case_id,
                        "scenario": args.scenario,
                        "condition_id": args.condition_id,
                        "seed": args.seed,
                        "pulse_start_sec": args.attack_start_sec,
                        "pulse_end_sec": args.duration_sec,
                        "scheduled_start_epoch_ns": int((experiment_start_wall + args.attack_start_sec) * 1_000_000_000),
                        "actual_start_epoch_ns": int((experiment_start_wall + args.attack_start_sec) * 1_000_000_000),
                        "actual_end_epoch_ns": int((experiment_start_wall + args.duration_sec) * 1_000_000_000),
                        "configured_rate_mbps": args.configured_average_attack_mbps,
                        "actual_sent_bytes": "",
                    }
                ],
                args.output_tag,
            )
        else:
            write_pulses(case_dir, [], args.output_tag)
        return
    log_path = case_dir / "raw" / f"composite_sender_log_{args.output_tag}.csv"
    if not log_path.exists():
        write_pulses(case_dir, synthetic_pulses(args), args.output_tag)
        return
    with log_path.open(newline="") as f:
        rows = [row for row in csv.DictReader(f) if row.get("phase") == "attack_burst"]
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("period_index", "")), []).append(row)
    pulses: list[dict[str, Any]] = []
    for index, key in enumerate(sorted(grouped, key=lambda item: int(item) if str(item).isdigit() else 0)):
        group = grouped[key]
        phase_starts = [float(row.get("phase_start_sec") or 0.0) for row in group]
        phase_ends = [float(row.get("phase_end_sec") or 0.0) for row in group]
        first_sends = [float(row.get("first_send_sec") or row.get("phase_start_sec") or 0.0) for row in group]
        last_sends = [float(row.get("last_send_sec") or row.get("phase_end_sec") or 0.0) for row in group]
        bytes_sent = sum(int(float(row.get("byte_count") or 0)) for row in group)
        rates = sum(float(row.get("rate_mbps") or 0.0) for row in group)
        start = min(first_sends) if first_sends else min(phase_starts)
        end = max(last_sends) if last_sends else max(phase_ends)
        scheduled = min(phase_starts)
        pulses.append(
            {
                "pulse_index": index,
                "case_id": args.case_id,
                "scenario": args.scenario,
                "condition_id": args.condition_id,
                "seed": args.seed,
                "pulse_start_sec": start,
                "pulse_end_sec": end,
                "scheduled_start_epoch_ns": int((experiment_start_wall + scheduled) * 1_000_000_000),
                "actual_start_epoch_ns": int((experiment_start_wall + start) * 1_000_000_000),
                "actual_end_epoch_ns": int((experiment_start_wall + end) * 1_000_000_000),
                "configured_rate_mbps": rates,
                "actual_sent_bytes": bytes_sent,
            }
        )
    write_pulses(case_dir, pulses, args.output_tag)


def run_attack_sender(host: Any, args: argparse.Namespace, case_dir: Path, existing_repo: Path, experiment_start_wall: float) -> Any:
    if args.scenario == "no_attack":
        return None
    log_dir = case_dir / "logs"
    if args.scenario == "constant_udp":
        return run_host_background(
            host,
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("send_constant_udp.py")),
                "--dst-ip",
                "10.0.0.2",
                "--dst-port",
                "5001",
                "--duration-sec",
                args.duration_sec,
                "--attack-start-sec",
                args.attack_start_sec,
                "--total-rate-mbps",
                args.configured_average_attack_mbps,
                "--num-flows",
                args.num_attack_flows,
                "--payload-size",
                args.payload_size,
                "--log",
                case_dir / "raw" / f"constant_udp_send_log_{args.output_tag}.csv",
                "--summary-json",
                case_dir / "raw" / f"constant_udp_summary_{args.output_tag}.json",
            ],
            log_dir / f"constant_udp_sender_{args.output_tag}.log",
        )

    sender_scenario = SCENARIO_MAP[args.scenario]
    attack_mode = "multi_flow_sync_lddos"
    payload_mode = "fixed"
    jitter_ratio = 0.0
    phase_spread_ms = 0.0
    feint_rate_ratio = 0.0
    attack_interval_placement = "start"
    if args.scenario == "random_microburst":
        sender_scenario = "composite_lddos"
        attack_mode = "multi_flow_sync_lddos"
        jitter_ratio = 0.5
        phase_spread_ms = 0.0
    elif args.scenario == "stat_matched_ldos":
        attack_mode = "f_lddos"
        payload_mode = "empirical"
        jitter_ratio = 0.5
        phase_spread_ms = min(args.burst_ms * 0.5, 200.0)
        feint_rate_ratio = 0.10
        attack_interval_placement = "end"

    command = [
        sys.executable,
        existing_repo / "mininet_experiment" / "traffic_generators" / "send_composite_lddos.py",
        "--dst-ip",
        "10.0.0.2",
        "--dst-port",
        "5001",
        "--base-src-port",
        "40000",
        "--duration-sec",
        args.duration_sec,
        "--attack-start-sec",
        args.attack_start_sec,
        "--experiment-start-wall",
        experiment_start_wall,
        "--scenario",
        sender_scenario,
        "--attack-mode",
        attack_mode,
        "--total-attack-rate-mbps",
        args.peak_rate_mbps,
        "--num-attack-flows",
        args.num_attack_flows,
        "--burst-ms",
        int(round(args.burst_ms)),
        "--period-ms",
        int(round(args.period_ms)),
        "--payload-size",
        args.payload_size,
        "--payload-mode",
        payload_mode,
        "--phase-spread-ms",
        phase_spread_ms,
        "--jitter-ratio",
        jitter_ratio,
        "--feint-rate-ratio",
        feint_rate_ratio,
        "--attack-interval-placement",
        attack_interval_placement,
        "--seed",
        args.seed,
        "--log",
        case_dir / "raw" / f"composite_sender_log_{args.output_tag}.csv",
        "--summary-json",
        case_dir / "raw" / f"composite_sender_summary_{args.output_tag}.json",
    ]
    if args.scenario == "stat_matched_ldos":
        command.extend(["--target-total-average-rate-mbps", args.configured_average_attack_mbps])
    if args.scenario == "random_microburst":
        command.append("--randomize-pulse-start")

    return run_host_background(
        host,
        command,
        log_dir / f"composite_sender_{args.output_tag}.log",
    )


def write_detector_from_existing(case_dir: Path, args: argparse.Namespace, existing_repo: Path, time_origin_sec: float) -> None:
    if args.scenario == "no_attack":
        write_empty_detector(case_dir, args)
        return
    pcap = case_dir / "raw" / "pcaps" / f"egress_after_bottleneck_{args.output_tag}.pcap"
    if not pcap.exists():
        write_empty_detector(case_dir, args)
        return
    sys.path.insert(0, str(existing_repo))
    sys.path.insert(0, str(existing_repo / "mininet_experiment"))
    try:
        from pcap_to_features import build_features_from_pcap
        from src.paper_reproduction_detector import PaperDetectorConfig, PaperReproductionDetector
    except Exception as exc:
        raise RuntimeError(f"Failed to import existing detector pipeline: {exc}") from exc

    features, _packets = build_features_from_pcap(
        pcap_path=pcap,
        bucket_ms=int(round(args.bucket_ms)),
        window_sec=args.bucket_ms / 1000.0,
        step_sec=args.bucket_ms / 1000.0,
        duration_sec=args.duration_sec,
        attack_start_sec=args.attack_start_sec,
        time_origin_sec=time_origin_sec,
        dst_port=5001,
        phase_intervals=case_dir / "raw" / f"composite_sender_log_{args.output_tag}.csv"
        if (case_dir / "raw" / f"composite_sender_log_{args.output_tag}.csv").exists()
        else None,
        min_overlap_sec=args.bucket_ms / 1000.0,
    )
    predictions = PaperReproductionDetector(
        PaperDetectorConfig(warmup_windows=0, min_packets_for_detection=1, suspicious_threshold=2)
    ).predict_stream(features)
    out = case_dir / "raw" / "detector" / f"detector_windows_{args.output_tag}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        fields = [
            "timestamp_sec",
            "attack_active",
            "attack_period_active",
            "attack_burst_active",
            "detector_attack",
            "suspicious_score",
            "iat_variance",
            "burst_rate",
            "payload_size_variance",
            "new_flow_rate",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for _, row in predictions.iterrows():
            ts = float(row.get("window_start_sec", row.get("timestamp_sec", 0.0)))
            writer.writerow(
                {
                    "timestamp_sec": ts,
                    "attack_active": int(ts >= args.attack_start_sec and args.scenario != "no_attack"),
                    "attack_period_active": int(ts >= args.attack_start_sec and args.scenario != "no_attack"),
                    "attack_burst_active": int(bool(row.get("target_burst", False))),
                    "detector_attack": int(bool(row.get("attack_detected", False))),
                    "suspicious_score": int(row.get("suspicious_score", 0)),
                    "iat_variance": float(row.get("iat_variance", 0.0)),
                    "burst_rate": float(row.get("burst_rate", 0.0)),
                    "payload_size_variance": float(row.get("payload_size_variance", 0.0)),
                    "new_flow_rate": float(row.get("new_flow_arrival_rate", 0.0)),
                }
            )


def write_empty_detector(case_dir: Path, args: argparse.Namespace) -> None:
    bucket_sec = args.bucket_ms / 1000.0
    steps = int(math.ceil(args.duration_sec / bucket_sec))
    out = case_dir / "raw" / "detector" / f"detector_windows_{args.output_tag}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp_sec",
                "attack_active",
                "attack_period_active",
                "attack_burst_active",
                "detector_attack",
                "suspicious_score",
                "iat_variance",
                "burst_rate",
                "payload_size_variance",
                "new_flow_rate",
            ],
        )
        writer.writeheader()
        for step in range(steps):
            writer.writerow(
                {
                    "timestamp_sec": step * bucket_sec,
                    "attack_active": 0,
                    "attack_period_active": 0,
                    "attack_burst_active": 0,
                    "detector_attack": 0,
                    "suspicious_score": 0,
                    "iat_variance": 0,
                    "burst_rate": 0,
                    "payload_size_variance": 0,
                    "new_flow_rate": 0,
                }
            )


def run_real_case(args: argparse.Namespace, case_dir: Path, metadata: dict[str, Any]) -> None:
    assert_real_environment()
    existing_repo = find_existing_repo_dir(args)
    mininet_dir = existing_repo / "mininet_experiment"
    sys.path.insert(0, str(mininet_dir))
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet
    from minimal_topo import MinimalABTopo

    cleanup()
    network = None
    procs: list[Any] = []
    ingress_tcpdump = None
    egress_tcpdump = None
    tcp_info_collector = None
    tc_state_before: dict[str, Any] = {}
    tc_state_after: dict[str, Any] = {}
    experiment_start_wall = time.time()
    case_start_epoch_ns = time.time_ns()
    case_start_monotonic_ns = time.monotonic_ns()
    try:
        network = Mininet(topo=MinimalABTopo(), link=TCLink, autoSetMacs=True, autoStaticArp=True)
        network.start()
        h1, h2, h3 = [network.get(name) for name in ("h1", "h2", "h3")]
        ingress_iface, egress_iface = find_bottleneck_ifaces(network, args)
        offload_settings = collect_offload_settings([ingress_iface, egress_iface], case_dir, args.disable_offloads, args.output_tag)
        qdisc_config = configure_bottleneck_qdisc(ingress_iface, args.bottleneck_mbps, args.queue_limit_packets)
        tc_state_before = collect_tc_qdisc_state([ingress_iface, egress_iface], case_dir, args.bottleneck_mbps, "before", args.output_tag)
        ingress_pcap = case_dir / "raw" / "pcaps" / f"ingress_before_bottleneck_{args.output_tag}.pcap"
        egress_pcap = case_dir / "raw" / "pcaps" / f"egress_after_bottleneck_{args.output_tag}.pcap"
        ingress_tcpdump = start_root_tcpdump(ingress_iface, ingress_pcap, case_dir / "raw" / "tcpdump" / f"ingress_{args.output_tag}.log")
        egress_tcpdump = start_root_tcpdump(egress_iface, egress_pcap, case_dir / "raw" / "tcpdump" / f"egress_{args.output_tag}.log")
        time.sleep(0.5)
        iperf_server = run_host_background(h2, ["iperf3", "-s", "-p", "5201"], case_dir / "logs" / f"iperf_server_{args.output_tag}.log")
        procs.append(iperf_server)
        time.sleep(0.5)
        case_start_epoch_ns = time.time_ns()
        case_start_monotonic_ns = time.monotonic_ns()
        if not args.disable_tcp_info:
            tcp_info_collector = start_tcp_info_collector(h1, args, case_dir, case_start_epoch_ns)
            procs.append(tcp_info_collector)
        iperf_command: list[Any] = ["iperf3", "-c", "10.0.0.2", "-p", "5201", "-t", int(args.duration_sec), "-P", "1", "-i", "1", "-J"]
        if args.tcp_target_mbps:
            iperf_command.extend(["-b", f"{args.tcp_target_mbps}M"])
        if args.tcp_pacing_timer_us:
            iperf_command.extend(["--pacing-timer", str(args.tcp_pacing_timer_us)])
        iperf_client = run_host_background(
            h1,
            iperf_command,
            case_dir / "raw" / "iperf" / f"iperf_client_{args.output_tag}.json",
        )
        procs.append(iperf_client)
        experiment_start_wall = time.time()
        sender = run_attack_sender(h3, args, case_dir, existing_repo, experiment_start_wall)
        if sender is not None:
            procs.append(sender)
        iperf_client.wait(timeout=args.duration_sec + 30.0)
        if sender is not None:
            sender.wait(timeout=max(args.duration_sec + 30.0, 30.0))
        if tcp_info_collector is not None:
            try:
                tcp_info_collector.wait(timeout=5.0)
            except Exception:
                pass
        time.sleep(1.0)
        tc_state_after = collect_tc_qdisc_state([ingress_iface, egress_iface], case_dir, args.bottleneck_mbps, "after", args.output_tag)
        write_real_pulses_from_sender_logs(case_dir, args, experiment_start_wall)
        shaping_summary = tc_state_after.get("interfaces", {}).get(ingress_iface, {})
        metadata.update(
            {
                "mode": "real-mininet",
                "status": "success",
                "error_message": "",
                "existing_repo_dir": str(existing_repo),
                "capture_ingress_iface": ingress_iface,
                "capture_egress_iface": egress_iface,
                "capture_ingress_pcap": str(ingress_pcap),
                "capture_egress_pcap": str(egress_pcap),
                "experiment_start_wall": experiment_start_wall,
                "case_start_epoch_ns": case_start_epoch_ns,
                "case_start_monotonic_ns": case_start_monotonic_ns,
                "offload_settings": offload_settings,
                "shaping_interface": ingress_iface,
                "configured_bottleneck_mbps": args.bottleneck_mbps,
                "qdisc_kind": shaping_summary.get("qdisc_kind", ""),
                "qdisc_rate": shaping_summary.get("qdisc_rate", ""),
                "qdisc_dropped_packets": shaping_summary.get("qdisc_dropped_packets", 0),
                "qdisc_overlimits": shaping_summary.get("qdisc_overlimits", 0),
                "qdisc_requeues": shaping_summary.get("qdisc_requeues", 0),
                "qdisc_backlog": shaping_summary.get("backlog", ""),
                "qdisc_configuration": qdisc_config,
                "tc_qdisc_state_before": tc_state_before,
                "tc_qdisc_state_after": tc_state_after,
                "rto_observation_source": "ss_tcp_info" if not args.disable_tcp_info else "",
            }
        )
        write_detector_from_existing(case_dir, args, existing_repo, experiment_start_wall)
    except Exception as exc:
        metadata.update({"mode": "real-mininet", "status": "failed", "error_message": str(exc)})
        write_empty_detector(case_dir, args)
        raise
    finally:
        stop_process(ingress_tcpdump)
        stop_process(egress_tcpdump)
        for proc in reversed(procs):
            stop_process(proc)
        if network is not None:
            network.stop()
        cleanup()


def main() -> int:
    args = parse_args()
    validate_args(args)
    case_dir = ensure_case_dirs(args.output_dir, args.case_id)
    metadata = base_metadata(args, case_dir)
    try:
        if args.dry_run or args.synthetic_test:
            run_synthetic_case(args, case_dir, metadata)
        else:
            run_real_case(args, case_dir, metadata)
        write_metadata(case_dir, metadata, args.output_tag)
        print(f"case complete: {args.case_id}")
        return 0
    except Exception as exc:
        metadata.setdefault("mode", "unknown")
        metadata["status"] = "failed"
        metadata["error_message"] = str(exc)
        write_metadata(case_dir, metadata, args.output_tag)
        print(f"case failed: {args.case_id}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
