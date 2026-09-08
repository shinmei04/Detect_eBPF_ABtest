#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Collect Linux TCP_INFO-like state for iperf3 TCP flows by periodically running
``ss -tin`` in the TCP sender namespace.  This collector is used because iperf3
owns the data socket, so the experiment runner cannot call TCP_INFO directly.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


TCP_INFO_FIELDS = [
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


STATE_LINE_RE = re.compile(
    r"^(?P<state>\S+)\s+\S+\s+\S+\s+"
    r"(?P<src>[^:\s]+):(?P<src_port>\S+)\s+"
    r"(?P<dst>[^:\s]+):(?P<dst_port>\S+)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--condition-id", required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--receiver-ip", default="10.0.0.2")
    parser.add_argument("--receiver-port", type=int, default=5201)
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--interval-ms", type=float, default=50.0)
    parser.add_argument("--time-origin-epoch-ns", type=int)
    parser.add_argument("--csv-output", required=True, type=Path)
    parser.add_argument("--raw-log", required=True, type=Path)
    parser.add_argument("--sampler-metrics-output", required=True, type=Path)
    parser.add_argument("--allow-unfiltered-fallback", action="store_true")
    return parser.parse_args()


def safe_float(value: Any, default: float = math.nan) -> float:
    if value in ("", None):
        return default
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    if value in ("", None, "*"):
        return default
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def parse_rate_mbps(value: str) -> float:
    text = value.strip()
    match = re.match(r"(?P<num>[-+]?\d+(?:\.\d+)?)(?P<unit>[KMG]?bps|[KMG]?Bps)?", text)
    if not match:
        return math.nan
    number = float(match.group("num"))
    unit = match.group("unit") or "bps"
    if unit.endswith("Bps"):
        number *= 8.0
        unit = unit.replace("Bps", "bps")
    scale = {"bps": 1e-6, "Kbps": 1e-3, "Mbps": 1.0, "Gbps": 1e3}
    return number * scale.get(unit, 1.0)


def parse_key_values(info_text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    tokens = info_text.replace(",", " ").split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if ":" in token:
            key, value = token.split(":", 1)
            values[key] = value
            index += 1
        elif token in {"pacing_rate", "delivery_rate"} and index + 1 < len(tokens):
            values[token] = tokens[index + 1]
            index += 2
        else:
            index += 1
    return values


def parse_ss_output(
    text: str,
    *,
    timestamp_epoch_ns: int,
    timestamp_sec: float,
    sample_duration_ms: float,
    scenario: str,
    condition_id: str,
    seed: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    info_parts: list[str] = []

    def flush() -> None:
        nonlocal current, info_parts
        if not current:
            return
        info_text = " ".join(info_parts)
        values = parse_key_values(info_text)
        retrans_value = values.get("retrans", "")
        retransmits = math.nan
        total_retrans = math.nan
        if "/" in retrans_value:
            left, right = retrans_value.split("/", 1)
            retransmits = safe_int(left, 0)
            total_retrans = safe_int(right, 0)
        elif retrans_value:
            retransmits = safe_int(retrans_value, 0)
        rtt_value = values.get("rtt", "")
        rtt_ms = math.nan
        rttvar_ms = math.nan
        if "/" in rtt_value:
            left, right = rtt_value.split("/", 1)
            rtt_ms = safe_float(left)
            rttvar_ms = safe_float(right)
        elif rtt_value:
            rtt_ms = safe_float(rtt_value)
        cc = ""
        for token in info_text.split():
            if ":" not in token and token not in {"cubic", "bbr", "reno", "dctcp"}:
                continue
            if token in {"cubic", "bbr", "reno", "dctcp"}:
                cc = token
                break
        current.update(
            {
                "timestamp_epoch_ns": timestamp_epoch_ns,
                "timestamp_sec": timestamp_sec,
                "sample_duration_ms": sample_duration_ms,
                "scenario": scenario,
                "condition_id": condition_id,
                "seed": seed,
                "congestion_control": cc,
                "rto_ms": safe_float(values.get("rto")),
                "backoff": safe_int(values.get("backoff"), 0),
                "retransmits": retransmits,
                "total_retrans": total_retrans,
                "lost": safe_int(values.get("lost"), 0),
                "unacked": safe_int(values.get("unacked"), 0),
                "sacked": safe_int(values.get("sacked"), 0),
                "cwnd": safe_float(values.get("cwnd")),
                "ssthresh": safe_float(values.get("ssthresh")),
                "rtt_ms": rtt_ms,
                "rttvar_ms": rttvar_ms,
                "mss": safe_int(values.get("mss"), 0),
                "pacing_rate_mbps": parse_rate_mbps(values.get("pacing_rate", "")),
                "delivery_rate_mbps": parse_rate_mbps(values.get("delivery_rate", "")),
                "bytes_acked": safe_float(values.get("bytes_acked")),
                "bytes_sent": safe_float(values.get("bytes_sent")),
                "ca_state": values.get("ca_state", ""),
                "observation_source": "ss_tcp_info",
            }
        )
        current["flow_id"] = (
            f"{current.get('source_ip')}:{current.get('source_port')}>"
            f"{current.get('destination_ip')}:{current.get('destination_port')}"
        )
        rows.append(current)
        current = None
        info_parts = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("State "):
            continue
        state_match = STATE_LINE_RE.match(line.strip())
        if state_match:
            flush()
            current = {
                "tcp_state": state_match.group("state"),
                "source_ip": state_match.group("src").strip("[]"),
                "source_port": safe_int(state_match.group("src_port").strip("*")),
                "destination_ip": state_match.group("dst").strip("[]"),
                "destination_port": safe_int(state_match.group("dst_port").strip("*")),
            }
        elif current is not None:
            info_parts.append(line.strip())
    flush()
    return rows


def run_ss(receiver_ip: str, receiver_port: int, allow_fallback: bool) -> subprocess.CompletedProcess[str]:
    filtered = ["ss", "-tin", "dst", receiver_ip, "dport", "=", f":{receiver_port}"]
    completed = subprocess.run(filtered, text=True, capture_output=True, check=False)
    if completed.returncode == 0 or not allow_fallback:
        return completed
    return subprocess.run(["ss", "-tin"], text=True, capture_output=True, check=False)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TCP_INFO_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    args = parse_args()
    if args.duration_sec <= 0:
        raise SystemExit("--duration-sec must be positive")
    if args.interval_ms <= 0:
        raise SystemExit("--interval-ms must be positive")
    args.raw_log.parent.mkdir(parents=True, exist_ok=True)
    args.sampler_metrics_output.parent.mkdir(parents=True, exist_ok=True)

    start_epoch_ns = args.time_origin_epoch_ns or time.time_ns()
    start_mono_ns = time.monotonic_ns()
    interval_sec = args.interval_ms / 1000.0
    deadline_ns = start_mono_ns + int(args.duration_sec * 1_000_000_000)
    next_sample_ns = start_mono_ns
    rows: list[dict[str, Any]] = []
    durations_ms: list[float] = []
    missed_deadlines = 0
    sample_count = 0
    cpu_before = resource.getrusage(resource.RUSAGE_SELF)
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_before = time.time()

    with args.raw_log.open("w", encoding="utf-8") as raw:
        while time.monotonic_ns() < deadline_ns:
            now_ns = time.monotonic_ns()
            if now_ns > next_sample_ns + int(interval_sec * 1_000_000_000):
                missed_deadlines += 1
            sleep_sec = (next_sample_ns - now_ns) / 1_000_000_000
            if sleep_sec > 0:
                time.sleep(sleep_sec)
            sample_mono_ns = time.monotonic_ns()
            sample_epoch_ns = start_epoch_ns + (sample_mono_ns - start_mono_ns)
            relative_sec = (sample_epoch_ns - start_epoch_ns) / 1_000_000_000
            cmd_start = time.monotonic_ns()
            completed = run_ss(args.receiver_ip, args.receiver_port, args.allow_unfiltered_fallback)
            cmd_end = time.monotonic_ns()
            duration_ms = (cmd_end - cmd_start) / 1_000_000.0
            durations_ms.append(duration_ms)
            sample_count += 1
            raw.write(f"# sample={sample_count} timestamp_epoch_ns={sample_epoch_ns} timestamp_sec={relative_sec:.9f} duration_ms={duration_ms:.3f} returncode={completed.returncode}\n")
            raw.write(completed.stdout)
            if completed.stderr:
                raw.write("\n# stderr\n")
                raw.write(completed.stderr)
            raw.write("\n")
            if completed.returncode == 0:
                rows.extend(
                    parse_ss_output(
                        completed.stdout,
                        timestamp_epoch_ns=sample_epoch_ns,
                        timestamp_sec=relative_sec,
                        sample_duration_ms=duration_ms,
                        scenario=args.scenario,
                        condition_id=args.condition_id,
                        seed=args.seed,
                    )
                )
            next_sample_ns += int(interval_sec * 1_000_000_000)

    write_csv(args.csv_output, rows)
    cpu_after = resource.getrusage(resource.RUSAGE_SELF)
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall_after = time.time()
    cpu_sec = (
        (cpu_after.ru_utime + cpu_after.ru_stime - cpu_before.ru_utime - cpu_before.ru_stime)
        + (child_after.ru_utime + child_after.ru_stime - child_before.ru_utime - child_before.ru_stime)
    )
    elapsed_sec = max(wall_after - wall_before, 1e-9)
    metrics = {
        "created_date": "2026-06-10",
        "purpose": "25 ms detector window comparison experiment",
        "case_id": args.case_id,
        "sample_count": sample_count,
        "tcp_info_rows": len(rows),
        "interval_ms": args.interval_ms,
        "mean_sample_duration_ms": sum(durations_ms) / len(durations_ms) if durations_ms else math.nan,
        "max_sample_duration_ms": max(durations_ms) if durations_ms else math.nan,
        "missed_deadline_count": missed_deadlines,
        "missed_deadline_rate": missed_deadlines / sample_count if sample_count else math.nan,
        "sampler_cpu_user_system_pct": 100.0 * cpu_sec / elapsed_sec,
        "observation_source": "ss_tcp_info",
    }
    args.sampler_metrics_output.write_text(
        "\n".join(f"{key}={value}" for key, value in metrics.items()) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
