"""Collect selected TCP internal-state fields from ``ss -ti``."""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import time
from pathlib import Path


FIELD_PATTERNS = {
    "cwnd": re.compile(r"\bcwnd:(\d+)"),
    "rto_ms": re.compile(r"\brto:(\d+(?:\.\d+)?)"),
    "rtt_ms": re.compile(r"\brtt:(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)"),
    "retrans": re.compile(r"\bretrans:(\d+)/(\d+)"),
    "delivery_rate": re.compile(r"\bdelivery_rate\s+([^\s]+)"),
}


def parse_args() -> argparse.Namespace:
    """Parse collector arguments."""
    parser = argparse.ArgumentParser(description="Collect ss -ti TCP state.")
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--interval-sec", type=float, default=0.1)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def parse_ss(text: str) -> dict[str, object]:
    """Parse the first matching TCP socket from ss output."""
    result: dict[str, object] = {
        "cwnd": "",
        "rtt_ms": "",
        "rto_ms": "",
        "rttvar_ms": "",
        "delivery_rate": "",
        "retrans_current": "",
        "retrans_total": "",
        "raw_ss": " ".join(text.split()),
    }
    match = FIELD_PATTERNS["cwnd"].search(text)
    if match:
        result["cwnd"] = int(match.group(1))
    match = FIELD_PATTERNS["rto_ms"].search(text)
    if match:
        result["rto_ms"] = float(match.group(1))
    match = FIELD_PATTERNS["rtt_ms"].search(text)
    if match:
        result["rtt_ms"] = float(match.group(1))
        result["rttvar_ms"] = float(match.group(2))
    match = FIELD_PATTERNS["delivery_rate"].search(text)
    if match:
        result["delivery_rate"] = match.group(1)
    match = FIELD_PATTERNS["retrans"].search(text)
    if match:
        result["retrans_current"] = int(match.group(1))
        result["retrans_total"] = int(match.group(2))
    return result


def main() -> None:
    """Collect until duration expires."""
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    rows = []
    while time.monotonic() - started <= args.duration_sec:
        completed = subprocess.run(
            ["ss", "-tin", "dst", args.dst_ip, "dport", "=", f":{args.dst_port}"],
            check=False,
            text=True,
            capture_output=True,
        )
        row = parse_ss(completed.stdout)
        row["timestamp_sec"] = time.monotonic() - started
        rows.append(row)
        target = started + len(rows) * args.interval_sec
        delay = target - time.monotonic()
        if delay > 0:
            time.sleep(delay)

    fields = [
        "timestamp_sec",
        "cwnd",
        "rtt_ms",
        "rto_ms",
        "rttvar_ms",
        "delivery_rate",
        "retrans_current",
        "retrans_total",
        "raw_ss",
    ]
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
