#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Small UDP sender for the constant_udp reference scenario.  It sends the same
configured average rate as the bursty scenarios, starting at attack_start_sec.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import socket
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, default=5001)
    parser.add_argument("--base-src-port", type=int, default=41000)
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--attack-start-sec", type=float, required=True)
    parser.add_argument("--total-rate-mbps", type=float, required=True)
    parser.add_argument("--num-flows", type=int, default=1)
    parser.add_argument("--payload-size", type=int, default=750)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--summary-json", type=Path, required=True)
    return parser.parse_args()


def validate(args: argparse.Namespace) -> None:
    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if not 0 <= args.attack_start_sec < args.duration_sec:
        raise ValueError("attack_start_sec must be in [0, duration_sec)")
    if args.total_rate_mbps <= 0:
        raise ValueError("total-rate-mbps must be positive")
    if args.num_flows <= 0:
        raise ValueError("num-flows must be positive")
    if args.payload_size <= 0:
        raise ValueError("payload-size must be positive")


def sleep_until(deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.01))


def main() -> int:
    args = parse_args()
    validate(args)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    sockets = []
    for flow in range(args.num_flows):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", args.base_src_port + flow))
        sockets.append(sock)

    per_flow_rate_mbps = args.total_rate_mbps / args.num_flows
    interval_sec = args.payload_size * 8.0 / (per_flow_rate_mbps * 1_000_000.0)
    payload = b"C" * args.payload_size
    rows = []
    start = time.monotonic()
    sent_bytes = [0 for _ in sockets]
    sent_packets = [0 for _ in sockets]
    try:
        sleep_until(start + args.attack_start_sec)
        next_send = [start + args.attack_start_sec + flow * interval_sec / args.num_flows for flow in range(args.num_flows)]
        while time.monotonic() < start + args.duration_sec:
            now = time.monotonic()
            flow = min(range(args.num_flows), key=lambda idx: next_send[idx])
            sleep_until(next_send[flow])
            if time.monotonic() >= start + args.duration_sec:
                break
            sockets[flow].sendto(payload, (args.dst_ip, args.dst_port))
            rel = time.monotonic() - start
            sent_bytes[flow] += args.payload_size
            sent_packets[flow] += 1
            rows.append({"timestamp_sec": rel, "flow_id": f"flow_{flow}", "payload_size": args.payload_size})
            next_send[flow] += interval_sec
    finally:
        for sock in sockets:
            sock.close()

    with args.log.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp_sec", "flow_id", "payload_size"])
        writer.writeheader()
        writer.writerows(rows)

    active_duration = max(args.duration_sec - args.attack_start_sec, 1e-9)
    total_bytes = sum(sent_bytes)
    summary = {
        "scenario": "constant_udp",
        "duration_sec": args.duration_sec,
        "attack_start_sec": args.attack_start_sec,
        "total_rate_mbps": args.total_rate_mbps,
        "num_flows": args.num_flows,
        "payload_size": args.payload_size,
        "sent_packets": sum(sent_packets),
        "sent_bytes": total_bytes,
        "actual_average_rate_mbps": total_bytes * 8.0 / active_duration / 1_000_000.0,
        "per_flow_packets": sent_packets,
        "per_flow_bytes": sent_bytes,
        "interval_sec": interval_sec,
    }
    args.summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if math.isnan(summary["actual_average_rate_mbps"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
