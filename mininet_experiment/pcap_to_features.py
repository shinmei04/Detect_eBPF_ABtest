"""Convert a Mininet UDP pcap into four-feature detector windows.

The parser uses ``tcpdump`` instead of scapy to keep requirements minimal on
WSL2 Ubuntu. Only UDP packets matching the selected destination port are used.
"""

from __future__ import annotations

import argparse
import math
import re
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.paper_reproduction_detector import compute_paper_window_features
from src.utils import count_buckets_for_duration


TCPDUMP_UDP_RE = re.compile(
    r"^(?P<timestamp>\d+(?:\.\d+)?)\s+IP\s+"
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.(?P<src_port>\d+)\s+>\s+"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?P<dst_port>\d+):\s+UDP,\s+length\s+"
    r"(?P<length>\d+)"
)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Convert UDP pcap to paper-detector features.")
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packets-output", type=Path)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--duration-sec", type=float)
    parser.add_argument("--attack-start-sec", type=float)
    parser.add_argument("--dst-port", type=int, default=5001)
    return parser.parse_args()


def main() -> None:
    """CLI entry point."""
    args = parse_args()
    features, packets = build_features_from_pcap(
        pcap_path=args.pcap,
        bucket_ms=args.bucket_ms,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
        duration_sec=args.duration_sec,
        attack_start_sec=args.attack_start_sec,
        dst_port=args.dst_port,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(args.output, index=False)
    if args.packets_output is not None:
        args.packets_output.parent.mkdir(parents=True, exist_ok=True)
        packets.to_csv(args.packets_output, index=False)


def build_features_from_pcap(
    pcap_path: Path,
    bucket_ms: int,
    window_sec: float,
    step_sec: float,
    duration_sec: float | None,
    attack_start_sec: float | None,
    dst_port: int = 5001,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Parse pcap and return ``(features, packets)`` DataFrames."""
    packets = parse_udp_pcap(pcap_path, dst_port=dst_port)
    if packets.empty:
        raise RuntimeError(f"no UDP packets for dst port {dst_port} found in {pcap_path}")

    first_timestamp = float(packets["timestamp"].min())
    packets = packets.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    packets["timestamp_sec"] = packets["timestamp"] - first_timestamp
    packets["bucket_index"] = np.floor(packets["timestamp_sec"] / (bucket_ms / 1000.0)).astype(int)
    packets["flow_id"] = (
        packets["src_ip"].astype(str)
        + ":"
        + packets["src_port"].astype(str)
        + ">"
        + packets["dst_ip"].astype(str)
        + ":"
        + packets["dst_port"].astype(str)
    )

    if duration_sec is None:
        duration_sec = max(float(packets["timestamp_sec"].max()) + bucket_ms / 1000.0, window_sec)
    total_buckets = count_buckets_for_duration(duration_sec, bucket_ms)
    buckets = [0] * total_buckets
    for bucket_index, count in packets["bucket_index"].value_counts().items():
        index = int(bucket_index)
        if 0 <= index < total_buckets:
            buckets[index] = int(count)

    feature_packets = packets.rename(columns={"timestamp_sec": "timestamp_sec"})[
        ["timestamp_sec", "bucket_index", "packet_size", "flow_id"]
    ]
    features = compute_paper_window_features(
        packets=feature_packets,
        buckets=buckets,
        bucket_ms=bucket_ms,
        window_sec=window_sec,
        step_sec=step_sec,
        label="",
    )
    if attack_start_sec is None:
        features["label"] = "unknown"
    else:
        features["label"] = np.where(features["window_start_sec"] >= attack_start_sec, "attack", "benign")
    features["target"] = (features["label"] == "attack").astype(int)
    return features, packets


def parse_udp_pcap(pcap_path: Path, dst_port: int = 5001) -> pd.DataFrame:
    """Parse UDP packet records from a pcap using tcpdump text output."""
    if not pcap_path.exists():
        raise FileNotFoundError(pcap_path)
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        raise RuntimeError("tcpdump is required to parse pcap files. Install it with apt.")

    command = [tcpdump, "-tt", "-nn", "-r", str(pcap_path), "udp"]
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"tcpdump failed: {completed.stderr.strip()}")

    rows: list[dict[str, object]] = []
    for line in completed.stdout.splitlines():
        match = TCPDUMP_UDP_RE.match(line.strip())
        if not match:
            continue
        parsed_dst_port = int(match.group("dst_port"))
        if parsed_dst_port != dst_port:
            continue
        rows.append(
            {
                "timestamp": float(match.group("timestamp")),
                "src_ip": match.group("src_ip"),
                "dst_ip": match.group("dst_ip"),
                "src_port": int(match.group("src_port")),
                "dst_port": parsed_dst_port,
                "packet_size": int(match.group("length")),
            }
        )

    frame = pd.DataFrame(
        rows,
        columns=["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "packet_size"],
    )
    if not frame.empty:
        frame = frame.replace([math.inf, -math.inf], np.nan).dropna(subset=["timestamp"])
    return frame.reset_index(drop=True)


if __name__ == "__main__":
    main()
