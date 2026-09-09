#!/usr/bin/env python3
"""Read an existing UDP PCAP with explicit epoch; no capture or transmission."""
from pathlib import Path
import argparse
import sys
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mininet_experiment.pcap_to_features import parse_udp_pcap
from src.research_analysis import dump_json, sha256

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--origin-epoch", type=float, required=True, help="Recorded run start in the capture clock")
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--dst-port", type=int, default=5001)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not np.isfinite([args.origin_epoch, args.duration_sec]).all() or args.origin_epoch <= 0 or args.duration_sec <= 0:
        parser.error("origin and duration must be finite and positive")
    if not 1 <= args.dst_port <= 65535:
        parser.error("invalid destination port")
    if args.output.exists() or args.output.with_suffix(".metadata.json").exists():
        parser.error("output exists; use a new analysis directory")
    packets = parse_udp_pcap(args.pcap, dst_port=args.dst_port)
    before = len(packets)
    packets["timestamp_sec"] = packets["timestamp"] - args.origin_epoch
    packets = packets[(packets.timestamp_sec >= 0) & (packets.timestamp_sec < args.duration_sec)].copy()
    packets["flow_id"] = "udp:" + packets.src_ip.astype(str) + ":" + packets.src_port.astype(str) + ">" + packets.dst_ip.astype(str) + ":" + packets.dst_port.astype(str)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    packets[["timestamp_sec", "packet_size", "flow_id"]].to_csv(args.output, index=False)
    dump_json(args.output.with_suffix(".metadata.json"), dict(pcap=str(args.pcap.resolve()), pcap_sha256=sha256(args.pcap),
        origin_epoch=args.origin_epoch, duration_sec=args.duration_sec, input_scope="udp_dst_port", dst_port=args.dst_port,
        retained_packets=len(packets), filtered_outside_duration=before-len(packets),
        caveat="IPv4 UDP only; empty input does not measure TCP false positives"))
