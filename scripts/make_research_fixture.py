#!/usr/bin/env python3
"""Generate small artificial CSV fixtures ONLY. No sockets; no network model.

Rates are aggregate UDP payload rates. This generator is for code validation,
not evidence of realistic TCP effects or detector accuracy.
"""
from pathlib import Path
import argparse
import sys
import numpy as np
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.research_analysis import dump_json


def generate(args: argparse.Namespace) -> None:
    numeric = [args.period_sec, args.burst_sec, args.payload, args.flows, args.duration_sec, args.start_sec, args.jitter]
    if not np.isfinite(numeric).all() or min(numeric[:5]) <= 0 or not 0 <= args.jitter < 1:
        raise ValueError("invalid positive condition/jitter")
    if not 0 < args.start_sec < args.duration_sec or args.burst_sec >= args.period_sec * (1 - args.jitter):
        raise ValueError("require start inside duration and nonoverlapping jittered bursts")
    peak = args.peak_rate_mbps
    if args.average_rate_mbps is not None:
        derived = args.average_rate_mbps * args.period_sec / args.burst_sec
        if peak is not None and not np.isclose(peak, derived):
            raise ValueError("inconsistent peak and average rate: average = peak * burst / period")
        peak = derived
    peak = 0.5 if peak is None else peak
    if not np.isfinite(peak) or peak <= 0:
        raise ValueError("rate must be positive")
    # Safety/performance bound is for a small offline fixture, not a benchmark.
    if max(args.duration_sec * peak * 1e6 / (8 * args.payload), args.duration_sec * 800) > 100000:
        raise ValueError("fixture too large (>100k packets upper bound); use experimental PC data")
    args.output_dir.mkdir(parents=True, exist_ok=False)
    common = dict(period_sec=args.period_sec, burst_duration_sec=args.burst_sec, peak_rate_mbps=peak,
                  nominal_average_rate_mbps=peak * args.burst_sec / args.period_sec, payload_bytes=args.payload,
                  flow_count=args.flows, start_time_sec=args.start_sec, jitter_ratio=args.jitter)
    def packets(mode: str, seed: int) -> pd.DataFrame:
        rng = np.random.default_rng(seed)
        timestamps = []
        # Nonperiodic normal training, with >10 packets per 25 ms window.
        if mode in ("train", "baseline"):
            timestamps = np.sort(rng.uniform(0, args.duration_sec, int(args.duration_sec * 800)))
            sizes = rng.integers(64, 1501, size=len(timestamps))
        else:
            onset = args.start_sec
            while onset < args.duration_sec:
                stop = min(onset + args.burst_sec, args.duration_sec)
                interval = 8 * args.payload / (peak * 1e6)
                timestamps.extend(np.arange(onset + interval / 2, stop, interval))
                spacing = (args.burst_sec + rng.exponential(args.period_sec - args.burst_sec)
                           if mode == "random_microburst" else args.period_sec * (1 + rng.uniform(-args.jitter, args.jitter)))
                onset += spacing
            timestamps = np.array(timestamps)
            sizes = np.full(len(timestamps), args.payload)
        return pd.DataFrame(dict(timestamp_sec=timestamps, packet_size=sizes,
                                 flow_id=[f"udp:10.0.0.3:{40000+i % args.flows}>10.0.0.2:5001" for i in range(len(timestamps))]))
    packets("train", args.seed).to_csv(args.output_dir / "train.csv", index=False)
    cases = []
    for index, mode in enumerate(("baseline", "random_microburst", "benign_periodic", "periodic_ldos")):
        data = packets(mode, args.seed + index + 1)
        data.to_csv(args.output_dir / f"{mode}.csv", index=False)
        conditions = dict(common)
        if mode == "baseline":
            conditions = dict(distribution="iid_uniform_timestamps", mean_packets_per_sec=800,
                              payload_min_bytes=64, payload_max_bytes=1500, flow_count=args.flows)
        elif mode == "random_microburst":
            conditions.update(jitter_ratio=None, idle_distribution="exponential", mean_idle_sec=args.period_sec-args.burst_sec)
        cases.append(dict(id=mode, scenario=mode, seed=args.seed + index + 1, packets_csv=f"{mode}.csv",
                          duration_sec=args.duration_sec, attack_intervals=[[args.start_sec, args.duration_sec]] if mode == "periodic_ldos" else [],
                          conditions=conditions, measured_average_payload_rate_mbps=float(data.packet_size.sum() * 8 / args.duration_sec / 1e6)))
    dump_json(args.output_dir / "config.json", dict(schema_version=1, synthetic=True, input_scope="udp_dst_port",
        time_origin_description="Artificial t=0; fixture only", bucket_ms=25, window_sec=args.window_sec, step_sec=args.step_sec,
        training=dict(packets_csv="train.csv", duration_sec=args.duration_sec, label="benign"),
        detector=dict(warmup_windows=2, min_packets_for_detection=10), cases=cases,
        enable_temporal=True, temporal=dict(window_sec=args.temporal_window_sec, burst_threshold_packets=1,
                                          min_intervals=3, min_period_sec=0.1, max_period_sec=3.0)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--duration-sec", type=float, default=8)
    parser.add_argument("--period-sec", type=float, default=1)
    parser.add_argument("--burst-sec", type=float, default=0.2)
    parser.add_argument("--peak-rate-mbps", type=float)
    parser.add_argument("--average-rate-mbps", type=float)
    parser.add_argument("--payload", type=int, default=80)
    parser.add_argument("--flows", type=int, default=1)
    parser.add_argument("--start-sec", type=float, default=1)
    parser.add_argument("--jitter", type=float, default=0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--window-sec", type=float, default=0.025)
    parser.add_argument("--step-sec", type=float, default=0.025)
    parser.add_argument("--temporal-window-sec", type=float, default=4)
    generate(parser.parse_args())
