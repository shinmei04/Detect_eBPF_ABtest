"""CLI for Phase 1.5 seed sweep experiments."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.detector_dataset import DEFAULT_SEEDS, SimulationConfig
from src.seed_sweep import run_seed_sweep


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run Phase 1.5 seed sweep.")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--bucket-ms", type=int, default=25)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--window-sec", type=float, default=4.0)
    parser.add_argument("--step-sec", type=float, default=1.0)
    parser.add_argument("--seeds", type=int, nargs="+", default=DEFAULT_SEEDS)
    parser.add_argument("--output-dir", type=Path, default=Path("results_seed_sweep"))
    return parser.parse_args()


def main() -> None:
    """Run seed sweep from the CLI."""
    args = parse_args()
    config = SimulationConfig(
        duration_sec=args.duration_sec,
        bucket_ms=args.bucket_ms,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        burst_pkts_per_bucket=args.burst_pkts_per_bucket,
        window_sec=args.window_sec,
        step_sec=args.step_sec,
    )
    results = run_seed_sweep(config, args.seeds, args.output_dir)
    print(f"Wrote seed sweep results to {args.output_dir.resolve()}")
    print(f"Seeds: {', '.join(str(seed) for seed in args.seeds)}")
    print(
        "periodic_ldos > random_microburst for normalized_1hz_power: "
        f"{int((results['normalized_1hz_power_periodic'] > results['normalized_1hz_power_random']).sum())}/"
        f"{len(results)}"
    )


if __name__ == "__main__":
    main()
