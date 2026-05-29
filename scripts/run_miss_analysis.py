"""Run stat-matched missed-attack analysis for Mininet detector outputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.miss_analysis import MissAnalysisConfig, run_miss_analysis


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Analyze stat-matched missed attack windows.")
    parser.add_argument("--stat-matched-dir", type=Path, required=True)
    parser.add_argument("--original-like-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--warmup-windows", type=int, default=20)
    parser.add_argument("--suspicious-threshold", type=int, default=2)
    parser.add_argument("--min-packets-for-detection", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    """Run miss analysis and print generated files."""
    args = parse_args()
    config = MissAnalysisConfig(
        stat_matched_dir=args.stat_matched_dir,
        original_like_dir=args.original_like_dir,
        output_dir=args.output_dir,
        warmup_windows=args.warmup_windows,
        suspicious_threshold=args.suspicious_threshold,
        min_packets_for_detection=args.min_packets_for_detection,
    )
    paths = run_miss_analysis(config)
    print(f"Wrote miss analysis to {args.output_dir.resolve()}")
    for name, path in sorted(paths.items()):
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
