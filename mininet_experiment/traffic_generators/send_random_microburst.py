"""Send stat-matched random microburst UDP traffic in Mininet."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from common import add_sender_arguments, send_bucket_pattern
from src.pattern_generator import generate_random_microburst_buckets


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Send random microburst UDP bucket pattern.")
    add_sender_arguments(parser)
    parser.add_argument("--period-ms", type=int, default=1000)
    parser.add_argument("--burst-ms", type=int, default=200)
    parser.add_argument("--burst-pkts-per-bucket", type=int, default=10)
    parser.add_argument("--seed", type=int, default=1)
    return parser.parse_args()


def main() -> None:
    """Generate the seeded random microburst bucket pattern and send it."""
    args = parse_args()
    buckets = generate_random_microburst_buckets(
        duration_sec=args.duration_sec,
        bucket_ms=args.bucket_ms,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        burst_pkts_per_bucket=args.burst_pkts_per_bucket,
        seed=args.seed,
    )
    send_bucket_pattern(buckets, args, mode="random_microburst")


if __name__ == "__main__":
    main()
