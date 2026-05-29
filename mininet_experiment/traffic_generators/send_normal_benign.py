"""Send low-rate non-bursty benign UDP traffic for the original_like condition."""

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
from src.utils import count_buckets_for_duration


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Send low-rate ordinary benign UDP traffic.")
    add_sender_arguments(parser)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--payload-low", type=int, default=40)
    parser.add_argument("--payload-high", type=int, default=120)
    return parser.parse_args()


def main() -> None:
    """Generate low-rate benign traffic and send it over one UDP flow."""
    args = parse_args()
    total_buckets = count_buckets_for_duration(args.duration_sec, args.bucket_ms)
    buckets = [1 if bucket_index % 2 == 0 else 0 for bucket_index in range(total_buckets)]

    def payload_sizer(packet_index: int) -> int:
        return int(args.payload_low if packet_index % 2 == 0 else args.payload_high)

    send_bucket_pattern(buckets, args, mode="normal_benign", payload_sizer=payload_sizer)


if __name__ == "__main__":
    main()
