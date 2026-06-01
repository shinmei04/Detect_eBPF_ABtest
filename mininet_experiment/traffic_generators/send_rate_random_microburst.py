"""Send rate-matched non-periodic random microburst UDP traffic."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rate_common import add_rate_sender_arguments, random_microburst_plan, send_burst_plan


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Send rate-matched random microburst UDP traffic.")
    add_rate_sender_arguments(parser)
    return parser.parse_args()


def main() -> None:
    """Send random microbursts and write measured burst logs."""
    args = parse_args()
    send_burst_plan(args, random_microburst_plan(args), mode="random_microburst_rate")


if __name__ == "__main__":
    main()
