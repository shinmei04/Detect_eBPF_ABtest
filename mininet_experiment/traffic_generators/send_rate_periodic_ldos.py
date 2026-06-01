"""Send rate-based periodic LDoS UDP bursts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from rate_common import add_rate_sender_arguments, periodic_burst_plan, send_burst_plan


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Send R/L/T rate-based periodic LDoS traffic.")
    add_rate_sender_arguments(parser)
    return parser.parse_args()


def main() -> None:
    """Send periodic LDoS bursts and write measured burst logs."""
    args = parse_args()
    send_burst_plan(args, periodic_burst_plan(args), mode="periodic_ldos_rate")


if __name__ == "__main__":
    main()
