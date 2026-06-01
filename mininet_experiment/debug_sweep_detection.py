"""Create debug outputs for throughput parameter sweep detector results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.sweep_debug import write_debug_outputs


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Debug detector inconsistency in throughput parameter sweep outputs.")
    parser.add_argument("--sweep-dir", type=Path, default=Path("results_throughput_sweep"))
    parser.add_argument("--output-dir", type=Path, default=Path("results_sweep_debug"))
    parser.add_argument("--original-window-log", type=Path)
    parser.add_argument("--stat-window-log", type=Path)
    return parser.parse_args()


def main() -> None:
    """Write sweep debug CSV and Markdown files."""
    args = parse_args()
    write_debug_outputs(
        sweep_dir=args.sweep_dir,
        output_dir=args.output_dir,
        original_path=args.original_window_log,
        stat_path=args.stat_window_log,
    )


if __name__ == "__main__":
    main()
