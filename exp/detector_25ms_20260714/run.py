#!/usr/bin/env python3
"""Run the saved-pcap 25 ms detector evaluation."""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from analyze import evaluate


SCRIPT_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--run-id", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_id = args.run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (args.output_dir or SCRIPT_DIR / "out" / run_id).resolve()
    evaluate(output_dir)
    print(f"OUTPUT_DIR={output_dir}")
    print(f"SUMMARY={output_dir / 'detector_summary_25ms.csv'}")
    print(f"REPORT={output_dir / 'detector_report_25ms.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

