#!/usr/bin/env python3
"""Create the representative DPSWS TCP/UDP time-sequence figure."""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    experiment_dir = Path(__file__).resolve().parent
    output_dir = args.output_dir or experiment_dir / "out" / datetime.now().strftime("%Y%m%d_%H%M%S")
    command = [
        sys.executable,
        str(experiment_dir / "analyze.py"),
        "--output-dir",
        str(output_dir),
    ]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
