#!/usr/bin/env python3
"""Check evaluation artifacts without rewriting results or claiming research success."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def validate_outputs(payload: Path, expected: list[str]) -> None:
    for name in expected:
        path = payload / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty evaluation artifact: {path}")
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))
        elif path.suffix == ".csv":
            with path.open(newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                if not reader.fieldnames or next(reader, None) is None:
                    raise ValueError(f"CSV has no data rows: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.run_dir / "manifest.json").read_text())
    if manifest["status"] != "succeeded":
        raise ValueError(f"run status is {manifest['status']}")
    validate_outputs(args.run_dir / "payload", manifest["profile"]["expected_outputs"])
    print("Evaluation artifacts present and readable; this is not a research acceptance criterion.")


if __name__ == "__main__":
    main()
