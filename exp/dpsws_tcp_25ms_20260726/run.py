#!/usr/bin/env python3
"""Run one additional TCP-unlimited trial with the unchanged 2026-07-24 runner."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "exp" / "dpsws_tcp_unlimited_20260724" / "run.py"


def main() -> int:
    spec = importlib.util.spec_from_file_location("dpsws_tcp_unlimited_source", SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SOURCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return int(module.main())


if __name__ == "__main__":
    raise SystemExit(main())
