"""Protect the harness boundary: no result overwrite, escaping paths, or false success."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HARNESS = Path(__file__).resolve().parents[1] / "exp/evaluation_harness_20260906"
sys.path.insert(0, str(HARNESS))
spec = importlib.util.spec_from_file_location("evaluation_harness", HARNESS / "run.py")
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)
sys.path.pop(0)


class HarnessTests(unittest.TestCase):
    def test_existing_result_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            output = harness.reserve_output(parent, "20260906_123456")
            sentinel = output / "result.csv"
            sentinel.write_bytes(b"original result")
            with self.assertRaises(FileExistsError):
                harness.reserve_output(parent, "20260906_123456")
            self.assertEqual(sentinel.read_bytes(), b"original result")

    def test_run_id_cannot_escape_output_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for value in ("../raw", "/tmp/data", "20269999_123456"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    harness.reserve_output(parent, value)
            self.assertEqual(list(parent.iterdir()), [])

    def test_config_cannot_redirect_output_even_with_argparse_abbreviation(self):
        profile = harness.load_profile(HARNESS.parents[1] / "configs/smoke.json")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            for option in ("--output-dir", "--out", "--output-dir=/tmp/results", "--run-id"):
                profile["args"] = [option]
                path.write_text(json.dumps(profile))
                with self.subTest(option=option), self.assertRaises(ValueError):
                    harness.load_profile(path)

    def test_output_contract_rejects_missing_empty_and_invalid_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary)
            with self.assertRaises(ValueError):
                harness.validate_outputs(payload, ["metrics.json"])
            (payload / "metrics.json").write_text("broken json")
            with self.assertRaises(ValueError):
                harness.validate_outputs(payload, ["metrics.json"])
            (payload / "windows.csv").write_text("label,score\n")
            with self.assertRaises(ValueError):
                harness.validate_outputs(payload, ["windows.csv"])

    def test_expected_paths_stay_in_payload(self):
        profile = harness.load_profile(HARNESS.parents[1] / "configs/smoke.json")
        profile["expected_outputs"] = ["../raw.csv"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(profile))
            with self.assertRaises(ValueError):
                harness.load_profile(path)


if __name__ == "__main__":
    unittest.main()
