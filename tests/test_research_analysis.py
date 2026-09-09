"""Short offline tests; no sockets, Mininet, benchmarks or traffic capture."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json
from unittest.mock import patch
from dataclasses import asdict

import numpy as np
import pandas as pd

from src.paper_reproduction_detector import PAPER_FEATURES, PaperDetectorConfig, PaperFeatureState, PaperReproductionDetector
from src.research_analysis import evaluate, extract_windows, paired_predictions, read_packets, validate_intervals, attach_temporal, temporal_decision, run
from src.temporal_features import TemporalConfig, describe_window


def rows(n=6):
    return pd.DataFrame([dict(window_start_sec=i * .025, window_end_sec=(i + 1) * .025,
        decision_time_sec=(i + 1) * .025, label="benign", metric_include=True, total_packets=20,
        iat_variance=.001 + i * .00001, burst_rate=800 + i, payload_size_variance=1000 + i,
        new_flow_arrival_rate=40) for i in range(n)])


class DetectorTests(unittest.TestCase):
    def test_default_matches_original_commit_all_existing_columns(self):
        root = Path(__file__).resolve().parents[1]
        source = subprocess.check_output(["git", "-C", str(root), "show", "f231630:src/paper_reproduction_detector.py"], text=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.py"
            path.write_text(source)
            spec = importlib.util.spec_from_file_location("regression_original", path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            frame = rows(40)
            frame.loc[0, [*PAPER_FEATURES, "total_packets"]] = 0
            frame.loc[23:, "burst_rate"] = 1e7
            frame.loc[25, "total_packets"] = 0
            for warmup in (0, 2, 20):
                before = module.PaperReproductionDetector(module.PaperDetectorConfig(warmup_windows=warmup)).predict_stream(frame)
                after = PaperReproductionDetector(PaperDetectorConfig(warmup_windows=warmup)).predict_stream(frame)
                pd.testing.assert_frame_equal(before, after[before.columns])

    def test_freeze_same_initial_state_no_updates_and_gate(self):
        test = rows(4)
        test["burst_rate"] = [1000, 1500, 0, 2000]
        test.loc[2, "total_packets"] = 0
        train, branches = paired_predictions(rows(5), test, {"warmup_windows": 2})
        dynamic, frozen = branches["dynamic"], branches["freeze"]
        for f in PAPER_FEATURES:
            self.assertEqual(dynamic.iloc[0][f + "_threshold"], frozen.iloc[0][f + "_threshold"])
            self.assertEqual(frozen[f + "_threshold"].nunique(), 1)
            self.assertFalse(frozen[f + "_updated"].any())
        self.assertFalse(frozen.loc[2, "relaxed_attack"])
        self.assertTrue((dynamic.original_attack <= dynamic.relaxed_attack).all())
        self.assertTrue((dynamic.suspicious_score == dynamic[[f + "_is_suspicious" for f in PAPER_FEATURES]].sum(axis=1)).all())

    def test_exact_score_two_and_lower_zero(self):
        detector = PaperReproductionDetector(PaperDetectorConfig(warmup_windows=0))
        detector.states = {f: PaperFeatureState(1, 0) for f in PAPER_FEATURES}
        frame = rows(1)
        frame.loc[0, PAPER_FEATURES] = [1, 2, 1, 2]
        result = detector.predict_stream(frame, update_thresholds=False).iloc[0]
        self.assertEqual(result.suspicious_score, 2)
        self.assertTrue(result.pred_attack)
        detector.states["iat_variance"] = PaperFeatureState(0, 1)
        frame.loc[0, "iat_variance"] = 0
        result = detector.predict_stream(frame).iloc[0]
        self.assertEqual(result.iat_variance_threshold, 0)
        self.assertFalse(result.iat_variance_raw_crossed)

    def test_invalid_training_rejected(self):
        frame = rows(4)
        frame.loc[0, "label"] = "attack"
        with self.assertRaises(ValueError):
            paired_predictions(frame, rows(), {})
        with self.assertRaises(ValueError):
            paired_predictions(rows(2), rows(), {"warmup_windows": 20})


class LabelMetricTests(unittest.TestCase):
    def test_empty_windows_boundaries_and_multiple_events(self):
        packets = pd.DataFrame(columns=["timestamp_sec", "packet_size", "flow_id"])
        cfg = dict(bucket_ms=25, window_sec=.1, step_sec=.025)
        frame, counts = extract_windows(packets, .3, cfg, [(.075, .2)])
        self.assertEqual(frame.iloc[0].label, "transition")
        self.assertEqual(frame.iloc[-1].label, "benign")
        self.assertTrue(frame.total_packets.eq(0).all())
        self.assertEqual(len(counts), 12)
        with self.assertRaises(ValueError):
            extract_windows(packets, .3, {**cfg, "window_sec": .03}, [])
        with self.assertRaises(ValueError):
            validate_intervals([[.1, .3], [.2, .4]], 1)

    def test_metrics_hand_computed_end_time_and_miss(self):
        frame = rows(6)
        frame["label"] = ["benign", "benign", "attack", "attack", "benign", "attack"]
        frame["pred"] = [True, False, False, True, False, False]
        frame["detection_enabled"] = True
        frame["enough_packets_for_detection"] = [True, True, False, True, True, False]
        result = evaluate(frame, [[.05, .1], [.125, .15]], "pred")
        self.assertEqual([result[k] for k in ("tp", "fp", "tn", "fn")], [1, 1, 2, 2])
        self.assertAlmostEqual(result["tpr"], 1/3)
        self.assertAlmostEqual(result["fpr"], 1/3)
        self.assertAlmostEqual(result["precision"], .5)
        self.assertAlmostEqual(result["events"][0]["latency_sec"], .05)
        self.assertIsNone(result["events"][1]["latency_sec"])
        self.assertEqual(result["packet_gated_windows"], 2)
        frame["label"] = "benign"
        self.assertIsNone(evaluate(frame, [], "pred")["tpr"])

    def test_latency_transition_no_future_detection(self):
        frame = rows(2)
        frame["window_start_sec"] = [0, .1]
        frame["window_end_sec"] = [.1, .2]
        frame["decision_time_sec"] = frame.window_end_sec
        frame["label"] = "transition"
        frame["metric_include"] = False
        frame["detection_enabled"] = True
        frame["enough_packets_for_detection"] = True
        frame["pred"] = [False, True]
        result = evaluate(frame, [[.05, .15]], "pred")
        self.assertIsNone(result["events"][0]["latency_sec"])
        frame.loc[0, "pred"] = True
        self.assertAlmostEqual(evaluate(frame, [[.05, .15]], "pred")["events"][0]["latency_sec"], .05)

    def test_bad_packet_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packets.csv"
            path.write_text("timestamp_sec,packet_size,flow_id\nNaN,80,x\n")
            with self.assertRaises(ValueError):
                read_packets(path, 1)


class TemporalTests(unittest.TestCase):
    cfg = TemporalConfig(window_sec=4, burst_threshold_packets=1, min_period_sec=.1, max_period_sec=2)

    def test_constant_and_insufficient_are_undefined(self):
        for x in (np.zeros(160), np.ones(160)):
            value = describe_window(x, 0, 160, .025, self.cfg)
            for name in ("jain", "cv", "autocorrelation", "spectral_peak"):
                self.assertIsNone(value[name])

    def test_periodic_jitter_equivalence_and_no_false_start(self):
        periodic = np.zeros(160)
        periodic[[5, 35, 65, 95, 125]] = 10
        value = describe_window(periodic, 0, 160, .025, self.cfg)
        self.assertAlmostEqual(value["jain"], 1)
        self.assertAlmostEqual(value["cv"], 0)
        self.assertGreater(value["autocorrelation"], .6)
        self.assertGreater(value["spectral_peak"], 0)
        jitter = np.zeros(160)
        jitter[[5, 31, 65, 92, 132]] = 10
        value = describe_window(jitter, 0, 160, .025, self.cfg)
        self.assertLess(value["jain"], 1)
        self.assertAlmostEqual(value["jain"], 1 / (1 + value["cv"] ** 2))
        pulse = np.zeros(160)
        pulse[4:10] = 10
        self.assertEqual(describe_window(pulse, 6, 160, .025, self.cfg)["burst_start_count"], 0)

    def test_temporal_is_causal_and_ready_only_after_full_history(self):
        packets = pd.DataFrame(columns=["timestamp_sec", "packet_size", "flow_id"])
        cfg = dict(bucket_ms=25, window_sec=.025, step_sec=.025, temporal=asdict(self.cfg))
        frame, counts = extract_windows(packets, 5, cfg, [])
        counts[[10, 40, 70, 100, 130]] = 10
        a = attach_temporal(frame.iloc[:160], counts, packets, cfg)
        counts[160:] = 100
        b = attach_temporal(frame.iloc[:160], counts, packets, cfg)
        pd.testing.assert_frame_equal(a, b)
        self.assertFalse(a.iloc[0].temporal_ready)
        self.assertTrue(a.iloc[-1].temporal_ready)

    def test_fixed_rules_require_calibration_and_handle_missing(self):
        frame = pd.DataFrame(dict(temporal_ready=[False, True, True], jain=[None, .99, .8]))
        rule = dict(threshold=.95, direction="upper", calibration_reference="independent-validation-test")
        self.assertEqual(temporal_decision(frame, "jain", rule).tolist(), [False, True, False])
        with self.assertRaises(ValueError):
            temporal_decision(frame, "jain", {**rule, "calibration_reference": ""})


class IntegrationTests(unittest.TestCase):
    def test_corrupt_pcap_does_not_become_empty_benign(self):
        from mininet_experiment.pcap_to_features import parse_udp_pcap
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corrupt.pcap"
            path.write_bytes(b"not a pcap")
            with patch("mininet_experiment.pcap_to_features.shutil.which", return_value="tcpdump"), patch(
                "mininet_experiment.pcap_to_features.subprocess.run",
                return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="truncated dump file")
            ):
                with self.assertRaises(RuntimeError):
                    parse_udp_pcap(path)

    def test_fixture_cli_reproducibility_and_25ms_4s_replay(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name in ("a", "b"):
                subprocess.run([sys.executable, str(root / "scripts/make_research_fixture.py"),
                    "--output-dir", str(base/name), "--duration-sec", "5", "--flows", "2",
                    "--period-sec", ".7", "--burst-sec", ".1", "--jitter", ".1"], check=True)
            self.assertEqual((base/"a/periodic_ldos.csv").read_bytes(), (base/"b/periodic_ldos.csv").read_bytes())
            for name, window, step in (("short", .025, .025), ("long", 4, 1)):
                cfg = json.loads((base/"a/config.json").read_text())
                cfg.update(window_sec=window, step_sec=step)
                cfg["detector"]["warmup_windows"] = 2
                cfg["temporal_rules"] = {"jain": dict(threshold=.95, direction="upper", calibration_reference="unit-test-only")}
                path = base/"a"/(name + ".json")
                path.write_text(json.dumps(cfg))
                run(path, base/name)
                metrics = json.loads((base/name/"metrics.json").read_text())
                self.assertEqual(len(metrics), 24)
                self.assertTrue((base/name/"COMPLETED").exists())
                log = pd.read_csv(base/name/"periodic_ldos_freeze_windows.csv")
                for f in PAPER_FEATURES:
                    self.assertEqual(log[f + "_threshold"].nunique(), 1)
                self.assertIn("jain_attack", log)
                self.assertIn("spectral_peak", log)
                self.assertTrue(log.enough_packets_for_detection.any())
                self.assertEqual(len(log), 200 if name == "short" else 2)
                with self.assertRaises(FileExistsError):
                    run(path, base/name)


if __name__ == "__main__":
    unittest.main()
