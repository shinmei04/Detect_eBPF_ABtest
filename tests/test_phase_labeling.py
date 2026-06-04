"""Unit tests for phase-aware LDDoS/F-LDDoS truth labels."""

from __future__ import annotations

import unittest

import pandas as pd

from src.lddos_composite_analysis import phase_detection_metrics
from src.phase_labeling import add_phase_labels, build_phase_intervals


class PhaseLabelingTest(unittest.TestCase):
    """Verify phase labels without Mininet or packet capture dependencies."""

    def setUp(self) -> None:
        self.windows = pd.DataFrame(
            [
                {"window_start_sec": 0.950, "window_end_sec": 0.975},
                {"window_start_sec": 1.100, "window_end_sec": 1.125},
                {"window_start_sec": 1.800, "window_end_sec": 1.825},
                {"window_start_sec": 2.100, "window_end_sec": 2.125},
            ]
        )
        self.windows["label"] = ["benign", "attack", "attack", "attack"]
        self.windows["target"] = [0, 1, 1, 1]
        self.intervals = pd.DataFrame(
            [
                {
                    "phase": "baseline",
                    "flow_id": "flow_0",
                    "src_port": 40000,
                    "phase_start_sec": 0.0,
                    "phase_end_sec": 1.0,
                },
                {
                    "phase": "feint",
                    "flow_id": "flow_0",
                    "src_port": 40000,
                    "phase_start_sec": 1.0,
                    "phase_end_sec": 1.8,
                },
                {
                    "phase": "attack_burst",
                    "flow_id": "flow_0",
                    "src_port": 40000,
                    "phase_start_sec": 1.8,
                    "phase_end_sec": 2.0,
                },
                {
                    "phase": "quiet",
                    "flow_id": "flow_0",
                    "src_port": 40000,
                    "phase_start_sec": 2.0,
                    "phase_end_sec": 2.5,
                },
            ]
        )

    def test_phase_aware_targets_keep_legacy_period(self) -> None:
        labeled = add_phase_labels(
            self.windows,
            attack_start_sec=1.0,
            phase_intervals=self.intervals,
            min_overlap_sec=0.025,
        )
        self.assertEqual(labeled["target_period"].tolist(), [0, 1, 1, 1])
        self.assertEqual(labeled["target"].tolist(), [0, 1, 1, 1])
        self.assertEqual(labeled["label"].tolist(), ["benign", "attack", "attack", "attack"])
        self.assertEqual(labeled["target_pre_attack"].tolist(), [1, 0, 0, 0])
        self.assertEqual(labeled["target_burst"].tolist(), [0, 0, 1, 0])
        self.assertEqual(labeled["target_feint"].tolist(), [0, 1, 0, 0])
        self.assertEqual(labeled["target_quiet"].tolist(), [0, 0, 0, 1])
        self.assertEqual(
            labeled["truth_phase"].tolist(),
            ["baseline", "feint", "attack_burst", "quiet"],
        )

    def test_missing_phase_log_falls_back_without_breaking_period_target(self) -> None:
        labeled = add_phase_labels(
            self.windows,
            attack_start_sec=1.0,
            phase_intervals=None,
            min_overlap_sec=0.025,
        )
        self.assertEqual(labeled["target_period"].tolist(), [0, 1, 1, 1])
        self.assertEqual(labeled["target_burst"].tolist(), [0, 0, 0, 0])
        self.assertEqual(labeled["target_feint"].tolist(), [0, 0, 0, 0])
        self.assertEqual(labeled["target_quiet"].tolist(), [0, 0, 0, 0])
        self.assertFalse(labeled["phase_labels_available"].any())

    def test_f_lddos_plan_contains_feint_burst_quiet_and_stable_ports(self) -> None:
        intervals = build_phase_intervals(
            duration_sec=4.0,
            attack_start_sec=1.0,
            scenario="composite_lddos",
            attack_mode="f_lddos",
            num_flows=2,
            period_ms=1000,
            burst_ms=200,
            phase_spread_ms=100,
            attack_interval_placement="end",
            seed=1,
            per_flow_rate_mbps=30.0,
            feint_rate_ratio=0.1,
        )
        self.assertTrue({"baseline", "feint", "attack_burst", "quiet"}.issubset(set(intervals["phase"])))
        self.assertEqual(set(intervals["src_port"]), {40000, 40001})
        self.assertTrue((intervals["phase_end_sec"] > intervals["phase_start_sec"]).all())

    def test_burst_fnr_does_not_count_feint_only_windows(self) -> None:
        predictions = pd.DataFrame(
            [
                {
                    "window_start_sec": 1.0,
                    "window_end_sec": 1.025,
                    "target_period": 1,
                    "target_burst": 0,
                    "target_feint": 1,
                    "target_quiet": 0,
                    "target_pre_attack": 0,
                    "truth_phase": "feint",
                    "pred_attack": False,
                    "suspicious_score": 0,
                    "is_warmup": False,
                    "first_attack_burst_start_sec": 1.025,
                },
                {
                    "window_start_sec": 1.025,
                    "window_end_sec": 1.050,
                    "target_period": 1,
                    "target_burst": 1,
                    "target_feint": 0,
                    "target_quiet": 0,
                    "target_pre_attack": 0,
                    "truth_phase": "attack_burst",
                    "pred_attack": True,
                    "suspicious_score": 2,
                    "is_warmup": False,
                    "first_attack_burst_start_sec": 1.025,
                },
            ]
        )
        metrics = phase_detection_metrics(predictions, prefix="")
        self.assertEqual(metrics["fnr_period"], 0.5)
        self.assertEqual(metrics["fnr_burst"], 0.0)
        self.assertEqual(metrics["recall_burst"], 1.0)
        self.assertEqual(metrics["fpr_feint"], 0.0)


if __name__ == "__main__":
    unittest.main()
