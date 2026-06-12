from __future__ import annotations

import argparse
import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mininet_experiment.traffic_generators.send_composite_lddos import (  # noqa: E402
    effective_settings,
    event_stream,
    planned_average_rate_multiplier,
)


class StatMatchedBudgetTests(unittest.TestCase):
    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            dst_ip="10.0.0.2",
            dst_port=5001,
            base_src_port=40000,
            duration_sec=60.0,
            attack_start_sec=20.0,
            experiment_start_wall=None,
            scenario="stat_matched_composite_lddos",
            attack_mode="f_lddos",
            total_attack_rate_mbps=45.0,
            target_total_average_rate_mbps=4.5,
            num_attack_flows=8,
            burst_ms=100,
            period_ms=1000,
            payload_size=750,
            payload_mode="empirical",
            phase_spread_ms=50.0,
            jitter_ratio=0.5,
            feint_rate_ratio=0.10,
            feint_randomness="poisson",
            attack_interval_placement="end",
            randomize_pulse_start=False,
            seed=1,
            log=Path("/tmp/stat_matched_budget.csv"),
            summary_json=Path("/tmp/stat_matched_budget.json"),
        )

    def test_stat_matched_target_plus_feint_matches_configured_average(self) -> None:
        args = self._args()
        settings = effective_settings(args)
        multiplier = planned_average_rate_multiplier(args, settings)
        self.assertGreater(multiplier, 0.0)
        _events, metadata = event_stream(args)
        effective_peak = float(metadata["total_attack_rate_mbps"])
        self.assertLess(effective_peak, args.total_attack_rate_mbps)
        self.assertAlmostEqual(effective_peak * multiplier, args.target_total_average_rate_mbps, places=6)
        self.assertAlmostEqual(float(metadata["configured_total_attack_avg_mbps"]), 4.5)

    def test_per_flow_split_uses_effective_peak(self) -> None:
        args = self._args()
        _events, metadata = event_stream(args)
        per_flow = float(metadata["per_flow_rate_mbps"])
        effective_peak = float(metadata["total_attack_rate_mbps"])
        self.assertTrue(math.isclose(per_flow * args.num_attack_flows, effective_peak, rel_tol=1e-12))

    def test_randomized_pulse_start_keeps_flows_synchronized_and_non_overlapping(self) -> None:
        args = self._args()
        args.duration_sec = 8.0
        args.attack_start_sec = 2.0
        args.scenario = "composite_lddos"
        args.attack_mode = "multi_flow_sync_lddos"
        args.total_attack_rate_mbps = 15.0
        args.target_total_average_rate_mbps = None
        args.num_attack_flows = 4
        args.burst_ms = 333
        args.phase_spread_ms = 0.0
        args.jitter_ratio = 0.0
        args.attack_interval_placement = "start"
        args.randomize_pulse_start = True

        settings = effective_settings(args)
        multiplier = planned_average_rate_multiplier(args, settings)
        self.assertAlmostEqual(multiplier, args.burst_ms / args.period_ms, places=6)

        events, _metadata = event_stream(args)
        attack_events = [event for event in events if event.phase == "attack"]
        starts_by_period_flow: dict[tuple[int, int], float] = {}
        for event in attack_events:
            starts_by_period_flow.setdefault((event.period_index, event.flow_index), event.scheduled_sec)

        period_starts = []
        for period_index in sorted({period for period, _flow in starts_by_period_flow}):
            starts = [starts_by_period_flow[(period_index, flow)] for flow in range(args.num_attack_flows)]
            self.assertLess(max(starts) - min(starts), 1e-9)
            period_start = args.attack_start_sec + period_index * args.period_ms / 1000.0
            self.assertGreaterEqual(starts[0], period_start)
            self.assertLessEqual(starts[0] + args.burst_ms / 1000.0, period_start + args.period_ms / 1000.0)
            period_starts.append(round(starts[0] - period_start, 6))
        self.assertGreater(len(set(period_starts)), 1)


if __name__ == "__main__":
    unittest.main()
