from __future__ import annotations

import argparse
import math
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyze_rto_calibration_20260611 import (  # noqa: E402
    build_case_and_validation_rows,
    parse_qdisc_text,
    ranking,
)


class RtoCalibrationTests(unittest.TestCase):
    def test_burst_formula_keeps_five_mbps_average(self) -> None:
        for peak_mbps, expected_burst_ms in [(15.0, 333.333333), (30.0, 166.666667), (45.0, 111.111111), (60.0, 83.333333)]:
            burst_ms = 1000.0 * 5.0 / peak_mbps
            average_mbps = peak_mbps * burst_ms / 1000.0
            self.assertAlmostEqual(burst_ms, expected_burst_ms, places=5)
            self.assertAlmostEqual(average_mbps, 5.0, places=6)

    def test_qdisc_parser_extracts_drop_and_backlog(self) -> None:
        text = """
qdisc netem 10: parent 5:1 limit 100 delay 20ms
 Sent 1000 bytes 10 pkt (dropped 3, overlimits 4 requeues 5)
 backlog 1200b 2p requeues 5
"""
        parsed = parse_qdisc_text(text)
        self.assertEqual(parsed["qdisc_kind"], "netem")
        self.assertEqual(parsed["qdisc_dropped"], 3)
        self.assertEqual(parsed["qdisc_overlimits"], 4)
        self.assertEqual(parsed["qdisc_requeues"], 5)
        self.assertEqual(parsed["backlog"], "1200b 2p requeues 5")

    def test_attack_rate_validation_uses_offered_rate(self) -> None:
        args = argparse.Namespace(
            evaluation_start_sec=7.0,
            evaluation_end_sec=18.0,
            tcp_target_mbps=5.0,
            attack_target_mbps=5.0,
            output_tag="20260611",
        )
        metadata = {
            "case_id": "rto_peak30_queue100_periodic_ldos_seed1_20260611",
            "condition_id": "rto_peak30_queue100",
            "scenario": "periodic_ldos",
            "seed": 1,
            "peak_rate_mbps": 30,
            "configured_queue_packets": 100,
            "burst_ms": 166.666667,
            "configured_average_attack_mbps": 5.0,
        }
        timeseries = [
            {
                "timestamp_sec": 8.0,
                "tcp_mbps": 3.0,
                "attack_mbps": 2.5,
                "attack_offered_mbps": 5.0,
                "idle_mbps": 9.5,
                "pulse_active": 1,
                "backoff": 0,
            }
        ]
        detector_row = {"FNR": 0.25, "FNR_burst": 0.5, "detection_delay_ms": 25.0}
        qdisc_row = {"qdisc_dropped": 7, "qdisc_overlimits": 0, "qdisc_requeues": 0, "backlog": ""}
        retrans_rows = [{"status": "ok", "retransmission": 1, "fast_retransmission": 0, "spurious_retransmission": 0, "duplicate_ack": 0, "lost_segment": 0}]
        with tempfile.TemporaryDirectory() as tmp:
            case_row, attack_row, _tcp_row = build_case_and_validation_rows(
                Path(tmp),
                metadata,
                timeseries,
                detector_row,
                [],
                qdisc_row,
                retrans_rows,
                "ok",
                {"total_retrans": 1, "mean_cwnd": math.nan, "min_cwnd": math.nan, "mean_rtt_ms": math.nan},
                {"rto_peak30_queue100": 5.0},
                args,
            )
        self.assertEqual(case_row["attack_valid"], 1)
        self.assertEqual(case_row["valid_case"], 1)
        self.assertAlmostEqual(attack_row["attack_rate_error_pct"], 0.0)
        self.assertAlmostEqual(case_row["tcp_degradation_pct"], 40.0)

    def test_ranking_prefers_lower_peak_then_larger_queue_after_effectiveness(self) -> None:
        rows = [
            {"condition_id": "peak30_queue100", "scenario": "periodic_ldos", "peak_mbps": 30, "queue_packets": 100, "valid_case": 1, "attack_valid": 1, "qdisc_dropped": 1, "pcap_retransmission_count": 1, "rto_event_count": 1, "max_backoff": 0, "tcp_degradation_pct": 20.0, "FNR_burst": 0.1},
            {"condition_id": "peak15_queue50", "scenario": "periodic_ldos", "peak_mbps": 15, "queue_packets": 50, "valid_case": 1, "attack_valid": 1, "qdisc_dropped": 1, "pcap_retransmission_count": 1, "rto_event_count": 1, "max_backoff": 0, "tcp_degradation_pct": 20.0, "FNR_burst": 0.1},
            {"condition_id": "peak15_queue200", "scenario": "periodic_ldos", "peak_mbps": 15, "queue_packets": 200, "valid_case": 1, "attack_valid": 1, "qdisc_dropped": 1, "pcap_retransmission_count": 1, "rto_event_count": 1, "max_backoff": 0, "tcp_degradation_pct": 20.0, "FNR_burst": 0.1},
        ]
        ranked = ranking(rows)
        self.assertEqual([row["condition_id"] for row in ranked], ["peak15_queue200", "peak15_queue50", "peak30_queue100"])


if __name__ == "__main__":
    unittest.main()
