"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.
"""

from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from metrics import (
    aggregate_seed_stats,
    average_attack_rate_mbps,
    classify_packet,
    compute_capacity_breakdown,
    configured_average_attack_pct,
    excess_degradation_pp,
    tcp_degradation_pct,
)


class BandwidthMetricTests(unittest.TestCase):
    def test_average_attack_rate(self) -> None:
        average = average_attack_rate_mbps(30.0, 100.0, 1000.0)
        self.assertAlmostEqual(average, 3.0)
        self.assertAlmostEqual(configured_average_attack_pct(average, 15.0), 20.0)

    def test_idle_calculation_one_to_one_to_one(self) -> None:
        breakdown = compute_capacity_breakdown(5.0, 5.0, 0.0, 15.0)
        self.assertAlmostEqual(breakdown.idle_mbps, 5.0)
        self.assertAlmostEqual(breakdown.tcp_share_pct, 100.0 / 3.0)
        self.assertAlmostEqual(breakdown.attack_share_pct, 100.0 / 3.0)
        self.assertAlmostEqual(breakdown.idle_share_pct, 100.0 / 3.0)

    def test_capacity_excess(self) -> None:
        breakdown = compute_capacity_breakdown(8.0, 8.0, 0.0, 15.0)
        self.assertAlmostEqual(breakdown.idle_mbps, 0.0)
        self.assertAlmostEqual(breakdown.capacity_excess_mbps, 1.0)
        self.assertAlmostEqual(breakdown.capacity_excess_pct, 100.0 / 15.0)

    def test_tcp_degradation(self) -> None:
        self.assertAlmostEqual(tcp_degradation_pct(15.0, 5.0), 66.6666666667)

    def test_excess_degradation_percentage_points(self) -> None:
        self.assertAlmostEqual(excess_degradation_pp(50.0, 36.0), 14.0)

    def test_packet_classification(self) -> None:
        tcp_data = {
            "proto": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 43000,
            "dst_port": 5201,
            "payload_bytes": 1448,
        }
        udp_attack = {
            "proto": "UDP",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 5001,
            "payload_bytes": 750,
        }
        ack_only = {
            "proto": "TCP",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "src_port": 5201,
            "dst_port": 43000,
            "payload_bytes": 0,
        }
        other = {"proto": "ICMP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
        self.assertEqual(classify_packet(tcp_data), "tcp_normal")
        self.assertEqual(classify_packet(udp_attack), "attack")
        self.assertEqual(classify_packet(ack_only), "other")
        self.assertEqual(classify_packet(other), "other")

    def test_seed_aggregation(self) -> None:
        stats = aggregate_seed_stats([1.0, 2.0, 3.0])
        self.assertAlmostEqual(stats["mean"], 2.0)
        self.assertAlmostEqual(stats["std"], 1.0)
        self.assertAlmostEqual(stats["ci95"], 1.96 / math.sqrt(3.0))
        self.assertEqual(stats["n"], 3)
        one = aggregate_seed_stats([2.0])
        self.assertAlmostEqual(one["mean"], 2.0)
        self.assertTrue(math.isnan(one["std"]))
        self.assertTrue(math.isnan(one["ci95"]))


if __name__ == "__main__":
    unittest.main()
