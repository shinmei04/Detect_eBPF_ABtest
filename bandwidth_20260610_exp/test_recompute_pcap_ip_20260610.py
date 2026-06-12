"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.
"""

from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recompute_bandwidth_from_pcap_20260610 import (  # noqa: E402
    capacity_warning,
    classify_packet,
    mbps,
    parse_tcpdump_records,
    validate_capture,
)


class RecomputePcapIpTests(unittest.TestCase):
    def test_parse_ip_total_length_and_l2_length(self) -> None:
        lines = [
            "1781072537.945762 00:00:00:00:00:01 > 00:00:00:00:00:02, ethertype IPv4 (0x0800), length 1514: (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto TCP (6), length 1500)",
            "    10.0.0.1.45508 > 10.0.0.2.5201: Flags [P.], seq 1:1449, ack 1, win 83, length 1448",
        ]
        packets = list(parse_tcpdump_records(lines))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["l2_len"], 1514)
        self.assertEqual(packets[0]["ip_len"], 1500)
        self.assertEqual(packets[0]["payload_len"], 1448)

    def test_ack_only_tcp_is_not_normal_tcp(self) -> None:
        args = SimpleNamespace(
            tcp_sender_ip="10.0.0.1",
            attacker_ips=["10.0.0.3"],
            iperf_port=5201,
            attack_udp_port=5001,
        )
        ack_only = {
            "proto": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 45508,
            "dst_port": 5201,
            "payload_len": 0,
        }
        data = dict(ack_only, payload_len=1448)
        self.assertEqual(classify_packet(ack_only, "10.0.0.2", args), "other")
        self.assertEqual(classify_packet(data, "10.0.0.2", args), "tcp")

    def test_attack_udp_and_receiver_direction(self) -> None:
        args = SimpleNamespace(
            tcp_sender_ip="10.0.0.1",
            attacker_ips=["10.0.0.3", "10.0.0.4"],
            iperf_port=5201,
            attack_udp_port=5001,
        )
        attack = {
            "proto": "UDP",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.2",
            "src_port": 40000,
            "dst_port": 5001,
            "payload_len": 750,
        }
        reverse = dict(attack, src_ip="10.0.0.2", dst_ip="10.0.0.3")
        self.assertEqual(classify_packet(attack, "10.0.0.2", args), "attack")
        self.assertEqual(classify_packet(reverse, "10.0.0.2", args), "not_receiver_direction")

    def test_l2_ip_separation_and_idle(self) -> None:
        ip_load = mbps(15_000_000 / 8 * 30, 30)
        l2_load = mbps((15_000_000 / 8 + 100_000) * 30, 30)
        self.assertAlmostEqual(ip_load, 15.0)
        self.assertGreater(l2_load - ip_load, 0.0)
        idle = max(15.0 - ip_load, 0.0)
        self.assertAlmostEqual(idle, 0.0)

    def test_capacity_warning_for_no_attack_over_105(self) -> None:
        row = {"scenario": "no_attack", "s2_ip_utilization_pct": 105.1}
        self.assertEqual(capacity_warning(row), "no_attack_ip_utilization_gt_105pct")
        self.assertEqual(capacity_warning({"scenario": "constant_udp", "s2_ip_utilization_pct": 101.0}), "ip_capacity_exceeded")
        self.assertEqual(capacity_warning({"scenario": "constant_udp", "s2_ip_utilization_pct": 99.0}), "")

    def test_s2_capture_validation(self) -> None:
        metadata = {
            "capture_ingress_iface": "s1-eth4",
            "capture_egress_iface": "s2-eth1",
            "capture_egress_pcap": "raw/pcaps/egress_after_bottleneck_20260610.pcap",
        }
        self.assertEqual(validate_capture(metadata), "ok")
        metadata["capture_egress_iface"] = "s1-eth4"
        self.assertIn("egress_not_s2", validate_capture(metadata))


if __name__ == "__main__":
    unittest.main()
