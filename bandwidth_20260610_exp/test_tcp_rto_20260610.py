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

from analyze_tcp_rto_20260610 import detect_rto_events, extract_rto_episodes, nearest_pulse_metrics, overlaps_pulse


def row(t: float, backoff: int, retransmits: int = 0, total_retrans: int = 0) -> dict[str, object]:
    return {
        "case_id": "case_20260610",
        "scenario": "periodic_ldos",
        "condition_id": "avg30_peak1",
        "seed": "1",
        "flow_id": "10.0.0.1:43000>10.0.0.2:5201",
        "timestamp_sec": t,
        "timestamp_epoch_ns": int(t * 1_000_000_000),
        "rto_ms": 200 * (2 ** max(backoff - 1, 0)),
        "backoff": backoff,
        "retransmits": retransmits,
        "total_retrans": total_retrans,
        "cwnd": 10 - backoff,
        "bytes_acked": 1000 * t,
        "observation_source": "ss_tcp_info",
    }


class TcpRtoTests(unittest.TestCase):
    def test_backoff_increment_detects_rto_event(self) -> None:
        events = detect_rto_events([row(0.0, 0), row(0.05, 1)])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["backoff_before"], 0)
        self.assertEqual(events[0]["backoff_after"], 1)
        self.assertEqual(events[0]["is_direct_rto_observation"], 1)

    def test_stable_backoff_not_double_counted(self) -> None:
        events = detect_rto_events([row(0.0, 1), row(0.05, 1), row(0.10, 1)])
        self.assertEqual(len(events), 0)

    def test_backoff_stage_increase_detected(self) -> None:
        events = detect_rto_events([row(0.0, 1), row(0.05, 2)])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["backoff_before"], 1)
        self.assertEqual(events[0]["backoff_after"], 2)

    def test_episode_extraction(self) -> None:
        rows = [row(0.0, 0), row(0.05, 1), row(0.10, 1), row(0.15, 2), row(0.20, 0)]
        events = detect_rto_events(rows)
        episodes = extract_rto_episodes(rows, events)
        self.assertEqual(len(episodes), 1)
        self.assertEqual(episodes[0]["maximum_backoff"], 2)

    def test_pulse_collision(self) -> None:
        pulse = {"pulse_start_sec": 1.000, "pulse_end_sec": 1.200}
        self.assertTrue(overlaps_pulse(1.150, pulse))
        self.assertFalse(overlaps_pulse(1.250, pulse))

    def test_phase_difference(self) -> None:
        pulse = {"pulse_index": 0, "pulse_start_sec": 1.000, "pulse_end_sec": 1.200}
        metrics = nearest_pulse_metrics(1.025, [pulse], period_ms=1000.0)
        self.assertAlmostEqual(metrics["rto_to_pulse_phase_ms"], 25.0)
        self.assertAlmostEqual(metrics["rto_to_pulse_phase_ratio"], 0.025)

    def test_direct_vs_inferred_observation_distinction(self) -> None:
        direct = detect_rto_events([row(0.0, 0), row(0.05, 1)])[0]
        inferred_retrans = {
            "event_type": "retransmission",
            "observation_source": "pcap_inference",
            "is_inferred_rto": 0,
            "inference_reason": "pcap retransmission label; not direct RTO evidence",
        }
        self.assertEqual(direct["observation_source"], "ss_tcp_info")
        self.assertEqual(direct["is_direct_rto_observation"], 1)
        self.assertEqual(inferred_retrans["observation_source"], "pcap_inference")
        self.assertEqual(inferred_retrans["is_inferred_rto"], 0)


if __name__ == "__main__":
    unittest.main()
