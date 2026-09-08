from __future__ import annotations

import csv
import math
import sys
import tempfile
import types
import unittest
from pathlib import Path

from analyze import (
    SsSample,
    actual_pulse_duration_sec,
    classify_retransmission_events,
    detect_sender_rto_events,
    evaluate_pulse_timing,
    interval_is_rto_like,
    nstat_diff,
    parse_ss_samples,
    qdisc_diff,
)
from run import UDP_BURST_CODE


class AnalyzeTests(unittest.TestCase):
    def test_parse_ss_sample_extracts_rto_backoff_and_retrans(self) -> None:
        text = """=== sample 0 epoch 100.000000000 rc 0 ===
ESTAB 0 0 10.0.1.1:40000 10.0.2.1:5201
\t cubic rto:204 backoff:1 rtt:21.5/3.5 cwnd:7 ssthresh:12 unacked:2 retrans:1/3
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ss_raw.log"
            path.write_text(text, encoding="utf-8")
            samples = parse_ss_samples(path, "t1000", 99.0)
        self.assertEqual(len(samples), 1)
        self.assertAlmostEqual(samples[0].rel_time, 1.0)
        self.assertAlmostEqual(samples[0].rto_ms, 204.0)
        self.assertEqual(samples[0].backoff, 1)
        self.assertAlmostEqual(samples[0].total_retrans, 3.0)
        self.assertAlmostEqual(samples[0].rttvar_ms, 3.5)

    def test_sender_backoff_increase_is_rto_event(self) -> None:
        samples = [
            SsSample(case="t1000", epoch=1.0, rel_time=1.0, rto_ms=200.0, backoff=0, total_retrans=0),
            SsSample(case="t1000", epoch=1.1, rel_time=1.1, rto_ms=400.0, backoff=1, total_retrans=1),
        ]
        events = detect_sender_rto_events(samples)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "ss")

    def test_fast_retransmit_is_not_observed_rto(self) -> None:
        pcap = [
            {
                "time_sec": 12.0,
                "is_sender_data": True,
                "is_retransmission": True,
                "is_fast_retransmission": True,
            }
        ]
        samples = [SsSample(case="t1000", epoch=12.0, rel_time=12.0, rto_ms=300.0, backoff=0)]
        rows = classify_retransmission_events("t1000", pcap, [], samples, [], {})
        self.assertEqual(rows[0]["classification"], "not_observed")

    def test_single_sender_rto_event_confirms_only_one_pcap_retransmission(self) -> None:
        pcap = [
            {"time_sec": 12.0, "is_sender_data": True, "is_retransmission": True, "is_fast_retransmission": False},
            {"time_sec": 12.05, "is_sender_data": True, "is_retransmission": True, "is_fast_retransmission": False},
        ]
        sender_events = [{"event_time_sec": 12.01, "sender_rto_ms": 400.0, "sender_backoff": 1}]
        samples = [
            SsSample(case="t1000", epoch=112.0, rel_time=12.0, rto_ms=400.0, backoff=1),
            SsSample(case="t1000", epoch=112.05, rel_time=12.05, rto_ms=400.0, backoff=1),
        ]
        rows = classify_retransmission_events(
            "t1000",
            pcap,
            sender_events,
            samples,
            [],
            {"TcpExtTCPTimeouts": 1},
        )
        self.assertEqual(sum(1 for row in rows if row["classification"] == "confirmed"), 1)

    def test_interval_can_be_probable_rto(self) -> None:
        sample = SsSample(case="t1000", epoch=1.0, rel_time=1.0, rto_ms=300.0)
        self.assertTrue(interval_is_rto_like(0.3, sample))
        self.assertFalse(interval_is_rto_like(0.05, sample))

    def test_qdisc_drop_is_not_double_counted_across_parent_child_qdiscs(self) -> None:
        before_text = """## r1-eth2
qdisc htb 5: root
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
qdisc netem 10: parent 5:1 limit 20 delay 20ms
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
"""
        after_text = """## r1-eth2
qdisc htb 5: root
 Sent 1000 bytes 10 pkt (dropped 7, overlimits 2 requeues 0)
qdisc netem 10: parent 5:1 limit 20 delay 20ms
 Sent 1000 bytes 10 pkt (dropped 7, overlimits 0 requeues 0)
"""
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.txt"
            after = Path(tmp) / "after.txt"
            before.write_text(before_text, encoding="utf-8")
            after.write_text(after_text, encoding="utf-8")
            rows = qdisc_diff(before, after)
        self.assertEqual(rows[0]["dropped_delta"], 7)

    def test_wall_clock_backward_does_not_extend_udp_pulse(self) -> None:
        class FakeTime(types.ModuleType):
            def __init__(self) -> None:
                super().__init__("time")
                self.mono_ns = 0

            def monotonic_ns(self) -> int:
                return self.mono_ns

            def time(self) -> float:
                offset = -1.2 if self.mono_ns >= 50_000_000 else 0.0
                return 1000.0 + self.mono_ns / 1_000_000_000.0 + offset

            def sleep(self, seconds: float) -> None:
                self.mono_ns += max(0, int(round(seconds * 1_000_000_000.0)))

        class FakeSocketInstance:
            def sendto(self, payload: bytes, _addr: tuple[str, int]) -> int:
                return len(payload)

            def close(self) -> None:
                return None

        class FakeSocket(types.ModuleType):
            AF_INET = 2
            SOCK_DGRAM = 2

            def socket(self, _family: int, _kind: int) -> FakeSocketInstance:
                return FakeSocketInstance()

        fake_time = FakeTime()
        fake_socket = FakeSocket("socket")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "pulses.csv"
            old_time = sys.modules.get("time")
            old_socket = sys.modules.get("socket")
            old_argv = sys.argv[:]
            try:
                sys.modules["time"] = fake_time
                sys.modules["socket"] = fake_socket
                sys.argv = [
                    "udp_burst",
                    "1000.0",
                    "0.0",
                    "0.2",
                    "1000",
                    "200",
                    "3",
                    "1000",
                    "10.0.2.1",
                    "5001",
                    str(output),
                ]
                exec(UDP_BURST_CODE, {})
            finally:
                if old_time is not None:
                    sys.modules["time"] = old_time
                if old_socket is not None:
                    sys.modules["socket"] = old_socket
                sys.argv = old_argv
            with output.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(len(rows), 1)
        self.assertLess(float(rows[0]["actual_end_epoch"]), float(rows[0]["actual_start_epoch"]))
        self.assertAlmostEqual(actual_pulse_duration_sec(rows[0]), 0.2, delta=0.010)
        self.assertEqual(int(rows[0]["bytes_sent"]), 75000)
        self.assertEqual(evaluate_pulse_timing(rows, {"period_ms": 1000.0})[0], "valid_timing")

    def test_nstat_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.txt"
            after = Path(tmp) / "after.txt"
            before.write_text("TcpExtTCPTimeouts 2 0.0\nTcpRetransSegs 3 0.0\n", encoding="utf-8")
            after.write_text("TcpExtTCPTimeouts 5 0.0\nTcpRetransSegs 9 0.0\n", encoding="utf-8")
            delta = nstat_diff(before, after)
        self.assertEqual(delta["TcpExtTCPTimeouts"], 3)
        self.assertEqual(delta["TcpRetransSegs"], 6)


if __name__ == "__main__":
    unittest.main()
