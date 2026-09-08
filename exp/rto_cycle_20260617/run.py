#!/usr/bin/env python3
"""Run the 2026-06-17 Mininet RTO-cycle observation experiment."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_CASE_PERIODS = {"t0800": 800.0, "t1000": 1000.0, "t1200": 1200.0}
DEFAULT_CASES = ["base", "t0800", "t1000", "t1200"]
IPERF_PORT = 5201
UDP_PORT = 5001
SENDER_IP = "10.0.1.1"
RECEIVER_IP = "10.0.2.1"
ATTACKER_IP = "10.0.3.1"
ROUTER_SENDER_IP = "10.0.1.254"
ROUTER_RECEIVER_IP = "10.0.2.254"
ROUTER_ATTACKER_IP = "10.0.3.254"


SS_SAMPLER_CODE = r"""
import subprocess
import sys
import time
from pathlib import Path

start_epoch = float(sys.argv[1])
duration_sec = float(sys.argv[2])
interval_sec = float(sys.argv[3])
output = Path(sys.argv[4])
output.parent.mkdir(parents=True, exist_ok=True)
time.sleep(max(0.0, start_epoch - time.time()))
deadline = start_epoch + duration_sec
sample_index = 0
with output.open("w", encoding="utf-8") as handle:
    while time.time() <= deadline + 1e-6:
        sample_epoch = time.time()
        result = subprocess.run(["ss", "-tin"], text=True, capture_output=True)
        handle.write(f"=== sample {sample_index} epoch {sample_epoch:.9f} rc {result.returncode} ===\n")
        handle.write(result.stdout)
        if result.stderr:
            handle.write("--- stderr ---\n")
            handle.write(result.stderr)
        handle.flush()
        sample_index += 1
        next_epoch = start_epoch + sample_index * interval_sec
        time.sleep(max(0.0, next_epoch - time.time()))
"""


UDP_BURST_CODE = r"""
import csv
import socket
import sys
import time
from pathlib import Path

NS_PER_SEC = 1_000_000_000


def sec_to_ns(value):
    return int(round(value * NS_PER_SEC))


def ns_to_sec(value):
    return value / NS_PER_SEC


def sleep_until_mono(deadline_ns):
    while True:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0:
            return
        time.sleep(ns_to_sec(remaining_ns))


start_epoch = float(sys.argv[1])
attack_start_sec = float(sys.argv[2])
attack_end_sec = float(sys.argv[3])
period_ms = float(sys.argv[4])
burst_ms = float(sys.argv[5])
rate_mbps = float(sys.argv[6])
payload_size = int(sys.argv[7])
dst_ip = sys.argv[8]
dst_port = int(sys.argv[9])
output = Path(sys.argv[10])
output.parent.mkdir(parents=True, exist_ok=True)
payload = b"U" * payload_size
interval_ns = max(1, sec_to_ns(payload_size * 8.0 / (rate_mbps * 1_000_000.0)))
period_ns = max(1, sec_to_ns(period_ms / 1000.0))
burst_ns = max(1, sec_to_ns(burst_ms / 1000.0))
attack_start_ns = sec_to_ns(attack_start_sec)
attack_end_ns = sec_to_ns(attack_end_sec)
start_delay_ns = sec_to_ns(max(0.0, start_epoch - time.time()))
start_mono_ns = time.monotonic_ns() + start_delay_ns
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
fields = [
    "pulse_index",
    "scheduled_start_sec",
    "scheduled_start_epoch",
    "scheduled_end_epoch",
    "scheduled_start_mono_ns",
    "scheduled_end_mono_ns",
    "actual_start_epoch",
    "actual_end_epoch",
    "actual_start_mono_ns",
    "actual_end_mono_ns",
    "scheduled_duration_sec",
    "actual_duration_sec",
    "packets_sent",
    "bytes_sent",
    "expected_bytes",
    "period_ms",
    "burst_ms",
    "target_rate_mbps",
    "skipped",
    "skip_reason",
]
with output.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    pulse_index = 0
    rel_start_ns = attack_start_ns
    while rel_start_ns < attack_end_ns:
        rel_start = ns_to_sec(rel_start_ns)
        scheduled_start_mono_ns = start_mono_ns + rel_start_ns
        scheduled_end_mono_ns = min(scheduled_start_mono_ns + burst_ns, start_mono_ns + attack_end_ns)
        scheduled_duration_sec = ns_to_sec(scheduled_end_mono_ns - scheduled_start_mono_ns)
        scheduled_start_epoch = start_epoch + rel_start
        scheduled_end_epoch = start_epoch + ns_to_sec(scheduled_end_mono_ns - start_mono_ns)
        expected_bytes = int(round(rate_mbps * 1_000_000.0 * scheduled_duration_sec / 8.0))
        sleep_until_mono(scheduled_start_mono_ns)
        actual_start_mono_ns = time.monotonic_ns()
        actual_start_epoch = time.time()
        packets = 0
        bytes_sent = 0
        skipped = 0
        skip_reason = ""
        if actual_start_mono_ns >= scheduled_end_mono_ns:
            skipped = 1
            skip_reason = "missed_scheduled_end"
            actual_end_mono_ns = actual_start_mono_ns
            actual_end_epoch = time.time()
        else:
            next_send_ns = actual_start_mono_ns
            while True:
                now_ns = time.monotonic_ns()
                if now_ns >= scheduled_end_mono_ns:
                    break
                if next_send_ns > now_ns:
                    sleep_until_mono(min(next_send_ns, scheduled_end_mono_ns))
                    now_ns = time.monotonic_ns()
                    if now_ns >= scheduled_end_mono_ns:
                        break
                sock.sendto(payload, (dst_ip, dst_port))
                packets += 1
                bytes_sent += payload_size
                next_send_ns = max(next_send_ns + interval_ns, time.monotonic_ns())
            actual_end_mono_ns = time.monotonic_ns()
            actual_end_epoch = time.time()
        actual_duration_sec = ns_to_sec(actual_end_mono_ns - actual_start_mono_ns)
        writer.writerow(
            {
                "pulse_index": pulse_index,
                "scheduled_start_sec": f"{rel_start:.9f}",
                "scheduled_start_epoch": f"{scheduled_start_epoch:.9f}",
                "scheduled_end_epoch": f"{scheduled_end_epoch:.9f}",
                "scheduled_start_mono_ns": scheduled_start_mono_ns,
                "scheduled_end_mono_ns": scheduled_end_mono_ns,
                "actual_start_epoch": f"{actual_start_epoch:.9f}",
                "actual_end_epoch": f"{actual_end_epoch:.9f}",
                "actual_start_mono_ns": actual_start_mono_ns,
                "actual_end_mono_ns": actual_end_mono_ns,
                "scheduled_duration_sec": f"{scheduled_duration_sec:.9f}",
                "actual_duration_sec": f"{actual_duration_sec:.9f}",
                "packets_sent": packets,
                "bytes_sent": bytes_sent,
                "expected_bytes": expected_bytes,
                "period_ms": f"{period_ms:.9f}",
                "burst_ms": f"{burst_ms:.9f}",
                "target_rate_mbps": f"{rate_mbps:.9f}",
                "skipped": skipped,
                "skip_reason": skip_reason,
            }
        )
        handle.flush()
        pulse_index += 1
        rel_start_ns += period_ns
sock.close()
"""


UDP_SINK_CODE = r"""
import csv
import socket
import sys
import time
from pathlib import Path

start_epoch = float(sys.argv[1])
duration_sec = float(sys.argv[2])
bind_ip = sys.argv[3]
port = int(sys.argv[4])
output = Path(sys.argv[5])
output.parent.mkdir(parents=True, exist_ok=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_ip, port))
sock.settimeout(0.2)
time.sleep(max(0.0, start_epoch - time.time()))
deadline = start_epoch + duration_sec
count = 0
total = 0
with output.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=["timestamp_epoch", "bytes", "src"])
    writer.writeheader()
    while time.time() <= deadline:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        count += 1
        total += len(data)
        writer.writerow({"timestamp_epoch": f"{time.time():.9f}", "bytes": len(data), "src": f"{addr[0]}:{addr[1]}"})
sock.close()
print(f"received_packets={count} received_bytes={total}", file=sys.stderr)
"""


IPERF_CLIENT_CODE = r"""
import math
import subprocess
import sys
import time

start_epoch = float(sys.argv[1])
duration_sec = float(sys.argv[2])
receiver_ip = sys.argv[3]
port = sys.argv[4]
time.sleep(max(0.0, start_epoch - time.time()))
duration_arg = str(max(1, int(math.ceil(duration_sec))))
result = subprocess.run(["iperf3", "-c", receiver_ip, "-p", port, "-t", duration_arg, "-i", "1", "-J"], text=True)
sys.exit(result.returncode)
"""


@dataclass
class ProcessHandle:
    proc: Any
    stdout: Any | None = None
    stderr: Any | None = None

    def wait(self, timeout: float | None = None) -> int:
        try:
            return int(self.proc.wait(timeout=timeout))
        finally:
            self.close()

    def terminate(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        self.close()

    def close(self) -> None:
        for stream in (self.stdout, self.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--cases", nargs="+", default=None)
    parser.add_argument("--case-period-ms", nargs="*", default=["t0800=800", "t1000=1000", "t1200=1200"])
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--attack-start-sec", type=float, default=10.0)
    parser.add_argument("--attack-end-sec", type=float, default=50.0)
    parser.add_argument("--bottleneck-mbps", type=float, default=1.5)
    parser.add_argument("--delay-ms", type=float, default=20.0)
    parser.add_argument("--queue-packets", type=int, default=20)
    parser.add_argument("--burst-rate-mbps", type=float, default=3.0)
    parser.add_argument("--burst-ms", type=float, default=200.0)
    parser.add_argument("--payload-size", type=int, default=1000)
    parser.add_argument("--ss-interval-ms", type=float, default=100.0)
    parser.add_argument("--start-delay-sec", type=float, default=1.0)
    parser.add_argument("--iperf-port", type=int, default=IPERF_PORT)
    parser.add_argument("--udp-port", type=int, default=UDP_PORT)
    parser.add_argument("--tcp-congestion", default="", help="Leave empty to keep the namespace default.")
    parser.add_argument("--tcp-sack", choices=["keep", "on", "off"], default="keep")
    parser.add_argument("--skip-analysis", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    apply_smoke_defaults(args)
    validate_args(args)
    assert_mininet_environment()

    case_periods = parse_case_periods(args.case_period_ms)
    cases = args.cases if args.cases is not None else DEFAULT_CASES
    for case in cases:
        if case != "base" and case not in case_periods:
            raise SystemExit(f"case {case!r} has no period; provide --case-period-ms {case}=<ms>")

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or (SCRIPT_DIR / "out" / run_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_config(args, output_dir, run_id, cases, case_periods)

    from mininet.clean import cleanup

    cleanup()
    case_results = []
    try:
        for case in cases:
            period_ms = None if case == "base" else case_periods[case]
            case_results.append(run_case(args, output_dir, case, period_ms))
    finally:
        cleanup()

    write_manifest(output_dir, args, run_id, cases, case_results)
    if not args.skip_analysis:
        sys.path.insert(0, str(SCRIPT_DIR))
        from analyze import analyze_run

        analyze_run(output_dir)
    print(f"Wrote RTO cycle run to {output_dir.resolve()}")


def apply_smoke_defaults(args: argparse.Namespace) -> None:
    if not args.smoke:
        return
    if args.cases is None:
        args.cases = ["base", "t1000"]
    if args.duration_sec == 60.0:
        args.duration_sec = 18.0
    if args.attack_start_sec == 10.0:
        args.attack_start_sec = 4.0
    if args.attack_end_sec == 50.0:
        args.attack_end_sec = 14.0


def validate_args(args: argparse.Namespace) -> None:
    if args.duration_sec <= 0:
        raise SystemExit("--duration-sec must be positive")
    if not 0 <= args.attack_start_sec < args.attack_end_sec <= args.duration_sec:
        raise SystemExit("require 0 <= --attack-start-sec < --attack-end-sec <= --duration-sec")
    if args.bottleneck_mbps <= 0 or args.burst_rate_mbps <= 0:
        raise SystemExit("rates must be positive")
    if args.delay_ms < 0 or args.queue_packets <= 0 or args.payload_size <= 0:
        raise SystemExit("delay, queue, and payload arguments are invalid")
    if args.burst_ms <= 0 or args.ss_interval_ms <= 0:
        raise SystemExit("--burst-ms and --ss-interval-ms must be positive")


def parse_case_periods(items: list[str]) -> dict[str, float]:
    periods = dict(DEFAULT_CASE_PERIODS)
    for item in items:
        if "=" not in item:
            raise SystemExit(f"invalid --case-period-ms item: {item!r}")
        name, value = item.split("=", 1)
        if not name:
            raise SystemExit("case period name cannot be empty")
        period = float(value)
        if period <= 0:
            raise SystemExit(f"period must be positive for {name}")
        periods[name] = period
    return periods


def assert_mininet_environment() -> None:
    if platform.system() != "Linux":
        raise SystemExit("Run this experiment on Linux with Mininet.")
    if os.geteuid() != 0:
        raise SystemExit("Mininet requires root privileges. Use sudo.")
    missing = [cmd for cmd in ("mn", "iperf3", "tcpdump", "tc", "ip", "ss", "nstat", "python3") if shutil.which(cmd) is None]
    if missing:
        raise SystemExit("Missing required command(s): " + ", ".join(missing))
    try:
        __import__("mininet")
    except ImportError as exc:
        raise SystemExit("The Mininet Python package is missing.") from exc


def write_config(args: argparse.Namespace, output_dir: Path, run_id: str, cases: list[str], periods: dict[str, float]) -> None:
    config = {
        "experiment": "rto_cycle",
        "date": "2026-06-17",
        "run_id": run_id,
        "created_epoch": time.time(),
        "output_dir": str(output_dir),
        "cases": [{"case": case, "period_ms": None if case == "base" else periods[case]} for case in cases],
        "duration_sec": args.duration_sec,
        "attack_start_sec": args.attack_start_sec,
        "attack_end_sec": args.attack_end_sec,
        "bottleneck_mbps": args.bottleneck_mbps,
        "one_way_delay_ms": args.delay_ms,
        "queue_packets": args.queue_packets,
        "queue_discipline": "DropTail",
        "burst_rate_mbps": args.burst_rate_mbps,
        "burst_ms": args.burst_ms,
        "payload_size": args.payload_size,
        "ss_interval_ms": args.ss_interval_ms,
        "tcp_congestion_requested": args.tcp_congestion,
        "tcp_sack_requested": args.tcp_sack,
        "command": " ".join(sys.argv),
    }
    (output_dir / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")


def run_case(args: argparse.Namespace, output_dir: Path, case: str, period_ms: float | None) -> dict[str, Any]:
    from mininet.clean import cleanup
    from mininet.link import TCLink
    from mininet.net import Mininet
    from mininet.node import Node
    from mininet.topo import Topo

    class LinuxRouter(Node):
        def config(self, **params: Any) -> None:
            super().config(**params)
            self.cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null")

        def terminate(self) -> None:
            self.cmd("sysctl -w net.ipv4.ip_forward=0 >/dev/null")
            super().terminate()

    class RtoCycleTopo(Topo):
        def build(self) -> None:
            h1 = self.addHost("h1")
            h2 = self.addHost("h2")
            h3 = self.addHost("h3")
            r1 = self.addHost("r1", cls=LinuxRouter)
            self.addLink(h1, r1, bw=100, delay="1ms", use_htb=True)
            self.addLink(h3, r1, bw=100, delay="1ms", use_htb=True)
            self.addLink(
                r1,
                h2,
                bw=args.bottleneck_mbps,
                delay=f"{args.delay_ms}ms",
                max_queue_size=args.queue_packets,
                use_htb=True,
            )

    case_dir = output_dir / "cases" / case
    raw_dir = case_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    print(f"Running case {case} period={period_ms}")
    cleanup()
    net = Mininet(topo=RtoCycleTopo(), link=TCLink, controller=None, autoSetMacs=True)
    handles: list[ProcessHandle] = []
    started = False
    try:
        net.start()
        started = True
        h1, h2, h3, r1 = [net.get(name) for name in ("h1", "h2", "h3", "r1")]
        configure_network(h1, h2, h3, r1, args)
        record_text(raw_dir / "tcp_config_before.txt", collect_tcp_config(h1))
        apply_tcp_settings(h1, args)
        record_text(raw_dir / "tcp_config.txt", collect_tcp_config(h1))
        record_text(raw_dir / "nstat_before.txt", h1.cmd("nstat -az"))
        record_qdisc(raw_dir / "qdisc_before.txt", r1, h2)

        pcap_before = raw_dir / "bottleneck_before.pcap"
        pcap_after = raw_dir / "bottleneck_after.pcap"
        handles.append(popen_node(r1, ["tcpdump", "-i", "r1-eth2", "-U", "-w", str(pcap_before)], raw_dir / "tcpdump_before.log"))
        handles.append(popen_node(h2, ["tcpdump", "-i", "h2-eth0", "-U", "-w", str(pcap_after)], raw_dir / "tcpdump_after.log"))
        handles.append(popen_node(h2, ["iperf3", "-s", "-p", str(args.iperf_port), "-1"], raw_dir / "iperf_server.log"))
        start_epoch = time.time() + args.start_delay_sec
        handles.append(
            popen_node(
                h2,
                [
                    "python3",
                    "-c",
                    UDP_SINK_CODE,
                    str(start_epoch),
                    str(args.duration_sec + 2.0),
                    "0.0.0.0",
                    str(args.udp_port),
                    str(raw_dir / "udp_sink.csv"),
                ],
                raw_dir / "udp_sink_stdout.log",
                raw_dir / "udp_sink_stderr.log",
            )
        )
        ss_handle = popen_node(
            h1,
            [
                "python3",
                "-c",
                SS_SAMPLER_CODE,
                str(start_epoch),
                str(args.duration_sec + 1.0),
                str(args.ss_interval_ms / 1000.0),
                str(raw_dir / "ss_raw.log"),
            ],
            raw_dir / "ss_sampler_stdout.log",
            raw_dir / "ss_sampler_stderr.log",
        )
        handles.append(ss_handle)
        if period_ms is not None:
            handles.append(
                popen_node(
                    h3,
                    [
                        "python3",
                        "-c",
                        UDP_BURST_CODE,
                        str(start_epoch),
                        str(args.attack_start_sec),
                        str(args.attack_end_sec),
                        str(period_ms),
                        str(args.burst_ms),
                        str(args.burst_rate_mbps),
                        str(args.payload_size),
                        RECEIVER_IP,
                        str(args.udp_port),
                        str(raw_dir / "pulses.csv"),
                    ],
                    raw_dir / "pulse_sender_stdout.log",
                    raw_dir / "pulse_sender_stderr.log",
                )
            )
        else:
            write_empty_pulse_log(raw_dir / "pulses.csv")

        client = popen_node(
            h1,
            [
                "python3",
                "-c",
                IPERF_CLIENT_CODE,
                str(start_epoch),
                str(args.duration_sec),
                RECEIVER_IP,
                str(args.iperf_port),
            ],
            raw_dir / "iperf3.json",
            raw_dir / "iperf_client_stderr.log",
        )
        handles.append(client)
        client_rc = client.wait(timeout=args.duration_sec + args.start_delay_sec + 20.0)
        time.sleep(1.0)
        record_text(raw_dir / "nstat_after.txt", h1.cmd("nstat -az"))
        record_qdisc(raw_dir / "qdisc_after.txt", r1, h2)
        case_meta = {
            "case": case,
            "period_ms": period_ms,
            "start_epoch": start_epoch,
            "client_rc": client_rc,
            "sender_ip": SENDER_IP,
            "receiver_ip": RECEIVER_IP,
            "attacker_ip": ATTACKER_IP,
            "bottleneck_before_pcap": str(pcap_before),
            "bottleneck_after_pcap": str(pcap_after),
            "bottleneck_before_iface": "r1-eth2",
            "bottleneck_after_iface": "h2-eth0",
        }
        (case_dir / "case.json").write_text(json.dumps(case_meta, indent=2), encoding="utf-8")
        return case_meta
    finally:
        for handle in reversed(handles):
            handle.terminate()
        if started:
            net.stop()
        cleanup()


def configure_network(h1: Any, h2: Any, h3: Any, r1: Any, args: argparse.Namespace) -> None:
    h1.setIP(f"{SENDER_IP}/24", intf="h1-eth0")
    h2.setIP(f"{RECEIVER_IP}/24", intf="h2-eth0")
    h3.setIP(f"{ATTACKER_IP}/24", intf="h3-eth0")
    r1.setIP(f"{ROUTER_SENDER_IP}/24", intf="r1-eth0")
    r1.setIP(f"{ROUTER_ATTACKER_IP}/24", intf="r1-eth1")
    r1.setIP(f"{ROUTER_RECEIVER_IP}/24", intf="r1-eth2")
    h1.cmd(f"ip route replace default via {ROUTER_SENDER_IP}")
    h2.cmd(f"ip route replace default via {ROUTER_RECEIVER_IP}")
    h3.cmd(f"ip route replace default via {ROUTER_ATTACKER_IP}")
    for host in (h1, h2, h3, r1):
        host.cmd("ip link set dev lo up")
    # TCLink installs the bottleneck qdisc. Keep this explicit record near setup.
    r1.cmd(f"tc qdisc show dev r1-eth2 > /tmp/rto_cycle_qdisc_{os.getpid()}.txt")


def apply_tcp_settings(h1: Any, args: argparse.Namespace) -> None:
    if args.tcp_congestion:
        h1.cmd(f"sysctl -w net.ipv4.tcp_congestion_control={args.tcp_congestion} >/dev/null")
    if args.tcp_sack != "keep":
        h1.cmd(f"sysctl -w net.ipv4.tcp_sack={'1' if args.tcp_sack == 'on' else '0'} >/dev/null")


def collect_tcp_config(h1: Any) -> str:
    lines = [
        "tcp_congestion_control=" + h1.cmd("sysctl -n net.ipv4.tcp_congestion_control").strip(),
        "tcp_available_congestion_control=" + h1.cmd("sysctl -n net.ipv4.tcp_available_congestion_control").strip(),
        "tcp_sack=" + h1.cmd("sysctl -n net.ipv4.tcp_sack").strip(),
        "tcp_timestamps=" + h1.cmd("sysctl -n net.ipv4.tcp_timestamps").strip(),
        "tcp_recovery=" + h1.cmd("sysctl -n net.ipv4.tcp_recovery 2>/dev/null || true").strip(),
    ]
    return "\n".join(lines) + "\n"


def record_qdisc(path: Path, r1: Any, h2: Any) -> None:
    text = [
        "## r1-eth2",
        r1.cmd("tc -s qdisc show dev r1-eth2"),
        "## h2-eth0",
        h2.cmd("tc -s qdisc show dev h2-eth0"),
    ]
    record_text(path, "\n".join(text))


def popen_node(node: Any, command: list[str], stdout_path: Path, stderr_path: Path | None = None) -> ProcessHandle:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stdout = stdout_path.open("wb")
    stderr = (stderr_path or stdout_path.with_suffix(stdout_path.suffix + ".err")).open("wb")
    proc = node.popen(command, stdout=stdout, stderr=stderr)
    return ProcessHandle(proc=proc, stdout=stdout, stderr=stderr)


def record_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_empty_pulse_log(path: Path) -> None:
    fields = [
        "pulse_index",
        "scheduled_start_sec",
        "scheduled_start_epoch",
        "scheduled_end_epoch",
        "scheduled_start_mono_ns",
        "scheduled_end_mono_ns",
        "actual_start_epoch",
        "actual_end_epoch",
        "actual_start_mono_ns",
        "actual_end_mono_ns",
        "scheduled_duration_sec",
        "actual_duration_sec",
        "packets_sent",
        "bytes_sent",
        "expected_bytes",
        "period_ms",
        "burst_ms",
        "target_rate_mbps",
        "skipped",
        "skip_reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        csv.DictWriter(handle, fieldnames=fields).writeheader()


def write_manifest(output_dir: Path, args: argparse.Namespace, run_id: str, cases: list[str], case_results: list[dict[str, Any]]) -> None:
    def git_text(command: list[str]) -> str:
        result = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True)
        return result.stdout.strip() if result.returncode == 0 else "unknown"

    tcp_config = ""
    if cases:
        tcp_config_path = output_dir / "cases" / cases[0] / "raw" / "tcp_config.txt"
        if tcp_config_path.exists():
            tcp_config = tcp_config_path.read_text(encoding="utf-8", errors="replace").strip()
    manifest = [
        f"experiment=rto_cycle",
        f"run_id={run_id}",
        f"created={datetime.now().isoformat(timespec='seconds')}",
        f"git_commit={git_text(['git', 'rev-parse', 'HEAD'])}",
        f"git_branch={git_text(['git', 'branch', '--show-current'])}",
        f"kernel={platform.release()}",
        f"platform={platform.platform()}",
        f"command={' '.join(sys.argv)}",
        f"cases={','.join(cases)}",
        f"duration_sec={args.duration_sec}",
        f"attack_window={args.attack_start_sec}-{args.attack_end_sec}",
        f"bottleneck_mbps={args.bottleneck_mbps}",
        f"delay_ms={args.delay_ms}",
        f"queue_packets={args.queue_packets}",
        f"burst_rate_mbps={args.burst_rate_mbps}",
        f"burst_ms={args.burst_ms}",
        f"ss_interval_ms={args.ss_interval_ms}",
        "",
        "tcp_config:",
        tcp_config or "unknown",
        "",
        "case_results=" + json.dumps(case_results, indent=2),
    ]
    (output_dir / "manifest.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
