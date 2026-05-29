"""UDP sink used by Mininet A/B experiments."""

from __future__ import annotations

import argparse
import csv
import signal
import socket
import time
from pathlib import Path


SHOULD_STOP = False


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Receive UDP packets and write a CSV log.")
    parser.add_argument("--bind-ip", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--duration-sec", type=float, default=130.0)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--socket-timeout-sec", type=float, default=0.5)
    return parser.parse_args()


def request_stop(_signum: int, _frame: object) -> None:
    """Signal handler that asks the receive loop to stop."""
    global SHOULD_STOP
    SHOULD_STOP = True


def main() -> None:
    """Receive UDP datagrams until duration or signal stop."""
    args = parse_args()
    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if not 0 < args.port < 65536:
        raise ValueError("port must be in 1..65535")

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    args.log.parent.mkdir(parents=True, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind_ip, int(args.port)))
    sock.settimeout(args.socket_timeout_sec)
    end_time = time.monotonic() + args.duration_sec

    with args.log.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["receive_timestamp", "src_ip", "src_port", "dst_port", "packet_size"],
        )
        writer.writeheader()
        while not SHOULD_STOP and time.monotonic() < end_time:
            try:
                payload, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            writer.writerow(
                {
                    "receive_timestamp": f"{time.time():.9f}",
                    "src_ip": address[0],
                    "src_port": int(address[1]),
                    "dst_port": int(args.port),
                    "packet_size": len(payload),
                }
            )
        handle.flush()
    sock.close()


if __name__ == "__main__":
    main()
