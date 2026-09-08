"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Shared metric and classification helpers for the LDoS bandwidth experiment.
Units:
  - Rates are Mbps unless the name explicitly says pct or ratio.
  - Degradation values with suffix _pct are percentages.
  - Excess degradation is a percentage-point difference between percentages.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import mean, stdev
from typing import Iterable, Mapping


DEFAULT_BOTTLENECK_MBPS = 15.0
DEFAULT_IPERF_PORT = 5201
DEFAULT_ATTACK_UDP_PORT = 5001
DEFAULT_TCP_SENDER_IP = "10.0.0.1"
DEFAULT_RECEIVER_IP = "10.0.0.2"
DEFAULT_ATTACKER_IPS = ("10.0.0.3", "10.0.0.4")


@dataclass(frozen=True)
class CapacityBreakdown:
    tcp_normal_mbps: float
    attack_passed_mbps: float
    other_mbps: float
    total_passed_mbps: float
    idle_mbps: float
    capacity_excess_mbps: float
    capacity_excess_pct: float
    link_utilization_pct: float
    tcp_share_pct: float
    attack_share_pct: float
    other_share_pct: float
    idle_share_pct: float


def average_attack_rate_mbps(peak_rate_mbps: float, burst_ms: float, period_ms: float) -> float:
    """R_avg = R * L / T."""
    if period_ms <= 0:
        raise ValueError("period_ms must be positive")
    return peak_rate_mbps * (burst_ms / period_ms)


def configured_average_attack_pct(average_mbps: float, bottleneck_mbps: float) -> float:
    if bottleneck_mbps <= 0:
        raise ValueError("bottleneck_mbps must be positive")
    return 100.0 * average_mbps / bottleneck_mbps


def compute_capacity_breakdown(
    tcp_normal_mbps: float,
    attack_passed_mbps: float,
    other_mbps: float,
    bottleneck_mbps: float,
) -> CapacityBreakdown:
    """Split bottleneck capacity into normal TCP, attack, other, and idle capacity."""
    if bottleneck_mbps <= 0:
        raise ValueError("bottleneck_mbps must be positive")
    total = max(tcp_normal_mbps, 0.0) + max(attack_passed_mbps, 0.0) + max(other_mbps, 0.0)
    idle = max(bottleneck_mbps - total, 0.0)
    excess = max(total - bottleneck_mbps, 0.0)
    return CapacityBreakdown(
        tcp_normal_mbps=tcp_normal_mbps,
        attack_passed_mbps=attack_passed_mbps,
        other_mbps=other_mbps,
        total_passed_mbps=total,
        idle_mbps=idle,
        capacity_excess_mbps=excess,
        capacity_excess_pct=100.0 * excess / bottleneck_mbps,
        link_utilization_pct=100.0 * total / bottleneck_mbps,
        tcp_share_pct=100.0 * max(tcp_normal_mbps, 0.0) / bottleneck_mbps,
        attack_share_pct=100.0 * max(attack_passed_mbps, 0.0) / bottleneck_mbps,
        other_share_pct=100.0 * max(other_mbps, 0.0) / bottleneck_mbps,
        idle_share_pct=100.0 * idle / bottleneck_mbps,
    )


def tcp_degradation_pct(tcp_baseline_mbps: float, tcp_mbps: float) -> float:
    """D_s = 1 - G_TCP,s / G_TCP,no_attack, returned as percent."""
    if tcp_baseline_mbps <= 0:
        return math.nan
    return 100.0 * (1.0 - tcp_mbps / tcp_baseline_mbps)


def excess_degradation_pp(primary_degradation_pct: float, reference_degradation_pct: float) -> float:
    """Percentage-point excess: e.g. 50% - 36% = 14 percentage points."""
    if math.isnan(primary_degradation_pct) or math.isnan(reference_degradation_pct):
        return math.nan
    return primary_degradation_pct - reference_degradation_pct


def normal_attack_idle_ratio(tcp_share_pct: float, attack_share_pct: float, idle_share_pct: float) -> str:
    return f"{tcp_share_pct / 100.0:.2f}:{attack_share_pct / 100.0:.2f}:{idle_share_pct / 100.0:.2f}"


def aggregate_seed_stats(values: Iterable[float]) -> dict[str, float]:
    valid = [float(v) for v in values if v is not None and not math.isnan(float(v))]
    if not valid:
        return {"mean": math.nan, "std": math.nan, "ci95": math.nan, "n": 0}
    if len(valid) == 1:
        return {"mean": valid[0], "std": math.nan, "ci95": math.nan, "n": 1}
    sample_std = stdev(valid)
    return {
        "mean": mean(valid),
        "std": sample_std,
        "ci95": 1.96 * sample_std / math.sqrt(len(valid)),
        "n": len(valid),
    }


def classify_packet(
    packet: Mapping[str, object],
    tcp_sender_ip: str = DEFAULT_TCP_SENDER_IP,
    receiver_ip: str = DEFAULT_RECEIVER_IP,
    attacker_ips: Iterable[str] = DEFAULT_ATTACKER_IPS,
    iperf_port: int = DEFAULT_IPERF_PORT,
    attack_udp_port: int = DEFAULT_ATTACK_UDP_PORT,
) -> str:
    """Classify a parsed packet into tcp_normal, attack, or other.

    TCP normal goodput includes sender-to-receiver TCP packets with payload.
    Reverse ACK-only traffic is intentionally excluded.
    """
    proto = str(packet.get("proto", "")).upper()
    src_ip = str(packet.get("src_ip", ""))
    dst_ip = str(packet.get("dst_ip", ""))
    src_port = int(packet.get("src_port") or 0)
    dst_port = int(packet.get("dst_port") or 0)
    payload_bytes = int(packet.get("payload_bytes") or 0)
    attackers = set(attacker_ips)

    if (
        proto == "TCP"
        and src_ip == tcp_sender_ip
        and dst_ip == receiver_ip
        and (dst_port == iperf_port or src_port == iperf_port)
        and payload_bytes > 0
    ):
        return "tcp_normal"
    if (
        proto == "UDP"
        and src_ip in attackers
        and dst_ip == receiver_ip
        and (dst_port == attack_udp_port or attack_udp_port == 0)
    ):
        return "attack"
    return "other"


def focused_conditions(bottleneck_mbps: float, period_ms: float) -> list[dict[str, float | str]]:
    """Default focused grid, excluding configured average loads above 33% of C."""
    specs = [
        ("avg10_peak1", 1.0, 0.10),
        ("avg20_peak1", 1.0, 0.20),
        ("avg30_peak1", 1.0, 0.30),
        ("avg30_peak1_5", 1.5, 0.20),
        ("avg30_peak3", 3.0, 0.10),
    ]
    rows: list[dict[str, float | str]] = []
    for condition_id, peak_multiplier, duty_ratio in specs:
        peak = bottleneck_mbps * peak_multiplier
        burst_ms = period_ms * duty_ratio
        avg = average_attack_rate_mbps(peak, burst_ms, period_ms)
        avg_pct = configured_average_attack_pct(avg, bottleneck_mbps)
        if avg_pct <= 33.0 + 1e-9:
            rows.append(
                {
                    "condition_id": condition_id,
                    "peak_multiplier": peak_multiplier,
                    "duty_ratio": duty_ratio,
                    "peak_rate_mbps": peak,
                    "burst_ms": burst_ms,
                    "period_ms": period_ms,
                    "configured_average_attack_mbps": avg,
                    "configured_average_attack_pct": avg_pct,
                }
            )
    return rows
