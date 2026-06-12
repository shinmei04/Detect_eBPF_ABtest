"""Send single-flow, composite, and F-LDDoS-style UDP traffic.

The sender owns one UDP socket per logical attack flow.  Source ports therefore
remain stable across the benign baseline, feint, and attack portions, allowing
the offline evaluator to compare aggregate and per-flow views of one pcap.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.phase_labeling import build_phase_intervals, canonical_phase, phase_offsets_ms


ATTACK_MODES = [
    "single_flow_ldos",
    "multi_flow_sync_lddos",
    "multi_flow_staggered_lddos",
    "multi_flow_randomized_lddos",
    "score_aware_lddos",
    "f_lddos",
]
SCENARIOS = [
    "random_microburst_only",
    "single_flow_ldos",
    "composite_lddos",
    "stat_matched_composite_lddos",
]
EMPIRICAL_PAYLOADS = [80, 750, 1000, 1200, 1472]
EMPIRICAL_WEIGHTS = [0.30, 0.30, 0.20, 0.10, 0.10]


@dataclass(frozen=True)
class PacketEvent:
    """One scheduled packet."""

    scheduled_sec: float
    flow_index: int
    payload_size: int
    phase: str
    period_index: int


def parse_args() -> argparse.Namespace:
    """Parse sender arguments."""
    parser = argparse.ArgumentParser(description="Send composite/F-LDDoS UDP traffic.")
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, default=5001)
    parser.add_argument("--base-src-port", type=int, default=40000)
    parser.add_argument("--duration-sec", type=float, required=True)
    parser.add_argument("--attack-start-sec", type=float, required=True)
    parser.add_argument(
        "--experiment-start-wall",
        type=float,
        help="Wall-clock origin used by pcap timestamps; defaults to sender start.",
    )
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--attack-mode", choices=ATTACK_MODES, required=True)
    parser.add_argument("--total-attack-rate-mbps", type=float, required=True)
    parser.add_argument(
        "--target-total-average-rate-mbps",
        type=float,
        help="Budget target for attack+feint average rate over the attack window.",
    )
    parser.add_argument("--num-attack-flows", type=int, required=True)
    parser.add_argument("--burst-ms", type=int, required=True)
    parser.add_argument("--period-ms", type=int, required=True)
    parser.add_argument("--payload-size", type=int, required=True)
    parser.add_argument("--payload-mode", choices=["fixed", "empirical", "uniform"], default="fixed")
    parser.add_argument("--phase-spread-ms", type=float, default=0.0)
    parser.add_argument("--jitter-ratio", type=float, default=0.0)
    parser.add_argument("--feint-rate-ratio", type=float, default=0.10)
    parser.add_argument("--feint-randomness", choices=["uniform", "poisson"], default="poisson")
    parser.add_argument("--attack-interval-placement", choices=["start", "end"], default="end")
    parser.add_argument(
        "--randomize-pulse-start",
        action="store_true",
        help="Randomize one aggregate pulse start within each attack period while keeping flows synchronized.",
    )
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--summary-json", type=Path, required=True)
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    """Validate sender arguments."""
    if args.duration_sec <= 0:
        raise ValueError("duration_sec must be positive")
    if not 0 <= args.attack_start_sec < args.duration_sec:
        raise ValueError("attack_start_sec must be in [0, duration_sec)")
    if args.total_attack_rate_mbps <= 0:
        raise ValueError("total_attack_rate_mbps must be positive")
    if args.target_total_average_rate_mbps is not None and args.target_total_average_rate_mbps <= 0:
        raise ValueError("target_total_average_rate_mbps must be positive when supplied")
    if args.num_attack_flows <= 0:
        raise ValueError("num_attack_flows must be positive")
    if args.burst_ms <= 0 or args.period_ms <= 0 or args.burst_ms > args.period_ms:
        raise ValueError("require 0 < burst_ms <= period_ms")
    if not 80 <= args.payload_size <= 1472:
        raise ValueError("payload_size must be in 80..1472")
    if args.phase_spread_ms < 0:
        raise ValueError("phase_spread_ms must be non-negative")
    if not 0 <= args.jitter_ratio <= 1:
        raise ValueError("jitter_ratio must be in [0, 1]")
    if args.feint_rate_ratio < 0:
        raise ValueError("feint_rate_ratio must be non-negative")
    if args.base_src_port <= 0 or args.base_src_port + args.num_attack_flows >= 65536:
        raise ValueError("source port range is invalid")


def effective_settings(args: argparse.Namespace) -> dict[str, object]:
    """Return mode-specific effective settings."""
    settings: dict[str, object] = {
        "attack_mode": args.attack_mode,
        "num_attack_flows": args.num_attack_flows,
        "phase_spread_ms": min(float(args.phase_spread_ms), float(args.burst_ms)),
        "jitter_ratio": float(args.jitter_ratio),
        "payload_mode": args.payload_mode,
    }
    if args.scenario == "single_flow_ldos" or args.attack_mode == "single_flow_ldos":
        settings.update(
            {
                "attack_mode": "single_flow_ldos",
                "num_attack_flows": 1,
                "phase_spread_ms": 0.0,
                "jitter_ratio": 0.0,
                "payload_mode": "fixed",
            }
        )
    elif args.attack_mode == "multi_flow_sync_lddos":
        settings["phase_spread_ms"] = 0.0
    elif args.attack_mode == "score_aware_lddos":
        settings["phase_spread_ms"] = max(
            float(settings["phase_spread_ms"]),
            min(float(args.burst_ms) * 0.5, 200.0),
        )
        settings["jitter_ratio"] = max(float(settings["jitter_ratio"]), 0.5)
        if settings["payload_mode"] == "fixed":
            settings["payload_mode"] = "empirical"
    return settings


def sample_payload(rng: random.Random, payload_mode: str, payload_size: int) -> int:
    """Sample one payload size."""
    if payload_mode == "fixed":
        return int(payload_size)
    if payload_mode == "empirical":
        return int(rng.choices(EMPIRICAL_PAYLOADS, weights=EMPIRICAL_WEIGHTS, k=1)[0])
    return int(max(80, min(1472, round(rng.uniform(payload_size * 0.5, payload_size * 1.5)))))


def rate_events(
    *,
    start_sec: float,
    end_sec: float,
    rate_mbps: float,
    flow_index: int,
    phase: str,
    period_index: int,
    payload_mode: str,
    payload_size: int,
    jitter_ratio: float,
    rng: random.Random,
    randomness: str = "uniform",
) -> list[PacketEvent]:
    """Build rate-controlled packet events in one interval."""
    if end_sec <= start_sec or rate_mbps <= 0:
        return []
    events: list[PacketEvent] = []
    current = start_sec
    if phase in {"baseline_normal", "feint"}:
        first_payload = sample_payload(rng, payload_mode, payload_size)
        mean_interval = first_payload * 8.0 / (rate_mbps * 1_000_000.0)
        current += rng.uniform(0.0, mean_interval)
    while current < end_sec:
        packet_size = sample_payload(rng, payload_mode, payload_size)
        events.append(PacketEvent(current, flow_index, packet_size, phase, period_index))
        mean_interval = packet_size * 8.0 / (rate_mbps * 1_000_000.0)
        if randomness == "poisson":
            interval = rng.expovariate(1.0 / max(mean_interval, 1e-9))
        elif phase in {"baseline_normal", "feint"}:
            interval = mean_interval * rng.uniform(0.5, 1.5)
        else:
            factor = rng.uniform(max(0.05, 1.0 - jitter_ratio), 1.0 + jitter_ratio)
            interval = mean_interval * factor
        current += max(interval, 1e-7)
    return events


def event_stream(args: argparse.Namespace) -> tuple[Iterable[PacketEvent], dict[str, object]]:
    """Return a bounded-memory event stream and effective metadata."""
    validate_args(args)
    settings = effective_settings(args)
    num_flows = int(settings["num_attack_flows"])
    average_multiplier = planned_average_rate_multiplier(args, settings)
    requested_total_attack_rate_mbps = float(args.total_attack_rate_mbps)
    if args.target_total_average_rate_mbps is not None and average_multiplier > 0:
        effective_total_attack_rate_mbps = float(args.target_total_average_rate_mbps) / average_multiplier
    else:
        effective_total_attack_rate_mbps = requested_total_attack_rate_mbps
    per_flow_rate = effective_total_attack_rate_mbps / num_flows
    configured_total_average = (
        float(args.target_total_average_rate_mbps)
        if args.target_total_average_rate_mbps is not None
        else effective_total_attack_rate_mbps * average_multiplier
    )
    metadata = {
        **settings,
        "scenario": args.scenario,
        "requested_total_attack_rate_mbps": requested_total_attack_rate_mbps,
        "total_attack_rate_mbps": float(effective_total_attack_rate_mbps),
        "per_flow_rate_mbps": float(per_flow_rate),
        "target_total_average_rate_mbps": args.target_total_average_rate_mbps,
        "configured_total_attack_avg_mbps": configured_total_average,
        "planned_average_rate_multiplier": average_multiplier,
        "burst_ms": int(args.burst_ms),
        "period_ms": int(args.period_ms),
        "payload_size": int(args.payload_size),
        "feint_rate_ratio": float(args.feint_rate_ratio),
        "feint_randomness": args.feint_randomness,
        "attack_interval_placement": args.attack_interval_placement,
        "randomize_pulse_start": bool(args.randomize_pulse_start),
    }
    return iter_scheduled_events(args, metadata), metadata


def planned_average_rate_multiplier(args: argparse.Namespace, settings: dict[str, object]) -> float:
    """Return attack-window average load per 1 Mbps aggregate burst rate.

    For F-LDDoS this includes both attack bursts and feint traffic.  The value
    is used to invert a configured total average budget into the aggregate
    burst rate that should be passed to the packet scheduler.
    """
    attack_duration = max(0.0, args.duration_sec - args.attack_start_sec)
    if attack_duration <= 0:
        return 0.0
    mode = str(settings["attack_mode"])
    num_flows = int(settings["num_attack_flows"])
    spread_ms = float(settings["phase_spread_ms"])
    period_sec = args.period_ms / 1000.0
    burst_sec = args.burst_ms / 1000.0
    rate_seconds = 0.0
    period_index = 0
    period_start = args.attack_start_sec
    while period_start < args.duration_sec:
        period_end = min(period_start + period_sec, args.duration_sec)
        offsets = phase_offsets_ms(mode, num_flows, spread_ms, period_index, args.seed)
        if mode == "f_lddos":
            attack_base = period_sec - burst_sec if args.attack_interval_placement == "end" else 0.0
            earliest_attack = max(0.0, attack_base - max(offsets, default=0.0) / 1000.0)
            feint_end = min(period_end, period_start + earliest_attack)
            feint_len = max(0.0, feint_end - period_start)
        else:
            attack_base = 0.0
            feint_len = 0.0
        for flow in range(num_flows):
            offset_sec = offsets[flow] / 1000.0
            if mode == "f_lddos" and args.attack_interval_placement == "end":
                attack_start = period_start + max(0.0, attack_base - offset_sec)
            else:
                attack_start = period_start + attack_base + offset_sec
            attack_end = min(attack_start + burst_sec, period_end)
            rate_seconds += max(0.0, attack_end - attack_start)
            if mode == "f_lddos":
                rate_seconds += args.feint_rate_ratio * feint_len
        period_index += 1
        period_start += period_sec
    return rate_seconds / (num_flows * attack_duration)


def build_events(args: argparse.Namespace) -> tuple[list[PacketEvent], dict[str, object]]:
    """Materialize events for small tests; the CLI uses ``event_stream``."""
    events, metadata = event_stream(args)
    return list(events), metadata


def iter_scheduled_events(
    args: argparse.Namespace,
    metadata: dict[str, object],
) -> Iterable[PacketEvent]:
    """Yield sorted events one period at a time to bound sender memory."""
    mode = str(metadata["attack_mode"])
    num_flows = int(metadata["num_attack_flows"])
    spread_ms = float(metadata["phase_spread_ms"])
    jitter_ratio = float(metadata["jitter_ratio"])
    payload_mode = str(metadata["payload_mode"])
    per_flow_rate = float(metadata["per_flow_rate_mbps"])
    period_sec = args.period_ms / 1000.0
    burst_sec = args.burst_ms / 1000.0
    rngs = [random.Random(args.seed * 1009 + flow * 9176) for flow in range(num_flows)]

    if args.scenario == "random_microburst_only":
        baseline_end = args.duration_sec
        baseline_kind = "baseline_microburst"
    else:
        baseline_end = args.attack_start_sec
        baseline_kind = (
            "baseline_microburst"
            if args.scenario == "stat_matched_composite_lddos"
            else "baseline_normal"
        )

    period_index = 0
    period_start = 0.0
    while period_start < baseline_end:
        period_end = min(period_start + period_sec, baseline_end)
        batch: list[PacketEvent] = []
        if baseline_kind == "baseline_normal":
            benign_rate = max(0.5, min(per_flow_rate * 0.10, 5.0))
            for flow in range(num_flows):
                batch.extend(
                    rate_events(
                        start_sec=period_start,
                        end_sec=period_end,
                        rate_mbps=benign_rate,
                        flow_index=flow,
                        phase=baseline_kind,
                        period_index=period_index,
                        payload_mode="empirical",
                        payload_size=args.payload_size,
                        jitter_ratio=1.0,
                        rng=rngs[flow],
                        randomness="poisson",
                    )
                )
        else:
            for flow in range(num_flows):
                rng = rngs[flow]
                latest_start = max(period_start, period_end - burst_sec)
                start = (
                    period_start
                    if latest_start <= period_start
                    else rng.uniform(period_start, latest_start)
                )
                batch.extend(
                    rate_events(
                        start_sec=start,
                        end_sec=min(start + burst_sec, period_end),
                        rate_mbps=per_flow_rate,
                        flow_index=flow,
                        phase=baseline_kind,
                        period_index=period_index,
                        payload_mode=payload_mode,
                        payload_size=args.payload_size,
                        jitter_ratio=max(0.5, jitter_ratio),
                        rng=rng,
                    )
                )
        yield from sorted(batch, key=lambda event: (event.scheduled_sec, event.flow_index))
        period_index += 1
        period_start += period_sec

    if args.scenario == "random_microburst_only":
        return

    period_index = 0
    period_start = args.attack_start_sec
    while period_start < args.duration_sec:
        period_end = min(period_start + period_sec, args.duration_sec)
        offsets = phase_offsets_ms(mode, num_flows, spread_ms, period_index, args.seed)
        batch = []
        if mode == "f_lddos":
            attack_base = (
                max(0.0, period_sec - burst_sec)
                if args.attack_interval_placement == "end"
                else 0.0
            )
            earliest_attack = max(0.0, attack_base - max(offsets, default=0.0) / 1000.0)
            feint_end = min(period_end, period_start + earliest_attack)
            for flow in range(num_flows):
                batch.extend(
                    rate_events(
                        start_sec=period_start,
                        end_sec=feint_end,
                        rate_mbps=per_flow_rate * args.feint_rate_ratio,
                        flow_index=flow,
                        phase="feint",
                        period_index=period_index,
                        payload_mode=payload_mode,
                        payload_size=args.payload_size,
                        jitter_ratio=1.0,
                        rng=rngs[flow],
                        randomness=args.feint_randomness,
                    )
                )
        else:
            attack_base = 0.0
            if args.randomize_pulse_start:
                latest_base = max(0.0, period_sec - burst_sec)
                attack_base = random.Random(args.seed * 1_000_003 + period_index * 10_007).uniform(0.0, latest_base)
                offsets = [0.0] * num_flows

        for flow in range(num_flows):
            offset_sec = offsets[flow] / 1000.0
            if mode == "f_lddos" and args.attack_interval_placement == "end":
                attack_start = period_start + max(0.0, attack_base - offset_sec)
            else:
                attack_start = period_start + attack_base + offset_sec
            batch.extend(
                rate_events(
                    start_sec=attack_start,
                    end_sec=min(attack_start + burst_sec, period_end),
                    rate_mbps=per_flow_rate,
                    flow_index=flow,
                    phase="attack",
                    period_index=period_index,
                    payload_mode=payload_mode,
                    payload_size=args.payload_size,
                    jitter_ratio=jitter_ratio,
                    rng=rngs[flow],
                )
            )
        yield from sorted(batch, key=lambda event: (event.scheduled_sec, event.flow_index))
        period_index += 1
        period_start += period_sec


def send_events(
    args: argparse.Namespace,
    events: Iterable[PacketEvent],
    metadata: dict[str, object],
) -> dict[str, object]:
    """Send scheduled events and write measured phase/flow summaries."""
    num_flows = int(metadata["num_attack_flows"])
    phase_plan = build_phase_intervals(
        duration_sec=args.duration_sec,
        attack_start_sec=args.attack_start_sec,
        scenario=args.scenario,
        attack_mode=str(metadata["attack_mode"]),
        num_flows=num_flows,
        period_ms=args.period_ms,
        burst_ms=args.burst_ms,
        phase_spread_ms=float(metadata["phase_spread_ms"]),
        attack_interval_placement=args.attack_interval_placement,
        seed=args.seed,
        per_flow_rate_mbps=float(metadata["per_flow_rate_mbps"]),
        feint_rate_ratio=args.feint_rate_ratio,
        base_src_port=args.base_src_port,
    )
    sockets = []
    for flow in range(num_flows):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", args.base_src_port + flow))
        sockets.append(sock)

    start_monotonic = time.monotonic()
    start_wall = time.time()
    rows = phase_plan.to_dict(orient="records")
    records: dict[tuple[str, int, int], dict[str, object]] = {}
    for row in rows:
        row.update(
            {
                "packet_count": 0,
                "byte_count": 0,
                "first_send_sec": math.nan,
                "last_send_sec": math.nan,
            }
        )
        if row["phase"] != "quiet":
            flow_index = int(str(row["flow_id"]).replace("flow_", ""))
            records[(str(row["phase"]), int(row["period_index"]), flow_index)] = row
    try:
        for event in events:
            phase = canonical_phase(event.phase)
            key = (phase, event.period_index, event.flow_index)
            record = records.get(key)
            if record is None:
                raise RuntimeError(f"phase plan missing sender event key: {key}")
            record["planned_packets"] = int(record["planned_packets"]) + 1
            sleep_until(start_monotonic + event.scheduled_sec)
            sockets[event.flow_index].sendto(b"L" * event.payload_size, (args.dst_ip, args.dst_port))
            now = time.monotonic() - start_monotonic
            record["sent_packets"] = int(record["sent_packets"]) + 1
            record["packet_count"] = int(record["packet_count"]) + 1
            record["byte_count"] = int(record["byte_count"]) + event.payload_size
            if math.isnan(float(record["first_send_sec"])):
                record["first_send_sec"] = now
            record["last_send_sec"] = now
        sleep_until(start_monotonic + args.duration_sec)
    finally:
        for sock in sockets:
            sock.close()

    experiment_start_wall = float(getattr(args, "experiment_start_wall", None) or start_wall)
    phase_time_offset_sec = start_wall - experiment_start_wall
    for row in rows:
        first = float(row["first_send_sec"])
        last = float(row["last_send_sec"])
        active = max(0.0, last - first) if not math.isnan(first) and not math.isnan(last) else 0.0
        row["active_duration_sec"] = active
        row["actual_active_rate_mbps"] = (
            int(row["byte_count"]) * 8.0 / active / 1_000_000.0 if active > 0 else 0.0
        )
        row["phase_start_sec"] = float(row["phase_start_sec"]) + phase_time_offset_sec
        row["phase_end_sec"] = float(row["phase_end_sec"]) + phase_time_offset_sec
        if args.randomize_pulse_start and row["phase"] == "attack_burst" and not math.isnan(first):
            row["phase_start_sec"] = first + phase_time_offset_sec
            row["phase_end_sec"] = max(first, last) + phase_time_offset_sec
        if not math.isnan(first):
            row["first_send_sec"] = first + phase_time_offset_sec
        if not math.isnan(last):
            row["last_send_sec"] = last + phase_time_offset_sec
        row["phase_time_offset_sec"] = phase_time_offset_sec
        row["sender_start_wall"] = start_wall
        row["experiment_start_wall"] = experiment_start_wall

    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open("w", newline="", encoding="utf-8") as handle:
        fields = list(rows[0].keys()) if rows else [
            "phase",
            "period_index",
            "flow_id",
            "phase_start_sec",
            "phase_end_sec",
            "planned_packets",
            "sent_packets",
            "src_port",
            "rate_mbps",
            "packet_count",
            "byte_count",
            "first_send_sec",
            "last_send_sec",
            "active_duration_sec",
            "actual_active_rate_mbps",
            "phase_time_offset_sec",
            "sender_start_wall",
            "experiment_start_wall",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    summary = summarize_records(args, metadata, rows)
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    args.summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def summarize_records(
    args: argparse.Namespace,
    metadata: dict[str, object],
    rows: list[dict[str, object]],
) -> dict[str, object]:
    """Build aggregate and per-flow actual-rate metrics."""
    num_flows = int(metadata["num_attack_flows"])
    attack_rows = [row for row in rows if row["phase"] == "attack_burst"]
    feint_rows = [row for row in rows if row["phase"] == "feint"]
    attack_bytes = sum(int(row["byte_count"]) for row in attack_rows)
    feint_bytes = sum(int(row["byte_count"]) for row in feint_rows)
    all_bytes = sum(int(row["byte_count"]) for row in rows)
    period_sec = args.period_ms / 1000.0
    burst_sec = args.burst_ms / 1000.0
    attack_duration = max(0.0, args.duration_sec - args.attack_start_sec)
    period_count = max(1, int(math.ceil(attack_duration / period_sec)))
    aggregate_attack_active = min(attack_duration, period_count * burst_sec)
    per_flow_attack_rates = []
    per_flow_average_rates = []
    for flow in range(num_flows):
        flow_attack_bytes = sum(
            int(row["byte_count"]) for row in attack_rows if row["flow_id"] == f"flow_{flow}"
        )
        flow_all_bytes = sum(int(row["byte_count"]) for row in rows if row["flow_id"] == f"flow_{flow}")
        per_flow_attack_rates.append(rate_mbps(flow_attack_bytes, aggregate_attack_active))
        per_flow_average_rates.append(rate_mbps(flow_all_bytes, args.duration_sec))
    feint_duration = max(0.0, attack_duration - aggregate_attack_active)
    measured_total_average = rate_mbps(attack_bytes + feint_bytes, attack_duration)
    configured_total_average = float(metadata.get("configured_total_attack_avg_mbps") or 0.0)
    attack_rate_error_pct = (
        100.0 * (measured_total_average - configured_total_average) / configured_total_average
        if configured_total_average > 0
        else 0.0
    )
    return {
        **metadata,
        "actual_sent_packets": int(sum(int(row["packet_count"]) for row in rows)),
        "actual_sent_bytes": int(all_bytes),
        "udp_actual_total_burst_rate_mbps": rate_mbps(attack_bytes, aggregate_attack_active),
        "udp_actual_total_average_rate_mbps": rate_mbps(all_bytes, args.duration_sec),
        "udp_actual_per_flow_burst_rate_mbps": mean(per_flow_attack_rates),
        "udp_actual_per_flow_average_rate_mbps": mean(per_flow_average_rates),
        "feint_actual_rate_mbps": rate_mbps(feint_bytes, feint_duration),
        "attack_actual_rate_mbps": rate_mbps(attack_bytes, aggregate_attack_active),
        "measured_total_attack_offered_mbps": measured_total_average,
        "measured_total_attack_passed_mbps": "",
        "attack_rate_error_pct": attack_rate_error_pct,
        "attack_rate_match_status": "ok" if abs(attack_rate_error_pct) <= 10.0 else "over_budget" if attack_rate_error_pct > 0 else "under_budget",
        "attack_sent_bytes": int(attack_bytes),
        "feint_sent_bytes": int(feint_bytes),
        "duration_sec": float(args.duration_sec),
        "attack_duration_sec": float(attack_duration),
        "unique_flow_count_total": int(num_flows),
        "stable_flow_mode": True,
        "src_port_reuse": True,
        "phase_time_offset_sec": float(rows[0].get("phase_time_offset_sec", 0.0)) if rows else 0.0,
    }


def rate_mbps(byte_count: int, duration_sec: float) -> float:
    """Return Mbps for bytes over a duration."""
    return byte_count * 8.0 / duration_sec / 1_000_000.0 if duration_sec > 0 else 0.0


def mean(values: list[float]) -> float:
    """Return a mean with empty handling."""
    return float(sum(values) / len(values)) if values else 0.0


def sleep_until(target_monotonic: float) -> None:
    """Sleep until a monotonic target."""
    delay = target_monotonic - time.monotonic()
    if delay > 0:
        time.sleep(delay)


def main() -> None:
    """CLI entry point."""
    args = parse_args()
    events, metadata = event_stream(args)
    send_events(args, events, metadata)


if __name__ == "__main__":
    main()
