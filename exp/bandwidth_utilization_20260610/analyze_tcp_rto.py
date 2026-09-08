#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Analyze TCP RTO/backoff state, retransmission events, and alignment with LDoS
attack pulses.  Direct RTO observations come from TCP_INFO fields exposed by
``ss -tin``.  pcap/tshark retransmission labels are kept separate and are not
treated as direct RTO evidence.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from metrics import aggregate_seed_stats


TCP_INFO_TIMESERIES_FIELDS = [
    "timestamp_sec",
    "timestamp_epoch_ns",
    "scenario",
    "condition_id",
    "seed",
    "flow_id",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "tcp_state",
    "congestion_control",
    "rto_ms",
    "backoff",
    "retransmits",
    "total_retrans",
    "lost",
    "unacked",
    "sacked",
    "cwnd",
    "ssthresh",
    "rtt_ms",
    "rttvar_ms",
    "mss",
    "pacing_rate_mbps",
    "delivery_rate_mbps",
    "bytes_acked",
    "bytes_sent",
    "ca_state",
    "attack_active",
    "detector_attack",
    "suspicious_score",
    "sample_duration_ms",
    "observation_source",
]

RTO_EVENT_FIELDS = [
    "rto_event_id",
    "rto_event_time_sec",
    "timestamp_epoch_ns",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "flow_id",
    "rto_ms_before",
    "rto_ms_after",
    "backoff_before",
    "backoff_after",
    "retransmits_before",
    "retransmits_after",
    "total_retrans_before",
    "total_retrans_after",
    "cwnd_before",
    "cwnd_after",
    "attack_active",
    "nearest_pulse_index",
    "time_from_previous_pulse_start_ms",
    "time_from_previous_pulse_end_ms",
    "time_to_next_pulse_start_ms",
    "rto_to_pulse_phase_ms",
    "rto_to_pulse_phase_ratio",
    "is_direct_rto_observation",
    "is_inferred_rto",
    "inference_confidence",
    "inference_reason",
    "observation_source",
]

RTO_EPISODE_FIELDS = [
    "episode_id",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "flow_id",
    "episode_start_sec",
    "episode_end_sec",
    "duration_ms",
    "initial_rto_ms",
    "maximum_rto_ms",
    "maximum_backoff",
    "rto_event_count",
    "tcp_bytes_acked_during_episode",
    "mean_cwnd_during_episode",
    "mean_tcp_throughput_during_episode",
    "attack_pulse_overlap_count",
    "attack_overlap_duration_ms",
]

TCP_RETRANS_FIELDS = [
    "timestamp_sec",
    "timestamp_epoch_ns",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "capture",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "tcp_seq",
    "tcp_ack",
    "tcp_len",
    "event_type",
    "is_fast_retransmission",
    "is_spurious_retransmission",
    "is_duplicate_ack",
    "is_inferred_rto",
    "inference_confidence",
    "inference_reason",
    "observation_source",
]

PULSE_ALIGNMENT_FIELDS = [
    "pulse_index",
    "case_id",
    "scenario",
    "condition_id",
    "seed",
    "pulse_start_sec",
    "pulse_end_sec",
    "configured_rate_mbps",
    "actual_sent_bytes",
    "cwnd_before",
    "cwnd_after",
    "rto_before_ms",
    "rto_after_ms",
    "backoff_before",
    "backoff_after",
    "total_retrans_before",
    "total_retrans_after",
    "tcp_rate_before_mbps",
    "tcp_rate_after_mbps",
    "rto_event_count_after_pulse",
    "rto_event_within_causal_window",
]

CASE_RTO_COLUMNS = [
    "rto_event_count",
    "rto_episode_count",
    "first_rto_time_sec",
    "mean_rto_ms",
    "max_rto_ms",
    "max_backoff",
    "time_in_rto_episode_sec",
    "time_in_rto_episode_pct",
    "total_retrans",
    "fast_retransmission_count",
    "inferred_retransmission_count",
    "rto_retransmission_collision_count",
    "rto_retransmission_collision_rate",
    "pulse_to_rto_event_count",
    "pulse_to_rto_event_rate",
    "mean_cwnd",
    "minimum_cwnd",
    "mean_rtt_ms",
    "mean_rttvar_ms",
    "rto_observation_source",
    "rto_observation_quality",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--rto-causal-window-ms", type=float, default=500.0)
    parser.add_argument("--period-ms", type=float, default=None)
    parser.add_argument("--tcp-info-join-method", choices=["previous", "nearest"], default="previous")
    parser.add_argument("--disable-tshark", action="store_true")
    return parser.parse_args()


def safe_float(value: Any, default: float = math.nan) -> float:
    if value in ("", None):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    if value in ("", None):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def format_value(value: Any) -> Any:
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:.9g}"
    return value


def read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: format_value(row.get(field, "")) for field in fields})


def read_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def discover_case_dirs(results_dir: Path) -> list[Path]:
    cases_dir = results_dir / "cases"
    if not cases_dir.exists():
        return []
    return sorted(path for path in cases_dir.iterdir() if path.is_dir() and (path / "metadata_20260610.json").exists())


def flow_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("case_id", "")), str(row.get("flow_id", "")))


def overlaps_pulse(time_sec: float, pulse: dict[str, Any]) -> bool:
    return safe_float(pulse.get("pulse_start_sec")) <= time_sec <= safe_float(pulse.get("pulse_end_sec"))


def interval_overlap_ms(start_a: float, end_a: float, start_b: float, end_b: float) -> float:
    return max(0.0, min(end_a, end_b) - max(start_a, start_b)) * 1000.0


def nearest_pulse_metrics(time_sec: float, pulses: list[dict[str, Any]], period_ms: float | None = None) -> dict[str, Any]:
    if not pulses:
        return {
            "nearest_pulse_index": "",
            "time_from_previous_pulse_start_ms": math.nan,
            "time_from_previous_pulse_end_ms": math.nan,
            "time_to_next_pulse_start_ms": math.nan,
            "rto_to_pulse_phase_ms": math.nan,
            "rto_to_pulse_phase_ratio": math.nan,
        }
    previous = [p for p in pulses if safe_float(p.get("pulse_start_sec")) <= time_sec]
    nexts = [p for p in pulses if safe_float(p.get("pulse_start_sec")) > time_sec]
    prev = max(previous, key=lambda p: safe_float(p.get("pulse_start_sec"))) if previous else None
    next_pulse = min(nexts, key=lambda p: safe_float(p.get("pulse_start_sec"))) if nexts else None
    nearest = min(pulses, key=lambda p: abs(time_sec - safe_float(p.get("pulse_start_sec"))))
    nearest_start = safe_float(nearest.get("pulse_start_sec"))
    phase_ms = (time_sec - nearest_start) * 1000.0
    return {
        "nearest_pulse_index": nearest.get("pulse_index", ""),
        "time_from_previous_pulse_start_ms": (time_sec - safe_float(prev.get("pulse_start_sec"))) * 1000.0 if prev else math.nan,
        "time_from_previous_pulse_end_ms": (time_sec - safe_float(prev.get("pulse_end_sec"))) * 1000.0 if prev else math.nan,
        "time_to_next_pulse_start_ms": (safe_float(next_pulse.get("pulse_start_sec")) - time_sec) * 1000.0 if next_pulse else math.nan,
        "rto_to_pulse_phase_ms": phase_ms,
        "rto_to_pulse_phase_ratio": phase_ms / period_ms if period_ms and period_ms > 0 else math.nan,
    }


def detect_rto_events(rows: list[dict[str, Any]], pulses: list[dict[str, Any]] | None = None, period_ms: float | None = None) -> list[dict[str, Any]]:
    pulses = pulses or []
    events: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[flow_key(row)].append(row)
    event_index = 1
    for (_case_id, _flow_id), group in sorted(grouped.items()):
        group = sorted(group, key=lambda row: safe_float(row.get("timestamp_sec"), 0.0))
        previous: dict[str, Any] | None = None
        for current in group:
            if previous is None:
                previous = current
                continue
            prev_backoff = safe_int(previous.get("backoff"), 0)
            curr_backoff = safe_int(current.get("backoff"), 0)
            prev_retransmits = safe_int(previous.get("retransmits"), 0)
            curr_retransmits = safe_int(current.get("retransmits"), 0)
            if curr_backoff > prev_backoff or curr_retransmits > prev_retransmits:
                t = safe_float(current.get("timestamp_sec"), 0.0)
                event = {
                    "rto_event_id": f"rto_{event_index:06d}_20260610",
                    "rto_event_time_sec": t,
                    "timestamp_epoch_ns": current.get("timestamp_epoch_ns", ""),
                    "case_id": current.get("case_id", ""),
                    "scenario": current.get("scenario", ""),
                    "condition_id": current.get("condition_id", ""),
                    "seed": current.get("seed", ""),
                    "flow_id": current.get("flow_id", ""),
                    "rto_ms_before": safe_float(previous.get("rto_ms")),
                    "rto_ms_after": safe_float(current.get("rto_ms")),
                    "backoff_before": prev_backoff,
                    "backoff_after": curr_backoff,
                    "retransmits_before": prev_retransmits,
                    "retransmits_after": curr_retransmits,
                    "total_retrans_before": safe_int(previous.get("total_retrans"), 0),
                    "total_retrans_after": safe_int(current.get("total_retrans"), 0),
                    "cwnd_before": safe_float(previous.get("cwnd")),
                    "cwnd_after": safe_float(current.get("cwnd")),
                    "attack_active": current.get("attack_active", ""),
                    "is_direct_rto_observation": 1,
                    "is_inferred_rto": 0,
                    "inference_confidence": "",
                    "inference_reason": "",
                    "observation_source": current.get("observation_source", "ss_tcp_info") or "ss_tcp_info",
                }
                event.update(nearest_pulse_metrics(t, pulses, period_ms))
                events.append(event)
                event_index += 1
            previous = current
    return events


def extract_rto_episodes(rows: list[dict[str, Any]], events: list[dict[str, Any]], pulses: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    pulses = pulses or []
    events_by_flow: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        events_by_flow[flow_key(event)].append(event)
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[flow_key(row)].append(row)

    episodes: list[dict[str, Any]] = []
    episode_index = 1
    for (case_id, flow_id), group in sorted(grouped.items()):
        group = sorted(group, key=lambda row: safe_float(row.get("timestamp_sec"), 0.0))
        active: list[dict[str, Any]] = []
        in_episode = False
        for row in group:
            backoff = safe_int(row.get("backoff"), 0)
            if not in_episode and backoff > 0:
                active = [row]
                in_episode = True
            elif in_episode:
                active.append(row)
                if backoff == 0:
                    episodes.append(build_episode_row(episode_index, case_id, flow_id, active, events_by_flow[(case_id, flow_id)], pulses))
                    episode_index += 1
                    active = []
                    in_episode = False
        if in_episode and active:
            episodes.append(build_episode_row(episode_index, case_id, flow_id, active, events_by_flow[(case_id, flow_id)], pulses))
            episode_index += 1
    return episodes


def build_episode_row(
    episode_index: int,
    case_id: str,
    flow_id: str,
    samples: list[dict[str, Any]],
    flow_events: list[dict[str, Any]],
    pulses: list[dict[str, Any]],
) -> dict[str, Any]:
    start = safe_float(samples[0].get("timestamp_sec"), 0.0)
    end = safe_float(samples[-1].get("timestamp_sec"), start)
    if end < start:
        end = start
    rto_values = [safe_float(row.get("rto_ms")) for row in samples if not math.isnan(safe_float(row.get("rto_ms")))]
    backoff_values = [safe_int(row.get("backoff"), 0) for row in samples]
    cwnd_values = [safe_float(row.get("cwnd")) for row in samples if not math.isnan(safe_float(row.get("cwnd")))]
    bytes_start = safe_float(samples[0].get("bytes_acked"), math.nan)
    bytes_end = safe_float(samples[-1].get("bytes_acked"), math.nan)
    overlapping_pulses = [
        pulse
        for pulse in pulses
        if interval_overlap_ms(start, end, safe_float(pulse.get("pulse_start_sec")), safe_float(pulse.get("pulse_end_sec"))) > 0
    ]
    overlap_ms = sum(
        interval_overlap_ms(start, end, safe_float(pulse.get("pulse_start_sec")), safe_float(pulse.get("pulse_end_sec")))
        for pulse in overlapping_pulses
    )
    event_count = sum(1 for event in flow_events if start <= safe_float(event.get("rto_event_time_sec")) <= end)
    duration_sec = max(end - start, 0.0)
    bytes_acked = bytes_end - bytes_start if not math.isnan(bytes_start) and not math.isnan(bytes_end) else math.nan
    return {
        "episode_id": f"episode_{episode_index:06d}_20260610",
        "case_id": case_id,
        "scenario": samples[0].get("scenario", ""),
        "condition_id": samples[0].get("condition_id", ""),
        "seed": samples[0].get("seed", ""),
        "flow_id": flow_id,
        "episode_start_sec": start,
        "episode_end_sec": end,
        "duration_ms": duration_sec * 1000.0,
        "initial_rto_ms": rto_values[0] if rto_values else math.nan,
        "maximum_rto_ms": max(rto_values) if rto_values else math.nan,
        "maximum_backoff": max(backoff_values) if backoff_values else 0,
        "rto_event_count": event_count,
        "tcp_bytes_acked_during_episode": bytes_acked,
        "mean_cwnd_during_episode": sum(cwnd_values) / len(cwnd_values) if cwnd_values else math.nan,
        "mean_tcp_throughput_during_episode": 8.0 * bytes_acked / duration_sec / 1_000_000.0
        if duration_sec > 0 and not math.isnan(bytes_acked)
        else math.nan,
        "attack_pulse_overlap_count": len(overlapping_pulses),
        "attack_overlap_duration_ms": overlap_ms,
    }


def enrich_tcp_info_rows(
    rows: list[dict[str, Any]],
    metadata: dict[str, Any],
    bandwidth_rows: list[dict[str, Any]],
    join_method: str,
) -> list[dict[str, Any]]:
    bw = sorted(
        [
            row
            for row in bandwidth_rows
            if str(row.get("condition_id")) == str(metadata.get("condition_id"))
            and str(row.get("scenario")) == str(metadata.get("scenario"))
            and str(row.get("seed")) == str(metadata.get("seed"))
        ],
        key=lambda row: safe_float(row.get("timestamp_sec"), 0.0),
    )
    for row in rows:
        row["case_id"] = metadata.get("case_id", "")
        t = safe_float(row.get("timestamp_sec"), 0.0)
        match = find_timeseries_match(t, bw, join_method)
        row["attack_active"] = match.get("attack_active", "") if match else ""
        row["detector_attack"] = match.get("detector_attack", "") if match else ""
        row["suspicious_score"] = match.get("suspicious_score", "") if match else ""
    return rows


def find_timeseries_match(time_sec: float, rows: list[dict[str, Any]], method: str) -> dict[str, Any] | None:
    if not rows:
        return None
    if method == "nearest":
        return min(rows, key=lambda row: abs(time_sec - safe_float(row.get("timestamp_sec"), 0.0)))
    previous = rows[0]
    for row in rows:
        if safe_float(row.get("timestamp_sec"), 0.0) <= time_sec:
            previous = row
        else:
            break
    return previous


def read_case_tcp_info(case_dir: Path, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    case_id = metadata.get("case_id", case_dir.name)
    path = case_dir / "raw" / "tcp_info" / str(case_id) / "tcp_info_timeseries_20260610.csv"
    return read_csv(path)


def read_case_pulses(case_dir: Path) -> list[dict[str, Any]]:
    path = case_dir / "raw" / "pulses" / "attack_pulses_20260610.csv"
    return read_csv(path)


def parse_tshark_retransmissions(case_dir: Path, metadata: dict[str, Any], capture: str) -> list[dict[str, Any]]:
    pcap_key = "capture_ingress_pcap" if capture == "ingress" else "capture_egress_pcap"
    pcap = metadata.get(pcap_key)
    if not pcap or not Path(str(pcap)).exists() or shutil.which("tshark") is None:
        return []
    command = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission || tcp.analysis.duplicate_ack || tcp.analysis.out_of_order",
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=,",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.ack",
        "-e",
        "tcp.len",
        "-e",
        "tcp.analysis.retransmission",
        "-e",
        "tcp.analysis.fast_retransmission",
        "-e",
        "tcp.analysis.spurious_retransmission",
        "-e",
        "tcp.analysis.duplicate_ack",
    ]
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode not in (0, 1):
        return []
    origin = safe_float(metadata.get("experiment_start_wall"), safe_float(metadata.get("case_start_epoch_ns"), 0.0) / 1_000_000_000.0)
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = line.split(",")
        if len(parts) < 12:
            continue
        epoch = safe_float(parts[0])
        fast = bool(parts[9])
        spurious = bool(parts[10])
        dupack = bool(parts[11])
        event_type = "duplicate_ack" if dupack else "spurious_retransmission" if spurious else "fast_retransmission" if fast else "retransmission"
        rows.append(
            {
                "timestamp_sec": epoch - origin if origin else math.nan,
                "timestamp_epoch_ns": int(epoch * 1_000_000_000) if not math.isnan(epoch) else "",
                "case_id": metadata.get("case_id", ""),
                "scenario": metadata.get("scenario", ""),
                "condition_id": metadata.get("condition_id", ""),
                "seed": metadata.get("seed", ""),
                "capture": capture,
                "source_ip": parts[1],
                "source_port": parts[2],
                "destination_ip": parts[3],
                "destination_port": parts[4],
                "tcp_seq": parts[5],
                "tcp_ack": parts[6],
                "tcp_len": parts[7],
                "event_type": event_type,
                "is_fast_retransmission": int(fast),
                "is_spurious_retransmission": int(spurious),
                "is_duplicate_ack": int(dupack),
                "is_inferred_rto": 0,
                "inference_confidence": "",
                "inference_reason": "pcap/tshark retransmission label; not direct RTO evidence",
                "observation_source": "pcap_inference",
            }
        )
    return rows


def read_case_retransmissions(case_dir: Path, metadata: dict[str, Any], disable_tshark: bool) -> list[dict[str, Any]]:
    synthetic = case_dir / "raw" / "tcp_retransmission_events_20260610.csv"
    if synthetic.exists():
        return read_csv(synthetic)
    if disable_tshark:
        return []
    return parse_tshark_retransmissions(case_dir, metadata, "ingress") + parse_tshark_retransmissions(case_dir, metadata, "egress")


def build_pulse_alignment(
    pulses: list[dict[str, Any]],
    tcp_rows: list[dict[str, Any]],
    rto_events: list[dict[str, Any]],
    bandwidth_rows: list[dict[str, Any]],
    causal_window_ms: float,
) -> list[dict[str, Any]]:
    if not pulses:
        return []
    rows: list[dict[str, Any]] = []
    sorted_tcp = sorted(tcp_rows, key=lambda row: safe_float(row.get("timestamp_sec"), 0.0))
    for pulse in pulses:
        start = safe_float(pulse.get("pulse_start_sec"), 0.0)
        end = safe_float(pulse.get("pulse_end_sec"), start)
        before = find_timeseries_match(start, sorted_tcp, "previous") or {}
        after = next((row for row in sorted_tcp if safe_float(row.get("timestamp_sec"), 0.0) >= end), sorted_tcp[-1] if sorted_tcp else {})
        case_events = [
            event
            for event in rto_events
            if end <= safe_float(event.get("rto_event_time_sec"), math.inf) <= end + causal_window_ms / 1000.0
        ]
        bw_before = find_timeseries_match(max(start - 0.1, 0.0), bandwidth_rows, "previous") or {}
        bw_after = find_timeseries_match(end + 0.1, bandwidth_rows, "previous") or {}
        rows.append(
            {
                "pulse_index": pulse.get("pulse_index", ""),
                "case_id": pulse.get("case_id", ""),
                "scenario": pulse.get("scenario", ""),
                "condition_id": pulse.get("condition_id", ""),
                "seed": pulse.get("seed", ""),
                "pulse_start_sec": start,
                "pulse_end_sec": end,
                "configured_rate_mbps": pulse.get("configured_rate_mbps", ""),
                "actual_sent_bytes": pulse.get("actual_sent_bytes", ""),
                "cwnd_before": before.get("cwnd", ""),
                "cwnd_after": after.get("cwnd", ""),
                "rto_before_ms": before.get("rto_ms", ""),
                "rto_after_ms": after.get("rto_ms", ""),
                "backoff_before": before.get("backoff", ""),
                "backoff_after": after.get("backoff", ""),
                "total_retrans_before": before.get("total_retrans", ""),
                "total_retrans_after": after.get("total_retrans", ""),
                "tcp_rate_before_mbps": bw_before.get("tcp_normal_mbps", ""),
                "tcp_rate_after_mbps": bw_after.get("tcp_normal_mbps", ""),
                "rto_event_count_after_pulse": len(case_events),
                "rto_event_within_causal_window": int(bool(case_events)),
            }
        )
    return rows


def case_rto_summary(
    metadata: dict[str, Any],
    tcp_rows: list[dict[str, Any]],
    events: list[dict[str, Any]],
    episodes: list[dict[str, Any]],
    retrans_rows: list[dict[str, Any]],
    pulses: list[dict[str, Any]],
    causal_window_ms: float,
) -> dict[str, Any]:
    duration = safe_float(metadata.get("duration_sec"), math.nan)
    rto_values = [safe_float(row.get("rto_ms")) for row in tcp_rows if not math.isnan(safe_float(row.get("rto_ms")))]
    backoff_values = [safe_int(row.get("backoff"), 0) for row in tcp_rows]
    cwnd_values = [safe_float(row.get("cwnd")) for row in tcp_rows if not math.isnan(safe_float(row.get("cwnd")))]
    rtt_values = [safe_float(row.get("rtt_ms")) for row in tcp_rows if not math.isnan(safe_float(row.get("rtt_ms")))]
    rttvar_values = [safe_float(row.get("rttvar_ms")) for row in tcp_rows if not math.isnan(safe_float(row.get("rttvar_ms")))]
    time_in_episode_sec = sum(safe_float(row.get("duration_ms"), 0.0) for row in episodes) / 1000.0
    direct_count = sum(1 for event in events if safe_int(event.get("is_direct_rto_observation"), 0) == 1)
    inferred_retrans = [row for row in retrans_rows if safe_int(row.get("is_duplicate_ack"), 0) == 0]
    collision_count = sum(
        1
        for event in events
        if any(overlaps_pulse(safe_float(event.get("rto_event_time_sec"), math.inf), pulse) for pulse in pulses)
    )
    pulse_to_rto = 0
    for pulse in pulses:
        end = safe_float(pulse.get("pulse_end_sec"), math.inf)
        if any(end <= safe_float(event.get("rto_event_time_sec"), math.inf) <= end + causal_window_ms / 1000.0 for event in events):
            pulse_to_rto += 1
    if tcp_rows and retrans_rows:
        quality = "partially_direct"
    elif tcp_rows:
        quality = "direct"
    elif retrans_rows:
        quality = "inferred_only"
    else:
        quality = "unavailable"
    return {
        "rto_event_count": len(events),
        "rto_episode_count": len(episodes),
        "first_rto_time_sec": min((safe_float(event.get("rto_event_time_sec")) for event in events), default=math.nan),
        "mean_rto_ms": sum(rto_values) / len(rto_values) if rto_values else math.nan,
        "max_rto_ms": max(rto_values) if rto_values else math.nan,
        "max_backoff": max(backoff_values) if backoff_values else math.nan,
        "time_in_rto_episode_sec": time_in_episode_sec,
        "time_in_rto_episode_pct": 100.0 * time_in_episode_sec / duration if duration and duration > 0 else math.nan,
        "total_retrans": max((safe_int(row.get("total_retrans"), 0) for row in tcp_rows), default=0),
        "fast_retransmission_count": sum(1 for row in retrans_rows if safe_int(row.get("is_fast_retransmission"), 0) == 1),
        "inferred_retransmission_count": len(inferred_retrans),
        "rto_retransmission_collision_count": collision_count,
        "rto_retransmission_collision_rate": collision_count / len(events) if events else math.nan,
        "pulse_to_rto_event_count": pulse_to_rto,
        "pulse_to_rto_event_rate": pulse_to_rto / len(pulses) if pulses else math.nan,
        "mean_cwnd": sum(cwnd_values) / len(cwnd_values) if cwnd_values else math.nan,
        "minimum_cwnd": min(cwnd_values) if cwnd_values else math.nan,
        "mean_rtt_ms": sum(rtt_values) / len(rtt_values) if rtt_values else math.nan,
        "mean_rttvar_ms": sum(rttvar_values) / len(rttvar_values) if rttvar_values else math.nan,
        "rto_observation_source": "ss_tcp_info" if tcp_rows else ("pcap_inference" if retrans_rows else ""),
        "rto_observation_quality": quality,
    }


def update_case_metrics(results_dir: Path, summary_by_case: dict[str, dict[str, Any]]) -> None:
    path = results_dir / "csv" / "case_metrics_20260610.csv"
    rows = read_csv(path)
    if not rows:
        return
    fields = list(rows[0].keys())
    for column in CASE_RTO_COLUMNS:
        if column not in fields:
            fields.append(column)
    for row in rows:
        summary = summary_by_case.get(str(row.get("case_id", "")), {})
        for column in CASE_RTO_COLUMNS:
            row[column] = summary.get(column, "")
    write_csv(path, fields, rows)


def update_aggregated_metrics(results_dir: Path) -> None:
    case_rows = read_csv(results_dir / "csv" / "case_metrics_20260610.csv")
    if not case_rows:
        return
    metric_fields = [
        "rto_event_count",
        "time_in_rto_episode_pct",
        "max_backoff",
        "total_retrans",
        "fast_retransmission_count",
        "rto_retransmission_collision_rate",
        "mean_cwnd",
        "minimum_cwnd",
        "mean_rtt_ms",
    ]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        grouped[(str(row.get("condition_id", "")), str(row.get("scenario", "")))].append(row)
    rows: list[dict[str, Any]] = []
    for (condition_id, scenario), group in sorted(grouped.items()):
        out: dict[str, Any] = {"condition_id": condition_id, "scenario": scenario, "n_seeds": len({row.get("seed") for row in group})}
        for metric in metric_fields:
            stats = aggregate_seed_stats(safe_float(row.get(metric), math.nan) for row in group)
            out[f"{metric}_mean"] = stats["mean"]
            out[f"{metric}_std"] = stats["std"]
            out[f"{metric}_ci95"] = stats["ci95"]
        rows.append(out)
    fields = list(rows[0].keys()) if rows else ["condition_id", "scenario", "n_seeds"]
    write_csv(results_dir / "csv" / "rto_aggregated_metrics_20260610.csv", fields, rows)


def main() -> int:
    args = parse_args()
    results_dir: Path = args.results_dir
    csv_dir = results_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    bandwidth_rows = read_csv(csv_dir / "bandwidth_timeseries_20260610.csv")

    all_tcp_rows: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []
    all_episodes: list[dict[str, Any]] = []
    all_retrans: list[dict[str, Any]] = []
    all_alignment: list[dict[str, Any]] = []
    summary_by_case: dict[str, dict[str, Any]] = {}

    for case_dir in discover_case_dirs(results_dir):
        metadata = read_json(case_dir / "metadata_20260610.json")
        case_id = str(metadata.get("case_id", case_dir.name))
        period_ms = args.period_ms or safe_float(metadata.get("period_ms"), math.nan)
        raw_tcp = read_case_tcp_info(case_dir, metadata)
        tcp_rows = enrich_tcp_info_rows(raw_tcp, metadata, bandwidth_rows, args.tcp_info_join_method)
        pulses = read_case_pulses(case_dir)
        retrans_rows = read_case_retransmissions(case_dir, metadata, args.disable_tshark)
        events = detect_rto_events(tcp_rows, pulses, period_ms)
        episodes = extract_rto_episodes(tcp_rows, events, pulses)
        case_bw = [
            row
            for row in bandwidth_rows
            if str(row.get("condition_id")) == str(metadata.get("condition_id"))
            and str(row.get("scenario")) == str(metadata.get("scenario"))
            and str(row.get("seed")) == str(metadata.get("seed"))
        ]
        alignment = build_pulse_alignment(pulses, tcp_rows, events, case_bw, args.rto_causal_window_ms)
        summary_by_case[case_id] = case_rto_summary(metadata, tcp_rows, events, episodes, retrans_rows, pulses, args.rto_causal_window_ms)
        all_tcp_rows.extend(tcp_rows)
        all_events.extend(events)
        all_episodes.extend(episodes)
        all_retrans.extend(retrans_rows)
        all_alignment.extend(alignment)

    write_csv(csv_dir / "tcp_info_timeseries_20260610.csv", TCP_INFO_TIMESERIES_FIELDS, all_tcp_rows)
    write_csv(csv_dir / "rto_events_20260610.csv", RTO_EVENT_FIELDS, all_events)
    write_csv(csv_dir / "rto_episodes_20260610.csv", RTO_EPISODE_FIELDS, all_episodes)
    write_csv(csv_dir / "tcp_retransmission_events_20260610.csv", TCP_RETRANS_FIELDS, all_retrans)
    write_csv(csv_dir / "pulse_tcp_alignment_20260610.csv", PULSE_ALIGNMENT_FIELDS, all_alignment)
    update_case_metrics(results_dir, summary_by_case)
    update_aggregated_metrics(results_dir)
    print(f"Wrote RTO CSV outputs to {csv_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
