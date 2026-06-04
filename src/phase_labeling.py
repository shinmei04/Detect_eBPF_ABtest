"""Phase-aware truth labels for composite LDDoS and F-LDDoS evaluation."""

from __future__ import annotations

import math
import random
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


PHASE_OVERLAP_COLUMNS = {
    "baseline": "overlap_benign_sec",
    "feint": "overlap_feint_sec",
    "attack_burst": "overlap_attack_burst_sec",
    "quiet": "overlap_quiet_sec",
}
PHASE_LOG_COLUMNS = [
    "phase",
    "period_index",
    "flow_id",
    "phase_start_sec",
    "phase_end_sec",
    "planned_packets",
    "sent_packets",
    "src_port",
    "rate_mbps",
]


def canonical_phase(value: object) -> str:
    """Return the canonical phase name used by evaluation outputs."""
    phase = str(value)
    if phase in {"baseline", "baseline_normal", "baseline_microburst", "benign"}:
        return "baseline"
    if phase in {"attack", "attack_burst", "burst"}:
        return "attack_burst"
    if phase == "feint":
        return "feint"
    if phase == "quiet":
        return "quiet"
    return phase


def phase_offsets_ms(
    mode: str,
    num_flows: int,
    spread_ms: float,
    period_index: int,
    seed: int,
) -> list[float]:
    """Return deterministic or seeded per-flow burst offsets."""
    if num_flows <= 1 or mode in {"single_flow_ldos", "multi_flow_sync_lddos"}:
        return [0.0] * num_flows
    if mode == "multi_flow_staggered_lddos":
        return [flow * spread_ms / max(1, num_flows - 1) for flow in range(num_flows)]
    rng = random.Random(seed * 1_000_003 + period_index * 10_007)
    return [rng.uniform(0.0, spread_ms) for _ in range(num_flows)]


def build_phase_intervals(
    *,
    duration_sec: float,
    attack_start_sec: float,
    scenario: str,
    attack_mode: str,
    num_flows: int,
    period_ms: int,
    burst_ms: int,
    phase_spread_ms: float,
    attack_interval_placement: str,
    seed: int,
    per_flow_rate_mbps: float,
    feint_rate_ratio: float,
    base_src_port: int = 40000,
) -> pd.DataFrame:
    """Build planned per-flow phase intervals on the experiment-relative clock."""
    period_sec = period_ms / 1000.0
    burst_sec = burst_ms / 1000.0
    spread_ms = min(float(phase_spread_ms), float(burst_ms))
    rows: list[dict[str, Any]] = []

    def add(
        phase: str,
        period_index: int,
        flow_index: int,
        start_sec: float,
        end_sec: float,
        rate_mbps: float,
    ) -> None:
        start = max(0.0, float(start_sec))
        end = min(float(duration_sec), float(end_sec))
        if end <= start:
            return
        rows.append(
            {
                "phase": canonical_phase(phase),
                "period_index": int(period_index),
                "flow_id": f"flow_{flow_index}",
                "phase_start_sec": start,
                "phase_end_sec": end,
                "planned_packets": 0,
                "sent_packets": 0,
                "src_port": int(base_src_port + flow_index),
                "rate_mbps": float(rate_mbps),
            }
        )

    baseline_end = duration_sec if scenario == "random_microburst_only" else attack_start_sec
    baseline_rate = (
        per_flow_rate_mbps
        if scenario in {"random_microburst_only", "stat_matched_composite_lddos"}
        else max(0.5, min(per_flow_rate_mbps * 0.10, 5.0))
    )
    period_index = 0
    period_start = 0.0
    while period_start < baseline_end:
        period_end = min(period_start + period_sec, baseline_end)
        for flow in range(num_flows):
            add("baseline", period_index, flow, period_start, period_end, baseline_rate)
        period_index += 1
        period_start += period_sec

    if scenario == "random_microburst_only":
        return pd.DataFrame(rows, columns=PHASE_LOG_COLUMNS)

    period_index = 0
    period_start = attack_start_sec
    while period_start < duration_sec:
        period_end = min(period_start + period_sec, duration_sec)
        offsets = phase_offsets_ms(attack_mode, num_flows, spread_ms, period_index, seed)
        active_by_flow: dict[int, list[tuple[float, float]]] = {flow: [] for flow in range(num_flows)}
        if attack_mode == "f_lddos":
            attack_base = period_sec - burst_sec if attack_interval_placement == "end" else 0.0
            earliest_attack = max(0.0, attack_base - max(offsets, default=0.0) / 1000.0)
            feint_end = min(period_end, period_start + earliest_attack)
            for flow in range(num_flows):
                add(
                    "feint",
                    period_index,
                    flow,
                    period_start,
                    feint_end,
                    per_flow_rate_mbps * feint_rate_ratio,
                )
                if feint_end > period_start:
                    active_by_flow[flow].append((period_start, feint_end))
        else:
            attack_base = 0.0

        for flow in range(num_flows):
            offset_sec = offsets[flow] / 1000.0
            if attack_mode == "f_lddos" and attack_interval_placement == "end":
                burst_start = period_start + max(0.0, attack_base - offset_sec)
            else:
                burst_start = period_start + attack_base + offset_sec
            burst_end = min(burst_start + burst_sec, period_end)
            add(
                "attack_burst",
                period_index,
                flow,
                burst_start,
                burst_end,
                per_flow_rate_mbps,
            )
            if burst_end > burst_start:
                active_by_flow[flow].append((burst_start, burst_end))

        for flow in range(num_flows):
            for quiet_start, quiet_end in complement_intervals(
                active_by_flow[flow], period_start, period_end
            ):
                add("quiet", period_index, flow, quiet_start, quiet_end, 0.0)

        period_index += 1
        period_start += period_sec

    return pd.DataFrame(rows, columns=PHASE_LOG_COLUMNS)


def complement_intervals(
    intervals: list[tuple[float, float]],
    range_start: float,
    range_end: float,
) -> list[tuple[float, float]]:
    """Return gaps not covered by intervals within one bounded range."""
    merged = merge_intervals(intervals)
    output: list[tuple[float, float]] = []
    cursor = range_start
    for start, end in merged:
        start = max(range_start, start)
        end = min(range_end, end)
        if start > cursor:
            output.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < range_end:
        output.append((cursor, range_end))
    return output


def read_phase_intervals(source: Path | pd.DataFrame | None) -> pd.DataFrame:
    """Read and normalize a sender phase log, returning an empty frame on fallback."""
    if source is None:
        return pd.DataFrame(columns=PHASE_LOG_COLUMNS)
    if isinstance(source, Path):
        if not source.exists():
            return pd.DataFrame(columns=PHASE_LOG_COLUMNS)
        frame = pd.read_csv(source)
    else:
        frame = source.copy()
    if frame.empty or "phase" not in frame:
        return pd.DataFrame(columns=PHASE_LOG_COLUMNS)
    if "phase_start_sec" not in frame and "first_send_sec" in frame:
        frame["phase_start_sec"] = frame["first_send_sec"]
    if "phase_end_sec" not in frame and "last_send_sec" in frame:
        frame["phase_end_sec"] = frame["last_send_sec"]
    if not {"phase_start_sec", "phase_end_sec"}.issubset(frame.columns):
        return pd.DataFrame(columns=PHASE_LOG_COLUMNS)
    frame["phase"] = frame["phase"].map(canonical_phase)
    frame["phase_start_sec"] = pd.to_numeric(frame["phase_start_sec"], errors="coerce")
    frame["phase_end_sec"] = pd.to_numeric(frame["phase_end_sec"], errors="coerce")
    frame = frame.dropna(subset=["phase_start_sec", "phase_end_sec"])
    frame = frame[frame["phase_end_sec"] > frame["phase_start_sec"]].copy()
    for column in PHASE_LOG_COLUMNS:
        if column not in frame:
            frame[column] = 0 if column in {"planned_packets", "sent_packets"} else ""
    return frame.reset_index(drop=True)


def add_phase_labels(
    windows: pd.DataFrame,
    *,
    attack_start_sec: float,
    phase_intervals: Path | pd.DataFrame | None = None,
    min_overlap_sec: float,
    is_attack_scenario: bool = True,
    flow_id: str | None = None,
    src_port: int | None = None,
) -> pd.DataFrame:
    """Add legacy period labels and phase-aware truth columns to detector windows."""
    result = windows.copy()
    if "window_end_sec" not in result:
        raise ValueError("windows must contain window_end_sec")
    result["target_period"] = (
        is_attack_scenario & (result["window_start_sec"].astype(float) >= attack_start_sec)
    ).astype(int)
    result["target_pre_attack"] = (
        result["window_end_sec"].astype(float) <= attack_start_sec
    ).astype(int)
    intervals = select_flow_intervals(read_phase_intervals(phase_intervals), flow_id, src_port)
    result["phase_labels_available"] = not intervals.empty
    if intervals.empty:
        for overlap_column in PHASE_OVERLAP_COLUMNS.values():
            result[overlap_column] = 0.0
        result["target_burst"] = 0
        result["target_feint"] = 0
        result["target_quiet"] = 0
        result["truth_phase"] = np.where(
            result["target_pre_attack"].eq(1),
            "baseline",
            np.where(result["target_period"].eq(1), "target_period", "unknown"),
        )
        result["first_attack_burst_start_sec"] = math.nan
        return result

    for phase, overlap_column in PHASE_OVERLAP_COLUMNS.items():
        phase_ranges = merge_intervals(
            [
                (float(row.phase_start_sec), float(row.phase_end_sec))
                for row in intervals[intervals["phase"].eq(phase)].itertuples()
            ]
        )
        result[overlap_column] = [
            interval_overlap_sum(float(row.window_start_sec), float(row.window_end_sec), phase_ranges)
            for row in result.itertuples()
        ]

    tolerance = 1e-9
    result["target_burst"] = (
        result["overlap_attack_burst_sec"].astype(float) + tolerance >= min_overlap_sec
    ).astype(int)
    result["target_feint"] = (
        (result["overlap_feint_sec"].astype(float) > tolerance) & result["target_burst"].eq(0)
    ).astype(int)
    result["target_quiet"] = (
        (result["overlap_quiet_sec"].astype(float) > tolerance)
        & result["target_burst"].eq(0)
        & result["target_feint"].eq(0)
    ).astype(int)
    result["truth_phase"] = np.select(
        [
            result["target_burst"].eq(1),
            result["target_feint"].eq(1),
            result["target_quiet"].eq(1),
            result["overlap_benign_sec"].astype(float) > tolerance,
            result["target_pre_attack"].eq(1),
        ],
        ["attack_burst", "feint", "quiet", "baseline", "baseline"],
        default="unknown",
    )
    attack_intervals = intervals[intervals["phase"].eq("attack_burst")]
    result["first_attack_burst_start_sec"] = (
        float(attack_intervals["phase_start_sec"].min()) if not attack_intervals.empty else math.nan
    )
    return result


def select_flow_intervals(
    intervals: pd.DataFrame,
    flow_id: str | None,
    src_port: int | None,
) -> pd.DataFrame:
    """Select one sender flow for per-flow evaluation, or all rows for aggregate."""
    if intervals.empty or flow_id is None and src_port is None:
        return intervals
    if src_port is not None and "src_port" in intervals:
        ports = pd.to_numeric(intervals["src_port"], errors="coerce")
        selected = intervals[ports.eq(int(src_port))]
        if not selected.empty:
            return selected
    if flow_id is not None and "flow_id" in intervals:
        return intervals[intervals["flow_id"].astype(str).eq(str(flow_id))]
    return intervals.iloc[0:0]


def merge_intervals(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Merge overlapping intervals so aggregate overlap never exceeds window length."""
    output: list[tuple[float, float]] = []
    for start, end in sorted(intervals):
        if end <= start:
            continue
        if not output or start > output[-1][1]:
            output.append((start, end))
        else:
            output[-1] = (output[-1][0], max(output[-1][1], end))
    return output


def interval_overlap_sum(
    window_start: float,
    window_end: float,
    intervals: list[tuple[float, float]],
) -> float:
    """Return overlap seconds between a half-open window and merged intervals."""
    return float(
        sum(max(0.0, min(window_end, end) - max(window_start, start)) for start, end in intervals)
    )
