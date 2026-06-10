#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Generate RTO/backoff/congestion-control figures from the LDoS bandwidth
experiment CSV outputs.
"""

from __future__ import annotations

import argparse
import base64
import csv
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


ONE_PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--bottleneck-mbps", type=float, default=15.0)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def to_float(value: Any, default: float = math.nan) -> float:
    if value in ("", None):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def slug(value: Any) -> str:
    text = str(value)
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in text)


def group_rows(rows: list[dict[str, str]], fields: list[str]) -> dict[tuple[str, ...], list[dict[str, str]]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(str(row.get(field, "")) for field in fields)].append(row)
    return grouped


def get_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def write_placeholder(path: Path, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".png":
        path.write_bytes(ONE_PIXEL_PNG)
    elif path.suffix.lower() == ".pdf":
        body = f"Placeholder figure: {title}; matplotlib unavailable."
        pdf = f"%PDF-1.1\n1 0 obj<<>>endobj\n2 0 obj<< /Length {len(body)+60} >>stream\nBT /F1 12 Tf 72 720 Td ({body}) Tj ET\nendstream endobj\ntrailer<<>>\n%%EOF\n"
        path.write_text(pdf)


def save_fig(plt: Any, base: Path, title: str) -> None:
    if plt is None:
        write_placeholder(base.with_suffix(".png"), title)
        write_placeholder(base.with_suffix(".pdf"), title)
        return
    base.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(base.with_suffix(".png"), dpi=180)
    plt.savefig(base.with_suffix(".pdf"))
    plt.close()


def mean_ci(values: list[float]) -> tuple[float, float]:
    values = [v for v in values if not math.isnan(v)]
    if not values:
        return math.nan, math.nan
    mean = sum(values) / len(values)
    if len(values) < 2:
        return mean, math.nan
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return mean, 1.96 * math.sqrt(variance) / math.sqrt(len(values))


def plot_rto_timeline(
    bandwidth_rows: list[dict[str, str]],
    tcp_rows: list[dict[str, str]],
    rto_events: list[dict[str, str]],
    retrans_rows: list[dict[str, str]],
    pulses: list[dict[str, str]],
    output_dir: Path,
    plt: Any,
    bottleneck_mbps: float,
) -> None:
    groups = group_rows(bandwidth_rows, ["condition_id", "scenario", "seed"])
    for key, bw_group in groups.items():
        condition, scenario, seed = key
        base = output_dir / f"05_rto_timeline_{slug(condition)}_{slug(scenario)}_seed{slug(seed)}_20260610"
        title = f"RTO timeline {condition} {scenario} seed {seed}"
        if plt is None:
            save_fig(None, base, title)
            continue
        bw_group = sorted(bw_group, key=lambda row: to_float(row.get("timestamp_sec"), 0.0))
        case_tcp = sorted(
            [
                row
                for row in tcp_rows
                if row.get("condition_id") == condition and row.get("scenario") == scenario and row.get("seed") == seed
            ],
            key=lambda row: to_float(row.get("timestamp_sec"), 0.0),
        )
        case_events = [
            row
            for row in rto_events
            if row.get("condition_id") == condition and row.get("scenario") == scenario and row.get("seed") == seed
        ]
        case_retrans = [
            row
            for row in retrans_rows
            if row.get("condition_id") == condition and row.get("scenario") == scenario and row.get("seed") == seed
        ]
        case_pulses = [
            row
            for row in pulses
            if row.get("condition_id") == condition and row.get("scenario") == scenario and row.get("seed") == seed
        ]
        fig, axes = plt.subplots(3, 1, figsize=(11, 8), sharex=True)
        ts = [to_float(row["timestamp_sec"]) for row in bw_group]
        tcp_mbps = [to_float(row.get("tcp_normal_mbps"), 0.0) for row in bw_group]
        attack_mbps = [to_float(row.get("attack_passed_mbps"), 0.0) for row in bw_group]
        axes[0].plot(ts, tcp_mbps, label="TCP throughput")
        axes[0].plot(ts, attack_mbps, label="Attack passed")
        axes[0].axhline(bottleneck_mbps, color="black", linestyle="--", linewidth=1, label="C")
        for pulse in case_pulses:
            axes[0].axvspan(to_float(pulse.get("pulse_start_sec")), to_float(pulse.get("pulse_end_sec")), color="red", alpha=0.12)
        axes[0].set_ylabel("Mbps")
        axes[0].set_title(title)
        axes[0].legend(fontsize=8, loc="upper right")

        tcp_ts = [to_float(row.get("timestamp_sec")) for row in case_tcp]
        rto = [to_float(row.get("rto_ms")) for row in case_tcp]
        backoff = [to_float(row.get("backoff"), 0.0) for row in case_tcp]
        axes[1].plot(tcp_ts, rto, label="rto_ms")
        ax2 = axes[1].twinx()
        ax2.step(tcp_ts, backoff, color="orange", where="post", label="backoff")
        event_ts = [to_float(row.get("rto_event_time_sec")) for row in case_events]
        if event_ts:
            axes[1].scatter(event_ts, [max([v for v in rto if not math.isnan(v)] or [1])] * len(event_ts), color="red", s=20, label="RTO event")
        for row in case_retrans:
            t = to_float(row.get("timestamp_sec"))
            marker = "^" if to_float(row.get("is_fast_retransmission"), 0.0) >= 1 else "x"
            axes[1].scatter([t], [0], marker=marker, color="purple", s=16)
        axes[1].set_ylabel("RTO [ms]")
        ax2.set_ylabel("backoff")
        axes[1].legend(fontsize=8, loc="upper left")

        cwnd = [to_float(row.get("cwnd")) for row in case_tcp]
        ssthresh = [to_float(row.get("ssthresh")) for row in case_tcp]
        rtt = [to_float(row.get("rtt_ms")) for row in case_tcp]
        axes[2].plot(tcp_ts, cwnd, label="cwnd")
        axes[2].plot(tcp_ts, ssthresh, label="ssthresh")
        ax3 = axes[2].twinx()
        ax3.plot(tcp_ts, rtt, color="green", label="RTT ms", alpha=0.8)
        detected = [to_float(row.get("timestamp_sec")) for row in bw_group if to_float(row.get("detector_attack"), 0.0) >= 1]
        for t in detected:
            axes[2].axvline(t, color="red", alpha=0.12, linewidth=0.7)
        axes[2].set_ylabel("packets")
        ax3.set_ylabel("RTT [ms]")
        axes[2].set_xlabel("Time [sec]")
        axes[2].legend(fontsize=8, loc="upper left")
        save_fig(plt, base, title)


def plot_rto_count_by_scenario(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    base = output_dir / "06_rto_event_count_by_scenario_20260610"
    title = "RTO event count by scenario"
    if plt is None:
        save_fig(None, base, title)
        return
    rows = []
    labels = []
    y = []
    yerr = []
    for key, group in group_rows(case_rows, ["condition_id", "scenario"]).items():
        values = [to_float(row.get("rto_event_count")) for row in group]
        mean, ci = mean_ci(values)
        labels.append(f"{key[0]}\n{key[1]}")
        y.append(mean)
        yerr.append(0 if math.isnan(ci) else ci)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 0.55), 5))
    ax.bar(range(len(labels)), y, yerr=yerr, capsize=3)
    ax.set_ylabel("RTO events")
    ax.set_title(title)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    save_fig(plt, base, title)


def plot_episode_share(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    base = output_dir / "07_rto_episode_time_share_20260610"
    title = "Time in RTO/backoff state"
    if plt is None:
        save_fig(None, base, title)
        return
    labels = []
    values = []
    for key, group in group_rows(case_rows, ["condition_id", "scenario"]).items():
        mean, _ci = mean_ci([to_float(row.get("time_in_rto_episode_pct")) for row in group])
        labels.append(f"{key[0]}\n{key[1]}")
        values.append(mean)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 0.55), 5))
    ax.bar(range(len(labels)), values)
    ax.set_ylabel("Time in RTO/backoff state [%]")
    ax.set_title(title)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    save_fig(plt, base, title)


def plot_collision_vs_degradation(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    base = output_dir / "08_rto_collision_vs_tcp_degradation_20260610"
    title = "RTO collision vs TCP degradation"
    if plt is None:
        save_fig(None, base, title)
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    for row in case_rows:
        x = 100.0 * to_float(row.get("rto_retransmission_collision_rate"))
        y = to_float(row.get("tcp_degradation_pct"))
        if math.isnan(x) or math.isnan(y):
            continue
        ax.scatter([x], [y])
        ax.annotate(f"{row.get('condition_id')}/{row.get('scenario')}", (x, y), fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax.set_xlabel("RTO retransmission collision rate [%]")
    ax.set_ylabel("TCP throughput degradation [%]")
    ax.set_title(title)
    save_fig(plt, base, title)


def plot_phase_distribution(rto_events: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    base = output_dir / "09_rto_to_pulse_phase_distribution_20260610"
    title = "RTO-to-pulse phase distribution"
    if plt is None:
        save_fig(None, base, title)
        return
    periodic = [to_float(row.get("rto_to_pulse_phase_ms")) for row in rto_events if "periodic" in row.get("scenario", "")]
    random = [to_float(row.get("rto_to_pulse_phase_ms")) for row in rto_events if "random" in row.get("scenario", "")]
    periodic = [v for v in periodic if not math.isnan(v)]
    random = [v for v in random if not math.isnan(v)]
    fig, ax = plt.subplots(figsize=(7, 5))
    if periodic:
        ax.hist(periodic, bins=20, alpha=0.6, label="periodic")
    if random:
        ax.hist(random, bins=20, alpha=0.6, label="random")
    ax.set_xlabel("RTO event - nearest pulse start [ms]")
    ax.set_ylabel("count")
    ax.set_title(title)
    ax.legend(fontsize=8)
    save_fig(plt, base, title)


def plot_detection_timing(case_rows: list[dict[str, str]], pulses: list[dict[str, str]], rto_events: list[dict[str, str]], bandwidth_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    base = output_dir / "10_rto_vs_detection_timeline_20260610"
    title = "First pulse, RTO, throughput drop, detection"
    if plt is None:
        save_fig(None, base, title)
        return
    labels = []
    first_pulse = []
    first_rto = []
    first_drop = []
    first_detection = []
    for row in case_rows:
        condition, scenario, seed = row.get("condition_id", ""), row.get("scenario", ""), row.get("seed", "")
        labels.append(f"{condition}\n{scenario}\nseed{seed}")
        case_pulses = [p for p in pulses if p.get("condition_id") == condition and p.get("scenario") == scenario and p.get("seed") == seed]
        case_rto = [e for e in rto_events if e.get("condition_id") == condition and e.get("scenario") == scenario and e.get("seed") == seed]
        case_bw = [b for b in bandwidth_rows if b.get("condition_id") == condition and b.get("scenario") == scenario and b.get("seed") == seed]
        first_pulse.append(min((to_float(p.get("pulse_start_sec")) for p in case_pulses), default=math.nan))
        first_rto.append(min((to_float(e.get("rto_event_time_sec")) for e in case_rto), default=math.nan))
        baseline = max((to_float(b.get("tcp_normal_mbps")) for b in case_bw if to_float(b.get("timestamp_sec")) < 2.0), default=math.nan)
        drop_time = math.nan
        for b in sorted(case_bw, key=lambda x: to_float(x.get("timestamp_sec"), 0.0)):
            if not math.isnan(baseline) and to_float(b.get("tcp_normal_mbps")) < baseline * 0.8:
                drop_time = to_float(b.get("timestamp_sec"))
                break
        first_drop.append(drop_time)
        first_detection.append(min((to_float(b.get("timestamp_sec")) for b in case_bw if to_float(b.get("detector_attack"), 0.0) >= 1), default=math.nan))
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 0.6), 5))
    x = list(range(len(labels)))
    series = [first_pulse, first_rto, first_drop, first_detection]
    names = ["first pulse", "first RTO", "first TCP drop", "first detection"]
    markers = ["o", "^", "s", "x"]
    for values, name, marker in zip(series, names, markers):
        ax.scatter(x, values, label=name, marker=marker)
    ax.set_ylabel("Time [sec]")
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
    ax.legend(fontsize=8)
    save_fig(plt, base, title)


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    case_rows = read_csv(args.input_dir / "case_metrics_20260610.csv")
    bandwidth_rows = read_csv(args.input_dir / "bandwidth_timeseries_20260610.csv")
    tcp_rows = read_csv(args.input_dir / "tcp_info_timeseries_20260610.csv")
    rto_events = read_csv(args.input_dir / "rto_events_20260610.csv")
    retrans_rows = read_csv(args.input_dir / "tcp_retransmission_events_20260610.csv")
    pulses = read_csv(args.input_dir / "pulse_tcp_alignment_20260610.csv")
    plt = get_matplotlib()
    plot_rto_timeline(bandwidth_rows, tcp_rows, rto_events, retrans_rows, pulses, args.output_dir, plt, args.bottleneck_mbps)
    plot_rto_count_by_scenario(case_rows, args.output_dir, plt)
    plot_episode_share(case_rows, args.output_dir, plt)
    plot_collision_vs_degradation(case_rows, args.output_dir, plt)
    plot_phase_distribution(rto_events, args.output_dir, plt)
    plot_detection_timing(case_rows, pulses, rto_events, bandwidth_rows, args.output_dir, plt)
    if plt is None:
        print("matplotlib was not available; placeholder RTO PNG/PDF files were written", file=sys.stderr)
    print(f"Wrote RTO figures to {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
