#!/usr/bin/env python3
"""
Created: 2026-06-10
Purpose: 25 ms detector window comparison experiment.

Generate bandwidth-utilization figures from the pipeline CSV outputs.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
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
    parser.add_argument("--input-dir", required=True, type=Path, help="Directory containing *_20260610.csv outputs")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--results-dir", type=Path, help="Optional root result directory for metadata lookup")
    parser.add_argument("--bottleneck-mbps", type=float, default=15.0)
    parser.add_argument("--attack-start-sec", type=float, default=20.0)
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


def load_metadata(results_dir: Path | None) -> dict[tuple[str, str, str], dict[str, Any]]:
    if not results_dir:
        return {}
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    cases = results_dir / "cases"
    if not cases.exists():
        return out
    for path in cases.glob("*/metadata_20260610.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        out[(str(data.get("condition_id", "")), str(data.get("scenario", "")), str(data.get("seed", "")))] = data
    return out


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
        body = f"Placeholder figure: {title}\nmatplotlib was not available.\n"
        pdf = (
            "%PDF-1.1\n1 0 obj<<>>endobj\n2 0 obj<< /Length "
            + str(len(body) + 70)
            + " >>stream\nBT /F1 12 Tf 72 720 Td ("
            + body.replace("(", "[").replace(")", "]").replace("\n", " ")
            + ") Tj ET\nendstream endobj\ntrailer<<>>\n%%EOF\n"
        )
        path.write_text(pdf)


def save_fig(plt: Any, path_base: Path, title: str) -> None:
    if plt is None:
        write_placeholder(path_base.with_suffix(".png"), title)
        write_placeholder(path_base.with_suffix(".pdf"), title)
        return
    path_base.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(path_base.with_suffix(".png"), dpi=180)
    plt.savefig(path_base.with_suffix(".pdf"))
    plt.close()


def group_rows(rows: list[dict[str, str]], fields: list[str]) -> dict[tuple[str, ...], list[dict[str, str]]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[tuple(str(row.get(field, "")) for field in fields)].append(row)
    return grouped


def plot_timeseries(rows: list[dict[str, str]], output_dir: Path, metadata: dict[tuple[str, str, str], dict[str, Any]], plt: Any, default_attack_start: float, default_c: float) -> None:
    for (condition, scenario, seed), group in group_rows(rows, ["condition_id", "scenario", "seed"]).items():
        group = sorted(group, key=lambda row: to_float(row.get("timestamp_sec"), 0.0))
        meta = metadata.get((condition, scenario, seed), {})
        attack_start = to_float(meta.get("attack_start_sec"), default_attack_start)
        bottleneck = to_float(meta.get("bottleneck_mbps"), default_c)
        title = f"Bandwidth timeseries {condition} {scenario} seed {seed}"
        base = output_dir / f"01_bandwidth_timeseries_{slug(condition)}_{slug(scenario)}_seed{slug(seed)}_20260610"
        if plt is None:
            save_fig(None, base, title)
            continue
        ts = [to_float(row["timestamp_sec"]) for row in group]
        tcp = [to_float(row["tcp_normal_mbps"], 0.0) for row in group]
        attack = [to_float(row["attack_passed_mbps"], 0.0) for row in group]
        total = [to_float(row["total_passed_mbps"], 0.0) for row in group]
        tcp_share = [to_float(row["tcp_share_pct"], 0.0) for row in group]
        attack_share = [to_float(row["attack_share_pct"], 0.0) for row in group]
        other_share = [to_float(row["other_share_pct"], 0.0) for row in group]
        idle_share = [to_float(row["idle_share_pct"], 0.0) for row in group]
        detector = [to_float(row["detector_attack"], 0.0) for row in group]
        fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
        axes[0].plot(ts, tcp, label="Normal TCP")
        axes[0].plot(ts, attack, label="Attack passed")
        axes[0].plot(ts, total, label="Total passed", linewidth=1.5)
        axes[0].axhline(bottleneck, color="black", linestyle="--", linewidth=1, label=f"C={bottleneck:g} Mbps")
        axes[0].axvline(attack_start, color="red", linestyle=":", linewidth=1)
        detected_ts = [t for t, flag in zip(ts, detector) if flag >= 1]
        if detected_ts:
            axes[0].scatter(detected_ts, [bottleneck * 1.02] * len(detected_ts), s=8, color="red", label="detector attack")
        axes[0].set_ylabel("Mbps")
        axes[0].set_title(title)
        axes[0].legend(loc="upper right", fontsize=8)
        axes[1].stackplot(ts, tcp_share, attack_share, other_share, idle_share, labels=["Normal TCP", "Attack", "Other", "Idle"], alpha=0.85)
        axes[1].axvline(attack_start, color="red", linestyle=":", linewidth=1)
        axes[1].set_ylim(0, 100)
        axes[1].set_xlabel("Time [sec]")
        axes[1].set_ylabel("Capacity share [%]")
        axes[1].legend(loc="upper right", fontsize=8)
        save_fig(plt, base, title)


def average_by_group(rows: list[dict[str, str]], fields: list[str], metrics: list[str]) -> list[dict[str, Any]]:
    out = []
    for key, group in group_rows(rows, fields).items():
        row = {field: value for field, value in zip(fields, key)}
        for metric in metrics:
            values = [to_float(item.get(metric), math.nan) for item in group]
            values = [value for value in values if not math.isnan(value)]
            row[metric] = sum(values) / len(values) if values else math.nan
        out.append(row)
    return sorted(out, key=lambda item: tuple(str(item[field]) for field in fields))


def plot_share_stacked(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    metrics = ["tcp_share_pct", "attack_share_pct", "other_share_pct", "idle_share_pct"]
    rows = average_by_group(case_rows, ["condition_id", "scenario"], metrics)
    base = output_dir / "02_bandwidth_share_stacked_20260610"
    title = "Average bottleneck capacity share"
    if plt is None:
        save_fig(None, base, title)
        return
    labels = [f"{row['condition_id']}\n{row['scenario']}" for row in rows]
    bottoms = [0.0] * len(rows)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 0.6), 5))
    colors = ["#3b82f6", "#ef4444", "#9ca3af", "#d1d5db"]
    names = ["Normal TCP", "Attack", "Other", "Idle"]
    for metric, color, name in zip(metrics, colors, names):
        values = [to_float(row[metric], 0.0) for row in rows]
        ax.bar(range(len(rows)), values, bottom=bottoms, label=name, color=color)
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
    ax.set_ylim(0, 100)
    ax.set_ylabel("Capacity share [%]")
    ax.set_title(title)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.legend(loc="upper right")
    save_fig(plt, base, title)


def plot_attack_load_vs_degradation(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    rows = average_by_group(
        [row for row in case_rows if row.get("scenario") != "no_attack"],
        ["condition_id", "scenario"],
        ["measured_attack_passed_mbps", "bottleneck_mbps", "tcp_degradation_pct"],
    )
    base = output_dir / "03_attack_load_vs_tcp_degradation_20260610"
    title = "Attack load vs TCP degradation"
    if plt is None:
        save_fig(None, base, title)
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    markers = {"constant_udp": "o", "random_microburst": "s", "periodic_ldos": "^", "stat_matched_ldos": "D"}
    for scenario, group in group_rows([{k: str(v) for k, v in row.items()} for row in rows], ["scenario"]).items():
        xs = []
        ys = []
        labels = []
        for row in group:
            c = to_float(row.get("bottleneck_mbps"), 15.0)
            xs.append(100.0 * to_float(row.get("measured_attack_passed_mbps"), 0.0) / c)
            ys.append(to_float(row.get("tcp_degradation_pct"), math.nan))
            labels.append(row.get("condition_id", ""))
        ax.scatter(xs, ys, label=scenario[0], marker=markers.get(scenario[0], "o"))
        for x, y, label in zip(xs, ys, labels):
            if not math.isnan(y):
                ax.annotate(label, (x, y), fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax.set_xlabel("Measured attack load / bottleneck capacity [%]")
    ax.set_ylabel("TCP throughput degradation [%]")
    ax.set_title(title)
    ax.legend(fontsize=8)
    save_fig(plt, base, title)


def plot_excess_vs_fnr(case_rows: list[dict[str, str]], output_dir: Path, plt: Any) -> None:
    rows = [
        row
        for row in case_rows
        if row.get("scenario") in {"periodic_ldos", "stat_matched_ldos"}
    ]
    rows = average_by_group(rows, ["condition_id", "scenario"], ["excess_degradation_vs_random_pct", "FNR"])
    base = output_dir / "04_excess_degradation_vs_fnr_20260610"
    title = "Excess degradation vs FNR"
    if plt is None:
        save_fig(None, base, title)
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    for row in rows:
        x = to_float(row.get("excess_degradation_vs_random_pct"), math.nan)
        y = 100.0 * to_float(row.get("FNR"), math.nan)
        if math.isnan(x) or math.isnan(y):
            continue
        ax.scatter([x], [y], label=row["scenario"])
        ax.annotate(row["condition_id"], (x, y), fontsize=7, xytext=(3, 3), textcoords="offset points")
    ax.set_xlabel("Excess degradation vs random [percentage points]")
    ax.set_ylabel("FNR [%]")
    ax.set_title(title)
    handles, labels = ax.get_legend_handles_labels()
    unique = dict(zip(labels, handles))
    if unique:
        ax.legend(unique.values(), unique.keys(), fontsize=8)
    save_fig(plt, base, title)


def write_markdown_table(case_rows: list[dict[str, str]], output_dir: Path) -> None:
    rows = average_by_group(
        case_rows,
        ["condition_id", "scenario"],
        [
            "tcp_share_pct",
            "attack_share_pct",
            "idle_share_pct",
            "tcp_degradation_pct",
            "excess_degradation_vs_random_pct",
            "FNR",
        ],
    )
    lines = [
        "# Bandwidth Share Table",
        "",
        "| condition | scenario | normal TCP % | attack % | idle % | TCP degradation % | excess degradation % | FNR % |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        fnr_pct = 100.0 * to_float(row.get("FNR"), math.nan)
        lines.append(
            "| {condition_id} | {scenario} | {tcp:.2f} | {attack:.2f} | {idle:.2f} | {deg:.2f} | {excess:.2f} | {fnr:.2f} |".format(
                condition_id=row["condition_id"],
                scenario=row["scenario"],
                tcp=to_float(row.get("tcp_share_pct"), math.nan),
                attack=to_float(row.get("attack_share_pct"), math.nan),
                idle=to_float(row.get("idle_share_pct"), math.nan),
                deg=to_float(row.get("tcp_degradation_pct"), math.nan),
                excess=to_float(row.get("excess_degradation_vs_random_pct"), math.nan),
                fnr=fnr_pct,
            )
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "bandwidth_share_table_20260610.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    timeseries = read_csv(args.input_dir / "bandwidth_timeseries_20260610.csv")
    case_rows = read_csv(args.input_dir / "case_metrics_20260610.csv")
    metadata = load_metadata(args.results_dir)
    plt = get_matplotlib()
    plot_timeseries(timeseries, args.output_dir, metadata, plt, args.attack_start_sec, args.bottleneck_mbps)
    plot_share_stacked(case_rows, args.output_dir, plt)
    plot_attack_load_vs_degradation(case_rows, args.output_dir, plt)
    plot_excess_vs_fnr(case_rows, args.output_dir, plt)
    write_markdown_table(case_rows, args.output_dir)
    if plt is None:
        print("matplotlib was not available; placeholder PNG/PDF files were written", file=sys.stderr)
    print(f"Wrote figures to {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
