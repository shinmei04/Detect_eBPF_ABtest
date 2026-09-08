#!/usr/bin/env python3
"""Plot one representative saved Periodic-LDoS time sequence."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import statistics
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_CSV = REPO_ROOT / "exp/dpsws_tcp_25ms_20260726/out/20260726_135301/tcp_results_10trials.csv"
PCAP_HELPER = REPO_ROOT / "exp/dpsws_figures_20260726/analyze.py"
ATTACK_START_SEC = 10.0
ATTACK_END_SEC = 50.0
CAPACITY_MBPS = 15.0
DURATION_SEC = 60.0
UDP_BIN_SEC = 0.1

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["DejaVu Serif"],
        "font.size": 9,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 7.5,
        "axes.linewidth": 0.8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
    }
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_pcap_helper() -> Any:
    spec = importlib.util.spec_from_file_location("dpsws_pcap_helper", PCAP_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load pcap helper: {PCAP_HELPER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def select_representative() -> tuple[dict[str, str], float]:
    with RESULTS_CSV.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["condition"] == "ldos"]
    if len(rows) != 10 or {int(row["trial"]) for row in rows} != set(range(1, 11)):
        raise RuntimeError("the source summary does not contain all 10 LDoS trials")
    attack_values = [float(row["tcp_attack_mbps"]) for row in rows]
    median = float(statistics.median(attack_values))
    selected = min(rows, key=lambda row: (abs(float(row["tcp_attack_mbps"]) - median), int(row["trial"])))
    return selected, median


def locate_case(run_dir: Path) -> Path:
    case_files = list((run_dir / "cases").glob("*/case.json"))
    if len(case_files) != 1:
        raise RuntimeError(f"expected one case under {run_dir}, found {len(case_files)}")
    return case_files[0].parent


def receiver_intervals(receiver_json: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, interval in enumerate(read_json(receiver_json).get("intervals", [])):
        value = interval.get("sum") or {}
        start = float(value["start"])
        end = float(value["end"])
        byte_count = int(value["bytes"])
        bps = float(value["bits_per_second"])
        rows.append(
            {
                "interval_index": index,
                "start_sec": start,
                "end_sec": end,
                "duration_sec": end - start,
                "bytes": byte_count,
                "goodput_mbps": bps / 1_000_000.0,
                "in_attack_window": int(start >= ATTACK_START_SEC and start < ATTACK_END_SEC),
                "exact_zero": int(byte_count == 0 and bps == 0.0),
            }
        )
    if len(rows) < 59:
        raise RuntimeError(f"unexpectedly few iperf3 intervals: {len(rows)}")
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def save_figure(fig: Any, base: Path) -> None:
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.03)
    fig.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)


def plot_sequence(
    intervals: list[dict[str, Any]],
    udp_mbps: np.ndarray,
    zero_rows: list[dict[str, Any]],
    output_base: Path,
) -> None:
    edges = np.array([float(intervals[0]["start_sec"])] + [float(row["end_sec"]) for row in intervals])
    values = np.array([float(row["goodput_mbps"]) for row in intervals])
    udp_time = np.arange(len(udp_mbps), dtype=float) * UDP_BIN_SEC

    fig, axes = plt.subplots(
        2,
        1,
        figsize=(7.0, 4.8),
        sharex=True,
        gridspec_kw={"height_ratios": [1.12, 0.88], "hspace": 0.10},
    )
    tcp_color = "#2166ac"
    udp_color = "#d95f02"
    zero_color = "#b2182b"
    attack_color = "#bdbdbd"

    for axis in axes:
        axis.axvspan(ATTACK_START_SEC, ATTACK_END_SEC, color=attack_color, alpha=0.28, zorder=0)
        axis.set_xlim(0, DURATION_SEC)
        axis.set_xticks(np.arange(0, 61, 10))
        axis.grid(axis="y", color="0.86", linewidth=0.5)
        axis.set_axisbelow(True)

    axes[0].stairs(values, edges, color=tcp_color, linewidth=1.25, label="TCP goodput")
    axes[0].axhline(CAPACITY_MBPS, color="0.25", linestyle="--", linewidth=0.85, label="15 Mbps capacity")
    for row in zero_rows:
        axes[0].axvspan(
            float(row["start_sec"]),
            float(row["end_sec"]),
            facecolor="none",
            edgecolor=zero_color,
            hatch="////",
            linewidth=0.0,
            zorder=2,
        )
    zero_midpoints = [(float(row["start_sec"]) + float(row["end_sec"])) / 2.0 for row in zero_rows]
    axes[0].scatter(
        zero_midpoints,
        np.zeros(len(zero_midpoints)),
        marker="x",
        s=28,
        linewidths=1.3,
        color=zero_color,
        clip_on=False,
        zorder=4,
        label=f"Exact 0 Mbps interval (n={len(zero_rows)})",
    )
    axes[0].set_ylim(0, 16)
    axes[0].set_ylabel("TCP goodput [Mbps]")
    attack_patch = Patch(facecolor=attack_color, edgecolor="none", alpha=0.28, label="Attack period")
    handles, labels = axes[0].get_legend_handles_labels()
    lookup = dict(zip(labels, handles))
    axes[0].legend(
        [lookup["TCP goodput"], lookup[f"Exact 0 Mbps interval (n={len(zero_rows)})"], attack_patch, lookup["15 Mbps capacity"]],
        ["TCP goodput", f"Exact 0 Mbps interval (n={len(zero_rows)})", "Attack period", "15 Mbps capacity"],
        loc="upper center",
        ncol=2,
        frameon=True,
    )

    axes[1].plot(udp_time, udp_mbps, color=udp_color, linewidth=1.05, drawstyle="steps-post", label="UDP received rate")
    axes[1].set_ylim(0, 16)
    axes[1].set_ylabel("UDP received rate [Mbps]")
    axes[1].set_xlabel("Time [s]")
    axes[1].legend(handles=[axes[1].lines[0], attack_patch], labels=["UDP received rate", "Attack period"], loc="upper right", ncol=2, frameon=True)

    fig.subplots_adjust(left=0.105, right=0.995, top=0.995, bottom=0.105)
    save_figure(fig, output_base)


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    data_dir = output_dir / "data"
    figures_dir = output_dir / "figures"
    data_dir.mkdir()
    figures_dir.mkdir()

    selected, median = select_representative()
    trial = int(selected["trial"])
    run_dir = Path(selected["run_dir"])
    case_dir = locate_case(run_dir)
    case_json = case_dir / "case.json"
    metadata = read_json(case_json)
    raw_dir = case_dir / "raw"
    receiver_json = raw_dir / "iperf3_server_20260707.json"
    receiver_pcap = raw_dir / "bottleneck_after_h2_eth0_20260707.pcap"
    pulses_csv = raw_dir / "pulses_20260707.csv"
    for source in (RESULTS_CSV, receiver_json, receiver_pcap):
        if not source.is_file() or source.stat().st_size == 0:
            raise RuntimeError(f"missing or empty source: {source}")

    intervals = receiver_intervals(receiver_json)
    attack_rows = [row for row in intervals if row["in_attack_window"]]
    zero_rows = [row for row in attack_rows if row["exact_zero"]]
    if len(attack_rows) != 40:
        raise RuntimeError(f"expected 40 attack-window intervals, found {len(attack_rows)}")

    helper = load_pcap_helper()
    source_case = helper.SourceCase("ldos", trial, case_dir, metadata, receiver_json, receiver_pcap, pulses_csv)
    _, udp_mbps, excluded_retransmissions, tcp_stream, max_clock_correction = helper.tshark_payload_bins(source_case)
    if len(udp_mbps) != 600:
        raise RuntimeError(f"expected 600 UDP bins, found {len(udp_mbps)}")

    write_csv(
        data_dir / "tcp_receiver_intervals.csv",
        intervals,
        ["interval_index", "start_sec", "end_sec", "duration_sec", "bytes", "goodput_mbps", "in_attack_window", "exact_zero"],
    )
    write_csv(
        data_dir / "udp_receiver_100ms.csv",
        [
            {"bin_index": index, "start_sec": f"{index * UDP_BIN_SEC:.1f}", "received_payload_mbps": f"{value:.9f}"}
            for index, value in enumerate(udp_mbps)
        ],
        ["bin_index", "start_sec", "received_payload_mbps"],
    )
    write_csv(
        data_dir / "tcp_zero_goodput_intervals_attack.csv",
        zero_rows,
        ["interval_index", "start_sec", "end_sec", "duration_sec", "bytes", "goodput_mbps", "in_attack_window", "exact_zero"],
    )

    plot_sequence(intervals, udp_mbps, zero_rows, figures_dir / "tcp_udp_sequence_representative_trial2")

    attack_udp = udp_mbps[100:500]
    selection = {
        "selection_rule": "LDoS trial whose 10-50 s TCP goodput is closest to the 10-trial median; ties resolved by lower trial number",
        "source_trial_count": 10,
        "median_tcp_goodput_10_50_mbps": median,
        "selected_trial": trial,
        "selected_tcp_goodput_10_50_mbps": float(selected["tcp_attack_mbps"]),
        "selected_tcp_goodput_full_mbps": float(selected["tcp_mean_mbps"]),
        "selected_tcp_timeouts": int(selected["tcp_timeouts"]),
        "exact_zero_goodput_interval_count_10_50": len(zero_rows),
        "exact_zero_goodput_intervals_sec": [[float(row["start_sec"]), float(row["end_sec"])] for row in zero_rows],
        "udp_received_payload_mean_10_50_mbps": float(attack_udp.mean()),
        "udp_received_payload_peak_100ms_mbps": float(attack_udp.max()),
        "excluded_tcp_retransmission_packets_in_pcap_helper": excluded_retransmissions,
        "tcp_data_stream": tcp_stream,
        "max_pcap_wall_clock_correction_sec": max_clock_correction,
    }
    (output_dir / "selection_and_metrics.json").write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")

    zero_text = ", ".join(f"{float(row['start_sec']):.3f}-{float(row['end_sec']):.3f} s" for row in zero_rows)
    summary = f"""# Representative Periodic-LDoS time sequence

- Selection rule: closest 10-50 s TCP goodput to the 10-trial median (tie: lower trial number)
- Selected condition/trial: Periodic LDoS, trial {trial}
- Ten-trial median TCP goodput (10-50 s): {median:.6f} Mbps
- Selected TCP goodput (10-50 s): {float(selected['tcp_attack_mbps']):.6f} Mbps
- Exact 0 Mbps receiver-iperf3 intervals during 10 <= t < 50: {len(zero_rows)}
- Zero intervals: {zero_text}
- TCP timeouts: {int(selected['tcp_timeouts'])}
- Receiver-pcap UDP payload mean (10-50 s): {float(attack_udp.mean()):.6f} Mbps
- Receiver-pcap UDP payload 100 ms peak (10-50 s): {float(attack_udp.max()):.6f} Mbps

TCP is the receiver-side iperf3 JSON `intervals[].sum.bits_per_second` at its native approximately one-second intervals. An exact zero requires both `bytes == 0` and `bits_per_second == 0`. UDP is receiver-side pcap payload (`udp.length - 8`) in 100 ms bins. The saved pcap's WSL wall-clock jumps are corrected with the same TCP-timestamp/frame-order method used by the existing DPSWS figure analysis. No experiment was rerun and no saved result was modified.
"""
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")
    (output_dir / "source_manifest.json").write_text(
        json.dumps(
            {
                "ten_trial_summary_csv": str(RESULTS_CSV),
                "case_json": str(case_json),
                "receiver_iperf3_json": str(receiver_json),
                "receiver_pcap": str(receiver_pcap),
                "pcap_analysis_helper": str(PCAP_HELPER),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (output_dir / "commands.log").write_text(
        f"python3 {Path(__file__).resolve()} --output-dir {output_dir}\n",
        encoding="utf-8",
    )
    print(json.dumps(selection, indent=2))
    print(figures_dir / "tcp_udp_sequence_representative_trial2.pdf")
    print(figures_dir / "tcp_udp_sequence_representative_trial2.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
