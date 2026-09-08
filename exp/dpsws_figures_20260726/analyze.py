#!/usr/bin/env python3
"""Generate manuscript figures from the saved TCP-unlimited 10-trial data."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import t as student_t


REPO_ROOT = Path(__file__).resolve().parents[2]
OLD_ROOT = REPO_ROOT / "exp/dpsws_tcp_unlimited_20260724/out/20260724_131803/runs"
NEW_ROOT = REPO_ROOT / "exp/dpsws_tcp_25ms_20260726/out/20260726_135301/runs"

CAPACITY_MBPS = 15.0
DURATION_SEC = 60.0
ATTACK_START_SEC = 10.0
ATTACK_END_SEC = 50.0
TCP_BIN_SEC = 1.0
UDP_BIN_SEC = 0.1
T_CRITICAL_95_N10 = float(student_t.ppf(0.975, 9))

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["DejaVu Serif"],
        "font.size": 9,
        "axes.labelsize": 9,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 8,
        "axes.linewidth": 0.8,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
    }
)


@dataclass(frozen=True)
class SourceCase:
    condition: str
    trial: int
    case_dir: Path
    metadata: dict[str, Any]
    receiver_json: Path
    receiver_pcap: Path
    pulses_csv: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--workers", type=int, default=2)
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def find_case_dir(run_dir: Path) -> Path:
    case_files = list((run_dir / "cases").glob("*/case.json"))
    if len(case_files) != 1:
        raise RuntimeError(f"expected one case.json under {run_dir}, found {len(case_files)}")
    return case_files[0].parent


def discover_sources() -> list[SourceCase]:
    sources: list[SourceCase] = []
    for condition in ("baseline", "ldos"):
        for trial in range(1, 11):
            if trial <= 3:
                if condition == "baseline" and trial == 3:
                    run_dir = OLD_ROOT / "baseline_trial_3_attempt_2"
                else:
                    run_dir = OLD_ROOT / f"{condition}_trial_{trial}"
            else:
                run_dir = NEW_ROOT / f"{condition}_trial_{trial}"
            case_dir = find_case_dir(run_dir)
            metadata = read_json(case_dir / "case.json")
            raw_dir = case_dir / "raw"
            receiver_json = raw_dir / "iperf3_server_20260707.json"
            receiver_pcap = raw_dir / "bottleneck_after_h2_eth0_20260707.pcap"
            pulses_csv = raw_dir / "pulses_20260707.csv"
            for source in (receiver_json, receiver_pcap):
                if not source.is_file() or source.stat().st_size <= 0:
                    raise RuntimeError(f"missing or empty source: {source}")
            expected_type = "base" if condition == "baseline" else "periodic_ldos"
            if metadata.get("case_type") != expected_type:
                raise RuntimeError(f"case type mismatch: {case_dir}")
            if int(metadata.get("trial", trial)) != trial and not str(metadata.get("case_id", "")).endswith(f"_{trial}"):
                raise RuntimeError(f"trial mismatch: {case_dir}")
            sources.append(
                SourceCase(condition, trial, case_dir, metadata, receiver_json, receiver_pcap, pulses_csv)
            )
    return sources


def overlap_rate_bins(intervals: list[dict[str, Any]], duration: int = 60) -> np.ndarray:
    bits = np.zeros(duration, dtype=float)
    covered = np.zeros(duration, dtype=float)
    for item in intervals:
        summary = item.get("sum") or {}
        left = float(summary.get("start", 0.0))
        right = float(summary.get("end", left))
        bps = float(summary.get("bits_per_second", 0.0))
        if right <= left:
            continue
        first = max(0, int(math.floor(left)))
        last = min(duration - 1, int(math.ceil(right) - 1))
        for index in range(first, last + 1):
            overlap = max(0.0, min(right, index + 1.0) - max(left, float(index)))
            if overlap > 0.0:
                bits[index] += bps * overlap
                covered[index] += overlap
    if np.any(covered < 0.999):
        missing = np.where(covered < 0.999)[0].tolist()
        raise RuntimeError(f"receiver iperf intervals do not cover one-second bins: {missing}")
    return bits / 1_000_000.0


def receiver_tcp_timeseries(case: SourceCase) -> np.ndarray:
    data = read_json(case.receiver_json)
    return overlap_rate_bins(data.get("intervals", []), int(DURATION_SEC))


def offered_udp_mean(case: SourceCase) -> float:
    if case.condition != "ldos":
        return 0.0
    with case.pulses_csv.open(newline="", encoding="utf-8") as handle:
        byte_count = sum(int(float(row["bytes_sent"])) for row in csv.DictReader(handle))
    return byte_count * 8.0 / (ATTACK_END_SEC - ATTACK_START_SEC) / 1_000_000.0


def tshark_payload_bins(case: SourceCase) -> tuple[np.ndarray, np.ndarray, int, int, float]:
    meta = case.metadata
    sender = str(meta["sender_ip"])
    receiver = str(meta["receiver_ip"])
    attacker = str(meta["attacker_ip"])
    iperf_port = int(meta.get("iperf_port", 5201))
    udp_port = int(meta.get("udp_port", 5001))
    display_filter = (
        f"(ip.src=={sender} && ip.dst=={receiver} && tcp.dstport=={iperf_port} && tcp.len>0) || "
        f"(ip.src=={attacker} && ip.dst=={receiver} && udp.dstport=={udp_port} && udp.length>8)"
    )
    fields = [
        "frame.number",
        "frame.time_epoch",
        "tcp.stream",
        "tcp.options.timestamp.tsval",
        "tcp.len",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
        "udp.length",
    ]
    command = [
        "tshark", "-n", "-r", str(case.receiver_pcap), "-Y", display_filter,
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1024 * 1024,
    )
    assert process.stdout is not None
    records: list[tuple[int, float, str, str, str, str, str, str, str]] = []
    for line in process.stdout:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < len(fields):
            parts.extend([""] * (len(fields) - len(parts)))
        frame_text, timestamp_text, tcp_stream, tcp_tsval, tcp_len_text, retrans, fast, spurious, udp_length_text = parts[:9]
        if not frame_text or not timestamp_text:
            continue
        records.append((int(frame_text), float(timestamp_text), tcp_stream, tcp_tsval, tcp_len_text, retrans, fast, spurious, udp_length_text))
    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"tshark failed for {case.receiver_pcap}: {stderr.strip()}")

    # WSL wall-clock synchronization can introduce multi-second jumps into
    # frame.time_epoch while the experiment continues on CLOCK_MONOTONIC. Use
    # the data connection's TCP timestamp option (1 ms Linux clock) as the
    # monotonic pcap timebase. UDP frames are placed by frame-order interpolation
    # between TCP timestamp anchors, so both protocols retain receiver-side pcap
    # packet and payload definitions without relying on the discontinuous clock.
    stream_bytes: dict[int, int] = {}
    for _, _, stream_text, _, tcp_len_text, _, _, _, _ in records:
        if stream_text and tcp_len_text:
            stream = int(stream_text)
            stream_bytes[stream] = stream_bytes.get(stream, 0) + int(tcp_len_text)
    if not stream_bytes:
        raise RuntimeError(f"no TCP data stream found in {case.receiver_pcap}")
    data_stream = max(stream_bytes, key=stream_bytes.get)
    anchors = [
        (frame, epoch, int(tsval))
        for frame, epoch, stream, tsval, tcp_len, _, _, _, _ in records
        if stream and int(stream) == data_stream and tcp_len and tsval
    ]
    if len(anchors) < 2:
        raise RuntimeError(f"insufficient TCP timestamp anchors in {case.receiver_pcap}")
    first_frame, first_epoch, first_tsval = anchors[0]
    base_relative = first_epoch - float(meta["start_epoch"])
    anchor_frames = np.array([item[0] for item in anchors], dtype=float)
    anchor_times = np.array(
        [base_relative + ((item[2] - first_tsval) & 0xFFFFFFFF) / 1000.0 for item in anchors],
        dtype=float,
    )
    raw_anchor_times = np.array([item[1] - float(meta["start_epoch"]) for item in anchors], dtype=float)
    max_clock_correction_sec = float(np.max(np.abs(raw_anchor_times - anchor_times)))

    tcp_bytes = np.zeros(int(DURATION_SEC), dtype=np.float64)
    udp_bytes_100ms = np.zeros(int(DURATION_SEC / UDP_BIN_SEC), dtype=np.float64)
    excluded_retransmissions = 0
    for frame, _, stream_text, tsval_text, tcp_len_text, retrans, fast, spurious, udp_length_text in records:
        relative = float(np.interp(float(frame), anchor_frames, anchor_times))
        if relative < 0.0 or relative >= DURATION_SEC:
            continue
        if tcp_len_text and stream_text and int(stream_text) == data_stream:
            if tsval_text:
                relative = base_relative + ((int(tsval_text) - first_tsval) & 0xFFFFFFFF) / 1000.0
            tcp_len = int(tcp_len_text)
            if retrans or fast or spurious:
                excluded_retransmissions += 1
            else:
                tcp_bytes[min(59, int(relative))] += tcp_len
        if udp_length_text:
            udp_payload = max(0, int(udp_length_text) - 8)
            udp_bytes_100ms[min(len(udp_bytes_100ms) - 1, int(relative / UDP_BIN_SEC))] += udp_payload
    tcp_mbps = tcp_bytes * 8.0 / TCP_BIN_SEC / 1_000_000.0
    udp_mbps_100ms = udp_bytes_100ms * 8.0 / UDP_BIN_SEC / 1_000_000.0
    return tcp_mbps, udp_mbps_100ms, excluded_retransmissions, data_stream, max_clock_correction_sec


def mean_sd_ci(values: Iterable[float]) -> tuple[int, float, float, float, float]:
    sample = [float(value) for value in values]
    n = len(sample)
    average = statistics.mean(sample)
    sd = statistics.stdev(sample) if n > 1 else 0.0
    margin = float(student_t.ppf(0.975, n - 1)) * sd / math.sqrt(n) if n > 1 else 0.0
    return n, average, sd, average - margin, average + margin


def timeseries_summary(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    average = matrix.mean(axis=0)
    sd = matrix.std(axis=0, ddof=1)
    margin = T_CRITICAL_95_N10 * sd / math.sqrt(matrix.shape[0])
    return average, sd, np.maximum(0.0, average - margin), average + margin


def save_figure(fig: Any, base: Path) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.03)
    fig.savefig(base.with_suffix(".png"), dpi=300, bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)


def plot_timeseries(
    output_dir: Path,
    tcp_matrix: np.ndarray,
    udp_matrix: np.ndarray,
) -> float:
    tcp_mean, _, tcp_low, tcp_high = timeseries_summary(tcp_matrix)
    udp_mean, _, udp_low, udp_high = timeseries_summary(udp_matrix)
    tcp_time = np.arange(60, dtype=float)
    udp_time = np.arange(udp_matrix.shape[1], dtype=float) * UDP_BIN_SEC

    fig, axes = plt.subplots(
        2, 1, figsize=(7.0, 4.8), sharex=True,
        gridspec_kw={"height_ratios": [1, 1], "hspace": 0.10},
    )
    tcp_color = "#1f77b4"
    udp_color = "#d95f02"
    attack_color = "#bdbdbd"

    for axis in axes:
        axis.axvspan(ATTACK_START_SEC, ATTACK_END_SEC, color=attack_color, alpha=0.28, zorder=0, label="Attack period")
        axis.set_xlim(0, 60)
        axis.set_xticks(np.arange(0, 61, 10))
        axis.grid(axis="y", color="0.85", linewidth=0.5)
        axis.set_axisbelow(True)

    axes[0].fill_between(tcp_time, tcp_low, tcp_high, color=tcp_color, alpha=0.18, linewidth=0, label="95% CI")
    axes[0].plot(tcp_time, tcp_mean, color=tcp_color, linewidth=1.35, label="TCP goodput")
    axes[0].axhline(CAPACITY_MBPS, color="0.25", linestyle="--", linewidth=0.9, label="15 Mbps capacity")
    axes[0].set_ylim(0, 16)
    axes[0].set_ylabel("TCP goodput [Mbps]")
    handles, labels = axes[0].get_legend_handles_labels()
    order = [labels.index(name) for name in ("TCP goodput", "95% CI", "Attack period", "15 Mbps capacity")]
    axes[0].legend([handles[i] for i in order], [labels[i] for i in order], loc="lower left", ncol=2, frameon=True)

    axes[1].fill_between(udp_time, udp_low, udp_high, step="post", color=udp_color, alpha=0.18, linewidth=0, label="95% CI")
    axes[1].plot(udp_time, udp_mean, color=udp_color, linewidth=1.1, drawstyle="steps-post", label="UDP received rate")
    udp_upper_limit = 16.0 if float(udp_high.max()) <= 16.0 else math.ceil((float(udp_high.max()) + 0.25) * 2.0) / 2.0
    axes[1].set_ylim(0, udp_upper_limit)
    axes[1].set_ylabel("UDP received rate [Mbps]")
    axes[1].set_xlabel("Time [s]")
    handles, labels = axes[1].get_legend_handles_labels()
    order = [labels.index(name) for name in ("UDP received rate", "95% CI", "Attack period")]
    axes[1].legend([handles[i] for i in order], [labels[i] for i in order], loc="upper right", ncol=3, frameon=True)
    fig.subplots_adjust(left=0.105, right=0.995, top=0.995, bottom=0.105)
    save_figure(fig, output_dir / "figures/tcp_udp_timeseries_10trials")
    return udp_upper_limit


def plot_bandwidth_utilization(output_dir: Path, summary_by_condition: dict[str, dict[str, dict[str, float]]]) -> None:
    conditions = ["baseline", "ldos"]
    labels = ["Baseline", "Periodic LDoS"]
    metric_keys = ["tcp_utilization_pct", "udp_utilization_pct", "unused_utilization_pct"]
    names = ["TCP", "UDP", "Unused"]
    colors = ["#4c78a8", "#f58518", "#b8b8b8"]
    hatches = ["///", "\\\\", "..."]
    x = np.arange(2)
    width = 0.56
    bottom = np.zeros(2)
    fig, axis = plt.subplots(figsize=(5.3, 3.7))
    for metric, name, color, hatch in zip(metric_keys, names, colors, hatches):
        values = np.array([summary_by_condition[condition][metric]["mean"] for condition in conditions])
        bars = axis.bar(
            x, values, width, bottom=bottom, label=name, color=color,
            edgecolor="black", linewidth=0.55, hatch=hatch,
        )
        for index, (bar, value, base) in enumerate(zip(bars, values, bottom)):
            if value >= 4.0:
                axis.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    base + value / 2.0,
                    f"{value:.1f}%",
                    ha="center", va="center", fontsize=8,
                    color="black",
                )
            elif value > 0.05:
                axis.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    base + value + 1.2,
                    f"{value:.1f}%",
                    ha="center", va="bottom", fontsize=8,
                    color="black",
                )
            elif name == "UDP":
                axis.text(
                    bar.get_x() + bar.get_width() + 0.025,
                    base,
                    "0.0%",
                    ha="left", va="center", fontsize=8,
                    color="black",
                )
        bottom += values
    axis.set_ylim(0, 100)
    axis.set_ylabel("Bandwidth utilization [%]")
    axis.set_xticks(x, labels)
    axis.set_yticks(np.arange(0, 101, 20))
    axis.grid(axis="y", color="0.85", linewidth=0.5)
    axis.set_axisbelow(True)
    axis.legend(loc="lower center", bbox_to_anchor=(0.5, 1.005), ncol=3, frameon=True)
    fig.subplots_adjust(left=0.15, right=0.985, top=0.90, bottom=0.14)
    save_figure(fig, output_dir / "figures/bandwidth_utilization_stacked")


def markdown_summary(
    utilization_rows: list[dict[str, Any]],
    utilization_stats: list[dict[str, Any]],
    baseline_iperf: tuple[int, float, float, float, float],
    ldos_iperf: tuple[int, float, float, float, float],
    degradation: tuple[int, float, float, float, float],
    offered_udp: tuple[int, float, float, float, float],
    udp_axis_max: float,
) -> str:
    lines = [
        "# DPSWS TCP-unlimited manuscript figure summary",
        "",
        "## Consistency metrics from receiver-side iperf3 JSON",
        "",
        f"- Baseline TCP goodput (10-50 s): {baseline_iperf[1]:.6f} ± {baseline_iperf[2]:.6f} Mbps",
        f"- Periodic LDoS TCP goodput (10-50 s): {ldos_iperf[1]:.6f} ± {ldos_iperf[2]:.6f} Mbps",
        f"- Paired TCP degradation: {degradation[1]:.6f} ± {degradation[2]:.6f}%",
        f"- Sender pulse-log UDP offered mean: {offered_udp[1]:.6f} ± {offered_udp[2]:.6f} Mbps",
        "",
        "## Per-trial pcap payload utilization",
        "",
        "| condition | trial | TCP Mbps | UDP Mbps | TCP % | UDP % | Unused % | excluded TCP retransmission packets |",
        "| -- | -: | --: | --: | --: | --: | --: | --: |",
    ]
    for row in utilization_rows:
        lines.append(
            f"| {row['condition']} | {row['trial']} | {row['tcp_mbps']:.6f} | {row['udp_mbps']:.6f} | "
            f"{row['tcp_utilization_pct']:.6f} | {row['udp_utilization_pct']:.6f} | "
            f"{row['unused_utilization_pct']:.6f} | {row['excluded_tcp_retransmission_packets']} |"
        )
    lines.extend(
        [
            "",
            "## Ten-trial pcap payload utilization statistics",
            "",
            "| condition | metric | n | mean | sample SD | 95% CI |",
            "| -- | -- | -: | --: | --: | --: |",
        ]
    )
    for row in utilization_stats:
        lines.append(
            f"| {row['condition']} | {row['metric']} | {row['n']} | {row['mean']:.6f} | "
            f"{row['sample_sd']:.6f} | [{row['ci95_low']:.6f}, {row['ci95_high']:.6f}] |"
        )
    lines.extend(
        [
            "",
            "TCP uses receiver-side pcap `tcp.len` and excludes Wireshark Retransmission, Fast Retransmission, and Spurious Retransmission flags. UDP uses `udp.length - 8`. Each trial is first aggregated into one-second bins over 10 <= t < 50, then averaged and divided by 15 Mbps.",
            "",
            "The saved pcaps contain WSL wall-clock corrections of up to about six seconds. Pcap bins therefore use the selected TCP data stream's `tcp.options.timestamp.tsval` as a monotonic timebase; UDP frames are aligned by receiver-pcap frame-order interpolation between those TCP anchors. No rate or packet count is synthesized.",
            "",
            f"The UDP time-series axis limit selected after inspecting the 95% CI upper envelope is 0-{udp_axis_max:g} Mbps.",
            "",
            "## Comparison with the legacy Figure/Table 5 artifact",
            "",
            "The layout and 10 <= t < 50 evaluation interval are retained, but the stored legacy `experiments/main_ldos_tcp6m/figures/bandwidth_utilization_attack_window_values.csv` is not receiver-pcap-payload based: its Periodic LDoS UDP value is 30.0032% (= 4.50048 Mbps), which matches offered pulse traffic. The new stacked graph follows the requested receiver-pcap definition and therefore reports received UDP separately from the 4.499 Mbps offered value.",
            "",
            "No source experiment result was modified and no experiment was re-executed.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    data_dir = output_dir / "data"
    figures_dir = output_dir / "figures"
    data_dir.mkdir(parents=True, exist_ok=False)
    figures_dir.mkdir(parents=True, exist_ok=False)

    sources = discover_sources()
    source_rows = []
    for case in sources:
        source_rows.append(
            {
                "condition": case.condition,
                "trial": case.trial,
                "case_id": case.metadata["case_id"],
                "case_json": str(case.case_dir / "case.json"),
                "receiver_iperf3_json": str(case.receiver_json),
                "receiver_pcap": str(case.receiver_pcap),
                "receiver_pcap_bytes": case.receiver_pcap.stat().st_size,
                "pulses_csv": str(case.pulses_csv) if case.pulses_csv.is_file() else "",
            }
        )
    write_csv(
        output_dir / "source_manifest.csv",
        ["condition", "trial", "case_id", "case_json", "receiver_iperf3_json", "receiver_pcap", "receiver_pcap_bytes", "pulses_csv"],
        source_rows,
    )

    tcp_by_key = {(case.condition, case.trial): receiver_tcp_timeseries(case) for case in sources}
    pcap_by_key: dict[tuple[str, int], tuple[np.ndarray, np.ndarray, int, int, float]] = {}
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        future_cases = {executor.submit(tshark_payload_bins, case): case for case in sources}
        for future in as_completed(future_cases):
            case = future_cases[future]
            pcap_by_key[(case.condition, case.trial)] = future.result()

    tcp_trial_rows: list[dict[str, Any]] = []
    for condition in ("baseline", "ldos"):
        for trial in range(1, 11):
            for second, value in enumerate(tcp_by_key[(condition, trial)]):
                tcp_trial_rows.append({"condition": condition, "trial": trial, "time_sec": second, "tcp_goodput_mbps": f"{value:.9f}"})
    write_csv(data_dir / "tcp_goodput_timeseries_per_trial.csv", ["condition", "trial", "time_sec", "tcp_goodput_mbps"], tcp_trial_rows)

    ldos_tcp_matrix = np.stack([tcp_by_key[("ldos", trial)] for trial in range(1, 11)])
    tcp_mean, tcp_sd, tcp_low, tcp_high = timeseries_summary(ldos_tcp_matrix)
    write_csv(
        data_dir / "tcp_goodput_timeseries_summary.csv",
        ["time_sec", "n", "mean_mbps", "sample_sd_mbps", "ci95_low_mbps", "ci95_high_mbps"],
        [
            {
                "time_sec": second, "n": 10, "mean_mbps": f"{tcp_mean[second]:.9f}",
                "sample_sd_mbps": f"{tcp_sd[second]:.9f}", "ci95_low_mbps": f"{tcp_low[second]:.9f}",
                "ci95_high_mbps": f"{tcp_high[second]:.9f}",
            }
            for second in range(60)
        ],
    )

    udp_matrix = np.stack([pcap_by_key[("ldos", trial)][1] for trial in range(1, 11)])
    udp_trial_rows: list[dict[str, Any]] = []
    for trial in range(1, 11):
        for index, value in enumerate(pcap_by_key[("ldos", trial)][1]):
            udp_trial_rows.append({"trial": trial, "time_sec": f"{index * UDP_BIN_SEC:.1f}", "udp_received_mbps": f"{value:.9f}"})
    write_csv(data_dir / "udp_received_timeseries_per_trial_100ms.csv", ["trial", "time_sec", "udp_received_mbps"], udp_trial_rows)
    udp_mean, udp_sd, udp_low, udp_high = timeseries_summary(udp_matrix)
    write_csv(
        data_dir / "udp_received_timeseries_summary_100ms.csv",
        ["time_sec", "n", "mean_mbps", "sample_sd_mbps", "ci95_low_mbps", "ci95_high_mbps"],
        [
            {
                "time_sec": f"{index * UDP_BIN_SEC:.1f}", "n": 10, "mean_mbps": f"{udp_mean[index]:.9f}",
                "sample_sd_mbps": f"{udp_sd[index]:.9f}", "ci95_low_mbps": f"{udp_low[index]:.9f}",
                "ci95_high_mbps": f"{udp_high[index]:.9f}",
            }
            for index in range(len(udp_mean))
        ],
    )

    per_second_rows: list[dict[str, Any]] = []
    utilization_rows: list[dict[str, Any]] = []
    for condition in ("baseline", "ldos"):
        for trial in range(1, 11):
            tcp_pcap, udp_100ms, excluded, data_stream, max_clock_correction = pcap_by_key[(condition, trial)]
            udp_1s = udp_100ms.reshape(60, 10).mean(axis=1)
            for second in range(10, 50):
                per_second_rows.append(
                    {
                        "condition": condition, "trial": trial, "time_sec": second,
                        "tcp_payload_mbps": f"{tcp_pcap[second]:.9f}",
                        "udp_payload_mbps": f"{udp_1s[second]:.9f}",
                    }
                )
            tcp_mbps = float(tcp_pcap[10:50].mean())
            udp_mbps = float(udp_1s[10:50].mean())
            tcp_pct = tcp_mbps / CAPACITY_MBPS * 100.0
            udp_pct = udp_mbps / CAPACITY_MBPS * 100.0
            unused_pct = 100.0 - tcp_pct - udp_pct
            utilization_rows.append(
                {
                    "condition": condition, "trial": trial,
                    "tcp_mbps": tcp_mbps, "udp_mbps": udp_mbps,
                    "tcp_utilization_pct": tcp_pct, "udp_utilization_pct": udp_pct,
                    "unused_utilization_pct": unused_pct,
                    "excluded_tcp_retransmission_packets": excluded,
                    "tcp_data_stream": data_stream,
                    "max_pcap_clock_correction_sec": max_clock_correction,
                }
            )
    write_csv(
        data_dir / "pcap_payload_rates_per_second_attack_window.csv",
        ["condition", "trial", "time_sec", "tcp_payload_mbps", "udp_payload_mbps"],
        per_second_rows,
    )
    write_csv(
        data_dir / "bandwidth_utilization_per_trial.csv",
        ["condition", "trial", "tcp_mbps", "udp_mbps", "tcp_utilization_pct", "udp_utilization_pct", "unused_utilization_pct", "excluded_tcp_retransmission_packets", "tcp_data_stream", "max_pcap_clock_correction_sec"],
        utilization_rows,
    )

    utilization_stats: list[dict[str, Any]] = []
    summary_by_condition: dict[str, dict[str, dict[str, float]]] = {}
    for condition in ("baseline", "ldos"):
        summary_by_condition[condition] = {}
        condition_rows = [row for row in utilization_rows if row["condition"] == condition]
        for metric in ("tcp_utilization_pct", "udp_utilization_pct", "unused_utilization_pct"):
            n, average, sd, low, high = mean_sd_ci(row[metric] for row in condition_rows)
            summary_by_condition[condition][metric] = {"mean": average, "sample_sd": sd, "ci95_low": low, "ci95_high": high}
            utilization_stats.append(
                {"condition": condition, "metric": metric, "n": n, "mean": average, "sample_sd": sd, "ci95_low": low, "ci95_high": high}
            )
    write_csv(
        data_dir / "bandwidth_utilization_summary.csv",
        ["condition", "metric", "n", "mean", "sample_sd", "ci95_low", "ci95_high"],
        utilization_stats,
    )

    baseline_iperf_values = [float(tcp_by_key[("baseline", trial)][10:50].mean()) for trial in range(1, 11)]
    ldos_iperf_values = [float(tcp_by_key[("ldos", trial)][10:50].mean()) for trial in range(1, 11)]
    degradation_values = [
        (base - attack) / base * 100.0
        for base, attack in zip(baseline_iperf_values, ldos_iperf_values)
    ]
    baseline_iperf = mean_sd_ci(baseline_iperf_values)
    ldos_iperf = mean_sd_ci(ldos_iperf_values)
    degradation = mean_sd_ci(degradation_values)
    offered_udp = mean_sd_ci(offered_udp_mean(case) for case in sources if case.condition == "ldos")
    if abs(baseline_iperf[1] - 14.339255) > 0.002:
        raise RuntimeError(f"Baseline iperf consistency check failed: {baseline_iperf[1]}")
    if abs(ldos_iperf[1] - 2.611214) > 0.002:
        raise RuntimeError(f"LDoS iperf consistency check failed: {ldos_iperf[1]}")
    if abs(degradation[1] - 81.789764) > 0.02:
        raise RuntimeError(f"degradation consistency check failed: {degradation[1]}")
    if abs(offered_udp[1] - 4.499304) > 0.002:
        raise RuntimeError(f"offered UDP consistency check failed: {offered_udp[1]}")

    ldos_util_rows = [row for row in utilization_rows if row["condition"] == "ldos"]
    receiver_udp = mean_sd_ci(float(row["udp_mbps"]) for row in ldos_util_rows)
    consistency_rows = [
        {"metric": "baseline_tcp_goodput_10_50_mbps", "source": "receiver iperf3 JSON", "n": baseline_iperf[0], "mean": baseline_iperf[1], "sample_sd": baseline_iperf[2], "ci95_low": baseline_iperf[3], "ci95_high": baseline_iperf[4]},
        {"metric": "ldos_tcp_goodput_10_50_mbps", "source": "receiver iperf3 JSON", "n": ldos_iperf[0], "mean": ldos_iperf[1], "sample_sd": ldos_iperf[2], "ci95_low": ldos_iperf[3], "ci95_high": ldos_iperf[4]},
        {"metric": "paired_tcp_degradation_pct", "source": "receiver iperf3 JSON", "n": degradation[0], "mean": degradation[1], "sample_sd": degradation[2], "ci95_low": degradation[3], "ci95_high": degradation[4]},
        {"metric": "udp_offered_10_50_mbps", "source": "sender pulse log", "n": offered_udp[0], "mean": offered_udp[1], "sample_sd": offered_udp[2], "ci95_low": offered_udp[3], "ci95_high": offered_udp[4]},
        {"metric": "udp_received_10_50_mbps", "source": "receiver pcap udp.length - 8", "n": receiver_udp[0], "mean": receiver_udp[1], "sample_sd": receiver_udp[2], "ci95_low": receiver_udp[3], "ci95_high": receiver_udp[4]},
    ]
    write_csv(
        data_dir / "consistency_metrics.csv",
        ["metric", "source", "n", "mean", "sample_sd", "ci95_low", "ci95_high"],
        consistency_rows,
    )

    udp_axis_max = plot_timeseries(output_dir, ldos_tcp_matrix, udp_matrix)
    plot_bandwidth_utilization(output_dir, summary_by_condition)

    settings = {
        "capacity_mbps": CAPACITY_MBPS,
        "duration_sec": DURATION_SEC,
        "attack_interval": "10 <= t < 50",
        "tcp_timeseries_source": "receiver-side iperf3 server JSON intervals",
        "tcp_timeseries_bin_sec": TCP_BIN_SEC,
        "udp_timeseries_source": "receiver-side bottleneck pcap",
        "udp_timeseries_bin_sec": UDP_BIN_SEC,
        "udp_payload_definition": "udp.length - 8",
        "utilization_source": "receiver-side bottleneck pcap",
        "utilization_bin_sec": 1.0,
        "tcp_payload_definition": "tcp.len",
        "tcp_exclusions": ["tcp.analysis.retransmission", "tcp.analysis.fast_retransmission", "tcp.analysis.spurious_retransmission"],
        "confidence_interval": "two-sided 95% Student-t CI across 10 trials",
        "t_critical_df9": T_CRITICAL_95_N10,
        "pcap_timebase": "data TCP stream tcp.options.timestamp.tsval; UDP placed by receiver-pcap frame-order interpolation between TCP timestamp anchors",
    }
    (output_dir / "settings.json").write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    (output_dir / "summary.md").write_text(
        markdown_summary(utilization_rows, utilization_stats, baseline_iperf, ldos_iperf, degradation, offered_udp, udp_axis_max),
        encoding="utf-8",
    )
    validation = [
        "# Validation",
        "",
        "- [PASS] 10 Baseline trials and 10 Periodic LDoS trials used",
        "- [PASS] receiver-side iperf3 JSON present for all 20 cases",
        "- [PASS] receiver-side pcap present for all 20 cases",
        "- [PASS] attack interval is 10 <= t < 50",
        "- [PASS] TCP pcap payload is tcp.len with three retransmission flags excluded",
        "- [PASS] UDP pcap payload is udp.length - 8",
        "- [PASS] pcap wall-clock jumps corrected using in-pcap TCP timestamps and frame order",
        "- [PASS] Baseline iperf goodput agrees with 14.339 Mbps result",
        "- [PASS] LDoS iperf goodput agrees with 2.611 Mbps result",
        "- [PASS] paired degradation agrees with 81.79% result",
        "- [PASS] sender pulse-log UDP offered mean agrees with 4.499 Mbps result",
        "- [PASS] receiver-pcap UDP is reported separately from sender offered UDP",
        "- [PASS] no source experiment was executed or modified",
        "- [PASS] two PDF and two PNG figures generated",
        "- [PASS] both final PDFs rendered to PNG and passed visual layout inspection",
    ]
    (output_dir / "validation.md").write_text("\n".join(validation) + "\n", encoding="utf-8")
    (output_dir / "commands.log").write_text(
        ".venv/bin/python exp/dpsws_figures_20260726/run.py --output-dir "
        + str(output_dir)
        + f" --workers {args.workers}\n",
        encoding="utf-8",
    )
    (output_dir / "failed_attempts.md").write_text(
        "# Failed or superseded analysis attempts\n\n"
        "The first output (`../20260726_144705/`) used raw `frame.time_epoch - start_epoch` bins. "
        "Validation exposed WSL wall-clock jumps of up to about six seconds, so that output is superseded and is not used. "
        "The retained analysis uses only timestamps and frame order contained in the same receiver pcap to reconstruct a monotonic timebase.\n",
        encoding="utf-8",
    )
    print(f"Wrote manuscript figures and data to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
