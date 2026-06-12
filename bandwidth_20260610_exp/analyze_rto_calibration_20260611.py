#!/usr/bin/env python3
"""
Analyze the 20260611 RTO calibration grid.

The grid keeps TCP at 5 Mbps and average attack at 5 Mbps while varying attack
peak and bottleneck queue limit.  Bandwidth uses the s2-side post-bottleneck
pcap, receiver direction, and IPv4 total length.  pcap retransmission labels
and direct TCP_INFO RTO/backoff observations are kept separate.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import subprocess
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from analyze_tcp5_attack5_20260611 import (
    ATTACK_VALIDATION_FIELDS,
    DETECTOR_FIELDS,
    RTO_FIELDS,
    TIMESERIES_FIELDS,
    build_timeseries,
    detector_metrics,
    eval_rows,
    format_value,
    mean,
    read_csv,
    read_iperf_receiver_mbps,
    safe_float,
    safe_int,
    validation_status,
    write_csv,
)
from bandwidth_metrics_20260610 import aggregate_seed_stats


CASE_FIELDS = [
    "case_id",
    "condition_id",
    "scenario",
    "seed",
    "peak_mbps",
    "queue_packets",
    "burst_ms",
    "tcp_mbps",
    "baseline_tcp_mbps",
    "tcp_valid",
    "attack_passed_mbps",
    "attack_offered_mbps",
    "attack_valid",
    "idle_mbps",
    "tcp_degradation_pct",
    "qdisc_dropped",
    "qdisc_overlimits",
    "qdisc_requeues",
    "qdisc_backlog",
    "retransmission_status",
    "pcap_retransmission_count",
    "fast_retransmission_count",
    "spurious_retransmission_count",
    "duplicate_ack_count",
    "lost_segment_count",
    "rto_event_count",
    "max_backoff",
    "total_retrans",
    "mean_cwnd",
    "min_cwnd",
    "mean_rtt_ms",
    "FPR",
    "FNR_period",
    "FNR_burst",
    "detection_delay_ms",
    "valid_case",
    "attack_established",
    "detection_evasion_candidate",
]

QDISC_FIELDS = [
    "case_id",
    "condition_id",
    "scenario",
    "seed",
    "interface",
    "configured_queue_packets",
    "qdisc_dropped",
    "qdisc_overlimits",
    "qdisc_requeues",
    "backlog",
    "qdisc_kind",
    "qdisc_rate",
    "raw_after_file",
]

RETRANS_FIELDS = [
    "case_id",
    "condition_id",
    "scenario",
    "seed",
    "status",
    "timestamp_sec",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "retransmission",
    "fast_retransmission",
    "spurious_retransmission",
    "duplicate_ack",
    "lost_segment",
    "event_type",
]

RANKING_FIELDS = [
    "rank",
    "condition_id",
    "peak_mbps",
    "queue_packets",
    "valid_rate",
    "drop_present",
    "tcp_retransmission_present",
    "rto_backoff_present",
    "tcp_degradation_pct",
    "FNR_burst",
    "qdisc_dropped",
    "pcap_retransmission_count",
    "rto_event_count",
    "max_backoff",
    "attack_established",
    "detection_evasion_candidate",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, type=Path)
    parser.add_argument("--bucket-ms", type=float, default=25.0)
    parser.add_argument("--bottleneck-mbps", type=float, default=15.0)
    parser.add_argument("--evaluation-start-sec", type=float, required=True)
    parser.add_argument("--evaluation-end-sec", type=float, required=True)
    parser.add_argument("--tcp-target-mbps", type=float, default=5.0)
    parser.add_argument("--attack-target-mbps", type=float, default=5.0)
    parser.add_argument("--output-tag", default="20260611")
    parser.add_argument("--mode", default="")
    return parser.parse_args()


def discover_cases(results_dir: Path, tag: str) -> list[tuple[Path, dict[str, Any]]]:
    cases_dir = results_dir / "cases"
    output: list[tuple[Path, dict[str, Any]]] = []
    if not cases_dir.exists():
        return output
    for case_dir in sorted(path for path in cases_dir.iterdir() if path.is_dir()):
        meta = case_dir / f"metadata_{tag}.json"
        if meta.exists():
            output.append((case_dir, json.loads(meta.read_text(encoding="utf-8"))))
    return output


def parse_qdisc_text(text: str) -> dict[str, Any]:
    dropped = sum(int(value) for value in re.findall(r"\bdropped\s+(\d+)", text))
    overlimits = sum(int(value) for value in re.findall(r"\boverlimits\s+(\d+)", text))
    requeues = sum(int(value) for value in re.findall(r"\brequeues\s+(\d+)\)", text))
    backlog = re.search(r"\bbacklog\s+([^\n]+)", text)
    kind = re.search(r"\bqdisc\s+(\S+)", text)
    rate = re.search(r"\brate\s+([0-9.]+\s*[kKmMgG]?bit)", text)
    return {
        "qdisc_dropped": dropped,
        "qdisc_overlimits": overlimits,
        "qdisc_requeues": requeues,
        "backlog": backlog.group(1).strip() if backlog else "",
        "qdisc_kind": kind.group(1) if kind else "",
        "qdisc_rate": rate.group(1).replace(" ", "") if rate else "",
    }


def qdisc_metrics(case_dir: Path, metadata: dict[str, Any], tag: str) -> dict[str, Any]:
    case_id = str(metadata.get("case_id", case_dir.name))
    iface = str(metadata.get("shaping_interface") or metadata.get("capture_ingress_iface") or "")
    after_file = ""
    text = ""
    state = metadata.get("tc_qdisc_state_after", {})
    iface_state = state.get("interfaces", {}).get(iface, {}) if isinstance(state, dict) else {}
    files = iface_state.get("files", {}) if isinstance(iface_state, dict) else {}
    qdisc_text = ""
    class_text = ""
    for key in ("tc_s_d_qdisc_show", "tc_s_qdisc_show", "tc_d_qdisc_show"):
        path_text = files.get(key, "")
        if path_text and Path(path_text).exists():
            after_file = after_file or path_text
            qdisc_text = Path(path_text).read_text(encoding="utf-8", errors="replace")
            break
    for key in ("tc_s_d_class_show", "tc_s_class_show", "tc_d_class_show"):
        path_text = files.get(key, "")
        if path_text and Path(path_text).exists():
            after_file = after_file or path_text
            class_text = Path(path_text).read_text(encoding="utf-8", errors="replace")
            break
    text = qdisc_text or class_text
    parsed = parse_qdisc_text(text)
    class_parsed = parse_qdisc_text(class_text)
    if class_parsed.get("qdisc_rate"):
        parsed["qdisc_rate"] = class_parsed["qdisc_rate"]
    if parsed["qdisc_dropped"] == 0:
        parsed["qdisc_dropped"] = safe_int(metadata.get("qdisc_dropped_packets"), 0)
    if parsed["qdisc_overlimits"] == 0:
        parsed["qdisc_overlimits"] = safe_int(metadata.get("qdisc_overlimits"), 0)
    if parsed["qdisc_requeues"] == 0:
        parsed["qdisc_requeues"] = safe_int(metadata.get("qdisc_requeues"), 0)
    return {
        "case_id": case_id,
        "condition_id": metadata.get("condition_id", ""),
        "scenario": metadata.get("scenario", ""),
        "seed": metadata.get("seed", ""),
        "interface": iface,
        "configured_queue_packets": metadata.get("configured_queue_packets", ""),
        "qdisc_dropped": parsed["qdisc_dropped"],
        "qdisc_overlimits": parsed["qdisc_overlimits"],
        "qdisc_requeues": parsed["qdisc_requeues"],
        "backlog": parsed["backlog"] or metadata.get("qdisc_backlog", ""),
        "qdisc_kind": parsed["qdisc_kind"] or metadata.get("qdisc_kind", ""),
        "qdisc_rate": parsed["qdisc_rate"] or metadata.get("qdisc_rate", ""),
        "raw_after_file": after_file,
    }


def tshark_retransmission_events(case_dir: Path, metadata: dict[str, Any], tag: str) -> tuple[list[dict[str, Any]], str]:
    tshark = shutil.which("tshark")
    case_id = str(metadata.get("case_id", case_dir.name))
    base = {
        "case_id": case_id,
        "condition_id": metadata.get("condition_id", ""),
        "scenario": metadata.get("scenario", ""),
        "seed": metadata.get("seed", ""),
    }
    if tshark is None:
        return [{**base, "status": "unavailable"}], "unavailable"
    pcap = metadata.get("capture_egress_pcap")
    if not pcap or not Path(str(pcap)).exists():
        return [{**base, "status": "missing_pcap"}], "missing_pcap"
    display_filter = (
        "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || "
        "tcp.analysis.spurious_retransmission || tcp.analysis.duplicate_ack || "
        "tcp.analysis.lost_segment"
    )
    command = [
        tshark,
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
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
        "tcp.analysis.retransmission",
        "-e",
        "tcp.analysis.fast_retransmission",
        "-e",
        "tcp.analysis.spurious_retransmission",
        "-e",
        "tcp.analysis.duplicate_ack",
        "-e",
        "tcp.analysis.lost_segment",
        "-E",
        "separator=,",
        "-E",
        "occurrence=f",
    ]
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode not in (0, 1):
        return [{**base, "status": "tshark_error", "event_type": proc.stderr.strip()[:200]}], "tshark_error"
    origin = safe_float(metadata.get("experiment_start_wall"), math.nan)
    if math.isnan(origin):
        origin = safe_float(metadata.get("case_start_epoch_ns"), 0.0) / 1_000_000_000.0
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = line.split(",")
        parts += [""] * (10 - len(parts))
        flags = {
            "retransmission": int(bool(parts[5])),
            "fast_retransmission": int(bool(parts[6])),
            "spurious_retransmission": int(bool(parts[7])),
            "duplicate_ack": int(bool(parts[8])),
            "lost_segment": int(bool(parts[9])),
        }
        event_type = ",".join(name for name, value in flags.items() if value)
        rows.append(
            {
                **base,
                "status": "ok",
                "timestamp_sec": safe_float(parts[0]) - origin,
                "source_ip": parts[1],
                "source_port": parts[2],
                "destination_ip": parts[3],
                "destination_port": parts[4],
                **flags,
                "event_type": event_type,
            }
        )
    return rows, "ok"


def tcp_info_summary(case_dir: Path, metadata: dict[str, Any], tag: str) -> dict[str, Any]:
    case_id = str(metadata.get("case_id", case_dir.name))
    path = case_dir / "raw" / "tcp_info" / case_id / f"tcp_info_timeseries_{tag}.csv"
    rows = read_csv(path)
    receiver_ip = str(metadata.get("receiver_ip", "10.0.0.2"))
    receiver_port = str(metadata.get("iperf_port", 5201))
    valid = [
        row
        for row in rows
        if str(row.get("destination_ip")) == receiver_ip and str(row.get("destination_port")) == receiver_port
    ]
    return {
        "total_retrans": max((safe_int(row.get("total_retrans"), 0) for row in valid), default=0),
        "mean_cwnd": mean(safe_float(row.get("cwnd")) for row in valid),
        "min_cwnd": min((safe_float(row.get("cwnd")) for row in valid if not math.isnan(safe_float(row.get("cwnd")))), default=math.nan),
        "mean_rtt_ms": mean(safe_float(row.get("rtt_ms")) for row in valid),
    }


def status_valid(error_pct: float) -> int:
    return int(validation_status(error_pct) in {"matched", "warning"})


def build_case_and_validation_rows(
    case_dir: Path,
    metadata: dict[str, Any],
    timeseries: list[dict[str, Any]],
    detector_row: dict[str, Any],
    rto_rows: list[dict[str, Any]],
    qdisc_row: dict[str, Any],
    retrans_rows: list[dict[str, Any]],
    retrans_status: str,
    tcp_info: dict[str, Any],
    baseline_by_condition: dict[str, float],
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    selected = eval_rows(timeseries, args.evaluation_start_sec, args.evaluation_end_sec)
    scenario = str(metadata.get("scenario", ""))
    condition_id = str(metadata.get("condition_id", ""))
    tcp_mbps = mean(safe_float(row.get("tcp_mbps")) for row in selected)
    attack_passed = mean(safe_float(row.get("attack_mbps")) for row in selected)
    attack_offered = mean(safe_float(row.get("attack_offered_mbps")) for row in selected)
    idle_mbps = mean(safe_float(row.get("idle_mbps")) for row in selected)
    baseline = baseline_by_condition.get(condition_id, math.nan)
    iperf_tcp = read_iperf_receiver_mbps(case_dir, args.output_tag)
    tcp_error = 100.0 * (iperf_tcp - args.tcp_target_mbps) / args.tcp_target_mbps if scenario == "no_attack" else math.nan
    attack_rate_for_validation = attack_offered if not math.isnan(attack_offered) else attack_passed
    attack_error = (
        100.0 * (attack_rate_for_validation - args.attack_target_mbps) / args.attack_target_mbps
        if scenario != "no_attack"
        else math.nan
    )
    tcp_valid = status_valid(tcp_error) if scenario == "no_attack" else 1
    attack_valid = status_valid(attack_error) if scenario != "no_attack" else 1
    degradation = 100.0 * (1.0 - tcp_mbps / baseline) if baseline > 0 and scenario != "no_attack" else 0.0 if scenario == "no_attack" else math.nan
    pcap_retrans = sum(safe_int(row.get("retransmission"), 0) for row in retrans_rows if row.get("status") == "ok")
    fast_retrans = sum(safe_int(row.get("fast_retransmission"), 0) for row in retrans_rows if row.get("status") == "ok")
    spurious = sum(safe_int(row.get("spurious_retransmission"), 0) for row in retrans_rows if row.get("status") == "ok")
    dup_ack = sum(safe_int(row.get("duplicate_ack"), 0) for row in retrans_rows if row.get("status") == "ok")
    lost = sum(safe_int(row.get("lost_segment"), 0) for row in retrans_rows if row.get("status") == "ok")
    max_backoff = max((safe_int(row.get("backoff"), 0) for row in selected), default=0)
    valid_case = int((scenario == "no_attack" and tcp_valid) or (scenario != "no_attack" and attack_valid and not math.isnan(baseline)))
    attack_established = int(
        scenario != "no_attack"
        and valid_case
        and safe_int(qdisc_row.get("qdisc_dropped"), 0) > 0
        and (pcap_retrans > 0 or len(rto_rows) > 0 or max_backoff > 0)
        and degradation > 0
    )
    evasion = int(attack_established and safe_float(detector_row.get("FNR_burst")) >= 0.5)
    case_row = {
        "case_id": metadata.get("case_id", case_dir.name),
        "condition_id": condition_id,
        "scenario": scenario,
        "seed": metadata.get("seed", ""),
        "peak_mbps": metadata.get("peak_rate_mbps", ""),
        "queue_packets": metadata.get("configured_queue_packets", ""),
        "burst_ms": metadata.get("burst_ms", ""),
        "tcp_mbps": tcp_mbps,
        "baseline_tcp_mbps": baseline,
        "tcp_valid": tcp_valid,
        "attack_passed_mbps": attack_passed,
        "attack_offered_mbps": attack_offered,
        "attack_valid": attack_valid,
        "idle_mbps": idle_mbps,
        "tcp_degradation_pct": degradation,
        "qdisc_dropped": qdisc_row.get("qdisc_dropped", ""),
        "qdisc_overlimits": qdisc_row.get("qdisc_overlimits", ""),
        "qdisc_requeues": qdisc_row.get("qdisc_requeues", ""),
        "qdisc_backlog": qdisc_row.get("backlog", ""),
        "retransmission_status": retrans_status,
        "pcap_retransmission_count": pcap_retrans if retrans_status == "ok" else "",
        "fast_retransmission_count": fast_retrans if retrans_status == "ok" else "",
        "spurious_retransmission_count": spurious if retrans_status == "ok" else "",
        "duplicate_ack_count": dup_ack if retrans_status == "ok" else "",
        "lost_segment_count": lost if retrans_status == "ok" else "",
        "rto_event_count": len(rto_rows),
        "max_backoff": max_backoff,
        "total_retrans": tcp_info.get("total_retrans", ""),
        "mean_cwnd": tcp_info.get("mean_cwnd", ""),
        "min_cwnd": tcp_info.get("min_cwnd", ""),
        "mean_rtt_ms": tcp_info.get("mean_rtt_ms", ""),
        "FPR": detector_row.get("FPR", math.nan) if scenario == "no_attack" else math.nan,
        "FNR_period": detector_row.get("FNR", math.nan) if scenario != "no_attack" else math.nan,
        "FNR_burst": detector_row.get("FNR_burst", math.nan) if scenario != "no_attack" else math.nan,
        "detection_delay_ms": detector_row.get("detection_delay_ms", math.nan) if scenario != "no_attack" else math.nan,
        "valid_case": valid_case,
        "attack_established": attack_established,
        "detection_evasion_candidate": evasion,
    }
    attack_row = {
        "case_id": case_row["case_id"],
        "scenario": scenario,
        "condition_id": condition_id,
        "seed": case_row["seed"],
        "configured_average_attack_mbps": metadata.get("configured_average_attack_mbps", ""),
        "measured_total_attack_offered_mbps": attack_offered,
        "measured_total_attack_passed_mbps": attack_passed,
        "measured_pulse_attack_passed_mbps": mean(safe_float(row.get("attack_mbps")) for row in selected if safe_int(row.get("pulse_active"), 0)),
        "attack_rate_error_pct": attack_error,
        "attack_rate_match_status": validation_status(attack_error) if scenario != "no_attack" else "",
    }
    tcp_row = {
        "case_id": case_row["case_id"],
        "seed": case_row["seed"],
        "target_tcp_mbps": args.tcp_target_mbps,
        "iperf_tcp_receiver_mbps": iperf_tcp,
        "pcap_tcp_mbps": tcp_mbps,
        "tcp_rate_error_pct": tcp_error,
        "tcp_rate_match_status": validation_status(tcp_error) if scenario == "no_attack" else "",
    }
    return case_row, attack_row, tcp_row


def ranking(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    periodic = [row for row in case_rows if row.get("scenario") == "periodic_ldos"]

    def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
        valid = safe_int(row.get("valid_case"), 0) == 1 and safe_int(row.get("attack_valid"), 0) == 1
        drop = safe_int(row.get("qdisc_dropped"), 0) > 0
        retrans = safe_int(row.get("pcap_retransmission_count"), 0) > 0
        rto = safe_int(row.get("rto_event_count"), 0) > 0 or safe_int(row.get("max_backoff"), 0) > 0
        return (
            int(valid),
            int(drop),
            int(retrans),
            int(rto),
            safe_float(row.get("tcp_degradation_pct"), -math.inf),
            -safe_float(row.get("peak_mbps"), math.inf),
            safe_float(row.get("queue_packets"), -math.inf),
        )

    ranked = sorted(periodic, key=sort_key, reverse=True)
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(ranked, start=1):
        rows.append(
            {
                "rank": index,
                "condition_id": row.get("condition_id", ""),
                "peak_mbps": row.get("peak_mbps", ""),
                "queue_packets": row.get("queue_packets", ""),
                "valid_rate": int(safe_int(row.get("valid_case"), 0) == 1 and safe_int(row.get("attack_valid"), 0) == 1),
                "drop_present": int(safe_int(row.get("qdisc_dropped"), 0) > 0),
                "tcp_retransmission_present": int(safe_int(row.get("pcap_retransmission_count"), 0) > 0),
                "rto_backoff_present": int(safe_int(row.get("rto_event_count"), 0) > 0 or safe_int(row.get("max_backoff"), 0) > 0),
                "tcp_degradation_pct": row.get("tcp_degradation_pct", ""),
                "FNR_burst": row.get("FNR_burst", ""),
                "qdisc_dropped": row.get("qdisc_dropped", ""),
                "pcap_retransmission_count": row.get("pcap_retransmission_count", ""),
                "rto_event_count": row.get("rto_event_count", ""),
                "max_backoff": row.get("max_backoff", ""),
                "attack_established": row.get("attack_established", ""),
                "detection_evasion_candidate": row.get("detection_evasion_candidate", ""),
            }
        )
    return rows


def aggregate_case_rows(case_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics = [
        "tcp_mbps",
        "attack_passed_mbps",
        "idle_mbps",
        "tcp_degradation_pct",
        "qdisc_dropped",
        "pcap_retransmission_count",
        "rto_event_count",
        "max_backoff",
        "FPR",
        "FNR_period",
        "FNR_burst",
    ]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in case_rows:
        groups[(str(row.get("condition_id", "")), str(row.get("scenario", "")))].append(row)
    output: list[dict[str, Any]] = []
    for (condition_id, scenario), group in sorted(groups.items()):
        out: dict[str, Any] = {"condition_id": condition_id, "scenario": scenario, "n_cases": len(group)}
        for metric in metrics:
            stats = aggregate_seed_stats(safe_float(row.get(metric), math.nan) for row in group)
            out[f"{metric}_mean"] = stats["mean"]
        output.append(out)
    return output


def get_matplotlib():
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except Exception:
        return None


def write_figures(results_dir: Path, case_rows: list[dict[str, Any]], timeseries: list[dict[str, Any]], rto_rows: list[dict[str, Any]], retrans_rows: list[dict[str, Any]], rank_rows: list[dict[str, Any]], tag: str) -> list[Path]:
    plt = get_matplotlib()
    if plt is None:
        return []
    fig_dir = results_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    output: list[Path] = []
    periodic = [row for row in case_rows if row.get("scenario") == "periodic_ldos"]
    peaks = sorted({safe_float(row.get("peak_mbps")) for row in periodic if not math.isnan(safe_float(row.get("peak_mbps")))})
    queues = sorted({safe_int(row.get("queue_packets")) for row in periodic if safe_int(row.get("queue_packets")) > 0})
    if peaks and queues:
        fig, ax = plt.subplots(figsize=(12, 6))
        values = [[math.nan for _ in peaks] for _ in queues]
        by_cell = {(safe_float(row.get("peak_mbps")), safe_int(row.get("queue_packets"))): row for row in periodic}
        for yi, queue in enumerate(queues):
            for xi, peak in enumerate(peaks):
                row = by_cell.get((peak, queue))
                if not row:
                    continue
                deg = safe_float(row.get("tcp_degradation_pct"))
                values[yi][xi] = deg
        image = ax.imshow(values, cmap="YlOrRd", aspect="auto")
        ax.set_xticks(range(len(peaks)))
        ax.set_xticklabels([f"{peak:g}" for peak in peaks])
        ax.set_yticks(range(len(queues)))
        ax.set_yticklabels([str(queue) for queue in queues])
        ax.set_xlabel("attack peak Mbps")
        ax.set_ylabel("queue packets")
        ax.set_title("RTO calibration heatmap: degradation with drop/retrans/RTO/FNR")
        fig.colorbar(image, ax=ax, label="TCP degradation %")
        for yi, queue in enumerate(queues):
            for xi, peak in enumerate(peaks):
                row = by_cell.get((peak, queue))
                if not row:
                    continue
                text = (
                    f"drop {safe_int(row.get('qdisc_dropped'))}\n"
                    f"ret {safe_int(row.get('pcap_retransmission_count'))}\n"
                    f"RTO {safe_int(row.get('rto_event_count'))}/{safe_int(row.get('max_backoff'))}\n"
                    f"deg {safe_float(row.get('tcp_degradation_pct'), 0.0):.1f}%\n"
                    f"FNRb {100.0 * safe_float(row.get('FNR_burst'), 0.0):.0f}%"
                )
                ax.text(xi, yi, text, ha="center", va="center", fontsize=8)
        base = fig_dir / f"01_peak_queue_heatmap_{tag}"
        plt.tight_layout()
        plt.savefig(base.with_suffix(".png"), dpi=180)
        plt.savefig(base.with_suffix(".pdf"))
        plt.close(fig)
        output.append(base.with_suffix(".png"))

    best_condition = str(rank_rows[0].get("condition_id", "")) if rank_rows else ""
    best_case = next((row for row in periodic if row.get("condition_id") == best_condition), periodic[0] if periodic else None)
    if best_case:
        case_id = str(best_case.get("case_id"))
        rows = [row for row in timeseries if row.get("case_id") == case_id]
        events = [row for row in rto_rows if row.get("case_id") == case_id]
        retrans = [row for row in retrans_rows if row.get("case_id") == case_id and row.get("status") == "ok"]
        fig, ax1 = plt.subplots(figsize=(12, 6))
        x = [safe_float(row.get("timestamp_sec")) for row in rows]
        ax1.plot(x, [safe_float(row.get("tcp_mbps")) for row in rows], label="TCP", color="#4C78A8")
        ax1.plot(x, [safe_float(row.get("attack_mbps")) for row in rows], label="Attack", color="#E45756")
        ax1.fill_between(x, 0, [2.0 if safe_int(row.get("pulse_active")) else 0.0 for row in rows], color="#E45756", alpha=0.15, label="pulse")
        ax1.scatter([safe_float(row.get("timestamp_sec")) for row in retrans], [0.4] * len(retrans), label="pcap retrans", color="#111111", s=18)
        ax1.scatter([safe_float(row.get("timestamp_sec")) for row in events], [0.8] * len(events), label="RTO/backoff", color="#B279A2", s=20)
        ax1.scatter(
            [safe_float(row.get("timestamp_sec")) for row in rows if safe_int(row.get("detector_attack"))],
            [1.2 for row in rows if safe_int(row.get("detector_attack"))],
            label="detector",
            color="#72B7B2",
            s=8,
        )
        ax1.set_xlabel("time [s]")
        ax1.set_ylabel("Mbps / event markers")
        ax2 = ax1.twinx()
        ax2.plot(x, [safe_float(row.get("cwnd")) for row in rows], label="cwnd", color="#F58518", alpha=0.8)
        ax2.plot(x, [safe_float(row.get("backoff")) for row in rows], label="backoff", color="#54A24B", alpha=0.8)
        ax2.set_ylabel("cwnd / backoff")
        ax1.set_title(f"Best RTO calibration candidate: {best_condition} (drop={safe_int(best_case.get('qdisc_dropped'))})")
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, frameon=False, ncol=4, loc="upper right")
        ax1.grid(alpha=0.25)
        base = fig_dir / f"02_best_condition_timeseries_{tag}"
        plt.tight_layout()
        plt.savefig(base.with_suffix(".png"), dpi=180)
        plt.savefig(base.with_suffix(".pdf"))
        plt.close(fig)
        output.append(base.with_suffix(".png"))
    return output


def compact_zip_path(results_dir: Path, tag: str) -> Path:
    timestamp = results_dir.name.split(f"{tag}_")[-1] if f"{tag}_" in results_dir.name else ""
    suffix = f"_{timestamp}" if timestamp else ""
    return results_dir / f"rto_calibration_chatgpt_compact_{tag}{suffix}.zip"


def write_summary(results_dir: Path, case_rows: list[dict[str, Any]], rank_rows: list[dict[str, Any]], failed_cases: list[str], args: argparse.Namespace) -> Path:
    path = results_dir / f"summary_rto_calibration_{args.output_tag}.md"
    best = rank_rows[0] if rank_rows else {}
    lines = [
        "# RTO calibration summary 20260611",
        "",
        "## Config",
        "",
        f"- bottleneck: {args.bottleneck_mbps} Mbps",
        f"- TCP target: {args.tcp_target_mbps} Mbps, 1 iperf3 TCP flow",
        f"- average attack target: {args.attack_target_mbps} Mbps",
        "- period: 1000 ms",
        "- burst_ms = 1000 * 5 / peak",
        f"- evaluation: {args.evaluation_start_sec} <= t < {args.evaluation_end_sec}",
        "",
        "## Best candidate",
        "",
        f"- condition: {best.get('condition_id', '')}",
        f"- peak Mbps: {best.get('peak_mbps', '')}",
        f"- queue packets: {best.get('queue_packets', '')}",
        f"- drops: {best.get('qdisc_dropped', '')}",
        f"- pcap retransmissions: {best.get('pcap_retransmission_count', '')}",
        f"- RTO events: {best.get('rto_event_count', '')}",
        f"- max backoff: {best.get('max_backoff', '')}",
        f"- TCP degradation %: {format_value(best.get('tcp_degradation_pct', ''))}",
        f"- FNR_burst: {format_value(best.get('FNR_burst', ''))}",
        "",
        "## Ranking",
        "",
        "| rank | condition | peak | queue | valid | drop | retrans | RTO/backoff | TCP degradation % | FNR_burst | established | evasion candidate |",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rank_rows:
        lines.append(
            f"| {row.get('rank')} | {row.get('condition_id')} | {row.get('peak_mbps')} | {row.get('queue_packets')} | "
            f"{row.get('valid_rate')} | {row.get('drop_present')} | {row.get('tcp_retransmission_present')} | "
            f"{row.get('rto_backoff_present')} | {format_value(row.get('tcp_degradation_pct'))} | "
            f"{format_value(row.get('FNR_burst'))} | {row.get('attack_established')} | {row.get('detection_evasion_candidate')} |"
        )
    lines.extend(["", "## Failed cases", ""])
    if failed_cases:
        lines.extend(f"- {case}" for case in failed_cases)
    else:
        lines.append("- none")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_zip(results_dir: Path, tag: str, summary_path: Path, figure_paths: list[Path]) -> Path:
    zip_path = compact_zip_path(results_dir, tag)
    include = [
        summary_path,
        results_dir / f"experiment_config_rto_calibration_{tag}.json",
        results_dir / f"manifest_rto_calibration_{tag}.json",
        results_dir / f"failed_cases_{tag}.txt",
        results_dir / "csv" / f"case_metrics_{tag}.csv",
        results_dir / "csv" / f"qdisc_metrics_{tag}.csv",
        results_dir / "csv" / f"retransmission_events_{tag}.csv",
        results_dir / "csv" / f"rto_events_{tag}.csv",
        results_dir / "csv" / f"detector_metrics_{tag}.csv",
        results_dir / "csv" / f"attack_rate_validation_{tag}.csv",
        results_dir / "csv" / f"tcp_rate_validation_{tag}.csv",
        results_dir / "csv" / f"ranking_{tag}.csv",
        results_dir / "csv" / f"aggregated_metrics_{tag}.csv",
    ]
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        for path in include:
            if path.exists():
                handle.write(path, path.relative_to(results_dir))
        for path in figure_paths:
            if path.exists():
                handle.write(path, path.relative_to(results_dir))
    return zip_path


def main() -> int:
    args = parse_args()
    results_dir = args.results_dir
    csv_dir = results_dir / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    cases = discover_cases(results_dir, args.output_tag)

    all_timeseries: list[dict[str, Any]] = []
    detector_rows: list[dict[str, Any]] = []
    qdisc_rows: list[dict[str, Any]] = []
    retrans_rows: list[dict[str, Any]] = []
    rto_rows: list[dict[str, Any]] = []
    per_case: list[tuple[Path, dict[str, Any], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], str, dict[str, Any]]] = []

    for case_dir, metadata in cases:
        timeseries, drow, events = build_timeseries(case_dir, metadata, args)
        qrow = qdisc_metrics(case_dir, metadata, args.output_tag)
        trows, tstatus = tshark_retransmission_events(case_dir, metadata, args.output_tag)
        info = tcp_info_summary(case_dir, metadata, args.output_tag)
        all_timeseries.extend(timeseries)
        detector_rows.append(drow)
        qdisc_rows.append(qrow)
        retrans_rows.extend(trows)
        rto_rows.extend(events)
        per_case.append((case_dir, metadata, timeseries, drow, events, qrow, trows, tstatus, info))

    baseline_by_condition: dict[str, float] = {}
    for _case_dir, metadata, timeseries, *_rest in per_case:
        if metadata.get("scenario") == "no_attack":
            selected = eval_rows(timeseries, args.evaluation_start_sec, args.evaluation_end_sec)
            baseline_by_condition[str(metadata.get("condition_id", ""))] = mean(safe_float(row.get("tcp_mbps")) for row in selected)

    case_rows: list[dict[str, Any]] = []
    attack_rows: list[dict[str, Any]] = []
    tcp_rows: list[dict[str, Any]] = []
    for case_dir, metadata, timeseries, drow, events, qrow, trows, tstatus, info in per_case:
        case_row, attack_row, tcp_row = build_case_and_validation_rows(
            case_dir,
            metadata,
            timeseries,
            drow,
            events,
            qrow,
            trows,
            tstatus,
            info,
            baseline_by_condition,
            args,
        )
        case_rows.append(case_row)
        attack_rows.append(attack_row)
        if metadata.get("scenario") == "no_attack":
            tcp_rows.append(tcp_row)

    rank_rows = ranking(case_rows)
    aggregate_rows = aggregate_case_rows(case_rows)
    aggregate_fields = list(aggregate_rows[0].keys()) if aggregate_rows else ["condition_id", "scenario", "n_cases"]

    write_csv(csv_dir / f"bandwidth_timeseries_{args.output_tag}.csv", TIMESERIES_FIELDS, all_timeseries)
    write_csv(csv_dir / f"case_metrics_{args.output_tag}.csv", CASE_FIELDS, case_rows)
    write_csv(csv_dir / f"qdisc_metrics_{args.output_tag}.csv", QDISC_FIELDS, qdisc_rows)
    write_csv(csv_dir / f"retransmission_events_{args.output_tag}.csv", RETRANS_FIELDS, retrans_rows)
    write_csv(csv_dir / f"rto_events_{args.output_tag}.csv", RTO_FIELDS, rto_rows)
    write_csv(csv_dir / f"detector_metrics_{args.output_tag}.csv", DETECTOR_FIELDS, detector_rows)
    write_csv(csv_dir / f"attack_rate_validation_{args.output_tag}.csv", ATTACK_VALIDATION_FIELDS, attack_rows)
    write_csv(csv_dir / f"tcp_rate_validation_{args.output_tag}.csv", ["case_id", "seed", "target_tcp_mbps", "iperf_tcp_receiver_mbps", "pcap_tcp_mbps", "tcp_rate_error_pct", "tcp_rate_match_status"], tcp_rows)
    write_csv(csv_dir / f"ranking_{args.output_tag}.csv", RANKING_FIELDS, rank_rows)
    write_csv(csv_dir / f"aggregated_metrics_{args.output_tag}.csv", aggregate_fields, aggregate_rows)

    failed_path = results_dir / f"failed_cases_{args.output_tag}.txt"
    failed_cases = [line.strip() for line in failed_path.read_text(encoding="utf-8").splitlines()] if failed_path.exists() else []
    if not failed_path.exists():
        failed_path.write_text("", encoding="utf-8")

    figure_paths = write_figures(results_dir, case_rows, all_timeseries, rto_rows, retrans_rows, rank_rows, args.output_tag)
    summary_path = write_summary(results_dir, case_rows, rank_rows, failed_cases, args)
    config = {
        "mode": args.mode,
        "bottleneck_mbps": args.bottleneck_mbps,
        "tcp_target_mbps": args.tcp_target_mbps,
        "attack_average_target_mbps": args.attack_target_mbps,
        "period_ms": 1000,
        "peak_grid_mbps": [15, 30, 45, 60],
        "queue_grid_packets": [50, 100, 200],
        "burst_formula": "burst_ms = 1000 * 5 / peak_mbps",
        "evaluation_start_sec": args.evaluation_start_sec,
        "evaluation_end_sec": args.evaluation_end_sec,
        "primary_metric": "s2 egress pcap, receiver direction, IPv4 total length",
    }
    (results_dir / f"experiment_config_rto_calibration_{args.output_tag}.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    zip_path = compact_zip_path(results_dir, args.output_tag)
    manifest = {
        "output_tag": args.output_tag,
        "results_dir": str(results_dir),
        "case_count": len(case_rows),
        "failed_cases": failed_cases,
        "csv_outputs": sorted(str(path.relative_to(results_dir)) for path in csv_dir.glob(f"*_{args.output_tag}.csv")),
        "figure_outputs": sorted(str(path.relative_to(results_dir)) for path in (results_dir / "figures").glob(f"*_{args.output_tag}.png")),
        "summary": str(summary_path.relative_to(results_dir)),
        "chatgpt_zip": str(zip_path),
    }
    (results_dir / f"manifest_rto_calibration_{args.output_tag}.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write_zip(results_dir, args.output_tag, summary_path, figure_paths)
    print(f"Wrote RTO calibration outputs to {results_dir}")
    print(f"ChatGPT ZIP: {zip_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
