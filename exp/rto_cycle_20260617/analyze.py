#!/usr/bin/env python3
"""Analyze RTO-cycle experiment outputs and build sharing archives."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Iterable


TARGET_TCP_PORT = 5201
SENDER_IP = "10.0.1.1"
RECEIVER_IP = "10.0.2.1"
SS_HEADER_RE = re.compile(r"^=== sample (?P<idx>\d+) epoch (?P<epoch>\d+(?:\.\d+)?) rc (?P<rc>-?\d+) ===$")
TIMELINE_FIELDS = [
    "case",
    "time_sec",
    "phase",
    "rto_ms",
    "backoff",
    "cwnd",
    "ssthresh",
    "unacked",
    "retransmits",
    "total_retrans",
    "rtt_ms",
    "rttvar_ms",
    "pulse_active",
    "pulse_index",
    "pulse_phase_ms",
]
EVENT_FIELDS = [
    "case",
    "event_time_sec",
    "source",
    "classification",
    "pcap_retransmission",
    "fast_retransmission",
    "duplicate_ack_nearby",
    "retrans_interval_sec",
    "sender_rto_ms",
    "sender_backoff",
    "timeouts_delta",
    "pulse_active",
    "reason",
]
SUMMARY_FIELDS = [
    "case",
    "period_ms",
    "rto_status",
    "timing_status",
    "timing_violations",
    "ss_samples",
    "pulse_count",
    "confirmed_events",
    "probable_events",
    "not_observed_events",
    "unknown_events",
    "tcp_timeouts_delta",
    "tcp_retrans_segs_delta",
    "max_backoff",
    "max_rto_ms",
    "mean_cwnd",
    "iperf_receiver_mbps",
    "iperf_retransmits",
    "qdisc_dropped_delta",
]


@dataclass
class SsSample:
    case: str
    epoch: float
    rel_time: float
    state: str = ""
    rto_ms: float = math.nan
    backoff: int = 0
    cwnd: float = math.nan
    ssthresh: float = math.nan
    unacked: float = math.nan
    retransmits: float = math.nan
    total_retrans: float = math.nan
    rtt_ms: float = math.nan
    rttvar_ms: float = math.nan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    analyze_run(args.output_dir)


def analyze_run(output_dir: Path) -> None:
    output_dir = output_dir.resolve()
    config = json.loads((output_dir / "config.json").read_text(encoding="utf-8"))
    manifest_path = output_dir / "manifest.txt"
    timeline_rows: list[dict[str, Any]] = []
    event_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []

    for case_cfg in config["cases"]:
        case = case_cfg["case"]
        case_dir = output_dir / "cases" / case
        case_meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        raw_dir = case_dir / "raw"
        pulses = read_csv(raw_dir / "pulses.csv")
        samples = parse_ss_samples(raw_dir / "ss_raw.log", case, float(case_meta["start_epoch"]))
        write_ss_samples(case_dir / "ss_samples.csv", samples, pulses, config)
        nstat_delta = nstat_diff(raw_dir / "nstat_before.txt", raw_dir / "nstat_after.txt")
        write_key_values(case_dir / "nstat_delta.csv", nstat_delta)
        qdisc_summary = qdisc_diff(raw_dir / "qdisc_before.txt", raw_dir / "qdisc_after.txt")
        write_rows(case_dir / "qdisc_summary.csv", qdisc_summary)
        pcap_events = extract_pcap_events(raw_dir / "bottleneck_after.pcap", float(case_meta["start_epoch"]))
        sender_events = detect_sender_rto_events(samples)
        events = classify_retransmission_events(case, pcap_events, sender_events, samples, pulses, nstat_delta)
        if not events and sender_events:
            events = sender_events_to_rows(case, sender_events, nstat_delta)
        for row in build_timeline(case, samples, pulses, config):
            timeline_rows.append(row)
        event_rows.extend(events)
        summary_rows.append(build_summary_row(case, case_cfg, raw_dir, samples, pulses, events, nstat_delta, qdisc_summary))

    write_rows(output_dir / "timeline.csv", timeline_rows, TIMELINE_FIELDS)
    write_rows(output_dir / "retrans_events.csv", event_rows, EVENT_FIELDS)
    write_rows(output_dir / "summary.csv", summary_rows, SUMMARY_FIELDS)
    write_report(output_dir / "report.md", config, summary_rows, event_rows)
    create_archives(output_dir, str(config.get("run_id", output_dir.name)), manifest_path)
    print(f"Wrote analysis outputs under {output_dir}")


def parse_ss_samples(path: Path, case: str, start_epoch: float) -> list[SsSample]:
    if not path.exists():
        return []
    samples: list[SsSample] = []
    current_epoch: float | None = None
    state_line = ""
    info_parts: list[str] = []

    def flush() -> None:
        nonlocal state_line, info_parts, current_epoch
        if current_epoch is None:
            return
        if state_line or info_parts:
            samples.append(build_ss_sample(case, current_epoch, start_epoch, state_line, " ".join(info_parts)))
        state_line = ""
        info_parts = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        header = SS_HEADER_RE.match(raw)
        if header:
            flush()
            current_epoch = float(header.group("epoch"))
            continue
        if current_epoch is None or not raw.strip() or raw.startswith("--- stderr"):
            continue
        if is_target_state_line(raw):
            flush()
            current_epoch = current_epoch
            state_line = raw.strip()
            info_parts = []
        elif state_line:
            info_parts.append(raw.strip())
    flush()
    return samples


def is_target_state_line(line: str) -> bool:
    text = line.strip()
    if not text or text.startswith(("Netid", "State", "Recv-Q")):
        return False
    return SENDER_IP in text and RECEIVER_IP in text and f":{TARGET_TCP_PORT}" in text


def build_ss_sample(case: str, epoch: float, start_epoch: float, state_line: str, info_text: str) -> SsSample:
    values = parse_ss_key_values(info_text)
    retransmits = math.nan
    total_retrans = math.nan
    if "retrans" in values:
        left, _, right = values["retrans"].partition("/")
        retransmits = safe_float(left)
        total_retrans = safe_float(right) if right else retransmits
    rtt_ms = math.nan
    rttvar_ms = math.nan
    if "rtt" in values:
        left, _, right = values["rtt"].partition("/")
        rtt_ms = safe_float(left)
        rttvar_ms = safe_float(right)
    return SsSample(
        case=case,
        epoch=epoch,
        rel_time=epoch - start_epoch,
        state=state_line.split()[0] if state_line.split() else "",
        rto_ms=safe_float(values.get("rto")),
        backoff=int(safe_float(values.get("backoff"), 0)),
        cwnd=safe_float(values.get("cwnd")),
        ssthresh=safe_float(values.get("ssthresh")),
        unacked=safe_float(values.get("unacked")),
        retransmits=retransmits,
        total_retrans=total_retrans,
        rtt_ms=rtt_ms,
        rttvar_ms=rttvar_ms,
    )


def parse_ss_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for token in text.replace(",", " ").split():
        if ":" in token:
            key, value = token.split(":", 1)
            values[key] = value
    return values


def build_timeline(case: str, samples: list[SsSample], pulses: list[dict[str, str]], config: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for sample in samples:
        pulse = pulse_at(sample.rel_time, pulses)
        rows.append(
            {
                "case": case,
                "time_sec": f"{sample.rel_time:.6f}",
                "phase": phase_for_time(sample.rel_time, config),
                "rto_ms": fmt(sample.rto_ms),
                "backoff": sample.backoff,
                "cwnd": fmt(sample.cwnd),
                "ssthresh": fmt(sample.ssthresh),
                "unacked": fmt(sample.unacked),
                "retransmits": fmt(sample.retransmits),
                "total_retrans": fmt(sample.total_retrans),
                "rtt_ms": fmt(sample.rtt_ms),
                "rttvar_ms": fmt(sample.rttvar_ms),
                "pulse_active": 1 if pulse else 0,
                "pulse_index": pulse.get("pulse_index", "") if pulse else "",
                "pulse_phase_ms": fmt((sample.rel_time - safe_float(pulse["scheduled_start_sec"])) * 1000.0) if pulse else "",
            }
        )
    return rows


def detect_sender_rto_events(samples: list[SsSample]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    previous: SsSample | None = None
    for sample in samples:
        if previous is None:
            previous = sample
            continue
        retrans_increased = number_increased(previous.total_retrans, sample.total_retrans)
        backoff_increased = sample.backoff > previous.backoff
        rto_increased = number_increased(previous.rto_ms, sample.rto_ms)
        if backoff_increased or (retrans_increased and rto_increased):
            events.append(
                {
                    "event_time_sec": sample.rel_time,
                    "source": "ss",
                    "sender_rto_ms": sample.rto_ms,
                    "sender_backoff": sample.backoff,
                    "sender_total_retrans": sample.total_retrans,
                    "reason": "backoff increased" if backoff_increased else "retrans and rto increased",
                }
            )
        previous = sample
    return events


def extract_pcap_events(path: Path, start_epoch: float) -> list[dict[str, Any]]:
    if not path.exists() or shutil.which("tshark") is None:
        return []
    fields = [
        "frame.time_epoch",
        "ip.src",
        "tcp.srcport",
        "ip.dst",
        "tcp.dstport",
        "tcp.seq",
        "tcp.ack",
        "tcp.len",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.lost_segment",
    ]
    command = ["tshark", "-r", str(path), "-Y", "tcp", "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts.extend([""] * (len(fields) - len(parts)))
        row = dict(zip(fields, parts))
        epoch = safe_float(row["frame.time_epoch"])
        row["time_sec"] = epoch - start_epoch if not math.isnan(epoch) else math.nan
        row["is_retransmission"] = truthy(row["tcp.analysis.retransmission"]) or truthy(row["tcp.analysis.fast_retransmission"])
        row["is_fast_retransmission"] = truthy(row["tcp.analysis.fast_retransmission"])
        row["is_duplicate_ack"] = truthy(row["tcp.analysis.duplicate_ack"])
        row["is_sender_data"] = row["ip.src"] == SENDER_IP and row["ip.dst"] == RECEIVER_IP
        rows.append(row)
    return rows


def classify_retransmission_events(
    case: str,
    pcap_events: list[dict[str, Any]],
    sender_events: list[dict[str, Any]],
    samples: list[SsSample],
    pulses: list[dict[str, str]],
    nstat_delta: dict[str, float],
) -> list[dict[str, Any]]:
    retrans = [row for row in pcap_events if row.get("is_sender_data") and row.get("is_retransmission")]
    dupacks = [row for row in pcap_events if row.get("is_duplicate_ack")]
    output = []
    previous_retrans_time = math.nan
    matched_sender_events: set[int] = set()
    timeout_delta = timeout_count(nstat_delta)
    for row in retrans:
        event_time = safe_float(row.get("time_sec"))
        nearest_sender_idx = nearest_event_index(event_time, sender_events)
        nearest_sender = sender_events[nearest_sender_idx] if nearest_sender_idx is not None else None
        nearest_sample = nearest_sample_at(event_time, samples)
        interval = event_time - previous_retrans_time if not math.isnan(previous_retrans_time) else math.nan
        dupack_near = any(abs(safe_float(ack.get("time_sec")) - event_time) <= 0.3 for ack in dupacks)
        fast = bool(row.get("is_fast_retransmission"))
        classification = "unknown"
        reason = "pcap retransmission without enough sender evidence"
        sender_aligned = nearest_sender is not None and abs(float(nearest_sender["event_time_sec"]) - event_time) <= 0.5
        sender_unused = nearest_sender_idx is not None and nearest_sender_idx not in matched_sender_events
        sender_backoff = safe_float(nearest_sender.get("sender_backoff") if nearest_sender else 0, 0)
        if fast or dupack_near:
            classification = "not_observed"
            reason = "fast retransmit or duplicate ACK evidence; not classified as RTO"
        elif sender_aligned and sender_unused and sender_backoff > 0 and timeout_delta > 0:
            classification = "confirmed"
            reason = "pcap retransmission aligned with unused sender backoff and TCPTimeouts evidence"
            matched_sender_events.add(nearest_sender_idx)
        elif sender_aligned and sender_unused and sender_backoff > 0:
            classification = "probable"
            reason = "pcap retransmission aligned with sender backoff, but TCPTimeouts did not increase"
            matched_sender_events.add(nearest_sender_idx)
        elif timeout_delta > 0 and nearest_sample and nearest_sample.backoff > 0 and interval_is_rto_like(interval, nearest_sample):
            classification = "probable"
            reason = "TCPTimeouts increased and retransmission interval matches sender RTO"
        elif interval_is_rto_like(interval, nearest_sample):
            classification = "probable"
            reason = "retransmission interval is compatible with sender RTO"
        output.append(
            {
                "case": case,
                "event_time_sec": fmt(event_time),
                "source": "pcap",
                "classification": classification,
                "pcap_retransmission": 1,
                "fast_retransmission": 1 if fast else 0,
                "duplicate_ack_nearby": 1 if dupack_near else 0,
                "retrans_interval_sec": fmt(interval),
                "sender_rto_ms": fmt(nearest_sample.rto_ms if nearest_sample else math.nan),
                "sender_backoff": nearest_sample.backoff if nearest_sample else "",
                "timeouts_delta": fmt(timeout_delta),
                "pulse_active": 1 if pulse_at(event_time, pulses) else 0,
                "reason": reason,
            }
        )
        previous_retrans_time = event_time
    return output


def sender_events_to_rows(case: str, sender_events: list[dict[str, Any]], nstat_delta: dict[str, float]) -> list[dict[str, Any]]:
    timeout_delta = timeout_count(nstat_delta)
    rows = []
    for row in sender_events:
        backoff = safe_float(row.get("sender_backoff"), 0)
        confirmed = timeout_delta > 0 and backoff > 0
        rows.append(
            {
                "case": case,
                "event_time_sec": fmt(row["event_time_sec"]),
                "source": "ss",
                "classification": "confirmed" if confirmed else "probable",
                "pcap_retransmission": "",
                "fast_retransmission": "",
                "duplicate_ack_nearby": "",
                "retrans_interval_sec": "",
                "sender_rto_ms": fmt(row.get("sender_rto_ms")),
                "sender_backoff": row.get("sender_backoff", ""),
                "timeouts_delta": fmt(timeout_delta),
                "pulse_active": "",
                "reason": row.get("reason", "sender rto/backoff evidence")
                if confirmed
                else "sender rto/backoff evidence without TCPTimeouts confirmation",
            }
        )
    return rows


def build_summary_row(
    case: str,
    case_cfg: dict[str, Any],
    raw_dir: Path,
    samples: list[SsSample],
    pulses: list[dict[str, str]],
    events: list[dict[str, Any]],
    nstat_delta: dict[str, float],
    qdisc_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    classifications = [str(row.get("classification", "")) for row in events]
    timing_status, timing_violations = evaluate_pulse_timing(pulses, case_cfg)
    if "confirmed" in classifications:
        status = "confirmed"
    elif "probable" in classifications:
        status = "probable"
    elif not events and timeout_count(nstat_delta) == 0 and not any(sample.backoff > 0 for sample in samples):
        status = "not_observed"
    else:
        status = "unknown"
    if timing_status == "invalid_timing":
        status = "invalid_timing"
    iperf = parse_iperf(raw_dir / "iperf3.json")
    return {
        "case": case,
        "period_ms": "" if case_cfg.get("period_ms") is None else fmt(case_cfg.get("period_ms")),
        "rto_status": status,
        "timing_status": timing_status,
        "timing_violations": timing_violations,
        "ss_samples": len(samples),
        "pulse_count": len(pulses),
        "confirmed_events": classifications.count("confirmed"),
        "probable_events": classifications.count("probable"),
        "not_observed_events": classifications.count("not_observed"),
        "unknown_events": classifications.count("unknown"),
        "tcp_timeouts_delta": fmt(timeout_count(nstat_delta)),
        "tcp_retrans_segs_delta": fmt(nstat_delta.get("TcpRetransSegs", math.nan)),
        "max_backoff": max([sample.backoff for sample in samples], default=0),
        "max_rto_ms": fmt(max([sample.rto_ms for sample in samples if not math.isnan(sample.rto_ms)], default=math.nan)),
        "mean_cwnd": fmt(mean([sample.cwnd for sample in samples if not math.isnan(sample.cwnd)]) if samples else math.nan),
        "iperf_receiver_mbps": fmt(iperf.get("receiver_mbps", math.nan)),
        "iperf_retransmits": fmt(iperf.get("retransmits", math.nan)),
        "qdisc_dropped_delta": fmt(sum(safe_float(row.get("dropped_delta")) for row in qdisc_rows)),
    }


def parse_iperf(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return {}
    end = data.get("end", {})
    receiver = end.get("sum_received", {}) or end.get("sum", {})
    sender = end.get("sum_sent", {}) or end.get("sum", {})
    return {
        "receiver_mbps": safe_float(receiver.get("bits_per_second")) / 1_000_000.0,
        "retransmits": safe_float(sender.get("retransmits")),
    }


def nstat_diff(before_path: Path, after_path: Path) -> dict[str, float]:
    before = parse_nstat(before_path)
    after = parse_nstat(after_path)
    keys = set(before) | set(after)
    return {key: after.get(key, 0.0) - before.get(key, 0.0) for key in keys}


def parse_nstat(path: Path) -> dict[str, float]:
    values: dict[str, float] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("#"):
            values[parts[0]] = safe_float(parts[1], 0.0)
    return values


def qdisc_diff(before_path: Path, after_path: Path) -> list[dict[str, Any]]:
    before = parse_qdisc(before_path)
    after = parse_qdisc(after_path)
    rows = []
    for iface in sorted(set(before) | set(after)):
        b = before.get(iface, {})
        a = after.get(iface, {})
        rows.append(
            {
                "interface": iface,
                "dropped_before": b.get("dropped", 0),
                "dropped_after": a.get("dropped", 0),
                "dropped_delta": a.get("dropped", 0) - b.get("dropped", 0),
                "overlimits_before": b.get("overlimits", 0),
                "overlimits_after": a.get("overlimits", 0),
                "overlimits_delta": a.get("overlimits", 0) - b.get("overlimits", 0),
                "backlog_after": a.get("backlog", ""),
            }
        )
    return rows


def parse_qdisc(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    current = ""
    if not path.exists():
        return output
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            output[current] = {"dropped": 0, "overlimits": 0, "backlog": ""}
        elif current:
            dropped_values = [int(value) for value in re.findall(r"\bdropped\s+(\d+)", line)]
            if dropped_values:
                output[current]["dropped"] = max(output[current]["dropped"], max(dropped_values))
            output[current]["overlimits"] += sum(int(value) for value in re.findall(r"\boverlimits\s+(\d+)", line))
            if "backlog" in line:
                output[current]["backlog"] = line.strip()
    return output


def write_report(path: Path, config: dict[str, Any], summary_rows: list[dict[str, Any]], event_rows: list[dict[str, Any]]) -> None:
    lines = [
        "# RTO Cycle Report",
        "",
        f"- run_id: `{config.get('run_id')}`",
        f"- duration_sec: `{config.get('duration_sec')}`",
        f"- attack_window: `{config.get('attack_start_sec')}`-`{config.get('attack_end_sec')}` sec",
        f"- bottleneck: `{config.get('bottleneck_mbps')}` Mbps, delay `{config.get('one_way_delay_ms')}` ms, DropTail `{config.get('queue_packets')}` packets",
        "",
        "## Summary",
        "",
        markdown_table(summary_rows),
        "",
        "## Classification Notes",
        "",
        "- `confirmed`: pcap retransmission aligned with unused sender backoff evidence and TCP timeout counters increased.",
        "- `probable`: retransmission timing is compatible with the sender RTO but lacks full confirmation.",
        "- `not_observed`: fast retransmit or duplicate ACK evidence was present, so it was not counted as an RTO observation.",
        "- `unknown`: insufficient combined evidence.",
        "- `invalid_timing`: at least one UDP pulse duration or byte count was outside the configured tolerance.",
        "",
        f"Total retransmission event rows: {len(event_rows)}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def create_archives(output_dir: Path, run_id: str, manifest_path: Path) -> None:
    summary_zip = output_dir / f"rto_cycle_{run_id}_summary.zip"
    full_zip = output_dir / f"rto_cycle_{run_id}_full.zip"
    summary_patterns = {
        "config.json",
        "summary.csv",
        "timeline.csv",
        "retrans_events.csv",
        "report.md",
        "manifest.txt",
    }
    with zipfile.ZipFile(summary_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(output_dir.rglob("*")):
            if path.is_dir() or path == summary_zip or path == full_zip:
                continue
            rel = path.relative_to(output_dir).as_posix()
            name = path.name
            if (
                rel in summary_patterns
                or name in {"iperf3.json", "ss_samples.csv", "nstat_delta.csv", "qdisc_summary.csv", "pulses.csv"}
            ):
                zf.write(path, rel)
    with zipfile.ZipFile(full_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(output_dir.rglob("*")):
            if path.is_dir() or path == summary_zip or path == full_zip:
                continue
            zf.write(path, path.relative_to(output_dir).as_posix())


def write_ss_samples(path: Path, samples: list[SsSample], pulses: list[dict[str, str]], config: dict[str, Any]) -> None:
    rows = build_timeline(samples[0].case if samples else "", samples, pulses, config) if samples else []
    write_rows(path, rows)


def write_key_values(path: Path, values: dict[str, float]) -> None:
    write_rows(path, [{"key": key, "delta": fmt(value)} for key, value in sorted(values.items())])


def write_rows(path: Path, rows: Iterable[dict[str, Any]], fields: list[str] | None = None) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and fields is None:
        path.write_text("", encoding="utf-8")
        return
    if fields is None:
        fields = []
        for row in rows:
            for key in row:
                if key not in fields:
                    fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def pulse_at(time_sec: float, pulses: list[dict[str, str]]) -> dict[str, str] | None:
    for pulse in pulses:
        start = safe_float(pulse.get("scheduled_start_sec"))
        duration = scheduled_pulse_duration_sec(pulse)
        if math.isnan(start) or math.isnan(duration):
            continue
        end = start + max(0.0, duration)
        if start <= time_sec <= end:
            return pulse
    return None


def evaluate_pulse_timing(pulses: list[dict[str, str]], case_cfg: dict[str, Any]) -> tuple[str, str]:
    if not pulses:
        return "not_applicable", ""
    violations = []
    for pulse in pulses:
        pulse_index = pulse.get("pulse_index", "?")
        scheduled_duration = scheduled_pulse_duration_sec(pulse)
        actual_duration = actual_pulse_duration_sec(pulse)
        expected_bytes = expected_pulse_bytes(pulse, case_cfg)
        bytes_sent = safe_float(pulse.get("bytes_sent"))
        skipped = truthy(pulse.get("skipped", "0"))
        reasons = []
        if skipped:
            reasons.append("skipped")
        if math.isnan(scheduled_duration) or math.isnan(actual_duration):
            reasons.append("duration_missing")
        elif abs(actual_duration - scheduled_duration) > 0.010:
            reasons.append(f"duration={actual_duration:.6f}s")
        if math.isnan(expected_bytes) or math.isnan(bytes_sent):
            reasons.append("bytes_missing")
        elif expected_bytes > 0 and abs(bytes_sent - expected_bytes) / expected_bytes > 0.05:
            reasons.append(f"bytes={int(bytes_sent)}")
        elif expected_bytes == 0 and bytes_sent != 0:
            reasons.append(f"bytes={int(bytes_sent)}")
        if reasons:
            violations.append(f"{pulse_index}:{'|'.join(reasons)}")
    if violations:
        return "invalid_timing", ";".join(violations[:20])
    return "valid_timing", ""


def scheduled_pulse_duration_sec(pulse: dict[str, str]) -> float:
    direct = safe_float(pulse.get("scheduled_duration_sec"))
    if not math.isnan(direct):
        return direct
    start_mono = safe_float(pulse.get("scheduled_start_mono_ns"))
    end_mono = safe_float(pulse.get("scheduled_end_mono_ns"))
    if not math.isnan(start_mono) and not math.isnan(end_mono):
        return (end_mono - start_mono) / 1_000_000_000.0
    start_epoch = safe_float(pulse.get("scheduled_start_epoch"))
    end_epoch = safe_float(pulse.get("scheduled_end_epoch"))
    if not math.isnan(start_epoch) and not math.isnan(end_epoch):
        return end_epoch - start_epoch
    return safe_float(pulse.get("burst_ms")) / 1000.0


def actual_pulse_duration_sec(pulse: dict[str, str]) -> float:
    direct = safe_float(pulse.get("actual_duration_sec"))
    if not math.isnan(direct):
        return direct
    start_mono = safe_float(pulse.get("actual_start_mono_ns"))
    end_mono = safe_float(pulse.get("actual_end_mono_ns"))
    if not math.isnan(start_mono) and not math.isnan(end_mono):
        return (end_mono - start_mono) / 1_000_000_000.0
    start_epoch = safe_float(pulse.get("actual_start_epoch"))
    end_epoch = safe_float(pulse.get("actual_end_epoch"))
    if not math.isnan(start_epoch) and not math.isnan(end_epoch):
        return end_epoch - start_epoch
    return math.nan


def expected_pulse_bytes(pulse: dict[str, str], case_cfg: dict[str, Any]) -> float:
    direct = safe_float(pulse.get("expected_bytes"))
    if not math.isnan(direct):
        return direct
    rate_mbps = safe_float(pulse.get("target_rate_mbps"))
    if math.isnan(rate_mbps):
        rate_mbps = safe_float(case_cfg.get("burst_rate_mbps"))
    duration = scheduled_pulse_duration_sec(pulse)
    if math.isnan(rate_mbps) or math.isnan(duration):
        return math.nan
    return rate_mbps * 1_000_000.0 * duration / 8.0


def phase_for_time(time_sec: float, config: dict[str, Any]) -> str:
    if time_sec < safe_float(config.get("attack_start_sec")):
        return "tcp_only"
    if time_sec < safe_float(config.get("attack_end_sec")):
        return "udp_burst"
    return "recovery"


def nearest_event(time_sec: float, events: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not events or math.isnan(time_sec):
        return None
    return min(events, key=lambda row: abs(float(row["event_time_sec"]) - time_sec))


def nearest_event_index(time_sec: float, events: list[dict[str, Any]]) -> int | None:
    if not events or math.isnan(time_sec):
        return None
    return min(range(len(events)), key=lambda idx: abs(float(events[idx]["event_time_sec"]) - time_sec))


def nearest_sample_at(time_sec: float, samples: list[SsSample]) -> SsSample | None:
    if not samples or math.isnan(time_sec):
        return None
    return min(samples, key=lambda sample: abs(sample.rel_time - time_sec))


def interval_is_rto_like(interval_sec: float, sample: SsSample | None) -> bool:
    if sample is None or math.isnan(interval_sec) or math.isnan(sample.rto_ms):
        return False
    rto_sec = sample.rto_ms / 1000.0
    return 0.6 * rto_sec <= interval_sec <= 1.8 * rto_sec


def timeout_count(delta: dict[str, float]) -> float:
    candidates = [value for key, value in delta.items() if "Timeout" in key or "timeout" in key]
    return max(candidates, default=0.0)


def number_increased(previous: float, current: float) -> bool:
    return not math.isnan(previous) and not math.isnan(current) and current > previous


def truthy(value: Any) -> bool:
    return str(value).strip() not in {"", "0", "False", "false"}


def safe_float(value: Any, default: float = math.nan) -> float:
    try:
        if value in ("", None):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def fmt(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "" if value is None else str(value)
    if math.isnan(number):
        return ""
    return f"{number:.9g}"


def markdown_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "_No rows._"
    fields = list(rows[0].keys())
    lines = [
        "| " + " | ".join(fields) + " |",
        "| " + " | ".join("---" for _ in fields) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
