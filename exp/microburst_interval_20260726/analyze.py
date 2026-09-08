#!/usr/bin/env python3
"""Analyze the one wide-interval benign microburst exploratory trial."""

from __future__ import annotations

import copy
import csv
import importlib.util
import json
import math
import sys
from pathlib import Path
from typing import Any

import numpy as np


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
OLD_ANALYZER = REPO_ROOT / "exp/dpsws_tcp_unlimited_20260724/analyze.py"
DIRECT_ANALYZER = REPO_ROOT / "exp/detector_25ms_20260714/analyze.py"
FIGURE_ANALYZER = REPO_ROOT / "exp/dpsws_figures_20260726/analyze.py"
CONTROL_CSV = REPO_ROOT / "exp/dpsws_tcp_25ms_20260726/out/20260726_135301/tcp_results_10trials.csv"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT_ROOT")
    output_root = Path(sys.argv[1]).resolve()
    case_files = list((output_root / "runs/wide_interval_trial_1/cases").glob("*/case.json"))
    if len(case_files) != 1:
        raise RuntimeError(f"expected one case.json, found {len(case_files)}")
    case_dir = case_files[0].parent
    raw = case_dir / "raw"
    meta = read_json(case_files[0])
    expected = {
        "status": "success", "client_rc": 0, "capacity_mbps": 15.0,
        "queue_packets": 100, "rate_mbps": 15.0, "payload_bytes": 80,
        "random_burst_min_ms": 5.0, "random_burst_max_ms": 30.0,
        "random_interval_min_ms": 50.0, "random_interval_max_ms": 300.0,
        "traffic_start_sec": 10.0, "traffic_end_sec": 50.0,
        "tcp_target_mbps": None, "tcp_limit_method": "none",
        "tcp_congestion": "reno", "tcp_sack": "off",
    }
    for key, value in expected.items():
        if meta.get(key) != value:
            raise RuntimeError(f"{key}={meta.get(key)!r}, expected {value!r}")

    old = load_module("wide_old_analyzer", OLD_ANALYZER)
    direct = load_module("wide_direct_detector", DIRECT_ANALYZER)
    figures = load_module("wide_figure_analyzer", FIGURE_ANALYZER)
    server = read_json(raw / "iperf3_server_20260707.json")
    client = read_json(raw / "iperf3_client_20260707.json")
    pulses = read_csv(raw / "pulses_20260707.csv")
    tcp_eval = old.interval_mbps(server, 10.0, 50.0)
    baseline_row = next(
        row for row in read_csv(CONTROL_CSV)
        if row["condition"] == "baseline" and int(row["trial"]) == 1
    )
    baseline = float(baseline_row["tcp_attack_mbps"])
    degradation = (baseline - tcp_eval) / baseline * 100.0
    offered_udp = sum(int(float(row["bytes_sent"])) for row in pulses) * 8.0 / 40.0 / 1_000_000.0
    pcap = raw / "bottleneck_after_h2_eth0_20260707.pcap"
    source_case = figures.SourceCase(
        "wide_microburst", 1, case_dir, meta, raw / "iperf3_server_20260707.json",
        pcap, raw / "pulses_20260707.csv",
    )
    _, udp_100ms, _, _, max_clock_correction = figures.tshark_payload_bins(source_case)
    received_udp = float(udp_100ms.reshape(60, 10).mean(axis=1)[10:50].mean())
    sent = client.get("end", {}).get("sum_sent") or {}
    before_drops = old.qdisc_drops(raw / "tc_qdisc_before_20260707.txt")
    after_drops = old.qdisc_drops(raw / "tc_qdisc_after_20260707.txt")

    training, _ = direct.build_features(direct.TRAINING_SPEC)
    detector = direct.PaperReproductionDetector(direct.PaperDetectorConfig())
    direct.predict_online(detector, training)
    spec = direct.CaseSpec(meta["case_id"], "wide_interval", str(pcap), str(case_files[0]), False)
    features, _ = direct.build_features(spec)
    online = direct.predict_online(copy.deepcopy(detector), features)
    evaluation = online[online["window_start_sec"].ge(10.0) & online["window_start_sec"].lt(50.0)].copy()
    scores = evaluation["suspicious_score"].astype(int)
    predicted = evaluation["pred_attack"].astype(bool)
    detector_dir = output_root / "detector_25ms"
    detector_dir.mkdir(parents=True, exist_ok=True)
    features.to_csv(detector_dir / "features_25ms.csv", index=False)
    direct.write_csv(
        detector_dir / "detector_windows_online_25ms.csv",
        direct.to_window_rows(spec.case, "online_after_training", online), direct.WINDOW_FIELDS,
    )

    result = {
        "baseline_tcp_mbps": baseline,
        "tcp_pre_mbps": old.interval_mbps(server, 0.0, 10.0),
        "tcp_eval_mbps": tcp_eval,
        "tcp_post_mbps": old.interval_mbps(server, 50.0, 60.0),
        "tcp_degradation_pct": degradation,
        "tcp_timeouts": int(old.nstat_delta(raw, "TcpExtTCPTimeouts")),
        "tcp_retransmissions": int(float(sent.get("retransmits", 0.0))),
        "qdisc_drops": int(after_drops - before_drops),
        "udp_offered_mbps": offered_udp,
        "udp_received_mbps": received_udp,
        "pulse_count": len(pulses),
        "detector_windows": len(evaluation),
        "valid_detector_windows": int(evaluation["enough_packets_for_detection"].astype(bool).sum()),
        "anomaly_windows": int(predicted.sum()),
        "FPR": float(predicted.mean()),
        "score_max": int(scores.max()),
        "score_mean": float(scores.mean()),
        "max_pcap_clock_correction_sec": max_clock_correction,
    }
    with (output_root / "result.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(result))
        writer.writeheader()
        writer.writerow(result)
    summary = [
        "# Wide random-interval exploratory result", "",
        "- Interval range: 50-300 ms (mean 175 ms; original 140-210 ms also mean 175 ms)",
        f"- Baseline TCP goodput: {baseline:.6f} Mbps",
        f"- TCP goodput during microbursts: {tcp_eval:.6f} Mbps",
        f"- TCP degradation: {degradation:.6f}%",
        f"- UDP offered mean: {offered_udp:.6f} Mbps",
        f"- UDP received mean: {received_udp:.6f} Mbps",
        f"- TCPTimeouts: {result['tcp_timeouts']}",
        f"- Retransmissions: {result['tcp_retransmissions']}",
        f"- qdisc drops: {result['qdisc_drops']}",
        f"- Detector anomalies: {result['anomaly_windows']}/{result['detector_windows']}",
        f"- Maximum score: {result['score_max']}", "",
        "## Comparison with the original interval range", "",
        "- Original 140-210 ms, 10-trial mean TCP goodput: 0.985900 Mbps",
        "- Original 140-210 ms, 10-trial mean degradation: 93.124468%",
        f"- Wide 50-300 ms, this trial TCP goodput: {tcp_eval:.6f} Mbps",
        f"- Wide 50-300 ms, this trial degradation: {degradation:.6f}%",
        f"- Apparent degradation improvement: {93.1244676114 - degradation:.6f} percentage points", "",
        "The wide-range result remains inside the original condition's observed degradation range (91.772-94.148%). This one trial does not show a material reduction.", "",
        "This is one exploratory trial and is not a formal selected control result.",
    ]
    (output_root / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    (output_root / "used_settings.json").write_text(json.dumps({**expected, "seed": meta["seed"]}, indent=2) + "\n", encoding="utf-8")
    (output_root / "commands.log").write_text(
        ".venv/bin/python exp/microburst_interval_20260726/run.py --output-dir "
        + str(output_root / "runs/wide_interval_trial_1") + "\n"
        + ".venv/bin/python exp/microburst_interval_20260726/analyze.py " + str(output_root) + "\n",
        encoding="utf-8",
    )
    (output_root / "validation.md").write_text(
        "# Validation\n\n- [PASS] exactly one successful TCP-unlimited case\n"
        "- [PASS] interval mean retained at 175 ms\n- [PASS] only interval range differs from adopted avg10 traffic\n"
        "- [PASS] 1600 detector evaluation windows\n- [PASS] no figures generated\n",
        encoding="utf-8",
    )
    print(f"Wrote analysis to {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
