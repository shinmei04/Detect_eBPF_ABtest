#!/usr/bin/env python3
"""Evaluate the saved LDoS pcaps with direct 25 ms detector windows."""

from __future__ import annotations

import copy
import csv
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mininet_experiment.pcap_to_features import parse_udp_pcap
from src.paper_reproduction_detector import (
    PAPER_FEATURES,
    PaperDetectorConfig,
    PaperReproductionDetector,
)


WINDOW_SEC = 0.025
STEP_SEC = 0.025
DURATION_SEC = 60.0
ATTACK_START_SEC = 10.0
ATTACK_END_SEC = 50.0
UDP_PORT = 5001


@dataclass(frozen=True)
class CaseSpec:
    case: str
    output_key: str
    pcap: str
    metadata: str
    has_attack: bool


TRAINING_SPEC = CaseSpec(
    case="train_random_avg10",
    output_key="training",
    pcap="experiments/main_ldos_tcp6m/raw_pcaps/random_benign_avg10.pcap",
    metadata=(
        "experiments/archive_unused/failed_training_candidates/"
        "random_interval_average_sweep_extra_files/train_random_avg10/case.json"
    ),
    has_attack=False,
)

EVALUATION_SPECS = [
    CaseSpec(
        case="base_tcp6m",
        output_key="base",
        pcap="experiments/main_ldos_tcp6m/raw_pcaps/base_tcp6m.pcap",
        metadata=(
            "experiments/archive_unused/unknown_files/main_conditions_extra_files/"
            "base_c15_tcp6m/case.json"
        ),
        has_attack=False,
    ),
    CaseSpec(
        case="periodic_ldos_tcp6m_r15_l300_t1000",
        output_key="periodic",
        pcap="experiments/main_ldos_tcp6m/raw_pcaps/periodic_ldos_tcp6m_r15_l300_t1000.pcap",
        metadata=(
            "experiments/archive_unused/unknown_files/main_conditions_extra_files/"
            "periodic_c15_tcp6m_r15_l300_t1000/case.json"
        ),
        has_attack=True,
    ),
    CaseSpec(
        case="true_random_packet_4p5m_sack_off",
        output_key="random_packet",
        pcap=(
            "experiments/dpsws_random_and_sack_check_20260709/out/20260709_162027/"
            "cases/true_random_packet_4p5m_sack_off/raw/"
            "bottleneck_after_h2_eth0_20260707.pcap"
        ),
        metadata=(
            "experiments/dpsws_random_and_sack_check_20260709/out/20260709_162027/"
            "cases/true_random_packet_4p5m_sack_off/case.json"
        ),
        has_attack=True,
    ),
]


WINDOW_FIELDS = [
    "mode",
    "case",
    "window_index",
    "window_start",
    "window_end",
    "label",
    "packet_count",
    "enough_packets",
    "iat_variance",
    "iat_threshold",
    "iat_crossed",
    "burst_rate",
    "burst_rate_threshold",
    "burst_rate_crossed",
    "payload_size_variance",
    "payload_size_threshold",
    "payload_size_crossed",
    "new_flow_arrival_rate",
    "new_flow_arrival_rate_threshold",
    "new_flow_arrival_rate_crossed",
    "score",
    "predicted_attack",
    "ema_updated",
]


SUMMARY_FIELDS = [
    "case",
    "mode",
    "pcap",
    "total_25ms_windows",
    "valid_windows",
    "skipped_windows",
    "attack_windows_total",
    "attack_windows_valid",
    "attack_windows_skipped",
    "benign_windows_total",
    "benign_windows_valid",
    "benign_windows_skipped",
    "predicted_attack_windows",
    "TP",
    "FP",
    "TN",
    "FN",
    "TP_valid",
    "FP_valid",
    "TN_valid",
    "FN_valid",
    "TPR_all_attack_windows",
    "FNR_all_attack_windows",
    "FPR_all_benign_windows",
    "TPR_valid_attack_windows",
    "FNR_valid_attack_windows",
    "FPR_valid_benign_windows",
    "precision",
    "F1",
    "score_0_windows",
    "score_1_windows",
    "score_2_windows",
    "score_3_windows",
    "score_4_windows",
    "attack_score_0_windows",
    "attack_score_1_windows",
    "attack_score_ge_2_windows",
    "attack_valid_score_0_windows",
    "attack_valid_score_1_windows",
    "attack_valid_score_ge_2_windows",
    "iat_crossed_attack_windows",
    "burst_rate_crossed_attack_windows",
    "payload_size_crossed_attack_windows",
    "new_flow_crossed_attack_windows",
]


def evaluate(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=False)
    validate_inputs([TRAINING_SPEC, *EVALUATION_SPECS])

    detector_config = PaperDetectorConfig()
    training_features, training_info = build_features(TRAINING_SPEC)
    trained_detector = PaperReproductionDetector(detector_config)
    training_predictions = predict_online(trained_detector, training_features)

    summary_rows: list[dict[str, Any]] = []
    case_infos: list[dict[str, Any]] = []
    for spec in EVALUATION_SPECS:
        features, case_info = build_features(spec)
        case_infos.append(case_info)

        online_detector = copy.deepcopy(trained_detector)
        freeze_detector = copy.deepcopy(trained_detector)
        online_predictions = predict_online(online_detector, features)
        freeze_predictions = predict_frozen(freeze_detector, features)

        case_rows: list[dict[str, Any]] = []
        for mode, predictions in (
            ("online_after_training", online_predictions),
            ("freeze_after_training", freeze_predictions),
        ):
            rows = to_window_rows(spec.case, mode, predictions)
            case_rows.extend(rows)
            summary_rows.append(summarize(spec, mode, predictions))

        validate_case_rows(spec, case_rows)
        write_csv(output_dir / f"detector_windows_{spec.output_key}_25ms.csv", case_rows, WINDOW_FIELDS)

    write_csv(output_dir / "detector_summary_25ms.csv", summary_rows, SUMMARY_FIELDS)
    four_second_rows = read_four_second_summary()
    write_report(
        output_dir / "detector_report_25ms.md",
        summary_rows,
        training_info,
        training_predictions,
        case_infos,
        four_second_rows,
        detector_config,
    )
    write_run_config(
        output_dir / "run_config.json",
        detector_config,
        training_info,
        case_infos,
        four_second_rows,
    )
    validate_outputs(output_dir, summary_rows)


def validate_inputs(specs: list[CaseSpec]) -> None:
    missing: list[str] = []
    for spec in specs:
        for path_text in (spec.pcap, spec.metadata):
            path = REPO_ROOT / path_text
            if not path.is_file():
                missing.append(str(path))
    if missing:
        raise FileNotFoundError("missing required input(s):\n" + "\n".join(missing))


def build_features(spec: CaseSpec) -> tuple[pd.DataFrame, dict[str, Any]]:
    pcap_path = REPO_ROOT / spec.pcap
    metadata_path = REPO_ROOT / spec.metadata
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    origin = float(metadata["start_epoch"])
    packets = parse_udp_pcap(pcap_path, dst_port=UDP_PORT)
    packets = packets.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    if not packets.empty:
        packets["timestamp_sec"] = packets["timestamp"].astype(float) - origin
        packets = packets[
            (packets["timestamp_sec"] >= 0.0) & (packets["timestamp_sec"] < DURATION_SEC)
        ].copy()
        packets["bucket_index"] = np.floor(packets["timestamp_sec"] / WINDOW_SEC).astype(int)
        packets["flow_id"] = (
            packets["src_ip"].astype(str)
            + ":"
            + packets["src_port"].astype(str)
            + ">"
            + packets["dst_ip"].astype(str)
            + ":"
            + packets["dst_port"].astype(str)
        )

    if not math.isclose(WINDOW_SEC, STEP_SEC):
        raise ValueError("the direct 25 ms evaluator requires non-overlapping window and step widths")
    total_windows = int(math.floor((DURATION_SEC - WINDOW_SEC) / STEP_SEC + 1e-9)) + 1
    starts = np.arange(total_windows, dtype=float) * STEP_SEC
    ends = starts + WINDOW_SEC
    packet_count = np.zeros(total_windows, dtype=int)
    iat_variance = np.zeros(total_windows, dtype=float)
    payload_variance = np.zeros(total_windows, dtype=float)
    new_flow_rate = np.zeros(total_windows, dtype=float)

    if not packets.empty:
        for bucket_index, group in packets.groupby("bucket_index", sort=True):
            index = int(bucket_index)
            if index < 0 or index >= total_windows:
                continue
            timestamps = group["timestamp_sec"].to_numpy(dtype=float)
            packet_sizes = group["packet_size"].to_numpy(dtype=float)
            count = len(group)
            packet_count[index] = count
            if count >= 2:
                iat_variance[index] = float(np.var(np.diff(timestamps), ddof=0))
            if count > 0:
                payload_variance[index] = float(np.var(packet_sizes, ddof=0))
                new_flow_rate[index] = float(group["flow_id"].nunique()) / WINDOW_SEC

    labels = np.full(total_windows, "benign", dtype=object)
    if spec.has_attack:
        # These boundaries are exact multiples of 25 ms. Use integer indices so
        # floating-point addition cannot label the 50.000-50.025 s window.
        indices = np.arange(total_windows, dtype=int)
        attack_start_index = int(round(ATTACK_START_SEC / WINDOW_SEC))
        attack_end_index = int(round(ATTACK_END_SEC / WINDOW_SEC))
        overlap = (indices < attack_end_index) & ((indices + 1) > attack_start_index)
        labels[overlap] = "attack"

    features = pd.DataFrame(
        {
            "window_index": np.arange(total_windows, dtype=int),
            "window_start_sec": starts,
            "window_end_sec": ends,
            "label": labels,
            "iat_variance": iat_variance,
            "burst_rate": packet_count.astype(float) / WINDOW_SEC,
            "payload_size_variance": payload_variance,
            "new_flow_arrival_rate": new_flow_rate,
            "total_packets": packet_count,
        }
    )
    features["target"] = (features["label"] == "attack").astype(int)
    ensure_finite_features(spec.case, features)

    info = {
        "case": spec.case,
        "pcap": str(pcap_path),
        "metadata": str(metadata_path),
        "start_epoch": origin,
        "pcap_bytes": pcap_path.stat().st_size,
        "udp_packets_in_duration": int(packet_count.sum()),
        "nonempty_windows": int((packet_count > 0).sum()),
        "valid_windows_at_min_10": int((packet_count >= 10).sum()),
        "attack_windows": int((labels == "attack").sum()),
    }
    return features, info


def ensure_finite_features(case: str, frame: pd.DataFrame) -> None:
    values = frame[PAPER_FEATURES].to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError(f"non-finite detector feature generated for {case}")


def predict_online(detector: PaperReproductionDetector, features: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for _, feature_row in features.iterrows():
        before = sum(state.update_count for state in detector.states.values())
        prediction = detector._predict_one(feature_row)
        after = sum(state.update_count for state in detector.states.values())
        prediction["ema_updated"] = after > before
        rows.append(prediction)
    return pd.DataFrame(rows)


def predict_frozen(detector: PaperReproductionDetector, features: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for _, row in features.iterrows():
        output = row.to_dict()
        enough_packets = int(row["total_packets"]) >= detector.config.min_packets_for_detection
        detection_enabled = detector.total_windows_processed >= detector.config.warmup_windows
        suspicious_score = 0
        for feature_name in PAPER_FEATURES:
            feature_config = detector.feature_configs[feature_name]
            state = detector.states[feature_name]
            value = float(row[feature_name])
            threshold = detector._threshold(feature_config, state)
            is_suspicious = False
            if enough_packets and detection_enabled:
                is_suspicious = value > threshold if feature_config.is_upper_threshold else value < threshold
                suspicious_score += int(is_suspicious)
            output[f"{feature_name}_threshold"] = threshold
            output[f"{feature_name}_is_suspicious"] = bool(is_suspicious)
        output["enough_packets_for_detection"] = bool(enough_packets)
        output["detection_enabled"] = bool(detection_enabled)
        output["suspicious_score"] = suspicious_score if enough_packets and detection_enabled else 0
        output["pred_attack"] = bool(
            enough_packets
            and detection_enabled
            and suspicious_score >= detector.config.suspicious_threshold
        )
        output["ema_updated"] = False
        rows.append(output)
    return pd.DataFrame(rows)


def to_window_rows(case: str, mode: str, frame: pd.DataFrame) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for _, row in frame.iterrows():
        rows.append(
            {
                "mode": mode,
                "case": case,
                "window_index": int(row["window_index"]),
                "window_start": format_float(row["window_start_sec"]),
                "window_end": format_float(row["window_end_sec"]),
                "label": row["label"],
                "packet_count": int(row["total_packets"]),
                "enough_packets": int(bool(row["enough_packets_for_detection"])),
                "iat_variance": format_float(row["iat_variance"]),
                "iat_threshold": format_float(row["iat_variance_threshold"]),
                "iat_crossed": int(bool(row["iat_variance_is_suspicious"])),
                "burst_rate": format_float(row["burst_rate"]),
                "burst_rate_threshold": format_float(row["burst_rate_threshold"]),
                "burst_rate_crossed": int(bool(row["burst_rate_is_suspicious"])),
                "payload_size_variance": format_float(row["payload_size_variance"]),
                "payload_size_threshold": format_float(row["payload_size_variance_threshold"]),
                "payload_size_crossed": int(bool(row["payload_size_variance_is_suspicious"])),
                "new_flow_arrival_rate": format_float(row["new_flow_arrival_rate"]),
                "new_flow_arrival_rate_threshold": format_float(row["new_flow_arrival_rate_threshold"]),
                "new_flow_arrival_rate_crossed": int(bool(row["new_flow_arrival_rate_is_suspicious"])),
                "score": int(row["suspicious_score"]),
                "predicted_attack": int(bool(row["pred_attack"])),
                "ema_updated": int(bool(row["ema_updated"])),
            }
        )
    return rows


def summarize(spec: CaseSpec, mode: str, frame: pd.DataFrame) -> dict[str, Any]:
    attack = frame["label"].eq("attack")
    benign = ~attack
    valid = frame["enough_packets_for_detection"].astype(bool)
    predicted = frame["pred_attack"].astype(bool)
    scores = frame["suspicious_score"].astype(int)

    tp = int((attack & predicted).sum())
    fp = int((benign & predicted).sum())
    tn = int((benign & ~predicted).sum())
    fn = int((attack & ~predicted).sum())
    tp_valid = int((attack & valid & predicted).sum())
    fp_valid = int((benign & valid & predicted).sum())
    tn_valid = int((benign & valid & ~predicted).sum())
    fn_valid = int((attack & valid & ~predicted).sum())

    row: dict[str, Any] = {
        "case": spec.case,
        "mode": mode,
        "pcap": str(REPO_ROOT / spec.pcap),
        "total_25ms_windows": len(frame),
        "valid_windows": int(valid.sum()),
        "skipped_windows": int((~valid).sum()),
        "attack_windows_total": int(attack.sum()),
        "attack_windows_valid": int((attack & valid).sum()),
        "attack_windows_skipped": int((attack & ~valid).sum()),
        "benign_windows_total": int(benign.sum()),
        "benign_windows_valid": int((benign & valid).sum()),
        "benign_windows_skipped": int((benign & ~valid).sum()),
        "predicted_attack_windows": int(predicted.sum()),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "TP_valid": tp_valid,
        "FP_valid": fp_valid,
        "TN_valid": tn_valid,
        "FN_valid": fn_valid,
        "TPR_all_attack_windows": safe_div(tp, tp + fn),
        "FNR_all_attack_windows": safe_div(fn, tp + fn),
        "FPR_all_benign_windows": safe_div(fp, fp + tn),
        "TPR_valid_attack_windows": safe_div(tp_valid, tp_valid + fn_valid),
        "FNR_valid_attack_windows": safe_div(fn_valid, tp_valid + fn_valid),
        "FPR_valid_benign_windows": safe_div(fp_valid, fp_valid + tn_valid),
        "precision": safe_div(tp, tp + fp),
        "F1": safe_div(2 * tp, 2 * tp + fp + fn),
    }
    for score in range(5):
        row[f"score_{score}_windows"] = int((scores == score).sum())
    row.update(
        {
            "attack_score_0_windows": int((attack & (scores == 0)).sum()),
            "attack_score_1_windows": int((attack & (scores == 1)).sum()),
            "attack_score_ge_2_windows": int((attack & (scores >= 2)).sum()),
            "attack_valid_score_0_windows": int((attack & valid & (scores == 0)).sum()),
            "attack_valid_score_1_windows": int((attack & valid & (scores == 1)).sum()),
            "attack_valid_score_ge_2_windows": int((attack & valid & (scores >= 2)).sum()),
            "iat_crossed_attack_windows": crossed_count(frame, attack, "iat_variance"),
            "burst_rate_crossed_attack_windows": crossed_count(frame, attack, "burst_rate"),
            "payload_size_crossed_attack_windows": crossed_count(frame, attack, "payload_size_variance"),
            "new_flow_crossed_attack_windows": crossed_count(frame, attack, "new_flow_arrival_rate"),
        }
    )
    return row


def crossed_count(frame: pd.DataFrame, mask: pd.Series, feature: str) -> int:
    return int((mask & frame[f"{feature}_is_suspicious"].astype(bool)).sum())


def safe_div(numerator: int | float, denominator: int | float) -> float | None:
    return float(numerator) / float(denominator) if denominator else None


def format_float(value: Any) -> str:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"non-finite value in output: {value}")
    return f"{number:.12g}"


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: "" if row.get(field) is None else row.get(field, "") for field in fields})


def read_four_second_summary() -> list[dict[str, str]]:
    path = REPO_ROOT / "experiments/main_ldos_tcp6m/detector_results/detector_summary_periodic.csv"
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_report(
    path: Path,
    summary_rows: list[dict[str, Any]],
    training_info: dict[str, Any],
    training_predictions: pd.DataFrame,
    case_infos: list[dict[str, Any]],
    four_second_rows: list[dict[str, str]],
    config: PaperDetectorConfig,
) -> None:
    periodic = rows_for_case(summary_rows, "periodic_ldos_tcp6m_r15_l300_t1000")
    random_packet = rows_for_case(summary_rows, "true_random_packet_4p5m_sack_off")
    online = periodic["online_after_training"]
    freeze = periodic["freeze_after_training"]
    classification = classify_result(online, freeze)

    lines = [
        "# 25 ms direct-window detector evaluation",
        "",
        "| case | mode | 全攻撃窓 | 有効攻撃窓 | skip攻撃窓 | 検知攻撃窓 | TPR（全攻撃窓） | TPR（有効攻撃窓） | FNR（有効攻撃窓） |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary_rows:
        lines.append(
            "| {case} | {mode} | {attack_windows_total} | {attack_windows_valid} | "
            "{attack_windows_skipped} | {TP} | {tpr_all} | {tpr_valid} | {fnr_valid} |".format(
                **row,
                tpr_all=display(row["TPR_all_attack_windows"]),
                tpr_valid=display(row["TPR_valid_attack_windows"]),
                fnr_valid=display(row["FNR_valid_attack_windows"]),
            )
        )

    lines.extend(
        [
            "",
            "## 1. 結論",
            "",
            f"最終分類: **{classification}**。",
            "",
            describe_periodic("online_after_training", online),
            "",
            describe_periodic("freeze_after_training", freeze),
            "",
            (
                "onlineとfreezeの検知数の差は "
                f"{abs(int(online['TP']) - int(freeze['TP']))} 窓である。"
            ),
            "",
            (
                "攻撃窓のうちパケット不足でskipされた割合はonlineで "
                f"{display(safe_div(online['attack_windows_skipped'], online['attack_windows_total']))}、"
                "freezeでも同じである。score=0集計にはskip窓が含まれるため、"
                "valid攻撃窓のscore分布を別列で保存した。"
            ),
            "",
            "### 完全ランダム条件",
            "",
        ]
    )
    for mode in ("online_after_training", "freeze_after_training"):
        row = random_packet[mode]
        lines.append(
            f"- {mode}: 全攻撃窓={row['attack_windows_total']}, 有効={row['attack_windows_valid']}, "
            f"skip={row['attack_windows_skipped']}, 検知={row['TP']}, "
            f"TPR(valid)={display(row['TPR_valid_attack_windows'])}, "
            f"valid score 0/1/>=2={row['attack_valid_score_0_windows']}/"
            f"{row['attack_valid_score_1_windows']}/{row['attack_valid_score_ge_2_windows']}"
        )

    lines.extend(
        [
            "",
            "## 2. 4秒窓版との比較",
            "",
            "既存4秒窓版は25ms bucketを160個含む4秒特徴量を1秒stepで判定した結果であり、"
            "今回の25ms直接判定とは窓幅も分母も異なる。検知窓数は単純比較できない。",
            "",
            "| version | mode | 全窓 | 攻撃窓 | 有効攻撃窓 | skip攻撃窓 | 検知攻撃窓 | FNR |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in four_second_rows:
        if row.get("mode") in {"online_after_training", "freeze_after_training"}:
            lines.append(
                f"| 4秒 | {row['mode']} | {row['total_windows']} | {row['attack_windows']} | "
                f"{row['attack_windows']} | 0 | {row['tp']} | {row['fnr']} |"
            )
    for mode, row in periodic.items():
        lines.append(
            f"| 25ms | {mode} | {row['total_25ms_windows']} | {row['attack_windows_total']} | "
            f"{row['attack_windows_valid']} | {row['attack_windows_skipped']} | {row['TP']} | "
            f"{display(row['FNR_valid_attack_windows'])} (valid) |"
        )

    valid_training = int(training_predictions["enough_packets_for_detection"].astype(bool).sum())
    updated_training = int(training_predictions["ema_updated"].astype(bool).sum())
    lines.extend(
        [
            "",
            "## 3. 実装条件と注意",
            "",
            f"- window/step: {WINDOW_SEC * 1000:g} ms / {STEP_SEC * 1000:g} ms。4秒集約は使用していない。",
            f"- packet filter: UDP destination port {UDP_PORT}のみ。TCPと他ポートは除外。",
            f"- score rule: score >= {config.suspicious_threshold}。閾値方向とEMA係数は既存 `paper_reproduction_detector.py` と同一。",
            f"- min_packets_for_detection: {config.min_packets_for_detection}。0～9 packet窓はCSVに残すが判定skip、score=0、EMA更新なし。",
            f"- warmup_windows: {config.warmup_windows}。全窓がvalidなら0.5秒相当だが、実装はvalid窓だけでカウンタを進める。",
            "- IAT variance: 0または1 packet窓は0。ただしこれらはmin packet条件により判定されない。",
            f"- training: 2400窓中valid={valid_training}, EMA更新窓={updated_training}, UDP packets={training_info['udp_packets_in_duration']}。",
            "- EMA初期状態は既存挙動のまま最初の空窓（全特徴量0）から作られる。その後、学習pcapのvalid窓で更新される。",
            "- onlineは現在閾値で判定後にEMA更新する。freezeは学習後状態を評価中に更新しない。",
            "- すべての25ms窓を保存し、NaN・無限値・ゼロ除算がないことを出力検証した。",
            "",
            "## 4. 入力pcap",
            "",
            f"- training: `{training_info['pcap']}` (start_epoch={training_info['start_epoch']})",
        ]
    )
    for info in case_infos:
        lines.append(
            f"- {info['case']}: `{info['pcap']}` (start_epoch={info['start_epoch']}, "
            f"UDP packets={info['udp_packets_in_duration']})"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def rows_for_case(rows: list[dict[str, Any]], case: str) -> dict[str, dict[str, Any]]:
    return {row["mode"]: row for row in rows if row["case"] == case}


def describe_periodic(mode: str, row: dict[str, Any]) -> str:
    feature_counts = {
        "iat_variance": row["iat_crossed_attack_windows"],
        "burst_rate": row["burst_rate_crossed_attack_windows"],
        "payload_size_variance": row["payload_size_crossed_attack_windows"],
        "new_flow_arrival_rate": row["new_flow_crossed_attack_windows"],
    }
    ordered = ", ".join(f"{name}={count}" for name, count in feature_counts.items())
    return (
        f"周期LDoSの{mode}は、全攻撃窓={row['attack_windows_total']}、"
        f"有効攻撃窓={row['attack_windows_valid']}、skip={row['attack_windows_skipped']}、"
        f"検知={row['TP']}、TPR(valid)={display(row['TPR_valid_attack_windows'])}、"
        f"FNR(valid)={display(row['FNR_valid_attack_windows'])}。"
        f"valid攻撃窓のscore 0/1/>=2は {row['attack_valid_score_0_windows']}/"
        f"{row['attack_valid_score_1_windows']}/{row['attack_valid_score_ge_2_windows']}。"
        f"閾値cross数は {ordered}。"
    )


def classify_result(online: dict[str, Any], freeze: dict[str, Any]) -> str:
    valid = min(int(online["attack_windows_valid"]), int(freeze["attack_windows_valid"]))
    if valid == 0:
        return "パケット不足が多く、現状の設定では判断不能"
    detected = max(int(online["TP"]), int(freeze["TP"]))
    if detected > 0:
        return "25ms窓では検知された"
    return "25ms窓でも検知回避した"


def display(value: Any) -> str:
    if value is None or value == "":
        return "N/A"
    return f"{float(value):.6g}"


def write_run_config(
    path: Path,
    config: PaperDetectorConfig,
    training_info: dict[str, Any],
    case_infos: list[dict[str, Any]],
    four_second_rows: list[dict[str, str]],
) -> None:
    payload = {
        "window_sec": WINDOW_SEC,
        "step_sec": STEP_SEC,
        "duration_sec": DURATION_SEC,
        "attack_start_sec": ATTACK_START_SEC,
        "attack_end_sec": ATTACK_END_SEC,
        "packet_filter": {"protocol": "UDP", "destination_port": UDP_PORT},
        "detector_config": asdict(config),
        "threshold_directions": {
            "iat_variance": "lower",
            "burst_rate": "upper",
            "payload_size_variance": "lower",
            "new_flow_arrival_rate": "upper",
        },
        "training": training_info,
        "evaluation_cases": case_infos,
        "four_second_reference_rows": four_second_rows,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def validate_case_rows(spec: CaseSpec, rows: list[dict[str, Any]]) -> None:
    expected = int(round(DURATION_SEC / WINDOW_SEC)) * 2
    if len(rows) != expected:
        raise AssertionError(f"{spec.case}: expected {expected} output rows, got {len(rows)}")
    for mode in ("online_after_training", "freeze_after_training"):
        mode_rows = [row for row in rows if row["mode"] == mode]
        if len(mode_rows) != expected // 2:
            raise AssertionError(f"{spec.case}/{mode}: wrong row count")
        if spec.has_attack and sum(row["label"] == "attack" for row in mode_rows) != 1600:
            raise AssertionError(f"{spec.case}/{mode}: attack window count is not 1600")


def validate_outputs(output_dir: Path, summary_rows: list[dict[str, Any]]) -> None:
    if len(summary_rows) != len(EVALUATION_SPECS) * 2:
        raise AssertionError("unexpected summary row count")
    for row in summary_rows:
        if int(row["valid_windows"]) + int(row["skipped_windows"]) != int(row["total_25ms_windows"]):
            raise AssertionError(f"valid/skip mismatch: {row['case']}/{row['mode']}")
        if int(row["attack_windows_valid"]) + int(row["attack_windows_skipped"]) != int(row["attack_windows_total"]):
            raise AssertionError(f"attack valid/skip mismatch: {row['case']}/{row['mode']}")
    required = [
        output_dir / "detector_summary_25ms.csv",
        output_dir / "detector_report_25ms.md",
        output_dir / "run_config.json",
    ]
    if any(not path.is_file() or path.stat().st_size == 0 for path in required):
        raise AssertionError("required output is missing or empty")
