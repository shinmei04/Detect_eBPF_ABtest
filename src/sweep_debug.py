"""Debug helpers for throughput parameter sweep detector inconsistencies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.paper_reproduction_detector import PAPER_FEATURES
from src.utils import ensure_dir, markdown_table


DEBUG_BASE_COLUMNS = [
    "scenario",
    "attack_start_sec",
    "window_index",
    "window_start_sec",
    "window_end_sec",
    "is_warmup",
    "detection_enabled",
    "enough_packets_for_detection",
    "total_packets",
    "true_label",
    "pred_label",
    "true_attack",
    "pred_attack",
    "suspicious_score",
    "tcp_throughput_mbps",
]


def find_scenario_window_logs(sweep_dir: Path) -> dict[str, Path]:
    """Infer original_like and stat_matched window logs from a sweep output directory."""
    summary_path = sweep_dir / "parameter_sweep_summary.csv"
    paths: dict[str, Path] = {}
    if summary_path.exists():
        summary = pd.read_csv(summary_path)
        original = summary[summary["scenario"] == "original_like_ldos"].copy()
        if not original.empty and "throughput_degradation" in original.columns:
            best = original.sort_values("throughput_degradation", ascending=False).iloc[0]
            burst = int(best["burst_pkts_per_bucket"])
            payload = int(best["payload_size"])
            candidate = sweep_dir / f"original_like_burst_{burst}_payload_{payload}" / "window_detailed_log.csv"
            if candidate.exists():
                paths["original_like_ldos"] = candidate
        stat = summary[summary["scenario"] == "stat_matched_ldos"].copy()
        if not stat.empty:
            if "selected_best_for_stat_matched" in stat.columns:
                selected = stat[stat["selected_best_for_stat_matched"].astype(bool)]
                stat = selected if not selected.empty else stat
            row = stat.iloc[0]
            burst = int(row["burst_pkts_per_bucket"])
            payload = int(row["payload_size"])
            candidate = sweep_dir / f"stat_matched_best_burst_{burst}_payload_{payload}" / "window_detailed_log.csv"
            if candidate.exists():
                paths["stat_matched_ldos"] = candidate

    if "original_like_ldos" not in paths:
        candidates = sorted(sweep_dir.glob("original_like_burst_*_payload_*/window_detailed_log.csv"))
        if candidates:
            paths["original_like_ldos"] = candidates[-1]
    if "stat_matched_ldos" not in paths:
        candidates = sorted(sweep_dir.glob("stat_matched_best_burst_*_payload_*/window_detailed_log.csv"))
        if candidates:
            paths["stat_matched_ldos"] = candidates[-1]
    return paths


def load_window_log(path: Path, scenario: str) -> pd.DataFrame:
    """Load and normalize a window detailed log."""
    if not path.exists():
        raise FileNotFoundError(path)
    frame = pd.read_csv(path)
    if "scenario" not in frame.columns:
        frame["scenario"] = scenario
    elif scenario in set(frame["scenario"].astype(str)):
        frame = frame[frame["scenario"].astype(str).eq(scenario)].copy()
    if "true_label" not in frame.columns:
        if "label" in frame.columns:
            frame["true_label"] = frame["label"].astype(str)
        elif "true_attack" in frame.columns:
            frame["true_label"] = np.where(frame["true_attack"].astype(bool), "attack", "benign")
    if "pred_label" not in frame.columns and "pred_attack" in frame.columns:
        frame["pred_label"] = np.where(frame["pred_attack"].astype(bool), "attack", "benign")
    if "true_attack" not in frame.columns and "true_label" in frame.columns:
        frame["true_attack"] = frame["true_label"].astype(str).eq("attack")
    if "pred_attack" not in frame.columns and "pred_label" in frame.columns:
        frame["pred_attack"] = frame["pred_label"].astype(str).eq("attack")
    return frame


def build_window_debug(frame: pd.DataFrame) -> pd.DataFrame:
    """Return per-window feature/EMA/threshold/score debug columns."""
    columns = [column for column in DEBUG_BASE_COLUMNS if column in frame.columns]
    for feature in PAPER_FEATURES:
        candidates = [
            feature,
            f"{feature}_mu",
            f"{feature}_ema",
            f"{feature}_sigma",
            f"{feature}_threshold",
            f"{feature}_margin",
            f"{feature}_abnormal",
            f"{feature}_is_suspicious",
            f"{feature}_ema_updated",
            f"{feature}_ema_skipped",
        ]
        columns.extend(column for column in candidates if column in frame.columns and column not in columns)
    return frame[columns].copy()


def build_score_distribution(logs: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Summarize suspicious score distribution over evaluated attack windows."""
    rows: list[dict[str, Any]] = []
    for scenario, frame in logs.items():
        attack = frame[frame["true_label"].astype(str).eq("attack")].copy()
        if "is_warmup" in attack.columns:
            evaluated = attack[~attack["is_warmup"].fillna(False).astype(bool)]
        else:
            evaluated = attack
        scores = evaluated["suspicious_score"].fillna(0).astype(int) if "suspicious_score" in evaluated else pd.Series(dtype=int)
        row: dict[str, Any] = {
            "scenario": scenario,
            "attack_window_count": int(len(attack)),
            "evaluated_attack_window_count": int(len(evaluated)),
        }
        for score in range(5):
            row[f"score_{score}_count"] = int((scores == score).sum())
        row["mean_score"] = float(scores.mean()) if len(scores) else np.nan
        row["median_score"] = float(scores.median()) if len(scores) else np.nan
        row["max_score"] = int(scores.max()) if len(scores) else 0
        row["threshold_reached_count"] = int((scores >= 2).sum())
        row["threshold_not_reached_count"] = int((scores < 2).sum())
        row["threshold_not_reached_rate"] = safe_divide((scores < 2).sum(), len(scores))
        rows.append(row)
    return pd.DataFrame(rows)


def write_debug_outputs(
    sweep_dir: Path,
    output_dir: Path,
    original_path: Path | None = None,
    stat_path: Path | None = None,
) -> None:
    """Write all requested debug outputs for a sweep result directory."""
    ensure_dir(output_dir)
    paths = find_scenario_window_logs(sweep_dir)
    if original_path is not None:
        paths["original_like_ldos"] = original_path
    if stat_path is not None:
        paths["stat_matched_ldos"] = stat_path

    logs: dict[str, pd.DataFrame] = {}
    for scenario in ["original_like_ldos", "stat_matched_ldos"]:
        if scenario in paths:
            logs[scenario] = load_window_log(paths[scenario], scenario)

    if "original_like_ldos" in logs:
        build_window_debug(logs["original_like_ldos"]).to_csv(
            output_dir / "original_like_window_debug.csv",
            index=False,
        )
    if "stat_matched_ldos" in logs:
        build_window_debug(logs["stat_matched_ldos"]).to_csv(
            output_dir / "stat_matched_window_debug.csv",
            index=False,
        )
    score_distribution = build_score_distribution(logs)
    score_distribution.to_csv(output_dir / "suspicious_score_distribution.csv", index=False)

    (output_dir / "phase3_vs_sweep_diff.md").write_text(
        build_phase3_diff_markdown(sweep_dir, paths, logs),
        encoding="utf-8",
    )
    (output_dir / "stat_matched_definition_check.md").write_text(
        build_stat_matched_definition_markdown(paths, logs),
        encoding="utf-8",
    )
    (output_dir / "debug_summary.md").write_text(
        build_debug_summary_markdown(score_distribution, paths, logs),
        encoding="utf-8",
    )


def build_phase3_diff_markdown(
    sweep_dir: Path,
    paths: dict[str, Path],
    logs: dict[str, pd.DataFrame],
) -> str:
    """Build Markdown describing Phase3 vs throughput sweep differences."""
    rows = [
        [
            "Traffic sequence",
            "benign UDP baseline for duration_sec, then periodic LDoS for duration_sec",
            "current profile: TCP-only pre-period, then UDP attack; phase3 profile restores UDP baseline",
        ],
        [
            "original_like benign baseline",
            "h4 normal_benign UDP",
            "current profile: none before attack; phase3 profile: h4 normal_benign UDP",
        ],
        [
            "stat_matched benign baseline",
            "h4 random_microburst UDP",
            "current profile: none before attack; phase3 profile: h4 random_microburst UDP",
        ],
        ["attack traffic", "h3 periodic_ldos UDP", "h3 periodic_ldos UDP"],
        ["window_sec / step_sec / bucket_ms", "4s / 1s / 25ms by default", "same by default"],
        ["warmup", "warmup can learn non-attack UDP baseline", "current profile warmup may start on attack packets"],
        ["label policy", "attack if window_start_sec >= attack_start_sec", "current profile used overlap; phase3 uses start>=attack_start"],
        ["detector logic", "4 features + EMA + suspicious score >= 2", "unchanged"],
    ]
    lines = [
        "# Phase3 vs throughput parameter sweep difference",
        "",
        f"- sweep_dir: `{sweep_dir}`",
        f"- original_like window log: `{paths.get('original_like_ldos', 'not found')}`",
        f"- stat_matched window log: `{paths.get('stat_matched_ldos', 'not found')}`",
        "",
        markdown_table(["item", "Phase3 Mininet A/B", "throughput-parameter-sweep"], rows),
        "",
        "## Main finding",
        "",
        "The current throughput sweep measured TCP baseline before attack, but did not send a UDP benign baseline before attack. "
        "Because the detector only advances warmup on windows with enough UDP packets, the pre-attack TCP-only period does not train "
        "the EMA baseline for the four UDP-derived features. The first enough-packet windows can therefore be attack windows, causing "
        "EMA warmup/adaptation on attack traffic and making original_like_ldos appear as benign.",
        "",
        "The added `--detector-profile phase3` profile restores Phase3-compatible UDP baseline traffic and label timing without changing "
        "the detector implementation.",
    ]
    if logs:
        lines.extend(["", "## Observed loaded logs", ""])
        for scenario, frame in logs.items():
            attack = frame[frame["true_label"].astype(str).eq("attack")]
            warmup = frame[frame["is_warmup"].fillna(False).astype(bool)] if "is_warmup" in frame else pd.DataFrame()
            lines.append(f"- `{scenario}`: windows={len(frame)}, attack_windows={len(attack)}, warmup_windows={len(warmup)}")
    return "\n".join(lines) + "\n"


def build_stat_matched_definition_markdown(paths: dict[str, Path], logs: dict[str, pd.DataFrame]) -> str:
    """Build Markdown checking whether stat_matched is actually stat-matched."""
    lines = [
        "# stat_matched_ldos definition check",
        "",
        "## Code-level check",
        "",
        "- current throughput profile: `stat_matched_ldos` sends only h3 periodic LDoS after `attack_start_sec`; no h4 random_microburst baseline is sent before attack.",
        "- current throughput profile: `original_like_ldos` also sends h3 periodic LDoS after `attack_start_sec`; with the same burst/payload parameters, detector input can be effectively the same except for scenario name.",
        "- phase3 profile: `stat_matched_ldos` sends h4 random_microburst as the benign baseline, then h3 periodic LDoS as attack.",
        "- phase3 profile: `original_like_ldos` sends h4 normal_benign as the benign baseline, then h3 periodic LDoS as attack.",
        "",
        "## Interpretation",
        "",
        "The current profile is useful for TCP impact timing, but it is not Phase3-equivalent as a detector evaluation. "
        "For detector comparison, use `--detector-profile phase3` so that the EMA baseline is learned from the intended benign UDP distribution.",
        "",
    ]
    rows = []
    for scenario, path in paths.items():
        rows.append([scenario, str(path), "found" if path.exists() else "missing"])
    if rows:
        lines.extend(["## Loaded window logs", "", markdown_table(["scenario", "path", "status"], rows), ""])
    if logs:
        lines.extend(["## Feature means by true label", ""])
        rows = []
        for scenario, frame in logs.items():
            for label in ["benign", "attack"]:
                subset = frame[frame["true_label"].astype(str).eq(label)]
                if subset.empty:
                    continue
                for feature in PAPER_FEATURES:
                    if feature in subset.columns:
                        rows.append([scenario, label, feature, f"{float(subset[feature].mean()):.6g}"])
        if rows:
            lines.append(markdown_table(["scenario", "label", "feature", "mean"], rows))
            lines.append("")
    return "\n".join(lines) + "\n"


def build_debug_summary_markdown(
    score_distribution: pd.DataFrame,
    paths: dict[str, Path],
    logs: dict[str, pd.DataFrame],
) -> str:
    """Build final debug summary Markdown."""
    metrics_rows = []
    for scenario, frame in logs.items():
        if "is_warmup" in frame.columns:
            evaluated = frame[~frame["is_warmup"].fillna(False).astype(bool)]
        else:
            evaluated = frame
        attack = evaluated[evaluated["true_label"].astype(str).eq("attack")]
        missed = attack[~attack["pred_label"].astype(str).eq("attack")]
        detected = attack[attack["pred_label"].astype(str).eq("attack")]
        metrics_rows.append(
            [
                scenario,
                str(len(attack)),
                str(len(detected)),
                str(len(missed)),
                f"{safe_divide(len(missed), len(attack)):.3f}",
            ]
        )
    score_rows = []
    for row in score_distribution.itertuples(index=False):
        score_rows.append(
            [
                row.scenario,
                str(row.evaluated_attack_window_count),
                str(row.score_0_count),
                str(row.score_1_count),
                str(row.score_2_count),
                str(row.score_3_count),
                str(row.score_4_count),
                f"{row.threshold_not_reached_rate:.3f}",
            ]
        )
    lines = [
        "# Sweep detector debug summary",
        "",
        "## Conclusion",
        "",
        "The likely cause of original_like_ldos FNR=1.0 in the throughput sweep is not a detector-code change. "
        "It is an experiment-profile mismatch: the current throughput sweep has a TCP-only pre-attack period, so the detector does not learn "
        "a benign UDP baseline before LDoS starts. Since warmup advances only on enough-packet UDP windows, EMA can warm up on attack windows.",
        "",
        "A second issue is that current-profile `stat_matched_ldos` is not actually using a random_microburst benign baseline; it is mostly "
        "the same periodic attack traffic as `original_like_ldos` under the same burst/payload parameters.",
        "",
        "The implementation now supports `--detector-profile phase3` to re-run throughput-impact and parameter-sweep experiments with "
        "Phase3-compatible UDP baseline traffic and label timing. The detector logic itself is unchanged.",
        "",
    ]
    if metrics_rows:
        lines.extend(
            [
                "## Loaded log metrics",
                "",
                markdown_table(["scenario", "attack windows", "detected", "missed", "FNR"], metrics_rows),
                "",
            ]
        )
    if score_rows:
        lines.extend(
            [
                "## Suspicious score distribution for evaluated attack windows",
                "",
                markdown_table(
                    ["scenario", "attack windows", "score0", "score1", "score2", "score3", "score4", "score<2 rate"],
                    score_rows,
                ),
                "",
            ]
        )
    lines.extend(
        [
            "## Output files",
            "",
            f"- original_like source: `{paths.get('original_like_ldos', 'not found')}`",
            f"- stat_matched source: `{paths.get('stat_matched_ldos', 'not found')}`",
        ]
    )
    return "\n".join(lines) + "\n"


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide with zero handling."""
    return 0.0 if denominator == 0 else float(numerator / denominator)
