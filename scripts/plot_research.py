#!/usr/bin/env python3
"""Plot one case/mode log with raw values, thresholds, flags, score and labels."""
from pathlib import Path
import argparse
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.paper_reproduction_detector import PAPER_FEATURES


def plot(csv: Path, output: Path) -> None:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    frame = pd.read_csv(csv)
    figure, axes = plt.subplots(5, 1, figsize=(12, 12), sharex=True, constrained_layout=True)
    t = frame.decision_time_sec
    for axis, feature in zip(axes, PAPER_FEATURES):
        axis.plot(t, frame[feature], label="raw", linewidth=1)
        axis.plot(t, frame[f"{feature}_threshold"], label="threshold before update", linewidth=1)
        crossed = frame[f"{feature}_is_suspicious"].astype(str).str.lower().eq("true")
        axis.scatter(t[crossed], frame.loc[crossed, feature], s=12, label="effective anomaly")
        axis.set_ylabel(feature)
        axis.legend(loc="upper right", fontsize=7)
    axes[-1].step(t, frame.suspicious_score, where="post", label="score")
    axes[-1].axhline(2, linestyle="--", label="Original >=2")
    axes[-1].axhline(1, linestyle=":", label="Relaxed >=1")
    axes[-1].set_ylim(-0.2, 4.5)
    axes[-1].legend()
    # Merge intervals so overlapping windows do not darken or stripe shading.
    spans = []
    for label in ("attack", "transition"):
        merged = []
        for row in frame[frame.label.eq(label)].sort_values("window_start_sec").itertuples():
            if merged and row.window_start_sec <= merged[-1][1] + 1e-10:
                merged[-1][1] = max(merged[-1][1], row.window_end_sec)
            else:
                merged.append([row.window_start_sec, row.window_end_sec])
        spans.extend((a, b, label) for a, b in merged)
    for axis in axes:
        for start, end, label in spans:
            axis.axvspan(start, end, alpha=0.07, color="red" if label == "attack" else "orange")
        axis.grid(alpha=0.2)
    axes[-1].set_xlabel("Decision time (s); red: attack windows, orange: boundary windows")
    figure.suptitle(csv.stem)
    figure.savefig(output)
    plt.close(figure)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    plot(args.windows, args.output)
