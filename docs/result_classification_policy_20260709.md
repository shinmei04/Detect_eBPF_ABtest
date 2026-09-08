# Result Classification Policy 20260709

This repository contains reusable detector code, Mininet runners, raw experiment
outputs, derived manuscript figures, and older exploratory runs. Do not decide
whether a result is usable from its directory name alone. Classify it by
measurement conditions, detector settings, and whether the raw evidence needed
for validation is still available.

## Classification Levels

| Level | Label | Meaning | Paper Use |
| --- | --- | --- | --- |
| A | `manuscript_ready` | Current manuscript-facing result or derived artifact. Conditions, detector rule, and aggregation are aligned with the current DPSWS claim. | Main text, main tables, main figures. |
| B | `reproducibility_support` | Raw data, validation outputs, source summaries, or fixed supplementary evaluations that support A-level results. | Methods, appendix, reproducibility notes, separated supplementary tables. |
| C | `historical_exploratory` | Older exploration, parameter search, pre-current detector settings, different TCP/capacity settings, or results not re-evaluated under the current 25 ms detector pipeline. | Do not use as main evidence. Keep for lineage and ideas. |
| D | `quarantine_unknown` | Unknown provenance, missing metadata, partial output, duplicate/cached material, or unclear condition/detector settings. | Do not cite until reclassified. |

## Current DPSWS Main-Result Gate

A result can be promoted to `manuscript_ready` for the current DPSWS Phase 4
story only if it satisfies all of the following:

- closed Mininet environment
- bottleneck: 15 Mbps
- TCP target: 6 Mbps
- TCP congestion control: Reno
- SACK: off
- duration: 60 s
- attack window: 10-50 s
- UDP destination port: 5001
- detector bucket: 25 ms
- detector window: 4 s
- detector step: 1 s
- detector rule: score >= 2
- detector features: `iat_variance`, `burst_rate`, `payload_size_variance`, `new_flow_arrival_rate`
- summary CSV, detector-window CSV, case metadata, and raw validation evidence are available or traceable
- results are not exploratory parameter search outputs

If any of these are missing, the result should not be used in a main DPSWS table
or figure. It can still be kept as `reproducibility_support`,
`historical_exploratory`, or `quarantine_unknown`.

## Handling Older Non-25ms Results

Older results that were not evaluated with the 25 ms bucket / 4 s detector
window / score >= 2 pipeline should be classified as `historical_exploratory`
unless they are reprocessed and validated under the current pipeline. Keep them
because they may explain the research path or motivate follow-up experiments,
but do not mix them into current DPSWS claims.

Examples of reasons to keep but not cite as current results:

- detector bucket/window differs from the current Phase 4 setting
- TCP target or bottleneck differs from the current DPSWS condition
- SACK setting is mixed or not recorded
- result came from parameter search or failed benign-training search
- goodput aggregation definition is older or unclear
- raw pcap, iperf JSON, nstat, qdisc, or case metadata are missing

## Safe Organization Rules

- Do not delete raw `pcap`, `json`, `csv`, or `md` evidence during cleanup.
- Do not physically move a result until it has an inventory entry and a target
  classification.
- Prefer adding inventory rows over renaming old result directories.
- If physical moves are later needed, use `git mv` for tracked files and update
  Python, shell, README, tests, and `.gitignore` references in the same change.
- Do not use names such as `final`, `latest`, `new`, `old`, `fix`, or `v2` for
  new experiment directories.
- Derived manuscript summaries should live separately from raw experiment runs.

## Promotion Rules

`historical_exploratory` can be promoted only after a deliberate re-analysis or
rerun plan records:

- exact source path
- detector configuration
- TCP/SACK/capacity/queue settings
- attack window definition
- goodput aggregation definition
- raw evidence availability
- reason it now satisfies the current claim

`quarantine_unknown` can be promoted only after provenance is recovered. If the
condition cannot be reconstructed, leave it quarantined.

## Current Practical Rule

For the DPSWS manuscript, use:

- `manuscript_ready`: `experiments/dpsws_phase4_final_summary_20260709/`
- `reproducibility_support`: current DPSWS raw/source runs and fixed validation
  runs listed in `docs/repo_result_inventory_20260709.md`
- `historical_exploratory`: older `exp/` and archived parameter-search results
  unless separately reclassified
- `quarantine_unknown`: archive buckets explicitly marked unknown or partial

