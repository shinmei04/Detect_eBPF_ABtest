# Repository Result Inventory 20260709

This inventory records the current interpretation of result-bearing directories
in `Detect_eBPF_ABtest`. The first pass was non-destructive classification; the
2026-07-09 cleanup then moved legacy local scratch material into
`experiments/archive_unused/` while leaving current DPSWS result paths in place.

## Status Labels

- `manuscript_ready`: can be used directly for the current DPSWS manuscript.
- `reproducibility_support`: supports a manuscript-ready result or separated
  supplementary table.
- `historical_exploratory`: keep for lineage, but do not use as current main
  evidence.
- `quarantine_unknown`: preserve, but do not cite until provenance is recovered.
- `code_or_docs`: reusable code, setup scripts, or documentation rather than
  result evidence.

## Current DPSWS Result Lineage

| Path | Status | Use | Notes |
| --- | --- | --- | --- |
| `experiments/dpsws_phase4_final_summary_20260709/` | `manuscript_ready` | DPSWS Phase 4 manuscript-facing summary, tables, and figures. | Derived artifact only. It intentionally excludes SACK-on results and separates supplementary fixed-evaluation rows. |
| `experiments/dpsws_random_and_sack_check_20260709/out/20260709_162027/` | `reproducibility_support` | Source run for Phase 4 periodic-vs-random controls. | Contains both SACK-off and SACK-on cases. For the current Phase 4 manuscript, use SACK-off rows only. |
| `experiments/dpsws_random_and_sack_check_20260709/` | `reproducibility_support` | Runner, scheduler, analysis, plotting code for the current random-control and SACK-check run. | Do not treat the whole directory as manuscript-ready because it includes SACK-on supplementary material. |
| `experiments/dpsws_additional_eval_20260709/out/20260709_150637/` | `reproducibility_support` | Fixed DPSWS additional evaluation and validation outputs. | Use only as separated supplementary evidence, especially feature-distance/detector-behavior context. |
| `experiments/dpsws_additional_eval_20260709/` | `reproducibility_support` | Runner and analyzer for fixed DPSWS additional evaluation. | Not the current Phase 4 main artifact. |
| `experiments/main_ldos_tcp6m/` | `reproducibility_support` | Earlier selected main-condition baseline, detector results, scripts, raw pcaps. | Important lineage and raw evidence. Do not mix directly into Phase 4 current-results tables unless explicitly labeled as support. |

## Archive and Historical Buckets

| Path | Status | Use | Notes |
| --- | --- | --- | --- |
| `experiments/archive_unused/failed_training_candidates/` | `historical_exploratory` | Failed benign-training/stat-matched candidate searches. | Keep for lineage; not manuscript evidence. |
| `experiments/archive_unused/old_greedy_tcp_trials/` | `historical_exploratory` | Older C=15 Mbps trials without the final TCP=6 Mbps shaping target. | Different condition; not current DPSWS evidence. |
| `experiments/archive_unused/old_low_capacity_trials/` | `historical_exploratory` | Older C=1.5 Mbps and queue exploration. | Different capacity/queue regime. |
| `experiments/archive_unused/obsolete_figures/` | `historical_exploratory` | Old figure/value files. | Keep only as provenance; not current figures. |
| `experiments/archive_unused/local_experiment_workspace_legacy_20260709/` | `historical_exploratory` | Legacy local scratch results, logs, archives, CSV/JSON, images, and compact ZIP files formerly under `local_experiment_workspace/`. | Large local-only provenance archive; not manuscript evidence. |
| `experiments/archive_unused/organization_dry_runs/organization_dry_run_20260709/` | `historical_exploratory` | Prior file-organization dry-run plans. | Administrative artifact, not experiment evidence. |
| `experiments/archive_unused/unknown_files/` | `quarantine_unknown` | Files with unclear or non-minimal provenance. | Do not cite until path-level metadata is recovered. |

## `exp/` Experiments

| Path | Status | Use | Notes |
| --- | --- | --- | --- |
| `exp/bandwidth_utilization_20260610/` | `historical_exploratory` | Earlier bandwidth/RTO calibration and detector-window exploration. | Useful context, but not current DPSWS Phase 4 evidence unless reclassified. |
| `exp/rto_cycle_20260617/` | `historical_exploratory` | RTO/backoff behavior under periodic UDP burst periods. | Mechanism context only; not current main-result evidence. |
| `exp/ldos_quick_check_20260707/` | `historical_exploratory` | Earlier LDoS quick-check runs and candidate searches. | Keep for lineage; do not use as current Phase 4 result without re-analysis. |
| `exp/README.md` | `code_or_docs` | Historical experiment inventory. | Existing inventory, not a result. |

## Reusable Code and Documentation

| Path | Status | Use | Notes |
| --- | --- | --- | --- |
| `src/` | `code_or_docs` | Reusable detector/evaluation code. | Do not archive as result data. |
| `mininet_experiment/` | `code_or_docs` | General Mininet experiment utilities and older runners. | Contains reusable machinery; some scripts may generate exploratory data. |
| `scripts/` | `code_or_docs` | General scripts and maintenance utilities. | Keep separate from result evidence. |
| `tests/` | `code_or_docs` | Tests. | Keep. |
| `docs/` | `code_or_docs` | Inventories, policies, experiment notes. | Current organizing layer. |
| `experiments/archive_unused/local_experiment_workspace_legacy_20260709/` | `historical_exploratory` | Local scratch or workspace material. | Formerly `local_experiment_workspace/`; keep out of manuscript result flow unless specifically inventoried. |

## What To Do With Results Not Used In The Paper

Do not delete them. Classify them:

1. If they are old but understandable: `historical_exploratory`.
2. If they are raw evidence for a current or supplementary claim:
   `reproducibility_support`.
3. If the condition or provenance is unclear: `quarantine_unknown`.
4. If they are derived manuscript outputs: place them in a dated summary
   directory and classify as `manuscript_ready` only when the source and scope
   are explicit.

Current cleanup action is limited physical archiving: legacy scratch material is
under `experiments/archive_unused/`, while current DPSWS result and support
directories keep their original paths.
