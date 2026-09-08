# Experiment Inventory

| Experiment | Date | Purpose | Entry | Status |
|---|---|---|---|---|
| `rto_cycle_20260617` | 2026-06-17 | Observe TCP RTO/backoff behavior under periodic UDP burst periods in Mininet. | `exp/rto_cycle_20260617/run.sh` | Implemented under `exp/`; writes outputs to `out/YYYYMMDD_HHMMSS/`. |
| `bandwidth_utilization_20260610` | 2026-06-10 | 25 ms detector window comparison for LDoS bandwidth utilization. Includes TCP=5 Mbps / attack=5 Mbps and RTO calibration CLI modes added for 2026-06-11 runs. | `exp/bandwidth_utilization_20260610/run.sh` | Organized under `exp/`; code filenames normalized. |
| `ldos_stat_matched_phase1` | unknown | Generate periodic LDoS and random microburst bucket series and compare statistics/frequency features. | `main.py` | Not moved; no explicit experiment date in path or README. |
| `seed_sweep` | unknown | Run Phase 1.5 seed sweep for stat-matched bucket generation. | `scripts/run_seed_sweep.py` | Not moved; no explicit experiment date in path or README. |
| `paper_like_detector` | unknown | Evaluate baseline and frequency-enhanced detector behavior on generated datasets. | `scripts/run_detector_experiment.py` | Not moved; no explicit experiment date in path or README. |
| `paper_reproduction` | unknown | Reproduce a four-feature paper-style detector in Python and compare conditions. | `scripts/run_paper_reproduction_experiment.py` | Not moved; no explicit experiment date in path or README. |
| `miss_analysis` | unknown | Analyze stat-matched missed-attack windows from Mininet detector outputs. | `scripts/run_miss_analysis.py` | Not moved; analysis role is clear, but experiment date is not explicit. |
| `mininet_ab` | unknown | Reproduce A/B traffic as Mininet packets, extract pcap features, and evaluate the four-feature detector. | `mininet_experiment/run_mininet_ab_experiment.py` | Not moved; no explicit experiment date in path or README. |
| `throughput_impact` | unknown | Evaluate whether missed stat-matched LDoS traffic reduces TCP throughput. | `mininet_experiment/run_throughput_impact_experiment.py` | Not moved; no explicit experiment date in path or README. |
| `ldos_parameter_sweep` | unknown | Sweep LDoS parameters for throughput degradation and detector behavior. | `mininet_experiment/run_ldos_parameter_sweep.py` | Not moved; no explicit experiment date in path or README. |
| `tradeoff_analysis` | unknown | Search R/L/T/payload tradeoffs among stat-matchedness, TCP degradation, and detector FNR. | `mininet_experiment/run_tradeoff_experiment.py` | Not moved; no explicit experiment date in path or README. |

## Out of Scope

- `src/`: reusable detector, feature extraction, analysis, and plotting code.
- `tests/`: shared tests for reusable logic.
- `experiments/archive_unused/local_experiment_workspace_legacy_20260709/`: ignored legacy local results, logs, archives, CSV/JSON, images, and compact ZIP files.
- Existing result directories such as `results_*` and `experiment_archive_*`.
- Setup and maintenance utilities such as `scripts/setup_wsl_ubuntu_mininet.sh` and `scripts/organize_local_experiments_20260612.sh`.
