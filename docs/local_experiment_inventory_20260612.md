# Local Experiment Inventory 2026-06-12

Large experiment artifacts are kept out of Git and organized under:

```text
local_experiment_workspace/
```

## Groups

```text
00_ab_throughput_tradeoff/
  results_mininet_ab/
  results_throughput/
  results_throughput_sweep/
  results_tradeoff/

01_phaseaware_ldos/
  results_flddos_phaseaware_onecase/
  results_phaseaware_grid_54_20260604_155650/
  results_phaseaware_grid_63_20260604_155530/

02_bandwidth_20260610/
  results_bandwidth_20260610_20260610_142104/
  results_bandwidth_20260610_20260610_142643/
  results_bandwidth_20260610_iprerun/
  experiment_archive_20260610/
  experiment_archive_20260610_iprerun/

03_tcp5_rto_20260611/
  results_tcp5_attack5_20260611_20260611_153019/
  results_rto_calibration_20260611_20260611_165912/
  results_rto_calibration_20260611_20260611_170800/

archive_legacy_code/
  run_phaseaware_grid_54.sh
  run_phaseaware_grid_63.sh
  legacy_experiment_code_20260612.tar.gz

logs/
  focused_20260610_20260610_142643.log
  results_phaseaware_grid_54_20260604_155650.log
  results_phaseaware_grid_63_20260604_155530.log
  rto_calibration_grid_20260611_165912.log
  rto_calibration_grid_20260611_170800.log
```

## Current Maintained Code

- `bandwidth_20260610_exp/`: 20260610/20260611 bandwidth, TCP5/Attack5, RTO calibration, pcap reanalysis.
- `mininet_experiment/`: Mininet topology, traffic generators, and AB-style experiment entry points.
- `src/`: detector, feature extraction, analysis, and plotting libraries.
- `scripts/`: maintained utility launchers plus the local organizer.

## Notes

- `local_experiment_workspace/` is intentionally ignored by Git.
- Raw pcaps, large result trees, and run logs should stay local unless a small
  summary or compact ZIP is explicitly needed for sharing.
- To re-run the organization step safely:

```bash
./scripts/organize_local_experiments_20260612.sh
```
