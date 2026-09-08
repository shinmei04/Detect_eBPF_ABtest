# DPSWS TCP-unlimited 10-trial / 25 ms evaluation

This experiment adds trials 4-10 to the existing three TCP-unlimited trials
without changing traffic parameters. Detector evaluation imports and reuses
the verified direct-window implementation in
`exp/detector_25ms_20260714/analyze.py` (`window=step=25 ms`).

Existing trials remain under `exp/dpsws_tcp_unlimited_20260724/out/20260724_131803`.
New runs and integrated outputs are written under this experiment's
`out/YYYYMMDD_HHMMSS/` directory.
