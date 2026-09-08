# DPSWS TCP-unlimited re-experiment

This experiment reuses the adopted `c15_tcp6m_avg30` main condition and changes
only the TCP sender target from `6.0 Mbps` to unset (`None`). This makes the
embedded iperf3 client omit `--bitrate 6M`; no sender TBF is installed.

Unchanged values are: bottleneck 15 Mbps, Reno, SACK off, delay 20 ms, queue 100
packets, duration 60 s, UDP interval 10-50 s, R=15 Mbps, L=300 ms, T=1000 ms,
payload 80 B, and one UDP flow. Detector evaluation uses the existing
`train_random_avg10` pcap and `online_after_training` mode with 25 ms buckets,
4 s windows, 1 s steps, and the unchanged score threshold of 2.

Run one condition as root:

```bash
./run.sh --condition baseline --trial 1 --output-dir <run-root>/runs/baseline_trial_1
./run.sh --condition ldos --trial 1 --output-dir <run-root>/runs/ldos_trial_1
```

Aggregate without generating figures:

```bash
../../.venv/bin/python analyze.py <run-root>
```
