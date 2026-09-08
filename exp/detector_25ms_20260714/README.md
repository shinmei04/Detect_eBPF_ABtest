# Direct 25 ms Detector Evaluation

This experiment evaluates saved pcaps without running Mininet. It computes the
four detector features directly in non-overlapping 25 ms windows and evaluates
both online and frozen EMA modes.

Inputs:

- Normal training: `experiments/main_ldos_tcp6m/raw_pcaps/random_benign_avg10.pcap`
- Periodic LDoS: `experiments/main_ldos_tcp6m/raw_pcaps/periodic_ldos_tcp6m_r15_l300_t1000.pcap`
- TCP-only base: `experiments/main_ldos_tcp6m/raw_pcaps/base_tcp6m.pcap`
- Packet-random control: the saved Phase 4 `true_random_packet_4p5m_sack_off` after-bottleneck pcap

Run:

```bash
./exp/detector_25ms_20260714/run.sh
```

Outputs are written under `out/YYYYMMDD_HHMMSS/`. Existing 4 second detector
code and results are not modified.
