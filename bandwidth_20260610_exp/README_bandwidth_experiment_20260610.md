# LDoS Bandwidth Experiment 20260610

Created: 2026-06-10  
Purpose: 25 ms detector window comparison experiment.

This bundle adds a non-destructive pipeline for evaluating whether periodic
LDoS traffic with average attack load at or below about one third of the
bottleneck capacity can reduce TCP throughput more than constant UDP or random
microbursts while avoiding the existing 25 ms detector.

## Existing Code Reuse

The real Mininet runner reuses the existing repository components instead of
rewriting the experiment:

- `Detect_eBPF_ABtest_mininet/mininet_experiment/minimal_topo.py`
  provides the h1/h2/h3/h4, s1/s2 topology.
- `Detect_eBPF_ABtest_mininet/mininet_experiment/traffic_generators/send_composite_lddos.py`
  sends `random_microburst_only`, `composite_lddos`, and
  `stat_matched_composite_lddos`.
- `Detect_eBPF_ABtest_mininet/mininet_experiment/pcap_to_features.py`
  extracts the four detector features from UDP pcap.
- `Detect_eBPF_ABtest_mininet/src/paper_reproduction_detector.py`
  runs the reproduced four-feature detector.

The existing topology defines the bottleneck on `s1-s2` as `bw=15`, so the
default capacity is `--bottleneck-mbps 15`.  The runner auto-detects the
`s1-s2` interface pair.  Override with `--capture-ingress-iface` and
`--capture-egress-iface` if needed.

## Commands

Smoke test on WSL/Ubuntu with Mininet:

```bash
sudo -v
sudo ./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh --smoke
```

Local/dry smoke test without Mininet:

```bash
./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh --smoke --synthetic-test
```

Focused experiment:

```bash
sudo -v
sudo ./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh --focused
```

Useful overrides:

```bash
sudo ./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh \
  --focused \
  --bottleneck-mbps 15 \
  --period-ms 1000 \
  --tcp-info-interval-ms 50 \
  --rto-causal-window-ms 500 \
  --seed-values 1 2 3 \
  --duration-sec 60 \
  --attack-start-sec 20
```

## Focused Grid

The default grid does not run a full parameter search.  It evaluates only:

| condition_id | R/C | L/T | configured average load |
|---|---:|---:|---:|
| avg10_peak1 | 1.0 | 0.10 | 10% |
| avg20_peak1 | 1.0 | 0.20 | 20% |
| avg30_peak1 | 1.0 | 0.30 | 30% |
| avg30_peak1_5 | 1.5 | 0.20 | 30% |
| avg30_peak3 | 3.0 | 0.10 | 30% |

Rows with configured average load above 33% of C are excluded.

Formulas:

```text
R_avg = R * L / T
A_configured = R_avg / C
```

## Scenarios

The output CSV keeps these scenario names:

- `no_attack`
- `constant_udp`
- `random_microburst`
- `periodic_ldos`
- `stat_matched_ldos`

Existing sender names are mapped internally:

```text
random_microburst -> random_microburst_only
periodic_ldos     -> composite_lddos
stat_matched_ldos -> stat_matched_composite_lddos
```

## Capture Points

Two pcaps are saved for each real case:

- Capture A: `raw/pcaps/ingress_before_bottleneck_20260610.pcap`
- Capture B: `raw/pcaps/egress_after_bottleneck_20260610.pcap`

Capture A is the `s1` side of the `s1-s2` bottleneck link.  Capture B is the
`s2` side.  The analysis uses Capture A for offered attack load and Capture B
for passed TCP, attack, other, and idle capacity.

The pcap parser prefers tcpdump Ethernet-frame length when available.  If
tcpdump output does not expose frame length, it falls back to transport payload
length.  The same length source is used for all traffic classes in a run.

## Bandwidth Metrics

For each 25 ms bucket:

```text
G_total = G_TCP + G_attack + G_other
G_idle = max(C - G_total, 0)
U = G_total / C * 100
S_TCP = G_TCP / C * 100
S_attack = G_attack / C * 100
S_idle = G_idle / C * 100
capacity_excess_mbps = max(G_total - C, 0)
```

The attack evaluation interval defaults to:

```text
evaluation_start = attack_start_sec + 5
evaluation_end = duration_sec - 5
```

TCP degradation:

```text
D_s = 1 - G_TCP,s / G_TCP,no_attack
```

Excess degradation is a percentage-point difference:

```text
excess_vs_random = D_periodic_or_stat_matched - D_random
excess_vs_constant = D_periodic_or_stat_matched - D_constant
```

Example: 50% minus 36% is 14 percentage points.

## Output

Each run creates:

```text
results_bandwidth_20260610_YYYYMMDD_HHMMSS/
  cases/
  csv/
  figures/
  logs/
  metadata_20260610.json
  summary_20260610.md
```

CSV outputs:

- `csv/bandwidth_timeseries_20260610.csv`
- `csv/case_metrics_20260610.csv`
- `csv/detector_metrics_20260610.csv`
- `csv/aggregated_metrics_20260610.csv`

Figures are written as PNG and PDF:

- `01_bandwidth_timeseries_<condition>_<scenario>_seed<seed>_20260610`
- `02_bandwidth_share_stacked_20260610`
- `03_attack_load_vs_tcp_degradation_20260610`
- `04_excess_degradation_vs_fnr_20260610`
- `bandwidth_share_table_20260610.md`

## Dependencies

Real Mininet execution needs:

- `tcpdump`
- `iperf3`
- `tc`
- `ip`
- `mn`
- `ovs-vsctl`
- `ss`
- `ethtool` when `--disable-offloads` is used
- Python packages already used by the existing repo, especially pandas, numpy,
  and matplotlib.

Local synthetic smoke mode uses the standard library for execution and
analysis.  The plotter uses matplotlib when available and otherwise writes
placeholder PNG/PDF files so CI-style smoke tests can still verify file
creation.

## TCP RTO Collection

RTO and congestion-control state are collected on the TCP sender host.  Because
the current TCP data connection is owned by iperf3, the pipeline uses method B:
periodic `ss -tin` sampling inside the Mininet host namespace.

Default:

```text
tcp_info_interval_ms = 50
```

The interval is configurable:

```bash
sudo ./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh \
  --focused \
  --tcp-info-interval-ms 100
```

For each case the raw output and sampler overhead are saved under:

```text
cases/<case_id>/raw/tcp_info/<case_id>/ss_raw_20260610.log
cases/<case_id>/raw/tcp_info/<case_id>/tcp_info_timeseries_20260610.csv
cases/<case_id>/raw/tcp_info/<case_id>/sampler_metrics_20260610.txt
```

The sampler records:

- sample count
- mean and maximum `ss` execution time
- missed sample deadline count and rate
- sampler CPU user/system percentage

RTO samples are collected at 50 ms by default.  They are joined to the 25 ms
bandwidth and detector timeline by carrying the previous observed TCP_INFO
sample forward.  This avoids fabricating intermediate RTO/backoff states.

## RTO Event Semantics

The pipeline treats these as direct RTO observations:

```text
current retransmits > previous retransmits
or
current backoff > previous backoff
```

Stable samples such as `backoff=1,1,1` do not create additional RTO events.
`backoff 1 -> 2` is counted as a new RTO/backoff-stage event.

pcap/tshark retransmission labels are saved separately in
`tcp_retransmission_events_20260610.csv`.  They are useful for distinguishing
normal retransmission, Fast Retransmit, spurious retransmission, and duplicate
ACKs, but they are not treated as direct RTO observations.  This prevents
retransmitted packets from being incorrectly equated with RTO.

RTO episode start:

```text
backoff changes from 0 to >= 1
```

RTO episode end:

```text
backoff returns to 0
or the TCP flow ends
```

## Attack Pulse Alignment

Attack pulses are saved per case:

```text
cases/<case_id>/raw/pulses/attack_pulses_20260610.csv
```

Each pulse row includes scheduled and actual epoch nanoseconds where available.
For existing composite LDoS senders, the pipeline derives pulse timing from
`composite_sender_log_20260610.csv`; for synthetic smoke tests it writes
deterministic pulse rows.

The RTO analyzer computes:

- RTO retransmission collision rate
- pulse-end to RTO event rate within `--rto-causal-window-ms`
- RTO-to-pulse phase difference in milliseconds
- phase normalized by period
- pulse-before and pulse-after cwnd, RTO, backoff, retransmission, and TCP rate

## Additional RTO Outputs

Additional CSV files:

- `csv/tcp_info_timeseries_20260610.csv`
- `csv/rto_events_20260610.csv`
- `csv/rto_episodes_20260610.csv`
- `csv/tcp_retransmission_events_20260610.csv`
- `csv/pulse_tcp_alignment_20260610.csv`
- `csv/rto_aggregated_metrics_20260610.csv`

Additional figures:

- `05_rto_timeline_<condition>_<scenario>_seed<seed>_20260610.png/.pdf`
- `06_rto_event_count_by_scenario_20260610.png/.pdf`
- `07_rto_episode_time_share_20260610.png/.pdf`
- `08_rto_collision_vs_tcp_degradation_20260610.png/.pdf`
- `09_rto_to_pulse_phase_distribution_20260610.png/.pdf`
- `10_rto_vs_detection_timeline_20260610.png/.pdf`

## Offload Notes

pcap TCP sequence analysis can be affected by TSO/GSO/GRO and other offloads.
The pipeline saves `ethtool -k <interface>` output for the bottleneck capture
interfaces when `ethtool` is available.  It does not disable offloads by
default.  To disable TSO/GSO/GRO for the capture interfaces:

```bash
sudo ./bandwidth_20260610_exp/run_ldos_bandwidth_grid_20260610.sh \
  --focused \
  --disable-offloads
```

Changing offload settings can change the experimental condition, so the before
and after states are saved in case metadata and raw logs.
