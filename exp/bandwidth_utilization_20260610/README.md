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
sudo ./exp/bandwidth_utilization_20260610/run.sh --smoke
```

Local/dry smoke test without Mininet:

```bash
./exp/bandwidth_utilization_20260610/run.sh --smoke --synthetic-test
```

Focused experiment:

```bash
sudo -v
sudo ./exp/bandwidth_utilization_20260610/run.sh --focused
```

Useful overrides:

```bash
sudo ./exp/bandwidth_utilization_20260610/run.sh \
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
`s2` side.  The primary presentation analysis uses Capture B
(`capture_egress_pcap`) only, filters packets in the receiver direction, and
counts IPv4 total length (`ip.len`).  Capture A is used only to estimate offered
attack load before the bottleneck.

Ethernet frame length (`frame.len`) is retained as a diagnostic L2 load, but it
is not compared to the configured 15 Mbps bottleneck in presentation metrics.
ARP and non-IPv4 traffic are excluded from the IP utilization calculation.

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

Here `G_TCP`, `G_attack`, and `G_other` are computed from IPv4 total length on
the s2 side of the bottleneck.  Normal TCP includes receiver-bound TCP data
packets, including retransmissions; ACK-only TCP packets are excluded from
normal TCP and remain in `other` only if they are receiver-bound IPv4 packets.
Attack traffic includes constant UDP, periodic LDoS, random microbursts,
stat-matched LDoS, and feint packets sent to the attack UDP port.

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
out/YYYYMMDD_HHMMSS/
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

## Existing Focused-Run Reanalysis

Do not modify the original focused result directory:

```text
results_bandwidth_20260610_20260610_142643/
```

Create an archive with a symlink to the original and write recomputed outputs
under `experiment_archive_20260610/recomputed_ip/`:

```bash
mkdir -p experiment_archive_20260610/{recomputed_l2,recomputed_ip,reports,manifests}
ln -sfn ../results_bandwidth_20260610_20260610_142643 experiment_archive_20260610/original_focused
python3 exp/bandwidth_utilization_20260610/recompute_bandwidth_from_pcap.py \
  --results-dir results_bandwidth_20260610_20260610_142643 \
  --output-dir experiment_archive_20260610/recomputed_ip \
  --l2-output-dir experiment_archive_20260610/recomputed_l2 \
  --reports-dir experiment_archive_20260610/reports \
  --manifests-dir experiment_archive_20260610/manifests
```

The reanalysis writes:

- `recomputed_pcap_case_bandwidth_ip_20260610.csv`
- `recomputed_pcap_aggregated_bandwidth_ip_20260610.csv`
- `recomputed_pcap_scenario_bandwidth_ip_20260610.csv`
- `recomputed_bandwidth_validation_20260610.md`

L2 diagnostic CSVs are written under `experiment_archive_20260610/recomputed_l2/`.

## Stat-Matched Budget

For `stat_matched_ldos`, the sender now treats the configured average attack
load as a total budget:

```text
target burst average + feint average = configured_average_attack_mbps
```

The F-LDDoS sender therefore lowers the effective aggregate burst rate when a
feint rate is enabled.  Sender summaries and recomputed pcap CSVs include:

```text
configured_total_attack_avg_mbps
measured_total_attack_offered_mbps
measured_total_attack_passed_mbps
attack_rate_error_pct
attack_rate_match_status
```

## tc/qdisc Capture

Future real Mininet runs save qdisc and link state for both bottleneck
interfaces (`s1-*` and `s2-*`) in each case:

```bash
tc -s -d qdisc show dev <iface>
tc -s -d class show dev <iface>
tc -s qdisc show dev <iface>
tc -d qdisc show dev <iface>
tc -s class show dev <iface>
tc -d class show dev <iface>
ip -s link show dev <iface>
```

Case metadata also records `shaping_interface`, `configured_bottleneck_mbps`,
`configured_queue_packets`, `qdisc_kind`, `qdisc_rate`,
`qdisc_dropped_packets`, `qdisc_overlimits`, `qdisc_requeues`, and
`qdisc_backlog`.

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
sudo ./exp/bandwidth_utilization_20260610/run.sh \
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
sudo ./exp/bandwidth_utilization_20260610/run.sh \
  --focused \
  --disable-offloads
```

Changing offload settings can change the experimental condition, so the before
and after states are saved in case metadata and raw logs.

## TCP5 / Attack5 Mode 20260611

The `20260611` mode keeps this experiment separate from the earlier
unlimited-TCP runs.  Normal TCP is limited with iperf3 bitrate control, while
the bottleneck remains 15 Mbps.  The presentation bandwidth metric is still the
s2-side post-bottleneck pcap, receiver direction only, using IPv4 total length.

Smoke:

```bash
sudo ./exp/bandwidth_utilization_20260610/run.sh \
  --tcp5-attack5-smoke \
  --existing-repo-dir "$PWD"
```

Focused, to run only after smoke passes:

```bash
sudo ./exp/bandwidth_utilization_20260610/run.sh \
  --tcp5-attack5-focused \
  --existing-repo-dir "$PWD"
```

Defaults for this mode:

```text
bottleneck = 15 Mbps
normal TCP target = 5 Mbps, 1 iperf3 TCP flow
attack peak = 15 Mbps
period = 1000 ms
burst = 333.333 ms
average attack rate = about 5 Mbps
bucket = 25 ms
TCP_INFO interval = 50 ms
```

Smoke uses seed 1, duration 20 seconds, attack start 5 seconds, and evaluation
window 7 to 18 seconds.  Focused uses seeds 1 through 5, duration 60 seconds,
attack start 20 seconds, and evaluation window 25 to 55 seconds.

The no-attack seed is validated before attack cases run.  The seed is accepted
when iperf3 receiver TCP is within 10% of 5 Mbps, with `matched` reported for
within 5%, `warning` for 5 to 10%, and `failed` above 10%.  Failed seeds are
not used for attack cases.

Outputs are written under:

```text
results_tcp5_attack5_20260611_<timestamp>/
```

Key outputs include:

```text
csv/case_metrics_20260611.csv
csv/bandwidth_timeseries_20260611.csv
csv/cycle_bandwidth_metrics_20260611.csv
csv/attack_rate_validation_20260611.csv
csv/tcp_rate_validation_20260611.csv
csv/rto_events_20260611.csv
csv/detector_metrics_20260611.csv
csv/aggregated_metrics_20260611.csv
summary_for_chatgpt_20260611.md
ldos_tcp5_attack5_chatgpt_compact_20260611_<timestamp>.zip
```

## RTO Calibration Grid 20260611

The RTO calibration modes reuse the TCP5/Attack5 machinery but vary the LDoS
peak rate and the s1-side bottleneck queue limit to find the smallest condition
that produces this chain:

```text
attack pulse -> qdisc drop -> TCP retransmission or RTO/backoff -> TCP loss
```

Only `no_attack` and `periodic_ldos` are run.  Fixed settings:

```text
bottleneck = 15 Mbps
normal TCP target = 5 Mbps, 1 iperf3 TCP flow
average offered attack = 5 Mbps
period = 1000 ms
seed = 1
duration = 20 seconds
attack start = 5 seconds
evaluation = 7 <= t < 18
bucket = 25 ms
TCP_INFO interval = 50 ms
```

The grid is:

```text
peak = 15, 30, 45, 60 Mbps
queue = 50, 100, 200 packets
burst_ms = 1000 * 5 / peak
```

Smoke runs only `peak=30 Mbps, queue=100 packets`:

```bash
sudo ./exp/bandwidth_utilization_20260610/run.sh \
  --rto-calibration-smoke \
  --existing-repo-dir "$PWD"
```

Run the full 12-condition grid only after smoke passes:

```bash
sudo ./exp/bandwidth_utilization_20260610/run.sh \
  --rto-calibration-grid \
  --existing-repo-dir "$PWD"
```

Each RTO calibration run writes:

```text
results_rto_calibration_20260611_<timestamp>/
```

Major outputs:

```text
csv/case_metrics_20260611.csv
csv/qdisc_metrics_20260611.csv
csv/retransmission_events_20260611.csv
csv/rto_events_20260611.csv
csv/detector_metrics_20260611.csv
csv/ranking_20260611.csv
figures/01_peak_queue_heatmap_20260611.png/.pdf
figures/02_best_condition_timeseries_20260611.png/.pdf
rto_calibration_chatgpt_compact_20260611_<timestamp>.zip
```

The attack rate validity check uses the s1-side offered attack rate, not the
s2-side passed rate, because qdisc drops are part of the condition being tested.
The main bandwidth and TCP degradation metrics still use the s2-side pcap,
receiver direction, and IPv4 total length.  `tshark` retransmission labels are
kept separate from direct TCP_INFO RTO/backoff observations; if `tshark` is not
installed, retransmission status is recorded as `unavailable`.
