# RTO Cycle Experiment 20260617

This experiment observes whether periodic UDP bursts align with TCP RTO/backoff behavior in Mininet.

## Topology

```text
TCP sender h1 -> router r1 -> TCP receiver h2
Attacker h3   -> router r1
```

The `r1 -> h2` link is the bottleneck. Defaults:

- duration: 60 sec
- TCP-only phase: 0-10 sec
- UDP burst phase: 10-50 sec
- recovery phase: 50-60 sec
- bottleneck: 1.5 Mbps
- one-way bottleneck delay: 20 ms
- queue: DropTail, 20 packets
- burst rate: 3 Mbps
- burst length: 200 ms
- cases: `base`, `t0800`, `t1000`, `t1200`

`base` is the TCP-only baseline. The other cases differ only in UDP burst period.

## Run

```bash
sudo ./exp/rto_cycle_20260617/run.sh --smoke
sudo ./exp/rto_cycle_20260617/run.sh
sudo ./exp/rto_cycle_20260617/run.sh --cases t1000
```

Outputs are written to:

```text
exp/rto_cycle_20260617/out/YYYYMMDD_HHMMSS/
```

All main experiment parameters are CLI-configurable. Useful examples:

```bash
sudo ./exp/rto_cycle_20260617/run.sh \
  --cases t0800 t1000 \
  --duration-sec 60 \
  --attack-start-sec 10 \
  --attack-end-sec 50 \
  --bottleneck-mbps 1.5 \
  --delay-ms 20 \
  --queue-packets 20 \
  --burst-rate-mbps 3 \
  --burst-ms 200 \
  --case-period-ms t0800=800 t1000=1000 t1200=1200
```

## Collected Data

Each case stores raw logs under `cases/<case>/raw/`:

- `iperf3.json`
- `bottleneck_before.pcap`
- `bottleneck_after.pcap`
- `pulses.csv`
- `ss_raw.log`
- `nstat_before.txt`, `nstat_after.txt`
- `qdisc_before.txt`, `qdisc_after.txt`
- `tcp_config.txt`

`pulses.csv` records both epoch and monotonic timestamps for scheduled and actual pulse timing, plus actual duration, sent bytes, expected bytes, and skip reason. Pulse scheduling, sleep, end checks, and send intervals use `time.monotonic_ns()`; epoch timestamps are logs only.

Top-level analysis outputs:

- `config.json`
- `summary.csv`
- `timeline.csv`
- `retrans_events.csv`
- `report.md`
- `manifest.txt`
- `rto_cycle_<datetime>_summary.zip`
- `rto_cycle_<datetime>_full.zip`

The summary ZIP includes processed analysis, config, iperf3 JSON, processed ss/nstat/qdisc files, pulse logs, and manifest. The full ZIP also includes pcaps and raw logs.

## RTO Classification

pcap retransmission count alone is not treated as RTO evidence. The analyzer combines:

- pcap retransmission and Fast Retransmit markers when `tshark` is available
- duplicate ACK markers when available
- retransmission interval compared with sender RTO
- sender-side `ss -tin` RTO/backoff/cwnd/retransmission state
- `nstat` timeout counter deltas

Event classification values are:

- `confirmed`
- `probable`
- `not_observed`
- `unknown`
- `invalid_timing`

`invalid_timing` is reported when any UDP pulse duration differs from its scheduled duration by more than 10 ms, or sent bytes differ from the theoretical byte count by more than 5%.
