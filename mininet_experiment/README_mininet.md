# Mininet A/B Experiment

## 目的

Mininet上でA/B通信を実パケットとして再現し、pcapから既存4特徴量を抽出して、元論文型4特徴量detectorの検知性能を確認します。

目的は、Python人工bucket列で見えた以下の傾向が、Mininet上のUDP実パケット列でも再現するかを確認することです。

- `original_like`: 通常benign baselineに対してperiodic LDoSを検知できるか。
- `stat_matched`: random microburst baselineに対して、統計特徴量が近いperiodic LDoSを見逃しやすくなるか。

## 実行環境

- WSL2 Ubuntuを想定しています。
- macOSネイティブではMininetを実行しません。
- Mininet実行にはroot権限が必要です。
- 外部ネットワークには送信しません。
- Mininet内部の `10.0.0.0/8` アドレスのみを使います。

## セットアップ

WSL2 Ubuntu上で実行してください。

```bash
bash scripts/setup_wsl_ubuntu_mininet.sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Mininetの状態が壊れた場合は、以下でクリーンアップします。

```bash
sudo mn -c
```

## トポロジ

```text
h1: TCP sender
h2: receiver / UDP sink / iperf server
h3: periodic_ldos generator
h4: random_microburst or normal benign generator

h1 ---- s1 ---- s2 ---- h2
h3 ---- s1
h4 ---- s1
```

リンク条件:

```text
h1-s1: 100 Mbps, delay 10ms
h3-s1: 100 Mbps, delay 10ms
h4-s1: 100 Mbps, delay 10ms
s2-h2: 100 Mbps, delay 10ms
s1-s2: 15 Mbps, delay 20ms
```

`s1-s2` をボトルネックリンクにします。

## 実行例

root権限が必要なので `sudo` を使います。

```bash
sudo .venv/bin/python mininet_experiment/run_mininet_ab_experiment.py \
  --duration-sec 60 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --payload-size 80 \
  --seed 1 \
  --output-dir results_mininet_ab
```

デフォルトでは `original_like` と `stat_matched` の両方を実行します。片方だけ実行する場合は、以下のように指定します。

```bash
sudo .venv/bin/python mininet_experiment/run_mininet_ab_experiment.py \
  --scenarios stat_matched \
  --output-dir results_mininet_ab
```

## 実験の流れ

各scenarioでは、同じpcap内にbenign baseline区間とattack区間を順番に記録します。

- `original_like`
  - h1 -> h2: TCP iperf3 background traffic
  - h4 -> h2: 低レート・非バーストnormal benign UDP
  - h3 -> h2: periodic LDoS UDP
- `stat_matched`
  - h4 -> h2: random microburst UDP
  - h3 -> h2: periodic LDoS UDP

pcapはh2側の `h2-eth0` で `tcpdump` により取得します。その後、`pcap_to_features.py` がUDP packetを復元し、以下の4特徴量だけを計算します。

- `iat_variance`
- `burst_rate`
- `payload_size_variance`
- `new_flow_arrival_rate`

検知器は既存の `src/paper_reproduction_detector.py` を使います。

```text
4特徴量
  -> EMA
  -> dynamic threshold
  -> suspicious score
  -> score >= 2 でattack判定
```

Goertzel法やSliding DFTなどの周波数特徴は、このMininet主実験では使いません。

## 出力

```text
results_mininet_ab/
  original_like/
    original_like.pcap
    send_logs/
    sink_log.csv
    features.csv
    predictions.csv
    metrics.json
    confusion_matrix.png
  stat_matched/
    stat_matched.pcap
    send_logs/
    sink_log.csv
    features.csv
    predictions.csv
    metrics.json
    confusion_matrix.png
  mininet_ab_summary.md
  mininet_ab_overview.png
  metrics_comparison.csv
  metrics_comparison.png
  feature_distribution_original_like.png
  feature_distribution_stat_matched.png
  suspicious_score_distribution_stat_matched.png
```

`mininet_ab_overview.png` は、F1/FPR/FNR、confusion matrix、detection delay、特徴量差分、suspicious score推移を1枚にまとめた概要図です。実験スクリプト完了時に自動生成されます。

既存の結果ディレクトリから概要図だけ作り直す場合:

```bash
.venv/bin/python mininet_experiment/plot_mininet_results.py \
  --results-dir results_mininet_ab
```

`results_mininet_ab/`、`*.pcap`、`*.log` は `.gitignore` で除外しています。GitHubには実験コードとREADMEだけをpushし、実験結果は必要に応じてsummaryだけ別途まとめる想定です。

## 評価指標

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- False Negative Rate
- Confusion Matrix
- Detection delay
- periodic LDoSをattackとして検知できた割合
- random microburstまたはnormal benignをattackと誤検知した割合

特に以下を比較します。

- `original_like` のF1 vs `stat_matched` のF1
- F1低下量
- FPR増加量
- FNR増加量

## TCP throughput impact実験

検知を見逃されたstat-matched LDoSが、実際にTCPスループットを低下させるかを確認する追加実験です。既存の検知ロジックは変更せず、4特徴量、EMA動的しきい値、`suspicious_score >= 2` のまま使います。Goertzel、Sliding DFT、周期性特徴量は使いません。

WSL2 Ubuntu上で実行してください。

```bash
sudo .venv/bin/python mininet_experiment/run_throughput_impact_experiment.py \
  --duration-sec 60 \
  --attack-start-sec 20 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --payload-size 80 \
  --seed 1 \
  --output-dir results_throughput
```

比較するscenario:

- `no_attack`: TCPのみ
- `random_microburst_only`: TCP + random microburst
- `original_like_ldos`: TCP + periodic LDoS
- `stat_matched_ldos`: TCP + stat-matched periodic LDoS

`--attack-start-sec` より前からTCPを開始し、攻撃前baseline区間と攻撃中区間を分けて集計します。`normalized_throughput` と `throughput_degradation` は、攻撃中区間の `no_attack` throughputを基準に計算します。

主な出力:

```text
results_throughput/
  throughput_summary.md
  throughput_metrics.csv
  tcp_throughput_timeseries.csv
  window_detailed_log.csv
  detector_metrics.csv
  confusion_matrices.csv
  missed_harmful_windows.csv
  throughput_comparison.png
  normalized_throughput_comparison.png
  detector_vs_throughput_summary.png
  tcp_throughput_timeseries_by_scenario.png
  throughput_degradation_comparison.png
  stat_matched_detection_vs_throughput_timeline.png
```

macOSなどMininetを実行できない環境で、出力生成だけ確認する場合は以下を使います。この結果は実験結果としては使わず、CLIとグラフ生成のスモークテスト用です。

```bash
.venv/bin/python mininet_experiment/run_throughput_impact_experiment.py \
  --synthetic-test \
  --duration-sec 60 \
  --output-dir results_throughput
```

### LDoS parameter sweep

`original_like_ldos` でTCP throughput degradationが大きくなる `burst_pkts_per_bucket` と `payload_size` を探索し、最大degradationの条件を `stat_matched_ldos` に適用します。detectorロジックは変更しません。

```bash
sudo .venv/bin/python mininet_experiment/run_ldos_parameter_sweep.py \
  --duration-sec 60 \
  --attack-start-sec 20 \
  --detector-profile phase3 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket-values 10 20 30 40 \
  --payload-size-values 80 200 400 800 \
  --seed 1 \
  --output-dir results_throughput_sweep
```

`--detector-profile phase3` は、Phase3のMininet A/B実験に合わせて、攻撃前にUDP benign baselineを流してからperiodic LDoSを流します。`original_like_ldos` では `normal_benign` baseline、`stat_matched_ldos` では `random_microburst` baselineを使います。`current` profileはTCPスループット測定のためにTCP-only pre-periodを置く旧設定で、detectorのEMA baseline学習にはPhase3と異なる条件になります。

主な出力:

```text
results_throughput_sweep/
  parameter_sweep_summary.csv
  parameter_sweep_summary.md
  degradation_heatmap.png
```

検知結果が想定と違う場合は、windowごとの特徴量、EMA、threshold、suspicious scoreを以下で確認できます。

```bash
.venv/bin/python mininet_experiment/debug_sweep_detection.py \
  --sweep-dir results_throughput_sweep \
  --output-dir results_sweep_debug
```

出力:

```text
results_sweep_debug/
  phase3_vs_sweep_diff.md
  original_like_window_debug.csv
  stat_matched_window_debug.csv
  suspicious_score_distribution.csv
  stat_matched_definition_check.md
  debug_summary.md
```

### Stat-matchedness / TCP degradation tradeoff

R/L/T/payloadをgrid searchして、4特徴量のstat-matched性、TCP throughput degradation、detector FNRのトレードオフを可視化します。detectorロジックは変更せず、周期性指標は分析用にのみ出力します。

```bash
sudo .venv/bin/python mininet_experiment/run_tradeoff_experiment.py \
  --duration-sec 60 \
  --attack-start-sec 20 \
  --detector-profile phase3 \
  --grid-search \
  --attack-rate-mbps-values 30 60 90 120 150 \
  --burst-ms-values 100 150 200 250 300 400 \
  --period-ms-values 800 1000 1200 1500 \
  --payload-size-values 80 750 1000 1200 1472 \
  --seed 1 \
  --output-dir results_tradeoff
```

途中再開:

```bash
sudo .venv/bin/python mininet_experiment/run_tradeoff_experiment.py \
  --duration-sec 60 \
  --attack-start-sec 20 \
  --detector-profile phase3 \
  --grid-search \
  --resume \
  --output-dir results_tradeoff
```

RTO presetのみ:

```bash
sudo .venv/bin/python mininet_experiment/run_tradeoff_experiment.py \
  --duration-sec 60 \
  --attack-start-sec 20 \
  --detector-profile phase3 \
  --attack-preset all_rto \
  --seed 1 \
  --output-dir results_tradeoff_rto
```

主な出力:

```text
results_tradeoff/
  tradeoff_all_conditions.csv
  pareto_optimal_conditions.csv
  top_tradeoff_candidates.csv
  tradeoff_summary.md
  final_claim_evaluation.md
  tradeoff_similarity_vs_degradation.png
  tradeoff_maxdiff_vs_degradation.png
  tradeoff_3d_similarity_degradation_fnr.png
  pareto_front_similarity_degradation.png
  fnr_vs_feature_similarity.png
  fnr_vs_degradation.png
  feature_diff_breakdown_top_candidates.png
  degradation_by_r_l_t_payload_heatmap.png
  success_level_scatter.png
```


## 注意

- この実験は元論文の完全再現ではありません。
- eBPF/XDPはまだ使っていません。
- Goertzel/Sliding DFTも使っていません。
- 元論文型4特徴量detectorのMininet上での追加評価です。
- Python人工bucket列で見えた傾向が実パケット列でも再現するかを見るための実験です。
- tcpdump、iperf3、Mininetがない場合、実験スクリプトは分かりやすいエラーで停止します。
- 実験失敗時にも、スクリプトはMininetをstopし、`mn -c` 相当のcleanupを試みます。

## トラブルシュート

Mininet関連のプロセスやインタフェースが残った場合:

```bash
sudo mn -c
sudo service openvswitch-switch start || true
```

pcapが空の場合:

- `results_mininet_ab/<scenario>/tcpdump.log` を確認してください。
- `results_mininet_ab/<scenario>/udp_sink.log` を確認してください。
- `send_logs/` に送信ログが出ているか確認してください。
- WSL2 Ubuntu上で `sudo` 実行しているか確認してください。
