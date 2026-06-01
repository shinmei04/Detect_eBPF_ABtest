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
