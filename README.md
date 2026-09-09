# ldos_stat_matched_phase1

## 現在の研究と実験PCへの引渡し

研究方針の入口は [AGENTS.md](AGENTS.md)、現在の優先作業は [Current Phase](docs/current_phase.md)、引渡しは [HANDOFF.md](docs/HANDOFF.md) を参照してください。5文書はこのGitリポジトリ内にあります。

以下の旧説明にあるPhase番号・固定1 Hzの人工比較・過去の絶対パスは歴史的な実装説明です。現在のPhase 1/2と混同せず、実行は引渡し手順から開始してください。

## 2026-09: 原因分析と単純baseline比較

現行detector互換のオフライン分析基盤を追加しました。
[調査結果](docs/REPOSITORY_AUDIT.md)、[分析手順・入力契約](docs/RESEARCH_ANALYSIS.md)、
[実験PC向け計画](EXPERIMENT_PLAN.md)、[研究ログ](RESEARCH_LOG.md)、[新規性候補](NOVELTY_NOTES.md)を参照してください。
25 ms bucketと判定windowは別設定です。現行再現器は窓全体の集計であり、5-tupleごとの独立検知や元XDPの完全再現ではありません。
Macでは実ネットワーク実験・長時間性能評価を実行しません。

## 実験の目的

純粋なPythonシミュレーションで、周期的なLDoS bucket列と、非周期的な正常マイクロバーストbucket列を生成します。

目的は、既存eBPF/XDP型LDoS検知で使われる軽量な窓内統計特徴量が似ていても、1秒周期の周波数特徴では分離できる条件を人工的に作れるか確認することです。

このPhase 1では、Mininet、ns-3、eBPF/XDP、ソケット通信、実パケット送信は使いません。人工bucket列だけを扱います。

Python 3.10以上を想定しています。

## 背景

既存eBPF/XDP型LDoS検知では、主に以下の4特徴量が使われます。

- Inter-Arrival Time variance
- Burst rate
- Payload size variance
- New flow arrival rate

これらは窓内の軽量統計特徴量です。一方、LDoS攻撃の本質はTCP RTO周期に対応した周期的バースト構造にあります。そのため、統計特徴量が似るA/B条件を作り、Goertzel法による1Hz付近の周波数特徴が差を出せるかを確認します。

## 生成する2種類の通信

### A. periodic_ldos

- label: `attack`
- bucket width: 25 ms
- duration: 60 sec
- period: 1000 ms
- burst length: 200 ms
- burst packets per bucket: 10
- payload size: 80 bytes
- flow mode: `same_flow`

25 ms bucketでは、1周期は40 buckets、burst長は8 bucketsです。各周期の先頭8 bucketsに10 packets/bucketを置き、残り32 bucketsを0にします。

### B. random_microburst

- label: `benign`
- periodic_ldosと総パケット数、burst bucket数、最大bucket count、payload分布、flow modeを一致させます。
- burst phaseをseed付きでランダム化し、同じphaseに周期的にburstが固定されにくいbucket列を生成します。
- 候補列の中から、packet-level IAT varianceをperiodic_ldosに近く保ちつつ、1Hz成分が低い列を選びます。

## 実行方法

```bash
cd /Users/niimi/Study/m1/Detect_ineBPF/compareAB/ldos_stat_matched_phase1
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py \
  --duration-sec 60 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --window-sec 4 \
  --step-sec 1 \
  --seed 1 \
  --output-dir results
```

環境によっては `python` で実行できます。その場合は `.venv/bin/python` を `python` に置き換えてください。

## 出力ファイル

- `results/periodic_ldos_buckets.csv`
- `results/random_microburst_buckets.csv`
- `results/features_periodic_ldos.csv`
- `results/features_random_microburst.csv`
- `results/feature_similarity.csv`
- `results/summary.md`
- `results/bucket_timeseries_example.png`
- `results/stat_features_comparison.png`
- `results/frequency_features_comparison.png`
- `results/feature_distance_summary.png`

## 結果の見方

`results/summary.md` を最初に確認してください。

成功条件は以下です。

- periodic_ldosとrandom_microburstの総パケット数が一致している。
- 既存4特徴量の平均値が近い。
- periodic_ldosの `normalized_1hz_power` が高い。
- random_microburstの `normalized_1hz_power` が低い。
- つまり、窓内統計は類似するが周期性が異なる条件を人工的に作れている。

`feature_similarity.csv` では、各特徴量について平均値、差分、相対差、cosine similarity、standardized distanceを確認できます。

## Phase 1.5: Seed sweep

### 目的

Phase 1のseed=1だけでなく、複数seedでrandom_microburstのburst位置を変えた場合にも、既存4特徴量が類似し、周波数特徴だけがperiodic_ldosで高くなる傾向が安定するか確認します。

### 実行方法

```bash
.venv/bin/python scripts/run_seed_sweep.py \
  --duration-sec 60 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --window-sec 4 \
  --step-sec 1 \
  --seeds 1 2 3 4 5 10 20 30 40 50 \
  --output-dir results_seed_sweep
```

### 出力ファイル

- `results_seed_sweep/seed_sweep_results.csv`
- `results_seed_sweep/seed_sweep_summary.md`
- `results_seed_sweep/seed_sweep_1hz_power.png`
- `results_seed_sweep/seed_sweep_rto_band_power.png`
- `results_seed_sweep/seed_sweep_stat_feature_distance.png`

### 結果の見方

`seed_sweep_summary.md` で、各特徴量のmean/std/min/max、`normalized_1hz_power` ratio、`normalized_rto_band_power` ratioを確認します。

成功条件は、複数seedでperiodic_ldosの周波数特徴がrandom_microburstより高く、`burst_rate`、`payload_size_variance`、`new_flow_arrival_rate` が安定して類似し、`iat_variance` が極端に乖離しないことです。

## Phase 2: Paper-like detector

### 目的

既存eBPF/XDP型LDoS検知で使われる4特徴量に近い簡易detectorを作り、stat-matched条件でperiodic_ldosとrandom_microburstをどの程度識別できるか確認します。さらにGoertzel周波数特徴を追加した場合に、FPR、FNR、F1-scoreなどが改善するか比較します。

### Baseline detector

Baselineは以下の4特徴量だけを使います。

- `iat_variance`
- `burst_rate`
- `payload_size_variance`
- `new_flow_arrival_rate`

各特徴量についてEMA平均とEMA分散を持ち、`value > ema_mean + beta * ema_std` を満たした特徴量数を `suspicious_score` とします。`suspicious_score >= suspicious_threshold` ならattack判定です。

### Frequency-enhanced detector

Frequency-enhancedはBaselineの4特徴量に以下を追加します。

- `normalized_1hz_power`
- `normalized_rto_band_power`

### 評価モード

- `warmup_then_attack`: 最初の20秒はbenign `random_microburst` のみでEMA baselineを学習し、20秒以降に`periodic_ldos`を開始します。detection delayは攻撃開始20秒から計算します。
- `cold_start_attack`: 時刻0から`periodic_ldos`が存在する攻撃ストリームと、時刻0から`random_microburst`だけが存在する正常ストリームを別々に評価します。EMAが攻撃に適応してしまうかを確認します。
- `conditional_ema`: `warmup_then_attack` と同じ時系列で、`suspicious_score` が一定以上のwindowではEMA baselineを更新しません。baseline poisoningを抑制できるか確認します。

### 実行方法

```bash
.venv/bin/python scripts/run_detector_experiment.py \
  --duration-sec 60 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --window-sec 4 \
  --step-sec 1 \
  --seeds 1 2 3 4 5 10 20 30 40 50 \
  --ema-alpha 0.3 \
  --threshold-beta 3.0 \
  --suspicious-threshold 2 \
  --warmup-windows 3 \
  --attack-start-sec 20 \
  --conditional-ema-threshold 1 \
  --output-dir results_detector
```

デフォルトでは `warmup_then_attack`、`cold_start_attack`、`conditional_ema` の3モードをすべて実行します。対象を絞る場合は `--evaluation-modes warmup_then_attack cold_start_attack` のように指定します。warmupを無効化する場合は `--no-warmup` を追加します。

### 評価指標

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- False Negative Rate
- Confusion Matrix
- Detection delay
- 攻撃開始後に何window目で検知したか
- 攻撃中にEMAが適応して異常度が下がったか

### 出力ファイル

- `results_detector/detector_mode_metrics.csv`
- `results_detector/detector_summary.md`
- `results_detector/metrics_comparison.png`
- `results_detector/<mode>_detector_dataset.csv`
- `results_detector/<mode>_baseline_predictions.csv`
- `results_detector/<mode>_frequency_predictions.csv`
- `results_detector/<mode>_metrics_baseline.json`
- `results_detector/<mode>_metrics_frequency.json`
- `results_detector/<mode>_confusion_matrix_baseline.png`
- `results_detector/<mode>_confusion_matrix_frequency.png`
- `results_detector/<mode>_suspicious_score_timeseries_baseline.png`
- `results_detector/<mode>_suspicious_score_timeseries_frequency.png`

### 注意点

- このpaper-like detectorは元論文の完全再現ではありません。
- 既存eBPF/XDP論文の特徴量設計に基づく簡易検知器です。
- 目的は、stat-matched条件において周波数特徴が補完的に有効かを確認することです。
- 結果が改善しない場合も、`detector_summary.md` に理由の考察を記録します。

## Paper reproduction detector: 4-feature rule-based evaluation

### 目的

元論文GitHubリポジトリの `README.md` と `xdp_prog.c` を参考に、4統計特徴量 + EMA dynamic threshold + suspicious score の検知ロジックをPython上で再現し、以下の2条件で検知性能を比較します。

- `original_like`: 通常benign trafficでEMA baselineを学習したあと、periodic LDoSを検知する条件。
- `stat_matched`: random microburstでEMA baselineを学習したあと、統計特徴量が近いperiodic LDoSを検知する条件。

今回の主実験ではLogistic RegressionやRandom Forestは使いません。Goertzel法やSliding DFTなどの周波数特徴も使いません。既存4特徴量だけのrule-based detectorが、stat-matched A/B条件でどの程度崩れるかを確認します。

### 参照元

- Repository: <https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP>
- xdp_prog.c: <https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP/blob/main/xdp_prog.c>
- README: <https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP/blob/main/README.md>

参照した主な要素は、4特徴量、EMA更新、動的閾値、suspicious score、`score >= 2` によるattack/drop判定です。Python版では人工bucket列から作ったwindow特徴量を入力にするため、eBPF/XDPの固定小数点スケールや実パケット処理は完全には再現していません。

### 使用特徴量

- `iat_variance`
- `burst_rate`
- `payload_size_variance`
- `new_flow_arrival_rate`

### 実行方法

```bash
.venv/bin/python scripts/run_paper_reproduction_experiment.py \
  --duration-sec 60 \
  --bucket-ms 25 \
  --period-ms 1000 \
  --burst-ms 200 \
  --burst-pkts-per-bucket 10 \
  --window-sec 4 \
  --step-sec 1 \
  --seeds 1 2 3 4 5 10 20 30 40 50 \
  --warmup-windows 20 \
  --score-threshold 2 \
  --output-dir results_paper_reproduction
```

### 出力ファイル

- `results_paper_reproduction/dataset_original_like.csv`
- `results_paper_reproduction/dataset_stat_matched.csv`
- `results_paper_reproduction/predictions_original_like.csv`
- `results_paper_reproduction/predictions_stat_matched.csv`
- `results_paper_reproduction/metrics_original_like.json`
- `results_paper_reproduction/metrics_stat_matched.json`
- `results_paper_reproduction/metrics_comparison.csv`
- `results_paper_reproduction/confusion_matrix_original_like.png`
- `results_paper_reproduction/confusion_matrix_stat_matched.png`
- `results_paper_reproduction/metrics_comparison.png`
- `results_paper_reproduction/detector_reproduction_summary.md`

### 評価指標

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate
- False Negative Rate
- Confusion Matrix
- Detection delay

### 注意点

- これは元論文の完全再現ではなく、検知ロジックのPython再現です。
- Mininet、ns-3、eBPF/XDP、ソケット通信、実パケット送信は使いません。
- 目的は、stat-matched条件において既存4特徴量だけのrule-based detectorが十分か、または周期性特徴の追加評価が必要かを確認することです。
- 結果が悪くても隠さず、`detector_reproduction_summary.md` に記録します。

## 今後の次ステップ

### Mininet/pcap検証

- このA/B条件をMininet上の実パケット列として再現する。
- pcapから同じ特徴量を抽出する。
- paper-like detectorで判定を比較する。

### 分類器評価

- Goertzel特徴を既存4特徴量に追加した場合の分類性能を評価する。
