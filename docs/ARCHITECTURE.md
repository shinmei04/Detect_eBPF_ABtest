# 検知・データ処理の構造

## 実装の区分
| 系統 | 特徴抽出 | 判定 | 実行入口 |
|---|---|---|---|
| 簡易版 | `src/features.py` + `src/goertzel.py` | `src/paper_like_detector.py` | `scripts/run_detector_experiment.py` |
| 論文ロジック再現版 | `compute_paper_window_features` | `src/paper_reproduction_detector.py` | `scripts/run_paper_reproduction_experiment.py` |
| 保存pcap・直接25ms | `build_features` | 再現版のonlineと独自frozen処理 | `exp/detector_25ms_20260714/run.py` |

再現版はローカル実装の仕様を記す。参照元URLはコードの`PAPER_SOURCE_*`にあるが、参照時commitは記録されておらず完全な原論文再現とは扱わない。

## 4特徴量
| 名前 | 簡易版 | 再現版 / 直接25ms |
|---|---|---|
| iat_variance | 窓内packet timestampの差の母分散、単位s² | 同じ計算。パケット間隔を窓境界越しに連結しない |
| burst_rate | 最大bucket packet数（ppsではない） | 窓packet数 / window秒（pps） |
| payload_size_variance | packet_sizeの母分散（B²） | 同じ計算。pcapではtcpdumpのUDP lengthを使用 |
| new_flow_arrival_rate | ストリーム全体で初出時刻が窓内のflow数 / window秒 | 窓内unique flow数 / window秒 |

pcapはIPv4 UDP・指定宛先port（通常5001）を抽出し、src/dst IP/portからflowを構成する。TCPは被害評価には使うが、このpcap検知器の特徴入力には含めない。

## 動的閾値とscore
再現版の`XDP_FEATURE_CONFIGS`:

| 特徴 | 旧状態EMA重み a | beta | 異常方向 |
|---|---:|---:|---|
| IAT分散 | 0.30 | 19.4 | value < max(mu - beta*sigma, 0) |
| burst rate | 0.30 | 48.5 | value > mu + beta*sigma |
| payload分散 | 0.85 | 24.25 | value < max(mu - beta*sigma, 0) |
| flow rate | 0.85 | 3.233 | value > mu + beta*sigma |

- 各窓は更新前の状態で判定。異常特徴の個数を加算し、既定score >= 2でattack。
- 既定では10 packet未満の窓は判定・EMA更新・warmupカウンタ増加をしない。warmupは20個の有効窓。
- 最初の行でmu=value、sigma=max(abs(value)*0.05, 1e-12)に初期化（少数packet行でも初期化は行う）。
- 更新はmu'=a*mu+(1-a)*value、sigma'=max(a*sigma+(1-a)*abs(value-mu'), 1e-12)。sigmaは絶対偏差EMAであり標準偏差ではない。
- warmup後は異常とされた特徴だけEMA更新を止める。`blocked_after_window`は履歴であり、後続全窓を強制attackにしない。実パケットdropは行わない。
- 簡易版は全特徴を上側閾値で判定し、alphaは新観測の重み。EMA分散の平方根を使う。conditional_emaはscore条件で全特徴更新を凍結する。再現版と混同しない。

## データ処理の流れ
- 合成: pattern_generator → packet_model → 統計/周波数特徴 → datasetのseed/stream順整列 → fresh detector → 予測CSV → 指標/図。
- 実通信: Mininet + iperf3 + UDP sender → pcap / case.json / pulse・ss・nstat・tcログ → pcap_to_features → ラベル → 再現版 → 窓CSV / 指標。
- 直接25ms: CaseSpecのpcap + case.json.start_epoch → 実験基準時刻へ変換 → 60秒を2400窓へ分割 → 正常pcapで学習 → 各testへ状態をdeepcopy → online/frozen → all/valid別集計。
- 25ms評価は攻撃期間[10,50)秒との重なりでラベルを付ける。random_packet対照も既存CaseSpecではhas_attack=Trueであり、正常学習データとは別物。
- 汎用pcap抽出は時刻原点未指定なら最初のUDP時刻を使う。再現時はcaseの原点を指定する。phase_labelingのtarget_period/target_burst/target_feintを取り違えない。

## 周期性を追加する位置
既に簡易版では`src/detector_dataset.py::_features_from_buckets`で統計と周波数特徴を窓キーで結合し、`FREQUENCY_ENHANCED_FEATURES`で2特徴を追加している。
`src/goertzel.py`は平均除去したbucket列に対し1Hzと0.8/0.9/1.0/1.1/1.2Hz帯等を計算し、N*sum(centered²)で正規化する。ゼロエネルギーは0。帯域値は離散周波数の和である。
再現版への周期性追加は未実装。4特徴の基準を維持し、新実験でbucket履歴から特徴を計算して既存窓と時刻を合わせる位置が候補。scoreへの加点・gate・別段判定は未決定。
25msの1窓だけでは1秒周期を観測できない。周期性の履歴長と判定stepを分離し、未来のデータを使わない評価が必要。
