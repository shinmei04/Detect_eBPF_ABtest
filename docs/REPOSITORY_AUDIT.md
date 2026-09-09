# LDoS検知研究の調査・実装ロードマップ

調査日: 2026-09-08。現行実装 HEAD: `f23163093e008b03ec7e4f5dddb8d20c32f7eef6`（変更前 clean）。原稿 HEAD: `69c6e56`。参照会話の全文を確認。実ネットワーク実験・長時間評価はこのMacでは実施しない。

## 1. 現在の検知データフロー

`mininet_experiment/run_mininet_ab_experiment.py:run_one_scenario` → Mininet受信PCAP → `pcap_to_features.py:parse_udp_pcap`（IPv4 UDP宛先5001のみ）→ `build_features_from_pcap`（最初の選択UDPを時刻0、25 ms bucket、IP/portからflow_id）→ `compute_paper_window_features`（既定4 s窓、1 s step）→ `PaperReproductionDetector.predict_stream` → predictions CSV / metrics JSON / plots。

flow_idは特徴計算に使うが、検知状態は窓全体に1組。5-tupleごとの独立検知ではない。現行再現器にXDPロードや実際のdrop処理はなく、drop_decisionは予測値。TCPはgoodput測定には使うが検知入力には入らない。BaselineをUDPフィルタで評価すると空入力になるため、全TCP正常通信でのFPRを意味しない。

現行TeXの160–162行はsource-portをフロー識別子と明記している。過去監査メモが指摘した「原稿5-tuple」の記述は現行原稿にはそのまま当てはめない。一方、現行PythonのIP/port連結IDとは一致しない。複数IPが同じsource-portを使う条件で差が生じるため、source-port版・5-tuple版を同一方式と呼ばない。

人工系列の入口は `main.py`、`scripts/run_paper_reproduction_experiment.py`。`pattern_generator.py`の正常マイクロバーストはIATを合わせ1 Hzを弱める候補選択を含む。一般的な正常分布の代表と扱わず、独立したランダム系列でも検証する。

## 2. 4特徴量の実装位置

主対象は `src/paper_reproduction_detector.py:compute_paper_window_features`。

| 特徴 | 式・単位 | 判定方向 |
|---|---|---|
| IAT variance | 選択パケット全体の隣接時刻差の母分散、s² | 値 < 下限 |
| burst rate | 窓内packet数 / 窓秒数、packet/s | 値 > 上限 |
| payload size variance | packet_sizeの母分散、byte²。PCAP入口ではUDP payload | 値 < 下限 |
| new flow arrival rate | 窓内unique flow_id数 / 窓秒数、flow/s | 値 > 上限 |

注意: new-flowは実験全体で初めて現れたflow数ではない。`src/features.py:compute_window_features`は別定義（burst=max bucket count、new-flow=全体で初出）。`paper_like_detector.py`も全特徴が上限判定、EMA分散方式なので混用不可。

## 3. 閾値更新

`PaperReproductionDetector._threshold/_update_feature`。上限=mu+beta*sigma、下限=max(mu-beta*sigma,0)。sigmaは標準偏差ではなくEMA絶対偏差。muを更新した後の偏差を使う。旧状態重みはIAT/burst 0.3、payload/new-flow 0.85。betaは順に19.4/48.5/24.25/3.233。

判定は更新前状態を使用。10 packets未満なら更新・warmup進行なし。warmup中またはその特徴が非異常の場合だけ更新。既定warmupは有効窓20個。初期状態は最初の行（空窓でも）の観測値、sigma=max(abs(value)*0.05,1e-12)。下限0かつ分散0ではstrict `<`が成立しない。この初期化・packet gate・ゼロ下限も原因候補。

## 4. score判定

`_predict_one`で4つの有効anomaly flagの和。packet gateとwarmup通過後、`score >= suspicious_threshold`。既定2。blocked_after_windowは履歴値であり現在窓の判定ではない。単純baselineは同じscoreから>=2と>=1を比較すればEMA差の交絡を避けられる（現行EMA更新は総scoreに依存しない）。

## 5. 既存分析・評価・過去結果・履歴

- `scripts/run_paper_reproduction_experiment.py`: 特徴生成、検知、混同行列、遅延、要約。
- `src/detector_evaluation.py`: paper-like用TPR相当recall/FPR/F1/遅延・EMA分析。欠損分母0の値を0と返し、遅延に窓開始時刻fallbackがあるため、新評価では未定義=null、判定時刻=窓終了で明示する。
- `mininet_experiment/plot_mininet_results.py`: 既存可視化。
- `analysis/scripts/generate_tcp_udp_retrans_backoff_timeseries.py`: 保存TCP/UDP/retransmissionログの補助作図。
- `archive/exp_202606/20260610_25ms_exp`: 25 ms比較アダプタ・config・テスト。別の旧runnerと旧detectorを参照。旧 `Detect_eBPF_ABtest_mininet/src/paper_reproduction_detector.py` の主要閾値/score処理は現行と一致。
- `manuscript_data/.../experiments/main_ldos_tcp6m/scripts/evaluate_detector_with_training.py`: 正常学習後のfreezeを別関数で再実装。時刻原点にstart_epochを利用するが、無ければ最初のUDPへfallback。
- `manuscript_data/.../experiments/dpsws_phase4_final_summary_20260709/phase4_feature_detection_summary.csv`: 周期、random、clustered、jitterの保存集計。周期L300主runの検知0/40、TCP低下58.5149%。原稿81.8%の10試行集計とは同一条件・runと断定しない。
- 原稿 `papers/dpsws2026/dpsws-jsample.tex` は25 ms逐次更新・10試行・81.8%低下を記述。`data/detector_25ms_main_result.csv`には生値/閾値/flow keyがなく、生成元の同定が必要。2026-07-21監査メモの「import先欠落」は現行cloneで解消されたが、CSVの生成履歴まで証明しない。
- 現行Git履歴は `457fbd1`（実験一式）→ `f231630`（overview）。旧実装には `9118564` 等の別履歴。原稿・archive・過去結果は変更しない。

## 6. 追加すべきコード

現行detectorへ既定動作を保つfreezeオプションと更新理由・生の閾値超過flagを追加。別モジュールに入力検証・明示的時刻原点・学習/評価分離・dynamic/freeze複製・ラベル境界・>=1/2評価・統一CSV/JSON/図を追加。Jain/CV/ACF/FFTは共通の因果的window入力で特徴値を出し、攻撃判定の改善を先取りしない。

## 7. 最初に検証すべき仮説

H1: 見逃しはEMA追従だけでなく、packet gate、下限0、特徴の無変動、窓幅/入力範囲、score>=2の組合せでも生じる。まず同じ正常学習状態と同じ入力でdynamic/freeze、>=2/1、25 ms/4 sを比較する。周期性欠落を原因と断定しない。

H2: 単純>=1はTPRとFPRの両方を変える可能性がある。正常TCP、無選別random burst、benign periodicを含む評価が必要。高TPR/低FPRなら時間構造追加の必要性を再検討する。

## 8. 実装ロードマップ

1. 既存判定を回帰テストで固定し、4特徴量/閾値/flag/score/labelを同じCSVへ保存。
2. 正常trainを共有するdynamic/freezeと>=2/1、窓終了時刻に基づくTPR/FPR/precision/recall/遅延。
3. Jainバースト開始間隔、CV、ACF、FFTを独立実装。正常周期、jitter、intensity/duty/duration/flowを記録。
4. 実験PCで入力原点/実測条件/seedを固定し再評価。テスト用人工系列で研究上の優位性を主張しない。
5. 独立validationで閾値を選び、held-out評価。結果によって複合特徴またはscore/重み付けへ分岐。
6. CPU/memory/processing timeを同条件で測定後、eBPF/XDP整数演算・状態上限・overflow・verifierを検討。


## 2026-09-09 元論文・公開コードによる補足

ユーザー提示PDFのp.24から公開先を同定し、commit 6f118ae22de22df6274a5a06ea25d99ec1d69989を確認した。[追加照合](ORIGINAL_PAPER_AUDIT.md)を参照。特に公開Cは正のmin_thresholdを持つため、本監査の「下限0」の記述は現行Pythonに限定する。本文Algorithm2には総scoreで全更新停止する条件があるが、公開C/現行Pythonの特徴別更新には同じ条件がない。比較対象を区別する。


## ユーザーによる25 ms実行の確認

原稿の評価は実行時に25 msを指定していたとユーザーから説明を受けた。原稿の評価窓は25 msとして扱い、現行コードのデフォルト4秒と混同しない。過去の別評価やデフォルト設定を根拠に、この原稿の実験が4秒だったと推定しない。実行設定の回収は再現性記録を揃えるための作業である。
