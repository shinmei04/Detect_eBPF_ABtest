# LDoS研究実装 引渡し報告

完了日: 2026-09-09 JST。作業対象: `/Users/niimi/Study/m1/ebpf-research/implementation`。変更元HEAD: `f23163093e008b03ec7e4f5dddb8d20c32f7eef6`。

## 調査で確認したこと

詳細な8項目の成果は [REPOSITORY_AUDIT.md](REPOSITORY_AUDIT.md) に記載。

1. データフロー: 保存/Mininet PCAP → IPv4 UDP dst5001 → 25 ms buckets → 窓全体の4特徴 → EMA閾値 → flag和 → CSV/JSON。
2. 特徴位置: `src/paper_reproduction_detector.py:compute_paper_window_features`。別の`src/features.py`とはburst/new-flow定義が異なる。
3. 閾値: 更新前mu±beta*sigma、sigmaはEMA絶対偏差、異常でない特徴だけ更新（warmup例外）。10 packets gate、有効窓20個のwarmup。
4. score: 4 flagの和、>=2。今回>=1も同じscoreから比較可能。
5. 既存評価: `src/detector_evaluation.py`、`scripts/run_paper_reproduction_experiment.py`、Mininet配下、archiveの25 ms比較、論文根拠データのfreeze評価、analysis補助作図。
6. 追加コード: paired分析、詳細ログ、明示時刻原点、ラベル境界・イベント遅延、時間特徴、config/provenance、テスト。
7. 最初の仮説: 閾値追従だけでなくgate・下限0・特徴無変動・窓幅・score構成が見逃しを生む可能性。
8. ロードマップ: 保存capture再解析 → >=1のTPR/FPR確認 → 必要なら時間特徴・正常周期・jitter → accuracy/cost → XDP候補選定。

**重要な未確定事項:** 現行は25 msごとの5-tuple別検知ではない。既定4秒窓/1秒step、状態は入力全体に1組。現行原稿のsource-port定義とも異なる。原稿の81.8%低下と各capture/生成commitの対応は未確認。これらを研究上の確定事実へ置き換えていない。

## 変更ファイルと理由

| ファイル | 内容・理由 |
|---|---|
| `src/paper_reproduction_detector.py` | 既定分類を保つfreeze引数、raw/effective flag、更新理由・margin追加。原因切り分け。 |
| `mininet_experiment/pcap_to_features.py` | tcpdump失敗を空正常captureとして扱わず例外にする。 |
| `src/research_analysis.py` | 同じ正常trainからdynamic/freeze、>=2/1、ラベル境界、イベントlatency、CSV/JSONとSHA256、任意の独立校正ルール。 |
| `src/temporal_features.py` | Jain/CV/ACF/FFTの共通interface、intensity/duty/duration/flow補助列。未来非参照。 |
| `scripts/analyze_research.py` | 再解析CLI。ネットワーク送信を行わない。 |
| `scripts/pcap_to_research_packets.py` | 実験start_epochを必須とする保存PCAP→packet CSV。 |
| `scripts/make_research_fixture.py` | seed/period/burst/rate/payload/start/flow/jitter/window/stepを変更できる小さな人工CSV。 |
| `scripts/plot_research.py` | 生値・更新前閾値・flag・score・labelを一緒に可視化。 |
| `configs/research_replay.example.json` | 実データの条件記入用。未確認payload/flow数を勝手に埋めない。 |
| `tests/test_research_analysis.py` | 既存判定の回帰・境界・freeze・時間特徴・CLI統合を検証。 |
| `docs/REPOSITORY_AUDIT.md` | README、原稿、実装、config、旧評価、過去結果、Git履歴の監査と8項目。 |
| `docs/RESEARCH_ANALYSIS.md` | 入出力契約、各指標/時間特徴の定義、実行手順と限界。 |
| `EXPERIMENT_PLAN.md` | 指定8見出しで保存capture再解析、条件/回収物/解釈分岐を整理。 |
| `RESEARCH_LOG.md` | 日付、仮説、変更/理由、実験待ち、結果/解釈、次仮説、失敗/保留案。 |
| `NOVELTY_NOTES.md` | 単純改善/既存方式との差、弱点、未検証の主張候補。 |
| `README.md` | 新しい分析入口と現行方式の位置付け。 |
| `docs/IMPLEMENTATION_REPORT.md` | この引渡し記録。 |

## テスト結果

- `python -m unittest discover -s tests -v`: **14件成功、約1秒**（Python 3.12.14 / NumPy 2.3.5 / pandas 2.2.3）。
- 変更元commitのdetectorを読み込み、warmup 0/2/20、空窓、異常値を含む入力で既存の全出力列が一致。
- freeze不変・初期閾値一致、score==2、lower threshold=0、packet gate、学習不備拒否。
- 手計算した混同行列とlatency、多イベント未検知null、境界窓、future非参照、Jain/CV同値、定数列未定義。
- 破損PCAPのエラー伝播（mock、実ネットワークなし）、独立校正ルール必須。
- 同じseedから同じCSV、25 ms/4 sの両方で4条件×2モード×3方式（>=2、>=1、テスト専用Jainルール）の統合処理。
- `python -m compileall -q src scripts tests mininet_experiment`: 成功。
- `git diff --check`: 成功。
- 8秒の人工CSVから4条件×dynamic/freezeのログ、metrics、buckets、provenanceを生成。診断図を生成・目視確認（Matplotlib 3.9.4）。

本実験、長時間評価、既存大容量PCAPの全再解析は未実施。人工fixtureの検知率は実データの研究成果として掲載しない。実PCAP parserの正常capture実機検証、元81.8%結果再現、CPU/メモリ/XDP評価は実験PC側の確認事項。

## 実験用PCで次にすること

1. 変更コードを同期し、commit/dirty diffと実行環境を保存する。
2. 正常trainと評価capture、各start_epoch/duration、attack interval、seed、payload/flow定義を回収する。
3. `EXPERIMENT_PLAN.md`のPCAP変換を実行し、実条件を埋めたconfigで25 msと4 sを再解析する。
4. `metrics.json`だけでなく各windowの4生値・閾値・raw/effective flag・更新理由を回収する。
5. >=1が高TPR/低FPRなら時間特徴追加を正当化せず、score方式を再検討する。正常周期をJainが拾う場合は複合特徴へ分岐する。

実験計画の環境変数は実験PCの保存ファイル/メタデータから設定する。新規ネットワーク本実験のrunnerは、不足正常条件と元runの対応を確認してから追加する。
