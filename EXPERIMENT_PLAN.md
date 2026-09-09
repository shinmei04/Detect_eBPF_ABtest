# LDoS原因切り分けと単純baseline比較

更新: 2026-09-08。本実験は未実施。Macではコード・短時間テストのみ。

## Hypothesis

H1: 閾値追従以外に、packet gate、ゼロ下限、特徴無変動、入力対象・窓幅、score>=2が見逃しに寄与する。H2: >=1だけでTPR/FPRが十分改善する可能性があり、時間構造追加の必要性は未確定。H3: 時間構造は正常周期も高値になり得る。H4: jitterと観測窓が精度/遅延/コストを変える。

## Required implementation

実装済: 現行detector互換ログ・freeze、明示時刻原点の保存PCAP変換、paired分析、>=2/1、Jain/CV/ACF/FFT、独立validationルールによる共通評価、可視化、再現情報、短いテスト。`docs/REPOSITORY_AUDIT.md`にデータフローと仕様差を記録。

本実験前に必要: 原稿81.8%の各runと生成コード/commit/configの対応、source-portと現行flow_idの仕様決定、TCP+UDP入力アダプタの照合。現行Mininet runnerは2種のbenign→attack系列だけで、独立Baseline/benign periodic/全jitter条件の本評価を満たさない。今回そのrunnerを本実験完成版と見なさない。

## Experiment command

まず実験PCで既存保存captureを再解析する。以下はネットワーク送信をしない。実験PCの実装rootで、回収した実ファイル/メタデータを使用。`ORIGIN_EPOCH`は同じPCAP時計に対応する保存start_epoch、`CAPTURE_SECONDS`は保存durationから設定し、推測しない。

```sh
python -m unittest discover -s tests -v
git rev-parse HEAD
python scripts/pcap_to_research_packets.py \
  --pcap "$TRAIN_PCAP" --origin-epoch "$TRAIN_ORIGIN_EPOCH" \
  --duration-sec "$TRAIN_CAPTURE_SECONDS" --dst-port 5001 --output "$REPLAY_DIR/train.csv"
python scripts/pcap_to_research_packets.py \
  --pcap "$LDOS_PCAP" --origin-epoch "$LDOS_ORIGIN_EPOCH" \
  --duration-sec "$LDOS_CAPTURE_SECONDS" --dst-port 5001 --output "$REPLAY_DIR/ldos.csv"
```

正常random/benign periodic/Baselineも各自のoriginとcaptureから同様に変換。`configs/research_replay.example.json`を`$REPLAY_DIR/config_25ms.json`にコピーし、実CSV、duration、seed、attack interval、全条件、時刻根拠を記入する。ファイルが無い条件は生成した実験結果で代用しない。まず実在するケースだけで実行し、未回収ケースを研究ログへ残す。

```sh
python scripts/analyze_research.py --config "$REPLAY_DIR/config_25ms.json" --output-dir "$RUN_DIR/analysis_25ms"
python scripts/analyze_research.py --config "$REPLAY_DIR/config_4s.json" --output-dir "$RUN_DIR/analysis_4s"
python scripts/plot_research.py --windows "$RUN_DIR/analysis_25ms/ldos_seed4_dynamic_windows.csv" --output "$RUN_DIR/analysis_25ms/ldos_diagnostics.png"
```

`config_4s.json`は同じ入力を参照しwindow_sec=4/step_sec=1のみ変更。図のcase名は実configに合わせる。全コマンド・stdout/stderrをrunログに保存する。単一runに比較不能な異なる入力scopeを混ぜない。

動作確認だけならfixtureを使用可能:

```sh
python scripts/make_research_fixture.py --output-dir "$RUN_DIR/fixture" --period-sec 1 --burst-sec 0.2 --peak-rate-mbps 0.05 --payload 80 --flows 2 --jitter 0.1 --window-sec 0.025 --step-sec 0.025
python scripts/analyze_research.py --config "$RUN_DIR/fixture/config.json" --output-dir "$RUN_DIR/fixture_analysis"
```

新規実ネットワーク本実験のコマンドは、元runの対応・flow仕様・不足正常条件の送信ハーネスを確認後に追加する。未完成runnerに存在しないオプションを付けたコマンドを提示しない。今の次アクションは既存capture再解析と不足データの特定。

## Conditions

- 主比較: Baseline（通常TCPの意味とUDPフィルタ空入力を区別）、無選別normal random burst、benign periodic、periodic LDoS。同じ正常trainからdynamic/freeze、Original>=2/Relaxed>=1。
- 主評価候補: 原稿のperiod=1 s、burst=.3 s、peak=15 Mbps、nominal average=4.5 Mbps、attack campaign=10–50 s、capture=60 s。payload/flow数は元caseから回収して確定。81.8%の条件と別runの数値を混ぜない。
- 入力scopeはUDP dst5001（現行互換）とTCP+UDP（将来）を別表にする。source-port・5-tuple・per-flow stateも別profile。
- 分割: train/validation/testでcapture/seedを分離し、重なるwindowを分割して漏洩させない。探索に使用した攻撃条件はheld-out結果と分離。
- 提案sweep（未実施）: period=.5/1/1.5/2 s、burst=.05/.1/.3 s（burst<period）、peakとaverageを整合、payload=80/750/1200 byte、flow=1/2/8、start=10/20 s、jitter=0/.05/.1/.2、temporal window=2/4/8 s、step=.025/.1/1 s。max_period<temporal windowを守る。全直積をMacで回さない。
- benign periodicの正当性は用途・発生源から定義し、Jainが高いから攻撃とラベルしない。randomもTCPへの実測影響を記録する。

## Required outputs

全runのREADME（TZ付き日時、PC、OS/kernel、commit、dirty diff、コマンド、成功/失敗）、実config、依存関係、入力PCAP、capture位置・drop数・start_epoch、UDP pulse schedule/実送信ログ、TCP sender/receiver iperf JSON、ss/retrans/timeoutログ。学習captureとテストcaptureの対応を残す。

新分析のconfig、provenance、training_windows、各case dynamic/freeze windows、buckets、metrics CSV/JSON、図、COMPLETED。古い集計/失敗runを削除しない。生pcapは実験PCで保存し、Macには必要な集計と検証対象のみ回収。

## Metrics

TPR/FPR/precision/recall、混同行列、各event latency/miss、gate停止数、warmup/transition除外数、特徴別raw/effective crossing数。正常・攻撃の窓分母とrun数を併記。攻撃off区間を含むcampaignとburst-only評価は別定義（後者は将来pulse truthで追加）。

CPU秒/peak memory/processing timeは同じ入力・ログ条件・測定範囲を固定して実験PCで計測する。現時点null。時間構造は閾値校正runを明記し、startup/undefined coverageを報告。正常周期FPR、jitterごとのTPR、検知遅延を比較する。

## Expected interpretation

freezeでも低scoreなら、EMA追従単独では説明不十分。ただし周期性不足を直接証明しない。raw_crossedとeffectiveの差はgate、分散0/threshold0は下限仕様、窓幅差は集約の影響を示す候補。

>=1で高TPR/低FPRなら追加時間特徴の必要性は弱い。TPRだけ改善/FPR悪化なら時間構造の分離を検討。Jainで正常周期も拾うなら単独採用しない。JainとCVの同等結果は式上予想されるもので独立再現証拠ではない。ACF/FFTが優る場合はaccuracy-costを同条件で評価する。

## Next action

A: >=1が十分 → score/重み付け・負荷変動耐性を優先。B: >=1のFPR悪化 → 独立validationで時間特徴校正。C: Jainで正常periodic誤検知 → intensity/duty/duration/flowをアブレーション。D: jitterで悪化 → burst抽出閾値・欠落pulse・窓長を切り分け。E: FFT/ACF優位 → costと状態上限を計測して候補を絞る。F: 元CSV再現不一致 → 原稿の結果/仕様対応を修正してから新提案を評価。全場合をRESEARCH_LOGに追記。


## 2026-09-09 追記: 実験PC不在中の前提確認

H0として、原論文・公開C・現行Pythonの仕様差を先に確定する。docs/ORIGINAL_PAPER_AUDIT.mdを参照。公開Cの正の閾値floor、IAT尺度、source-port、100 packet/CPU上限、外部map初期化を未確認のまま、現行Pythonの成績を元検知器の成績と扱わない。>=1/2の同じscoreログによる比較は現行の特徴別更新用であり、論文Algorithm2の総score依存更新では別々の状態推移を評価する必要がある。実ネットワーク実験は引き続き保留し、版・数式・初期化の照合を進める。
