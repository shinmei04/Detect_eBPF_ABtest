# 実験条件と再現方法

## Baselineと対照
「Baseline」は比較対象を必ず指定する。

| 対象 | Baseline | 比較対象 |
|---|---|---|
| 簡易検知器 | 4統計特徴のみ | 同じdatasetへGoertzel 2特徴追加 |
| 再現検知器の学習条件 | original_like: regular benignで学習 | stat_matched: 合成random_microburstで学習 |
| TCP被害 | UDPなしTCP-only | 正常microburst / 周期UDP / 同負荷ランダム対照 |
| 学習後更新 | freeze_after_training | online_after_training |

合成random_microburstは総packet数、非ゼロbucket数、最大値、2値分布を周期列に一致させ、1024候補から周波数・IAT差に基づいて選ぶ（`src/pattern_generator.py`）。自然な正常通信全体の代表とは扱わない。
実測で採用されたtrain_random_avg10はR=15Mbps、burst 5–30ms、interval 140–210msの条件を持つ。細部の時刻分布は`experiments/main_ldos_tcp6m/scripts/run_experiment.py::build_cases`とsender実装を確認する。周期攻撃と同じ平均負荷ではない。

## 時間粒度と攻撃パラメータ
| 条件 | bucket | window / step | 通信条件 |
|---|---:|---:|---|
| 合成paper_reproduction | 25ms | 4s / 1s | 各benign/attack segment 60s、T=1000ms、L=200ms、10packet/bucket、seed 1,2,3,4,5,10,20,30,40,50 |
| 合成frequency_comparison | 25ms | 4s / 1s | 60s、同T/L/packet、通常attack開始20s。cold_startは別stream |
| 主実測TCP6m | 25ms | 4s / 1s | 60s、攻撃10–50s、C=15Mbps、R=15Mbps、L=300ms、T=1000ms、payload80B、1 UDP flow |
| 保存pcap直接25ms | 25ms相当 | 25ms / 25ms | 主実測と保存random_packet対照。60s=2400窓 |
| TCP上限なしtrial | 25ms | 4s / 1s、後続実験では25ms / 25ms | TCP6m条件から送信targetのみNoneへ変更した別実験 |

bucketは時系列の集約間隔、windowは特徴計算の観測長、stepは窓開始時刻の間隔。25ms bucketでも4秒窓なら160 bucketを使う。再現版の既定warmup20は秒ではなく有効窓数。
合成packetの既定payloadは80B/same_flow（regular benignだけ40/120B交互に変更）。合成packet数をMininetのMbpsと直接比較しない。
実測の主条件はReno・SACK off、delay20ms、queue100packet、TCP target6Mbpsをiperf3 pacingで指定。詳細は[実験プロトコル](../experiments/main_ldos_tcp6m/notes/experiment_protocol.md)。
理論平均攻撃負荷はR*L/T（主条件なら4.5Mbps）。offered payload・受信IP bytes・L2 bytes・goodputは異なる測定量なので、実測値は列の定義を確認する。

## 指標と評価分母
- TP/FP/TN/FN、Precision=TP/(TP+FP)、Recall/TPR=TP/(TP+FN)、FPR=FP/(FP+TN)、FNR=FN/(FN+TP)、F1、Accuracy。
- 合成再現CLIはwarmup除外。分母ゼロは既存safe_divideで0、検知遅延未検知はNone。成功したseedだけの平均遅延と未検知seed数を併記する。
- 再現CLIの`detection_window_after_attack`は秒差に基づく既存式でstep一般化に制約がある。step変更時はこの列を無条件に窓番号と解釈しない。
- 25ms評価はall windowsとvalid（10packet以上）を別集計。分母ゼロはNone/CSV空欄。少数packetのattack窓をFNに含むallとvalidを混ぜない。
- ラベルは攻撃期間全体/実バースト区間で別物。`src/phase_labeling.py`の利用時はtarget列とphase log有無を記録する。
- TCP被害: baseline比goodput低下、TCPTimeouts差、backoff、再送・qdisc drop、UDP/TCP/未使用帯域。seed/trialと攻撃期間を揃えて比較する。
- 自己相関・Goertzel等は特徴であり、研究の合格閾値は未決定。低いFPRだけでなく正常性・TCP被害も確認する。

## 環境
WSL Ubuntu/Linux、Bash、Python 3.10以上を想定。今回確認環境はPython3.12.3。

```bash
python3 -m venv .venv  # 未作成の場合のみ
.venv/bin/python -m pip install -r requirements.txt
bash scripts/verify.sh
```

入口は既存.venv/bin/pythonを優先し、なければpython3。`PYTHON_BIN=/absolute/path/to/python`で指定可能。必要な依存がなければ失敗する。
保存pcapにはtcpdumpが必要。新規Mininet実通信はroot、Mininet、iperf3、tc、C senderなどが別途必要。verifyは通信・sudo・パッケージインストールを実行しない。

## 評価入口
リポジトリrootから:

```bash
bash scripts/run_evaluation.sh --profile smoke --dry-run
bash scripts/run_evaluation.sh --profile smoke
bash scripts/run_evaluation.sh --profile paper_reproduction
bash scripts/run_evaluation.sh --profile frequency_comparison
bash scripts/run_evaluation.sh --profile saved_pcap_25ms --dry-run
bash scripts/run_evaluation.sh --profile saved_pcap_25ms
```

既定はsmoke。8秒/segment、seed1、warmup2の配線確認であり、本評価に使わない。
dry-runはプロファイル構造・保存pcapの存在等を確認してコマンドを表示する。実処理や入力hash計算、完全なCLI引数検証はしない。
本評価プロファイルは複数seedの候補探索に時間がかかる。`execution.log`に進捗/エラーを保存する。
出力は`exp/evaluation_harness_20260906/out/YYYYMMDD_HHMMSS/`。同秒または`--run-id`で既存名と衝突した場合は停止する。新しいrun-idで実行し、失敗runも削除・再利用しない。

- manifest.json: 状態、実行argv、時刻/環境、git HEADとdirty状態、コード/入力/出力SHA256、終了コード。
- config.json: 使用プロファイル。
- execution.log: 既存CLIの標準出力・標準エラー。
- payload/: 既存評価のCSV/JSON/図/報告。既存の各出力名を維持する。

```bash
.venv/bin/python exp/evaluation_harness_20260906/analyze.py exp/evaluation_harness_20260906/out/<run-id>
```

この分析入口は成果物の存在と可読性を確認する。検知率の改善を合格条件にしない。
保存pcapの参照先は既存25ms分析のCaseSpecから取得する。欠落があれば停止し、別データや合成値で埋めない。全入力のhashを実行前後で比較する。

## 実通信実験を追加する場合
[調査文書](REPOSITORY_AUDIT.md)の実験表から近いrun.pyを選び、対象実験のREADME・preset・出力先を確認する。既存実験にrun.shがあっても、旧mainの壊れた日付参照をそのまま使わない。
新規条件は新しいexpディレクトリと新規outで実施し、既存sender/runnerを再利用する。既存分析が入力ディレクトリへ結果を書き戻す場合は、新規出力先を与えるadapterを先に用意する。
このハーネスのプロファイルはoffline専用。新規Mininet測定・全trial再集約の自動化は含めていない。

## 短い依頼の例
- 「AGENTSに従い、IATの閾値更新を調査して。実装は変えず根拠を報告」
- 「paper_reproductionを再評価し、前回runとFNRを比較。条件差も示して」
- 「保存pcapを25msで再評価し、all/validの違いを説明して」
- 「自己相関の追加案をDECISIONSに記録。判定規則の採用は保留」
- 「次の実験に1秒lag特徴を追加。既存4特徴の結果を維持し、verifyとsmokeを実行」
