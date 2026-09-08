# 評価プロファイルと設定集約案

## 今回動く範囲
`bash scripts/run_evaluation.sh --profile <name>`は同名JSONを読み、既存CLIへargsをそのまま渡す。優先順位はJSONの明示引数 > 既存CLI既定値。既存コードがconfigsを直接読むようには変更していない。

| profile | 用途 | 条件の出典 |
|---|---|---|
| smoke | 8秒/segment・seed 1・warmup 2の配線確認 | paper CLIを短縮。研究用の採用条件ではない |
| paper_reproduction | original_like / stat_matched、4特徴量 | `scripts/run_paper_reproduction_experiment.py::parse_args`既定値 |
| frequency_comparison | 簡易版4特徴 / 周波数追加、3モード | `scripts/run_detector_experiment.py::parse_args`既定値 |
| saved_pcap_25ms | 正常学習後、保存pcapをonline/frozenで再評価 | `exp/detector_25ms_20260714/analyze.py`の定数/CaseSpec |

JSON schema_version=1のフィールド:
- `kind`: synthetic_smoke / synthetic_evaluation / saved_pcap_evaluation。
- `entry`: ハーネスの許可済み既存Python入口。任意のネットワーク実験入口は受け付けない。
- `args`: CLI tokenの文字列配列。Shell文字列ではなく配列として渡す。
- `expected_outputs`: payload内の必要成果物。空/欠損や読めないCSV/JSONを検出する。
- `schema_version`: 1。

output-dirとrun-idはハーネスが管理し、argsからの指定を拒否する。
保存pcapの入力一覧はCaseSpecを読み込んで事前確認し、case.jsonと参考4秒summary（存在する場合）もhash記録する。
保存pcap条件の一元管理は未実施。JSONは入口だけを管理し、実条件は既存analyze.pyを正とする。

## 現在分散している設定
- 合成: CLI / SimulationConfig、packet_modelのpayload/flow、pattern_generatorの候補数1024・内部4秒窓/1秒step。
- 検知器: DetectorConfig / PaperDetectorConfig / XDP_FEATURE_CONFIGS。
- Mininet: run_experiment.py::build_cases、各実験run.pyの上書き。
- 追加対照: `experiments/dpsws_additional_eval_20260709/cases_fixed.yaml`と`experiments/dpsws_random_and_sack_check_20260709/cases.yaml`。旧実験ごとの読込み経路を維持する。
- pcap: 25ms analyze.pyの定数とCaseSpec、保存結果内のcase.json。

## 段階的な集約提案（未実装）
将来はconfigs内にsimulation / detector / topology / traffic / datasets / evaluationの区分を置き、実験ごとに参照するプロファイルで組み合わせる。
trafficにはR/L/T/payload/flow/seed、datasetsにはpcapとcase.json・原点・capture位置・hash、evaluationにはbucket/window/step・学習trace・ラベル・分母・modeを持たせる。
まず既存CLIを維持したadapterを追加し、同一入力で移行前後の出力を比較する。内部定数の外部化は別変更として理由と差分を記録する。
1つの万能Baselineへ値を統一しない。6Mbps/上限なしや4秒/25msは別プロファイルにする。

requirements.txtは未固定のまま維持した。各runのmanifestにPython/ライブラリversionを保存するが、完全な環境lockやコードsnapshotではない。再現を共有する前にコードをcommitし、必要なら別途lock導入を判断する。
