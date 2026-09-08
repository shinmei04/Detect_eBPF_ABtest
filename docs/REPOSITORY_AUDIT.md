# リポジトリ現状調査

調査日: 2026-09-06。変更前に全ファイル配置・拡張子、Python/Shell入口、import/CLI、主要文書、検知/生成/分析コードとテストを調査した。保存結果の全行再分析や全pcapの内容検査はしていない。

## 構成と根拠
| 場所 | 現状と参照用途 |
|---|---|
| README.md, main.py | Phase 1合成実験の説明・入口。READMEの絶対パスは旧環境 |
| src/ | 共有の生成、特徴、2系統の検知器、指標、phaseラベル、被害/トレードオフ分析 |
| mininet_experiment/ | Mininet topology・送信・pcap抽出、A/B/複合攻撃/sweep |
| exp/bandwidth_utilization_20260610/ | 帯域、pcap再計算、TCP/RTO校正と4テストファイル |
| exp/rto_cycle_20260617/ | RTO周期実験・解析・単体テスト |
| exp/detector_25ms_20260714/ | 保存pcapの独立25ms評価。入力パスはanalyze.pyに固定 |
| exp/dpsws_tcp_unlimited_20260724/ | TCP上限を解除したtrial |
| exp/dpsws_tcp_25ms_20260726/ | trial追加と25msの統合評価 |
| exp/dpsws_microburst_20260726/, exp/microburst_interval_20260726/ | 正常microburstと間隔変更の実験 |
| exp/dpsws_figures_20260726/, exp/dpsws_sequence_20260727/ | 保存trialから図作成 |
| experiments/main_ldos_tcp6m/ | 採用済みpcap、summary、検知窓、実験プロトコル、通信runner |
| experiments/dpsws_additional_eval_20260709/, experiments/dpsws_random_and_sack_check_20260709/ | 負荷・ランダム性・SACK対照、自己相関事後分析、既存YAML |
| experiments/dpsws_phase4_final_summary_20260709/ | 既存の研究まとめ。名称は保存のため維持 |
| experiments/archive_unused/, exports/, docs/images/, tmp/pdfs/ | アーカイブ、共有成果物、図など。今回移動しない |
| tests/ | phaseラベル・stat-matched送信予算のunittest |
| scripts/ | 合成CLI、環境セットアップ、旧整理スクリプト |

変更前の非.git/.venv/__pycache__ファイルにPython 95、Shell 17、pcap 699、CSV 2792、JSON 2193、PDF 218を確認。data/rawは現状見当たらないが、将来も保護対象とする。

## 既知の不整合・制約
- 調査開始時点でbandwidth実験のgit rename、文書・.gitignore変更、多数の未追跡実験が存在。利用者の変更として維持した。
- `experiments/main_ldos_tcp6m/scripts/run.sh`は存在しない`run_all_20260707.sh`を参照。
- 同`run_all.sh`/`Makefile`は旧日付付きPython/C名を参照。Makefileは現存C名と不一致。今回修正・ビルドしない。
- exp/README.mdは最近の全実験を網羅しない。この表を補助地図とする。
- 設定はCLI/dataclass、run.pyのpreset・monkey patch、analyze.py定数、2個のYAMLへ分散。全体の共通config loaderはない。
- 保存pcap評価にはarchive側のcase.jsonも必要。archiveという名前だけで削除しない。
- 既存READMEの合成実験と採用実験では正常データ・窓・TCP負荷が異なる。単一のBaseline設定へ統合しない。
- requirements.txtは4ライブラリの未固定依存。CI/lintの専用設定は確認できず、shellcheck/ruffは調査環境にない。
- 外部参照XDPのcommit固定がない。ローカル実装から読める仕様と原実装の同一性を区別する。

## 今回の整理範囲
AGENTSとdocsで参照経路を作成し、configsと評価/検証入口を追加する。既存ファイルの移動、元データの更新、検知器の仕様変更、旧入口の包括的修復は行わない。
verifyは構文と既存unit testおよびハーネスの検証であり、旧Mininet入口を含む全実験の実通信成功は保証しない。

## ハーネスの動作確認
- `bash scripts/verify.sh`: 既存39件 + ハーネス境界5件、計44テスト成功。Shell20ファイル構文検証、Pythonコンパイル成功。
- smoke: `exp/evaluation_harness_20260906/out/20260906_135818/manifest.json`、status=succeeded、成果物11件。
- 保存pcap25ms: `exp/evaluation_harness_20260906/out/20260906_135840/manifest.json`、status=succeeded、成果物6件。pcap/case.json/参考summary計9入力の実行前後SHA256一致。
- いずれも既存検知CLIを呼び出した。研究上の性能改善を検証成功の基準にはしていない。
- 全seedのpaper_reproduction/frequency_comparisonはdry-runのみ。新規Mininet通信、全pcapの再解析、旧入口修復は未実施。
- 元の未コミット変更は維持。git statusでsrcへの追加変更がないことを確認。開始時の全体size/mtime一覧は一時領域消失のため最終比較できず、全699pcapの前後同一性を一括検証したとは主張しない。
- 最終verifyログはsmoke run内の`verify.log`に保存する。outはgitignore対象なので、共有時は必要なmanifest/logを別途添付する。
