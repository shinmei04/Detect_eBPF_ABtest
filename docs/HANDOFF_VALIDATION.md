# 引渡し検証記録

2026-09-09 JST。対象はPhase 1 / P1-G0用のソース引渡し。

| 検証 | 結果 |
|---|---|
| 既存の単体・回帰テスト | 14件成功 |
| 8秒の人工CSV → 25 ms窓解析 → 期待出力検査 | 成功 |
| Git bundleと未コミットソースのアーカイブから別ディレクトリへ復元 | 全ソースhash一致 |
| 復元先での既存14テストと同じ人工CSV解析 | 成功 |
| 既存復元先への上書き | 拒否を確認 |
| パッケージ内ソースの改変 | hash不一致で復元前に拒否を確認 |
| 研究5文書と引渡し手順のローカル参照 | 配布物内で解決 |

実行環境: macOS、Python 3.12.14、numpy 2.3.5、pandas 2.2.3。
受入確認コマンドは `python scripts/smoke_replay.py --output-dir <新規出力先>`。

証拠: [準備側の結果](handoff_evidence/stage_acceptance.json)、[テストログ](handoff_evidence/stage_01.txt)、[復元側の結果](handoff_evidence/restored_acceptance.json)、[復元側テストログ](handoff_evidence/restored_01.txt)。結果内の絶対パスは検証時の一時ディレクトリの記録。実験PCでは新しいパスへ再実行する。

本格Mininet、Linux実機、実PCAP変換、作図、処理コスト、検知性能改善は未検証。実データ計画はDRAFTのまま。原稿・既存の検知ロジック・実データは変更していない。
