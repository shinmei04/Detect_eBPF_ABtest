# Codex research map

## 最初に読む
- 目的・仮説・未解決事項: [docs/PROJECT.md](docs/PROJECT.md)
- 検知器・特徴量・拡張位置: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- 条件・評価分母・再現手順: [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)
- 設計判断と未決事項: [docs/DECISIONS.md](docs/DECISIONS.md)
- 調査範囲・既知の不整合: [docs/REPOSITORY_AUDIT.md](docs/REPOSITORY_AUDIT.md)
- 設定の入口と集約案: [configs/README.md](configs/README.md)

## コードへの入口
- 合成データ: `src/pattern_generator.py`, `src/packet_model.py`
- 簡易検知器: `src/features.py`, `src/goertzel.py`, `src/paper_like_detector.py`
- 論文ロジック再現: `src/paper_reproduction_detector.py`
- pcap抽出: `mininet_experiment/pcap_to_features.py`
- ラベル: `src/phase_labeling.py`; 指標: `src/detector_evaluation.py`
- 保存pcapの直接25ms評価: `exp/detector_25ms_20260714/analyze.py`
- 採用条件の通信生成: `experiments/main_ldos_tcp6m/scripts/run_experiment.py`
- 実験一覧: `exp/README.md`; 最近の実験は調査文書も参照する。

## 作業手順
1. `git status --short`を確認し、利用者の未コミット変更を維持する。
2. 関連文書・実装・既存テストを読む。仮説と測定結果を区別する。
3. 小さく実装し、実装と同じ変更で関連文書・設定・判断記録を更新する。
4. `bash scripts/verify.sh`を実行する。評価は`bash scripts/run_evaluation.sh`。
5. 変更理由、検証結果、出力先、未実行・未解決事項を報告する。

## 必須ルール
- `data/raw/`、元pcap、既存結果を変更・上書き・削除しない。
- 保存済み結果・PDF・pcap・CSV・JSON・`src/`の再利用コードは原則改名しない。
- 結果を推測・捏造しない。合成データ・実測・仮想図を混同しない。
- 未確定の研究判断を勝手に採用しない。DECISIONSへ未決事項として記録する。
- 同名特徴量でも簡易版と再現版では定義が違う。閾値・ラベル・分母も明示する。
- 既存コードの動作変更は理由を明示し、無関係なロジック変更を加えない。
- 既存コード・CLIを再利用する。旧結果への互換コピーを作らない。
- 新規実験は`exp/<topic>_<YYYYMMDD>/`。topicはsnake_case・3語以内。
- 日付は実験ディレクトリ名にのみ付ける（結果の時刻ディレクトリを除く）。
- 実行は`run.py`、分析は`analyze.py`、実験入口は`run.sh`。
- 結果は各実験の`out/YYYYMMDD_HHMMSS/`に新規作成する。衝突時は停止する。
- `final`, `new`, `latest`, `old`, `fix`, `v2`など曖昧な新規名称は禁止。
- 条件差はCLI引数またはcase名で管理する。
- 既存ファイルを移動する場合は`git mv`を使い、Python・Shell・README・tests・`.gitignore`の参照を更新する。
- 完了前に`python3 -m compileall exp src`とShell構文検証を行う（verifyに含む）。
- 実通信は閉じたMininet環境内で実施する。送信条件・TCP設定・復元処理を確認する。
- 検証成功を研究仮説の成立と扱わない。入力不足・テスト失敗を黙ってスキップしない。
