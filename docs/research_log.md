# Research Log

重要な実験・分析結果と判断を古い順に追記する。既存entryを結果に合わせて書き換えず、訂正entryから元entryを参照する。仮説、実施内容、結果、支持される解釈、未証明事項を分離する。

既存の [implementation/RESEARCH_LOG.md](../RESEARCH_LOG.md) は詳細履歴として保持する。以下へ移したかのように扱わず、必要なentryを参照する。今後の研究全体の判断はこのファイルに追記し、同一結果の全文を複数箇所で管理しない。未実施の実験は [実験計画](experiment_plan.md) に置く。

## 2026-09-09: 研究ハーネス初期化と既存資料の確認

### Question

既存成果物を保持しつつ、何を事実・仮説・現在の実装範囲として管理すべきか。

### Hypothesis

既存の時間特徴・分析基盤を再利用し、対象版とrunの対応を確認することが、時間構造の検知価値を調べる最短の次段階になる。これは研究実行上の判断仮説であり、LDoS検知性能の結論ではない。

### What was tested

実施種別: ディレクトリ確認・資料読取り・ソース静的確認。ネットワーク実験、過去データの再解析、単体テスト再実行、性能測定は行っていない。

- 旧 `Detect_ineBPF/README.md` の移転案内とユーザー指定に従い、追加先を `ebpf-research/` に確定。
- [workspace README](HANDOFF.md#layout)、[workflow](context/workflow.md)、[ロードマップ](context/ldos-research-roadmap-2026-09-09.md)、[既存計画](../EXPERIMENT_PLAN.md)、[分析仕様](./RESEARCH_ANALYSIS.md)、[元論文監査](./ORIGINAL_PAPER_AUDIT.md)、[既存ログ](../RESEARCH_LOG.md) を確認。
- [時間特徴のソース](../src/temporal_features.py) と分析CLI、実装リポジトリの変更状態を確認。

### Result

- 親ワークスペースにはルート `AGENTS.md` とルート `docs/` がなく、既存の詳細文書は主に この実装リポジトリ と `notes/` にある。
- 時間特徴の関数と共通interfaceがソースに存在する。現行基盤では時間特徴を記述値として扱い、判定ルールは独立校正を必要とするとの仕様記録がある。
- 実装リポジトリに既存の未コミット変更・未追跡ファイルがある。
- 既存ログは14件の短いテスト成功を報告している一方、実データでの改善・処理負荷は未検証と記載している。これは過去記録の確認であり今回のテスト結果ではない。
- 元論文・公開C・現行Pythonの相違と、原稿評価の25 ms実行に関するユーザー補足が既存監査に記録されている。

### Interpretation

時間特徴をゼロから再実装する必要性は認められない。まず比較対象の版と実験条件を固定し、既存基盤を使って実装差・単純条件の寄与を切り分ける。過去のロードマップの予定日だけではPhaseを進めない。

### What this does NOT prove

既存基盤の現在の動作保証、元論文の完全再現、元手法の見逃し原因、81.8%という過去報告値の再現、時間特徴による改善、軽量性、Phase 2の価値、新規性のいずれも今回の確認では証明していない。

### Decision

Phase 1を主軸にP1-G0から始める。長期原則・研究方向・現在のPhase・研究ログ・実験計画を5文書に分ける。既存コード・原稿・設定・詳細文書は保持し、Phase 2と完成版実装を保留する。

### Next action

[P1-G0](current_phase.md#next-decision-gate) に従い、元runと入力・時刻・版・設定・解析の対応表を作成する。既存の検証処理を再利用し、不足するメタデータ検証だけを追加する。実験PC用の [P1-REPLAY-001](experiment_plan.md#experiment-p1-replay-001) を具体化する。

## 2026-09-09: 実験PCへ引き渡せる配置とソース配布

### Question

研究5文書と未コミット実装を、実験PCで同じ状態へ復元できるか。

### Hypothesis

5文書を実装Gitリポジトリ内に置き、Git履歴と現行ソースの両方を保存すれば、未コミット作業や回帰テストの参照版を失わずに引き渡せる。

### What was tested

5文書の正本をこのリポジトリへ移し、親には案内を残した。Git bundle＋ソースsnapshotを別ディレクトリへ復元し、ファイルhash、既存14テスト、短い人工CSV解析を確認した。既存復元先と改変ファイルの拒否も確認した。証拠は [引渡し検証](HANDOFF_VALIDATION.md)。

### Result

準備側・復元側とも14テストと人工解析が成功。全ソースhashの一致、既存復元先・改変ファイルの拒否を確認した。PCAP・Linux環境・本実験は今回使っていない。

### Interpretation

オフライン基盤と研究方針は、未コミット状態でもアーカイブで引渡し可能。実験PCではまず同じ受入確認と元run対応の回収を行える。

### What this does NOT prove

Linuxでの動作、実PCAPの正当性、元集計の再現、検知改善、TCP性能改善、CPU/memoryコスト、Phase 2の価値は未証明。

### Decision

引渡し用ソースは準備完了。研究GateはP1-G0を維持し、実データ計画P1-REPLAY-001はDRAFTのまま。自動commit・pushや実験PCでの実行はしていない。

### Next action

[HANDOFF.md](HANDOFF.md) に従って実験PCへ復元し、受入確認後に元PCAP・時刻・設定・seed・版・元集計の対応を回収する。

## 2026-09-09: 引渡し方法をGit同期へ変更

### Question

実験PCへの引渡しとしてユーザーが求めた方法は何か。

### Hypothesis

実装と研究5文書を同一のGit履歴へ含めれば、実験PCのpullで同期できる。

### What was tested

ユーザーから「渡せるようにする」はpushの意味との訂正を受けた。既存remoteが `shinmei04/eBPFdetecter_exp`、作業ブランチがmainであること、fetch時点でローカルHEADとorigin/mainが一致することを確認した。

### Result

研究5文書は実装リポジトリ内へ配置済み。引渡し手順の主経路をclone/pullへ変更した。ソースの14テストと人工解析の検証結果は直前entryを参照。

### Interpretation

通常の引渡しにアーカイブ復元は必要ない。研究ハーネスと分析基盤をまとめてGitで管理する。

### What this does NOT prove

Git同期は実験成功を意味しない。実PCAPの再解析とLinux実機での受入確認は未実施。

### Decision

既存mainへ研究ハーネス・分析基盤をcommit/pushする。P1-G0と実データ計画DRAFTは維持する。アーカイブは補助手段として扱う。

### Next action

実験PCでGitから取得し、[HANDOFF.md](HANDOFF.md) の受入確認と元run対応の回収を行う。pushの成否はGitのremote確認で報告する。

## Entry template（未記入・結果ではない）

以下を複製し、日付順の実entryとしてこのテンプレートの前に追加する。既知の事実は出典、観測は入力と成果物を必ず辿れるようにする。

```markdown
## YYYY-MM-DD: タイトル

Entry ID: 一意なID
Experiment ID / Analysis ID: 対応する計画とrun ID
Evidence: 入力・出力パス、hash、コード版・差分、環境、コマンド

### Question
何を判断するか。

### Hypothesis
検証する仮説と競合仮説。観測前の予測。

### What was tested
実際に行った実装・実験・分析、対照、条件、seed、除外規則。
実施種別（静的確認／人工fixture／実データ解析／実ネットワーク等）。

### Result
観測値、単位、分母、試行数、不確実性、欠測・失敗と成果物。
未実施・未測定は明示し、0で埋めない。

### Interpretation
観測がどの仮説をどの範囲で支持／反証するか。交絡と限界。

### What this does NOT prove
一般化できない条件、未検証の原因・性能・新規性。

### Decision
GO / REVISE / NO-GO / 未判定、対象Gate、根拠、更新した文書。

### Next action
次の最小実験または実装、必要データ、判定すべきGate。
```
