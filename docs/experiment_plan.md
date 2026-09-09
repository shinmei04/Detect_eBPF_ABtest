# Experiment Plan

更新日: 2026-09-09（JST）。実装PCでは準備と小規模な確認を行い、本格実験は実験用PCで実施する。目的は、実験用PCに持ち込めば再現できる状態まで条件・コード・手順・出力仕様を揃えること。

この文書は研究全体の実験台帳。既存の [詳細計画](../EXPERIMENT_PLAN.md) と [分析仕様](./RESEARCH_ANALYSIS.md) は保持して参照する。詳細計画のsweepを現在のGateに関係なく一括実行しない。

## Status and handoff rules

- `DRAFT`: 条件・スクリプト・入力等に未確定項目がある。
- `READY`: 必須項目・実ファイル・コマンドが揃い、短い動作確認済み。成功基準と解析規則を結果を見る前に固定し、持ち込み可能。
- `RUNNING`: 実験PCで実行中。
- `COMPLETED`: 実行終了だけでなく、期待出力・入力対応・解析の検証まで完了。科学的な仮説成立とは別。
- `FAILED / INCOMPLETE`: 失敗または欠損を理由・ログとともに保持。
- `CANCELLED`: Gate判断等で実施しない。理由を研究ログへ残す。

未確定値や未作成スクリプトを埋めたふりをしない。READYになるまで実行可能な完成手順とは扱わない。run IDは [既存workflow](context/workflow.md) の `YYYYMMDD_HHMMSS_条件名` を使い、計画IDと対応付ける。

引渡しには、実装のcommit・dirty diff・必要な未追跡ファイル、環境・依存関係、設定、入力hash、以下5文書のスナップショットを含める。5文書は実装Gitリポジトリ内へ配置済み。通常はGitで同期する。手順は [HANDOFF.md](HANDOFF.md) を参照。出力は実装と別の `runs/<run ID>/` に保存し、既存出力を上書きしない。生データは実験PCに保持し、必要な集計だけMacへ取得する。

## Experiment P1-REPLAY-001

### Experiment ID

`P1-REPLAY-001` — P1-G0用の保存capture再解析。実run ID: 未割当。

### Research question

対象版・入力・開始時刻・実行条件を対応付けたとき、保存されている見逃し結果を再現できるか。再現後に、単純な判定条件で説明できるかをP1-G1で調べる。

### Conditions

P0（現行Python）から開始。P1/P2や異なる入力scopeを同じ方式名で混ぜない。独立正常train、通常TCP、正常random burst、正常periodic、periodic LDoSの保存データの有無を一覧化する。不足条件は未回収と記録し、人工fixtureで補って実測評価にしない。

初回は元の実行条件に合わせる。原稿の25 msは既存ログでユーザー確認済みとして扱い、実configとの対応を回収する。4 s窓等の変更比較は別config・別解析IDにする。

### Network topology

保存captureを生成した元トポロジー、ボトルネック帯域・遅延・queue、capture位置・drop数・時計を回収する。現時点では未確定。再解析自体はネットワーク送信を行わない。

### Traffic configuration

元の送信schedule、実送信ログ、payload・flowの定義、攻撃区間、平均/peak帯域、burst長・周期、jitterを回収する。既存計画には60 s、10–50 s、period 1 s、burst 0.3 s、peak 15 Mbpsの候補記載があるが、対象runと照合するまでは確定設定にしない。正常ラベルを特徴値から決めない。

### TCP variant

元runの実設定から回収。未確定。OS/kernel、輻輳制御アルゴリズム、SACK等の関連設定と、取得したTCPログの定義を保存する。

### Duration

各captureの保存メタデータから開始epochとdurationを指定する。先頭packetの時刻を実験開始と推定しない。再解析の処理時間は別途記録する。

### Seeds

元runに記録されたseedと生成器の版を使用。未回収値を創作しない。train/validation/testのrun・seedを分離し、重複窓を別集合へ分割しない。

### Commands

実験PCの この実装リポジトリ を作業ディレクトリとする。以下は存在するCLIの準備用ひな形であり、変数・config未確定のため現在はDRAFT。各値を証拠に基づいて設定してから実行する。

```sh
# 実際のパスと保存メタデータを設定済みであることを検査する。
: "${TRAIN_PCAP:?Set the actual training PCAP path}"
: "${TRAIN_ORIGIN_EPOCH:?Set the recorded start epoch}"
: "${TRAIN_CAPTURE_SECONDS:?Set the recorded duration}"
: "${REPLAY_DIR:?Set a new replay output directory}"
: "${RUN_DIR:?Set a new run output directory}"

# 独立した新規ディレクトリを使い、出力を上書きしない。
mkdir "$RUN_DIR" "$REPLAY_DIR"
git rev-parse HEAD > "$RUN_DIR/implementation_commit.txt"
git status --short > "$RUN_DIR/working_tree.txt"
python -m unittest discover -s tests -v > "$RUN_DIR/tests.log" 2>&1
```

テストの終了コードとログを確認してから次へ進む。dirty diff・必要な未追跡ソースも配布物に保存する。現在のアダプタはIPv4 UDP用であるため、TCPのみのBaselineが空になることをTCP FPRの測定と扱わない。

```sh
python scripts/pcap_to_research_packets.py \
  --pcap "$TRAIN_PCAP" --origin-epoch "$TRAIN_ORIGIN_EPOCH" \
  --duration-sec "$TRAIN_CAPTURE_SECONDS" --dst-port 5001 \
  --output "$REPLAY_DIR/train.csv" > "$RUN_DIR/convert_train.log" 2>&1
```

変換成功を確認する。各caseも対応する実PCAP・epoch・durationから別CSVへ変換する。`--dst-port 5001` は現行互換の例であり、元runの入力scopeと照合して確定する。

`configs/research_replay.example.json` を基に、`$REPLAY_DIR/config_25ms.json` を作成する。実CSV、seed、duration、attack interval、正常train、flow規則、25 msのwindow/step設定を照合する。テンプレートの例示値を実条件として流用しない。

```sh
python scripts/analyze_research.py \
  --config "$REPLAY_DIR/config_25ms.json" \
  --output-dir "$RUN_DIR/analysis_25ms" > "$RUN_DIR/analyze.log" 2>&1
```

終了コードと出力の `COMPLETED` を確認する。実case名・modeに対応するwindows CSVを選び、`scripts/plot_research.py --windows <実CSV> --output <新規PNG>` で作図する。実際に展開したコマンド全文をrun READMEへ保存する。後続の性能評価・追加特徴の判定は現在のGate通過後に別計画として確定する。

### Required scripts

既存: [PCAP変換](../scripts/pcap_to_research_packets.py)、[再解析](../scripts/analyze_research.py)、[作図](../scripts/plot_research.py)、[fixture](../scripts/make_research_fixture.py)、[設定例](../configs/research_replay.example.json)。

準備対象: 元run対応表と不足メタデータの検証処理。既存config/provenance検証を確認して必要部分だけ追加する。新規ネットワーク生成のrunnerは独立正常条件等への対応確認が必要で、現時点で本評価完成版とは扱わない。

### Expected output files

- run README: 計画ID、run ID、TZ付き日時、実験PC識別、OS/kernel、依存関係、実行版・差分、実コマンド、終了コード、入力/設定hash、成否。
- `train.csv` と各case CSV、実際に使用したconfig、変換ログ。
- 解析先の `config.json`、`provenance.json`、`source.diff`、`training_windows.csv`、各caseの `*_windows.csv` / `*_buckets.csv`、`metrics.csv` / `metrics.json`、`COMPLETED`、診断図。
- 元run→PCAP→CSV→解析→保存結果の対応表、再現一致／不一致／欠損の検証記録。
- 元PCAP、送信ログ、TCP影響ログは実験PC側の原本へ参照を残す。欠損ファイルを生成済みとは記さない。

### Metrics

現Gate: 元集計との一致・差分、ラベル／時間／版／入力scopeの対応、欠損件数。許容差は元の集計定義と数値精度を確認して再解析前に固定する。

後続評価: Recall、FPR、Precision / F1、TP/FP/TN/FNと分母、event latency・未検知数、特徴未定義率、gate抑制、raw/effective crossing。F1の出力有無を確認し、不足なら保存混同行列から定義とゼロ分母処理を明記して算出する。Feature calculation cost・CPU・memoryは別の測定範囲を固定して実験PCで計測する。現在は未測定。

確認評価前に固定する値: 許容FPR、必要Recall改善幅、latency上限、計算・CPU・memory予算、試行数、不確実性の評価方法。現在はすべて未設定。これらがない状態で性能のGO判定はしない。

### Analysis script

既存 `scripts/analyze_research.py` と `scripts/plot_research.py` を使用する。定義は [分析仕様](./RESEARCH_ANALYSIS.md) に従う。全体Precision/F1をクラス比の異なるcaseの単純平均で作らない。元の保存結果との対応・差分検証は既存処理の対応範囲を確認して不足分のみ作成する。

### Completion status

**DRAFT — 未実行。** 元run、実PCAP、時計・条件、seed、入力scope、許容差が未確定。引渡しの動作確認は [HANDOFF_VALIDATION.md](HANDOFF_VALIDATION.md) に記録する。人工データの成功では実PCAPを使うこの計画をREADYにしない。

- [ ] 元runと実データ・メタデータを回収
- [ ] 対象版・入力定義・条件・seedと分割を固定
- [ ] 検証基準を事前設定し、実configとコマンドを確定
- [ ] 短いfixtureで入力・出力と必要な検証処理を確認
- [ ] コード・差分・5文書・依存関係を引渡し可能に保存
- [ ] 実験PCで再解析し、終了コードと出力を検証
- [ ] 研究ログへ観測・限界・Gate判断を追記

## Experiment template

新規計画ごとに以下を複製する。未確定は理由付きで明示する。

```markdown
## Experiment <ID>

### Experiment ID
計画ID、run ID、対象Phase/Gate。

### Research question
仮説・競合仮説、判断を分ける予測。

### Conditions
攻撃と厳しい正常対照、対象版、校正/評価分割、事前の成功・中止基準。

### Network topology
ノード、リンク、帯域、遅延、queue、観測位置、時刻同期、capture欠落。

### Traffic configuration
生成器・版、送信schedule、rate、payload、flow数、burst、period、jitter、ラベル根拠。

### TCP variant
アルゴリズム、OS/kernel、関連設定、ground truthの取得方法。

### Duration
warmup、観測時間、攻撃区間、反復数、停止条件。

### Seeds
明示値、生成器との対応、train/validation/testのrun分割。

### Commands
実験PCの作業ディレクトリ、環境準備、実行・解析・検証コマンド、終了コード保存。

### Required scripts
実在パス、コード版・差分、依存関係、未作成部分。

### Expected output files
ファイル名、形式・単位、保存先、必要メタデータ、完了検証方法。

### Metrics
定義・分母・除外・欠測・未検知の扱い、計測範囲、事前固定する判定基準。

### Analysis script
パス、版、コマンド、入力hash、図表への対応。

### Completion status
DRAFT / READY / RUNNING / COMPLETED / FAILED / INCOMPLETE / CANCELLED
不足事項、検証結果、研究ログentry、次の作業。
```
