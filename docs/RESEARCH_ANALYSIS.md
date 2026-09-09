# オフライン分析基盤

対象: 現行Python `PaperReproductionDetector` の窓全体集計プロファイル。元XDP、per-CPU、固定小数点、source-port版、5-tuple別検知の完全再現ではない。既存CLIの既定判定は保持。

## 短い動作確認

リポジトリroot、Python 3.10+、既存requirementsを利用。

```sh
python -m unittest discover -s tests -v
python scripts/make_research_fixture.py --output-dir /tmp/ldos_fixture_01
python scripts/analyze_research.py --config /tmp/ldos_fixture_01/config.json --output-dir /tmp/ldos_analysis_01
python scripts/plot_research.py --windows /tmp/ldos_analysis_01/periodic_ldos_dynamic_windows.csv --output /tmp/ldos_analysis_01/diagnostics.png
```

fixtureは8秒の人工CSVであり、ネットワークモデル・TCP・実パケット送信を含まない。人工benchでの検知率を論文の性能値にしない。既存出力を上書きしない。途中失敗では出力が残るが `COMPLETED` は作られないので別の出力先で再実行する。

## 入力契約

`timestamp_sec,packet_size,flow_id`のCSV。時刻はPCAPと同じ時計で記録した実験開始epochとの差分。先頭パケットを時刻0と推定しない。packet_sizeはUDP payload byte（TCP+UDP集計の場合もpayload定義を揃える）。flow_idは選んだ識別規則を明記し全ファイルで統一する。現在のPCAPアダプタはIPv4 UDPのみ。

空CSVはヘッダを保持。空窓も全件残す。NaN、無効サイズ、時刻範囲外を拒否。bucket/window/step/durationは整数個のbucketに整列させ、勝手に丸めない。元特徴抽出器を再利用し、flowの数え方などを黙って変更しない。

`configs/research_replay.example.json`を回収CSVと同じディレクトリへコピーして編集。相対パスはconfig基準。`training.label=benign`を明示し、独立の正常学習captureを指定。十分なpacket-qualified学習窓が無ければ停止する。各ケースは`baseline/random_microburst/benign_periodic/periodic_ldos`、seed、duration、attack_intervalsを明示。正常は`[]`。攻撃ラベルは攻撃campaign全体（off区間を含む）であり、パケットがある窓だけを攻撃にしない。

比較は1ケースごとに同じtrainから新しいdetectorを生成しdynamic/freezeに複製する。dynamicは「全特徴を常時更新」ではなく現行の特徴別conditional更新。freezeは学習後のmu/sigma更新なし。score>=1/2による実際のdropは行わず、同じ受信列への反実仮想の分類比較に限る。

## 出力

- `training_windows.csv`: 正常学習の生値・閾値・flag・更新履歴。
- `<case>_<mode>_windows.csv`: 4生値、更新前mu/sigma/threshold、raw_crossed、effective is_suspicious、direction、signed margin、updated/update_reason、score、original/relaxed、label、attack overlap、event、gate、decision time、時間構造特徴。
- `<case>_buckets.csv`: 0を含む25 ms counts。
- `metrics.csv/json`: ケース/seed/mode/method別混同行列、TPR、FPR、precision、recall、イベント別latency/miss。分母0はnull（CSVでは空欄）。caseを混ぜたprecision平均は自動生成しない。
- `config.json/provenance.json/source.diff/COMPLETED`: 実条件、入力SHA256、全src/scriptsソースSHA256、Git HEAD/dirty状態、runtime、完了確認。未追跡ファイルの内容はsource.diffに入らないため、配布コード自体も保存する。

生の閾値超過と有効flagを分けることで「特徴量が閾値に届かない」と「packet gateで判定が抑制される」を識別できる。`sigma`はEMA絶対偏差であり標準偏差と呼ばない。

## 指標と時間

窓は[start,end)、decision=end。attack intervalに完全包含されればattack、交差しなければbenign、一部交差ならtransition。window-level指標からtransitionとwarmupを除外するが、packet gateによる無検知は除外しない。通常のwarmupは独立trainで完了している。

latencyは攻撃開始から、その攻撃と重なる窓の初回decisionまで。transitionでもdecisionが攻撃終了以前ならイベント検知に含める。攻撃終了後に完成した窓はイベント検知としない。未検知はnull、平均は検知イベントだけなのでmissed_eventsと併記。窓TPRとイベント検知率は異なる。観測が重なる窓は独立標本ではないため、信頼区間は将来run/seed単位で計算する。

## 時間構造の共通interface

`src/temporal_features.py:METHODS`の各関数に`counts, intervals, bucket_sec, TemporalConfig`を渡す。窓の末尾は4特徴のdecision時刻、観測長は`temporal.window_sec`。未来データなし。全窓が揃う前はtemporal_ready=false。burst threshold以上への立上りから間隔を取り、窓左端の継続burst・capture開始時の不明な立上りは数えない。最小間隔数未満のJain/CVは未定義。

- Jain: `(sum d)^2/(m sum d²)`。
- CV: 母標準偏差/平均。同じ間隔列では`J=1/(1+CV²)`なので情報量の追加はない。
- ACF: 平均を引いたcount列、lag0 energyで正規化したbiased自己相関の指定周期範囲内最大値。一定列は未定義。
- FFT: 平均除去、矩形窓、rFFT。周期範囲内最大power/全non-DC片側power（binの倍重みなし）。周波数分解能は1/window。固定1 Hz照合ではない。
- intensity、duty cycle、完結burstの平均duration、active flow数も同時記録。継続burstのdurationは右打切りで除外。burst閾値依存を必ずsweepする。

既定では時間構造は記述値のみ。攻撃判定を比較する場合、独立validationで決めたルールをconfigへ指定する（test結果で最適化しない）。例えば形式は`"temporal_rules": {"jain": {"threshold": 0.95, "direction": "upper", "calibration_reference": "validation-run-id"}}`。0.95は構文例であり推奨閾値でも検証済み値でもない。CVはlower、ACF/FFTはupperを使える。共通指標で起動待ち/未定義を無検知として含め、coverageも出力。時間構造単独判定には元detectorの10-packet gateを掛けないが、正常train完了は共通。dynamic/freezeで時間構造単独の値は同一で、2つの結果を独立試行として数えない。

## 変更可能な条件

fixture CLIはperiod/burst duration/peakまたはaverage/payload/start/flow数/jitter/window/stepに対応。rateは全flow合計payload rate、average=peak*burst/period（理想値）で、実現平均は別記録。jitterは周期に対する一様相対揺らぎ。randomは指数的idle時間、seed固定。正常periodicとLDoSが同形になるfixtureは「周期性だけでは意味ラベルを識別できない」ことのテストに使う。

本実験の条件はcase.conditionsに保存し、実際の送信schedule/pcap/メタデータと照合する。このCLIで実験用ネットワークの送信条件を変更することはない。CPU/memory/processing time欄は未測定null。Pythonのオフライン処理速度からXDP可能性を断定しない。
