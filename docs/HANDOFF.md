# 実験PCへの引渡し

引渡し対象は **Phase 1 / P1-G0のオフライン再解析基盤**。時間特徴・分析コード・研究ハーネスを含む。実PCAPを使う計画は必要データの回収待ちでDRAFT。本格Mininet実験とPhase 2はまだ開始しない。

## Layout

復元先そのものが実装Gitリポジトリになる。Macでは `ebpf-research/implementation/` が該当する。研究ハーネスの正本は次の5ファイル。

1. [AGENTS.md](../AGENTS.md)
2. [research_direction.md](research_direction.md)
3. [current_phase.md](current_phase.md)
4. [research_log.md](research_log.md)
5. [experiment_plan.md](experiment_plan.md)

この順で読み、既存の詳細監査・実験計画へ進む。Macの親ワークスペースの同名文書は移転案内。背景資料は `docs/context/` にスナップショットとして同梱し、現在の指示として優先しない。原稿・生データ・旧アーカイブは配布に含めない。

## Gitで受け取る（通常の引渡し方法）

GitHubの `shinmei04/eBPFdetecter_exp` の `main` で、研究5文書・分析コード・設定・テストを一緒に管理する。

新しく取得する場合:

```sh
git clone https://github.com/shinmei04/eBPFdetecter_exp.git
cd eBPFdetecter_exp
```

既存cloneでは作業中の変更を保持し、作業ツリーとブランチを確認してから更新する。

```sh
git status --short
git branch --show-current
git pull --ff-only origin main
```

実験用Linux PCではローカルの役割を設定する。Macでは実行しない。

```sh
python3 -c 'import json, platform; from pathlib import Path; assert platform.system() == "Linux", "Experiment PC must be Linux"; Path("machine_role.local.json").write_text(json.dumps({"role": "experiment"}) + "\n")'
```

続いて下記「環境と短い受入確認」を行う。通常のGit引渡しではアーカイブの復元操作は不要。アーカイブ関連の記述は、ネットワークを使わない引渡しが必要な場合の補助手段。

## 配布物（補助手段）

`research-handoff-20260909.tar.gz` はGitのHEAD履歴を含む `repository.bundle` と、未コミット・未追跡ソースを含む `source/`、元の変更状態、ファイルhash、復元スクリプトを含む。元のGit設定・認証情報・ローカル機械設定は含めない。未コミット変更を失わないよう、Git履歴だけでなく現在のソースを重ねて復元する。

復元先ではローカルブランチ `handoff-work` を作成し、変更は未コミットのままになる。自動commit・pushはしない。通常のGit同期へ切り替える場合は差分を確認し、研究5文書・コード・テスト・設定を明示してcommit対象に含める。

## 実験PCでの復元

必要: Linux、Git、Python 3.12。ネットワーク実験用のsudoやMininetはこのオフライン受入確認には不要。以下を、アーカイブを転送した新しい空の作業ディレクトリで実行する。

```sh
sha256sum -c research-handoff-20260909.tar.gz.sha256
tar -xzf research-handoff-20260909.tar.gz
python3 research-handoff/restore.py restore \
  --destination "$PWD/implementation" --machine-role experiment
cd implementation
```

既存の `implementation/` には復元できない。別の新規パスを指定する。復元は全ファイルのhashを検査してから実行し、終了時に再確認する。Macで復元だけ確認する場合は `--machine-role implementation` を使う。experimentはLinux上でのみ指定できる。

復元先の `machine_role.local.json` はGit管理外。Macからコピーしない。実験PC指定は本格実験の準備完了を意味せず、各計画のREADY判定が別途必要。

## 環境と短い受入確認

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-replay.txt
.venv/bin/python scripts/smoke_replay.py --output-dir ../runs/acceptance_001
.venv/bin/python -m pip freeze > ../runs/acceptance_001/environment.txt
```

`requirements-replay.txt` は今回確認したnumpy/pandasの版を固定している。インストールにはパッケージ取得先への接続が必要で、Linux用wheelは同梱していない。

受入確認は、既存14テスト→8秒の人工CSV生成→25 ms窓での解析→期待出力検査を実行する。PCAP取得、ネットワーク送信、Mininet、長時間測定は行わない。出力先が存在する場合は別名にする。失敗ログを消して再実行しない。

成功時は `../runs/acceptance_001/SMOKE_PASSED` と `acceptance.json` が作られる。各段階のコマンド・終了コード・ログ・環境版も保存される。これは人工データでの動作確認であり、検知性能の実測結果ではない。

作図や旧実装全体には既存 `requirements.txt` の依存関係が別途必要。現行PCAP変換には `tcpdump` が必要。これらのLinux動作、実captureの変換、CPU/memoryコストは今回の受入確認対象外。追加依存関係を導入した場合は、その版をrunの `environment.txt` へ記録する。

## 実験PCのCodexに渡す最初の指示

```text
この実装リポジトリのAGENTS.mdと、そこに指定された順序で研究文書を読んでください。
現在はPhase 1 / P1-G0です。まずdocs/HANDOFF.mdのオフライン受入確認結果を確認し、
保存PCAP・開始epoch・実行設定・seed・コード版・元集計の対応を回収してください。
docs/experiment_plan.mdのP1-REPLAY-001を実データで具体化し、必要情報が揃えば
保存captureを再解析して見逃し結果の再現性を確認してください。
情報が欠ける場合は推測で補わず、不足一覧と次の最小作業を記録してください。
結果・未証明事項・Gate判断を研究ログに残し、current_phase.mdを更新してください。
本格Mininet実験やPhase 2へは、対応する計画とDecision Gateを満たすまで進まないでください。
```

## 再配布と履歴管理

実装リポジトリのルートで実行する。出力はリポジトリ外の新規ファイルとする。

```sh
python3 scripts/handoff.py build --output ../research-handoff-next.tar.gz
```

buildはソース・文書・設定の明示範囲を収録し、PCAP・結果・仮想環境を除外する。新しい種類の必須ファイルを追加した場合は収録範囲を更新する。復元後はremote未設定。GitHubで同期する場合は対象remoteとブランチを確認して設定する。実行中のコードを更新せず、測定を同時実行しない。
