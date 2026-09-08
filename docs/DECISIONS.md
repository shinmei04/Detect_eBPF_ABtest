# 設計判断記録

「実装済み」「文書に記録あり」「提案」「未決定」を区別する。以下は今回確認できたローカル根拠であり、過去の会話や未確認論文の判断を補わない。

| ID | 論点 | 状態・理由・根拠 |
|---|---|---|
| D001 | 4特徴量 + EMA + score | 実装済み。既存軽量検知の限界を比較する基準。`src/paper_reproduction_detector.py`。完全XDP再現ではない |
| D002 | Goertzel | 簡易版に実装済み。初期READMEは1Hz付近の差を確認する目的を明記。`src/goertzel.py`。FFT等との費用対効果の実測比較は未確認 |
| D003 | FFT | 採用・棄却の理由は未確認。比較候補。対象帯域、窓関数、DC除去、正規化、更新費用を決める必要がある |
| D004 | 自己相関 | 事後分析に実装済み。`experiments/dpsws_additional_eval_20260709/analyze.py::periodicity_score`は攻撃区間のpacket-count列の1秒lag Pearson相関。25msならlag=40。短すぎる列はNaN、ほぼ一定なら0。検知scoreへの組込みは未決定 |
| D005 | pulse由来自己相関 | `experiments/dpsws_random_and_sack_check_20260709/analyze.py::pulse_periodicity`にも実装。送信pulse由来と受信pcap由来を混ぜて比較しない |
| D006 | Jain指標 | 実装・採用理由は今回のコード/文書調査で確認できない。公平性か時系列の偏りか、対象ベクトル・ゼロ入力・判定方向が未決定。数値を作らない |
| D007 | 正常学習trace | 採用記録あり。`experiments/main_ldos_tcp6m/notes/experiment_protocol.md`はTCPを壊さないrandom avg10を採用し、害のある候補を除外。攻撃との同平均負荷を意味しない |
| D008 | 25ms直接窓 | 実装済み。`exp/detector_25ms_20260714/README.md`。既存4秒評価を維持した比較。どちらを最終研究の主設定にするかはこのハーネスでは決めない |
| D009 | TCP送信上限なし | 実装・変更理由の記録あり。`exp/dpsws_tcp_unlimited_20260724/README.md`。6Mbps指定のみ外す実験。元条件と別集計 |
| D010 | 評価ハーネス | 今回採用。既存CLIを呼ぶ薄い入口、JSONプロファイル、新規out、manifest、verifyで再現手順を固定。検知ロジックは変更しない |

## 追記テンプレート
- ID / 題名:
- 状態: 提案 / 採用 / 棄却 / 保留 / 置換済み
- 記録日 / 判断者:
- 問題と研究仮説:
- 比較した選択肢:
- 決定内容と理由（不明なら不明）:
- 根拠: コード関数、config、runディレクトリ、入力hash、指標の列名
- 評価条件・ラベル・分母:
- 利点と代償 / 適用範囲:
- 未解決事項と次の確認:
- 置き換える判断ID / 関連文書:

過去の判断を変更する際は行を消さず、置換先IDを記録する。
