# 研究の目的と課題

## 目的
既存eBPF/XDP型LDoS検知の軽量な窓内統計だけで、TCPへ悪影響を与える周期UDPバーストと正常ランダムバーストを識別できるか検証する。さらに周期性の情報が補完に有効かを評価する。
根拠: [初期研究README](../README.md)、[採用実験プロトコル](../experiments/main_ldos_tcp6m/notes/experiment_protocol.md)。
このリポジトリの検知器はPythonでの窓単位評価であり、実行するXDPプログラムは含まれていない。

## 研究仮説（結論ではない）
- 窓内統計が近い通信でも時間配置が異なれば、周期LDoSだけがTCPのRTO/backoffやgoodput低下を誘発し得る。
- 4特徴量と動的閾値・score判定は、この条件で正常と攻撃を十分に分離できない可能性がある。
- Goertzel等の周期性特徴が識別を改善する可能性がある。採用手法と最終判定規則は未確定。

## 現在の研究課題
- 合成stat-matched条件と実測Mininet条件を区別し、正常性と負荷一致を個別に検証する。
- 採用された正常学習pcapはTCPを壊さない条件だが、周期攻撃と平均UDP負荷が同一ではない。因果比較には同負荷対照も必要。
- 4秒窓と直接25ms窓、online/frozen EMA、TCP 6Mbps制限あり/なしの差を追跡する。
- 少数パケット窓の扱い、全攻撃期間とバースト区間のラベル、評価分母を揃える。
- Reno/SACK off中心の知見が他のTCP設定・周期・seedにも当てはまるか確認する。
- 周期性手法の比較、閾値の決め方、最終データ分割、許容FPR・遅延・計算資源の基準は未決。
- 合成random_microburstは低周波パワーを小さくする候補選択を含む。独立した自然な正常データへの一般化を別途評価する。

## 最終的に評価したいもの
1. 検知性能: TP/FP/TN/FN、FPR/FNR、Precision/Recall/F1、検知遅延、seed/trial間のばらつき。
2. 通信被害: TCP goodput低下、TCPTimeouts/backoff、再送、qdisc drop、ボトルネック未使用率。
3. 周期性追加の効果: 同じ学習・評価データで4特徴量単独との差を比較する。
4. 実装可能性: CPU・メモリ・更新コストとオンライン遅延。XDP上の性能は今後の測定対象で、Python評価から推定しない。

## 根拠の読み方
既存の数値は[主実験summary](../experiments/main_ldos_tcp6m/summaries/summary_main_conditions.csv)と[検知summary](../experiments/main_ldos_tcp6m/detector_results/detector_summary_periodic.csv)を起点に、pcap・case.json・窓CSVへ遡る。
これらは保存された条件における結果であり、最新の全trial集約や一般的な性能保証を意味しない。
再評価で作った数値は新しいoutへ保存し、元のsummaryを更新しない。
