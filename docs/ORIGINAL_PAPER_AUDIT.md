# 元論文・著者公開コード・現行再現器の照合

確認日: 2026-09-09 JST。読取・静的照合のみ。実ネットワーク、XDPロード、Mininet、性能評価は実施していない。

## 論文と公開先の同定

ユーザー提示PDF: Elzoghbi / He, *Kernel-level LDoS attack detection in SDN networks: an eBPF/XDP framework with dynamic thresholding*, Computer Networks 275 (2026), 111939。
DOI: https://doi.org/10.1016/j.comnet.2025.111939 。PDF第1ページの書誌は2026年、オンライン公開日は2025-12-15。リポジトリREADMEの2025表記と区別する。

PDF p.24 Code availabilityに著者公開先が明記されている:
https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP

今回取得したHEAD: `6f118ae22de22df6274a5a06ea25d99ec1d69989`（2025-12-18）。取得ファイルはREADME.md、xdp_prog.c、simple_switch_13.py、topo.py。浅いcloneで取得したため全履歴監査は未実施。著者公開コードとの対応は確認できるが、このHEADが論文実験に使われた版と一致するかは未確定。

検知本体の固定参照:
https://github.com/mahmoudelzoghbi92/LDoS-Detection-eBPF-XDP/blob/6f118ae22de22df6274a5a06ea25d99ec1d69989/xdp_prog.c

## 比較表

| 項目 | 原論文 | 公開xdp_prog.c | 現行Python再現器 |
|---|---|---|---|
| 窓 | p.5 §4.1.2: 25 ms。パケット到着で期限を判定 | 定数は25 ms (L15)。実際にはsystem_config_map.window_duration_nsを参照 (L336–338) | bucket25 ms、判定窓の既定4 s/step1 s。新分析は25 msも指定可能 |
| 入力/状態 | per-CPUから集約する構造 (p.6,8) | IPv4 TCP+UDP (L273–281)、16 CPUまで集約、CPU0で検知 (L346–375) | PCAP入口はIPv4 UDP dst5001、窓全体に1組の状態 |
| flow識別 | 5-tuple (p.6 式12)。5-tuple別に全特徴/検知状態を持つという意味ではない | source-portのみ (L525–543)。CPUごとの最大50ポート、CPU間の数は加算 | 窓内のIP/port連結flow_idのunique数。固定UDP条件ではprotocol暗黙 |
| burst rate | n/W (p.6 式7) | n×1e9/window_duration_ns (L379) | n/window_sec |
| IAT variance | n個のpacketからn−1個の間隔、その母分散の式 (p.5 式3–4、p.6 Algorithm1) | sum_sqにiat²/1e6を累積 (L516)、sumはnsのまま。分母にtotal_packetsを渡す (L184–188,378) | np.var(np.diff(timestamp_sec),ddof=0)。単位s² |
| payload | IP全長−IPヘッダ−transportヘッダ (p.6 式10) | frame長−Ethernet−IPヘッダ、transportヘッダを差し引かない (L521)。分散×1e6 (L175–180) | UDP payload byteの母分散 |
| 取り込む量 | 一般の窓内packet集合を記述 | CPUごと先頭100 packetまで統計へ加算 (L17,510–547)。後続packetも期限確認/遮断判定は通る | 窓内の全選択packetを集計 |
| 閾値下限 | p.7式18: mu±beta*sigma | min_thresholdが4特徴ごとに1000/5000000/1000000000/500000 (L155–159)、全方向でfloor適用 (L216–241) | 4つともmin_threshold=0。下限のみmaxで0に制限 |
| 初期値/計算 | p.7–8: EMA/整数計算の説明 | 設定済みmu/sigma定数、整数除算、sigma floor1000 | 既定は最初の観測値から初期化、float、sigma floor1e-12 |
| 閾値更新 | p.7式22・p.8 Algorithm2: score>=2なら全更新停止。score<2で非異常特徴のみ更新 | 各特徴の判定直後に非異常特徴を更新 (L421–459)、その後score>=2を判定 (L461–485)。総scoreによる全更新停止なし | 公開コードに近い特徴別更新。総scoreによる全更新停止なし |
| sigma偏差 | p.7式16では旧mu、p.8 Algorithm2の逐次代入では更新後muを使う形 | 更新後muとの差 (L440–446) | 更新後muとの差 |
| score | p.7式20–21、p.8 Algorithm2: 4 flagの和、>=2 | 同じ (L421–462)、warmup20/最低10 packet | 同じscore/下限packet gate。元コードの上限・CPU集約は再現しない |
| 遮断 | kernelでdrop | attack_mapの共有ブロック状態とtimer/manual recovery (L293–320,461–485) | 分類ログのみ。実drop/CPU競合・回復を再現しない |

## 特に優先する再現性の問題

1. **閾値下限が一致しない。** 前回挙げた「下限0かつ分散0でlower判定が成立しない」は現行Pythonの性質。公開元コードは正の下限を持つため、そのまま元検知器のblind spotとは言えない。公開コードの整数スケールを確認せず定数だけPythonへ移植することもしない。
2. **論文と公開コード自体の更新規則が異なる。** 論文のscore条件で全更新停止する方式では、score>=1/2を変えると将来のEMA状態も変わり得る。前回の「同じscoreログを2通りに読む」比較は現行Python/公開コード型の特徴別更新に対して有効であり、論文Algorithm2型への一般化はしない。
3. **実行configの初期化が不明。** 公開4ファイルにはsystem_config_mapのwindow_duration_ns等へ値を設定する処理が見当たらない。定数WINDOW_DURATION_NSを定義していてもその値がmapへ代入されるとは限らない。公開READMEの手順だけで論文どおり25 msで動くことは未確認。外部user-control/loaderと実際のmap値の回収が必要。
4. **IAT整数式の単位整合に疑義。** 10 packetが等間隔1,000,000 nsで到着した小例を公開式に代入すると、sum=9,000,000、sum_sq=9,000,000、mean=900,000。signedの差は900,000−810,000,000,000=−809,999,100,000で、u64ではwrapする。これは公開式を小さな整数演算で検算した結果であり、実機での発生率/検知性能の測定ではない。論文実験版との対応を確かめず修正して元手法扱いにしない。

補足: PDFはIATのn−1分母を不偏推定と説明しているが、間隔の標本数自体がn−1なので掲載式はその間隔列に対する母分散。式と説明を区別する。

## 研究方針への反映

当面はP0=現行Python、P1=論文数式/Algorithm準拠、P2=commit固定の公開Cコードを別の比較対象とする。CPU0集約やサンプリング上限、外部初期化はP2の実行環境依存として記録する。

次の実装前に、論文で使ったコード版、初期化/校正データ、source-port/5-tupleの扱い、IATスケーリング、payload長定義を確認する。必要なら著者への問い合わせ文を準備できるが、送信はしていない。現行実装は維持し、今回の照合だけで検知器の仕様を書き換えない。

この時点で元手法の見逃し原因も提案手法の改善も結論しない。まず「どの検知器のどの現象を説明しているか」を固定することが優先。

取得xdp_prog.c SHA256: `23f07a284e4022636c36a4e3f7831e1adc277b1d658dc183bfeaeb53acb65f5d`。


## ユーザーによる実行条件の補足

ユーザーから、原稿の評価は実行時に25 msを指定して実施したとの説明を受けた。原稿の評価条件は25 msとして扱う。比較表の「既定4 s」は現行Pythonのデフォルト設定についての記述であり、原稿の実験が4秒窓だったことを示さない。実行時設定の保存・対応確認は再現性記録の整備として行い、既定値だけを根拠に原稿の25 ms記述を疑う理由にはしない。閾値下限、数値スケール、更新規則等は別の照合事項として残る。
