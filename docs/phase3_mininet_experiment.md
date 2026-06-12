# Phase3：Mininet A/B実験結果

## 1. 目的

本実験の目的は、元論文型の4特徴量detectorが、通常条件とstat-matched条件でどの程度検知性能を維持できるかを確認することである。

特に確認したいことは以下である。

```text
元論文型4特徴量detectorは、通常条件ではLDoSを検知できるが、
窓内統計特徴量を類似させた periodic LDoS と random microburst の条件では、
LDoSを見逃しやすくなるのか？
```

## 2. 実験の位置づけ

今回の実験は、元論文の完全再現ではない。
元論文リポジトリを参考にした **4特徴量 + EMA + suspicious score** のPython再現detectorを用いた追加評価である。

今回の実験では以下は行っていない。

* eBPF/XDP実装は使っていない
* Goertzel法 / Sliding DFT などの周波数特徴は使っていない
* 元論文の完全再現ではない
* Mininet上の実パケット列からpcapを取得し、そこから特徴量を抽出して評価した

## 3. 使用した検知器

元論文型detectorとして、以下の4特徴量を用いた。

| 特徴量                         | 内容            |
| --------------------------- | ------------- |
| Inter-Arrival Time variance | パケット到着間隔のばらつき |
| Burst rate                  | 短時間窓内のバースト強度  |
| Payload size variance       | ペイロードサイズのばらつき |
| New flow arrival rate       | 新規フロー発生率      |

検知処理は以下の流れで行った。

```text
4特徴量をwindowごとに計算
  ↓
EMAでbaselineを更新
  ↓
動的閾値を超えた特徴量数をカウント
  ↓
suspicious scoreを算出
  ↓
suspicious score >= 2 でattack判定
```

## 4. Mininet実験条件

Mininet上で以下の2条件を比較した。

### original_like

通常条件で元論文型detectorがLDoSを検知できるかを確認する条件。

| 項目     | 内容               |
| ------ | ---------------- |
| attack | periodic LDoS    |
| benign | 通常benign通信       |
| 目的     | 通常条件で検知器が機能するか確認 |

### stat_matched

periodic LDoS と random microburst の窓内統計特徴量を近づけた条件。

| 項目     | 内容                         |
| ------ | -------------------------- |
| attack | periodic LDoS              |
| benign | random microburst          |
| 目的     | 統計特徴量を似せたA/B条件で検知性能が落ちるか確認 |

random microburstは、periodic LDoSと以下が近くなるように生成した。

* 総パケット数
* burst bucket数
* 最大bucket count
* burst rate
* payload size variance
* new flow arrival rate
* 可能な範囲でIAT variance

ただし、random microburstはperiodic LDoSとは異なり、1秒周期の規則的なバースト構造を持たない。

## 5. 結果

### 全体指標

| 指標              | original_like | stat_matched |       変化 |
| --------------- | ------------: | -----------: | -------: |
| Accuracy        |         0.918 |        0.515 |   -0.402 |
| Precision       |         0.877 |        1.000 |   +0.123 |
| Recall          |         1.000 |        0.175 |   -0.825 |
| F1-score        |         0.934 |        0.299 |   -0.636 |
| FPR             |         0.200 |        0.000 |   -0.200 |
| FNR             |         0.000 |        0.825 |   +0.825 |
| Detection delay |       4.0 sec |      7.0 sec | +3.0 sec |

## 6. original_likeの結果

original_like条件では、元論文型detectorは高い検知性能を示した。

| 指標              |       値 |
| --------------- | ------: |
| Precision       |   0.877 |
| Recall          |   1.000 |
| F1-score        |   0.934 |
| FPR             |   0.200 |
| FNR             |   0.000 |
| Detection delay | 4.0 sec |

混同行列は以下。

|             | pred benign | pred attack |
| ----------- | ----------: | ----------: |
| true benign |          32 |           8 |
| true attack |           0 |          57 |

true attack 57 window のうち、false negativeは0であった。
したがって、今回のPython再現detectorは通常条件ではperiodic LDoSを検知できており、検知器自体が壊れているわけではないと考えられる。

## 7. stat_matchedの結果

stat_matched条件では、元論文型detectorの検知性能が大きく低下した。

| 指標              |       値 |
| --------------- | ------: |
| Precision       |   1.000 |
| Recall          |   0.175 |
| F1-score        |   0.299 |
| FPR             |   0.000 |
| FNR             |   0.825 |
| Detection delay | 7.0 sec |

混同行列は以下。

|             | pred benign | pred attack |
| ----------- | ----------: | ----------: |
| true benign |          40 |           0 |
| true attack |          47 |          10 |

true attack 57 window のうち、47 window が benign と判定された。
つまり、periodic LDoSの大半を見逃した。

一方で、FPRは0であり、random microburstをattackと誤検知してはいない。
したがって、今回の問題はfalse positiveではなく、false negativeである。

## 8. 結果の解釈

original_like条件では、元論文型4特徴量detectorはRecall=1.000、F1=0.934を示し、通常条件ではLDoSを高精度に検知できた。

一方で、stat_matched条件ではRecall=0.175、F1=0.299、FNR=0.825となり、periodic LDoSの大半を正常として見逃した。

この結果から、元論文型4特徴量detectorは通常条件では有効である一方、窓内統計特徴量を類似させたperiodic LDoSとrandom microburstの条件では、検知性能が大きく低下する可能性が示された。

## 9. Suspicious scoreの解釈

元論文型detectorでは、4特徴量のうち動的閾値を超えた特徴量数をsuspicious scoreとして扱い、scoreが2以上になるとattack判定する。

original_likeでは、suspicious scoreが閾値2に到達するwindowが多く、attack判定されやすかった。

一方、stat_matchedでは、suspicious scoreが0〜1付近に留まるwindowが多く、閾値2に届きにくかった。

つまり、stat_matched条件では以下のようなことが起きたと考えられる。

```text
periodic LDoSとrandom microburstの窓内統計特徴量が類似する
  ↓
4特徴量のうち、異常と判定される特徴量数が少ない
  ↓
suspicious scoreが2に届かない
  ↓
attack判定されない
  ↓
false negativeが増える
```

## 10. 現時点で言えること

安全に言えることは以下である。

* 元論文型4特徴量detectorは、original_like条件では高い検知性能を示した。
* original_likeではRecall=1.000、F1=0.934、FNR=0.000であり、通常条件ではperiodic LDoSを検知できた。
* stat_matched条件ではRecall=0.175、F1=0.299、FNR=0.825まで性能が低下した。
* stat_matchedではperiodic LDoSの大半をbenignとして見逃した。
* 問題はrandom microburstをattackと誤検知することではなく、periodic LDoSを見逃すことである。
* したがって、窓内統計特徴量が類似する条件では、元論文型4特徴量detectorの検知性能が大きく低下する可能性がある。

## 11. まだ言えないこと

以下はまだ断定できない。

* 元論文の実装そのものが必ず失敗するとは言えない。
* 元論文の報告精度を否定するものではない。
* 今回の実験は元論文の完全再現ではない。
* 今回はeBPF/XDP実装ではなく、元論文型検知ロジックのPython再現を用いている。
* 今回はGoertzel法やSliding DFTによる改善は評価していない。
* より多様な正常通信・攻撃パターンでも同じ結果になるとはまだ言えない。

## 12. 次にやること

次にやるべきことは、stat_matched条件でなぜperiodic LDoSが見逃されたのかを分析することである。

具体的には、missed attack windowについて以下を確認する。

* IAT varianceが閾値を超えていたか
* Burst rateが閾値を超えていたか
* Payload size varianceが閾値を超えていたか
* New flow arrival rateが閾値を超えていたか
* suspicious scoreが何点だったか
* scoreが2に届かなかった理由は何か

その後、改善案として以下を検討する。

* Goertzel法による1Hz/RTO周期成分の軽量推定
* Sliding DFTによる周期性の逐次追跡
* 既存4特徴量 + 周期性スコアのHybrid detector
* EMA異常検知とは別に、RTO周期性スコアを独立に扱う設計
* suspicious scoreに周期性特徴を追加する方式

## 13. 短いまとめ

Mininet上で、元論文型4特徴量detectorを用いてoriginal_like条件とstat_matched条件を比較した。

original_like条件では、F1=0.934、Recall=1.000、FNR=0.000となり、通常条件ではLDoSを高精度に検知できた。

一方で、stat_matched条件では、F1=0.299、Recall=0.175、FNR=0.825となり、periodic LDoSの大半を正常として見逃した。

この結果から、元論文型4特徴量detectorは通常条件では有効である一方、窓内統計特徴量を類似させたperiodic LDoSとrandom microburstの条件では、検知性能が大きく低下する可能性が示された。

ただし、これは元論文の完全再現ではなく、元論文型検知ロジックのPython再現による追加評価である。したがって、元論文の結果を否定するものではなく、未評価条件に対する追加検証として位置づける。
