> 2026-09-09時点の背景資料スナップショット。現在の方針は `AGENTS.md` と `docs/current_phase.md` を優先する。

# LDoS防御研究ロードマップ・研究方針

更新日: 2026-09-09

## 1. 研究の最終目的

本研究では、既存のLDoS（Low-rate Denial-of-Service）検知器が見逃す通信パターンを分析し、その原因を明らかにした上で、**検知率を改善しつつ実運用可能な軽量性を維持する防御手法**の確立を目指す。

特に、研究を以下の2段階で進める。

1. **時間構造を考慮した軽量LDoS検知**
   - 既存の軽量検知器に周期性・時間的規則性を表す特徴量を追加する。
   - Jain指標、自己相関、FFTなどを比較し、検知性能と計算コストのトレードオフを評価する。

2. **TCP輻輳制御状態遷移を利用したLDoS検知**
   - 攻撃トラフィックそのものの形状ではなく、LDoSによってTCPが受ける影響を観測する。
   - Slow Start、Congestion Avoidance、Recovery、Backoff等の状態を推定し、その遷移パターンの異常からLDoSを検知する。

最終的には、

> **「攻撃トラフィックがどのような形をしているか」ではなく、「TCP輻輳制御にどのような異常を引き起こしているか」に基づくLDoS検知**

へ発展させることを長期的な方向性とする。

---

# 2. 現在までの研究状況

## 2.1 対象としている既存検知器

現在は Elzoghbi & He による2026年のLDoS検知方式を主な対象としている。

同方式はeBPF/XDPを利用し、カーネル／データパス側でLDoSを高速に検知することを目的としている。既存SDN型方式の問題として、制御チャネル負荷、検知遅延、False Positive、攻撃variantへの対応などを挙げ、実運用を意識した軽量検知を設計している。 citeturn291368search2

主要な特徴量は以下である。

- Inter Arrival Time (IAT) variance
- Burst rate
- Payload size variance
- New flow arrival rate

これらについて動的閾値を計算し、複数特徴量の異常判定を組み合わせる。

### 現時点で考えている弱点

これらの特徴量は局所的な通信統計を表している一方、

> **バーストが時間軸上でどのような間隔で配置されているか**

という時間構造を直接表現していない。

そのため、

```text
burst     burst     burst     burst
  |---------|---------|---------|
      T         T         T
```

のような長時間の規則性が、各短時間区間の統計特徴量から失われる可能性がある。

---

## 2.2 現在得られている結果

既存検知器をオフラインで再現し、管理下のMininet環境で生成した通信について評価したところ、周期的LDoS通信によってTCP性能が大幅に低下しているにもかかわらず、既存検知器では異常判定に至らないケースを確認している。

代表条件では、

- 60秒試行
- 10–50秒を攻撃区間
- UDP平均帯域 約4.5 Mbps
- Peak 15 Mbps
- burst duration 300 ms
- period 1000 ms
- 25 ms bucket
- 4 s window
- 1 s step

を利用している。

10試行を合算した結果では、

- 攻撃区間で `score >= 2` の検知なし
- TCP goodput

  - Baseline: 約14.34 Mbps
  - LDoS時: 約2.61 Mbps
- 約81.8%のgoodput低下
- Timeoutも多数発生

している。

したがって、

> **TCPに実害が発生しているにもかかわらず既存特徴量では検知できない**

という現象までは確認できている。

---

# 3. 既存研究調査

## 3.1 LDoSとTCP輻輳制御の関係

LDoSがTCPの輻輳制御機構を悪用するという考え方自体は以前から広く知られている。

LDoSによってlossやcongestionが発生すると、

```text
Congestion Avoidance
        ↓
Packet Loss
        ↓
Fast Recovery / Timeout
        ↓
Slow Start
        ↓
Congestion Avoidance
```

といったTCPの回復過程が発生する。

したがって、LDoS研究ではTCP輻輳制御への影響そのものは既に重要な攻撃原理として認識されている。

---

## 3.2 Congestion Participation Rate（2012）

Zhangらは、LDoS flowがネットワーク輻輳へどの程度参加しているかを見る **Congestion Participation Rate（CPR）** を提案している。 citeturn291368search1

これは、

> 「どのflowがcongestionを発生させる側として振る舞っているか」

を見る方式であり、単純な帯域量よりLDoSの性質に踏み込んでいる。

ただし、

```text
Slow Start
Congestion Avoidance
Recovery
Backoff
```

といったTCP輻輳制御状態を逐次推定しているわけではない。

---

## 3.3 MF-HMM（2015）

LDoS検知にHidden Markov Modelを利用した研究も既に存在する。

MF-HMMでは、

- TCP header feature
- Power Spectral Density
- traffic-level feature

などを複数の観測系列として利用し、LDoSを識別している。周期性をPSDで表現する点も重要である。 citeturn291368search3turn291368search8

したがって、

> 「HMMや状態モデルをLDoS検知へ導入する」

というだけでは新規性にならない。

ただし、このHMMのhidden stateは、

```text
Slow Start
Congestion Avoidance
Fast Recovery
Backoff
```

というTCP輻輳制御上の意味を持った状態ではない。

---

# 4. TCP輻輳制御状態推定に関する調査

## 4.1 TCPWN（NDSS 2018）

非常に重要な関連研究としてTCPWNが存在する。

TCPWNでは、ネットワーク上を流れるTCP packetのみを観測して、

> **送信者が現在どのTCP congestion-control stateに存在するか**

を推定するCongestion Control State Trackerを実装している。 citeturn291368search0turn291368search60

例えば、

```text
Slow Start
Congestion Avoidance
Fast Recovery
Exponential Backoff
```

などの状態を外部から推定する。

これは本研究に非常に近い技術である。

ただしTCPWNの目的はLDoS検知ではない。

```text
Network traffic
      ↓
TCP CC state inference
      ↓
TCP implementation testing
      ↓
Attack / vulnerability discovery
```

という研究である。

したがって、

> **Passive TCP congestion-control state inferenceそのものは既存技術**

として扱う必要がある。

---

## 4.2 aBBRate（RAID 2020）

BBRについても同様の研究が存在する。

aBBRateではBBRの詳細なFinite State Machineを構築し、パケットをpassiveに観測することでBBRの現在状態を推定する手法を提案している。 citeturn291368search6

したがって、

> 「TCP/輻輳制御アルゴリズムの内部状態を外部観測から推定できる」

という点そのものには新規性はない。

一方で、これらの既存技術をLDoS検知へ利用できる可能性がある。

---

# 5. 最近のLDoS防御研究

近年は、単純なトラフィック量検知だけでなく、

- 軽量なkernel/data-plane検知
- 時間構造
- end-host観測
- QoSへの影響
- programmable data plane

などへ研究が進んでいる。

### HawkEye（2025）

HawkEyeは検知をend-hostへ配置し、複数のnetwork traffic featuresをLightGBMで分類する。TCP adaptive mechanismがLDoSの標的であることを明確にしているが、TCP CC状態系列そのものを復元する方式ではない。 citeturn975465search0

### Elzoghbi & He（2026）

eBPF/XDPを利用したkernel-levelの軽量検知を目指している。

研究の重点は、

- real-time detection
- scalability
- low false-positive rate
- deployment practicality

などに置かれている。 citeturn291368search2

### PT-Radar（2026）

PT-Radarはprogrammable data plane上で0.1秒単位のtime slotを利用し、LDoSのpulse–quiet構造を表す特徴量を抽出する。

つまり、最新研究でも**時間構造を明示的に観測する方向**が重要視されている。 citeturn975465search1

### IDQS（2026）

IDQSでは、将来のQoSを予測し、

\[
QoS_{predicted}
\]

と

\[
QoS_{actual}
\]

の乖離からLDoSを検知する。

これは、

> 攻撃トラフィックそのものではなく、攻撃によって生じた通信品質への影響を見る

という方向に近い。 citeturn975465search2

---

# 6. 現時点で考えられる研究ギャップ

既存研究を整理すると、

### 既に研究されているもの

- LDoSによるTCP congestion controlへの影響
- congestionを利用したLDoS検知
- FFT / PSD / Waveletなどによる周期性検知
- HMMを利用したLDoS検知
- 機械学習によるLDoS分類
- QoS変化を利用したLDoS検知
- TCP congestion-control stateのpassive inference

は既に存在する。

一方、今回確認した文献の範囲では、

> **Slow Start / Congestion Avoidance / Recovery / Backoff等のTCP輻輳制御状態をpassiveに推定し、その状態遷移系列の異常をLDoS検知の主要シグナルとして利用する方式**

は確認できていない。

したがって現時点では、

> **「TCP状態推定そのもの」ではなく、「既存のTCP状態推定技術をLDoS検知へ導入し、意味を持つ状態遷移系列からLDoSを検出する」**

ことを新規性候補とする。

ただし、現段階では「世界初」等の主張は行わない。

IEEE Xplore、ACM Digital Library、Scopus等を含めた追加調査を行った上で最終的に判断する。

---

# 7. 研究の基本方針

研究を2フェーズで進める。

---

# Phase 1: Lightweight Temporal-Aware LDoS Detection

## 目的

現在確認している既存検知器の見逃しについて、

> **時間的規則性を特徴量として持っていないことが原因なのか**

を検証する。

## 基本構成

```text
Existing detector
│
├── IAT variance
├── Burst rate
├── Payload variance
├── New-flow rate
│
└── Temporal feature ← 追加
```

候補は、

1. Jain index
2. Autocorrelation
3. FFT

とする。

---

## 7.1 Jain index

25 ms bucketなどからburst開始時刻

\[
t_1,t_2,\ldots,t_n
\]

を抽出する。

burst intervalを

\[
d_i=t_{i+1}-t_i
\]

として、

\[
J=
\frac{
(\sum_{i=1}^{m}d_i)^2
}{
m\sum_{i=1}^{m}d_i^2
}
\]

を計算する。

等間隔なら、

\[
J \rightarrow 1
\]

となる。

### 利点

- FFTより軽量
- 実装が単純
- incremental calculationが可能
- eBPF等への実装可能性も考えやすい

### 課題

- burst抽出精度に依存
- periodicityそのものを数学的に測る指標ではない
- jitterの大きい通信には弱い可能性がある

---

## 7.2 Autocorrelation

traffic time series

\[
x_t
\]

に対して、

\[
R(k)=
\frac{
\sum_t(x_t-\bar{x})(x_{t+k}-\bar{x})
}{
\sum_t(x_t-\bar{x})^2
}
\]

を計算する。

特定lagで高い相関が繰り返し現れる場合、周期構造が存在すると判断できる。

---

## 7.3 FFT

traffic time seriesを周波数領域へ変換し、

\[
X(f)=FFT(x_t)
\]

ピーク周波数から周期構造を検出する。

精度面では有力だが、Jainや単純自己相関より計算量が大きいため、

> **実運用可能な軽量検知**

という本研究の目的とのトレードオフを評価する。

---

# 8. Phase 1のResearch Questions

### RQ1

**既存検知器が周期的LDoSを見逃す原因は、時間的規則性を特徴量として持たないことなのか。**

### RQ2

**時間構造特徴量を追加することでRecallを改善できるか。**

### RQ3

**False Positiveを増加させずに検知率を改善できるか。**

### RQ4

**Jain / Autocorrelation / FFTのどれが、検知性能と計算コストのバランスに優れているか。**

### RQ5

**既存検知器の軽量性を維持できるか。**

---

# 9. Phase 1の評価項目

## Detection

- TP
- FP
- TN
- FN
- Recall
- Precision
- F1
- FPR

## TCPへの影響

- TCP goodput
- retransmission
- timeout
- RTT
- packet loss

## Operational Cost

- feature calculation time
- CPU usage
- memory usage
- detection latency

---

# 10. Phase 1の比較条件

最低限、以下を比較する。

```text
Baseline
    ↓
Normal TCP traffic

Benign burst
    ↓
Non-periodic / random burst traffic

Periodic LDoS
    ↓
Regular burst traffic
```

さらに、

```text
Original detector

Original + Jain

Original + Autocorrelation

Original + FFT
```

を比較する。

---

# 11. Phase 2: Congestion-Control State-Transition-Aware Detection

Phase 1終了後の発展研究として実施する。

## 中心となる考え方

従来方式では、

```text
Attack Traffic
     ↓
statistics / periodicity
     ↓
LDoS detection
```

を行う。

Phase 2では、

```text
TCP packets
     ↓
Congestion-control state inference
     ↓
State-transition sequence
     ↓
Transition anomaly
     ↓
LDoS detection
```

とする。

つまり、

> **攻撃パケットの形状ではなく、攻撃によってTCPがどのように壊されているかを見る。**

---

# 12. 推定対象状態

初期段階ではReno/NewReno等を対象として、

\[
S_t \in
\{
SS,
CA,
Recovery,
Backoff
\}
\]

とする。

- `SS`: Slow Start
- `CA`: Congestion Avoidance
- `Recovery`: Fast Recovery等
- `Backoff`: RTO / Exponential Backoff

状態推定自体についてはTCPWN等の既存技術を参考にする。

本研究では状態推定方法自体を主要な新規性とはしない。

---

# 13. 状態遷移から作るLDoS特徴量候補

## 13.1 Transition Count

一定時間内の状態遷移回数

\[
N_{transition}
\]

---

## 13.2 Recovery Event Count

例えば、

\[
CA
\rightarrow
Recovery
\rightarrow
SS
\]

の発生回数。

---

## 13.3 Backoff → Slow Start Count

\[
N_{Backoff\rightarrow SS}
\]

---

## 13.4 State Dwell Time

各stateに滞在した時間

\[
T_{SS},T_{CA},T_{Recovery},T_{Backoff}
\]

を利用する。

---

## 13.5 Transition Probability

正常通信からtransition matrix

\[
P_{normal}
\]

を構築する。

観測通信から、

\[
P_{current}
\]

を求め、

\[
D(P_{current},P_{normal})
\]

を異常度とする。

---

# 14. Phase 2の仮説

正常TCPでは、

```text
SS
 ↓
CA ──────────
      ↓
   Recovery
      ↓
     CA
```

のような比較的安定した状態遷移になる。

一方、LDoSによる繰り返しのcongestion disruptionが発生すると、

```text
CA
 ↓
Recovery / Backoff
 ↓
SS
 ↓
CA
 ↓
Recovery / Backoff
 ↓
SS
 ↓
...
```

という異常な状態cycleが発生する可能性がある。

この違いを検知に利用する。

---

# 15. Phase 2のResearch Questions

### RQ6

**LDoSによってTCP congestion-control state transitionに正常通信とは異なる特徴が現れるか。**

### RQ7

**状態遷移特徴量からLDoSを検知できるか。**

### RQ8

**traffic periodicityを利用した方式より、攻撃パターンの変化に対して頑健か。**

### RQ9

**TCP variantが変化しても同じ考え方を利用できるか。**

### RQ10

**状態遷移検知を軽量に実現できるか。**

---

# 16. Phase 1とPhase 2の関係

最終的には、

```text
Level 1
Traffic statistics
    │
    │ Elzoghbi
    ↓

Level 2
Temporal structure
    │
    │ Jain / ACF / FFT
    ↓

Level 3
Transport-layer impact
    │
    │ CC state transition
    ↓

LDoS Detection
```

という階層として整理できる。

---

# 17. 本研究で狙う新しい価値

完全に新しいアルゴリズムをゼロから発明することを目的とはしない。

本研究では、

> **既存技術を新しい問題設定へ組み合わせることで、新しい検知価値を作る**

ことを狙う。

具体的には、

### 既存技術A

軽量LDoS detection

### 既存技術B

Temporal analysis

### 既存技術C

Passive TCP congestion-control state inference

を組み合わせ、

```text
Traffic feature
      +
Temporal feature
      +
Transport-layer behavior
```

という複数レイヤからLDoSを捉える。

---

# 18. 新規性候補

現時点で想定する研究上の貢献は以下。

## Contribution 1

**最新の軽量LDoS検知器が特定の周期通信を見逃すケースを示し、その原因を時間構造の欠落という観点から分析する。**

## Contribution 2

**Jain / ACF / FFTを比較し、低計算コストで時間構造を補完できる特徴量を明らかにする。**

## Contribution 3

**Passive TCP congestion-control state inferenceをLDoS検知へ導入する。**

## Contribution 4

**TCP CC state-transition anomalyという新しい観測軸からLDoSを検知する。**

## Contribution 5

**Traffic Statistics / Periodicity / CC State Transitionを同一条件で比較し、それぞれの検知可能範囲を明らかにする。**

---

# 19. 重要な評価軸

単純に

> 「Accuracyが上がった」

だけでは研究として弱い。

以下を同時に評価する。

\[
Detection\ Performance
\]

×

\[
Robustness
\]

×

\[
Computational\ Cost
\]

×

\[
Detection\ Latency
\]

特にElzoghbi方式を拡張する以上、

> **既存方式の軽量性をどの程度維持できたか**

を必ず評価する。

---

# 20. 想定されるリスク

## 20.1 TCP状態推定の精度

packet observationだけではTCP stateを完全に復元できない可能性がある。

特に、

- application-limited traffic
- CUBIC
- SACK
- PRR
- TLP
- BBR

等では状態推定が難しくなる。

### 対応

最初は単純なbulk TCP + Reno/NewRenoから始める。

Mininet上ではsender内部のstateをground truthとして取得し、

```text
Ground truth state
        vs
Passive inferred state
```

を比較する。

---

## 20.2 正常輻輳との区別

正常なネットワークでも、

```text
CA
→ Recovery
→ CA
```

等の遷移は当然発生する。

したがって、

> 「Recoveryが発生したから攻撃」

とはできない。

### 対応

- transition frequency
- repeated transition sequence
- dwell time
- transition probability
- QoS degradation

などを複合的に利用する。

---

## 20.3 TCP variant依存

RenoとCUBIC、BBRでは状態構造が異なる。

### 対応

最初から全TCP variantへ一般化しない。

```text
Step 1: Reno/NewReno
Step 2: CUBIC
Step 3: BBR
```

の順で拡張する。

---

# 21. 研究ロードマップ

## Phase 1-A: 既存検知器の分析
### ～ 9/10

- [x] Elzoghbi検知器の再現
- [x] 周期LDoSの見逃し確認
- [x] TCP goodputへの影響確認
- [x] score / featureの確認
- [ ] 見逃し原因を図として整理
- [ ] 特徴量ごとの正常／LDoS分布を可視化

---

## Phase 1-B: 時間構造特徴量実装
### 9/10 ～ 9/12

- [ ] burst開始時刻抽出
- [ ] burst interval算出
- [ ] Jain index実装
- [ ] Autocorrelation実装
- [ ] FFT実装
- [ ] 共通interface化

---

## Phase 1-C: 比較評価
### 9/12 ～ 9/15

- [ ] Baseline評価
- [ ] Benign random burst評価
- [ ] Periodic LDoS評価
- [ ] Original detector評価
- [ ] Original + Jain
- [ ] Original + ACF
- [ ] Original + FFT

評価項目:

- Recall
- Precision
- FPR
- F1
- Detection latency
- Calculation time

---

## Phase 1-D: 改善方式決定
### 9/15 ～ 9/17

以下を総合して方式を決定する。

```text
Detection performance
        vs
Computation cost
```

- [ ] 最良特徴量決定
- [ ] threshold決定
- [ ] window size検討
- [ ] step size検討
- [ ] ablation study

---

## Phase 1-E: 研究結果整理
### 9/17 ～ 9/20

- [ ] 実験結果図
- [ ] TP/FP/TN/FN表
- [ ] goodput比較
- [ ] computation cost比較
- [ ] 考察
- [ ] 新規性整理
- [ ] 原稿への反映

---

# 22. Phase 2ロードマップ

## Phase 2-A: Feasibility Study
### 9/21 ～ 9/24

目的:

> TCP状態遷移に本当にLDoS由来の異常が現れるか確認する。

- [ ] TCPWN詳細調査
- [ ] state tracker仕様整理
- [ ] Mininet TCP state ground truth取得
- [ ] PCAPとの時刻同期
- [ ] 正常TCP state timeline作成
- [ ] LDoS時state timeline作成

---

## Phase 2-B: Passive State Inference PoC
### 9/24 ～ 9/28

- [ ] SS推定
- [ ] CA推定
- [ ] Recovery推定
- [ ] Backoff推定
- [ ] ground truthとの比較

評価:

\[
State\ Inference\ Accuracy
\]

---

## Phase 2-C: Transition Feature設計
### 9/28 ～ 10/2

- [ ] transition count
- [ ] Backoff→SS count
- [ ] Recovery cycle count
- [ ] dwell time
- [ ] transition matrix
- [ ] anomaly score

---

## Phase 2-D: LDoS Detection
### 10/2 ～ 10/7

比較:

```text
Traffic Statistics
vs
Periodicity
vs
CC State Transition
```

評価:

- Recall
- FPR
- Detection latency
- CPU cost
- Variant robustness

---

# 23. Decision Gate

研究を自動的に一方向へ進めず、結果によって次の方向を変える。

## Case A

Jain等の軽量特徴量で十分な改善が得られる。

→ Phase 1を独立した研究成果としてまとめる。

---

## Case B

FFT / ACFのみ高精度でJainが弱い。

→ 精度と計算量を比較し、軽量化方法を検討する。

---

## Case C

時間構造を少し変えるだけでperiodicity detectorの性能が大幅に低下する。

→ 「周期性依存」という限界を明確化し、Phase 2を主研究へ昇格する。

---

## Case D

LDoS時に明確なCC state-transition anomalyが現れる。

→ Phase 2を本格実装する。

---

## Case E

Passive state inferenceの精度が不足する。

→ TCPの完全なstate推定に固執せず、

- retransmission event
- loss epoch
- recovery event
- RTO event
- ACK dynamics

など、直接観測しやすい**transport-layer event**へ抽象化する。

---

# 24. 最終的に目指す比較

最終論文では以下を比較できる状態を目指す。

| Method | 観測対象 | Periodicity依存 | TCP意味情報 | 計算量 |
|---|---|---:|---:|---:|
| Existing detector | Traffic statistics | Low | No | Very Low |
| Jain extension | Burst interval | High | No | Very Low |
| ACF | Time series | High | No | Low–Medium |
| FFT | Frequency structure | High | No | Medium |
| CC Transition | TCP behavior | Low | Yes | TBD |

この表を実験結果で埋めることが最終目標の一つとなる。

---

# 25. 最終的な研究ストーリー候補

研究全体としては以下のストーリーを狙う。

```text
1. 最新の軽量LDoS検知器を再現

             ↓

2. TCPへ深刻な影響を与えるにもかかわらず
   検知されない通信を確認

             ↓

3. 原因を分析
   → 局所統計だけでは時間構造が失われる

             ↓

4. Lightweight Temporal Featureを追加

             ↓

5. 検知性能を改善

             ↓

6. しかしperiodicity自体に依存する限界が存在

             ↓

7. LDoSの本質である
   TCP congestion-control disruptionへ着目

             ↓

8. CC state-transitionを観測

             ↓

9. 攻撃trafficの形状ではなく
   transport-layer impactからLDoSを検知
```

---

# 26. 現時点での研究テーマ案

### 短期

**Lightweight Temporal-Aware Detection for Low-rate Denial-of-Service Attacks**

日本語:

**時間構造を考慮した軽量LDoS攻撃検知手法**

---

### 中期・本命候補

**LDoS Detection Based on TCP Congestion-Control State Transitions**

日本語:

**TCP輻輳制御状態遷移に基づくLDoS攻撃検知手法**

---

### さらに広くする場合

**Transport-Layer Impact-Aware Detection of Low-rate Denial-of-Service Attacks**

日本語:

**トランスポート層への影響に着目したLDoS攻撃検知手法**

この名称であれば将来的に、

- TCP Reno
- CUBIC
- BBR
- QUIC

などへの拡張も扱いやすい。

---

# 27. 直近TODO

現時点ではPhase 2へ飛ばず、まずPhase 1を完成させる。

優先順位は以下。

1. **既存検知器の見逃し原因を定量化**
2. **Jain / ACF / FFTを同一interfaceで実装**
3. **検知率と計算コストを比較**
4. **最適な時間特徴量を決定**
5. **9/20までにPhase 1の研究結果を確定**
6. **TCPWNを基にState TrackerのPoCを開始**
7. **正常/LDoSでCC state timelineを比較**
8. **状態遷移方式を本研究へ組み込む価値を判断**

---

# 28. 現時点での研究方針

現段階では、

> **「周期性検知を最終目的とする」のではなく、周期性検知を既存検知器の弱点を理解するための第一段階として位置づける。**

その上で、

> **LDoSの本質であるTCP輻輳制御への影響を直接観測する検知方式へ発展できるかを検証する。**

完全に新しい要素技術の発明に固執せず、

> **既存のLDoS検知技術とTCP状態推定技術を適切に組み合わせ、新しい観測軸と検知価値を作る**

ことを研究の基本方針とする。

最終的な研究テーマは実験結果に基づいて決定し、現時点ではPhase 1とPhase 2の双方を候補として維持する。
