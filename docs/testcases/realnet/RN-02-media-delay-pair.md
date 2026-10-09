---
id: RN-02
title: 低 RTT 路径加 tc 时延，关闭 FEC，媒体成对对照
kind: agent
where: 低 RTT 路径（t1→g5 或 g5→t1；曾用 zjg→t1，zjg 已于 2026-10-09 下线）
automation: tools/realnet/srt/cmp_round.py 跑轮次；判定用 cmp_pair.py --limits 加本文规则
duration: 约 1.5 小时（两条链并行，每条 7 轮）
last_run: 2026-10-08 通过（3353b9d 对 44a963c，t1→g5，16 对，`LIMITS OK`；音频 −0.37 [−1.24, +0.49]、视频 −0.06、可解码 −0.36、关键帧 −0.18 个百分点，线上带宽 +0.51%；+100 ms 15% 一个场景按规则加种子重跑，见基准）
---

# RN-02 受控时延下的媒体（关闭 FEC）

## 目的

这是版本回归的主用例，在可控的时延与丢包下，比较只靠重传的音视频交付：

- 音频、视频、关键帧的准时率；
- 可解码的视频；
- 时延；
- 线上带宽。

接收端缺口等待、RTO、RACK、重传调度、ACK、线上格式和拥塞控制的改动都会反映在这里。

## 前置

- RN-01 已通过；
- 发送端与接收端的带宽预算：两条链各 2 个 lane × 2000 kbit，每台主机共 8 Mbit。加上同时运行的其他用例，不能超过 `cap_kbps − 5000`。

## 步骤

1. 写批次脚本（参考 `anliu-realnet-work/fecopt-20261006/batch.sh`）：

   ```sh
   A=anl-nf,anl-nf@cand; B=anl-nf@cand,anl-nf
   one() {   # CHAIN PORTBASE DELAY LOSS SEED PROTOS
     for attempt in 1 2; do
       out=$(timeout 1800 python3 $R/srt/cmp_round.py t1 g5 2000 $4 $5 $2 --anl base --protos $6 --delay $3 --drive-check 2>&1 </dev/null | tail -2)
       echo "$(date '+%F %T') [$1] delay $3 loss $4 seed $5 $out" | tr '\n' ' '; echo
       echo "$out" | grep -q "True$" && return
     done
   }
   chain() {   # NAME PORTBASE DELAY
     for s in 501 502; do for l in 3 5; do one $1 $2 $3 $l $s $([ $s = 501 ] && echo $A || echo $B); done; done
     for l in 7 10 15; do one $1 $2 $3 $l 501 $A; done
   }
   chain d100 9960 100 & sleep 20; chain d200 9970 200 & wait; echo ALLDONE
   ```

   `anl-nf` 的参数是：

   - FEC 关闭，固定码率（视频比例 1000，不跟随编码器）；
   - 音频 max_age 200 ms，视频 500 ms；
   - 缺口等待用默认值；
   - 按 150 / 300 ms 计准时。

2. 等到 `lane.log` 中出现 `ALLDONE`。
3. 分析：
   ```sh
   python3 $R/srt/cmp_ana.py > ana.txt
   cd $R/srt && python3 cmp_pair.py anl-nf anl-nf@cand --limits > pair.txt
   ```

## 通过规则

- 有效轮次 ≥ 12 / 14；
- `pair.txt` 末行为 `LIMITS OK`。各项限值（全部轮次"候选 − 基线"的均值；只有均值超出限值、并且 95% 区间不含 0，才判失败）：

  | 指标 | 限值 |
  |---|---|
  | 音频准时 | ≥ −0.5 个百分点 |
  | 视频准时 | ≥ −1.0 个百分点 |
  | 可解码视频 | ≥ −1.0 个百分点 |
  | 关键帧 | ≥ −2.0 个百分点 |
  | 音频 p50 | ≤ +5 ms |
  | 视频 p95 | ≤ +15 ms |
  | 线上带宽 | ≤ +3% |

- 任何一个场景（时延 × 丢包）的音频均值低于基线 2 个百分点以上，或视频均值低于基线 5 个百分点以上，都要在该场景加两个种子（503、504）重跑，并以全部轮次的均值重新判定；
- 两个版本都没有 `DEAD` 行（`grep -l "^DEAD" results/*.srv results/*.cli` 为空）；
- 每一轮每个 lane 的端到端丢包（`DATAGRAM_COST` 的发送与接收之差）与 tc 设定相差不超过 2 个百分点，否则该轮无效（见 [README.md](README.md) 的"出口容量"一节）。

`LIMIT ... WARN`（均值超出限值、但区间含 0）记为"待确认"，按 [../README.md](../README.md) 的判定规则处理。

## 基准

2026-10-08（`44a963c` 对 `3353b9d`，t1→g5，`reg-20261008`）：

- 全部 16 对：
  - 音频 −0.37 [−1.24, +0.49]、视频 −0.06 [−0.20, +0.09]、可解码视频 −0.36 [−1.09, +0.37]、关键帧 −0.18 [−0.58, +0.22] 个百分点；
  - 视频 p95 −0.6 ms；
  - 线上带宽 +0.51% [+0.13, +0.89]：线上格式每个数据报多 1..2 字节，是预期的变化。
- 基线绝对值（+100 / +200 ms）：

  | 丢包 | 音频（+100 / +200） | 可解码视频（+100 / +200） |
  |---|---|---|
  | 3% | 98.0 / 96.9 | 99.9 / 93.9 |
  | 5% | 99.5 / 95.0 | 99.0 / 84.3 |
  | 10% | 97.9 / 89.9 | 92.2 / 51.8 |
  | 15% | 92.4 / 85.4 | 83.8 / 27.0 |

- 已定位并修复（两个版本都有，2026-10-08）：+100 ms 15% 丢包时，音频重传会在某一刻起失效，并且不再恢复（每 30 s 缺失的音频帧从约 30 个跳到约 210 个）。
  - 原因：发送端截住对端的 ts（`peer_ts` 不越过 `ref`），`peer_ts` 越来越落后于对端时钟。CTRL_ECHO 回送的就是它，于是只收不发的接收端量到的 RTT 从 101 ms 涨到 116..124 ms，越过 `rcv_hole_hopeless` 的阈值（约 122 ms）后，接收端把所有缺口立即跳过。
  - 修复：允许对端 ts 超前 `ref` 至多 1 s（`TS_AHEAD_MAX`）。
  - 实网 A/B（4 轮）：修复前 echo RTT 117..124 ms，一轮失效，音频 90.8%；修复后 99..101 ms，音频 97.8..97.9%。
  - 检查方法：按 30 s 统计 `.cli` 中 `MDIAG_R 1` 缺失的序号。

## 失败时收集

- `pair.txt`；
- 差值最大的那一轮两个 lane 的 `.srv` 与 `.cli`：`DEAD`、`HEALTH`、`STATS` 行，以及末尾 50 行；
- 该轮的 tc 丢包（`cmp_ana.py` 的 `loss` 列）。
