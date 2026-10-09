---
id: RN-06
title: 开启自动 FEC 的媒体成对对照
kind: agent
where: 低 RTT 路径（g5→t1）加 tc 时延 +100 / +200 ms
automation: cmp_round.py 跑轮次（lane anl、anl@cand）；判定用 cmp_pair.py anl anl@cand --limits 加本文规则
duration: 约 1.5 小时
last_run: 2026-10-08 通过（fecon-20261008，3353b9d + TS_AHEAD_MAX 修复 对 44a963c，t1→g5 +100/+200、rb→t1、g5→hz，28 对，`LIMITS OK`；音频 −0.10、视频 −0.13、可解码 −0.13、关键帧 −0.20 个百分点，线上带宽 +0.44%，区间都含 0）
---

# RN-06 自动 FEC（只在改动 FEC 时做）

2026-10-06 起，性能测试只覆盖关闭 FEC 的情况，开启 FEC 的表现视为已经验证。只有改动 FEC 的代码时才做本用例：

- 块的划分、校验包的配置；
- 自适应冗余的门；
- 丢失估计；
- FEC 缓存（DESIGN 8.7）。

## 步骤

与 RN-02 相同，只有下面几点不同（2026-10-08 起还加上 RN-03 的两条广域网路径，每条 lane 为 anl 与 anl@cand）：

- `A=anl,anl@cand`，`B=anl@cand,anl`；
- 丢包 3、5（两个种子）、7、10、15。

## 通过规则

- 有效轮次 ≥ 12 / 14；
- `cmp_pair.py anl anl@cand --limits` 末行为 `LIMITS OK`；
- 只看 FEC 的开销：线上带宽的均值差不超过 +3%。如果改动本来就是为了降低开销，在报告中给出各场景的节省比例。

## 基准

`fecopt-20261006`，+100 ms：

- 线上带宽：3 / 5% 丢包时 −10.4 / −13.3%，7..15% 时 −1.4..−3.1%；
- +200 ms 时 −0.5..−2.5%；
- 音视频与关键帧持平。
