---
id: RN-01
title: 两个版本部署到测试主机，并各跑一轮短冒烟
kind: agent
where: 本批次用到的全部主机
automation: tools/realnet/deploy.py、churn_round.py deploy、cmp_round.py（--dur 120）
duration: 10 分钟
last_run: 2026-10-08 通过（候选 3353b9d 对基线 44a963c；g5→t1 5% 两个 lane 端到端丢包 4.8%；出口实测 g5 约 10、t1 约 14、rb 约 16 Mbit）
---

# RN-01 部署与冒烟

## 目的

在占用几个小时的实网时间之前，先确认三件事：

- 两个版本能在各主机上编译；
- 测试工具的输出能被分析脚本读懂；
- tc 整形与丢包能匹配到流量。

## 前置

- 每台主机都满足：`ssh -o ConnectTimeout=10 <主机> true` 成功；
- 每个发送端都满足：`ssh <发送端> sudo -n /usr/sbin/tc qdisc show` 成功；
- 基线与候选都是提交，不是工作区；
- 做 RN-03 时，每台主机上要有 `base/anliu-realnet/srt/srtnet`。

## 步骤

1. 建立批次目录并设置环境变量，见 [03-realnet.md](03-realnet.md)。
2. 部署两个媒体变体和两个 churn 变体（`--tools-from-rev`），在本批次用到的每台主机上都部署：
   ```sh
   python3 $R/deploy.py base <基线> --tools-from-rev g5 t1 rb hz
   python3 $R/deploy.py cand <候选> --tools-from-rev g5 t1 rb hz
   python3 $R/churn_round.py deploy cbase <基线> --tools-from-rev g5 t1 rb
   python3 $R/churn_round.py deploy ccand <候选> --tools-from-rev g5 t1 rb
   ```
3. 媒体冒烟，120 s：
   ```sh
   python3 $R/srt/cmp_round.py g5 t1 2000 5 901 9960 --anl base --protos anl-nf,anl-nf@cand --dur 120 --drive-check
   ```
4. churn 冒烟，120 s：
   ```sh
   python3 $R/churn_round.py run g5 rb ccand 901 9850 --loss 5 --dur 120
   ```
5. 运行 `python3 $R/srt/cmp_ana.py` 和 `cd $R && python3 churn_ana.py`。确认每个 lane 都有完整的一行，并且 tc 丢包接近 5%。
6. 测每个发送端的出口容量：`python3 $R/capacity_probe.py <发送端> <接收端> 9940 2,4,8,12,16 8`。按"第一个出现丢包的速率 − 5 Mbit"安排本批次各主机同时运行的 lane 数，见 [03-realnet.md](03-realnet.md) 的"出口容量"一节。

## 通过规则

- 每个部署命令对每台主机都输出 `<主机>: ok <哈希>`，没有 `HASH MISMATCH`；
- 第 3 步的末行以 `True` 结尾，并且 `cmp_ana.py` 对 `anl-nf` 与 `anl-nf@cand` 都给出音频、视频、关键帧和 wire 数值；
- 第 4 步输出 `CHURN_DONE ... True`，两端都有 `HEALTH state=0 errors=0 ok=1`；
- 实测的 tc 丢包（`cmp_ana.py` 的 `loss` 列、`churn_ana.py` 的 `tc` 列）在 3.5..6.5% 之间；
- 第 3 步两个 lane 的端到端丢包，即 `.srv` 的 `DATAGRAM_COST tx_packets` 与 `.cli` 的 `rx_packets` 之差，在 3.5..6.5% 之间；
- 第 6 步给出了每个发送端的容量。批次计划中每台主机同时运行的 lane 限速合计，不超过"容量 − 5 Mbit"。

## 失败时收集

- 部署命令的完整输出；
- `results/` 中该轮次的 `.json`，以及 `.srv`、`.cli` 的末尾 50 行。
