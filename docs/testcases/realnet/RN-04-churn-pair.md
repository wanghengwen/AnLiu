---
id: RN-04
title: 流的打开与关闭，在真实路径上成对对照
kind: agent
where: 中 RTT 广域网（t1→rb、rb→t1；曾用 g5→rb）
automation: tools/realnet/churn_round.py run 跑轮次，churn_ana.py 汇总，判定按本文
duration: 约 1 小时（每轮 600 s，两条路径 × 两个版本同时运行）
last_run: 2026-10-08 通过（3353b9d 对 44a963c，t1→rb 与 rb→t1，16 轮全部有效；约 32.4 万次打开、32.8 万次关闭全部确认，被拒绝 0，完整性错误 0，无 DEAD；关闭确认 p99 两版相同）
---

# RN-04 流的打开与关闭（churn）

## 目的

检验以下几方面在丢包和长 RTT 下没有回归：

- 流的生命周期：打开、CLOSE 一直重发到收到 RST、sid 记录表、保留期；
- 数据完整性；
- 连接存活：dead_link、RACK 退避。

`bench/churn.c` 的两端各自保持最多 31 个本端打开的流，按六种方式不停地开关：

- 可靠流全部确认后关闭；
- 半可靠流随时关闭；
- 可靠流带着在途数据关闭；
- 接收方关闭；
- 两端几乎同时关闭；
- 打开后立即关闭。

每一轮约打开 2 万个流。

## 前置

- RN-01 已通过（`cbase` / `ccand` 已部署）；
- 带宽：每轮实际约 2.4 Mbit 每方向，`--rate 4000` 是上限。每个发送端两个轮次按 8 Mbit 计入预算（见 [README.md](README.md) 的"出口容量"一节）；两条路径都用到的主机，按两个方向分别计算。

## 步骤

1. 批次脚本（参考 `anliu-realnet-work/churn-rack-20261008/batch.sh`）：

   ```sh
   one() {   # VARIANT SERVER CLIENT PORT SEED LOSS [EXTRA]
     out=$(timeout 1200 python3 $R/churn_round.py run $2 $3 $1 $5 $4 --loss $6 --rate 4000 $7 2>&1 </dev/null | tail -1)
     echo "$(date '+%F %T') [$1 $2>$3 loss $6 $7] $out"
   }
   for l in 3 5 10 "10 --delay 100"; do
     set -- $l; L=$1; X="${*:2}"
     one cbase rb t1 9870 7 $L "$X" & sleep 5
     one ccand rb t1 9872 7 $L "$X" & sleep 5
     one cbase t1 rb 9874 6 $L "$X" & sleep 5
     one ccand t1 rb 9876 6 $L "$X" & wait
   done; echo ALLDONE
   ```

2. 等到 `ALLDONE`，然后运行 `cd $R && python3 churn_ana.py`。

## 通过规则

- 有效轮次 ≥ 14 / 16；候选的每一个无效轮次都要有可归因的原因（例如 tc 计数为 0、主机故障），并且与它同时运行的基线轮次不是有效的。
- 候选的每个有效轮次，两端都满足：
  - `HEALTH errors=0 ok=1 state=0`；
  - `CHURN_FINAL ok=1`：只剩默认流，没有待确认的关闭；
  - `CHURN_READ` 中的 `order_errors=0`、`pattern_errors=0`、`gen_errors=0`、`graceful_short=0`；
  - 被拒绝的打开为 0；
  - `CHURN_NET` 中的 `input_errors=0`；
  - 没有 `DEAD` 行。
- 关闭确认时间的 p99：候选不超过同一路径、同一时间基线的 1.5 倍加 100 ms。
- 每轮的打开数：候选不低于同时运行的基线的 90%。

## 基准

2026-10-08（`reg-20261008`，`--rate 4000`，基线 / 候选）：

- 每轮的打开数：两版各约 2.1 万次（10% 加 +100 ms 时约 1.87 万次）；
- 关闭确认 p99（ms）：

  | 丢包 | t1→rb | rb→t1 |
  |---|---|---|
  | 3% | 239 / 239 | 241 / 238 |
  | 5% | 510 / 512 | 507 / 507 |
  | 10% | 520 / 539 | 541 / 515 |
  | 10% +100 ms | 942 / 953 | 970 / 955 |

- 候选的 `max_sid` 等于打开次数（sid 不复用），基线约 160..170。

- `churn-rack-20261008`（`44a963c` 的前一版与 `ff3a786` 成对，5 / 7 / 10%，12 轮）：
  - 全部有效，约 24.9 万次打开，关闭全部确认；
  - 关闭确认 p99 为 0.25..0.54 s；
  - 每端每轮约 1 万次打开。
- `churn-20261007`：p99 在 3% 时约 0.45 s，5% 时约 0.9 s，+100 ms 时 1.3 s，15% 时 1.9..2.7 s。

## 失败时收集

- 失败轮次两端的 `CHURN_*`、`HEALTH`、`DEAD` 行；
- `DEAD_REASON` 行，以及 `.srv` / `.cli` 的末尾 50 行；
- 该轮的 `tc_loss`。
