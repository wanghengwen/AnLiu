# AnLiu vs ikcp 对照测试

`bench.c` 在模拟网络上同条件运行 AnLiu 和 ikcp（`ikcp.c/h` 取自 github.com/skywind3000/kcp master，MIT 许可，见 `LICENSE-ikcp`），统计实际占用带宽、到达率、及时率、延迟分位数，并自动检查正确性与异常行为。

## 构建与运行

```sh
make
./anl_bench                          # s1..s5 + crypto，默认矩阵（约 10 分钟）
./anl_bench --quick                  # 缩小矩阵
./anl_bench s3 --loss 10 --rtt 200 --dur 120
./anl_bench soak --soak 3600         # 1 小时变网络环境长稳测试
./anl_bench --profile default        # 使用两者的默认参数（开启拥塞控制）
./anl_bench --csv out.csv            # 全部指标写入 CSV
./anl_bench s1 --bw 0 --wnd 4096     # 不限带宽，批量流窗口 4096
./anl_bench --quick --fec-ratio 15   # FEC 冗余率（默认 25）
./anl_bench bwstep                   # 瓶颈 8/2/5/1/8 Mbps 阶梯：带宽估计、利用率、时延（--step 秒，--step-loss %）
BENCH_CC=100 ./anl_bench soak        # 把 AnLiu 的拥塞控制状态打印到 stderr：soak、bwstep 每 BENCH_CC ms 一行，s1~s5 固定每 500 ms 一行
BENCH_DEBUG=1 ./anl_bench ...        # 打印损坏消息的细节
```

其他选项（`./anl_bench` 不带参数打印完整用法）：`all`（s1~s5、soak、crypto 全跑）；`--bulk MB`（s1 的数据量）；`--init-cwnd N`；`--fec-auto`（FEC 流用 `ANL_FEC_RTT_AUTO`，覆盖 `--fec-ratio`）；`--rcv-deadline MS`（半可靠流的缺口等待，-1 为本地期限，0 关闭）；`--qdelay MS`（瓶颈缓冲深度，默认 100，很小时近似限速器）；`--policer KBPS` / `--pbucket KB`（瓶颈前的令牌桶限速器及其桶深，只丢不排队）；`--tbf KB`（瓶颈为该突发量的令牌桶整形器，0 为普通 FIFO）；`--step-rtt MS`（bwstep 的路径 RTT）；`--abr` / `--nobulk`（bwstep 不带批量流，视频码率跟随 `target_rate` / 固定）；`--phase S` / `--sample S`（soak 的阶段长度与采样周期）。环境变量：`SIM_VIDEO_LATENCY`（视频预算 L ms，max_age 取 L + 200）、`SIM_VIDEO_FEC_DEADLINE`（drop_until_key 视频流的 `fec_deadline_ms`）、`SIM_VIDEO_LATENCY_RTT`（它的 `latency_rtt`）。

对照组不使用 anliu 的内部符号，只调用公开 API；`test.c` 仍负责功能正确性，本程序负责性能与长稳。

## 模拟网络

虚拟时钟 1 ms 步进，结果可由 `--seed` 完全复现（AnLiu 的随机填充也用由种子派生的 PRNG；此前的版本用系统熵，同一种子两次运行略有差异）。每个方向独立：

| 参数 | 说明 |
|---|---|
| 随机丢包 / 突发丢包 | `--loss`；突发丢包为两状态模型，平均突发长度 `--burst`；状态每个包推进一步，空闲时每毫秒也推进一步（突发持续的是一段时间，不是若干个包） |
| RTT / 抖动 | `--rtt`；抖动行 `--jitter`（单向时延的百分比，允许乱序） |
| 路径 RTT 切换 | `--rttshift MS`（s1~s5）：每个方向各自随机地在"加 MS 单向时延"与不加之间切换，平均停留 `--rttshift-ms`（默认 1500）；RTT 在 rtt、rtt+MS、rtt+2MS 之间移动而没有队列（跨境路径换路由）。`s3 --av`：音频（prio 0）+ 视频（prio 1）同一连接、无批量流 |
| 瓶颈带宽 | `--bw`（s1~s4，默认 20 Mbps）/ `--bw5`（s5，默认 5 Mbps），队列 100 ms，满则尾丢弃 |

带宽统计包含每包 28 字节 IP/UDP 头。

## 场景

| 场景 | 流量 | 对照组 |
|---|---|---|
| s1 | 可靠批量 4 MB | anl / kcp |
| s2 | 可靠交互 200 B / 20 ms | anl / kcp |
| s3 | 视频 30 fps，I 帧 25~35 KB，P 帧 2.5~3.5 KB，max_age 500 | anl / anl+fec / kcp / kcp+drop |
| s4 | 音频 160 B / 20 ms，max_age 200 | 同上 |
| s5 | 音频 + 视频 + 饱和批量流，5 Mbps 瓶颈 | 同上（kcp 每条流一个 conv） |
| soak | 音频 + 视频 + 交互 + 250 KB/s 批量；每 60 s 切换网络阶段（良好 / 5% / 突发 / 15% / 2 Mbps / 5 s 断网 / 高 RTT）；时钟从回绕前 30 s 开始 | anl+fec / kcp+drop |
| bwstep | 音频 + 视频 + 批量，瓶颈每 10 s 切换 8 → 2 → 5 → 1 → 8 Mbps；每阶段报告带宽估计 / 实际、利用率、音视频时延 | anl / anl+fec / kcp |
| crypto | 真实时钟下每个数据报的 input 开销（合法包 / 伪造包） | anl / kcp |

`kcp+drop` 是在 ikcp 之上加的应用层丢帧策略：尚未发出的积压（`kcp->nsnd_que`）超过 max_age 对应的数据量时不再提交新帧（音频 10 帧，视频约 0.5 s，视频按关键帧恢复）；已交给 ikcp 的数据仍全部可靠送达。v5 之前的结果用的是 `ikcp_waitsnd`（含已发未确认），在高 RTT 下会在无拥塞时误丢帧。它只代表一种常见做法，不是 ikcp 本身的能力。

## 输出列

`dlv%` 到达数/产生数；`ontm%` 在 单向时延 + 抖动 + 预算 内到达的比例；`p50..max` 端到端延迟（ms）；`up`/`dn` 两个方向的线上带宽（kbps）；`cost` 两个方向线上字节 / 有效交付字节；`sdrop` 发送端丢帧；`adrop` 应用层丢帧；`skip` 接收端跳帧；`fec` FEC 恢复数。

## 自动检查

- **ERROR**（返回码非 0）：内容损坏、乱序、可靠流缺口、frame_no 与发送序号不符、`lost_before` 统计不闭合、释放连接后内存未归零。
- **WARN**：连接 dead、可靠流停滞超过 5 s、批量流未在时限内完成、srtt 偏离真实 RTT、峰值内存过大、断网恢复慢、0% 丢包下半可靠流未全部到达、开了 FEC 却没有恢复任何数据。
