# 实网用例的环境与参数

这些用例在真实的广域网和机房主机上执行。执行前先读：

- [../README.md](../README.md) 中的代理执行规则；
- [tools/realnet/README.md](../../../tools/realnet/README.md)。

**仓库里不包含任何主机地址或账号。** 主机表放在仓库之外，由 `ANL_REALNET_HOSTS` 指定，用例中只用表中的主机名。

## 环境变量

```sh
export ANL_REALNET_HOSTS=~/workspace/anliu-realnet-work/realnet-hosts.json   # 主机表（仓库外）
export ANL_REALNET_WORK=~/workspace/anliu-realnet-work/<批次名>              # 本批次：变体、results/、events.jsonl
R=~/workspace/AnLiu_github/tools/realnet
```

批次名写成"用途-日期"，例如 `reg-20261008`。每个批次的 `batch.sh` 放在它自己的工作目录中，用来记录这一批次实际执行的命令。

## 主机与路径

主机表每一项有以下字段：

- `cap_kbps`：可用带宽；
- `slots`：同时运行的进程数上限；
- `pool`：同一台机器上的主机共用一个 pool；
- `shape`：能否 `sudo -n tc`。只有能整形的主机可以做发送端。

用例按路径的类别写，执行时从表中选择当时可达、而且出口容量够用的主机：

| 类别 | RTT | 用途 | 例（主机表中的名字） |
|---|---|---|---|
| 低 RTT | ≈1 ms | 加 tc 时延做受控时延（RN-02） | t1→g5、g5→t1（曾用 zjg→t1，zjg 已于 2026-10-09 下线） |
| 内网 | <1 ms | 约 90 Mbit，做瓶颈与闭环（RN-05） | F→G（G 为 macOS 客户端；F 只能被 G 访问） |
| 中 RTT 广域网 | ≈99 ms | RN-03、RN-04 | rb→t1、t1→rb、g5→rb |
| 长 RTT 广域网 | ≈167 ms | RN-03 | g5→hz |

注意以下几点：

- hz 不能整形，只能做接收端；
- F 在内网里，公网上的主机连不到它，因此 F 只能和 G 配对；
- G 在 NAT 之后，churn 用 G 做客户端时，tc 过滤器匹配不到它的数据报（`churn_round.py` 会判为无效）。

执行前测一次 RTT：

```sh
ssh <发送端> ping -c 10 -q <接收端的 ip>
```

有的主机不回 ICMP，这时以 `cmp_round.py` 记录的 `rtt_min_ms` 为准。

### 出口容量（每个批次之前）

主机表中的 `cap_kbps` 可能已经过时。2026-10-08 的实测：

- g5：标称 30 Mbit，实际约 10 Mbit 以上就丢包，16 Mbit 时全部丢失；
- t1：约 14 Mbit；
- rb：约 16 Mbit。

2026-10-09 的复测（主机空闲，`capacity_probe.py`，接收端用其防火墙放行的端口）：

- t1、rb 的出口约 30 Mbit（30 Mbit 不丢，35 Mbit 丢约 5%），g5 约 10 Mbit（12 Mbit 丢 8%，14 Mbit 丢 22%）。前一天 t1 只测到 14 Mbit，应是测量受了干扰。
- 这几台的线速都是 1 Gbit，限速由云平台的令牌桶完成（超出即丢、不排队）。突发（`burst_probe.py`，空闲 3 s 后线速发出）：128 KB 每次都全部通过；256 KB..1 MB 多数时候全部通过，有时只通过 120..380 KB，桶的大小不稳定。曾有一次 t1→rb 的 512 KB 突发之后连续几秒全部丢失，复测没有再出现。

2026-10-09 的实测：F→G 约 90 Mbit（80 Mbit 不丢，120 Mbit 丢 19%），不是主机表原来写的 1 Gbit。当天 6 个 30 Mbit 令牌桶的轮次同时运行（编码器约 18 Mbit/路），tc 和 TBF 之外多丢约 5%，整批无效。主机表中 G 的 `cap_kbps` 已改为 90000，调度器因此一次只跑一对。

当天 g5 同时发送约 14 Mbit，tc 之外多出约 20% 的丢包，两个版本连同 SRT 的视频准时率都降到 20..90%，整批无效。

因此每个批次之前，在主机空闲时测一次每个发送端的出口：

```sh
python3 $R/capacity_probe.py <发送端> <接收端> <端口> 2,4,8,12,16 8
```

- 以第一个出现丢包的速率作为容量，预算为"容量 − 5 Mbit"；
- 限速器的桶用 `python3 $R/burst_probe.py <发送端> <接收端> <端口> 64,128,256,512,1024 3` 测，每个大小重复几次（结果波动大）；
- 测量要逐级升速：超出限速很多时，云平台可能会暂时丢掉全部数据报。

每一轮中，还要用两端的数据报计数核对实际丢包：发送端 `.srv` 的 `DATAGRAM_COST tx_packets` 与接收端 `.cli` 的 `rx_packets` 之差，应当接近 tc 设定的丢包率（相差不超过 2 个百分点）。差得多的轮次，说明路径或出口另有丢包，该轮无效。

## 版本（变体）

一个变体是部署到各主机的一份"库加测试工具"，目录在 `ANL_REALNET_WORK/<变体>` 与远端的 `base/anliu-realnet/<变体>`。

```sh
python3 $R/deploy.py base <基线提交> --tools-from-rev <主机...>      # 媒体（realnet_trace）
python3 $R/deploy.py cand HEAD --tools-from-rev <主机...>
python3 $R/churn_round.py deploy cbase <基线提交> --tools-from-rev <主机...>   # 流的开关（churn）
python3 $R/churn_round.py deploy ccand HEAD --tools-from-rev <主机...>
```

- `realnet.c` 和 `churn.c` 直接包含 `anliu.c`，会读内部字段。库的内部结构变了以后（例如 `lt_*` 字段收进 `lt` 结构），新工具无法用旧库编译。因此对照时两个版本都用 `--tools-from-rev`，各用自己版本的测试工具。
- 两个版本工具的输出行（`MDIAG_*`、`HEALTH`、`CHURN_*`）要一致。不一致时先改分析脚本，再运行。
- 部署输出每台主机一行 `ok <哈希>`。出现 `HASH MISMATCH` 或编译错误时判为"阻塞"。
- 不能在旧提交上用 `WORKTREE` 部署候选：工作区的内容不可复现。候选必须是一个提交。

## 有效轮次

| 工具 | 有效条件 |
|---|---|
| `cmp_round.py` | 末行 `... True`：两端正常退出，运行时长完整，末尾 HEALTH 正常，发送端音视频序号完整，有接收记录和 tc 字节计数 |
| `multi_round.py` | `MULTI_DONE True`；用 tc 丢包时，tc 计数不为 0 |
| `churn_round.py` | `CHURN_DONE <tag> True`：两端 `HEALTH errors=0 ok=1 state=0`，tc 频段计数不为 0 |

无效轮次重跑一次（`cmp_round.py` 的批次脚本按两次尝试写）。

## 批次脚本的写法

参考以往批次（`anliu-realnet-work/*/batch.sh`）：

- 每条"链"串行运行一组轮次，各链之间并行；
- 各链的端口段不同；
- 链之间间隔 20 s 启动；
- 同一条链内，种子为奇数和偶数时交换两个版本 lane 的顺序（端口随之交换）；
- 输出写到 `lane.log`，最后打印 `ALLDONE`；
- 在后台运行：`nohup bash batch.sh > lane.log 2>&1 &`。

## 分析

| 用途 | 命令 |
|---|---|
| 每轮每个 lane 的明细 | `python3 $R/srt/cmp_ana.py` |
| 两个 AnLiu lane 的成对差值与限值判定 | `cd $R/srt && python3 cmp_pair.py anl-nf anl-nf@cand --limits` |
| 流的开关 | `cd $R && python3 churn_ana.py` |
| `multi_round.py` 的轮次 | `results/*.json` 的 `metrics` |
| 两个 `multi_round.py` lane 的成对差值 | `cd $R && python3 multi_pair.py base+nf cand+nf`：tc 和 TBF 之外的丢包超过发送数 2% 的轮次判为 SKIP |

## 清理

每个轮次在结束时清除自己的 tc 频段，看门狗（deadman）会在超时后兜底清理。批次结束后在每个发送端检查：

```sh
tc filter show dev <dev> | grep -c u32      # 与批次开始前相同
pgrep -fa 'realnet_trace|srtnet|bench/churn'   # 没有本批次留下的进程
```

工作目录中的 `events.jsonl` 含有地址，留在仓库之外，不要复制进仓库。
