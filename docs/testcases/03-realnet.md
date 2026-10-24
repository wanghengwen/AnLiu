# 实网用例的环境与参数

实网用例（本目录的 `RN-*.md`）在真实的广域网和机房主机上执行。执行前先读：

- [../TESTING.md](../TESTING.md) 中的代理执行规则；
- [tools/realnet/README.md](../../tools/realnet/README.md)。

**仓库里不包含任何主机地址或账号。** 主机表放在仓库之外，由 `ANL_REALNET_HOSTS` 指定，用例中只用表中的主机名。

## 环境变量

```sh
export ANL_REALNET_HOSTS=~/workspace/anliu-realnet-work/realnet-hosts.json   # 主机表（仓库外）
export ANL_REALNET_WORK=~/workspace/anliu-realnet-work/<批次名>              # 本批次：变体、results/、events.jsonl
R=~/workspace/AnLiu_github/tools/realnet
```

批次名写成"用途-日期"，例如 `reg-20261008`。每个批次的 `batch.sh` 放在它自己的工作目录中，用来记录这一批次实际执行的命令。

## 主机与路径

主机表每一项有以下字段（`ssh`、`ip`、`base`、`dev` 见 [tools/realnet/README.md](../../tools/realnet/README.md)）：

- `cap_kbps`：可用带宽，默认 30000；
- `slots`：同一个 pool 同时运行的进程数上限（取 pool 内的最大值），默认 3；
- `pool`：同一台机器上的主机共用一个 pool，默认为主机名；
- `port_base`：调度器（`multi_sched_pair.py`）给该发送端分配端口的起点，默认 9900；
- `shape`：能否 `sudo -n tc`。只有能整形的主机可以做发送端。

用例按路径的类别写，执行时从表中选择当时可达、而且出口容量够用的主机：

| 类别 | RTT | 用途 | 例（主机表中的名字，2026-10-24） |
|---|---|---|---|
| 低 RTT | ≈1 ms | 加 tc 时延做受控时延（RN-02、RN-06），瓶颈闭环（RN-05） | g5→lsj、lsj→g5、t1→lsj（t1、g5、lsj 在同一机房） |
| 内网 | <1 ms | 约 90 Mbit，做瓶颈与闭环（RN-05） | F→G（G 为 macOS 客户端；F 只能被 G 访问） |
| 中 RTT 广域网 | ≈150 ms | RN-03、RN-06、RN-04 | s_ld→t1；RN-04 用 g5⇄n2、lsj⇄n1（n1、n2 只做客户端） |
| 长 RTT 广域网 | ≈185 ms | RN-03、RN-06 | t1→hz |

各主机的限制：

| 主机 | 出口 | 限制 |
|---|---|---|
| t1 | 约 30 Mbit 令牌桶 | 1 核、960 MB 内存；运行着维护者的服务（npf、postgres），UDP 9910 / 9911 / 9920 已占用，只接受 99xx 的 UDP |
| g5 | 约 10 Mbit 令牌桶 | 1 核、960 MB；npf 占用 UDP 9910 / 9911 / 9920 |
| lsj | 约 11.6 Mbit，桶约 1.2 MB | 1 核、960 MB；和 n1 之间双向都不通 ICMP（`cmp_round.py` 要 ping，lsj→n1 不能跑媒体轮次，churn 可以） |
| s_ld | 至少 8 Mbit | 1 核、960 MB；不回 ICMP（ping 只能从 s_ld 发出） |
| hz | — | 不能整形，只能做接收端 |
| n1、n2 | — | 借用的生产主机：防火墙只放行 TCP 22 / 80 / 443 和 UDP 9910 / 9911 / 9920（被服务占用），因此只能做接收端或 churn 客户端。主机表的 `base` 写 `../../tmp`，部署在 `/tmp/anliu-realnet`；用完必须清理，见"借用主机的部署与清理" |
| F、G | 约 90 Mbit | F 只能和 G 配对；G 在 NAT 之后，churn 用 G 做客户端时 tc 过滤器匹配不到它的数据报 |

已下线：zjg（2026-10-09）、rb（2026-10-24）。

执行前测一次 RTT：

```sh
ssh <发送端> ping -c 10 -q <接收端的 ip>
```

`cmp_round.py` 记录的 `rtt_min_ms` 也是 ping 得到的（接收端到发送端、再反过来各试一次，都不通时轮次中止）；完全不回 ICMP 的路径看 `.cli` 日志里 realnet 自己测的 `PATH ping rtt_min=`。

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

每一轮中，还要用两端的数据报计数核对实际丢包：发送端 `.srv` 的 `DATAGRAM_COST tx_packets` 与接收端 `.cli` 的 `rx_packets` 之差，应当接近 tc 设定的丢包率（相差不超过 2 个百分点）。差得多的轮次，说明路径或出口另有丢包：`cmp_pair.py` 自动跳过高出 tc 设定 2 个百分点以上的轮次（低于设定的不跳过），`multi_pair.py` 跳过"tc 与 TBF 之外的丢包超过发送数 2%"的轮次。

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
| `churn_round.py` | `CHURN_DONE <tag> True ...`（后面还有错误字段，不能按 `True$` 匹配）：两端 `HEALTH state=0 errors=0 ok=1`，`--loss > 0` 时 tc 频段计数不为 0 |

无效轮次重跑一次（`cmp_round.py` 的批次脚本按两次尝试写）。

## 批次脚本的写法

用 [tools/realnet/regress/lib.sh](../../tools/realnet/regress/lib.sh) 里的函数写批次脚本：
- `pairchain`：RN-02 / RN-06 的一条链；
- `rn03`：RN-03 的一条链，带 SRT 参考 lane；
- `rn04`：RN-04 的一条链；
- `one` / `churn`：单个轮次，带重试，每次尝试前用 `waitnet` 等两端可达。

[waves.example.sh](../../tools/realnet/regress/waves.example.sh) 是 2026-10-24 那次完整回归的布局，复制到批次目录后按当时的主机修改。规则：

- **每个发送端同时只跑一条链**，各发送端的链并行。不要把所有链都压在一台主机上：2026-10-24 第一版布局把 4 条链和 RN-05 都放在 t1（约 15 Mbit、12 个 lane），带宽与 CPU 都会干扰测量，t1 还因内存耗尽卡住约 2.5 分钟，该批作废重跑。
- 各链的端口段不同；链之间间隔约 45 s 启动。
- 同一条链内，种子为奇数和偶数时交换两个版本 lane 的顺序（端口随之交换）。
- 每条链写自己的 `chain-*.log`，一批结束时打印 `WAVE*_DONE`。下一批用 `until grep -q WAVEA_DONE waveA.log` 等前一批结束，或者像示例那样写在同一个脚本里。
- 在后台运行：`nohup bash waveA.sh > waveA.log 2>&1 &`。
- 正在运行的 bash 脚本不要修改：bash 边执行边读文件，已经 `source` 的函数也不会更新。要改就先停掉，再重新启动。
- 测试工具（`tools/realnet/*.py`）每轮重新加载。批次运行中修改工具，会影响此后启动的所有轮次；先在副本上测好（见"修改工具后的验证"）再放回。

## 分析

| 用途 | 命令 |
|---|---|
| 每轮每个 lane 的明细 | `python3 $R/srt/cmp_ana.py` |
| 两个 AnLiu lane 的成对差值与限值判定 | `cd $R/srt && python3 cmp_pair.py anl-nf anl-nf@cand --limits` |
| 同上，自动 FEC（RN-06） | `cd $R/srt && python3 cmp_pair.py anl anl@cand --limits` |
| 流的开关 | `cd $R && python3 churn_ana.py` |
| `multi_round.py` 的轮次 | `results/*.json` 的 `metrics` |
| 两个 `multi_round.py` lane 的成对差值 | `cd $R && python3 multi_pair.py base+nf cand+nf`：tc 和 TBF 之外的丢包超过发送数 2% 的轮次判为 SKIP |

## 清理

轮次启动后就在主机上独立运行，不依赖本机的连接：
- 每个频段的看门狗（deadman）在发送端进程退出、写出 `.rc` 后，读出 TBF 与丢包计数（`QDISC_STATS`、`LOSS_STATS`），写进该轮次的 `logs/<tag>[.<lane>].deadman`，并清除这个频段；没有 `.rc` 时，到 `--hold` 超时也会清除。
- 远端进程都有超时，本机不回来也会自己结束。
- 客户端启动后，本机的 ssh 遇到连接错误会一直重试，最多等 1 小时。连接恢复后，再取回日志和看门狗的计数，判定这一轮是否有效。
- 批次脚本在每次尝试前先等两端主机可达，本机断网不会用掉重试次数。

批次结束后在每个发送端检查：

```sh
tc filter show dev <dev> | grep -c u32      # 与批次开始前相同
pgrep -fa 'realnet_trace|srtnet|bench/churn'   # 没有本批次留下的进程
```

工作目录中的 `events.jsonl` 含有地址，留在仓库之外，不要复制进仓库。

## 完整回归的执行流程

2026-10-24 那次完整回归（RN-01 .. RN-06，约 5 小时）的实际步骤。下次照着做，按当时可用的主机调整。

1. **单机部分先通过**（[../TESTING.md](../TESTING.md) 的"版本回归"第一步）。候选必须是一个提交。
2. **建批次目录**：`~/workspace/anliu-realnet-work/reg-<日期>/`。
   - 从上一批复制 `hosts-batch.json`（主机表）和 `rn05.jsonl`（RN-05 的 16 个任务）。
   - 先确认每台主机都能 ssh 登录，下线的主机从表中去掉。
3. **测出口容量**：每个发送端测一次（见"出口容量"一节），结果写进批次目录的 `capacity.txt`。按"容量 − 5 Mbit"核对布局：
   - 每个 lane 约 1.1 Mbit（自动 FEC 约 1.3–1.5 Mbit）；
   - churn 每轮每个方向约 2.3 Mbit；
   - RN-05 每个 lane 最多 2 Mbit。
4. **部署**（RN-01）：`deploy.py base|cand` 和 `churn_round.py deploy cbase|ccand`，都加 `--tools-from-rev`。另外用 `srt/deploy_srt.py <srtnet>` 部署 srtnet。
   - 本批次用到的每台主机都要部署，包括只做接收端的主机。
   - 每台主机一行 `ok <哈希>`，两个版本在所有主机上的哈希必须一致。
5. **冒烟**（RN-01，120 s）：一条低 RTT、一条广域网媒体轮次，加一个 churn 轮次。冒烟结果放进批次目录的 `smoke/`，不参与对比。
6. **写批次脚本并在后台运行**：见"批次脚本的写法"。2026-10-24 用了三批：
   - A：RN-02 + RN-03，约 80 分钟；
   - B：RN-06，约 80 分钟；
   - C：RN-05 + RN-04，约 90 分钟。
7. **运行中每 30 分钟检查一次**：
   - `chain-*.log` 中非 `True` 的行，以及 `sched-*/sched.log` 中的 `ok=False`；
   - 每个发送端的可用内存（`free -m`）；
   - deadman 进程数（`pgrep -fc '[m]ulti_tc.py deadman'`），应当等于该主机上正在运行的频段数，不应积压。
8. **分析**：见"分析"一节。
   - `cmp_pair.py ... --limits` 要输出 `LIMITS OK`。
   - RN-04 按 RN-04-churn-pair.md 的规则逐对检查打开数与 p99。
   - 检查所有 `.srv` / `.cli` 中没有 `DEAD` 行。
   - 某一对差异明显、但仍在规则内的，先用 TRACE（`srtt`、`target`）和两端的数据报计数，分清是路径问题还是版本问题；需要时在该场景加种子再跑。
9. **与上一次回归对比**：
   - 成对差值：对比上一批的 `cmp_pair.py` / `multi_pair.py` / `churn_ana.py` 输出，以及 PROGRESS.md 中的记录。
   - 同类场景的绝对值：对比两批的 `cmp_ana.py` 汇总表。
   - 同一路径绝对值变差时，先核对端到端丢包和 RTT：路径本身可能多丢包。2026-10-24 的 t1→hz 就多丢了 0.3–2.2 个百分点，RTT 也高了 2–16 ms。
10. **清理**：见"清理"与"借用主机的部署与清理"。每台主机都要查 tc、进程和 deadman 状态文件。
11. **报告与记录**：
    - 中文报告，表格列为"编号 / 结果 / 实测值 / 证据"。
    - 更新各 `RN-*.md` 的 `last_run`。
    - PROGRESS.md 只写"做了版本回归"和测试总结。

## 借用主机的部署与清理

维护者临时借给测试的主机（2026-10-24 的 n1、n2）：

- 部署到 `/tmp`：主机表的 `base` 写 `../../tmp`（工具在 `$HOME/<base>/anliu-realnet` 下工作）。
- 不修改它们的防火墙，只用作接收端或客户端。
- 需要装编译器时，装之前先保存包列表：`dpkg-query -W -f='${Package}\n' | sort > /tmp/anl-pkgs-before.txt`。装完再存一份 after，两者之差写进 `/tmp/anl-pkgs-new.txt`，本地也留一份。
- 测试结束后：
  1. 先模拟卸载（`apt-get -s purge $(cat /tmp/anl-pkgs-new.txt)`），确认要删的包正好是清单里的，不会连带删掉别的包；
  2. 再执行卸载，然后核对包列表与 before 完全相同；
  3. 删除 `/tmp/anliu-realnet`、`/tmp/anl-*`、`~/.anliu-multi-tc.*`；
  4. 确认 tc 是原来的根队列，没有 ingress 过滤器，也没有残留进程。

## 修改工具后的验证

修改 `tools/realnet/` 下影响轮次流程的代码（启动、收尾、tc）后，先在副本上测，再放回仓库：

- 把 `tools/realnet` 复制到 scratch 目录，另建一个工作目录：把 `base`、`cand` 等变体目录用符号链接接进来，`results/` 用空目录。
- 跑一个 `--dur 120` 的短轮次，选一个不影响正在运行批次的发送端，或者负载在预算内的发送端。
- **模拟本机断网**：只切断测试进程，不影响正在运行的批次。
  ```sh
  sudo groupadd anltest
  sudo -g anltest -u $USER env HOME="$HOME" PATH=/usr/local/bin:/usr/bin:/bin ANL_REALNET_HOSTS=... ANL_REALNET_WORK=<副本工作目录> python3 <副本>/srt/cmp_round.py ...
  # 客户端启动后：
  sudo iptables -I OUTPUT -m owner --gid-owner anltest -d <发送端 ip> -j DROP   # 接收端同样处理
  # 断开时间要覆盖整个收尾阶段（≥ 4 分钟）；期间从自己的 shell 查看发送端的 deadman 日志和 tc；然后：
  sudo iptables -D OUTPUT -m owner --gid-owner anltest -d <发送端 ip> -j DROP
  sudo groupdel anltest
  ```
- 断网期间应当看到：远端进程按时结束，deadman 日志里有 `QDISC_STATS`、`LOSS_STATS`、`CLEARED`，频段已清除。连接恢复后，这一轮应当判为有效（`True`）。
- `cmp_round.py` 用的端口段不能和正在运行的批次相同：它的 ssh 主连接按端口段区分，端口段相同时测试进程会复用批次的连接，iptables 切不断它。

## 常见问题

- **`pkill -f` / `pgrep -f` 会匹配到执行它的 shell 自己**（命令行里含有同样的字符串），远端 `ssh host 'pkill -f ...'` 也一样，结果是把自己的 shell 杀掉。解决办法：
  - 把命令写进脚本文件，用 `ssh host 'bash -s' < script.sh` 执行；
  - 或者模式里写 `[r]ealnet_trace` 这样的字符类；
  - 或者先用 `pgrep` 取 pid，再用 `kill` 逐个杀。
- **1 核、960 MB 的主机**（t1、g5、lsj、s_ld）内存余量只有 400–650 MB。2026-10-24 曾因每轮留下一个约 55 分钟的 deadman（每个 10–14 MB）把 t1 的内存耗尽，OOM 杀掉了维护者的 postgres。工具已经改为本轮结束即退出；运行中仍要看 deadman 数和 `free -m`。
- **t1 上维护者的 postgres 被 OOM 打断后，会卡在关闭阶段**（`systemctl` 显示 `deactivating`）。经维护者同意后，用 `pg_ctl -D /var/lib/postgresql/16/main stop -m immediate` 停掉，systemd 会把它启动起来，启动时重放 WAL。
- **残留的 tc 频段会干扰后续轮次**：例如一轮在 setup 之后、deadman 启动之前中断，就会留下一个频段，它的过滤器优先于后来同一端口、同一对端的轮次。中断一批之后，在每个发送端查看 `~/.anliu-multi-tc.json`。每个残留频段都用它自己 deadman 的参数执行一次 `multi_tc.py clear`，再停掉 deadman。
- **广域网路径在晚间可能自身丢包**（端到端丢包高于 tc 设定）。超出设定 2 个点以上的轮次由 `cmp_pair.py` 自动跳过；两个版本同时运行，受到的影响相同。
- **`cmp_round.py` 需要两端之间至少一个方向能 ping 通**，用来量 RTT；都不通时报 `no ping`。
