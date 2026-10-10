# 实网测试工具

在真实网络上成对运行 AnLiu 的两个版本（或 AnLiu 与 SRT），同一路径、同一时间，按 600 秒一轮统计音视频准时率、带宽与 FEC/重传开销。docs/PERFORMANCE.md 与 docs/COMPARISON.md 中的实网数据都由这些脚本产生。

仓库里不包含任何主机地址或账号：主机表放在仓库外，由环境变量指定。

## 环境变量

| 变量 | 含义 |
| --- | --- |
| `ANL_REALNET_HOSTS` | 主机表 JSON 文件（必需），格式见 `hosts.example.json` 与 `hosts.py` |
| `ANL_REALNET_WORK` | 本地工作目录：变体、`results/`、`events.jsonl`（默认当前目录） |
| `ANL_REALNET_REMOTE_DIR` | 远端测试目录，在各主机 `base` 之下（默认 `anliu-realnet`） |

主机表每项：`ssh`（user@host）、`ip`（对端发往的地址）、`base`（远端家目录下的目录）、`dev`（出口网卡，发送端整形用）、`shape`（能否 `sudo -n tc`，只有能整形的主机可做发送端），以及调度用的 `cap_kbps`（默认 30000）、`slots`（每个 pool 同时运行的进程数上限，默认 3）、`pool`（同一台机器上的主机共用一个 pool，默认主机名）、`port_base`（`multi_sched_pair.py` 分配端口的起点，默认 9900）。

## 前提

- 本机到各主机可免密 ssh；发送端主机可 `sudo -n /usr/sbin/tc`；
- 各主机有 python3、gcc；
- 整形与丢包都在发送端完成：每轮一个独立的 prio 频段（TBF + u32 端口过滤），`multi_tc.py` 管理，有看门狗兜底清理。

## 用法

```sh
export ANL_REALNET_HOSTS=~/realnet-hosts.json ANL_REALNET_WORK=~/realnet-work

# 打包并部署两个版本（库取自 git 版本，测试工具取自工作区）
python3 tools/realnet/deploy.py base  main
python3 tools/realnet/deploy.py cand  WORKTREE
# realnet.c 直接包含 anliu.c、读内部字段：旧版本的库可能无法和当前工具一起编译，对照时两个版本都用各自提交里的工具
python3 tools/realnet/deploy.py base  44a963c --tools-from-rev

# 单轮：发送端 a、接收端 b、变体、种子、限速 kbit、端口
python3 tools/realnet/multi_round.py a b cand 901 2000 9900 --loss 5 --drive-check

# 批量：一行一个 JSON 任务，相邻且只差 variant 的任务成对同时启动
python3 tools/realnet/multi_sched_pair.py jobs.jsonl sched-log/
```

`multi_round.py` 的选项：`--loss`（两端接收侧随机丢包，范围 0–15%，默认 15）、`--unlimited`（不限速，只计字节）、`--delay MS`（发送端附加单向时延）、`--burst BYTES`（TBF 桶，默认 16 KB；约 3200 时接近普通 FIFO 队列）、`--audio-only`、`--audio-max-age MS`、`--video-max PERMILLE`（编码器上限）、固定码率（位置参数 FIXED_SCALE）、`--tc-loss`（`--loss` 改由 tc 在发送端两个方向丢包，应用内不丢）、`--fec-off`（关闭 FEC，只靠重传）、`--queue-ms MS`（TBF 的队列，默认 100）、`--police`（令牌桶限速器：tc police 按 RATE_KBPS 限速，桶为 `--burst`，默认 64 KB，超出即丢、不排队；它后面是 `--line KBPS` 的线路，默认 40000，即本频段的 TBF 及其 `--queue-ms` 队列），以及 `--drive-check`（两端按 `anl_check` 决定下一次 `anl_update`，与应用的用法一致；不加时每 1 ms 轮询一次）。范围检查：`--loss` 0..15、`--delay` 0..200、`--burst` 1600..4 MB、`--queue-ms` 1..1000、`--video-max` 1000..20000、`--line` 1000..1000000。

测试用例（场景、轮次与通过规则）见 [docs/TESTING.md](../../docs/TESTING.md)；实网用例的主机、带宽预算与有效轮次的规定见 [docs/testcases/03-realnet.md](../../docs/testcases/03-realnet.md)。

结果在 `$ANL_REALNET_WORK/results/<tag>.{json,srv,cli,bw}`，两个变体成对轮次的差值用 `multi_pair.py BASE CAND`（tc、TBF 与限速器之外的丢包超过发送数 2% 的轮次判为 SKIP）；

TBF 不是限速器：tc 的 TBF 队列上限是"速率 × latency + 桶"，1 MB 桶就是 1 MB 的排队；加 `--delay` 时 netem 是 TBF 的子队列，队列又被 netem 的 limit 截断。要模拟"线速很高、按令牌限速、超出即丢"的网络，用 `--police`。`analysis/` 里是 docs/PERFORMANCE.md 各批次用过的成对分析脚本。

## 流的打开与关闭（`churn_round.py`）

`bench/churn.c` 在一条真实路径上不停地打开、关闭流，检验关闭握手（CLOSE 重发到对端回 RST，DESIGN 6.1）。两端各自保持最多 N 个本端打开的流（默认 31，两端合计 62 个加默认流不超过 64），按六种方式关闭：可靠流全部确认后关闭（对端必须读到全部消息再得到 `ANL_ECLOSED`）、半可靠流随时关闭、可靠流带在途数据关闭、接收方关闭、两端几乎同时关闭、打开后立即关闭。本端名额计入尚未确认的关闭，因此新开的流不应被对端以表满拒绝；被拒绝、消息缺失或错序、关闭未确认、结束时两端还有残留的流，都算失败。

```sh
python3 tools/realnet/churn_round.py deploy close WORKTREE g5 rb        # 构建 churn（旧版本的库加 --tools-from-rev）
python3 tools/realnet/churn_round.py run g5 rb close 1 9850 --loss 5     # 600 s，31 个流，tc 双向 5% 丢包
python3 tools/realnet/churn_round.py run g5 rb close 1 9850 --loss 5 --delay 100 --conc 12
python3 tools/realnet/churn_ana.py                                       # 汇总 results/churn_*.json
```

服务端用 `multi_tc.py` 独占一个频段：TBF 默认 8000 kbit（只是上限），`--loss` 两个方向随机丢包，`--delay` 增加单向时延。每端输出关闭确认时间的分布（从本端关闭到收到对端 RST）、被拒绝的打开数、对端读到的数据，以及结束时的检查（`CHURN_FINAL` 行的 `ok=1`：两端只剩默认流、没有待确认的关闭）。

每条消息带打开方的流编号（`uid`，本端打开次数的低 16 位）：接收方记下第一条消息的编号，之后编号不同的消息是另一个流的数据串入，记为 `gen_errors`（sid 在连接内不复用，DESIGN 6.1；2026-10-08 之前的版本复用 sid，这项检查针对上一代流）。`CHURN_OPEN max_sid` 是本端用到的最大 sid，`CHURN_NET replays` 是路径重复的数据报（`ANL_EREPLAY`，不算错误）。连接在收到握手包时才创建，启动慢的客户端不会让服务端先空闲超时。

## 与 SRT 对比（`srt/`）

`srt/srtnet.c` 用 SRT live 模式发送与 realnet 相同的 frame_v1 负载（音频、视频各一个连接，共用一个 UDP 端口）。仓库不包含 libsrt，需要自行获取并编译（对比使用 1.5.4，关闭加密、静态库）：

```sh
git clone --depth 1 --branch v1.5.4 https://github.com/Haivision/srt.git srt-src
cmake -S srt-src -B srt-build -DENABLE_ENCRYPTION=OFF -DENABLE_SHARED=OFF -DENABLE_STATIC=ON \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/srt-install
cmake --build srt-build -j && cmake --install srt-build
g++ -O2 -static -x c tools/realnet/srt/srtnet.c -x none -Isrt-install/include -Lsrt-install/lib -lsrt -lpthread -o srtnet

python3 tools/realnet/srt/deploy_srt.py ./srtnet
python3 tools/realnet/srt/cmp_round.py a b 2000 5 501 9960 --anl base   # AnLiu 与三种 SRT 配置同时运行
python3 tools/realnet/srt/cmp_ana.py
(cd tools/realnet/srt && python3 cmp_pair.py anl-nf anl-nf@cand --limits)   # 两个 AnLiu lane 的成对差值与回归限值
python3 tools/realnet/capacity_probe.py a b 9940 2,4,8,12,16      # 批次前：发送端出口容量（主机表的 cap_kbps 可能过时）
```

`cmp_round.py` 的丢包由 tc 在发送端两个方向完成（`multi_tc.py --loss`），不在应用内丢弃；统计口径见 docs/COMPARISON.md 2.1。

`--delay MS` 只增加发送方向的时延，因此 `srt-rec` 的延迟取 `max(120, ceil(4 × (ping RTT + MS)))` 毫秒。结果记录原始 `rtt_min_ms` 和包含人工延迟的 `effective_rtt_ms`。

有效轮次要求两端正常退出、运行时长完整、末尾 HEALTH 正常、发送端音频/视频序号分别覆盖 `duration × 50/30` 帧，并具备接收记录和 TC 字节计数。丢帧和 SRT 发送失败仍计入质量结果，不能仅因到达率低而排除轮次。脚本将退出码和运行秒数写入日志末尾的 `CMP_EXIT`；分析脚本重新检查完整性，旧日志没有该标记时仍检查 HEALTH 与完整发送序列。

离线验证无需主机表或 libsrt：`python3 tools/realnet/srt/test_cmp_checks.py`；本地有 Python3 时 CTest 也会运行。
