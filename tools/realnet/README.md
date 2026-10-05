# 实网测试工具

在真实网络上成对运行 AnLiu 的两个版本（或 AnLiu 与 SRT），同一路径、同一时间，按 600 秒一轮统计音视频准时率、带宽与 FEC/重传开销。performance.md 与 COMPARISON.md 中的实网数据都由这些脚本产生。

仓库里不包含任何主机地址或账号：主机表放在仓库外，由环境变量指定。

## 环境变量

| 变量 | 含义 |
| --- | --- |
| `ANL_REALNET_HOSTS` | 主机表 JSON 文件（必需），格式见 `hosts.example.json` 与 `hosts.py` |
| `ANL_REALNET_WORK` | 本地工作目录：变体、`results/`、`events.jsonl`（默认当前目录） |
| `ANL_REALNET_REMOTE_DIR` | 远端测试目录，在各主机 `base` 之下（默认 `anliu-realnet`） |

主机表每项：`ssh`（user@host）、`ip`（对端发往的地址）、`base`（远端家目录下的目录）、`dev`（出口网卡，发送端整形用）、`shape`（能否 `sudo -n tc`，只有能整形的主机可做发送端），以及调度用的 `cap_kbps`、`slots`、`pool`（同一台机器上的主机共用一个 pool）。

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

# 单轮：发送端 a、接收端 b、变体、种子、限速 kbit、端口
python3 tools/realnet/multi_round.py a b cand 901 2000 9900 --loss 5 --drive-check

# 批量：一行一个 JSON 任务，相邻且只差 variant 的任务成对同时启动
python3 tools/realnet/multi_sched_pair.py jobs.jsonl sched-log/
```

`multi_round.py` 的选项：`--loss`（两端接收侧随机丢包，默认 20）、`--unlimited`（不限速，只计字节）、`--delay MS`（发送端附加单向时延）、`--burst BYTES`（TBF 桶，默认 16 KB；约 3200 时接近普通 FIFO 队列）、`--audio-only`、`--audio-max-age MS`、`--video-max PERMILLE`（编码器上限）、固定码率（位置参数 FIXED_SCALE），以及 `--drive-check`（两端按 `anl_check` 决定下一次 `anl_update`，与应用的用法一致；不加时每 1 ms 轮询一次）。

结果在 `$ANL_REALNET_WORK/results/<tag>.{json,srv,cli,bw}`；`analysis/` 里是 performance.md 各批次用过的成对分析脚本。

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
```

`cmp_round.py` 的丢包由 tc 在发送端两个方向完成（`multi_tc.py --loss`），不在应用内丢弃；统计口径见 COMPARISON.md 2.1。
