# 仿真

这些用例在单机上运行，使用虚拟时间。网络模型在 `bench/bench.c` 中，包括瓶颈队列、随机丢包、时延和突发。媒体负载与实网的 `realnet.c` 相同：

- 音频 50 帧/秒；
- 视频 30 帧/秒，每秒一个关键帧。

用到的程序：`build/bench/anl_media_loss`（Release）和 `build-asan/bench/anl_media_loss`（Sanitizer）。

## SM-01 媒体门槛（脚本）

```sh
python3 bench/test_media_loss.py build-asan/bench/anl_media_loss --output /tmp/gate
```

覆盖 8 个场景，每个场景 3 个种子，共 24 轮：

- 5 Mbit：100 ms 时 10% / 15% 丢包；2 ms 时 15% 丢包；100 / 180 ms 时 0% 丢包；100 ms 时 15% 丢包并在 30 s 停止；
- 800 / 2000 kbit 固定码率、100 ms、15% 丢包，600 s。

随机丢包最高 15%（2026-10-09 起，原为 20%）。

**通过规则**：每个场景都打印 `PASS` 行，脚本退出码为 0。断言写在脚本里，主要包括：

- 5 Mbit 场景：音频准时 ≥ 99.5%；
- 100 ms、有丢包时：视频与关键帧准时 ≥ 98%，校验字节 ≤ 首发字节的 55%，线上带宽 ≤ 2.2 Mbit/s；
- 无丢包时：视频全部准时，FEC 门不打开；2 ms 时还要求没有校验包；30 s 停止丢包的场景要求停止 40 s 后门一直关着；
- 800 kbit 时：音频 ≥ 95.5%，视频 ≥ 94%，关键帧 ≥ 90%；2000 kbit 时：音频 ≥ 98%，视频 ≥ 97%，关键帧 ≥ 97.5%；两者另有生成/准时视频码率的下限、线上带宽的上限和队列丢弃数 < 1500。

**基准**：24/24（2026-10-10，本次整理后的代码，ASan 构建约 45 s）。2026-10-08 `44a963c` 的 24/24 对应的是 20% 丢包的旧场景（`a75f02d` 起改为 10 / 15%）。

## SM-02 新旧版本成对仿真（代理）

改动涉及拥塞控制、FEC 或重传时做。

1. 分别构建基线与候选的 `anl_media_loss`：
   - 基线的源码用 `git worktree add /tmp/anl-base <基线提交>` 取出，在那里构建；
   - 候选在当前工作区构建。
2. 运行：
   ```sh
   python3 bench/test_media_protection.py --baseline /tmp/anl-base/build/bench/anl_media_loss \
       --candidate build/bench/anl_media_loss --output /tmp/prot --quick --check-recovery
   ```
3. 读取 `/tmp/prot/comparison.json`，即每个场景的"候选 − 基线"。

**通过规则**：

- 候选打印 `PASS recovery`；
- 无丢包的场景，两版的准时率逐项相同；
- 全部场景"候选 − 基线"的均值，按 95% 区间判定（`comparison.json` 只有每个场景、每个种子的差值，均值与区间由执行者计算）。只有均值超出下列限值、并且区间不含 0 时才判失败：
  - 音频 ≥ −0.1 个百分点；
  - 视频 ≥ −0.3 个百分点；
  - 关键帧数 ≥ −1；
  - 线上带宽 ≤ +3%。
- 单个场景的音频或视频下降超过 2 个百分点时，用另外 8 个种子（4..11）重跑该场景，再按上一条判定。脚本的种子固定为 1..3，加种子直接运行两个版本的 `anl_media_loss`（参数顺序 `带宽 kbit RTT 丢包% 种子 时长 s [停止时刻 ...]`，见 `bench/media_loss.c` 的 `main`）。

注意两点：

- 线上带宽的差值要按百分比计算：`comparison.json` 中的 `wire_delta_kbps` 是 kbit/s。
- `--quick`（120 s）下闭环场景（800 / 2000 kbit、编码器跟随目标码率）的噪声很大。任何字节数的变化都会让码率控制和随机数序列从某一刻起发散，单个种子的差异可以达到 ±13 个百分点（2026-10-08 实测）。这些场景只看多种子的均值与区间，不看单个种子。

只改线上格式时，线上带宽有预期的变化：每个数据报多 1..2 字节，约 +0.2%（5 Mbit 视频）到 +1%（以音频为主）。在报告中写明这一点，不判为回归。

## SM-03 多种子单元测试（代理）

```sh
for s in $(seq 1 24); do ANL_TEST_SEED=$s build/anl_test > /tmp/seed$s.log; grep -q "  FAIL " /tmp/seed$s.log && echo "seed $s"; done
```

**通过规则**：失败只出现在已知的不稳定检查上，并且失败的种子数不多于基线在同一组种子上的失败数加 2。

已知的不稳定检查：

- `test_fec_capacity_recovery`：种子 7 / 10% 在最后 10 s 内有 626 ms shortage，与基线相同；它从本次运行的种子重新取随机数，单独运行结果一样；
- `test_latency_rtt` 的 "frames delivered by retransmission"（种子 7、20，2026-10-10 观察到）；
- 自适应冗余不上调的检查（偶发）；
- `test_fec_loss_onset` 的"parity within 1.5 s of the first loss"：偶尔为 1520 ms，同一随机数状态下基线相同（2026-10-08）。

出现其他检查失败时，先用 `ANL_TEST_TRACE=1` 找到失败前的随机数状态，再用 `ANL_TEST_RND=<状态> ANL_TEST_ONLY=<测试名>` 分别在基线和候选上回放：

- 两者结果相同，就是原有的不稳定检查；
- 只有候选失败，判为回归。

注意：失败行是 `  FAIL <test.c 的完整路径>:<行号>: ...`（行首两个空格，路径由构建目录决定），匹配 `"  FAIL "` 即可；只搜 `FAIL test` 会漏掉。
