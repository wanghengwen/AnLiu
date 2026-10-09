# 单元测试

单元测试都放在 `ctest` 里。`test.c` 和 `test_attack.c` 直接包含 `anliu.c`，因此可以检查内部状态。判定标准：

- Release 与 Sanitizer 两种构建下，`ctest` 都全部通过；
- 输出中没有 `FAIL` 行。

`test.c` 的结果由种子决定：环境变量 `ANL_TEST_SEED` 不设时使用默认种子。下面三个环境变量用来缩小范围：

- `ANL_TEST_ONLY=子串`：只运行名字含该子串的测试；
- `ANL_TEST_TRACE=1`：在每个测试前打印当时的随机数状态；
- `ANL_TEST_RND=状态`：从打印出的状态开始回放。

## CTest

| 编号 | CTest 名称 | 程序 | 内容 | 预期 |
|---|---|---|---|---|
| UT-01 | `anliu.unit` | `test.c` | 协议单元测试，见下表 | 默认种子没有 `FAIL` |
| AT-01 | `anliu.attack` | `test_attack.c` | 不持有 PSK 的路径上攻击者：重放、反射、伪造、篡改、可塑性、注入、认证前模糊、不放大 | 没有被接受的伪造数据报 |
| DG-01 | `anliu.fec_accounting` | `bench/test_fec_diag.c` | FECCOST 核算：丢失、重传、FEC 路径 | 字节核算平衡 |
| DG-02 | `anliu.tx_accounting` | `bench/test_tx_diag.c` | pacing 令牌与输出字节的核算 | 断言通过 |
| DG-03 | `anliu.media_workload` | `bench/test_media_workload.c` | 相同种子产生相同的媒体负载，与协议、端点角色、定时器批次无关 | 帧序列相同 |
| DG-04 | `anliu.comparison_validation` | `tools/realnet/srt/test_cmp_checks.py` | 实网对比轮次的有效性检查（离线） | 通过 |
| FZ-00 | `anliu.fuzz_peer_smoke` | `tools/fuzz/fuzz_peer.c` | libFuzzer 运行 2 万次，固定种子（只在 Clang 且 `-DANLIU_BUILD_FUZZERS=ON` 时有） | 没有崩溃，没有违反不变量 |

## `test.c` 的内容（UT-01）

按 `main` 中的运行顺序分组列出。`test_fec_capacity_recovery` 从本次运行的种子开始取随机数，不受前面测试的影响。新测试加在 `test_fec_buffers_release` 之后（目前是 `test_echo_clock_rate`），以免扰动它之前各测试的随机序列。

| 组 | 测试 | 检查什么 |
|---|---|---|
| 基础与线上格式 | `test_kat` `test_demux` `test_output_rewrite` `test_wire_v1_wrap` `test_seg_size` | 已知答案、按 conv 分流、输出回调原地改写明文头、ts / sn 回绕、段长度上限 |
| 可靠流与半可靠流 | `test_default_stream` `test_reliable` `test_semi` `test_window_reopen_loss` `test_handle_lifetime` | 有丢包和无丢包时的完整性与顺序、窗口重开、句柄生命周期 |
| 安全与健壮性 | `test_reflect` `test_replay` `test_violation` `test_default_violation` `test_fuzz` | 反射、重放窗口（pn）、违规段导致流重置；默认流只丢弃违规段，不会被结束；随机段 |
| 流的生命周期 | `test_close_notify` `test_close_confirm` `test_semi_close` `test_stream_lifecycle` `test_sid_lifecycle` `test_sid_hold` `test_sid_churn` `test_accept_limits` `test_max_streams` | CLOSE 一直重发到收到 RST；两端计数一致；sid 不复用、保留期；接受上限；64 个流 |
| 调度与 pacing | `test_pacing` `test_priority` `test_review_scheduler` `test_review_timers` `test_review_backlog` | 加权轮询的额度、按优先级调度、时钟回绕时的定时器、积压计数 |
| 媒体语义 | `test_key_sender_purge` `test_key_receiver_discard` `test_receiver_deadline_default` `test_receiver_skip_ack_fragments` `test_rcv_skip_clears_fwd` `test_rcv_hole_echo` `test_echo_clock_rate` | drop_until_key、接收端缺口等待的默认值（max_age 的 3/5）、跳过补不回的缺口；对端时钟偏快时 echo RTT 不漂移（`clock_ppm`） |
| FEC | `test_fec_*`、`test_latency_rtt`、`test_report_late_clock`、`test_review_gf_tables` | 自动 FEC 的门、预算、丢失估计、容量门、伪修复；缓存释放（DESIGN 8.7）；GF 表 |
| 拥塞控制 | `test_start_rate` `test_bbr_*` `test_tiny_rtt` `test_target_rate*` `test_delay_report` `test_rtt_stale_ack` `test_start_absent` | 起步、交付窗口、应用受限、限速器检测、目标码率 |
| 断网与判死 | `test_outage` `test_rack_repeat_backoff` | 断网恢复；RACK 反复判丢的可靠重传要退避，不能在对端还在应答时判死 |
| 报告与送达计量 | `test_report_rx_bytes` `test_report_rx_count` `test_bbr_policer_reports` `test_bbr_report_intervals` `test_report_epoch_wrap` `test_report_capacity_recovery` | REPORT 的 `rx_bytes`：只用对端时间更新的报告推进，乱序、重复、丢失与回绕；无丢包时接收计数等于 `sent_wire`；限速器检测用报告速率（覆盖不足时按 ACK）、一次重测；报告缺失、跨变速的迟到快照、短 REPORT 被跳过；浅 FIFO 的容量恢复（种子 9、10） |

新增测试时，在对应的组里加上它的名字。

### 报告送达计量与容量恢复回归的补充说明

`test_bbr_report_intervals` / `test_report_epoch_wrap` 检查报告缺失、跨变速的迟到快照、恢复报告和发送端时间戳回绕；REPORT 固定 22 字节，更短的 REPORT 与其它过短的控制段一样跳过，同一数据报里其后的段照常处理。

`test_report_capacity_recovery` 固定覆盖种子 10 / 10% 与种子 9 / 15% 的浅 FIFO 容量恢复，不放宽原有恢复断言。扩展扫描 `ANL_TEST_SEED=1..25 ANL_TEST_ONLY=fec_capacity_recovery` 时，种子 7 / 10% 仍有基线同样的最终 10 秒内 626 ms shortage 失败，必须单独记录，不能声称整个多种子扫描全通过。

## Sanitizer 构建（SAN-01）

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DANLIU_ENABLE_SANITIZERS=ON
cmake --build build-asan -j && (cd build-asan && ctest --output-on-failure)
```

通过规则：

- 全部通过；
- 没有 ASan、UBSan 或 LeakSanitizer 报告。

## 编译警告（SAN-02）

在 Release 构建的输出中查找 `warning`，与基线比较。通过规则：`anliu.c`、`test.c`、`test_attack.c` 没有新增警告。

`bench/` 的比较工具（`bench.c`、`capacity_step.c`）在 GCC 13 下已有 `-Wmaybe-uninitialized` 与 `-Wformat-truncation` 警告，不计入。

## 模糊测试（FZ-01，代理）

做法见 [tools/fuzz/README.md](../../tools/fuzz/README.md)：用 Clang 构建，先用 `anl_fuzz_seeds` 生成种子，再运行 `anl_fuzz_peer -max_total_time=1800 -jobs=4 -workers=4 corpus`。

通过规则：

- 没有 `crash-*`、`leak-*`、`timeout-*` 文件；
- 没有 `abort`（违反不变量时会 abort）。

改动解析器或段的处理时必须做。
