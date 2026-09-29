# TC 测试的发送预算与时间记录

诊断不改变协议参数。普通编译不包含新增内部钩子；内部构建使用同一份协议源码：

```sh
cc -std=gnu99 -O2 -DREALNET_INTERNAL -I. bench/realnet.c bench/ikcp.c -lm -o /tmp/realnet_trace
```

发送端设置 `REALNET_TXDIAG=1 REALNET_TRACE=250 REALNET_CLOCK=1`，双方设置
`REALNET_TIMEBASE=1 REALNET_SECS=1`，可靠流双方加 `--verify 1`。
发送端另加 `REALNET_RATE=1` 可记录建议载荷速率的变化回调及时间戳，
见 [RATE.md](RATE.md)；此观察也适用于普通构建，不改变测试负载。
内部构建已包含 anliu.c，不能再单独链接它。旧协议也必须回移本提交的
anliu.c 诊断钩子；只更换 realnet.c 不会产生完整额度记录。

## TXDIAG

日志为累计值，`stage=lt_begin` 是控制器实际开始一个测量区间，`lt_end`
紧邻原有 LTINT 的 before；`final` 为整个进程的最终值。
配对相邻 begin/end 并相减，不要按固定秒数猜 LT 区间。
遇新的 begin 而前一段没有 end，表示跳过了换速过渡区间。
`now` 是 32 位协议毫秒时钟，求差需处理回绕；`lt_ts` 沿用协议的
`current|1` 标记，可能比实际边界晚 1 ms，时长使用 now。

| 字段 | 口径 |
|---|---|
| earned / clipped | pace_refill 实际计算出的新增字节额度 / 被桶上限裁掉的额度；clipped 可包含之前积累的余额，不能直接当作网络丢包 |
| spent / tokens | 实际扣除的 pacing 字节 / 当前有符号余额；余额可为负 |
| control | 未扣 pacing 的控制数据报字节 |
| refill_ms / refill_n | 实际执行补充所覆盖的时间之和 / 次数；不是每次调用的名义 interval 之和 |
| flush_n / rtx_cap_n | 有效 flush 次数 / 重传循环触及额度上限的次数 |
| retrans_seg_bytes | 重传循环累计发送的 DATA 段编码字节；该循环也可补发 xmit=0 的分片，不等于重传 UDP 字节 |
| budget_min / budget_max | 从进程开始记录以来，每次 flush 初始 `cwnd - pipe` 的最小/最大分片数；这是累计极值，不可做差当作当前区间极值 |

同一观察区间应满足：

```text
spent_delta = earned_delta - clipped_delta + tokens_begin - tokens_end
```

spent 包含被扣费数据报的认证头、padding、同报文控制段等；不含 realnet
外层 1 字节、UDP/IP 头。control 是另一项，不应再次算入 spent。
实际 output 调用不保证网络发送成功，应结合 HEALTH 的 output_errors、
测试程序线上字节和 TC 计数。

累计状态时长按 update/input/send 和 flush 事件观察，使用协议毫秒时钟，
把上一次观察的状态保持至下一事件。它们是事件采样积分，不能当作 CPU
运行/调度耗时，也不能保证每一微秒都满足该状态；同时报告 CLOCK 时钟滞后。

| 字段 | 状态 |
|---|---|
| elapsed_ms | 已观察到的协议时间跨度 |
| newq_empty_ms | 所有可发送流都没有新数据排队；仍可能有重传或未确认数据，不能直接称为应用受限的带宽样本 |
| all_window_ms | 有新数据排队，但所有这样的流都被自身/对端序号窗口挡住 |
| cwnd_ms | 至少一条流有序号窗口，但连接现有 pipe 估计不小于 cwnd |
| pace_ms | 有新数据排队，当前 pacing 余额不允许继续发送 |
| ready_ms | 至少一条流有新数据、序号窗口及连接 cwnd/pacing 余量；不表示 CPU 已执行发送 |

这些原因可能重叠，不要相加求总阻塞时间。它们是连接范围状态；混合业务中
all_window_ms=0 不代表某一条 bulk 流从未被窗口阻塞。pipe 是协议最近维护的
在途估计，包含其已有的更新时序。逐流调度、CPU 耗时仍需专门事件或 profile。

## 时间与原始吞吐

`REALNET_TIMEBASE=1` 输出 `TIMEBASE`：traffic_start 为本进程测试开始，rx_first
为接收端首次向应用交付 bulk/stream 数据。event_mono_us 给出事件的单调时钟；
anchor_mono_lo_us / anchor_mono_hi_us 夹住同次 wall_us 采样。
同主机 TC 记录可按该锚点换算；跨主机的 wall clock 偏差、漂移和 NTP 调整
仍需另行测量，不能直接拿控制机 launch_ms 减远端时间。
TCP 分支目前只记录 rx_first，不提供 traffic_start 锚点。

媒体的 `MDIAG_R` 第五个数值是相对本机 traffic_start 的接收毫秒，可能为负：
下行服务端可以在客户端等待 ping 的阶段就开始发帧。标记
`MDIAG ... rx_time=signed_start_ms` 的新工具先保存绝对单调接收时间，结束时
再换算，字段数量和其余列含义不变。旧工具在起点尚未设置时就做无符号换算，
这些早到帧的 t_ms 可能是巨大的正数；不可据此排序或与 TC 对齐。旧日志的
owd_us 及按发送生成时间划分的时延统计不受此问题影响。

原 `SECS` 保留，另输出 `SECS_BYTES`：

- base_mono_us：接收首字节，与 rx_first 同一时钟；step_us 固定 1000000。
- values：按原顺序逐秒的应用载荷字节，没有整数 Mbps 舍入。
- window_bytes：所有列出桶的字节和；outside_bytes：统计窗口外（如排空阶段）的字节。
- `window_bytes + outside_bytes = HEALTH.received_bytes`（AnLiu 可靠流）；不能把整个排空后的总量当作发送阶段平均吞吐。

先取得 TC 每次操作的真实起止和时间锚点，再切接收端字节桶。缺少可对齐的
时间基准时保留为未对齐结果；不要用吞吐曲线拐点替代控制操作时间。
边界落在一秒桶内部时，保留整桶误差范围，或仅统计完整落在阶段内的桶，
不可假装可以精确拆分该秒。低档验收和恢复时间均注明边界不确定性。

## 本地检查

```sh
cc -std=gnu99 -O2 -DREALNET_INTERNAL -I. bench/test_tx_diag.c bench/ikcp.c -lm -o /tmp/test_tx_diag
/tmp/test_tx_diag
```

该检查不创建 socket，验证真实发送和重传过程的额度守恒、时钟回绕、
同一毫秒不重复补充，以及窗口/cwnd/pacing 状态的独立记录。
诊断打印与额外观察也有执行开销，真实吞吐验收应保留关闭诊断的对照。
