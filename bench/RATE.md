# 测试中的速率变化回调

realnet 通过现有公开接口 `anl_set_rate_callback()` 记录流量控制器的建议速率变化：

```c
static void rate_changed(anl_t *w, uint32_t target_bytes_per_second, void *user);
anl_set_rate_callback(connection, rate_changed);
```

回调参数是所有流合计的**建议应用载荷速率，单位 B/s**。它不是网卡吞吐、
带宽上限或单个视频流可独占的速率。库约每 200 ms 更新一次建议值，首次
得到有效建议或相对上次通知变化至少 5% 时同步回调。允许在回调中读取
`anl_get_stats()` / `anl_stream_get_stats()`，其他协议操作应留到主循环。

发送端启用记录；普通、内部诊断和 v2 构建均支持。两端同时启用也可以，
纯接收端通常没有速率建议事件。TCP / KCP 没有这一接口，不产生 RATE 记录。

```sh
cc -std=gnu99 -O2 -I. bench/realnet.c anliu.c bench/ikcp.c -lm -o /tmp/realnet
# 两台机器使用同一冻结版本和相同测试选项；以下为上行。
REALNET_CLOCK=1 REALNET_TIMEBASE=1 REALNET_RATE=1 /tmp/realnet server --proto anlauto --test media --dir up --dur 150 --seed 1
REALNET_CLOCK=1 REALNET_TIMEBASE=1 REALNET_RATE=1 /tmp/realnet client --host HOST --proto anlauto --test media --dir up --dur 150 --seed 1
```

回调只读取统计并保存记录，结束时统一输出，避免逐条打印干扰收发节奏。
`REALNET_RATE=0` 或未设置时不注册诊断回调。此选项只观察建议值；媒体仍使用
固定的 frame_v1 负载，不会自动按回调改变帧大小或发送频率。

`RATE` 汇总回调次数 callbacks、保存记录数 recorded、未能保存的 dropped，
满足 `callbacks = recorded + dropped`。记录按需分配，最多 65536 条；达到
上限或分配失败只增加 dropped，不中断传输。dropped 非零时记录不完整，
不能把相邻保存记录当作连续回调。异常终止来不及输出时也不能据此判断没有变化。

每条 `RATE_CHANGE` 包含：

| 字段 | 口径 |
|---|---|
| mono_us / t_ms | 本机单调时钟微秒 / 相对本机 traffic_start 的毫秒；尚无起点时 t_ms=-1 |
| protocol_ms | 最近传给协议 update 的 32 位毫秒时钟，可能回绕；与 mono_us 对照可检查输入时钟滞后 |
| previous_Bps / target_Bps | 上一次回调值 / 本次建议值；首次 previous=0；乘 8/1000 换算为 kbps |
| bw_Bps / pace_Bps | 回调当时的带宽估计 / 有效 pacing 速率，同为 B/s |
| srtt_ms / min_rtt_ms | 平滑 RTT / 最小 RTT |
| cwnd / inflight | 拥塞窗口 / 在途分片数 |
| app_limited / bw_age_ms | 最近带宽样本是否应用受限 / 距最近网络受限样本的时间；4294967295 表示还没有此类样本 |
| retrans | 累计重传分片数 |
| wire_bytes | 本机成功 sendto 的累计字节估算，含 mux 与 IPv4/UDP 头及工具报文；与原 wire_kbps 同口径，位于 TC 之前 |

按 mono_us 与 [TIMEBASE](TXDIAG.md) 对齐同机 TC 操作时间，检查降速后建议值
何时下调、恢复后何时上调。跨机仍需时钟偏差记录。实际吞吐使用 SECS_BYTES，
FEC 成本使用 [FECCOST](FECCOST.md)；RATE_CHANGE 的间隔是不均匀的，不能把
建议值曲线直接当作实际流量曲线。正在进行的冻结批次保留原工具，新批次再统一启用。
