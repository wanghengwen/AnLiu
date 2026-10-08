# FEC 实际字节诊断

内部诊断版本支持 `REALNET_FECCOST=1`，结束时输出 `FECCOST`。普通库编译不包含这些钩子，不改变协议行为或线上格式。

```sh
cc -std=gnu99 -O2 -DREALNET_INTERNAL -I. bench/realnet.c bench/ikcp.c -lm -o /tmp/realnet_trace
REALNET_CLOCK=1 REALNET_MDIAG=1 REALNET_FECCOST=1 /tmp/realnet_trace server --proto anlauto --test media --dir up --dur 150 --seed 1
# 另一台主机，HOST 替换为服务端地址；两端使用同一冻结源码与负载版本。
REALNET_CLOCK=1 REALNET_MDIAG=1 REALNET_FECCOST=1 /tmp/realnet_trace client --host HOST --proto anlauto --test media --dir up --dur 150 --seed 1
```

可与 `REALNET_TXDIAG=1`、TIMEBASE、SECS_BYTES 同时使用。记录两端最终统计，才可计算双向成本。TCP/KCP 或非内部构建不提供这些协议分类。

| 字段 | 口径 |
|---|---|
| `first_seg_bytes` | 首发 DATA 段的实际编码长度，含段头、可能附带的 OPEN 参数和数据 |
| `retrans_seg_bytes` | 重传 DATA 段的实际编码长度 |
| `parity_seg_bytes` | 实际发出 PARITY 段的编码长度，含控制段头与 FEC 元数据 |
| `parity_proto_bytes` / `parity_datagrams` | 仅含 PARITY 的数据报完整协议字节 / 数量，包含这些数据报自己的头部、认证和 padding，是 proto_bytes 的子集，不重复加到总和 |
| `control_seg_bytes` | 除 PARITY 外的控制、ACK、FWD 等段的编码长度 |
| `overhead_bytes` | 数据报头、认证 tag 和 padding 的实际字节，不在各流之间强行分摊 |
| `proto_bytes` / `datagrams` | 协议交给 output 回调的数据报字节 / 数量，在模拟丢包和 sendto 之前 |
| `pending_seg_bytes` | 已构造但尚未交给 output 的段字节，不计入已输出合计 |
| `blocks` / `block_data` / `block_parities` | 进入冗余生成的封块数、数据分片数、计划生成的校验包数；校验包可能尚未全部发出，不可替代实际发送字节 |
| `floor_blocks` | 自适应模式中 m 高于仅用名义 ratio 取整所得数量的块数 |
| `errors` | 段长合计超过所在数据报长度的记账错误数，应为 0 |

`FECCOST tag=...` 列出各流的 DATA/PARITY 与封块计数；1/2/3 对应音频/视频/bulk，0 为其他 tag。最后一条 `FECCOST total` 汇总全部流及控制/封装，满足：

```text
proto_bytes = first_seg_bytes + retrans_seg_bytes + parity_seg_bytes
            + control_seg_bytes + overhead_bytes
```

合并数据报的头部不会重复算到各段，变长段头和 padding 按实际长度计数；公共头始终为 23 字节（明文头 11 字节含 4 字节包号，加 12 字节 tag，`ANL_OVERHEAD`）。`parity_seg_bytes / first_seg_bytes` 是实际段字节冗余率，与名义 `fec_ratio`、按包数估算的 m/k 不同，也没有包含 parity 对应的数据报头。PARITY 可与 DATA 或 ECHO 同包，`parity_proto_bytes` 只统计纯 PARITY 数据报，不能代表全部 FEC 成本；IPv4 输出尝试量加封装估算则为 `parity_proto_bytes + 29 × parity_datagrams`。完整成本应报告总 `proto_bytes`，同时列出生成与准时交付的媒体字节。

`proto_bytes + 29 × datagrams` 可给出本工具 IPv4 的“协议输出尝试量加 mux/IP/UDP 估算”，但不是 NIC 成功发送量：output 之后仍会模拟丢包、sendto 失败或被 TC 丢弃；HELLO/ping 等工具自身报文也不经过协议分类。原有 `wire_kbps` 只累计成功 sendto 并加估算头部。保留两种口径交叉核对，不能直接相除当作同一批成功发包的开销率。

无网络自测：

```sh
cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic bench/test_fec_diag.c -o /tmp/test_fec_diag
/tmp/test_fec_diag
```

该测试核对有丢包/重传及 FEC 的可靠传输、完整内容、发送队列排空、实际输出字节守恒。诊断只在内部构建启用；A/B 两侧统一开关并保留工具和协议哈希。
