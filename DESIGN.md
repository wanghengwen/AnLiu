# AnLiu（暗流）协议设计文档

版本：v0.5 草案
状态：第四轮修订（流扩展到 8192 个、可像 TCP 一样开关；修订项见第 13 节）
日期：2026-09-25

---

## 1. 概述

AnLiu 是一个基于 UDP 的轻量传输协议，参考 [ikcp](https://github.com/skywind3000/kcp) 的实现方式：

- 只有两个文件：`anliu.h` / `anliu.c`；
- 不依赖外部库，不直接操作 socket，通过 output 回调发包、`anl_input` 收包；
- 由应用驱动时钟，调用 `anl_update` / `anl_check`。

在 ikcp 的基础上增加了以下能力：

| # | 能力 | 概要 |
|---|---|---|
| 1 | 加密与抗探测 | 数据报整体认证并加密（12 字节标签），按传输方向派生密钥；线上没有固定明文特征 |
| 2 | 流级 FEC | 8+1 XOR 纠错，可交错；按流开关，默认关闭 |
| 3 | 精简头部 | 公共字段提到数据报级；DATA 段头典型 5~7 字节 |
| 4 | 多流 | 最多 8192 个并发流（含随连接创建的默认流 sid 0），sid（13 位）与段类型、1 个保留位合用 2 字节；流以句柄操作，两端都可随时打开/关闭，对端打开的流经回调自动接收并带应用 tag；流参数随第一个段携带，无握手；一个 sid 在连接内只用一次；每流独立序号空间 |
| 5 | 半可靠帧传输 | 按帧发送，积压或超时时整帧丢弃，用 FWD 通知接收方跳过 |
| 6 | 平滑发送 | 连接级令牌桶按速率发送，不把整个窗口一次性突发出去 |

### 1.1 非目标

以下内容不在 v1 范围内：

- 密钥交换与前向保密：使用预共享密钥（PSK），由应用负责分发和轮换（轮换上限见 3.7）；
- 完整防重放：只做基于 ts 的时间窗检查（见 4.2），用于挡住回绕周期之外的旧包；时间窗之内的重复数据由 sn 去重；
- 路径 MTU 探测、连接迁移；
- 隐藏流量时序特征（随机填充只能模糊包长）；
- BBR 等新型拥塞控制：沿用 ikcp 的 cwnd 逻辑，扩展到多流共享。

---

## 2. 分层结构

```
 应用层   anl_send / anl_recv                         （默认流，可靠字节流）
          anl_stream_send / anl_stream_recv           （可靠流句柄，语义同 ikcp）
          anl_stream_send_frame / anl_stream_recv_frame（半可靠流句柄）
   │
 流层     每个流独立：sn 空间、snd/rcv 队列、可靠模式、FEC 编解码
   │      所有流共享：RTT/RTO、拥塞窗口 cwnd；按优先级加权调度
   │
 包层     多个段打包进一个数据报；数据报头只写一份（conv、ts）
   │
 加密层   SipHash-2-4-128 认证（截断 12 字节）+ ChaCha20 加密（SIV 构造）；
   │      按方向派生密钥；可选随机填充
   │
 output 回调 → UDP
```

---

## 3. 加密层

### 3.1 角色与密钥派生

应用在配置里提供 32 字节 PSK，并指定本端角色 `role`：`ANL_ROLE_CLIENT`（0）或 `ANL_ROLE_SERVER`（1）。两端角色必须不同。

按**传输方向**派生两套密钥，方向 `dir` = 发送方的角色：

```
blk[dir] = ChaCha20_Block(key = PSK, nonce = "AnLiu-KDF-v1"(12B), counter = dir)   // 64 字节
k_enc[dir] = blk[dir][0..31]    // ChaCha20 密钥，32 字节
k_mac[dir] = blk[dir][32..47]   // SipHash 密钥，16 字节
k_rng[dir] = blk[dir][48..63]   // 本端内置 PRNG 的种子密钥，16 字节（仅 dir == role 时使用）
```

- 本端**发送**时使用 `dir = role` 的密钥，**验证和解密**时使用 `dir = 1 - role` 的密钥；
- 因此把 A 发出的数据报反射回 A，会因为密钥方向不匹配而认证失败。这是防反射攻击的关键；
- 两端角色配置相同时，双方都无法验证对方的包，连接会快速失败而不是静默出错。

v1 版本中，同一服务端的所有连接共用一个 PSK。这样服务端在查到连接之前，就能先验证数据报并解出 conv（见 3.4）。派生结果可以放在 `anl_keys` 中复用，避免每个数据报都重做 KDF。

### 3.2 SIV 构造（发送）

设 `P` 为明文数据报（数据报头 + 各段 + 可选填充），不含 tag。

```
tag   = SipHash-2-4-128(k_mac[role], P)[0..11]        // 16 字节输出截断为 12 字节
nonce = tag                                          // 12 字节 IETF nonce
C     = P XOR ChaCha20(k_enc[role], nonce, counter=0) // 整个 P 都加密
wire  = tag || C
```

只有一种加密模式：整包加密、整包认证。原 v0.1 的 `ANL_ENC_HEADER` 模式已删除：它会把段头（type|sid、递增的 sn、ACK 结构）暴露在线上，与"没有固定明文特征"的目标矛盾，而 SipHash 仍需处理整个 P，CPU 节省不到一半，不值得为此多一种模式。

### 3.3 接收

1. 数据报长度小于 `12 + 9` 字节，或大于配置的 `mtu`，直接丢弃（`ANL_EFORMAT`）；
2. 用 tag 当 nonce、用 `k_enc[1 - role]` 解密；
3. 用 `k_mac[1 - role]` 重新计算 `SipHash-2-4-128(P)[0..11]`，与 tag 做常量时间比较；
4. 比较失败时，`anl_input` 返回 `ANL_EAUTH`。**调用方不得对该包做任何回应**，这是抗主动探测的关键；
5. 认证通过后依次检查版本号/保留位（`ANL_EFORMAT`）、conv（`ANL_ECONV`）、时间窗（`ANL_ESTALE`，见 4.2），任一失败即丢弃。

### 3.4 服务端分发（demux）

```c
typedef struct anl_keys anl_keys;                       /* 两个方向的 k_enc / k_mac / k_rng */
void anl_keys_derive(anl_keys *keys, const uint8_t psk[32]);

/* 用 keys 验证并解密一个数据报。成功时返回明文 P 的长度，P 写入 plain（容量 >= size - 12），
 * 并输出 conv；失败返回 ANL_EAUTH / ANL_EFORMAT。role 是本端角色。 */
int  anl_peek_conv(const anl_keys *keys, int role, const char *data, long size,
                   uint32_t *conv, char *plain);

/* 喂入已经由 anl_peek_conv 验证过的明文 P，跳过解密和认证，只做步骤 5 及之后的处理。 */
int  anl_input_plain(anl_t *w, const char *plain, long size);
```

服务端流程：`anl_keys_derive` 一次 → 每个数据报 `anl_peek_conv` → 用 conv 找到连接 → `anl_input_plain`。

这样一个数据报只做一次 ChaCha20 和一次 SipHash。v0.1 的方案在 FULL 模式下 peek 已经必须解密整个 P 才能算 tag，随后 `anl_input` 再解密一次，crypto 开销翻倍，因此改为现在的接口。`anl_input` 仍然保留，供客户端或单连接场景使用。

**服务端建连策略**：协议没有握手，服务端对"认证通过但 conv 未知"的数据报创建新连接，就是事实上的隐式建连。任何拿到历史抓包的人都可以重放不同 conv 的旧数据报，让服务端批量创建僵尸连接；重放包还会成为新连接第一个初始化 `peer_ts`（4.2）的包。协议层面的对策和对应用的要求：

- 服务端角色的 `idle_timeout_ms` 默认 30 s（6.6），僵尸连接会被自动回收；
- 应用应对"新 conv 建连"限速（例如每源 IP 每秒不超过 N 个），并限制同时存在的连接总数；
- conv 应由服务端分配并通过带外渠道告知客户端，或由客户端取随机 32 位值、服务端拒绝与现存连接冲突的值。协议不提供 conv 分配机制；
- 对端进程重启后必须使用新的 conv（见 4.2）。

### 3.5 随机填充

- `pad_max` 取值 0..255，**默认 32**；为 0 时关闭；
- 当 `pad_max > 0` 时，每个数据报追加 `N` 字节填充，`N` 在 `[1, pad_max]` 内随机，且不超过 MTU 剩余空间；
- 填充的最后 1 字节是 `N` 本身，其余字节随机；
- 数据报头 flags 中的 `PAD` 位表示本包带填充。

随机源：`anl_config.rng` 回调（`void rng(void *user, uint8_t *buf, size_t n)`）可选。未提供时使用内置 PRNG：`ChaCha20(k_rng[role], nonce = 对象地址 ⊕ conv 在 anl_create 时确定, counter 递增)`，首次 `anl_update` 时再把 `current` 混入 nonce。种子必须在 `anl_create` 就可用，因为 `flush_on_send`（6.5）可能在第一次 `anl_update` 之前就需要填充。填充内容位于加密区内，其可预测性不影响机密性；只有 `N` 的分布影响抗流量分析的效果。

默认开启填充是因为 ACK-only 数据报的长度否则固定为 `21 + 12` 字节，是明显的协议指纹。

### 3.6 数据报时间窗（PAWS）

见 4.2。它是加密层之上的完整性补充：认证只能证明"这个包是持有 PSK 的一方发的"，不能证明"这个包不是旧包"。

### 3.7 安全性说明

本协议的密码构造是 SipHash-2-4-128（截断）+ ChaCha20 拼成的 SIV，没有现成的安全证明和参考实现；12 字节标签是为了省开销做的刻意取舍。安全目标显式列出如下，使用者据此判断是否满足场景：

- **伪造**：每次尝试成功概率 2^-96；
- **机密性**：SIV 是确定性加密，相同的 P 得到相同的密文。tag 兼作 nonce，nonce 碰撞会导致 ChaCha20 密钥流重用。碰撞服从生日界：N 个数据报的碰撞概率约 `N^2 / 2^97`。**单个 PSK 的所有连接、两个方向合计不超过 2^40 个数据报**（约 1.1 万亿，碰撞概率 < 2^-17），超过前应轮换 PSK；
- **反射**：由方向密钥防止；
- **重放**：只有时间窗检查（4.2）；时间窗内的重放会被 sn 去重，但攻击者可以借此造成少量重复处理开销；
- **流量分析**：不防；随机填充只模糊包长分布；
- **密钥分离**：同一 PSK 的所有连接共用密钥，任何持有 PSK 的一方都可以伪造任意 conv 的数据报。PSK 的信任边界是"同一组互信端点"；
- **未认证包的处理代价**：SIV 必须先解密整个 P 才能计算 tag，无法像 encrypt-then-MAC 那样先廉价拒绝垃圾包。每个包约一次 ChaCha20 + 一次 SipHash（1400 字节约 1~2 µs），1 Gbps 小包洪泛大约占用一个核的 20%。这是构造固有的代价，换来的是 12 字节而非 16+12 字节的开销；M6 需要实测这一数值；
- 版本号位于加密区内，密码套件升级无法通过版本号协商，只能靠更换端口或 PSK 实现（见第 4 节）。

---

## 4. 数据报格式

字节序统一使用小端，与 ikcp 一致。varint 使用 LEB128（小端，每字节 7 位，最高位为续标志），**最多 3 字节**，超出视为 `ANL_EFORMAT`。

```
  0             12       16     17       21
  +-------------+--------+------+--------+-----------------------+-------------+
  | tag (12)    | conv(4)| flg  | ts (4) |  段 1 | 段 2 | ...     | [填充 N 字节] |
  +-------------+--------+------+--------+-----------------------+-------------+
   明文           └────────────────── 加密区（一直加密到包尾）───────────────────┘
```

| 字段 | 大小 | 说明 |
|---|---|---|
| tag | 12 | SipHash-2-4-128 标签的前 12 字节，同时作为 nonce |
| conv | 4 | 连接号，非零 |
| flg | 1 | bit7-6：版本号（当前为 0）；bit0：PAD；其余位保留，必须为 0 |
| ts | 4 | 发送方时钟（毫秒），供对端在 ACK 中回显，并用于时间窗检查 |

**数据报级固定开销为 21 字节**，其中 12 字节用于认证和 nonce。

- 收到版本号未知或保留位不为 0 的包，直接丢弃；
- 允许 0 个段的数据报（只有头部和可选填充），用作 keepalive（见 6.6）；
- 默认 MTU 为 1400，与 ikcp 相同。

### 4.1 版本号的局限

版本号在加密区内，只有解密成功后才能读到。因此它只能用于同一密码套件下的格式演进；更换密码套件属于不兼容升级，需要新的端口或 PSK。

### 4.2 时间窗检查

16 位 sn 每 65536 个分片回绕一次。1 Gbps、1400 字节时约 0.7 秒一圈；延迟超过半圈的自然重复包、或攻击者在若干回绕周期后重放的旧包，都会以合法 sn 落入接收窗口。为此接收端在连接级做一次基于 ts 的检查：

- 连接记录对端最近的 ts：`peer_ts`（用有符号 32 位差值比较，允许回绕）；
- 认证通过后，若 `diff(ts, peer_ts) < -ts_window`，丢弃该数据报，`anl_input` 返回 `ANL_ESTALE`；否则 `peer_ts = max(peer_ts, ts)`；
- `ts_window = cfg.ts_window_ms`，默认 1000，**固定值，不与 RTO 挂钩**。时间窗防的是在网络中滞留过久的旧数据报，与重传无关（重传总是放在带新 ts 的新数据报里）；若与 RTO 挂钩，ikcp 的 RTO 上限 60 s 会让窗口膨胀到 240 s，每流速率上限随之降到约 136 分片/秒，保护形同虚设；
- 第一个通过认证的数据报直接初始化 `peer_ts`。

由此带来的约束（需要在使用文档中写明）：

- **单个流的发送速率不得超过 32768 个分片 / ts_window**（默认约 32768 分片/秒，1400 字节时约 45 MB/s），否则时间窗内也可能出现 sn 歧义；
- 对端的 `current` 必须是单调时钟。若它向后跳超过 ts_window，其数据报会被丢弃直到时钟追上；
- **对端进程重启后必须使用新的 conv**。重启后 `current` 通常从另一个基准重新计时，ts 大幅倒退，同 conv 的数据报会被永久判为 ESTALE。协议不做"连续多个 stale 则重置 peer_ts"之类的自愈：那会给重放攻击开后门。同 conv 重连在 ikcp 里同样是错误用法（sn 空间从 0 重置），这里只是让失败更早、更明确。

---

## 5. 段格式

每个段的前 2 字节：

```
 b0: bit 7 6 |  5  | 4 3 2 1 0     b1: bit 7..0
       type  | rsv | sid[12:8]           sid[7:0]        sid = 0..8191
```

- sid 位置固定，解密后读取前 2 字节即可得到流 ID；
- `rsv` 为保留位：发送方必须置 0；接收方收到非 0 时按 `ANL_EFORMAT` 丢弃整个数据报，与数据报头保留位的规则一致。留作将来扩展（例如更多 sid 或新的段类型）；
- v0.3 的单字节格式 type(2)|sid(6) 只能容纳 64 个流，已废弃。

| type | 名称 | 用途 |
|---|---|---|
| 0 | DATA | 数据分片 |
| 1 | ACK | 确认，兼作窗口通告和窗口探测 |
| 2 | FWD | 半可靠流通知接收方跳过 |
| 3 | CTRL | 扩展控制，第 2 字节为子类型 |

### 5.1 序号编码

- 线上的 sn 和 una 都是 **16 位**，内部扩展为 32 位：`sn32 = ref32 + (int16_t)(sn16 - (uint16_t)ref32)`；
- 接收方的参考值 ref 取 `rcv_nxt`，发送方取 `snd_una`；
- 要求窗口远小于 32768，因此实现中限制 `snd_wnd` 和 `rcv_wnd` 不超过 8192；
- 窗口限制只保证在途数据不歧义，不保证旧包不被当作新包，后者由 4.2 的时间窗检查负责。

### 5.2 DATA

```
 b0      : 00 | sid
 b1      : OPEN(1) | HAS_FRAME(1) | KEY(1) | frg(5)
 [frg_ext]: varint，仅当 frg5 == 31 时出现，实际 frg = 31 + frg_ext
 sn      : u16
 [frame] : u16，仅当 HAS_FRAME 时出现，为 frame_no 的低 16 位
 [open]  : 5 字节流参数，仅当 OPEN 时出现，见下
 len     : varint
 payload
```

**流参数（open body，5 字节）**，DATA / CLOSE / STREAM_OPEN 共用：

```
 ob      : u8     bit0 = SEMI（半可靠流），bit1 = STREAM（字节流模式，仅可靠流）
 rcv_wnd : u16    打开方的接收窗口，两端相同
 tag     : u16    应用定义的流用途
```

**分片大小**：连接 mss = MTU − 21 − 11（DATA 头部最大值，不含流参数）。对端尚未应答时切出的分片，载荷上限为 mss − 5，重传时仍可能携带流参数而不超过 MTU；收到对端任何段之后切出的分片使用完整 mss（peer_opened 只会从 0 变 1，之后切出的分片不会再带流参数）。只让少量早期分片承担这 5 字节，而不是整条连接一直少 5 字节 mss。

- **frg**：分片倒计数，语义与 ikcp 相同。最后一片为 0，第一片为 n-1。
- **len 总是存在**。v0.4 曾对数据报最后一个 DATA 段省略 len（HAS_LEN 标志），封包时需要回写 b1 并挪动 payload，还引出过 PARITY 被吞的错误（13.5）；省下的 1~2 字节不值这份复杂度。
- **OPEN**：打开方在**收到对端该流的任何段之前**，发出的每个 DATA 都带流参数（多 5 字节）；收到对端的任何非 RST 段后清除。接收方靠它在数据到达时直接建流（见 6.1），不需要单独的握手。
- **HAS_FRAME / KEY**：只出现在半可靠流中每一帧的**首个分片**上。HAS_FRAME 同时是帧起点标记，接收方靠它来跳帧。
- **模式校验**：可靠流收到带 HAS_FRAME 的 DATA、或收到 FWD，说明对端把该 sid 当作半可靠流；本端向对端发 RST 并按"对端已释放"处理该流（见 6.1）。
- **头部大小**：
  - 可靠流：`2 + 1 + 2 + (1~2)` = **6~7 字节**；对端尚未应答时再加 5 字节；
  - 半可靠流的帧首片：再加 2 字节。

### 5.3 ACK

```
 b0      : 01 | sid
 b1      : WASK(1) | FRESH(1) | 保留(6)
 una     : u16     该流中接收方已连续收到的下一个 sn
 wnd     : u16     接收方剩余窗口
 ts_echo : u32     回显最近一个带有本流 DATA 的数据报的 ts
 n       : varint  后面的区间个数
 gap[i]  : varint  区间起点 - 上一个区间的终点（第一个区间相对 una），≥ 1
 len[i]  : varint  区间长度，≥ 1；区间 [起点, 起点 + len) 内的分片都已收到
```

**区间确认（SACK）**：v0.4 之前 ACK 逐个列出本次新收到的 sn，每个 sn 只确认一次，ACK 丢失后发送端只能等 RTO（13.11）。现在区间直接由 rcv_buf（una 之上、乱序到达的分片）生成，按升序列出：

- 每个分片记录自己被报告的次数；一个区间只要其中有分片被报告少于 **3 次**（`SACK_REPEAT`）就列入本次 ACK，所以一个分片会出现在至少 3 个 ACK 中，单个 ACK 丢失不再引起多余重传或队头停滞；
- 收到已有的分片（发送端重传了它，说明发送端可能不知道它已送达）时，把它的报告次数清零，重新报告；
- 一个 ACK 段放不下时拆成多个 ACK 段，每段都带完整的 una / wnd / ts_echo；
- 编码：连续收到的分片只占一个区间，连续确认 100 个分片约 2 字节（旧格式约 101 字节，ikcp 为 2400 字节）；
- 接收端检查：gap 与 len 为 0、区间总跨度超过 `ANL_MAX_WND` 的 ACK 视为格式错误；发送端忽略终点超过 snd_nxt 的区间。

**标志位**：

- `FRESH`：自上一个 ACK 以来收到过本流的数据，ts_echo 是新的，可以作为 RTT 样本。只有 FRESH 的 ACK 参与 RTT 计算和 RACK；窗口探测的应答、FWD 触发的 ACK 不带 FRESH；
- 旧格式中每个 sn 只确认一次，而区间会在多个 ACK 中重复出现，所以发送端对已经删除的分片再次收到确认是正常的，直接忽略。

- **RTT 计算**：`rtt = now - ts_echo`。ts 标识的是某一次具体的发送，所以不存在 Karn 歧义。RTT/RTO 在连接级统一维护。**一个收到的数据报最多产生一个 RTT 样本**：取其中所有 ACK 段里最新的 ts_echo，避免多个流回显同一个 ts 时重复采样、压低 rttval。样本 `< 0` 或 `> 60 s` 视为无效并忽略（认证通过的数据报里 ts_echo 也可能因实现错误或时钟问题而离谱，直接代入 srtt 会导致整数溢出）。
- **窗口探测**：
  - 对端窗口为 0 时，发送 `WASK=1, n=0` 的 ACK，替代 ikcp 的 WASK；探测间隔从 1 s 起步、每次 ×1.5、上限 60 s（ikcp 从 7 s 起步，对实时业务过长）；
  - 对端回一个 `n=0` 的 ACK，替代 ikcp 的 WINS。
- **触发条件**：收到本流的 DATA、收到 FWD（无论是否改变了 rcv_nxt）、接收端因 rcv_deadline 跳帧之后，都必须为该流排一个 ACK。后两条是 FWD 能收敛的前提（见 7.4）。
- **发出时机**（`cfg.ack_nodelay`，默认 1）：
  - `ack_nodelay = 0`：与 ikcp 相同，排好的 ACK 等下一次 flush 发出，最坏延迟一个 interval。只收不发的端（例如观看端）会让发送端的 RTT 估计和 RTO 系统性偏大 interval；
  - `ack_nodelay = 1`：`anl_input` 处理完一个带 DATA 的数据报后，若自上次发出 ACK 起已累计收到 **2 个**带 DATA 的数据报，或该数据报带 FWD / WASK，则在 `anl_input` 返回前立即发出一个只含 ACK/CTRL 的数据报；否则等下一次 flush。这与 TCP 延迟确认的"每两个段确认一次"一致，ACK 数量约为数据报的一半。ACK-only 数据报不消耗 pacing 令牌（6.7），且 `anl_input` 内会同步调用 output（重入规则见 6.5）。

### 5.4 FWD（仅半可靠流）

```
 b0      : 10 | sid
 new_una : u16    所有小于 new_una 的 sn 都已被发送方放弃
```

共 3 字节。new_una **必定等于某一存活帧首个分片的 sn**（发送端为每帧记录 `first_sn`），或者在没有存活帧时等于 `snd_nxt`。它与 `snd_una` 是两个不同的量，详细规则见 7.3。

### 5.5 CTRL

```
 b0   : 11 | sid
 b1   : subtype
 len  : varint      body 的字节数
 body[len]
```

| subtype | 名称 | body | 说明 |
|---|---|---|---|
| 0x00 | 保留 | — | — |
| 0x01 | PARITY | 见 8.3 | FEC 校验段 |
| 0x02 | STREAM_OPEN | 5 字节流参数（5.2） | 单向通告：打开方尚未收到对端任何段时，按退避周期发送，让对端在没有数据的情况下也能建流；对端回一个普通 ACK（n=0）即可，见 6.1 |
| 0x03 | STREAM_CLOSE | `final_sn(u16) flags(u8) una(u16) [open(5)]` | 本端关闭该流，final_sn 为本端最后一个 sn 的下一个值；`flags` bit0 = **RST**（该 sid 在本端已经释放），bit1 = **OPEN**（后接 5 字节流参数，打开方尚未收到对端任何段时置位，使先于数据到达的 CLOSE 也能建流）；**una** 为本端该流的 rcv_nxt，非 RST 的 CLOSE 在对端按 ACK 的 una 处理（RST 中为 0，忽略），见 6.1 |
| 其他 | 保留 | — | 按 len 跳过 |

- 收到未知 subtype 时，按 len 跳过这个段，继续解析后面的段。这样以后新增控制类型时，旧版本的实现也能兼容。

---

## 6. 流层

### 6.1 流管理与参数校验

**默认流（sid 0）**：

- `anl_create` 时两端各自隐式创建，随连接存在，不能关闭（`anl_stream_close` 返回 `ANL_EINVAL`）；
- 可靠流、**字节流模式**，`anl_send / anl_recv / anl_peeksize / anl_waitsnd` 直接作用于它，语义与 ikcp 相同；发送即 flush；
- 窗口由 `cfg.default_snd_wnd / default_rcv_wnd` 设置，默认均为 1200；
- **严格优先级**：重传和新数据都先于其他所有流发送；
- 创建后立即可收发，两端各自按配置设定窗口，线上不交换默认流的参数；
- 字节流模式下一次 `recv` 可能返回多条应用消息拼接的数据，接收缓冲必须不小于待读分片（最多一个 mss），否则返回 `ANL_EBUFSIZE`——与 ikcp 字节流模式相同，应用需要自行分帧。

**其他流（句柄）**：

- `anl_stream_t *anl_stream_open(w, opt, &err)` 自动分配 sid：客户端只用偶数（从 2 开始）、服务端只用奇数，两端不会冲突；**sid 单调递增，一个 sid 在连接内只使用一次**，用完 4096 个后 `anl_stream_open` 返回 `ANL_EBUSY`——一条连接的生命周期内开关几千次流的用法不在设计目标内，需要时重建连接。失败返回 NULL，原因写入 `err`（`ANL_EINVAL / ANL_EDEAD / ANL_EBUSY / ANL_ENOMEM`）。不支持应用指定 sid；
- `opt.tag`（0..65535）由应用定义，随流参数发给对端，用于说明流的用途（例如 1 = 视频、2 = 文件）；
- 发送、接收、查询都以句柄进行（`anl_stream_send / recv / send_frame / recv_frame / peeksize / waitsnd / get_stats`），另有 `anl_stream_id`（线上 sid，两端一致）、`anl_stream_tag`、`anl_stream_conn`、`anl_stream_set_user / get_user`；
- **对端打开的流自动接收**：收到未知 sid 上带流参数的段（DATA 的 OPEN 标志、CLOSE 的 OPEN 标志或 STREAM_OPEN）时先建流，再调用 `anl_set_accept()` 注册的回调 `int accept(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)`。opt 已按对端的 mode / stream / tag / rcv_wnd 预填，这四项回调**不能改**（改了会被忽略），其余本端参数可以修改（例如 prio、snd_wnd、FEC、`rcv_drop_until_key` 等）；返回 0 表示接收，此后应用拥有该句柄；返回负数表示拒绝，流被释放，本端回 RST。未注册回调时按默认参数接收，应用通过 `anl_readable` 发现新流。回调在 `anl_input` 内同步调用，除 `anl_stream_set_user` 外不得调用任何 `anl_*` 函数；
- 对端同时打开的流数量受 `cfg.max_peer_streams`（默认 1024，上限 8192）限制，超出时回 RST。它防止对端用大量新 sid 耗尽本端内存；本端主动打开的流不受此限制；
- **mode / stream / tag / rcv_wnd 由打开方决定，两端相同**；其余选项两端可以不同。rcv_wnd 两端一致后，发送方的分片数检查（7.2、第 9 节）直接用本地 rcv_wnd，不需要再向对端通告；
- `anl_readable(w, out, max)` 返回应用持有的、可以读的流句柄：有完整消息或帧、或已到流末尾。

**句柄生命周期（与 socket 相同）**：

- 句柄从 `anl_stream_open` 或 accept 回调开始有效，直到应用对它调用 `anl_stream_close`（或 `anl_release`）为止；
- 对端关闭或 RST 的流，句柄仍然有效：发送返回 `ANL_ECLOSED`；接收先交付剩余数据，**读完后返回 `ANL_ECLOSED`（流结束）**；应用仍需 close 一次；
- `anl_stream_close` 之后句柄立即失效：未读的接收数据被丢弃，之后到达的数据也直接丢弃；可靠流尚未确认的发送数据仍会送达，关闭交换在协议内部继续完成；
- 流结构体在**两个条件都满足**时释放：协议侧已结束（`closed` 且待发的 ACK / CLOSE 应答已发出）、应用已 close。只满足前者时，它从 sid 表中摘除（不再收发），结构体保留到应用 close 为止；只满足后者时，它继续留在 sid 表中完成关闭交换。

**实现要求（流数量可达 8192）**：

- 流表采用两级页表（64 页 × 128 项，按需分配）加一条所有流的链表；不得使用 8192 项的定长数组，否则每个连接固定占用 64 KB，且每次 flush 都要扫描 8192 项；
- 有待发控制段（ACK / FWD / CLOSE / RST / 窗口探测）的流挂在连接的一条**待发控制链表**上，`anl_input` 在 ack_nodelay 下立即回 ACK 时（以及 open / close 时）只走这条链表。否则每个数据报都要遍历全部流，开销随流数量线性增长；实测 16384 个流（v0.4 草案曾支持的上限）时，测试耗时从约 100 s 降到约 13 s。CLOSE / FWD / STREAM_OPEN 的重发和窗口探测等定时工作，仍由按 interval 进行的全量 flush 处理。

**流的建立（无握手）**：

- 打开方在收到对端该流的任何段（ACK / DATA / FWD / 不带 RST 的 CLOSE）之前，发出的每个 DATA 和 CLOSE 都携带 5 字节流参数（5.2 的 OPEN 标志）。数据不必等待对端，"打开、发送、立即关闭"也不丢数据：CLOSE 本身带流参数，先于数据到达时同样能建流；
- 打开方在此期间还按 RTO 起步的指数退避（RTO、2RTO、4RTO……上限 5 s）发送 STREAM_OPEN 段，用于"本端打开、等对端先说话"的用法：没有它，对端永远不知道这条流存在。它是单向通告，对端回普通 ACK（`n=0`）即可；**重发不计入 dead_link**。收到对端任何段后停止；
- 接收方收到未知 sid 上带流参数的段：`sid` 若在本连接内已经用过（见下面的位图）则回 RST；否则按 6.1 的规则自动接收，然后照常处理该段的内容（DATA 入 rcv_buf、CLOSE 记 final_sn）。带流参数的段落在已存在的流上时，校验 mode / stream 是否一致，不一致视为协议违规（见下）；
- `anl_stream_get_stats().state` 在收到对端任何段之前报告 `opening`，之后为 `open`；这只是信息，不影响收发。

**协议违规**：流参数不一致、可靠流收到 FWD 或带 HAS_FRAME 的 DATA 等，本端向对端发 RST，并把本端流按"收到对端 RST"处理（见下面的 RST 语义）：应用侧表现为发送返回 `ANL_ECLOSED`、接收读完已交付数据后返回 `ANL_ECLOSED`。不再有单独的错误状态和错误码。

**未知 sid**：收到未知 sid 的 ACK / FWD 时静默丢弃；收到**不带流参数的 DATA / CLOSE 时回 RST**。场景：本端的数据已被对端收到但 ACK 丢失，对端随后正常关闭并释放了流，本端的重传就会落到对端的未知 sid 上；若静默丢弃，本端会一直重传直到 dead_link 拖死连接。正常的新流第一批段一定带流参数，RST 不会误伤。

**STREAM_CLOSE 与有序关闭**：

- STREAM_CLOSE 的 body 是 `final_sn(u16) flags(u8) [流参数]`，final_sn 表示本端在该流上最后一个 sn 的下一个值。可靠流取 `snd_nxt + snd_queue 中的分片数`（关闭前已提交但尚未搬入 snd_buf 的数据同样要送达），半可靠流取 `snd_nxt`；
- `anl_stream_close()` 后本端进入 `closing`：拒绝新的发送（返回 `ANL_ECLOSED`），**继续重传 snd_buf 中的分片直到全部确认**（可靠流）；半可靠流直接丢弃 snd_queue / snd_buf 并置 `final_sn = snd_nxt`；
- STREAM_CLOSE 从 RTO 起按数据分片的规则**退避**重发（nodelay=0 翻倍，否则 ×1.5），重发次数计入 dead_link，直到收到对端同一 sid 的 STREAM_CLOSE。固定以 RTO 为周期时，约 2 秒的断网就会用完 20 次 dead_link；
- 对端收到 STREAM_CLOSE(final_sn) 时：
  - 记录 `peer_final_sn`；rcv_buf / rcv_queue 中的数据继续正常接收和交付，直到 `rcv_nxt ≥ peer_final_sn`；
  - 若本端尚未关闭，自动进入 `closing` 并回一个 STREAM_CLOSE（携带自己的 final_sn）。流的关闭是**全双工同时关闭**，不支持半关闭；
  - **对端每一个（不带 RST 的）CLOSE 都回应一次**，由对端的重发自然限速。只回应一次时，这一次回应一旦丢失，对端会一直重发 CLOSE 直到 dead_link，拖死整条连接。处理这个 CLOSE 时本端流若随即进入 `closed`，也仍要回应，否则对端只能等下一次重发换来 RST；
- 本端同时满足以下条件时状态变为 `closed`：已收到对端 CLOSE，且 snd_queue / snd_buf 为空（或半可靠流），且 `rcv_nxt ≥ peer_final_sn`。该判定在收到 ACK、收到 DATA、本地 close 时都要执行（只在收到 CLOSE 时判一次会漏掉“CLOSE 先到、数据后到”的情况）。进入 `closed` 后若还有未发出的 ACK 或 CLOSE 应答，下一次 flush 先把它发出去再把流从 sid 表摘除，保证对端最后几个分片能被确认；已交付到 rcv_queue 但应用未读的数据保留，读完后接收接口返回 `ANL_ECLOSED`；
- **RST 语义**：收到属于已 `closed` 或已释放 sid 的 DATA / STREAM_OPEN / 不带 RST 的 CLOSE 时，回一个带 **RST 标志**的 STREAM_CLOSE（`final_sn` = 记录的旧值或 0），流仍存在时**每个 sid 每 RTO 最多回一次**。对已无任何状态的 sid 回的 RST 放在一个可增长的队列中（位图去重）：大量流同时关闭时，对端的 CLOSE 重发是同步的，固定容量（曾为 32）的队列每次溢出同一批 sid，它们永远得不到 RST。收到 RST 的一端可以立即释放该流（不再等 `rcv_nxt ≥ peer_final_sn`，也不再等对端确认），因为对端已经没有这个流了。RST 标志用于区分“对端已释放”和“对端 CLOSE 的普通重发”，否则收到迟到的重发 CLOSE 也会被当成 RST 而提前释放；对带 RST 的 CLOSE 不再回应，避免两端互发 RST；
- **没有 TIME_WAIT**：流 `closed` 且待发段发完后立即从 sid 表摘除。旧一代段落到同一 sid 上的问题由"sid 不重用"解决：连接保存一个 8192 位（1 KB）的**已用 sid 位图**，本端分配和对端首次使用时置位；已用 sid 上再出现带流参数的段一律回 RST，不会建出第二代流。迟到的旧 DATA / CLOSE 得到 RST，对端若还持有该流就按上面的 RST 语义释放；迟到的 ACK / FWD 静默丢弃。因此线上不需要 generation 编号，也不需要墓碑和到期定时器；
- 应用未读完 rcv_queue 的已关闭流（`closed` 状态）仍在 sid 表中，对端此时若向它发送会收到 RST。

### 6.2 每流状态

与 ikcp 相同的部分：

- `snd_queue` / `snd_buf` / `rcv_buf` / `rcv_queue`
- `snd_una` / `snd_nxt` / `rcv_nxt` / `rmt_wnd`
- 每个分片的 `resendts` / `xmit`，以及最后一次发送时间 `ts_sent`；ikcp 的 `fastack` 计数由 RACK 的 `lost` 标记取代（6.3）；接收端 rcv_buf 中的分片记录被 SACK 报告的次数（5.3）
- 不再有 `acklist`：ACK 待发标志 + FRESH 标志 + rcv_buf 即可生成 ACK；发送端分片另记 `rack_rtx`（最后一次发送是否为 RACK 重传，用于 Eifel 检测）

新增的部分：

- 可靠模式（`mode`）和优先级（`prio`）；
- 流状态：`open` / `closing` / `closed`（`opening` 只是 `open` 且尚未收到对端任何段时的对外报告），是否已收到对端任何段（`peer_opened`），是否由对端打开，`final_sn` / `peer_final_sn`，STREAM_OPEN 退避定时器，RST 限速时间戳，是否已从 sid 表摘除 / 应用是否已 close（两者都成立时释放）；
- FEC 编解码状态；
- 半可靠流的相关状态：每帧的 `first_sn`、入队时间、待发的 FWD `new_una`。

### 6.3 连接级共享状态与拥塞控制

- RTT 相关：`rx_srtt` / `rx_rttval` / `rx_rto`；
- 拥塞控制：`cwnd` / `ssthresh` / `incr`；
- 发送参数：`nodelay` / `interval` / `resend` / `nc`，语义同 `ikcp_nodelay`；
- 时间窗：`peer_ts`（4.2）；
- 令牌桶：`pace_tokens` / `pace_last`（6.7）；
- 接收缓冲总量：`rcv_bytes`。

ikcp 的 cwnd 逻辑基于单流的 `snd_una`，多流共享时按以下规则重新定义：

- **在途量** `inflight` = 所有流 snd_buf 中分片数之和（不含 FEC 校验段）；
- **本次 flush 的新数据预算** = `cwnd - inflight - 本次 flush 已发出的校验段数`。校验段不需要确认，所以不进入 inflight，但占用预算，避免 FEC 在拥塞时无限制加压；
- **cwnd 只限制新数据**（snd_queue → snd_buf 的搬运），与 ikcp 相同。**重传不受 cwnd 限制**：丢包后 cwnd 减半几乎必然小于 inflight，若重传也受预算约束，突发丢包后将没有任何分片能发出，连接卡死。重传的速率由 6.7 的 pacer 约束；
- **初始值**：`cwnd = init_cwnd`，默认 16（ikcp 为 1；从 1 开始慢启动会让半可靠流的首个关键帧在 max_age_ms 内发不完，被丢弃后再等下一个关键帧，启动阶段反复）；
- **增长**：只有 `parse_ack` **实际确认了分片**（ACK 的 sn 列表命中 snd_buf，或 una 前移覆盖的分片确实在 snd_buf 中）时，才按 ikcp 的规则用连接 mss 增长（慢启动阶段每确认一个分片 +1，拥塞避免阶段每确认一个分片按 incr 累加；即以“被确认的分片”而不是“收到的数据报”为单位，与 TCP 一致）。`ssthresh` 初值为 `ANL_MAX_WND`。因 FWD 或接收端 deadline 跳帧导致的 una 跳变**不算**：那些分片没有送达，若计入增长，会形成"越拥塞越丢帧、越丢帧 cwnd 越大"的正反馈；
- **上限**：`cwnd ≤ Σ 各已打开流的 rmt_wnd`，且 `≤ ANL_MAX_WND`；
- **丢包判定（RACK，RFC 8985，`resend > 0` 时启用）**：取代 ikcp 的 fastack 计数。连接记录对端已收到的最新数据报的发送时间 `rack_ts`（所有流带 FRESH 的 ACK 的 ts_echo 的最大值）和它的 RTT `rack_rtt`；每条流另记本流的 `rack_ts` 与对端报告过的最高 sn `rack_hi`（una 或最高区间终点）。snd_buf 中满足以下条件的分片判为丢失，在下一次 flush 重传（通常就是本次 input 触发的那次，见 6.4）：
  - 尚未确认，且有证据表明比它晚发出的数据已经送达：`ts_sent < 连接 rack_ts`（任何流的数据报都算：所有流共用一条数据报序列，接收端在同一次 flush 里为所有流回 ACK）；或 `ts_sent ≤ 本流 rack_ts` 且 sn < 本流 rack_hi（同一毫秒发出的按 sn 顺序）。只用本流证据时，低速流（例如控制流）的分片在大流占满 cwnd 时没有后续分片可作证据，只能等 RTO，RTO 翻倍后停顿可达 2 s（13.11）；
  - **已经等待了 `rack_rtt + reo_wnd`**：`now ≥ ts_sent + rack_rtt + reo_wnd`。
  判定在每个 ACK 和每次 flush 时进行，`anl_check` 把最早的判定时刻当作定时器返回。第一版实现用的是 `rack_ts − ts_sent > reo_wnd`，同一次 flush 发出的一批分片发送时间相同，其中丢失的那个永远不满足条件，窗口受限时队头丢失只能等 RTO（13.11）；
  - 与按 ACK 个数计数相比，判定只依赖"比它晚发出的数据已经到达"和时间差，与 ACK 频率、每个 ACK 覆盖多少分片无关。旧方案下 AnLiu 每 2 个数据报就回 ACK，比 ikcp 密得多，resend=2 在有抖动的链路上 98% 的快速重传是多余的（13.11）；
  - 一个重传出去的分片，只有在它之后发出的数据报送达、它仍未确认且超出乱序窗口时，才会再次被判为丢失，所以每个 RTT 至多重传一次，不再需要 ikcp 的 `xmit ≤ 5` 上限；
  - **乱序窗口** `reo_wnd = reo_mult × min_rtt / 16`，上限 srtt，至少 1 ms。min_rtt 是 10 s 窗口内的最小 RTT 样本，基准不用 srtt：拥塞时排队延迟会把 srtt 抬高，乱序窗口随之变大，丢包检测就失效了。起点取 min_rtt/16 而不是 RFC 的 min_rtt/4：实时业务对每次恢复多等的几十毫秒很敏感（RTT 200 ms 时 min_rtt/4 就是 50 ms），链路确有乱序时由下面的自适应放宽。**半可靠流始终用最小窗口**（不乘 reo_mult）：帧晚到与丢失一样，一次多余重传只多花一点带宽；放宽只作用于可靠流；
  - **自适应（Eifel，RFC 3522）**：分片记录最后一次发送是否为 RACK 重传。这样的分片被一个带 FRESH 的 ACK 确认、而该 ACK 的 ts_echo 早于那次重传的发送时间时，说明对端当时收到的最新数据报还在重传之前，确认的只能是原分片——那次重传是乱序造成的误判。此时 `reo_mult` 加倍（1、2、4、8、16，即窗口最大到 min_rtt），**每个 RTT 最多一次**：一次乱序往往同时造成几十上百个误判，逐个累加会立刻把窗口推到上限，而每次只加一档（min_rtt/16）在大窗口下又跟不上。连续 16 个 RTT 没有误判后，每个 RTT 减 1。只检查 RACK 重传：RTO 重传的重复（排队延迟、ACK 丢失）与乱序无关。演变过程见 13.11；
- **RACK 重传触发**：`ssthresh = max(inflight / 2, 2)`，`cwnd = ssthresh + resend`；每次 flush 最多触发一次；
- **RTO 丢包触发**：`ssthresh = max(inflight / 2, 2)`，`cwnd = init_cwnd`（ikcp 为 1）；每次 flush 最多触发一次；
- 半可靠流发送端**主动丢帧不算丢包事件**，不影响 cwnd；
- `nc = 1` 时不受 cwnd 限制，但仍受 pacer 限制。

**发送限制**：

- 单个流：`min(snd_wnd, rmt_wnd)`；
- 所有流合计的新数据：不超过上述预算；
- 所有数据报：受 6.7 的速率限制。

**接收缓冲总量上限** `rcv_limit_bytes`（默认 16 MB，0 表示不限）：连接内所有流 rcv_buf + rcv_queue 的字节数之和达到上限时，所有流在 ACK 中通告 `wnd = 0`，低于上限的 3/4 后恢复正常通告。每流 rcv_wnd 的最坏情况是 `64 × rcv_wnd × mss`（默认配置下约 46 MB），服务端不能依赖它作为内存上界。

### 6.4 flush 调度顺序

每次 flush 按以下顺序组包，包装满 MTU 就输出，再开下一个包；所有带数据的数据报都受 6.7 的令牌桶约束，令牌用尽即停止本次 flush 的后续步骤：

1. 所有流的 ACK（包括窗口探测和窗口回复）——**不消耗令牌**；
2. 所有待发的 CTRL（STREAM_OPEN / STREAM_CLOSE / RST）和 FWD——不消耗令牌；
3. **所有流的重传分片**：先默认流，再按优先级从高到低访问各流，流内按 sn 顺序，不受权重和 cwnd 限制。**重传状态（RTO 退避、resendts、fastack）只在分片真正发出时才修改**：因 pacing 令牌不足或重传配额用尽而推迟的重传，不能先被退避一次——v0.4 草案的实现先退避再检查令牌，视频占满令牌时控制流的超时重传每次都被推迟且 RTO 翻倍，控制流停滞数十秒（见 13.6）。若此时还有新数据待发，重传最多使用本次可用令牌的 **3/4**，剩余留给新数据（重传用满 3/4 只结束重传步骤，**不得**阻止第 4 步发送新数据）；没有新数据时可以用满。这样低优先级流的重传不会被高优先级流的新数据饿死，反过来，一条丢包严重的大流也不能在 cwnd 最小时用重传占满带宽，把实时流的新数据挤掉；
4. **新数据**：受 cwnd 预算限制。**默认流严格优先**，先发完它的可发数据；其余流按优先级**加权轮询**，`prio` 0~3 对应权重 **8 : 4 : 2 : 1**：
   - 每一轮中，每个流最多发送 `weight` 个分片，然后轮到下一个流；
   - 某个流没有数据或窗口用尽时跳过，其配额不转让给其他流；
   - 所有流都无数据可发、预算用尽或令牌用尽时结束；
5. FEC 校验段：块封块时（见 8.2）在同一次 flush 中紧跟数据发出，消耗令牌并占用预算。

v0.1 的严格优先级会让低优先级流零带宽，改为加权轮询后高优先级仍占大部分带宽，但低优先级流保有最小份额。

**ACK 驱动发送**（仅 `nc = 1`）：`anl_input` 处理完一个数据报后，若其中的 ACK 确认了分片且有新数据可发，或者 RACK 判定了丢包，立即执行一次完整的 flush（仍受 pacing 约束），而不是等下一个 interval。nc = 0 时不启用：ikcp 式的 cwnd 没有时延信号，每个 ACK 都发送会让瓶颈队列一直处于满载，优先级测试中控制流的重传在队尾被反复丢弃，p99 从约 380 ms 恶化到 2.3 s（13.11）。否则窗口受限时，每个窗口往返都要多等最多一个 interval：RTT 20 ms、interval 10 ms 时吞吐只有窗口上限的 2/3。代价是 flush 次数随 ACK 增加；流很多时每次 flush 都要遍历所有流。

### 6.5 半可靠流的即时发送

`opt.flush_on_send`（半可靠流默认 1，可靠流默认 0）：`anl_send_frame` 成功后立即执行一次 flush，而不是等到下一次 `anl_update`。实时媒体场景下 interval 造成的排队延迟因此可以忽略。令牌不足时本次 flush 只发出令牌允许的部分，其余在 `anl_check` 给出的时间点继续，因此不会因多条流各自触发 flush 而产生突发。

`interval` 默认改为 **20 ms**（ikcp 为 100）。ikcp 的默认值面向吞吐场景，本协议的目标场景是实时流，100 ms 的重传检查周期偏慢。

**重入规则**：`anl_send_frame`（flush_on_send）、`anl_input`（ack_nodelay，见 5.3）和 `anl_flush` 都可能在调用栈内同步调用 output 回调。output 回调中**不得**调用任何 `anl_*` 函数，只能把数据交给 socket 或队列，与 ikcp 的约定相同。

### 6.6 连接存活

- **dead_link**：以下任一计数达到 `dead_link`（默认 20）时连接进入 `dead` 状态，`anl_state()` 返回 -1：可靠流某个分片的重传次数 `xmit`；某个 FWD 的重发次数；某个 STREAM_CLOSE 的重发次数。STREAM_OPEN 的重发**不计入**（见 6.1）。`dead` 之后 `anl_input` 仍可处理数据报（用于诊断），但 flush 不再发送，所有发送接口返回 `ANL_EDEAD`。半可靠流的数据分片被丢帧机制回收，不会触发 dead_link；
- dead_link 是连接级的：任一可靠流的对端消失都会拖死整条连接。这是刻意的简化——同一连接的两端要么都活着要么都不在，单个流"对端消失"只可能来自实现 bug 或未按 6.1 走关闭流程；
- **idle_timeout_ms**：超过该时长没有收到任何通过认证的数据报，连接进入 `dead`。默认值按角色区分：`ANL_ROLE_SERVER` 为 30000，`ANL_ROLE_CLIENT` 为 0（关闭）。服务端默认开启是为了回收 3.4 中由重放包制造的僵尸连接；
- **keepalive_ms**（默认 0 即关闭）：超过该时长没有发出任何数据报时，发一个 0 段的数据报。keepalive 数据报**始终带填充**（即使 `pad_max = 0` 也至少填 1..16 字节），否则它是固定 21 字节的协议指纹。与 idle_timeout 配合使用时建议 `keepalive_ms < idle_timeout_ms / 3`。

### 6.7 发送速率限制（pacing）

ikcp 在 flush 时把窗口允许的分片一次性全部发出。对实时视频，一个几百分片的 I 帧就是一个几百 KB 的突发，浅缓冲路由器上突发丢包是最常见的丢包来源，而 8+1 FEC 无法恢复整块连续丢失。因此所有带数据的数据报都经过一个连接级令牌桶：

- **速率** `pace_rate`（字节/秒）：`cfg.pace_rate` 非 0 时使用该固定值；为 0 时自动估算：
  ```
  W    = cwnd                          （nc = 0）
       = Σ min(snd_wnd, rmt_wnd)       （nc = 1，对所有 open 状态的流求和）
  rate = 1.25 × W × mss / srtt         （srtt 尚无样本时按 rto 初值 200 ms 计）
  ```
  1.25 的增益让发送略快于当前窗口对应的速率，避免 pacer 本身成为瓶颈，与 BBR 的 startup 之外的 pacing_gain 同量级；
- **桶容量** `pace_burst`（字节，默认 `4 × mtu`）：允许连续发出的最大字节数，用于容纳一个 flush 内多个小段的打包和 ACK 捎带，不是为了放行整帧；
- **令牌补充**：每次 flush 开始时按 `rate × (now - pace_last)` 补充。空闲时积累的令牌上限为桶容量；但上一次 flush 因令牌不足而停止（有数据在等令牌）时，上限放宽为 `rate × min(now - pace_last, interval)`。否则每次补充最多只有桶容量，吞吐被封顶在"桶容量 / 调用间隔"，与计算出的速率无关：1 ms 时钟下约 7 MB/s（13.11）；
- **消耗**：每个带 DATA 或 PARITY 的数据报按其线上长度（含 tag 和填充）消耗令牌，令牌不足时该数据报不发，本次 flush 到此为止；ACK / CTRL / FWD / keepalive 数据报不消耗令牌；
- **调度**：`anl_check` 返回值取 ikcp 原有结果与"下一个数据报的令牌何时凑齐"两者中较早者。因此 pacing 的时间精度取决于应用调用 `anl_update` 的频率：只按 interval（20 ms）调用时，每 20 ms 发一批；要得到平滑的发送，应用应按 `anl_check` 的返回值驱动定时器，实时场景建议 1~5 ms 精度；
- **与丢帧的关系**：pacer 只是把突发摊平，不增加总带宽。编码码率高于 `pace_rate` 时帧会在 snd_queue 里堆积，最终由 max_age_ms / max_bytes 丢弃——这正是需要的背压。应用应通过 `anl_get_stats().pace_rate` 和 `backlog_bytes` 调整编码码率；
- **与 nc=1 的关系**：nc=1 关闭的是 cwnd 对新数据的限制，pacing 仍然生效。要完全关闭 pacing，设 `cfg.pace_rate = -1`。
- **nc=1 必须配合低于瓶颈带宽的固定 `pace_rate`**：nc=1 时自动速率按各流窗口估算（1.25 × Σ窗口 / srtt），与链路带宽无关。发送量超过瓶颈带宽时，丢包发生在网络队列里，控制流和视频流一起被丢，加上 RTO 退避会出现拥塞崩溃，发送端的优先级无能为力（见 13.6 的测试数据）。

---

## 7. 半可靠流（帧模式）

### 7.1 帧号

- `frame_no` 由协议按流自动分配，从 0 开始，每帧加 1，通过 `anl_send_frame` 的出参返回给应用；
- 应用自己的时间戳（如 PTS）请放在负载里；
- 线上只带低 16 位。接收方扩展为 32 位时，**参考值取已收到（含 rcv_buf 中首片）的最大 frame_no**，而不是最近一次交付的帧。这样长时间断网、丢弃了大量帧之后，只要重新收到的帧号与最近看到的帧号相差不超过 32767，扩展仍然正确。

这样设计的好处：接收方看到帧号跳变，就能精确算出丢了几帧，包括发送端还没发出就被丢弃的帧。

### 7.2 发送

`anl_send_frame(w, sid, flags, buf, len, &frame_no)`：

1. 分配 frame_no；
2. 按 mss 切片；首片设置 HAS_FRAME，关键帧再设置 KEY；
3. 记录入队时间和 `first_sn` 占位，放入 `snd_queue`；
4. 分片数不能超过 `rcv_wnd`（由打开方决定、两端相同，见 6.1），否则返回 `ANL_ETOOBIG`。**大 I 帧需要相应调大 rcv_wnd。** 半可靠流的 snd_wnd / rcv_wnd 默认均为 512：snd_wnd 若小于一帧的分片数，一帧要跨多个发送窗口，至少多花 1 个 RTT 才能发完；
5. 若 `flush_on_send` 为 1，立即 flush（受 pacing 约束，见 6.7）。

### 7.3 发送端丢帧

每次 `anl_send_frame` 和每次 flush 时都会检查：

| 条件 | 处理 | 配置项 |
|---|---|---|
| 积压字节数（snd_queue + snd_buf 中未确认的部分）超过 `max_bytes` | 丢弃**最老的整帧**，无论它是否已发出 | `max_bytes`，0 表示不限 |
| **尚未完整发出**的帧（仍有分片在 snd_queue）入队超过 `max_age_ms` | 丢弃该帧；若它已有分片发出，同时放弃所有更老的帧并发 FWD | `max_age_ms`，0 表示不限 |
| **已完整发出**的帧超过 `max_age_ms` | 不丢弃、不发 FWD；正常确认则结束。若它的某个分片需要重传（RTO 超时或快速重传触发），**不再重传**，改为放弃该帧及所有更老的帧并发 FWD | 同上 |

`max_age_ms` 的含义因此是"超过这个时间就不值得再发（包括重传）"，而不是"超过这个时间还没被确认就丢"。v0.3 的实现按后者处理：RTT 大于 max_age 时，每一帧在确认前都会被"丢弃"——失去重传机会、每帧触发一次 FWD，音频流在 0% 丢包、RTT 300 ms 的链路上约 7 s 即被判死（见 13.5）。

"放弃该帧时一并放弃所有更老的帧"是为了保持被放弃的 sn 为未确认区间的前缀：FWD 的语义是"new_una 之前全部放弃"，若只放弃较新的帧，接收端会把仍在途的较老帧一起跳过。由于帧按入队顺序老化，较老的帧此时也已超龄。

**`drop_until_key`（可选）**：一旦有帧被丢弃，后续非关键帧也一并丢弃，直到出现下一个关键帧：

- 已在队列中的非关键帧：直接丢弃；
- 新提交的非关键帧：返回 `ANL_EDROPPED`，但仍然占用一个 frame_no。应用收到这个返回值后，可以请求编码器立即出一个关键帧。

**丢弃规则**：

- 丢弃始终是整帧；
- 帧还在 `snd_queue` 中时，没有分配 sn，丢弃后不会在序号上留下空洞；
- 帧已有分片分配过 sn 时（无论这些分片还在 snd_buf，还是已被确认移除，只剩尾部在 snd_queue）：
  - 移除它在 snd_buf 和 snd_queue 中的所有分片，停止重传；
  - 必须发 FWD。若只看 snd_buf，"首片已确认、尾部仍在 snd_queue"的帧会被静默丢弃，接收端 rcv_queue 里留下半截帧；
  - `snd_una` 照常取 snd_buf 中最小的 sn（没有时为 `snd_nxt`）；
  - **FWD 的 `new_una` 取第一个存活帧的 `first_sn`**（没有存活帧时为 `snd_nxt`），并标记 FWD 待发。

注意 `new_una` 不能取"第一个存活分片的 sn"：ikcp 是 SACK 式逐段确认，存活帧的首片可能已被单独确认并从 snd_buf 移除，此时第一个存活分片是该帧的第 2 片，new_una 会越过首片，接收端按 7.5 丢弃 sn < new_una 的分片时会把已收到的首片一起丢掉，整帧作废且失去 HAS_FRAME 无法再同步。

### 7.4 FWD 的可靠性

- 发送端只维护**一个**待发的 `new_una`，多次丢帧时取最大值；
- FWD 从 RTO 起按数据分片的规则**退避**重发，直到收到的 ACK 中 `una ≥ new_una`；重发次数计入 dead_link。固定以 RTO 为周期时，只要有半可靠流在丢帧，约 2 秒的断网就会让连接被判死（每次都能复现）。**收到的 ACK 中 una 有推进时，重发计数清零**：持续拥塞下发送端不断丢帧，new_una 一直前移，对端的 una 永远追不上最新值，若不清零，计数会跨越多个 new_una 累加，约 20 个 RTO 后把一条正常的连接判死；
- 接收端收到 FWD 后必须排一个 ACK（5.3），否则在发送端暂时没有新数据时（例如 `drop_until_key` 等待关键帧）FWD 永远得不到确认；
- 如果 ACK 中的 una 落后于发送方的 snd_una，发送方忽略它。

### 7.5 接收端

**收到 FWD(new_una) 时**：

1. 若 `diff(new_una, rcv_nxt) ≤ 0`，忽略该 FWD（但仍排一个 ACK）。FWD 每 RTO 重发一次，乱序或重复到达的旧 FWD、或接收端已经自行跳过的情况下，`rcv_nxt` 决不能倒退；
2. 丢弃 `rcv_buf` 中所有 sn < new_una 的分片；
3. 丢弃 `rcv_queue` 尾部不完整的帧；
4. 令 `rcv_nxt = new_una`；
5. 继续把 rcv_buf 中连续的分片移入 rcv_queue；
6. 排一个 ACK。

**接收端截止时间（可选，`rcv_deadline_ms`，0 表示关闭）**：

- 触发条件：`rcv_nxt` 处有空洞，且 rcv_buf 中空洞之后已有数据，这种阻塞状态持续超过 `rcv_deadline_ms`。计时从空洞出现时开始，只有 `rcv_nxt` 前进才重新计时——v0.4 草案的实现每收到一个分片就重新计时，持续发送的流（到达间隔小于 deadline）永远不会触发跳过；
- 处理方式：接收端主动跳到空洞之后第一个带 HAS_FRAME 的分片，并立即排一个 ACK；
- 跳过之后，ACK 中的 una 前移。发送方按 ikcp 的 `parse_una` 逻辑移除 una 之前的分片，相当于这些分片被放弃。una 的语义因此统一为"接收方不再需要该 sn 之前的任何数据"。

**`anl_recv_frame` 返回的 `anl_frame_info`**：

| 字段 | 含义 |
|---|---|
| `frame_no` | 32 位帧号，由 16 位线上值扩展得到 |
| `flags` | 是否关键帧（KEY） |
| `lost_before` | 与上一次交付的帧之间丢了几帧，等于 `frame_no - last_frame_no - 1` |

**组帧校验**：交付前检查 rcv_queue 中构成一帧的 `frg + 1` 个分片 sn 连续、frg 逐一递减，且除首片外不带 HAS_FRAME。不满足时丢弃到下一个帧起点，计入 `frames_skipped`，决不把两帧拼接后交付。发送端规则正确时不会触发，这是防御性检查。

可靠流不允许跳过，FWD 和接收端截止时间都只对半可靠流生效。

### 7.6 关键帧与参考帧依赖

视频的非关键帧（P 帧）依赖前面的帧，一旦前面某帧丢失，直到下一个关键帧之前的 P 帧都无法解码。协议在两端各提供一个选项，默认都关闭：

**发送端 `drop_until_key`**：

- 任何一帧被丢弃（超龄、超过 max_bytes、已发帧需重传时超龄）后进入"等待关键帧"状态；
- 丢弃时一并丢弃其后直到下一个关键帧之间的非关键帧，**包括已经发出、仍在 snd_buf 中等待确认的**——它们即使送达也无法解码，继续重传只会浪费带宽；最后只发一个 FWD，new_una 取第一个存活帧的 first_sn（首片已确认、只剩尾部在 snd_queue 的帧取 cur_first_sn）；
- 为此每个分片都记录本帧是否关键帧（线上只有首片带 KEY 标志，首片可能已被确认移除）；
- 之后提交的非关键帧返回 `ANL_EDROPPED`（仍占用 frame_no），直到应用提交关键帧。应用据此让编码器立即产生关键帧。

**接收端 `rcv_drop_until_key`**：

- 交付前检查：若下一帧不是关键帧，且它与上一次交付的帧之间有缺口（`frame_no != last_delivered + 1`），则丢弃该帧（包括它已到达的分片），计入 `frames_discarded`，并继续检查下一帧，直到遇到关键帧；
- 被丢弃的帧计入下一个交付帧的 `lost_before`，`frame_no` 连续性与"交付数 + lost_before 之和 = 最后帧号 + 1"的统计关系保持不变；
- 缺口可能来自网络丢失后发送端放弃、接收端 `rcv_deadline` 跳过，或发送端的 FWD，接收端不区分来源。

**关键帧请求不在协议内实现**：接收端何时请求关键帧、发送端如何响应（立即编码、限速、与 GOP 的配合）由应用层决定。应用可以根据 `lost_before`、`frames_discarded` 的变化，或发送端的 `ANL_EDROPPED`，通过自己的控制流（例如一个高优先级的可靠流）传递请求。

B 帧（不被参考的帧，丢失不影响后续解码）不做特殊处理：丢失任何非关键帧都视为参考链中断。

---

## 8. 流级 FEC（8+1 XOR，可交错）

### 8.1 适用范围

- 按流配置：`opt.fec = 1` 开启，**默认关闭**；
- 只保护 DATA 段，并且只在分片**首次发送**时编入校验组，重传不再参与；
- 校验段不需要确认，也不重传；
- 校验段占用 flush 的发送预算（6.3）和 pacing 令牌（6.7），但不计入 inflight。

> 权衡说明：FEC 每组额外占用约 1/8 的带宽，默认关闭。不过在实时场景下，重传通常来不及，所以 WebRTC 等系统常对音频启用 FEC。这是一个按流的开关，可以按场景实测后再决定。**要让 FEC 优于 ARQ，`fec_flush_ms` 必须明显小于 RTT**，否则校验段到达时重传已经在路上了。

### 8.2 分组与交错（发送端）

设交错深度为 `D`（`fec_depth`，取值 1..16，默认 1）。

- 以 **块** 为单位组织，一个块包含 D 个组，最多 8×D 个连续的 sn；
- 块的起始 sn 为 S，组 j（0 ≤ j < D）的成员为 `S + j + i*D`（i = 0..7）；
- 分片按 sn 顺序首次发送，因此依次轮流落入各组；
- **封块条件**（满足任一即可）：
  1. 块中已放满 8×D 个分片；
  2. 自块中第一个分片发出起，已超过 `fec_flush_ms`（**默认 `min(interval, 20)`**；v0.1 默认等于 interval=100，对 20 ms 音频帧意味着校验段至少 100 ms 后才到，比重传还慢）。
- 封块时，每个非空的组各发一个 PARITY，组内成员数 k 可以小于 8；
- 下一个块从下一个 sn 开始。

### 8.3 PARITY 段

```
 b0    : 11 | sid
 b1    : 0x01（PARITY）
 len   : varint       = 3 + Lmax（CTRL 通用长度字段）
 base  : u16          组内第一个成员的 sn
 kd    : 保留(1) | (k-1)(3) | (D-1)(4)     k = 1..8，D = 1..16
 payload[Lmax]        Lmax = 组内规范编码的最大长度
```

组内成员为 `base + i*D`（i = 0..k-1）。

**规范编码**：参与 XOR 运算的是每个 DATA 分片的规范编码，不足 Lmax 的部分补 0：

```
C(seg) = b1（清除 OPEN）| [frg_ext] | [frame u16] | plen u16 | payload
payload_parity = C(seg_0) XOR C(seg_1) XOR ... XOR C(seg_{k-1})
```

**MTU 预留**：开启 FEC 的流，其 mss 要比连接的 mss 小 `ANL_FEC_OVERHEAD`（12 字节），保证校验段也能放进一个数据报。

### 8.4 恢复（接收端）

- 开启 FEC 的流维护一个缓存，保存最近 `2 × 8 × D` 个分片的规范编码。按 D=1、mss=1400 估算，约占 22KB；D=16 时约 350KB，按流计；
- **校验段先于成员到达时不丢弃**：缓存该校验段，直到组内最后一个成员 sn 到达、或经过 1 个 RTO，再做一次判断。缓存的校验段数量以 2 个块为上限；
- 判断组内 k 个成员：
  - 恰好缺 1 个，且该 sn **不小于 `rcv_nxt`**、不在 rcv_buf 中、也没有被确认过：用校验负载与其余成员做 XOR，恢复出规范编码，再还原为 DATA 分片，按正常收包流程处理；
  - 缺的那个 sn 已小于 `rcv_nxt`（被 FWD 或 rcv_deadline 跳过）：不恢复，丢弃校验段；
  - 缺少超过 1 个：无法恢复，丢弃校验段；
  - 1 个都不缺：同样丢弃校验段；
- 恢复出的分片会触发 ACK，发送方随即停止重传该分片。

---

## 9. 可靠流

语义与 ikcp 相同：

- `anl_send` / `anl_recv` / `anl_peeksize` / `anl_waitsnd`；
- 通过 `opt.stream` 在字节流模式和消息模式之间切换；
- **消息模式下的分片数检查**：一条消息的分片数不能超过 `rcv_wnd`（两端相同），否则 `anl_stream_send` 返回 `ANL_ETOOBIG`。接收方必须凑齐整条消息才能交付，分片数超过它的接收窗口时永远凑不齐，rcv_buf 也无法排出，双方死锁。ikcp 有同样的检查（`count >= rcv_wnd`），v0.1 只对帧接口写了这条规则；
- 支持快速重传（`resend`）和 nodelay 选项；
- 在可靠流上调用帧接口，或在半可靠流上调用 `anl_send` / `anl_recv`，都返回 `ANL_EMODE`。

---

## 10. API 草案

线程模型与 ikcp 相同：一个 `anl_t` 的所有调用必须在同一线程或由调用方加锁串行化；不同 `anl_t` 之间无共享状态（`anl_allocator` 除外）。

```c
/* ---------- 返回码 ---------- */
#define ANL_OK          0
#define ANL_EINVAL     -1   /* 参数错误 */
#define ANL_EMODE      -3   /* 接口与流模式不匹配 */
#define ANL_EAGAIN     -4   /* 无数据可读 */
#define ANL_EBUFSIZE   -5   /* 接收缓冲区太小 */
#define ANL_ETOOBIG    -6   /* 超过 rcv_wnd 分片上限 */
#define ANL_EDROPPED   -7   /* 帧被丢弃（drop_until_key） */
#define ANL_EAUTH      -8   /* 认证失败：调用方必须静默丢弃，不得回应 */
#define ANL_ECONV      -9   /* conv 不匹配 */
#define ANL_EFORMAT   -10   /* 格式错误 */
#define ANL_ENOMEM    -11   /* 内存分配失败 */
#define ANL_ECLOSED   -13   /* 流已关闭 / 已到流末尾（含被对端 RST 或协议违规） */
#define ANL_ESTALE    -14   /* 数据报 ts 超出时间窗，已丢弃 */
#define ANL_EDEAD     -15   /* 连接已进入 dead 状态 */
#define ANL_EBUSY     -16   /* sid 用尽 */

/* ---------- 配置 ---------- */
#define ANL_ROLE_CLIENT 0
#define ANL_ROLE_SERVER 1
#define ANL_RELIABLE    0
#define ANL_SEMI        1
#define ANL_FRAME_KEY   1

typedef void (*anl_rng_fn)(void *user, uint8_t *buf, size_t n);

typedef struct anl_config {
    uint8_t psk[32];
    int role;                           /* ANL_ROLE_CLIENT / ANL_ROLE_SERVER，两端必须不同 */
    int mtu;                            /* 1400 */
    int pad_max;                        /* 32，0 关闭，上限 255 */
    anl_rng_fn rng;                     /* NULL 时使用内置 PRNG */
    int nodelay, interval, resend, nc;  /* 0, 20, 0, 0；interval 默认与 ikcp 不同 */
    int ack_nodelay;                    /* 1：每 2 个数据报立即回 ACK；0：等下一次 flush */
    int init_cwnd;                      /* 16 */
    int dead_link;                      /* 20 */
    int ts_window_ms;                   /* 1000，固定值 */
    int keepalive_ms;                   /* 0 关闭 */
    int idle_timeout_ms;                /* SERVER 30000 / CLIENT 0 */
    int pace_rate;                      /* 字节/秒；0 自动估算，-1 关闭 pacing */
    int pace_burst;                     /* 令牌桶容量，字节；0 表示 4 × mtu */
    int rcv_limit_bytes;                /* 连接级接收缓冲上限，16 MB；0 不限 */
    int max_peer_streams;               /* 对端同时打开的流数上限，1024；<= 8192 */
    int default_snd_wnd, default_rcv_wnd; /* 默认流窗口，1200 / 1200 */
} anl_config;

#define ANL_STREAM_OPENING  0   /* open，但尚未收到对端任何段（仅统计用） */
#define ANL_STREAM_OPEN     1
#define ANL_STREAM_CLOSING  2
#define ANL_STREAM_CLOSED   3

typedef struct anl_stream_opt {
    int mode;             /* ANL_RELIABLE / ANL_SEMI，打开方决定 */
    int prio;             /* 0..3，0 最高，默认 2；权重 8/4/2/1 */
    int snd_wnd, rcv_wnd; /* 可靠流 32 / 128；半可靠流 512 / 512；上限 8192；rcv_wnd 打开方决定 */
    int stream;           /* 仅可靠流：字节流模式，打开方决定 */
    int tag;              /* 0..65535，应用定义，打开方决定 */
    int flush_on_send;    /* 半可靠流默认 1，可靠流默认 0 */
    int fec;              /* 0 */
    int fec_depth;        /* 1..16，默认 1 */
    int fec_flush_ms;     /* 0 表示 min(interval, 20) */
    int max_age_ms;       /* 仅半可靠流，默认 500，0 表示不限 */
    int max_bytes;        /* 仅半可靠流，默认 0，即不限 */
    int drop_until_key;   /* 仅半可靠流，默认 0 */
    int rcv_deadline_ms;  /* 仅半可靠流，默认 0，即关闭 */
} anl_stream_opt;

typedef struct anl_frame_info {
    uint32_t frame_no;
    int      flags;        /* ANL_FRAME_KEY */
    uint32_t lost_before;
} anl_frame_info;

/* ---------- 统计 ---------- */
typedef struct anl_stats {
    uint32_t srtt, rttval, rto;         /* ms */
    uint32_t cwnd, ssthresh, inflight;  /* 分片数 */
    uint32_t retrans;                   /* 累计重传分片数 */
    uint32_t pace_rate;                 /* 当前生效的发送速率，字节/秒 */
    uint32_t rcv_bytes;                 /* 所有流接收缓冲占用字节数 */
    uint64_t tx_datagrams, rx_datagrams;
    uint64_t rx_auth_fail, rx_stale;    /* 认证失败 / 时间窗丢弃 */
} anl_stats;

typedef struct anl_stream_stats {
    int      state;             /* ANL_STREAM_OPENING .. ANL_STREAM_CLOSED */
    uint32_t wait_snd;          /* snd_queue + snd_buf 分片数 */
    uint32_t backlog_bytes;     /* 未确认字节数 */
    uint32_t rmt_wnd;
    uint32_t retrans;
    uint32_t frames_dropped;    /* 发送端主动丢弃的帧 */
    uint32_t frames_skipped;    /* 接收端因 FWD / deadline 跳过的帧 */
    uint32_t fec_recovered;
} anl_stream_stats;

void anl_config_default(anl_config *cfg, int role);
void anl_stream_opt_default(anl_stream_opt *opt, int mode);

/* ---------- 密钥与服务端分发 ---------- */
typedef struct anl_keys anl_keys;   /* sizeof 由 anl_keys_size() 给出，或在头文件中公开定义 */
void anl_keys_derive(anl_keys *keys, const uint8_t psk[32]);
int  anl_peek_conv(const anl_keys *keys, int role, const char *data, long size,
                   uint32_t *conv, char *plain);

/* ---------- 连接 ---------- */
anl_t   *anl_create(uint32_t conv, const anl_config *cfg, void *user);   /* conv 非零 */
void     anl_release(anl_t *w);
void     anl_setoutput(anl_t *w, int (*output)(const char *buf, int len, anl_t *w, void *user));
int      anl_input(anl_t *w, const char *data, long size);        /* 原始数据报 */
int      anl_input_plain(anl_t *w, const char *plain, long size); /* 已由 anl_peek_conv 验证的明文 */
void     anl_update(anl_t *w, uint32_t current);
uint32_t anl_check(const anl_t *w, uint32_t current);
void     anl_flush(anl_t *w);
int      anl_state(const anl_t *w);                               /* 0 正常，-1 dead */
int      anl_get_stats(const anl_t *w, anl_stats *out);
void     anl_allocator(void *(*new_malloc)(size_t), void (*new_free)(void *));

/* ---------- 默认流（sid 0，随连接创建，可靠字节流，严格优先，不可关闭） ---------- */
int      anl_send(anl_t *w, const char *buf, int len);
int      anl_recv(anl_t *w, char *buf, int len);
int      anl_peeksize(const anl_t *w);
int      anl_waitsnd(const anl_t *w);
anl_stream_t *anl_default_stream(anl_t *w);

/* ---------- 流句柄（生命周期同 socket：open / accept 到 close） ---------- */
typedef struct anl_stream anl_stream_t;
typedef int (*anl_accept_fn)(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user);
void     anl_set_accept(anl_t *w, anl_accept_fn accept);   /* NULL：按默认参数接收全部 */
anl_stream_t *anl_stream_open(anl_t *w, const anl_stream_opt *opt, int *err);
int      anl_stream_close(anl_stream_t *s);
int      anl_stream_send(anl_stream_t *s, const char *buf, int len);
int      anl_stream_recv(anl_stream_t *s, char *buf, int len);          /* 流结束：ANL_ECLOSED */
int      anl_stream_send_frame(anl_stream_t *s, int flags, const char *buf, int len, uint32_t *frame_no);
int      anl_stream_recv_frame(anl_stream_t *s, char *buf, int len, anl_frame_info *info);
int      anl_stream_peeksize(const anl_stream_t *s);
int      anl_stream_waitsnd(const anl_stream_t *s);
int      anl_stream_get_stats(const anl_stream_t *s, anl_stream_stats *out);
int      anl_stream_id(const anl_stream_t *s);
int      anl_stream_tag(const anl_stream_t *s);
anl_t   *anl_stream_conn(const anl_stream_t *s);
void     anl_stream_set_user(anl_stream_t *s, void *user);
void    *anl_stream_get_user(const anl_stream_t *s);
int      anl_readable(anl_t *w, anl_stream_t **out, int max);
```

---

## 11. 与 ikcp 对比

| 项目 | ikcp | AnLiu |
|---|---|---|
| 头部开销 | 每段固定 24 字节 | 每个数据报 21 字节（含 12 字节认证），每个 DATA 段 5~7 字节 |
| 单段数据报的总开销 | 24 字节 | 约 25~27 字节，已包含认证和加密；多段打包时摊薄 |
| 加密 | 无 | SIV（ChaCha20 + SipHash-2-4-128 截断 12 字节），PSK，按方向密钥 |
| 多流 | 无，需每个 conv 一个实例 | 8192 个 sid，两端可随时开关，自动接收；共享拥塞窗口和 ACK 打包 |
| sn 位宽 | 32 位 | 线上 16 位，内部 32 位，配合 ts 时间窗 |
| 可靠性 | 全可靠 | 按流选择：可靠 / 半可靠（帧） |
| FEC | 无 | 按流开关的 8+1 XOR，可交错 |
| 窗口探测 | 独立的 WASK/WINS 命令 | 并入 ACK |
| RTT 采样 | 每段带 ts，ACK 回显 | 每个数据报带 ts，ACK 回显，每收到一个数据报最多一个样本 |
| 调度 | 单流 | 重传优先（上限 3/4），新数据按 8/4/2/1 加权轮询 |
| 发送节奏 | flush 时整窗突发 | 连接级令牌桶 pacing |
| ACK 时机 | 下一次 flush | 默认每 2 个数据报立即回 ACK |
| 流生命周期 | 无 | 首个段携带流参数（无握手）、带 final_sn 的有序关闭、RST 式回应 |
| 存活检测 | dead_link | dead_link + 可选 keepalive / idle_timeout（服务端默认 30 s） |

---

## 12. 实现计划

| 阶段 | 内容 |
|---|---|
| M1 | `anliu.h`：线格式常量、结构体、完整 API |
| M2 | 加密层（ChaCha20、SipHash-2-4-128、SIV、按方向 KDF、内置 PRNG）+ 包层组包与解包 + 时间窗 + `anl_keys` / `anl_peek_conv` / `anl_input_plain`。**必须带已知答案测试**：ChaCha20 用 RFC 8439 向量，SipHash-2-4-128 用官方参考向量；SIV 组合没有标准向量，用回环一致性测试和一份独立的参考实现（脚本即可）互测 |
| M3 | 流层可靠流：移植 ikcp 核心逻辑，改为多流共享 cwnd（6.3 规则）、重传不受 cwnd 限制、加权轮询、pacing 令牌桶、ack_nodelay、首段携带流参数、带 final_sn 的有序关闭与 RST、dead_link、keepalive、rcv_limit_bytes、统计接口 |
| M4 | 半可靠流：帧、丢帧、FWD（first_sn、单调性、ACK 触发）、接收端截止时间 |
| M5 | 流级 FEC 与交错，校验段缓存 |
| M6 | `test.c`：本地回环模拟器（可配置丢包、乱序、延迟、重复、反射、带宽/缓冲深度），覆盖各项特性。重点用例：FWD 乱序/重复、首片已确认后的丢帧、反射包、时间窗外旧包、流参数不一致、CLOSE 丢失后的 RST 收敛、突发丢包后的重传不被 cwnd 卡死、pacing 下 I 帧的发送时序、ack_nodelay 对 RTT 估计的影响。另外两项：**段解析 fuzz**（认证只证明对端持有 PSK，不证明对端实现无 bug，畸形段不得越界）；**未认证包洪泛的 CPU 开销实测**（3.7） |

预估规模：`anliu.c` 约 3000 行（v0.5 实现 3008 行）。

---

## 13. 评审结论

### 13.1 第一轮（2026-09-25）

| 项目 | 结论 |
|---|---|
| 多流 | 协议内管理，最多 64 个流，type 与 sid 合用 1 字节，每流独立 sn |
| sn | 16 位回绕 |
| 半可靠丢帧 | 按存活时间和积压字节数触发；支持 drop_until_key |
| frame_no | 由协议自动分配 |
| max_age_ms | 默认 500 |
| 优先级 | 4 级 |
| FEC | 流级，默认关闭，可配置交错深度 |
| CTRL 段 | 带 varint 长度字段，未知子类型可跳过 |
| 接收接口 | 按 sid 读取，配合 64 位可读位图 |
| 发送接口 | 可靠数据用 `anl_send`（参考 ikcp），帧用独立的 `anl_send_frame` |

### 13.2 第二轮（2026-09-25）修订项

| 问题 | 修订 | 章节 |
|---|---|---|
| 双向同密钥可被反射攻击 | 按方向派生密钥，配置增加 role | 3.1 |
| 8 字节 SIV 标签的 nonce 生日界仅 2^32 | SipHash-2-4-128 截断 12 字节，生日界 2^48；PSK 上限 2^40 数据报 | 3.2, 3.7 |
| `ANL_ENC_HEADER` 暴露段头且收益低 | 删除，仅保留整包加密 | 3.2 |
| `anl_peek_conv` 使服务端 crypto 翻倍 | `anl_keys` + peek 输出明文 + `anl_input_plain` | 3.4 |
| 填充缺随机源、pad_max 无上限、ACK-only 包长固定 | rng 回调 / 内置 PRNG；pad_max ≤ 255，默认 32 | 3.5 |
| 16 位 sn 回绕后旧包被当新包 | ts 时间窗检查（PAWS）；写明速率上限 | 4.2 |
| FWD 可使 rcv_nxt 倒退 | `diff(new_una, rcv_nxt) ≤ 0` 时忽略 | 7.5 |
| new_una 定义与丢帧规则矛盾 | new_una = 第一个存活帧的 first_sn，与 snd_una 分离 | 5.4, 7.3 |
| FWD 无 ACK 触发，无法收敛 | 收到 FWD / deadline 跳帧后必须排 ACK；只维护最大 new_una | 5.3, 7.4 |
| 流参数不一致无校验；sid 重用致序号错乱 | STREAM_OPEN / STREAM_CLOSE；错误状态；sid 不可重用 | 5.5, 6.1 |
| 多流 cwnd 规则缺失；慢启动从 1 开始与半可靠流冲突 | 明确 inflight / 增长 / 上限 / 丢包规则；init_cwnd 16；校验段占预算 | 6.3 |
| 严格优先级饿死低优先级 | 重传优先；新数据 8/4/2/1 加权轮询 | 6.4 |
| 缺统计接口、dead_link、keepalive | `anl_get_stats` / `anl_get_stream_stats` / `anl_state`；dead_link、idle_timeout、keepalive | 6.6, 10 |
| interval 100 ms 对实时流过慢 | 默认 20 ms；半可靠流 flush_on_send | 6.5 |
| frame_no 扩展参考值在长断网后歧义 | 参考值取已收到的最大 frame_no | 7.1 |
| 同一数据报多个 ACK 重复 RTT 采样 | 每数据报最多一个样本 | 5.3 |
| FEC 封块描述不一致；fec_flush_ms 默认过大；校验段先到即丢；恢复出已跳过的 sn | 统一为封块时发；默认 min(interval, 20)；缓存校验段；sn < rcv_nxt 不恢复 | 6.4, 8.2, 8.4 |
| varint、conv 非零、线程模型、版本号局限未写明 | 补齐 | 4, 4.1, 10 |

### 13.3 第三轮（2026-09-25）修订项

前 3 条是 v0.2 引入的错误，其余是 v0.1 就存在但上一轮未覆盖的问题。

| 问题 | 修订 | 章节 |
|---|---|---|
| 重传受 cwnd 预算限制，突发丢包后卡死 | 重传不受 cwnd 限制，只受 pacing；有新数据时最多占令牌的 3/4 | 6.3, 6.4 |
| FWD / deadline 跳帧引起的 una 前进触发 cwnd 增长，形成正反馈 | 只有 parse_ack 实际确认分片才增长 | 6.3 |
| ts_window 与 4×RTO 挂钩，RTO 上限 60 s 时保护失效 | 固定为 ts_window_ms | 4.2 |
| 对端重启后被时间窗永久拒绝 | 规定重启必须换 conv，不做自愈 | 4.2, 3.4 |
| CLOSE 丢失或懒打开使对端重传到 dead_link，拖死整条连接 | OPEN 指数退避且不计 dead_link；收到 OPEN 前数据留在 snd_queue；已关闭 sid 收到段时回 RST 式 CLOSE（每 RTO 一次） | 6.1, 6.6 |
| sid 不可重用限制 | 保留简单方案，不引入 generation；写明一条连接最多 64 个流 | 6.1 |
| 关闭丢弃未确认数据 | STREAM_CLOSE 携带 final_sn；closing 状态继续重传到全部确认；全双工同时关闭 | 5.5, 6.1 |
| flush 整窗突发 | 连接级令牌桶 pacing：速率自动估算或固定，桶容量 4×mtu，anl_check 纳入令牌时间 | 6.7 |
| 大流重传在 cwnd 最小时挤掉实时流新数据 | 重传占令牌上限 3/4 | 6.4 |
| 可靠流消息模式缺分片数检查，可能死锁 | anl_send 按 peer_rcv_wnd 检查，返回 ETOOBIG | 9 |
| 半可靠流 snd_wnd 256 小于典型 I 帧 | 默认 512 | 7.2, 10 |
| 接收缓冲无连接级上限 | rcv_limit_bytes 默认 16 MB，超限通告 wnd=0 | 6.3 |
| 只收不发的端 ACK 延迟 = interval | ack_nodelay 默认 1，每 2 个数据报立即 ACK | 5.3 |
| 服务端隐式建连可被重放制造僵尸连接 | 服务端 idle_timeout 默认 30 s；要求应用限速建连、conv 分配规则 | 3.4, 6.6 |
| 未认证包处理开销未说明 | 写入安全性说明，M6 实测 | 3.7 |
| flush_on_send / ack_nodelay 的重入 | output 回调中不得调用 anl_*；pacing 消解多流各自 flush 的碎包 | 6.5 |
| 错误状态不可恢复 | 写明，随 sid 不可重用一并接受 | 6.1 |
| PRNG 在首次 update 前不可用 | 种子在 anl_create 确定，current 事后混入 | 3.5 |
| keepalive 固定 21 字节指纹 | keepalive 强制带填充 | 6.6 |
| 实现风险 | M2 加 KAT；M6 加 fuzz 与洪泛开销实测 | 12 |

### 13.4 实现记录（anliu.c / test.c）

参考实现 `anliu.c`（约 2600 行，C99，无外部依赖）与自测 `test.c`（`#include "anliu.c"`，含环回网络仿真器）。测试内容：

- RFC 8439 ChaCha20 块函数与加密向量、SipHash-2-4-128 参考向量、SIV 往返/反射/篡改；varint 边界；
- `anl_peek_conv` + `anl_input_plain` 的服务端分流路径；
- 可靠流：消息模式与字节流模式、双向同时发送、0% / 10% 丢包 + 2% 重复；
- 半可靠流：无损、5% 丢包、5% 丢包 + FEC(8+1, D=2)、1 Mbps 瓶颈链路（验证发送端丢帧与 `lost_before` 计数）；
- 反射攻击、时间窗重放、流参数不一致、先开流后对端打开 + 有序关闭（0% / 15% 丢包）、pacing 突发上限、20000 个变异明文的模糊测试；
- 全部在 `-fsanitize=address,undefined` 下通过。

实现过程中发现并修正的设计遗漏（已同步到正文）：

| 问题 | 处理 | 章节 |
|---|---|---|
| 两端互相回显 STREAM_OPEN 形成永不停止的乒乓 | OPEN 的 mode 字节 bit7 = ACK，带 ACK 的 OPEN 不再回显 | 5.5, 6.1 |
| RST 式 CLOSE 与普通 CLOSE 重发无法区分，迟到的重发会导致提前释放 | CLOSE 增加 `flags(u8)`，bit0 = RST | 5.5, 6.1 |
| `closed` 判定只在收到 CLOSE 时执行，“CLOSE 先到、数据后到”时流永远停在 `closing` | 收到 DATA / ACK 时也判定；释放前先发出最后的 ACK | 6.1 |
| 可靠流 `final_sn = snd_nxt` 未计入 snd_queue 中尚未搬运的数据 | `final_sn = snd_nxt + nsnd_que` | 6.1 |
| 认证通过但 ts_echo 离谱的数据报使 RTT 计算整数溢出（模糊测试发现） | 样本 `< 0` 或 `> 60 s` 忽略 | 5.3 |
| 链路重排 ±10 ms 时快速重传大量误触发，cwnd 收敛到个位数 | 加入 ikcp 的 FASTACK_CONSERVE（按 `ts_sent` 过滤） | 6.2 |

未在正文中单列的实现选择：每确认一个分片增长一次 cwnd（TCP 语义）；`ssthresh` 初值 `ANL_MAX_WND`；窗口探测 1 s 起步；重传数据报受 pacing 约束，纯 ACK / CTRL 数据报不受约束。

已知限制：`resend > 0` 时若链路本身存在明显重排（例如多路径），仍可能有一定比例的误重传，属 ikcp 同类行为；需要时可关闭快速重传（`resend = 0`）或后续引入 RACK 式基于时间的判定。

### 13.5 第四轮（2026-09-25）：对照测试发现的问题与流模型扩展

`bench/`（AnLiu 与 ikcp 在模拟网络上同条件对照，见 `bench/README.md`）在 v0.3 实现上发现以下问题，均已修正：

| 问题 | 现象 | 处理 | 章节 |
|---|---|---|---|
| PARITY 写在 DATA 之后时，DATA 仍省略了 len | 消息尾部被拼进校验段字节；**未开 FEC 的可靠流也会损坏**（同一数据报中其他流的 PARITY） | 组包器写入任何段都撤销"最后一段是 DATA"标记 | 5.2 |
| FWD 重发计数跨 new_una 累加 | 持续拥塞约 8 s 后连接被判死 | una 有推进时清零 | 7.4 |
| max_age 把已发出、未确认的帧当作超龄 | RTT > max_age 时每帧"丢弃"并发 FWD；0% 丢包、RTT 300 ms 的音频流约 7 s 判死、到达率 11% | 改为选项二语义：只丢未发完的帧；已发完的帧超龄后需要重传时才放弃 | 7.3 |
| 首片已确认、尾部超龄被丢时不发 FWD；接收端组帧不校验 | 半截关键帧与下一帧拼接后交付 | 发送端补发 FWD；接收端校验 sn 连续与 frg 递减 | 7.3, 7.5 |
| 重传用满 3/4 配额后阻塞新数据 | 高优先级新数据被低优先级重传挡住 | 配额用尽只结束重传步骤 | 6.4 |
| 快速重传无次数上限 | 瓶颈队列满时同一分片反复快速重传，xmit 很快达到 dead_link | 与 ikcp 相同，xmit > 5 后只等 RTO | 6.3 |

修正后，完整矩阵（27 种链路条件 × 5 个场景）和 1 小时长稳测试（网络阶段轮换，时钟与 16 位序号多次回绕）均无正确性错误、无判死。

流模型扩展（需求：流数量 64 → 8192，像 TCP 一样打开/关闭）：

| 决定 | 内容 | 章节 |
|---|---|---|
| sid 编码 | 固定 2 字节：type(2) + 保留(1) + sid(13)；每段多 1 字节。最初按 16384 个流（sid 14 位）实现，评审后改为 8192 个，空出 1 位保留 | 5 |
| 打开 | 两端都可打开；ANL_SID_AUTO 按奇偶分配；显式打开对端已开的 sid 视为同时打开 | 6.1 |
| 接收 | 自动接收 + 回调（可改本端参数或拒绝）；max_peer_streams 限制对端并发流数 | 6.1 |
| 重用 | TIME_WAIT 墓碑，期限 ts_window + 2×RTO；新一代 OPEN 须晚于墓碑记录的关闭时刻 | 6.1 |
| 接口 | `anl_stream_open` 返回 sid；`anl_readable` 改为返回 sid 列表；新增 `anl_set_accept`、`ANL_EBUSY` | 10 |
| 实现 | 两级页表 + 流链表；即时控制 flush 只处理本次输入触及的 sid | 6.1 |

`test.c` 新增：两端各开 100 个流交叉收发并由不同端关闭（0% / 10% 丢包）、TIME_WAIT 期间拒绝重用与期满后重用（含旧一代数据报注入）、接收回调拒绝/改参数与 max_peer_streams、8192 个流全部打开收发并关闭回收、sid 保留位非 0 时拒绝。全部在 ASan/UBSan 下通过。

已知限制：`anl_readable` 与 `anl_check` 仍遍历全部流，流很多时应用不宜每毫秒调用；周期 flush 每个 interval 遍历全部流一次。

### 13.6 第五轮（2026-09-25）：丢帧与优先级

**丢帧（7.6）**：实现发送端连带丢弃在途的非关键帧、接收端 `rcv_drop_until_key`；评审后决定关键帧请求（KEY_REQUEST）由应用层实现，协议不提供。B 帧不处理。

**优先级测试**（`test.c` 的 test_priority）：3 Mbps 瓶颈、RTT 40 ms、1% 丢包，控制流为可靠流，每 50 ms 发 200 B；视频约 3.6 Mbps，超过链路带宽。发现并修正：

| 问题 | 现象 | 处理 | 章节 |
|---|---|---|---|
| 重传被 pacing 推迟前就已执行 RTO 退避 | 视频占满令牌时，控制流一个丢失分片的 RTO 反复翻倍而未发出，控制流停滞数十秒（12 个随机种子中 7 个复现，最差 98/400 条送达） | 先判断能否发送，发出时才修改重传状态 | 6.4 |
| 重传按流的创建顺序访问 | 低优先级流的重传可能先占用令牌 | 按优先级访问 | 6.4 |
| rcv_deadline 每收到一个分片就重新计时 | 持续发送的流永远不触发跳过 | 仅 rcv_nxt 前进时重新计时 | 7.5 |

修正后的结果（控制流 prio 0、视频 prio 2）：

| 配置 | 控制流 p50 / p99 | 控制流在 AnLiu 中未发出的最大分片数 |
|---|---|---|
| 控制流单独 | 22 / 22~123 ms | 0 |
| nc=1，pace_rate 2.8 Mbps（低于瓶颈） | 40 / 53~142 ms | 1 |
| nc=0（cwnd 开启） | 约 50 / 约 370~760 ms | 2~4 |

结论：

- 在 AnLiu 内部，控制流不会排在视频后面：未发出的控制分片最多是等待共享 cwnd 腾出的几个；
- 视频码率超过链路带宽时，延迟主要产生在**网络瓶颈队列**：I 帧突发让控制包在路由器中排队约 100 ms 以上，并引起 RTO 误重传和真实丢包。这不是发送端优先级能解决的，需要应用按 `anl_get_stats().pace_rate` / `backlog_bytes` 调整视频码率，或使用低于瓶颈带宽的 pace_rate；
- 尝试过"按优先级计算 cwnd 预算"（低优先级在途数据不占高优先级的预算）：控制分片确实不再在发送端等待，但被直接送进已满的瓶颈队列，p99 反而从约 370 ms 升到约 450 ms，已撤回；
- 原型验证：基于时间的丢包检测（RACK，任何流上更晚发出的数据报被确认即判定更早的分片丢失）可把 nc=0 下的控制流 p99 从约 370 ms 降到约 245 ms。尚未合入，待评审。

测试可复现性说明：内置 PRNG 的 nonce 混入了连接对象地址，随机填充长度因此随进程而变，同一随机种子两次运行的时序并不完全相同；需要逐包复现时应通过 `cfg.rng` 提供确定性随机源。

### 13.7 第六轮（2026-09-25）：默认流与流句柄

| 决定 | 内容 |
|---|---|
| 默认流 | sid 0 随连接创建，可靠字节流，严格优先，不可关闭；`anl_send / anl_recv` 作用于它（原按 sid 的接口改为 `anl_stream_*`）；窗口 `default_snd_wnd / default_rcv_wnd`，默认 1200；后台交换一次 OPEN，不阻塞收发 |
| 流句柄 | `anl_stream_open(w, opt, &err)` 返回 `anl_stream_t *`，sid 自动分配，失败返回 NULL 并给出 err |
| 生命周期 | 同 socket：到应用 close 为止有效；对端关闭后读完剩余数据返回 `ANL_ECLOSED` |
| 流用途 | `opt.tag`（u16）随 STREAM_OPEN 发给对端，accept 回调与 `anl_stream_tag` 可见；STREAM_OPEN body 增加 2 字节 |

改造过程中测试发现的协议问题（均已修正）：

| 问题 | 现象 | 处理 |
|---|---|---|
| 流在对端 OPEN 到达前就被关闭时，CLOSE 立即发出 | OPEN 丢失而 CLOSE 先到，对端回 RST，已提交的数据丢失 | 收到对端 OPEN 之前不发 CLOSE 和数据，OPEN 持续退避重发 |
| 对端先关闭时本端只回应一次 CLOSE | 这次回应丢失后对端一直重发 CLOSE，达到 dead_link 拖死连接 | 每个 CLOSE 都回应 |
| 发往已释放 sid 的 DATA 被静默丢弃 | 最后一个分片的 ACK 丢失、对端已过 TIME_WAIT 时，本端无限重传 | 回 RST |

验证：`test.c` 全部改用句柄接口，新增默认流（免握手、字节流、窗口配置）、协议违规、打开后立即关闭并读到流结束、句柄生命周期（对端关闭后句柄保持有效、sid 被对端新流重用）等用例；`-O2` 连续 16 次、ASan/UBSan 连续 3 次全部通过。`bench/` 快速矩阵 0 错误，10 分钟 soak 0 错误（`soak_v5.txt`）。

### 13.8 第七轮（2026-09-25）：对照组修正与断网 / 关闭的健壮性

**对照组修正**：`bench` 中 ikcp 的应用层丢帧（kcp+drop）原先以 `ikcp_waitsnd`（含已发未确认）为积压指标，RTT 200 ms 时音频在无拥塞时也被大量丢弃，对 ikcp 不公平。改为只看尚未发出的 `nsnd_que`，阈值为 max_age 对应的数据量（音频 10 帧、视频约 0.5 s）。

**10 分钟 soak 中发现连接在断网阶段被判死**（`soak_v6.txt`，AnLiu 代码未变，此前的运行碰巧通过），据此发现并修正：

| 问题 | 现象 | 处理 | 章节 |
|---|---|---|---|
| FWD 以固定 RTO 周期重发 | 半可靠流在丢帧时断网约 2.2 s，连接判死（10/10 复现） | FWD / CLOSE 与数据分片一样退避 | 7.4, 6.1 |
| 本端流在处理 CLOSE 时即进入 closed，不回应 | 对端只能靠后续 RST 得知，RST 丢失后更依赖下一条 | closed / TIME_WAIT 状态也回应 CLOSE | 6.1 |
| 无状态 sid 的 RST 队列固定 32 项 | 大量流同时关闭时，同一批 sid 每次溢出，永远卡在 closing | 可增长队列 + 位图去重 | 6.1 |
| 流释放后 FEC 块计数未清零 | 周期 flush 对已释放的 FEC 缓冲封块，段错误（模糊测试在部分随机种子下触发） | fec_free 清零块计数，封块前检查缓冲 | 8.2 |

**测试可复现性**：`test.c` 的模拟网络通过 `cfg.rng` 使用确定性随机源，一次运行完全由种子决定（环境变量 `ANL_TEST_SEED`）；以上问题都是在多种子扫描中复现并定位的。新增用例 test_outage：5 s 断网，同时运行半可靠流与可靠流，并在断网中关闭一个流。

### 13.9 第八轮（2026-09-25）：简化

`anliu.c` 达到 3050 行后对设计做了一次整体评估，目标是去掉不再需要的机制而不改变行为。保留 FEC（B.1）不动。

| 项 | 之前 | 之后 | 章节 |
|---|---|---|---|
| 流的建立 | STREAM_OPEN 双向交换（ACK 标志、回显、收到对端 OPEN 前不发数据和 CLOSE）、`opening` 状态、`peer_rcv_wnd` | 首个 DATA / CLOSE 直接携带 5 字节流参数；STREAM_OPEN 退化为单向通告，只用于"打开后等对端先说话"；mode / stream / tag / rcv_wnd 由打开方决定、两端相同 | 5.2, 5.5, 6.1 |
| sid 分配与重用 | 轮转分配 + TIME_WAIT 墓碑（到期定时器、关闭时刻 peer_ts、新一代 OPEN 判定） | 单调递增、一个 sid 在连接内只用一次；1 KB 已用位图；没有 TIME_WAIT。代价：一条连接最多开 4096 条流 | 6.1 |
| DATA 的 len | 最后一个 DATA 省略 len（HAS_LEN），封包时回写 | len 总是存在；b1 的 bit7 改作 OPEN 标志 | 5.2 |
| 错误状态 | `error` 状态、`ANL_EMISMATCH`、`ANL_STREAM_ERROR` | 协议违规 = 发 RST 并按收到 RST 处理，应用看到 `ANL_ECLOSED` | 6.1 |
| 待发控制段 | 定长 `touch[]` 数组 + 溢出标志 + epoch | 一条侵入式链表，有待发控制段的流挂上去 | 6.1 |
| 流结构体释放 | `tomb` 标志、`detached` / `app_released` 多处分别判断 | 单一释放路径：从 sid 表摘除且应用已 close 时释放 | 6.1 |

其他：`ANL_ENOSTREAM` 删除；`anl_stream_stats.peer_rcv_wnd` 删除；accept 回调不能再改 rcv_wnd；DATA 头部最大值由 11 增至 16 字节（mss 减 5；13.10 改为只对对端应答前切出的分片生效）。

验证：`test.c` 相应重写（sid 只用一次 + 旧一代数据报重放得到 RST、句柄生命周期、accept 参数约束），ASan/UBSan 与 `-O2` 全部通过；`bench/` 编译通过。

### 13.10 第九轮（2026-09-25）：简化后的回归测试

对 13.9 的版本做 30 个种子 × （`-O2`、ASan/UBSan）扫描，11/30 个种子失败：

| 问题 | 现象 | 处理 | 章节 |
|---|---|---|---|
| 流参数的 5 字节计入了连接 mss（1368 → 1363） | 优先级测试（pacing 2.8 Mbps、3 Mbps 链路）控制流 p99 267~558 ms，超过 250 ms 阈值；此前为 51~150 ms。15000 字节的 P 帧从正好 11 片变成 11 片 + 7 字节尾片，尾片单独成包，发送方向小数据报每轮从约 15 个增至约 300 个，瓶颈丢包 69 → 102，控制流被重传阻塞 | DATA 头部最大值恢复为 11；只有对端应答前切出的分片使用 mss − 5（`seg_limit`） | 5.2 |
| test_open_close（15% 丢包）等待 8 s 过短 | 种子 29 下一个分片的 7 次重传全部被随机丢包丢掉，指数退避使其超出等待时间（分片之后仍然送达，协议无误） | 等待改为 20 s | — |

### 13.11 第十轮（2026-09-25）：吞吐量——pacing、区间确认、RACK、ACK 驱动发送

**起因**：不限带宽对照中 AnLiu 在大窗口下吞吐只有约 7 MB/s；抖动链路上 98% 的快速重传是多余的；一个 ACK 丢失就可能让队头停滞到 RTO。

| 改动 | 原因 | 章节 |
|---|---|---|
| pacing 令牌上限随速率放宽（仅在有数据等令牌时） | 每次补充截断在桶容量（5600 B），1 ms 时钟下吞吐封顶约 7 MB/s，与速率无关 | 6.7 |
| ACK 改为 una + SACK 区间，每个分片至少报告 3 次；删除 acklist | 旧格式每个 sn 只确认一次，ACK 丢失后只能等 RTO | 5.3 |
| RACK（RFC 8985）取代 fastack：连接级证据 + 本流同毫秒按 sn；定时器 | ACK 越密，按个数计数越容易误判（抖动链路 98% 多余重传）；第一版用 `rack_ts - ts_sent > reo` 判定，同一批发出的分片永远不满足，窗口受限时退化为 RTO，突发丢包下判死；只用本流证据时低速控制流停顿 2 s | 6.3 |
| 乱序窗口 min_rtt/16 起步，Eifel 检测误判后每 RTT 加倍（最多 min_rtt），16 个 RTT 无误判后每 RTT 减 1；半可靠流固定最小窗口 | 以 srtt 为基准时排队把窗口撑大；按任意重复计数时 RTO 重传、半可靠跳帧、FEC 恢复都会误放大；逐个 +1 时大窗口跟不上，DSACK 记录环在大窗口下被覆盖 | 6.3 |
| ACK 驱动发送（仅 nc=1） | 窗口受限时每个往返多等一个 interval；nc=0 时会让瓶颈队列持续满载，控制流 p99 恶化到 2.3 s | 6.4 |
| CLOSE 携带 una | 对端释放流后最后一个 ACK 丢失，关闭方只能靠退避重传与 RST 收尾（种子 2 需 22 s） | 5.5 |
| bench：突发丢包按时间推进（空闲的每毫秒也走一步） | 按包推进时，几秒才发一个包的发送端会被困在"坏"状态几十秒，判死；ikcp 同样受影响 | bench |

**结果**（`bench/unlimited_v3_*`、`bench/regress_v9/`）：
- 单元测试 30 种子 × O2/ASan 全部通过；
- 不限带宽 18 种链路 × 10 种子：相对 ikcp 吞吐几何平均 1.23 / 1.08 / 0.96 倍（窗口 128 / 1024 / 4096）；无丢包时比旧版高 26~37%（ACK 驱动）；有丢包时比旧版低 5~30%，但线上开销从 1.2~2.1 降到 1.09~1.35，抖动链路从 1.4~2.1 降到 1.10~1.25。旧版的吞吐部分来自大量多余重传（相当于免费的冗余副本），带宽不受限时有利，带宽受限时是浪费；
- 带宽受限对照（20 Mbps）：交互、视频、音频、混合场景持平或更好（s5 音频 anl+fec 及时率 85.7% → 90.0%）；批量吞吐 −8%，开销 −13%；
- 10 分钟 soak：音频到达 94.8% → 96.2%，视频 90.3% → 88.0%；已知的 2 Mbps（nc=1 无固定速率）阶段两版都拥塞崩溃。

