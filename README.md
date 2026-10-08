# AnLiu（暗流）

**暗流**：“暗”指整个数据报都经过认证，conv 之后的版本、段类型、序号与载荷经过加密；conv 仅做可逆混淆；“流”指一条连接里同时流淌着多股相互独立的数据流——控制信令、音频、视频、文件——它们共享带宽，但各有各的可靠性和优先级。水面平静，水下暗流交汇，这就是这个名字的由来。

AnLiu 是一个基于 UDP 的传输协议，实现方式参考 [ikcp](https://github.com/skywind3000/kcp)：只有 `anliu.h` / `anliu.c` 两个文件，不依赖外部库，不直接操作 socket（通过回调发包、`anl_input` 收包），时钟由应用驱动。在 kcp 的基础上，它加入了面向实时音视频的能力：

| 能力 | 说明 |
|---|---|
| 加密与抗识别 | ChaCha20 + SipHash-2-4 组成的 SIV 构造，整包认证、conv 之后加密，按方向派生密钥，随机填充 |
| 多流 | 一个连接同时最多 64 个流（`ANL_MAX_STREAMS`，含默认流）；流 ID 单向递增，连接内不复用；对端的流消失后其 ID 保留 2 s（时间窗调大时更长），迟到的首个数据报不会建出新流；两端都可随时打开和关闭，关闭通知对端（CLOSE 重发到对端确认）；共享拥塞控制并合并 ACK 数据报，按优先级加权调度 |
| 半可靠帧传输 | 以“帧”为单位发送，过期或积压时整帧丢弃；关键帧依赖处理；接收端跳帧 |
| 流级 FEC | 按流开关的 Reed-Solomon 前向纠错：支持固定冗余（默认比例 25%）与条件自适应，固定块长 100 ms，自适应最长 400 ms，块内任意 m 个丢包都能恢复 |
| 拥塞控制与带宽估计 | BBRv2（采用 BBRv3 式的四相位带宽探测）：按测得的瓶颈带宽和传播时延发送，不把瓶颈队列塞满；带宽估计通过 `anl_get_stats()` 交给应用调码率 |
| 平滑发送 | 连接级令牌桶 pacing（速率 = 增益 × 带宽估计），大帧不会整窗突发 |
| 现代丢包恢复 | 区间确认（SACK）+ 基于时间的丢包判定（RACK）+ 乱序自适应 |
| 精简头部 | 数据报头 23 字节（含 12 字节认证和 4 字节包号），默认 MTU 下基础 DATA 段头 6~7 字节，分片扩展、帧号、流 ID 扩展和 OPEN 参数另计；kcp 每段 24 字节且不加密 |

详细设计见 [DESIGN.md](DESIGN.md)，性能测试数据见 [performance.md](performance.md)，代码里各条规则的实验依据见 [TUNING.md](TUNING.md)，对照测试工具位于 `bench/`。

## 编译与安装

使用 CMake 3.16 或更新版本及支持 C99 的 C 编译器：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

默认生成 `anliu` 库、现有单元测试与诊断测试，并在 POSIX 平台构建模拟工具；Linux 另构建 `realnet` / `realnet_trace`。测试直接包含实现以检查内部状态，CMake 不重复链接一份库。Release 下保留诊断测试的 assert 检查。

```sh
# 只编译库
cmake -S . -B build-lib -DBUILD_TESTING=OFF -DANLIU_BUILD_BENCHMARKS=OFF
cmake --build build-lib --parallel

# ASan / UBSan，GCC 或 Clang，使用现有测试
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DANLIU_ENABLE_SANITIZERS=ON -DANLIU_BUILD_BENCHMARKS=OFF
cmake --build build-asan --parallel
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure

# 安装库、头文件、许可与 CMake package 到指定目录
cmake --install build --prefix "$PWD/install"
```

库仅以静态库形式构建。安装后可用 `find_package(AnLiu CONFIG REQUIRED)` 与 `target_link_libraries(app PRIVATE AnLiu::anliu)`；配置应用时通过 `CMAKE_PREFIX_PATH` 指定安装前缀。测试程序位于构建目录，工具位于 `build/bench/`；多配置生成器可能另加配置子目录。当然最简单的做法是把 `anliu.h` / `anliu.c` 两个文件拷贝到你的工程直接使用。

```sh
./build/bench/anl_bench --quick s3 s4
REALNET_CLOCK=1 ./build/bench/realnet server --proto anlauto --test media --dir up --dur 150
```

---

## 1. 为什么要引入“帧”

以前的工作跟音视频处理打交道比较多，对实时音视频传输的痛点有很深的体会：

- **延时比完整更重要**。一帧视频晚到 500 ms，和丢了没有区别；可靠传输会为了一个丢失的包把后面所有的包都堵住（队头阻塞），画面越卡越久，延时越积越大；
- **网络一抖就卡**。可靠协议在丢包时退避、重传、再退避，积压的数据只能越排越长，直到网络恢复后“快进”追赶；
- **帧之间有依赖**。I 帧丢了，后面的 P 帧全都无法解码，继续传它们只是浪费带宽；
- **应用不知道协议在想什么**。kcp 之类的字节流/消息接口里没有“帧”的概念，应用只能在外面猜测何时该丢数据。

所以 AnLiu 把“帧”做进了协议：

- `anl_stream_send_frame` / `anl_stream_recv_frame`：帧号由协议分配，接收端拿到 `frame_no` 和 `lost_before`（前面跳过了几帧），可以直接驱动解码器；
- **发送端丢帧**：帧在队列里超过 `max_age_ms` 就整帧丢弃；已经发出但超时的帧不再重传，改发 FWD 通知接收端跳过；
- **关键帧依赖**：`drop_until_key` 在发送端丢到下一个关键帧为止（已在途的依赖帧一并清除）；`rcv_drop_until_key` 在接收端丢弃无法解码的 P 帧；
- **接收端 deadline**：后续数据揭示缺口后，等待超过本地 `rcv_deadline_ms`（默认为本地 `max_age_ms` 的 3/5）可跳到后面的帧；期限不是发送端帧年龄；
- **FEC**：见第 3 节。

### 带宽估计

视频最好的状态，是编码码率刚好匹配可用带宽：码率高了排队、丢帧、卡顿，码率低了画质白白浪费。所以协议里的拥塞控制用的是 **BBRv2** 的思路，带宽探测按 BBRv3 的方式（DESIGN 6.8）：以带宽和时延模型为主，并结合丢包与排队证据调整约束，持续测量两样东西——**瓶颈带宽**（最近 10 个往返的最大交付速率）和**传播时延**（10 秒内的最小 RTT），按"带宽 × 增益"平滑发送，在途数据保持在约两倍带宽时延积。这个带宽模型本身就是交给应用的带宽估计：

```c
anl_stats st;
anl_get_stats(w, &st);
/* st.bw_estimate：字节/秒（线上字节，含头部、重传与 FEC 校验包）
   st.bw_app_limited：1 = 应用发得比估计值少，真实带宽可能更高
   st.min_rtt / st.cc_state：传播时延；STARTUP / DRAIN / PROBE_BW / PROBE_RTT */
```

**给编码器用的码率**（DESIGN 6.10）：`st.target_rate` 已经扣掉包头、FEC 校验包、重传和 10% 余量，是所有流合计可以发送的**载荷**字节/秒；变化 5% 以上时回调：

```c
static void on_rate(anl_t *w, uint32_t target_rate, void *user)
{
    uint32_t video_bytes = target_rate > audio_bytes_per_s ? target_rate - audio_bytes_per_s : 0;
    encoder_set_bitrate(user, (uint64_t)video_bytes * 8);   /* 只读统计，不能调用其他 anl_* */
}
anl_set_rate_callback(w, on_rate);
```

它比直接用 `bw_estimate` 多做了三件事：应用受限（编码器发得比估计值少）且没有排队时，目标值最多每秒上调 25%，让编码器逐步试探；常规上升最多每秒 25%，持续交付受限时可在已测交付上界内恢复；RTT 显示瓶颈在排队时，立刻降到实际交付速率——带宽骤降后编码器还没跟上时，半可靠流的数据会在确认前过期，BBR 数秒内拿不到样本，而 RTT 仍然看得到队列。相关对照结果见 [performance.md](performance.md)。

**接收端时延反馈**（DESIGN 6.9）：半可靠流的接收端每 `max(srtt, 100 ms)` 把测得的抖动、排队时延、帧时延（最早分片发出到整帧收齐，扣除传播时延）、完成帧数和跳过帧数报告给发送端：

```c
anl_stream_stats ss;
anl_stream_get_stats(video, &ss);
/* ss.peer：对端最近一次报告（ss.peer.age_ms 为到达至今的时间）
   ss.peer.frame_delay_max_ms 升高 → 帧开始晚到：降码率或插关键帧前先等等
   ss.rx：本端作为接收方测得的同一组数据 */
anl_set_report_callback(w, on_report);   /* 报告到达时回调 */
```

为适应实时业务，在 BBRv2 的基础上做了几处调整（详见 DESIGN 6.8）：通常结合排队信号判断丢失是否为拥塞，PROBE_BW 极高丢失时也会减速；无排队时对发送速率与 FEC 开销进行有限补偿；应用受限（关键帧之间的视频）时保留关键帧测到的带宽，并在路径带宽未知时允许关键帧突发；能识别路径时延变长（切换网络）与带宽下降这两种不同的情况；常规带宽探测采用 2~3 秒随机墙钟间隔，并有轮次上限；容量恢复时还可提前探测（DESIGN 6.8、8.6）。

---

## 2. 为什么用多个流，而不是多个实例

在同一个传输链路上使用多个实列存在几个根本性问题：

1. **带宽是共享的，但拥塞控制各算各的**。多个实例各有各的 cwnd 和重传节奏，互相看不见。视频把瓶颈队列塞满时，控制信令和音频的包排在后面、被尾丢弃，而它们的拥塞控制对此毫无办法；
2. **信令、音频、视频的重要性不一样**。控制信令（例如“请求关键帧”“静音”“挂断”）量很小但必须立刻送达；音频对延时最敏感；视频量最大但可以丢帧；文件传输只要最终送达。多个实例之间没有任何优先级；
3. **开销与指纹**。每个实例各自发 ACK、各自一套包头，小包多；多个 conv 也更容易被识别和关联。

AnLiu 的做法：

- 一条连接里多个流，**共享** RTT 估计、拥塞窗口和 pacing 令牌桶，所有流的数据和 ACK 可以打进同一个数据报；
- **默认流（sid 0）严格优先**，适合放控制信令；其他流分 4 个优先级，按每流 **8 : 4 : 2 : 1** 的 DATA 分片额度加权轮询，额度跨 flush 保留。在默认流未持续占满发送能力、连接和流窗口允许发送时，低优先级也能取得进展；这不是线上字节比例保证；
- 重传优先于新数据，且按优先级顺序进行；重传最多占用 3/4 的发送令牌，丢包严重的大流挤不掉实时流的新数据；
- 丢包判定（RACK）用整条连接的送达证据：低速的控制流即使自己没有后续分片，也能借视频流的送达及时发现丢包；
- 每个流独立选择可靠 / 半可靠、窗口、FEC、优先级，两端都可以随时打开和关闭流：关闭时本端立即释放，待发、在途及未读数据全部丢弃，并通知对端；对端那一端随之结束，已按序到达的数据仍可读完，之后返回 `ANL_ECLOSED`，句柄由对端应用 close。可靠流需要送达时，应用先等 `anl_stream_waitsnd` 为 0，再关闭。

已知上行配额时，可用 `cfg.pace_rate` 设置 BBR 的发送速率上限；优先级与混合流测试结果见 [performance.md](performance.md)。

---

## 3. 为什么引入 FEC

实时场景里，重传通常来不及：一次丢包要等"发现丢失 + 重传一个往返"，发现丢失和再次传输会占去实时业务的时延预算。FEC 用额外的带宽换时间：接收端用校验包直接恢复丢失的包，**不需要等重传**。可以按流开关（视频、音频开，文件不开）。

**算法：Reed-Solomon**（GF(2⁸) 上的 Cauchy 矩阵，DESIGN 8）。一个块 k 个数据包配 m 个校验包，块内**任意 m 个**丢失都能恢复。RS 可以把更多的包放进一个块而不失去恢复能力。

**固定冗余的主要参数：冗余率** `fec_ratio`（每 100 个数据包配多少个校验包，默认 25）：

- 块最多收集 100 ms（或 64 个包）就封块；固定比例按 `k × 冗余率` 累积余数分配校验包，每块最多 16 个；块可以跨多帧，实际恢复还受 pacing、调度和网络时延影响；
- 校验包后续发送间隔至少 5 ms，实际时机取决于 flush、pacing 与调度；小块校验包可搭载在同一流下一块的数据报中，其他校验包单独发送（可能附带 ECHO），以减少与本块数据同时丢失的机会；
- 被校验包覆盖的包，发送端的 RACK 等待从该块最后一个校验包的发送时刻起算，RTO 也可延后，但受帧期限和重传能否赶上的约束，具体见 DESIGN 8.2。

**自适应冗余**（`opt.fec_ratio = 0`，DESIGN 8.5）：按未能及时恢复的丢失调整名义比例，并结合连接丢包估计、块大小与冗余预算决定实际校验包数。自适应模式的名义比例在 10%~100% 间变化；校验包数还受每块上限、低时延下的重传能力及容量不足状态影响。比例和时延的对照数据见 [performance.md](performance.md)。

**默认值**：可靠流默认不开 FEC；半可靠流默认 `fec = ANL_FEC_RTT_AUTO`，结合预计修复时间、`fec_deadline_ms` 和近期硬丢失证据决定是否开启，并提供一次有界音频启动保护与关键帧保护。容量不足时暂停生成自适应冗余。要持续开启可显式设 `fec = 1`：`fec_ratio = 25` 为固定比例，`0` 为自适应。收发两端均需启用 FEC；接收端可在 accept 回调里设置本地选项（详见 DESIGN 8.6）。

---

## 4. 性能测试

模拟网络、真实 UDP 路径、吞吐、媒体时延、优先级和 FEC 冗余率的测试条件及历史数据统一放在 [performance.md](performance.md)。测试工具和运行方法见第 6 节。

---

## 5. 加密与“无特征”

**构造**：`tag = SipHash-2-4-128(k_mac, P)` 截断到 12 字节，同时作为 ChaCha20 的 nonce，认证整个明文 `P`（含 conv），仅加密 conv 之后的部分：`wire = tag || convx || ChaCha20(k_enc, tag, P[4..])`，其中 `convx` 是 conv 与公开 tag 字节的异或混淆。这是 SIV（合成 IV）方式：不需要维护 nonce 计数器，同一个明文加密结果相同，丢包重传不会暴露 nonce 的规律。

- **按方向派生密钥**：两端从 32 字节 PSK 派生出“客户端→服务端”“服务端→客户端”两套独立密钥，把对方的包反射回去会认证失败；
- **认证失败绝不回应**：`anl_input` 返回 `ANL_EAUTH`，调用方必须静默丢弃，主动探测得不到任何响应；
- **conv 可见**：版本号、包类型、序号与载荷在密文里；conv 仅做混淆，知道算法的人无需密钥即可还原，并可据此关联同一连接的包。混淆不提供保密性；
- **随机填充**：默认不带 DATA/PARITY 的数据报追加 1~32 字节随机填充（受 MTU 剩余空间限制）；DATA/PARITY 数据报不填充，keepalive 始终填充；
- **重放**：每个数据报带本方向的包号，接收端记住最近 4096 个，重复或更早的数据报认证后直接丢弃（`ANL_EREPLAY`），不解析任何段（DESIGN 4.3）；ts 的时间窗（默认 1 s）另外挡住滞留过久的数据报和倒退的时钟（DESIGN 4.2）。重放包仍要先解密和认证；
- **伪造**：每次尝试成功概率 2⁻⁹⁶。

**已知限制**（使用前请评估）：

- 这是一个自定义的密码组合，**没有现成的安全证明**，也没有经过第三方审计；
- 只有 PSK，**没有密钥交换和前向保密**：PSK 泄露后，历史流量都可以被解密；
- 单个 PSK 在所有连接、两个方向合计不应超过 2⁴⁰ 个数据报（tag 兼作 nonce 的生日界），超过前需要轮换；
- **不隐藏流量时序**：包的间隔、突发和大致的包长分布仍然可以被统计分析；
- 未认证的包也要先解密才能验证，垃圾包洪泛的 CPU 代价较高。

---

## 6. 测试方法与测试代码

测试分三层：单元测试（功能与健壮性，可复现）、模拟对照测试（与 kcp 在同一个模拟网络上比性能，可复现）、真实网络测试（在真实 UDP 路径上比性能）。每一轮修改都按 6.4 的流程判断。

### 6.1 单元测试：`test.c`

`test.c` 直接 `#include "anliu.c"`（可以检查内部状态），内置一个可复现的模拟网络：丢包、指定丢某个数据报、时延、抖动乱序、重复、带宽瓶颈与队列。整个运行由种子决定。

```sh
gcc -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined test.c -o anl_test -lm
./anl_test                          # 默认种子
ANL_TEST_SEED=1234 ./anl_test       # 指定种子，结果可完整复现
ANL_TEST_ONLY=priority ./anl_test   # 只运行名字包含 priority 的测试
```

覆盖内容：

| 类别 | 测试 |
|---|---|
| 密码学 | ChaCha20（RFC 8439 向量）、SipHash-2-4 已知答案；服务端分发（`anl_peek_conv` 免解密取 conv、conv 混淆与篡改检测）；反射攻击；重放（包号窗口：重复、窗口内乱序、窗口之下、向前跳跃、超出领先范围、2³¹ 之后的包号 0、回绕）与过期 ts |
| 可靠流 | 0% / 10% 丢包，消息模式与字节流模式，内容与顺序校验 |
| 半可靠流 | 0% / 5% 丢包、有无 FEC、1 Mbps 拥塞；帧号、`lost_before` 统计闭合 |
| FEC | 指定丢掉某些数据报（帧的最后一个分片、分散丢 3 个、连续丢 4 个）必须在一个 RTT 内由 RS 恢复；自适应冗余（无丢包降到下限、误时的丢失使其上升、重传赶得上时不上升）；音频 + 视频两个流同时自适应；PARITY 段模糊测试 |
| 关键帧 | 发送端清除在途依赖帧；接收端丢弃无法解码的 P 帧 |
| 流生命周期 | 关闭通知对端与确认（CLOSE / RST 丢失、对端未见过、双方同时关闭）；半可靠流由发送端 / 接收端关闭；两端各开 31 个流（含 10% 丢包）；64 个流上限；sid 生命周期（单向递增、2 s 保留期及随时间窗加长、消失的流迟到的首个数据报得到 RST、无人应答的 CLOSE 放弃、9000 次开关含 10% 丢包和 5% 重复包）；句柄生命周期；accept 回调 |
| 调度与拥塞控制 | 优先级（5 种组合 × BBR / BBR + 速率上限）；pacing 突发上限；分片大小；RTT 小于 2 ms 的链路 |
| 应用接口 | `target_rate`：跟随它的编码器爬升到链路、带宽下降后跟上；时延报告：接收端测量、发送端收到 |
| 健壮性 | 5 秒断网恢复；协议违规（RST），默认流上的违规段只丢弃、默认流不受影响；20000 个随机变异数据报的模糊测试；持 PSK 对端的覆盖率引导模糊测试见 `tools/fuzz/`（libFuzzer，可选） |

**多种子扫描**：同一套测试换 1000 个种子在 AddressSanitizer + UndefinedBehaviorSanitizer 下逐一运行，失败的种子单独重跑、定位到具体的丢包序列再修复。

```sh
seq 1001 2000 | xargs -P 6 -I{} sh -c 'ANL_TEST_SEED={} ./anl_test > out_{}.txt 2>&1 || echo "{} failed"'
```

### 6.2 模拟对照测试：`bench/anl_bench`

同一个模拟网络（1 ms 虚拟时钟）上同时跑 AnLiu 与 kcp（原版 `ikcp.c`，`nodelay 1, 10, 2, 1`）；半可靠流量在 kcp 上按可靠方式发送（`kcp`），或加一层应用层丢帧（`kcp+drop`）。同一个种子的结果完全可复现（包括随机填充）。

```sh
cd bench && make
./anl_bench --quick                       # s1~s5：批量、交互、视频、音频、混合；10 种链路
./anl_bench --quick --fec-ratio 0 s3 s4   # FEC 冗余率：1..100，0 = 自适应
./anl_bench --quick bwstep                # 带宽阶梯 8 → 2 → 5 → 1 → 8 Mbps：带宽估计、利用率、时延
./anl_bench --quick --abr bwstep          # 同上，视频码率跟随 target_rate（--nobulk：固定码率对照）
./anl_bench soak --soak 600               # 10 分钟长稳：链路每 60 s 切换（含 5 s 断网、RTT 翻倍）
./anl_bench s1 --bw 0 --wnd 4096          # 不限带宽的吞吐
./anl_bench s1 --bw 45000 --qdelay 3      # 瓶颈缓冲只有 3 ms：近似运营商的限速器
./anl_bench s3 --av --bw 800 --tbf 16 --rtt 170 --fec-auto   # 瓶颈是 16 KB 突发的令牌桶整形器（tc tbf），容量低于媒体
./anl_bench --quick --nobulk bwstep --fec-auto --step-rtt 170  # 只有音视频的带宽阶梯，路径 RTT 170 ms（8 → 2 → 5 → 1 → 8 Mbps）
BENCH_CC=100 ./anl_bench soak             # 每 100 ms 输出一次拥塞控制状态（stderr）
./anl_bench crypto                        # 加解密开销（真实时钟）
```

常用选项：`--seed N`、`--loss L,..`（%）、`--rtt R,..`（ms）、`--bw KBPS`、`--qdelay MS`、`--csv FILE`。自动检查：内容损坏、乱序、可靠流缺口、帧号不符、统计不闭合、内存泄漏记为 ERROR；连接判死、长时间停滞、RTT 估计偏离、断网恢复慢等记为 WARN。

**判断一项修改用多个种子**，不看单个种子：拥塞控制的一个小改动常常改变整条轨迹，单个种子的差异多半是分叉带来的噪声。常用的一组：s3 / s4 各 20 个种子 × 10 种链路、s5 与 bwstep 各 20 个种子、soak 6~20 个种子、bwstep `--abr` 10 个种子，再加单元测试里优先级测试的 6 个种子。把修改前后的代码各编译一份，同一组种子跑两遍对照。

### 6.3 真实网络测试：`bench/realnet`

同一套流量在真实 UDP 路径上跑，服务端与客户端各运行一个 `realnet`：

```sh
cd bench && make realnet              # 两端都编译（服务器上同样）
export REALNET_CLOCK=1                # 收包批次内按当前毫秒刷新协议时钟
# 服务器（AnLiu 默认监听 UDP 9836，ikcp 9837；--port 可改）
./realnet server --proto anlauto --test media --dir up --dur 150
# 客户端（参数与服务端相同）
./realnet client --host <服务器地址> --proto anlauto --test media --dir up --dur 150
```

| 选项 | 含义 |
|---|---|
| `--proto` | `anl`（不开 FEC）、`anlfec`（固定 25%）、`anlauto`（自适应）、`kcp`、`kcpdrop`（kcp + 应用层丢帧）、`tcp`（系统 TCP，只用于 `--test stream`，作为对照） |
| `--test media` | 音频 160 B / 20 ms + 视频 30 fps（约 940 kbps，每 30 帧一个关键帧），与模拟测试相同 |
| `--test stream` | 可靠流在 `--dur` 秒内一直填满，逐秒统计吞吐（平均、最差一秒、10% 分位） |
| `--test bulk` | 可靠流传完 `--bulk` MB 计时 |
| `--wnd N` | 可靠流（bulk / stream）的收发窗口，分片数（默认 1024；可用 4096 扩大窗口） |
| `--dir up / down` | 客户端发送 / 服务端发送 |
| `--loss P` | 两端发送时再随机丢 P%，在真实路径上叠加弱网（报告中单独标注） |

- **时延**：每帧带发送端时钟，接收端统计"单向时延 − 该流最小的单向时延"，即排队、重传、抖动带来的额外时延，**不需要两端时钟同步**；准时率的预算与模拟测试相同（音频 150 ms、视频 300 ms）。
- **一个端口两种协议**：每个数据报多 1 字节协议标记（工具层），客户端先发 20 个 ping 测路径 RTT。
- **同时对比**：媒体测试中 AnLiu 与 kcp 同时各跑一个进程（端口不同），同一时刻的网络条件相同；吞吐测试两者先后各跑一段，避免互相抢带宽。
- **一轮约 12.5 分钟**：媒体上行 150 s、媒体下行 150 s（两协议同时）、可靠流上行 AnLiu / kcp / TCP 各 75 s、下行各 75 s。每个组合跑 15 轮，分布在一天的不同时段。
- **TCP 对照**：记录实际拥塞控制算法与缓冲配置，使用相同的逐秒吞吐统计；若 TCP 经过代理而 UDP 直连，应单独标注路径差异。历史测试环境见 performance.md。
- **并行**：多个组合可以同时跑，同一台主机不同时跑同一种测试（媒体 / 流），各组合用不同端口。
- **排查**：`REALNET_SECS=1` 打印逐秒吞吐；`make realnet_trace` 后 `REALNET_TRACE=1` 每 100 ms 输出一次拥塞控制内部状态（cwnd、带宽估计、`bw_lo`、`inflight_hi`、PROBE_BW 相位、丢包率、限速器状态）。时钟与限速器问题可通过这些状态定位，相应历史测量见 performance.md。
- **应用集成提示**：`anl_input` 以最近一次 `anl_update` 的时间计算 RTT，收包前先调用 `anl_update(now)` 能让 RTT 样本准确（运行 `realnet` 时设置 `REALNET_CLOCK=1`）。

### 6.4 每一轮修改的流程

1. 单元测试（ASan / UBSan）全部通过；
2. 模拟对照：修改前后同一组种子对照（6.2），任何场景的退化都要先找到原因，再决定修正还是撤回；
3. 1000 种子扫描；
4. 涉及拥塞控制、FEC、调度的修改，再做真实网络对照（6.3）；
5. 测试数据、代码版本与限制写入 performance.md；实现规则有变化时同步更新 DESIGN.md。

---

## 7. 下一步与建议

1. **码率自适应调优**：`target_rate` 与时延报告已实现，仍需结合真实编码器、移动网络和 Wi-Fi 弱网校准增长策略与预算；
2. **FEC 反馈完善**：当前使用净重建数、跳过操作和发送端证据估计丢失；精确的原始丢包率、突发长度与校验包实际用量仍可增加专门反馈；
3. **密钥交换与前向保密**：目前只有 PSK，握手和会话密钥管理仍由应用解决；
4. **连接迁移与路径 MTU 探测**：当前不提供地址验证、迁移握手或自动 MTU 探测；
5. **接收端反馈参与码率控制**：时延报告已交给应用，当前 `target_rate` 主要根据发送端模型、RTT 与实际交付计算；
6. **持续模糊测试**：对解密后的报文解析（内部 `anl_input_plain`）接入覆盖率引导的长期模糊测试。

---

## 8. 快速示例

```c
#include "anliu.h"

static int udp_out(char *buf, int len, anl_t *w, void *user) {
    /* 需要时可先原地处理前 16 字节明文头（tag + conv），长度不变 */
    /* sendto(sock, buf, len, ...) */
    return 0;
}

anl_config cfg;
anl_config_default(&cfg, ANL_ROLE_CLIENT);        /* 对端用 ANL_ROLE_SERVER */
memcpy(cfg.psk, my_psk, 32);
anl_t *w = anl_create(conv, &cfg, NULL);
/* 实际应用应检查 anl_create / anl_stream_open 的返回值和各接口错误码 */
anl_setoutput(w, udp_out);
anl_update(w, now_ms);                         /* 发送前初始化单调毫秒时钟 */

/* 默认流：可靠、严格优先，适合控制信令 */
anl_send(w, "hello", 5);

/* 视频流：半可靠，超过 500 ms 的帧不再发送或重传，丢到下一个关键帧为止 */
anl_stream_opt o;
anl_stream_opt_default(&o, ANL_SEMI);
o.prio = 1; o.max_age_ms = 500; o.drop_until_key = 1;
anl_stream_t *video = anl_stream_open(w, &o, NULL);
anl_stream_send_frame(video, is_key ? ANL_FRAME_KEY : 0, frame, frame_len, NULL);

/* 主循环：每个收包前刷新当前单调毫秒时钟；接收批次内也要检查时间 */
anl_update(w, now_ms);
anl_input(w, pkt, pkt_len);                    /* ANL_EAUTH 必须静默丢弃 */
/* 按 anl_check(w, now_ms) 安排下一次定时更新；时间到时刷新 now_ms 再 update */

/* 使用完毕 */
anl_stream_close(video);                      /* 关闭后句柄失效 */
anl_release(w);
```

完整 API 见 `anliu.h`，协议细节见 [DESIGN.md](DESIGN.md)。音视频应用什么时候用 FEC、各参数怎么设，见 [VIDEO_GUIDE.md](VIDEO_GUIDE.md)。

## 许可

AnLiu 使用 MIT 许可，见 [LICENSE](LICENSE)。

对照测试使用的 `bench/ikcp.c` / `ikcp.h` 来自 [skywind3000/kcp](https://github.com/skywind3000/kcp)，MIT 许可，见 `bench/LICENSE-ikcp`。
