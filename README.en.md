# AnLiu (暗流)

[中文](README.md) | English

**AnLiu** (暗流, "undercurrent"): *An* (暗, "hidden") means every datagram is authenticated, and the version, segment type, sequence numbers and payload after conv are encrypted; conv itself is only reversibly masked. *Liu* (流, "stream") means one connection carries several independent streams at once — control signaling, audio, video, files — sharing the bandwidth while each keeps its own reliability and priority. Calm on the surface, currents meeting underneath: that is where the name comes from.

AnLiu is a UDP-based transport protocol whose implementation style follows [ikcp](https://github.com/skywind3000/kcp): just two files, `anliu.h` / `anliu.c`, no external dependencies, no direct socket handling (packets go out through a callback and come in through `anl_input`), and an application-driven clock. On top of the ikcp model it adds capabilities aimed at real-time audio and video:

| Capability | Description |
|---|---|
| Encryption and anti-fingerprinting | SIV construction from ChaCha20 + SipHash-2-4; whole-datagram authentication, encryption after conv, per-direction keys, random padding |
| Multiple streams | Up to 64 streams on a connection at once (`ANL_MAX_STREAMS`, the default stream included); a stream ID is the lowest free one, used again 2 s (longer with a larger timestamp window) after its close is confirmed, with a generation number telling the two apart; either side can open and close at any time, a close tells the peer (CLOSE, repeated until the peer confirms); shared congestion control, ACKs merged into datagrams, weighted scheduling by priority |
| Semi-reliable frame delivery | Data is sent as "frames"; whole frames are dropped when they expire or back up; key-frame dependency handling; receiver-side frame skipping |
| Per-stream FEC | Reed-Solomon forward error correction enabled per stream: fixed redundancy (default ratio 25%) or conditional adaptive mode; fixed blocks of 100 ms, adaptive blocks up to 400 ms; any m losses within a block are recoverable |
| Congestion control and bandwidth estimation | BBRv2 (with BBRv3-style four-phase bandwidth probing): sends according to the measured bottleneck bandwidth and propagation delay without filling the bottleneck queue; the bandwidth estimate is exposed to the application through `anl_get_stats()` for bitrate control |
| Smooth sending | Connection-level token-bucket pacing (rate = gain × bandwidth estimate); large frames are never sent as a full-window burst |
| Modern loss recovery | Selective acknowledgment (SACK) + time-based loss detection (RACK) + reordering adaptation |
| Compact headers | 23-byte datagram header (including a 12-byte authentication tag and a 4-byte packet number), 6~7-byte base DATA segment header at the default MTU, or 5 bytes when the last segment omits its length; fragmentation extension, frame number, stream-ID extension and OPEN parameters are extra. ikcp uses 24 bytes per segment, unencrypted |

See [DESIGN.md](DESIGN.md) for the detailed design and [performance.md](performance.md) for performance data; comparison tools are in `bench/`. (Both documents are currently in Chinese.)

## Build and install

Requires CMake 3.16 or newer and a C99 compiler:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

By default this builds the `anliu` library, the unit tests and diagnostic tests, plus the simulation tools on POSIX platforms; Linux additionally builds `realnet` / `realnet_trace`. The tests include the implementation directly to inspect internal state, so CMake does not link a second copy of the library. Assert checks in the diagnostic tests are kept in Release builds.

```sh
# Library only
cmake -S . -B build-lib -DBUILD_TESTING=OFF -DANLIU_BUILD_BENCHMARKS=OFF
cmake --build build-lib --parallel

# ASan / UBSan with GCC or Clang, using the existing tests
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DANLIU_ENABLE_SANITIZERS=ON -DANLIU_BUILD_BENCHMARKS=OFF
cmake --build build-asan --parallel
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure

# Install the library, header, license and CMake package into a prefix
cmake --install build --prefix "$PWD/install"
```

The library is built as a static library only. After installation, use `find_package(AnLiu CONFIG REQUIRED)` and `target_link_libraries(app PRIVATE AnLiu::anliu)`, pointing `CMAKE_PREFIX_PATH` at the install prefix when configuring your application. Test programs are in the build directory and tools in `build/bench/`; multi-config generators may add a per-configuration subdirectory. Of course, the simplest option is to copy `anliu.h` / `anliu.c` into your project and use them directly.

```sh
./build/bench/anl_bench --quick s3 s4
REALNET_CLOCK=1 ./build/bench/realnet server --proto anlauto --test media --dir up --dur 150
```

---

## 1. Why "frames"

My previous work involved a lot of audio/video processing, and the pain points of real-time media transport are very familiar:

- **Latency matters more than completeness.** A video frame that arrives 500 ms late is no better than a lost one. Reliable transport blocks everything behind a single lost packet (head-of-line blocking), so stalls grow longer and latency keeps accumulating;
- **Any network jitter causes stalls.** A reliable protocol backs off, retransmits and backs off again on loss; the backlog keeps growing until the network recovers and playback "fast-forwards" to catch up;
- **Frames depend on each other.** If an I-frame is lost, none of the following P-frames can be decoded, and sending them only wastes bandwidth;
- **The application cannot see what the protocol is thinking.** Byte-stream / message interfaces such as ikcp have no notion of a "frame", so the application can only guess from the outside when to drop data.

So AnLiu builds frames into the protocol:

- `anl_stream_send_frame` / `anl_stream_recv_frame`: frame numbers are assigned by the protocol; the receiver gets `frame_no` and `lost_before` (how many frames were skipped before this one) and can drive the decoder directly;
- **Sender-side frame dropping**: a frame that stays in the queue longer than `max_age_ms` is dropped as a whole; frames already sent but expired are not retransmitted — a FWD tells the receiver to skip them instead;
- **Key-frame dependencies**: `drop_until_key` drops on the sender until the next key frame (dependent frames already in flight are cleared too); `rcv_drop_until_key` discards undecodable P-frames on the receiver;
- **Receiver deadline**: once later data reveals a gap and the wait exceeds the local `rcv_deadline_ms` (by default 3/5 of the local `max_age_ms`), the receiver can skip ahead to later frames; the deadline is not the sender-side frame age;
- **FEC**: see section 3.

### Bandwidth estimation

Video is at its best when the encoder bitrate matches the available bandwidth: too high and you get queuing, dropped frames and stalls; too low and quality is wasted. The congestion control therefore follows **BBRv2**, with bandwidth probing done the BBRv3 way (DESIGN 6.8). It is driven primarily by a bandwidth/delay model, adjusted by loss and queuing evidence, and continuously measures two things — **bottleneck bandwidth** (maximum delivery rate over the last 10 round trips) and **propagation delay** (minimum RTT over 10 seconds) — pacing at "bandwidth × gain" and keeping roughly two BDPs in flight. This bandwidth model is itself the estimate handed to the application:

```c
anl_stats st;
anl_get_stats(w, &st);
/* st.bw_estimate: bytes/s (wire bytes, including headers, retransmissions and FEC parity)
   st.bw_app_limited: 1 = the application sends less than the estimate; real bandwidth may be higher
   st.min_rtt / st.cc_state: propagation delay; STARTUP / DRAIN / PROBE_BW / PROBE_RTT */
```

**Bitrate for the encoder** (DESIGN 6.10): `st.target_rate` already excludes headers, FEC parity, retransmissions and a 10% margin; it is the total **payload** bytes/s all streams may send. A callback fires when it changes by more than 5%:

```c
static void on_rate(anl_t *w, uint32_t target_rate, void *user)
{
    uint32_t video_bytes = target_rate > audio_bytes_per_s ? target_rate - audio_bytes_per_s : 0;
    encoder_set_bitrate(user, (uint64_t)video_bytes * 8);   /* read-only stats; do not call other anl_* here */
}
anl_set_rate_callback(w, on_rate);
```

Compared with using `bw_estimate` directly, it does three more things: when application-limited (the encoder sends less than the estimate) with no queuing, the target rises by at most 25% per second so the encoder probes gradually; normal increases are capped at 25% per second, and sustained delivery-limited periods may recover within the measured delivery bound; when RTT shows the bottleneck is queuing, it drops immediately to the actual delivery rate — after a sudden bandwidth drop, before the encoder has caught up, semi-reliable data can expire before being acknowledged and BBR gets no samples for seconds, but RTT still reveals the queue. Comparison results are in [performance.md](performance.md).

**Receiver delay feedback** (DESIGN 6.9): every `max(srtt, 100 ms)` the receiver of a semi-reliable stream reports the measured jitter, queuing delay, frame delay (from the first fragment sent to the whole frame received, minus propagation delay), completed frames and skipped frames back to the sender:

```c
anl_stream_stats ss;
anl_stream_get_stats(video, &ss);
/* ss.peer: the peer's latest report (ss.peer.age_ms is the time since it arrived)
   ss.peer.frame_delay_max_ms rising → frames start arriving late: wait a moment before lowering the bitrate or inserting a key frame
   ss.rx: the same metrics measured locally as receiver */
anl_set_report_callback(w, on_report);   /* called when a report arrives */
```

Several adjustments were made to BBRv2 for real-time traffic (see DESIGN 6.8): loss is usually judged as congestion or not together with queuing signals, and PROBE_BW also slows down under very high loss; with no queuing, the sending rate and FEC overhead get limited compensation; when application-limited (video between key frames), the bandwidth measured during key frames is retained, and key-frame bursts are allowed while path bandwidth is unknown; the two different situations of a longer path delay (network switch) and a bandwidth drop are distinguished; regular bandwidth probing uses random 2~3 second wall-clock intervals with a per-round cap; and probing can start early when capacity recovers (DESIGN 6.8, 8.6).

---

## 2. Why multiple streams instead of multiple instances

Running several instances over the same link has a few fundamental problems:

1. **Bandwidth is shared, but congestion control is not.** Each instance has its own cwnd and retransmission rhythm and cannot see the others. When video fills the bottleneck queue, control and audio packets queue behind it and get tail-dropped, and their congestion control can do nothing about it;
2. **Signaling, audio and video differ in importance.** Control signaling ("request key frame", "mute", "hang up") is tiny but must arrive immediately; audio is the most latency-sensitive; video is the largest but can drop frames; file transfer only needs eventual delivery. There is no priority between separate instances;
3. **Overhead and fingerprinting.** Each instance sends its own ACKs with its own headers, producing many small packets; multiple convs are also easier to identify and correlate.

AnLiu's approach:

- Multiple streams in one connection **share** RTT estimation, the congestion window and the pacing token bucket; data and ACKs from all streams can go into the same datagram;
- **The default stream (sid 0) has strict priority**, suitable for control signaling; other streams have 4 priority levels with per-stream DATA quotas of **8 : 4 : 2 : 1**, retained across flushes. Lower priorities make progress while connection/stream windows permit and the default stream does not continuously consume all sending capacity; these are segment quotas, not wire-byte shares;
- Retransmissions go before new data, in priority order; retransmissions use at most 3/4 of the sending tokens, so a large lossy stream cannot crowd out new data of real-time streams;
- Loss detection (RACK) uses delivery evidence from the whole connection: a low-rate control stream with no later fragments of its own can still detect loss promptly from video deliveries;
- Each stream independently chooses reliable / semi-reliable, window, FEC and priority, and either side can open or close streams at any time: closing any stream immediately frees local queued, unacknowledged and unread data and tells the peer, whose end is then over: data that had arrived in order can still be read, then calls return `ANL_ECLOSED`, and the peer application closes its own handle. To ensure reliable delivery, the application must wait for `anl_stream_waitsnd` to reach zero before closing.

If the uplink quota is known, `cfg.pace_rate` sets an upper limit on BBR's sending rate. Priority and mixed-stream test results are in [performance.md](performance.md).

---

## 3. Why FEC

In real-time scenarios, retransmission is usually too late: a loss costs "loss detection + one retransmission round trip", which eats into the latency budget of real-time traffic. FEC trades extra bandwidth for time: the receiver rebuilds lost packets directly from parity packets, **without waiting for retransmission**. It can be enabled per stream (on for video and audio, off for files).

**Algorithm: Reed-Solomon** (Cauchy matrix over GF(2⁸), DESIGN 8). A block of k data packets gets m parity packets, and **any m** losses within the block can be recovered. RS can put more packets into one block without losing recovery power.

**Main parameter of fixed redundancy: the ratio** `fec_ratio` (parity packets per 100 data packets, default 25):

- A block collects for at most 100 ms (or 64 packets) before it is sealed; the fixed ratio allocates parity by accumulating the remainder of `k × ratio`, at most 16 parity packets per block; a block can span multiple frames, and actual recovery also depends on pacing, scheduling and network delay;
- Subsequent parity packets are spaced at least 5 ms apart; actual timing depends on flushes, pacing and scheduling. Small-block parity can ride with data from the same stream’s next block; other parity is sent separately (possibly with ECHO);
- For packets covered by parity, the sender's RACK wait starts from the send time of the block's last parity packet, RTO can also be delayed, subject to frame deadlines and whether a retry can still arrive in time (DESIGN 8.2).

**Adaptive redundancy** (`opt.fec_ratio = 0`, DESIGN 8.5): the nominal ratio is adjusted according to losses that were not recovered in time, and the actual parity count is decided together with the connection loss estimate, block size and redundancy budget. In adaptive mode the nominal ratio varies between 10% and 100%; the parity count is further limited by the per-block cap, the retransmission capability at low latency, and the capacity-shortage state. Ratio and latency comparisons are in [performance.md](performance.md).

**Defaults**: reliable streams have FEC off by default; semi-reliable streams default to `fec = ANL_FEC_RTT_AUTO`, which decides whether to enable FEC from the expected repair time, `fec_deadline_ms` and recent hard-loss evidence, and provides one bounded audio start-up protection plus key-frame protection. Adaptive redundancy is paused when capacity is insufficient. To keep FEC always on, set `fec = 1` explicitly: `fec_ratio = 25` for a fixed ratio, `0` for adaptive. Both ends must enable FEC; the receiver can set local options in the accept callback (see DESIGN 8.6).

---

## 4. Performance tests

Test conditions and historical data for simulated networks, real UDP paths, throughput, media latency, priority and FEC redundancy are collected in [performance.md](performance.md). Test tools and how to run them are described in section 6.

---

## 5. Encryption and "no fingerprint"

**Construction**: `tag = SipHash-2-4-128(k_mac, P)` truncated to 12 bytes, which also serves as the ChaCha20 nonce for encrypting the part after conv: `wire = tag || convx || ChaCha20(k_enc, tag, P[4..])`. The tag authenticates all of `P`, including conv; `convx` masks conv by XOR with public tag bytes. This is the SIV (synthetic IV) approach: no nonce counter has to be maintained, the same plaintext encrypts to the same output, and retransmissions after loss reveal no nonce pattern.

- **Per-direction keys**: both ends derive two independent key sets, "client→server" and "server→client", from a 32-byte PSK, so reflecting a peer's packet back to it fails authentication;
- **Never respond to authentication failures**: `anl_input` returns `ANL_EAUTH` and the caller must drop the packet silently, so active probing gets no response at all;
- **conv is visible**: version, packet type, sequence numbers and payload are encrypted. Anyone knowing the masking algorithm can recover conv without a key and correlate packets from the same connection; masking provides no confidentiality;
- **Random padding**: by default datagrams without DATA/PARITY get 1~32 random padding bytes, limited by available MTU space. DATA/PARITY datagrams are not padded; keepalives are always padded;
- **Replay**: every datagram carries its direction's packet number and the receiver remembers the last 4096; a repeated or older datagram is dropped after authentication (`ANL_EREPLAY`) without parsing any segment (DESIGN 4.3). The timestamp window (default 1 s) still drops datagrams held up for too long and a clock that went backwards (DESIGN 4.2). A replayed datagram still costs its decryption and authentication;
- **Forgery**: success probability per attempt is 2⁻⁹⁶.

**Known limitations** (evaluate before use):

- This is a custom cryptographic composition with **no existing security proof**, and it has not been audited by a third party;
- PSK only, **no key exchange and no forward secrecy**: if the PSK leaks, all past traffic can be decrypted;
- A single PSK should not exceed 2⁴⁰ datagrams in total across all connections and both directions (birthday bound, since the tag doubles as the nonce); rotate it before that;
- **Traffic timing is not hidden**: packet intervals, bursts and the rough packet-length distribution can still be analyzed statistically;
- Unauthenticated packets must be decrypted before they can be verified, so floods of garbage packets are relatively expensive in CPU.

---

## 6. Test methodology and test code

Testing has three layers: unit tests (functionality and robustness, reproducible), simulated comparison tests (performance against ikcp on the same simulated network, reproducible), and real-network tests (performance on real UDP paths). Every change goes through the process in 6.4.

### 6.1 Unit tests: `test.c`

`test.c` directly `#include "anliu.c"` (so it can inspect internal state) and contains a reproducible simulated network: loss, dropping a specific datagram, delay, jitter and reordering, duplication, bandwidth bottleneck and queue. The whole run is determined by a seed.

```sh
gcc -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined test.c -o anl_test -lm
./anl_test                          # default seed
ANL_TEST_SEED=1234 ./anl_test       # fixed seed, fully reproducible
ANL_TEST_ONLY=priority ./anl_test   # run only tests whose name contains "priority"
```

Coverage:

| Category | Tests |
|---|---|
| Cryptography | ChaCha20 (RFC 8439 vectors), SipHash-2-4 known answers; server dispatch (`anl_peek_conv` without keys, conv masking and tamper detection); reflection attack; replay (packet-number window: duplicate, reordered inside the window, below it, a jump ahead, beyond the ahead range, pn 0 after 2^31, wrap) and a stale timestamp |
| Reliable streams | 0% / 10% loss, message mode and byte-stream mode, content and order checks |
| Semi-reliable streams | 0% / 5% loss, with and without FEC, 1 Mbps congestion; frame numbers, `lost_before` accounting closes |
| FEC | Specific datagram drops (last fragment of a frame, 3 scattered, 4 consecutive) must be recovered by RS within one RTT; adaptive redundancy (falls to the floor without loss, rises on late losses, does not rise when retransmission is in time); audio + video streams adapting simultaneously; PARITY segment fuzzing |
| Key frames | Sender clears dependent frames in flight; receiver discards undecodable P-frames |
| Stream lifecycle | Close told to the peer and confirmed (lost CLOSE / RST, stream the peer never saw, both sides closing at once); semi-reliable close by sender / receiver; 31 streams opened on each side (with 10% loss); 64-stream limit; sid reuse (lowest free, 2 s hold and its growth with the timestamp window, a late first datagram of the earlier generation gets RST, a late ACK of the earlier generation taken for the new one's answer, an unanswered CLOSE given up, 9000 opens and closes with 10% loss and 5% duplicates); handle lifetime; accept callback |
| Scheduling and congestion control | Priority (5 combinations × BBR / BBR + rate cap); pacing burst cap; fragment size; links with RTT under 2 ms |
| Application interface | `target_rate`: an encoder following it climbs to the link rate and keeps up after a bandwidth drop; delay reports: measured on the receiver, received by the sender |
| Robustness | Recovery after a 5 s outage; protocol violation (RST); fuzzing with 20000 randomly mutated datagrams |

**Multi-seed sweep**: the same suite is run with 1000 seeds one by one under AddressSanitizer + UndefinedBehaviorSanitizer; failing seeds are rerun individually, traced down to the exact loss sequence, then fixed.

```sh
seq 1001 2000 | xargs -P 6 -I{} sh -c 'ANL_TEST_SEED={} ./anl_test > out_{}.txt 2>&1 || echo "{} failed"'
```

### 6.2 Simulated comparison: `bench/anl_bench`

AnLiu and ikcp (original `ikcp.c`, `nodelay 1, 10, 2, 1`) run on the same simulated network (1 ms virtual clock); on ikcp, semi-reliable traffic is sent reliably (`kcp`) or with an application-level frame-drop layer (`kcp+drop`). Results for the same seed are fully reproducible (random padding included).

```sh
cd bench && make
./anl_bench --quick                       # s1~s5: bulk, interactive, video, audio, mixed; 10 link types
./anl_bench --quick --fec-ratio 0 s3 s4   # FEC ratio: 1..100, 0 = adaptive
./anl_bench --quick bwstep                # bandwidth steps 8 → 2 → 5 → 1 → 8 Mbps: estimation, utilization, latency
./anl_bench --quick --abr bwstep          # same, video bitrate follows target_rate (--nobulk: fixed-bitrate baseline)
./anl_bench soak --soak 600               # 10-minute soak: link switches every 60 s (including 5 s outages, doubled RTT)
./anl_bench s1 --bw 0 --wnd 4096          # throughput without a bandwidth limit
./anl_bench s1 --bw 45000 --qdelay 3      # 3 ms bottleneck buffer: approximates a carrier rate limiter
./anl_bench s3 --av --bw 800 --tbf 16 --rtt 170 --fec-auto   # bottleneck is a token-bucket shaper with 16 KB burst (tc tbf), capacity below the media rate
./anl_bench --quick --nobulk bwstep --fec-auto --step-rtt 170  # audio/video-only bandwidth steps, path RTT 170 ms (8 → 2 → 5 → 1 → 8 Mbps)
BENCH_CC=100 ./anl_bench soak             # print congestion control state every 100 ms (stderr)
./anl_bench crypto                        # encryption/decryption cost (real clock)
```

Common options: `--seed N`, `--loss L,..` (%), `--rtt R,..` (ms), `--bw KBPS`, `--qdelay MS`, `--csv FILE`. Automatic checks: content corruption, reordering, gaps in reliable streams, frame number mismatches, accounting that does not close, and memory leaks are reported as ERROR; dead connections, long stalls, RTT estimate drift, slow outage recovery and similar are reported as WARN.

**Judge a change with many seeds**, not a single one: a small congestion-control change often alters the whole trajectory, and a difference on one seed is mostly divergence noise. A typical set: s3 / s4 with 20 seeds × 10 link types, s5 and bwstep with 20 seeds each, soak with 6~20 seeds, bwstep `--abr` with 10 seeds, plus the 6 seeds of the priority unit test. Build the code before and after the change and run the same seed set on both.

### 6.3 Real-network tests: `bench/realnet`

The same traffic runs over real UDP paths, with one `realnet` on the server and one on the client:

```sh
cd bench && make realnet              # build on both ends (same on the server)
export REALNET_CLOCK=1                # refresh the protocol clock to the current ms within a receive batch
# Server (AnLiu listens on UDP 9836 by default, ikcp on 9837; change with --port)
./realnet server --proto anlauto --test media --dir up --dur 150
# Client (same parameters as the server)
./realnet client --host <server address> --proto anlauto --test media --dir up --dur 150
```

| Option | Meaning |
|---|---|
| `--proto` | `anl` (no FEC), `anlfec` (fixed 25%), `anlauto` (adaptive), `kcp`, `kcpdrop` (ikcp + application-level frame dropping), `tcp` (system TCP, only for `--test stream`, as a baseline) |
| `--test media` | Audio 160 B / 20 ms + video 30 fps (about 940 kbps, a key frame every 30 frames), same as the simulation |
| `--test stream` | A reliable stream kept full for `--dur` seconds, throughput measured per second (average, worst second, 10th percentile) |
| `--test bulk` | Time to transfer `--bulk` MB over a reliable stream |
| `--wnd N` | Send/receive window of reliable streams (bulk / stream), in fragments (default 1024; 4096 for a larger window) |
| `--dir up / down` | Client sends / server sends |
| `--loss P` | Both ends randomly drop an extra P% on send, adding weak-network conditions on top of the real path (marked separately in reports) |

- **Latency**: each frame carries the sender's clock; the receiver measures "one-way delay − the stream's minimum one-way delay", i.e. the extra delay from queuing, retransmission and jitter, **without requiring clock synchronization**; on-time budgets match the simulation (audio 150 ms, video 300 ms).
- **Two protocols on one port**: each datagram carries one extra protocol-marker byte (tool layer); the client first sends 20 pings to measure path RTT.
- **Simultaneous comparison**: in media tests AnLiu and ikcp each run a process at the same time (different ports), so they see the same network conditions; throughput tests run one after the other to avoid competing for bandwidth.
- **About 12.5 minutes per round**: media uplink 150 s, media downlink 150 s (both protocols simultaneously), reliable stream uplink AnLiu / ikcp / TCP 75 s each, downlink 75 s each. Each combination runs 15 rounds spread across different times of day.
- **TCP baseline**: record the actual congestion control algorithm and buffer configuration and use the same per-second throughput statistics; if TCP goes through a proxy while UDP is direct, mark the path difference separately. Historical test environments are in performance.md.
- **Parallelism**: several combinations can run at once, but one host never runs the same kind of test (media / stream) twice at the same time; each combination uses its own ports.
- **Troubleshooting**: `REALNET_SECS=1` prints per-second throughput; after `make realnet_trace`, `REALNET_TRACE=1` prints congestion control internals every 100 ms (cwnd, bandwidth estimate, `bw_lo`, `inflight_hi`, PROBE_BW phase, loss rate, rate-limiter state). Clock and rate-limiter issues can be located from these; related historical measurements are in performance.md.
- **Integration tip**: `anl_input` computes RTT using the time of the most recent `anl_update`; calling `anl_update(now)` before receiving packets keeps RTT samples accurate (set `REALNET_CLOCK=1` when running `realnet`).

### 6.4 Process for each change

1. All unit tests pass (ASan / UBSan);
2. Simulated comparison: same seed set before and after the change (6.2); any regression in any scenario must be explained before deciding to fix or revert;
3. 1000-seed sweep;
4. Changes to congestion control, FEC or scheduling also get a real-network comparison (6.3);
5. Test data, code version and limitations go into performance.md; when implementation rules change, DESIGN.md is updated as well.

---

## 7. Next steps and suggestions

1. **Tuning rate adaptation**: `target_rate` and delay reports are implemented, but the growth policy and budget still need calibration with real encoders, mobile networks and weak Wi-Fi;
2. **Better FEC feedback**: losses are currently estimated from net reconstructions, skip operations and sender-side evidence; dedicated feedback for exact raw loss rate, burst length and actual parity usage could be added;
3. **Key exchange and forward secrecy**: only PSK for now; handshakes and session-key management are left to the application;
4. **Connection migration and path MTU discovery**: no address validation, migration handshake or automatic MTU probing yet;
5. **Receiver feedback in rate control**: delay reports are delivered to the application, but `target_rate` is currently computed mainly from the sender model, RTT and actual delivery;
6. **Continuous fuzzing**: long-running coverage-guided fuzzing of the decrypted-datagram parser (internal `anl_input_plain`).

---

## 8. Quick example

```c
#include "anliu.h"

static int udp_out(char *buf, int len, anl_t *w, void *user) {
    /* may first rewrite the clear 16-byte header (tag + conv) in place, same length */
    /* sendto(sock, buf, len, ...) */
    return 0;
}

anl_config cfg;
anl_config_default(&cfg, ANL_ROLE_CLIENT);        /* the peer uses ANL_ROLE_SERVER */
memcpy(cfg.psk, my_psk, 32);
anl_t *w = anl_create(conv, &cfg, NULL);
/* Real applications should check the return values of anl_create / anl_stream_open and all error codes */
anl_setoutput(w, udp_out);
anl_update(w, now_ms);                         /* initialize the monotonic ms clock before sending */

/* Default stream: reliable, strict priority, suitable for control signaling */
anl_send(w, "hello", 5);

/* Video stream: semi-reliable; frames older than 500 ms are neither sent nor retransmitted; drop until the next key frame */
anl_stream_opt o;
anl_stream_opt_default(&o, ANL_SEMI);
o.prio = 1; o.max_age_ms = 500; o.drop_until_key = 1;
anl_stream_t *video = anl_stream_open(w, &o, NULL);
anl_stream_send_frame(video, is_key ? ANL_FRAME_KEY : 0, frame, frame_len, NULL);

/* Main loop: refresh the monotonic ms clock before each received packet; check the time within a receive batch too */
anl_update(w, now_ms);
anl_input(w, pkt, pkt_len);                    /* ANL_EAUTH must be dropped silently */
/* Schedule the next timed update with anl_check(w, now_ms); when it is due, refresh now_ms and update */

/* When done */
anl_stream_close(video);                      /* the handle is invalid after close */
anl_release(w);
```

See `anliu.h` for the full API and [DESIGN.md](DESIGN.md) for protocol details.

## License

AnLiu is licensed under the MIT License; see [LICENSE](LICENSE).

`bench/ikcp.c` / `ikcp.h`, used for comparison tests, come from [skywind3000/kcp](https://github.com/skywind3000/kcp) under the MIT License; see `bench/LICENSE-ikcp`.
