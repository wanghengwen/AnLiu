/*
 * realnet: AnLiu vs ikcp over a real UDP path.
 *
 *   server:  ./realnet server [--port P] <test options>
 *   client:  ./realnet client --host H [--port P] <test options>
 *   (default port: AnLiu 9836, ikcp 9837)
 *
 * Both ends get the same test options:
 *   --proto anl | anlfec | anlauto | kcp | kcpdrop | tcp (stream test only: the
 *           kernel's TCP on the same port number, for comparison)
 *   --test  media (audio 160 B / 20 ms + video 30 fps ~940 kbps) | bulk (--bulk MB, timed)
 *           | stream (a reliable stream kept full for --dur seconds: goodput per second)
 *           | mixed (media and a full reliable stream at the same time; use --wnd 128 as anl_bench s5)
 *   --dir   up (client sends) | down (server sends)
 *   --dur S       media: seconds of traffic (default 60)
 *   --bulk MB     bulk: megabytes (default 16)
 *   --wnd N       bulk / stream: send and receive window in segments (default 1024;
 *                 about 1 MB, 30 Mbps at 280 ms RTT)
 *   --loss P      extra random loss in % on every datagram sent (both ends)
 *   --interval MS AnLiu cfg.interval (default 10)
 *   --init-cwnd N AnLiu initial congestion window in segments (default from library)
 *   --seed N
 *   --prio-audio N / --prio-video N  media stream priority 0..3, 0 highest (default audio 0, video 1)
 *   --adapt 1     media sender: closed loop, video frame sizes follow the target_rate
 *                 callback (an encoder model; ADAPT / ADAPTSUM lines)
 *
 *   REALNET_TIMEBASE=1  wall/monotonic anchors at traffic start and first delivered byte
 *   REALNET_SECS=1  stream: rounded SECS plus exact SECS_BYTES per-second payload bytes
 *   REALNET_TXDIAG=1  INTERNAL build: cumulative pacing budgets and sampled blocking times
 *   REALNET_FECCOST=1 INTERNAL build: exact protocol byte categories before emulated loss/sendto
 *   REALNET_RATE=1  record target-rate callbacks and their timestamps (all AnLiu builds)
 *   REALNET_MDIAG=1  media: per-frame send / receive records and 100 ms stream samples (MDIAG lines)
 * One UDP port carries everything: every datagram starts with one byte,
 * 'A' AnLiu, 'K' ikcp, 'H' hello (the client tells the server where it is),
 * 'P' / 'Q' ping / pong. Frames carry the sender's clock; the receiver
 * reports the one-way delay above the smallest one it saw on that flow
 * (queueing, retransmission, jitter), so no clock synchronisation is needed.
 *
 * Build:  gcc -std=gnu99 -O2 -I. -I.. realnet.c ../anliu.c ikcp.c -o realnet -lm
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <math.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#ifdef REALNET_INTERNAL
#include "anliu.h"
static void trace_lt_interval(const anl_t *, uint32_t, uint32_t, uint32_t, uint32_t, int);
static void trace_dead(const anl_t *, const char *, int, uint32_t, uint32_t, uint32_t, uint32_t);
static void trace_pace_refill(const anl_t *, uint32_t, uint64_t, uint64_t);
static void trace_tx_output(const anl_t *, uint32_t, int);
static void trace_media_tx_output(const anl_t *, uint32_t, int);
static void trace_seg_commit(const anl_t *, uint32_t, int);
static void trace_data_seg(const anl_t *, const anl_stream_t *, const void *, uint32_t, int);
static void trace_parity_seg(const anl_t *, int, uint32_t);
static void trace_fec_block(const anl_t *, const anl_stream_t *, uint32_t, uint32_t, uint32_t, int);
static void trace_flush(const anl_t *, int64_t, int64_t, int);
static void trace_lt_begin(const anl_t *);
#define ANL_TRACE_pace_refill trace_pace_refill
#define ANL_TRACE_tx_output trace_media_tx_output
#define ANL_TRACE_seg_commit trace_seg_commit
#define ANL_TRACE_data_seg trace_data_seg
#define ANL_TRACE_parity_seg trace_parity_seg
#define ANL_TRACE_fec_block trace_fec_block
#define ANL_TRACE_flush trace_flush
#define ANL_TRACE_policer_begin trace_lt_begin
#define ANL_TRACE_policer trace_lt_interval
#define ANL_TRACE_dead trace_dead
#include "anl_trace.h"
#include "../anliu.c"       /* build without ../anliu.c: REALNET_TRACE shows BBR internals */
#include "tx_diag.h"
#include "fec_diag.h"
static void trace_media_tx_output(const anl_t *w, uint32_t bytes, int paced)
{
    trace_tx_output(w, bytes, paced);
    fec_diag_output(w, bytes);
}
#define TX_OBSERVE(w) tx_diag_observe(&g_tx_diag, (w))
#elif defined(ANL_V2)
#include "anliuv2.h"
#else
#include "anliu.h"
#endif
#include "ikcp.h"
#ifndef TX_OBSERVE
#define TX_OBSERVE(w) ((void)0)
#endif

#define MTU         1400
#define KCP_CONV0   0x1000
#define NFLOW       4           /* flow ids 1 audio, 2 video, 3 bulk */
#define HDR         16          /* id key pad pad | seq u32 | send_us u64 */

enum { P_ANL, P_ANLFEC, P_ANLAUTO, P_KCP, P_KCPDROP, P_TCP };
static const char *proto_name[] = { "anl", "anlfec", "anlauto", "kcp", "kcpdrop", "tcp" };

typedef struct flow {
    const char *name;
    int id, semi, prio, wnd;
    int period_ms, size_min, size_max, key_min, key_max, gop;
    int max_age, budget_ms, until_key, kcp_thr;
    /* sender */
    uint32_t seq, sent, app_drop, dropping;
    uint64_t next_us, start_us;
    /* receiver */
    uint32_t dlv, max_seq, have;
    int64_t *owd; size_t nowd, capowd;
    int64_t *owdk; size_t nowdk, capowdk;  /* key frames only */
    uint64_t bytes;
} flow;

static flow g_fl[NFLOW];
static int g_proto = P_ANL, g_test = 0 /* 0 media, 1 bulk, 2 stream, 3 mixed */, g_up = 1, g_server = 0;
static int g_dur = 60, g_bulk_mb = 16, g_port = 0, g_wnd = 1024, g_interval = 10;      /* 0: anl 9836, kcp 9837 */
static double g_loss = 0;
static double g_rx_loss;
static uint64_t g_rx_proto_packets, g_rx_proto_dropped;
static int g_verify;
static uint64_t g_input_errors, g_output_errors, g_payload_errors, g_checked_bytes;
static uint64_t g_rng = 88172645463325252ull;
static uint64_t g_media_seed; /* workload is independent of loss, role and timer batching */
static const char *g_host = NULL;

static int g_fd = -1;
static struct sockaddr_storage g_peer;
static socklen_t g_peerlen = 0;
static uint64_t g_tx_bytes, g_tx_pkts, g_rx_bytes, g_rx_pkts, g_tx_dropped;
/* REALNET_CLOCK=1: give the protocol the current millisecond before every datagram
   of a receive batch (otherwise one update per batch) and end a batch after 5 ms
   (otherwise it runs while datagrams keep coming); batch size / duration and the
   protocol clock's lag behind the real clock at input are reported (CLOCK line) */
static int g_clock_refresh;
static int g_timebase; /* explicit wall/monotonic anchors for TC phase alignment */
static uint32_t g_protocol_ms;  /* timestamp actually supplied to ep_update */
/* REALNET_DRIVE=check: drive anl_update the way an application does - wait in
   poll until anl_check's time (or a frame, a ping, input), update only when
   due, before input when the millisecond moved (REALNET_CLOCK) - instead of
   updating twice per 1 ms poll */
static int g_drive_check;
static uint32_t g_next_upd;
static unsigned long long g_updates;
static int32_t ms_diff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }
static uint64_t g_clk_batches, g_clk_refreshes;
static uint32_t g_clk_max_pkts, g_clk_max_us, g_clk_max_lag;
static uint32_t g_clk_int_max_us;          /* largest receive batch since the last MDIAG sample */
static uint64_t g_t0_us;                   /* test start on this host (MDIAG receiver times) */

/* Buffer callback observations until the test ends; no terminal/file I/O in
   the callback. This observes the recommended payload rate, not a traffic
   generator control or a notification of every change in actual throughput. */
typedef struct {
    uint64_t mono_us, wire_bytes;
    uint32_t protocol_ms, previous;
    anl_stats stats;
} rate_event;
#define RATE_EVENT_MAX 65536u
static int g_rate_diag;
static rate_event *g_rate_events;
static size_t g_nrate, g_caprate;
static uint64_t g_rate_calls, g_rate_dropped;
static uint32_t g_rate_previous;

/* REALNET_MDIAG=1 (media test): per-frame sender / receiver records and 100 ms
   stream samples, kept in memory and printed at the end (MDIAG_S / MDIAG_R /
   MDIAG_T lines), so the diagnosis does not disturb the timing it looks at */
typedef struct { uint32_t t_ms, seq, frame_no, len; int8_t id, key; int16_t rc; } mdiag_s;
typedef struct { uint32_t seq, frame_no, lost_before, len; int64_t owd_us; uint64_t mono_us; int8_t id, key; } mdiag_r;
typedef struct { uint32_t t_ms; int id; anl_stream_stats ss; anl_stats cs; uint32_t batch_us; } mdiag_t;
static int g_mdiag;
static int g_init_cwnd;                    /* 0 keeps the library default */
static int g_pace_rate, g_pace_burst;      /* anl_config.pace_rate (B/s) / pace_burst (B); 0 keeps the library default */
static int g_start_rate;                    /* anl_config.start_rate (B/s), --start-rate; 0 = off (library default) */
/* --adapt 1: closed loop - the sender's video frame sizes follow the library's
   target_rate callback like an encoder (payload B/s for all streams, less the
   8000 B/s of audio), scaled against the nominal 117500 B/s of frame_v1 video,
   between ADAPT_MIN and 1 (the encoder's maximum is the nominal rate) */
#define ADAPT_NOMINAL_VIDEO 117500
#define ADAPT_AUDIO         8000
#define ADAPT_MIN           100             /* per mille of the nominal video rate */
static int g_adapt;
static int g_adapt_scale = 1000;            /* per mille */
static uint64_t g_adapt_calls, g_adapt_sum_ms, g_adapt_wsum;   /* time-weighted mean scale */
static uint64_t g_adapt_last_us;
static int g_adapt_min = 1000;
static int g_adapt_max = 1000;             /* REALNET_VIDEO_MAX: the encoder's maximum, per mille of the nominal (1000..20000) */
static int g_fixed_scale;                  /* REALNET_FIXED_SCALE: video at this per mille, no rate callback */
static int g_rcv_deadline = -2, g_fec_rtt_auto, g_fec_ratio = -1; /* explicit policy A/B controls */
static int g_fec_ratio_flow[3] = { -1, -1, -1 };   /* --fec-ratio-audio / --fec-ratio-video: per-flow override, [1] audio, [2] video */
static int g_rcv_deadline_flow[3] = { -2, -2, -2 }; /* --rcv-deadline-audio / --rcv-deadline-video: per-flow receiver gap wait */
static int g_prio_flow[3] = { -1, -1, -1 };        /* --prio-audio / --prio-video: stream priority override (0..3, 0 highest), [1] audio, [2] video */
static mdiag_s *g_mds; static size_t g_nmds, g_capmds;
static mdiag_r *g_mdr; static size_t g_nmdr, g_capmdr;
static mdiag_t *g_mdt; static size_t g_nmdt, g_capmdt;
static int g_last_rc; static uint32_t g_last_fno;       /* of the last ep_send / ep_recv */
static anl_frame_info g_last_fi;
#define MDIAG_PUSH(a, n, cap, v) do { if ((n) == (cap)) { (cap) = (cap) ? (cap) * 2 : 4096; \
        (a) = realloc((a), (cap) * sizeof(*(a))); } (a)[(n)++] = (v); } while (0)

static anl_t *g_anl;
static anl_stream_t *g_h[NFLOW];
static ikcpcb *g_kcp[NFLOW];

/* bulk */
static uint64_t g_bulk_sent, g_bulk_rcvd, g_bulk_first_us, g_bulk_done_us;
static uint64_t g_bulk_last_us, g_gap_max_us, g_gap_max_at_us;   /* stream receive gaps inside --dur */
static unsigned g_gap_n1, g_gap_n2, g_gap_n5;
#define MAXSEC 3600
static uint64_t g_sec_bytes[MAXSEC];      /* stream: bytes received in each second after the first byte */

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}
static uint32_t now_ms(void) { return (uint32_t)(now_us() / 1000); }

static void rate_changed(anl_t *w, uint32_t target, void *user);
/* closed-loop encoder model (--adapt 1): keep a time-weighted mean of the scale */
static void adapt_rate(anl_t *w, uint32_t target, void *user)
{
    uint64_t t = now_us();
    int64_t v = (int64_t)target - ADAPT_AUDIO;
    int sc = v <= 0 ? ADAPT_MIN : (int)(v * 1000 / ADAPT_NOMINAL_VIDEO);
    if (sc > g_adapt_max) sc = g_adapt_max;
    if (sc < ADAPT_MIN) sc = ADAPT_MIN;
    if (g_adapt_last_us && g_t0_us && t > g_adapt_last_us) {
        uint64_t d = (t - g_adapt_last_us) / 1000;
        g_adapt_sum_ms += d; g_adapt_wsum += d * (uint64_t)g_adapt_scale;
    }
    g_adapt_last_us = t;
    g_adapt_calls++;
    g_adapt_scale = sc;
    if (g_t0_us && sc < g_adapt_min) g_adapt_min = sc;
    printf("ADAPT t_ms=%lld target_Bps=%u scale=%d\n", g_t0_us ? ((long long)t - (long long)g_t0_us) / 1000 : -1LL, target, sc);
    if (g_rate_diag) rate_changed(w, target, user);
}

static void rate_changed(anl_t *w, uint32_t target, void *user)
{
    uint64_t event_us = now_us();
    uint32_t previous = g_rate_previous;
    rate_event *e;
    (void)user;
    g_rate_calls++;
    g_rate_previous = target;
    if (g_nrate == g_caprate) {
        size_t cap = g_caprate ? g_caprate * 2 : 256;
        rate_event *p;
        if (cap > RATE_EVENT_MAX) { g_rate_dropped++; return; }
        p = realloc(g_rate_events, cap * sizeof(*p));
        if (!p) { g_rate_dropped++; return; }
        g_rate_events = p; g_caprate = cap;
    }
    e = &g_rate_events[g_nrate++];
    e->mono_us = event_us; e->protocol_ms = g_protocol_ms;
    e->wire_bytes = g_tx_bytes; e->previous = previous;
    anl_get_stats(w, &e->stats); /* explicitly permitted inside the rate callback */
}

/* Bracket the wall-clock sample with monotonic reads. This only aligns clocks
   on this host; cross-host offset/drift must be measured by the test operator. */
static void report_timebase(const char *event, uint64_t event_us)
{
    struct timespec wall;
    uint64_t before, after, wall_us;
    if (!g_timebase) return;
    before = now_us();
    clock_gettime(CLOCK_REALTIME, &wall);
    after = now_us();
    wall_us = (uint64_t)wall.tv_sec * 1000000ull + (uint64_t)wall.tv_nsec / 1000;
    printf("TIMEBASE event=%s event_mono_us=%llu anchor_mono_lo_us=%llu anchor_mono_hi_us=%llu wall_us=%llu\n",
           event, (unsigned long long)event_us, (unsigned long long)before,
           (unsigned long long)after, (unsigned long long)wall_us);
}

static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}
/* frame_v1: a stable size for each (seed, flow, sequence). A shared RNG makes
   equal --seed runs generate different frames when FEC changes packet counts. */
static int media_frame_size_raw(const flow *f, int key)
{
    int a = key ? f->key_min : f->size_min;
    int b = key ? f->key_max : f->size_max;
    uint64_t x;
    if (a >= b) return a;
    x = g_media_seed + ((uint64_t)f->seq + 1) * 0x9e3779b97f4a7c15ull
        + (uint64_t)f->id * 0xd1b54a32d192ed03ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    x ^= x >> 31;
    return a + (int)(x % (uint32_t)(b - a + 1));
}
static int media_frame_size(const flow *f, int key)
{
    int n = media_frame_size_raw(f, key);
    int sc = g_fixed_scale ? g_fixed_scale : g_adapt ? g_adapt_scale : 1000;
    if (f->id == 2 && sc != 1000) {
        n = (int)((int64_t)n * sc / 1000);
        if (n < 200) n = 200;               /* > HDR; a tiny P frame still carries headers */
    }
    return n;
}

static int is_anl(void) { return g_proto <= P_ANLAUTO; }
static int is_sender(void) { return g_server ? !g_up : g_up; }

#ifdef REALNET_INTERNAL
static void trace_dead(const anl_t *w, const char *reason, int sid, uint32_t sn,
                       uint32_t xmit, uint32_t enqueued, uint32_t last_sent)
{
    fprintf(stderr, "DEAD now=%u reason=%s sid=%d sn=%u xmit=%u enqueued=%u last_sent=%u"
            " last_rx=%u srtt=%d rto=%d lt=%d rate=%u pace=%u hold=%u\n",
            w->current, reason, sid, sn, xmit, enqueued, last_sent, w->last_rx,
            w->rx_srtt, w->rx_rto, w->lt.state, w->lt.rate, w->pace_rate, w->lt.hold);
}

/* Completed intervals, including local measurements lost when the detector
   resets its counters. "after" still has that interval's byte counters. */
static void trace_lt_interval(const anl_t *w, uint32_t dur, uint32_t rate,
                              uint32_t loss, uint32_t counted, int after)
{
    uint32_t sent = w->sent_wire - w->lt.sent0;
    const anl_stream_t *bulk = g_h[3];
    if (!after) tx_diag_print(w, "lt_end");
    if (!is_sender() || !getenv("REALNET_TRACE")) return;
    fprintf(stderr, "LTINT now=%u stage=%s st=%d ph=%d lt=%d k=%u from=%u tail=%u bad=%d hold=%u left=%u span=%u rounds=%u dur=%u"
            " sent=%u infl0=%llu infl1=%llu delivered=%llu lost=%llu loss=%u counted=%u"
            " rate=%u ref_loss=%u prev_rate=%u prev_loss=%u res=%u compensated=%u base=%u floor=%u probe=%u send_rate=%u pace=%u applied_pace=%u"
            " cwnd=%u infl=%u queued=%d sendable=%d rmt_wnd=%u snd_span=%u snd_queued=%u snd_buf=%u"
            " minrtt=%u qprobe=%u lag_ms=%d\n",
            w->current, after ? "after" : "before", w->bbr_state, w->probe_phase, w->lt.state, w->lt.k, w->lt.from,
            w->lt.tail, w->lt.bad, w->lt.hold, w->lt.left, w->lt.span, w->lt.rounds, dur,
            sent, (unsigned long long)w->lt.infl0, (unsigned long long)bbr_inflight_bytes(w),
            (unsigned long long)w->lt.rd, (unsigned long long)w->lt.lost, loss, counted,
            rate, w->lt.ref_loss, w->lt.prev_rate, w->lt.prev_loss, w->lt.res,
            sat32((uint64_t)rate * 1000 / (1000 - w->lt.res)), w->lt.rate, w->lt.rate / 8 * 7,
            bbr_lt_probe_rate(w), sat32((uint64_t)sent * 1000 / dur), compute_pace_rate(w), w->pace_rate,
            w->cwnd, w->inflight_segs, has_queued_data(w), has_new_data(w), bulk ? bulk->rmt_wnd : 0,
            bulk ? bulk->snd_nxt - bulk->snd_una : 0, bulk ? bulk->nsnd_que : 0, bulk ? bulk->nsnd_buf : 0,
            w->min_rtt, w->path.qflat_probe, tdiff(now_ms(), w->current));
}
#endif

/*--------------------------------------------------------------------
 * UDP
 *-------------------------------------------------------------------*/
static void udp_send(char tag, const char *buf, int len)
{
    char out[2048];
    if (g_peerlen == 0 || len + 1 > (int)sizeof(out)) return;
    if (g_loss > 0 && (rnd() % 1000000) < (uint32_t)(g_loss * 10000)) { g_tx_dropped++; return; }
    out[0] = tag;
    memcpy(out + 1, buf, (size_t)len);
    if (sendto(g_fd, out, (size_t)len + 1, 0, (struct sockaddr *)&g_peer, g_peerlen) > 0) {
        g_tx_bytes += (uint64_t)len + 1 + 28;
        g_tx_pkts++;
    } else g_output_errors++;
}

static int anl_out(char *buf, int len, anl_t *w, void *user)
{
    (void)w; (void)user;
    udp_send('A', buf, len);
    return 0;
}

static int kcp_out(const char *buf, int len, ikcpcb *k, void *user)
{
    (void)k; (void)user;
    udp_send('K', buf, len);
    return 0;
}

/*--------------------------------------------------------------------
 * flows and endpoints
 *-------------------------------------------------------------------*/
static void flows_init(void)
{
    flow *a = &g_fl[1], *v = &g_fl[2], *b = &g_fl[3];
    memset(g_fl, 0, sizeof(g_fl));
    a->name = "audio"; a->id = 1; a->semi = 1; a->prio = 0; a->wnd = 512;
    a->period_ms = 20; a->size_min = a->size_max = 160; a->max_age = 200; a->budget_ms = 150;
    /* REALNET_AUDIO_MAX_AGE: audio max_age in ms (fec_deadline is half of it); test tool only */
    if (getenv("REALNET_AUDIO_MAX_AGE")) {
        int ma = atoi(getenv("REALNET_AUDIO_MAX_AGE"));
        if (ma >= 50 && ma <= 2000) a->max_age = ma;
    }
    a->kcp_thr = 10;
    v->name = "video"; v->id = 2; v->semi = 1; v->prio = 1; v->wnd = 512;
    v->period_ms = 33; v->gop = 30; v->key_min = 25000; v->key_max = 35000; v->size_min = 2500; v->size_max = 3500;
    v->max_age = 500; v->budget_ms = 300; v->until_key = 1; v->kcp_thr = 140000 / 2 / 1376 + 1;
    /* REALNET_VIDEO_MAX_AGE: video max_age in ms (a longer latency budget); test tool only */
    if (getenv("REALNET_VIDEO_MAX_AGE")) {
        int ma = atoi(getenv("REALNET_VIDEO_MAX_AGE"));
        if (ma >= 50 && ma <= 5000) v->max_age = ma;
    }
    b->name = "bulk"; b->id = 3; b->semi = 0; b->prio = 3; b->wnd = g_wnd; b->budget_ms = 1000000;
}

#ifdef REALNET_INTERNAL
/* ZWND: spans in which the sender's bulk stream holds new data but the peer's
   last advertised window is 0 (window-probe recovery, suggestion.md 14:13). */
static uint64_t g_zw_start_us, g_zw_total_us, g_zw_max_us, g_zw_max_at_us;
static unsigned g_zw_n, g_zw_n1;
static void zwnd_sample(uint64_t t, uint64_t start_us)
{
    const anl_stream_t *b = g_h[3];
    int zero = b && b->rmt_wnd == 0 && b->nsnd_que > 0;
    if (zero && !g_zw_start_us) { g_zw_start_us = t; g_zw_n++; }
    if (!zero && g_zw_start_us) {
        uint64_t d = t - g_zw_start_us;
        g_zw_total_us += d; g_zw_n1 += d >= 1000000u;
        if (d > g_zw_max_us) { g_zw_max_us = d; g_zw_max_at_us = g_zw_start_us - start_us; }
        g_zw_start_us = 0;
    }
}
#endif

static int flow_active(int id) { return g_test == 3 || (g_test == 0 ? (id == 1 || id == 2) : id == 3); }

static void flow_opt(const flow *f, anl_stream_opt *o)
{
    anl_stream_opt_default(o, f->semi ? ANL_SEMI : ANL_RELIABLE);
    o->tag = f->id;
    o->prio = f->prio;
    o->snd_wnd = o->rcv_wnd = f->wnd;
    if (f->semi) {
        o->max_age_ms = f->max_age;
        o->drop_until_key = f->until_key;
        o->fec = 0; /* the named anl protocol remains an explicit no-FEC control */
        if (g_proto == P_ANLFEC) { o->fec = 1; o->fec_ratio = 25; }
        if (g_proto == P_ANLAUTO) { o->fec = 1; o->fec_ratio = 0; }
#ifdef ANL_FEC_RTT_AUTO
        if (g_fec_rtt_auto) { o->fec = ANL_FEC_RTT_AUTO; o->fec_ratio = 0; }
#endif
        if (g_fec_ratio >= 0) { o->fec = 1; o->fec_ratio = g_fec_ratio; }   /* --fec-ratio: fixed, 0 adaptive */
        if (f->id >= 1 && f->id <= 2 && g_fec_ratio_flow[f->id] >= 0) { o->fec = 1; o->fec_ratio = g_fec_ratio_flow[f->id]; }
        if (g_rcv_deadline >= -1) o->rcv_deadline_ms = g_rcv_deadline;
        if (f->id >= 1 && f->id <= 2 && g_rcv_deadline_flow[f->id] >= -1) o->rcv_deadline_ms = g_rcv_deadline_flow[f->id];
    }
}

static int accept_cb(anl_t *w, anl_stream_t *st, anl_stream_opt *opt, void *user)
{
    int tag = anl_stream_tag(st);
    (void)w; (void)user;
    if (tag <= 0 || tag >= NFLOW) return -1;
    flow_opt(&g_fl[tag], opt);
    g_h[tag] = st;
    return 0;
}

static void ep_create(void)
{
    int i;
    if (is_anl()) {
        anl_config cfg;
        anl_config_default(&cfg, g_server ? ANL_ROLE_SERVER : ANL_ROLE_CLIENT);
        memset(cfg.psk, 0x5a, sizeof(cfg.psk));
        cfg.mtu = MTU;
        cfg.interval = g_interval;
        if (g_init_cwnd) cfg.init_cwnd = g_init_cwnd;
        g_init_cwnd = cfg.init_cwnd;
        if (g_pace_rate) cfg.pace_rate = g_pace_rate;
        if (g_pace_burst) cfg.pace_burst = g_pace_burst;
#ifdef ANL_CONFIG_START_RATE
        if (g_start_rate) cfg.start_rate = g_start_rate;
        printf("PACECFG init_cwnd=%d pace_rate=%d pace_burst=%d start_rate=%d (0 = library default)\n",
               cfg.init_cwnd, cfg.pace_rate, cfg.pace_burst, cfg.start_rate);
#else
        if (g_start_rate) { fprintf(stderr, "--start-rate: this protocol build has no anl_config.start_rate\n"); exit(2); }
        printf("PACECFG init_cwnd=%d pace_rate=%d pace_burst=%d (0 = library default)\n", cfg.init_cwnd, cfg.pace_rate, cfg.pace_burst);
#endif
        g_anl = anl_create(0x5a5a0001, &cfg, NULL);
        anl_setoutput(g_anl, anl_out);
        anl_set_accept(g_anl, accept_cb);
        if (g_adapt && is_sender()) anl_set_rate_callback(g_anl, adapt_rate);
        else if (g_rate_diag) anl_set_rate_callback(g_anl, rate_changed);
        g_protocol_ms = now_ms();
        anl_update(g_anl, g_protocol_ms);
        return;
    }
    for (i = 1; i < NFLOW; i++) {
        ikcpcb *k;
        if (!flow_active(i)) continue;
        k = ikcp_create(KCP_CONV0 + (IUINT32)i, NULL);
        ikcp_setoutput(k, kcp_out);
        ikcp_setmtu(k, MTU);
        ikcp_wndsize(k, g_fl[i].wnd, g_fl[i].wnd);
        ikcp_nodelay(k, 1, 10, 2, 1);
        g_kcp[i] = k;
    }
}

static void ep_open_streams(void)
{
    int i, err = 0;
    if (!is_anl()) return;
    for (i = 1; i < NFLOW; i++) {
        anl_stream_opt o;
        if (!flow_active(i)) continue;
        flow_opt(&g_fl[i], &o);
        g_h[i] = anl_stream_open(g_anl, &o, &err);
        if (g_h[i] == NULL) { fprintf(stderr, "anl_stream_open %d failed %d\n", i, err); exit(1); }
    }
}

static void ep_update(uint32_t now)
{
    int i;
    g_protocol_ms = now;
    g_updates++;
    if (is_anl()) { anl_update(g_anl, now); TX_OBSERVE(g_anl); return; }
    for (i = 1; i < NFLOW; i++) if (g_kcp[i]) ikcp_update(g_kcp[i], now);
}

static void ep_input(const char *d, int len)
{
    if (g_clock_refresh) {
        uint32_t now = now_ms();
        if (now != g_protocol_ms) {
            ep_update(now);
            g_clk_refreshes++;
        }
    }
#ifdef REALNET_INTERNAL
    if (is_anl() && g_anl) {
        int32_t lag = tdiff(now_ms(), g_anl->current);
        if (lag > 0 && (uint32_t)lag > g_clk_max_lag) g_clk_max_lag = (uint32_t)lag;
    }
#endif
    if (is_anl()) {
        int ir = anl_input(g_anl, d, len);
        if (ir < 0 && ir != ANL_EREPLAY) g_input_errors++;     /* a duplicated datagram is taken once: no error */
        TX_OBSERVE(g_anl);
        return;
    }
    if (len >= 24) {
        IUINT32 conv = ikcp_getconv(d);
        uint32_t id = conv - KCP_CONV0;
        if (id < NFLOW && g_kcp[id]) ikcp_input(g_kcp[id], d, len);
    }
}

/* 0 sent, 1 dropped by the protocol / app policy */
static int ep_send(flow *f, const char *buf, int len, int key)
{
    int r;
    if (is_anl()) {
        if (!f->semi) {
            r = anl_stream_send(g_h[f->id], buf, len);
            TX_OBSERVE(g_anl);
            return r < 0;
        }
        g_last_fno = 0;
        r = anl_stream_send_frame(g_h[f->id], key ? ANL_FRAME_KEY : 0, buf, len, &g_last_fno);
        g_last_rc = r;
        TX_OBSERVE(g_anl);
        return r != 0;
    }
    if (g_proto == P_KCPDROP && f->semi) {
        int w = (int)g_kcp[f->id]->nsnd_que;
        if (key) f->dropping = 0;
        if (!key && (f->dropping || w > f->kcp_thr)) {
            if (f->until_key) f->dropping = 1;
            g_last_rc = 1; g_last_fno = f->seq;
            return 1;
        }
    }
    r = ikcp_send(g_kcp[f->id], buf, len);
    g_last_rc = r; g_last_fno = f->seq;
    return r < 0;
}

static int ep_waitsnd(int id)
{
    if (is_anl()) return g_h[id] ? anl_stream_waitsnd(g_h[id]) : 0;
    return g_kcp[id] ? ikcp_waitsnd(g_kcp[id]) : 0;
}

static int ep_recv(int id, char *buf, int cap)
{
    if (is_anl()) {
        anl_frame_info fi;
        if (g_h[id] == NULL) return -1;
        if (g_fl[id].semi) {
            int r = anl_stream_recv_frame(g_h[id], buf, cap, &fi);
            if (r >= 0) g_last_fi = fi;  /* info is unwritten on EAGAIN / other errors */
            return r;
        }
        return anl_stream_recv(g_h[id], buf, cap);
    }
    return g_kcp[id] ? ikcp_recv(g_kcp[id], buf, cap) : -1;
}

/*--------------------------------------------------------------------
 * traffic
 *-------------------------------------------------------------------*/
static char g_buf[1 << 20];      /* a key frame at REALNET_VIDEO_MAX 8000 is ~280 KB */

static void put_hdr(char *p, const flow *f, int key, uint32_t seq, uint64_t t)
{
    p[0] = (char)f->id; p[1] = (char)key; p[2] = p[3] = 0;
    memcpy(p + 4, &seq, 4);
    memcpy(p + 8, &t, 8);
}

static void gen_media(uint64_t t, uint64_t end_us)
{
    int i;
    for (i = 1; i <= 2; i++) {
        flow *f = &g_fl[i];
        /* REALNET_AUDIO_ONLY: no video frames (test tool only) */
        if (i == 2 && getenv("REALNET_AUDIO_ONLY")) continue;
        while (t >= f->next_us && f->next_us < end_us) {
            int key = f->gop && (f->seq % (uint32_t)f->gop) == 0;
            int len = media_frame_size(f, key);
            put_hdr(g_buf, f, key, f->seq, now_us());
            memset(g_buf + HDR, (int)(f->seq & 0xff), (size_t)(len - HDR));
            if (ep_send(f, g_buf, len, key) != 0) f->app_drop++;
            if (g_mdiag) {
                mdiag_s e;
                e.t_ms = (uint32_t)((now_us() - f->start_us) / 1000u); e.seq = f->seq; e.frame_no = g_last_fno;
                e.len = (uint32_t)len; e.id = (int8_t)i; e.key = (int8_t)key; e.rc = (int16_t)g_last_rc;
                MDIAG_PUSH(g_mds, g_nmds, g_capmds, e);
            }
            f->seq++;
            f->sent++;
            f->next_us = f->start_us + (uint64_t)f->seq * (uint64_t)f->period_ms * 1000u;
            if (i == 2) f->next_us = f->start_us + (uint64_t)f->seq * 1000000u / 30u;
        }
    }
}

static void gen_bulk(uint64_t t, uint64_t end_us)
{
    flow *f = &g_fl[3];
    uint64_t total = g_test >= 2 ? (t < end_us ? ~0ull : g_bulk_sent) : (uint64_t)g_bulk_mb << 20;
    while (g_bulk_sent < total && ep_waitsnd(3) < 2 * f->wnd) {
        int len = 1024;
        if (g_bulk_sent + (uint64_t)len > total) len = (int)(total - g_bulk_sent);
        put_hdr(g_buf, f, 0, f->seq, now_us());
        if (g_verify) {
            int j;
            for (j = 0; j < len; j++) g_buf[j] = (char)((g_bulk_sent + (uint64_t)j) * 31u + 7u);
        }
        if (ep_send(f, g_buf, len, 0) != 0) break;
        f->seq++;
        f->sent++;
        g_bulk_sent += (uint64_t)len;
    }
}

static void rx_frames(void)
{
    int i;
    for (i = 1; i < NFLOW; i++) {
        flow *f = &g_fl[i];
        int r;
        if (!flow_active(i)) continue;
        while ((r = ep_recv(i, g_buf, (int)sizeof(g_buf))) > 0) {
            uint64_t t = now_us();
            if (i == 3) {
                uint64_t sec;
                if (g_verify) {
                    int j;
                    for (j = 0; j < r; j++)
                        if ((uint8_t)g_buf[j] != (uint8_t)((g_bulk_rcvd + (uint64_t)j) * 31u + 7u)) g_payload_errors++;
                    g_checked_bytes += (uint64_t)r;
                }
                if (g_bulk_first_us == 0) { g_bulk_first_us = t; report_timebase("rx_first", t); }
                g_bulk_rcvd += (uint64_t)r;
                sec = (t - g_bulk_first_us) / 1000000u;
                if (sec < MAXSEC) g_sec_bytes[sec] += (uint64_t)r;
                if (g_bulk_last_us && sec < (uint64_t)g_dur) {
                    uint64_t gap = t - g_bulk_last_us;
                    if (gap > g_gap_max_us) { g_gap_max_us = gap; g_gap_max_at_us = g_bulk_last_us - g_bulk_first_us; }
                    g_gap_n1 += gap >= 1000000u; g_gap_n2 += gap >= 2000000u; g_gap_n5 += gap >= 5000000u;
                }
                g_bulk_last_us = t;
                if (g_test >= 2) continue;
                if (g_bulk_rcvd >= ((uint64_t)g_bulk_mb << 20) && g_bulk_done_us == 0) g_bulk_done_us = t;
                continue;
            }
            if (r >= HDR && g_buf[0] == (char)i) {
                uint32_t seq; uint64_t st;
                memcpy(&seq, g_buf + 4, 4);
                memcpy(&st, g_buf + 8, 8);
                if (f->nowd == f->capowd) {
                    f->capowd = f->capowd ? f->capowd * 2 : 4096;
                    f->owd = (int64_t *)realloc(f->owd, f->capowd * sizeof(int64_t));
                }
                f->owd[f->nowd++] = (int64_t)(t - st);
                if (g_buf[1]) {
                    if (f->nowdk == f->capowdk) {
                        f->capowdk = f->capowdk ? f->capowdk * 2 : 256;
                        f->owdk = (int64_t *)realloc(f->owdk, f->capowdk * sizeof(int64_t));
                    }
                    f->owdk[f->nowdk++] = (int64_t)(t - st);
                }
                if (g_mdiag) {
                    mdiag_r e;
                    /* Downlink frames can precede the client's traffic_start.
                       Convert to a signed offset only after that anchor exists. */
                    e.mono_us = t; e.seq = seq; e.len = (uint32_t)r; e.owd_us = (int64_t)(t - st);
                    e.frame_no = is_anl() ? g_last_fi.frame_no : seq; e.lost_before = is_anl() ? g_last_fi.lost_before : 0;
                    e.id = (int8_t)i; e.key = g_buf[1];
                    MDIAG_PUSH(g_mdr, g_nmdr, g_capmdr, e);
                }
                f->dlv++;
                if (!f->have || seq > f->max_seq) f->max_seq = seq;
                f->have = 1;
                f->bytes += (uint64_t)r;
            }
        }
    }
}

static int cmp64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}

static void report_receiver(void)
{
    int i;
    for (i = 1; i < NFLOW; i++) {
        flow *f = &g_fl[i];
        int64_t mn;
        size_t k, ontime = 0;
        double p50, p95, p99, pmax;
        if (!flow_active(i) || i == 3) continue;
        if (f->nowd == 0) { printf("RESULT %s %s dlv=0\n", proto_name[g_proto], f->name); continue; }
        mn = f->owd[0];
        for (k = 1; k < f->nowd; k++) if (f->owd[k] < mn) mn = f->owd[k];
        for (k = 0; k < f->nowd; k++) {
            f->owd[k] -= mn;
            if (f->owd[k] <= (int64_t)f->budget_ms * 1000) ontime++;
        }
        qsort(f->owd, f->nowd, sizeof(int64_t), cmp64);
        if (f->nowdk > 0) {
            for (k = 0; k < f->nowdk; k++) f->owdk[k] -= mn;
            qsort(f->owdk, f->nowdk, sizeof(int64_t), cmp64);
            printf("KEYFRAMES %s %s n=%zu p50=%.1f p95=%.1f max=%.1f\n", proto_name[g_proto], f->name, f->nowdk,
                   f->owdk[f->nowdk / 2] / 1000.0, f->owdk[f->nowdk * 95 / 100] / 1000.0, f->owdk[f->nowdk - 1] / 1000.0);
        }
        p50 = f->owd[f->nowd / 2] / 1000.0;
        p95 = f->owd[f->nowd * 95 / 100] / 1000.0;
        p99 = f->owd[f->nowd * 99 / 100] / 1000.0;
        pmax = f->owd[f->nowd - 1] / 1000.0;
        printf("RESULT %s %s dlv=%u sent~=%u ontime=%zu p50=%.1f p95=%.1f p99=%.1f max=%.1f kbps=%.0f\n",
               proto_name[g_proto], f->name, f->dlv, f->max_seq + 1, ontime, p50, p95, p99, pmax,
               f->bytes * 8.0 / 1000.0 / g_dur);
    }
    if (g_test >= 2) {
        int n = g_dur < MAXSEC ? g_dur : MAXSEC, k;
        static double v[MAXSEC];
        double sum = 0;
        uint64_t window_bytes = 0;
        for (k = 0; k < n; k++) {
            v[k] = g_sec_bytes[k] * 8.0 / 1e6; sum += v[k]; window_bytes += g_sec_bytes[k];
        }
        for (k = 1; k < n; k++) {                       /* insertion sort, n <= 3600 */
            double x = v[k]; int j = k - 1;
            while (j >= 0 && v[j] > x) { v[j + 1] = v[j]; j--; }
            v[j + 1] = x;
        }
        if (getenv("REALNET_SECS")) {
            printf("SECS");
            for (k = 0; k < n; k++) printf(" %.0f", g_sec_bytes[k] * 8.0 / 1e6);
            printf("\n");
            printf("SECS_BYTES base_mono_us=%llu step_us=1000000 n=%d window_bytes=%llu outside_bytes=%llu values=",
                   (unsigned long long)g_bulk_first_us, n, (unsigned long long)window_bytes,
                   (unsigned long long)(g_bulk_rcvd - window_bytes));
            for (k = 0; k < n; k++) printf("%s%llu", k ? " " : "", (unsigned long long)g_sec_bytes[k]);
            printf("\n");
        }
        printf("RESULT %s stream secs=%d bytes=%llu avg_Mbps=%.2f min_Mbps=%.2f p10_Mbps=%.2f p50_Mbps=%.2f max_Mbps=%.2f\n",
               proto_name[g_proto], n, (unsigned long long)g_bulk_rcvd, sum / n, v[0], v[n / 10], v[n / 2], v[n - 1]);
        if (g_proto != P_TCP)
            printf("BULKGAP max_ms=%.1f at_s=%.1f n_1s=%u n_2s=%u n_5s=%u (receive gaps within --dur after the first byte)\n",
                   g_gap_max_us / 1000.0, g_gap_max_at_us / 1e6, g_gap_n1, g_gap_n2, g_gap_n5);
    }
    if (g_test == 1) {
        double s = g_bulk_done_us ? (g_bulk_done_us - g_bulk_first_us) / 1e6 : -1;
        printf("RESULT %s bulk bytes=%llu done_s=%.2f goodput_KBps=%.0f\n", proto_name[g_proto],
               (unsigned long long)g_bulk_rcvd, s, s > 0 ? g_bulk_rcvd / 1024.0 / s : 0);
    }
}

static void report_mdiag(void)
{
    size_t k;
    if (!g_mdiag) return;
    printf("MDIAG proto=%s frames_sent=%zu frames_rcvd=%zu samples=%zu init_cwnd=%d rx_time=signed_start_ms\n", proto_name[g_proto], g_nmds, g_nmdr, g_nmdt, g_init_cwnd);
    /* sender: flow seq key len t_ms rc frame_no */
    for (k = 0; k < g_nmds; k++)
        printf("MDIAG_S %d %u %d %u %u %d %u\n", g_mds[k].id, g_mds[k].seq, g_mds[k].key, g_mds[k].len, g_mds[k].t_ms, g_mds[k].rc, g_mds[k].frame_no);
    /* receiver: flow seq key len t_ms owd_us frame_no lost_before;
       t_ms may be negative for data received before this host's traffic_start. */
    for (k = 0; k < g_nmdr; k++)
        printf("MDIAG_R %d %u %d %u %lld %lld %u %u\n", g_mdr[k].id, g_mdr[k].seq, g_mdr[k].key, g_mdr[k].len,
               g_t0_us ? ((long long)g_mdr[k].mono_us - (long long)g_t0_us) / 1000 : -1,
               (long long)g_mdr[k].owd_us, g_mdr[k].frame_no, g_mdr[k].lost_before);
    /* sampler: t_ms flow wait_snd backlog retrans dropped skipped fec_rec fec_ratio discarded
       rx_frame_delay_max peer_frame_delay_max | conn retrans srtt rto cwnd inflight pace batch_max_ms */
    for (k = 0; k < g_nmdt; k++) {
        const mdiag_t *e = &g_mdt[k];
        printf("MDIAG_T %u %d %u %u %u %u %u %u %u %u %u %u | %u %u %u %u %u %u %.1f\n", e->t_ms, e->id,
               e->ss.wait_snd, e->ss.backlog_bytes, e->ss.retrans, e->ss.frames_dropped, e->ss.frames_skipped,
               e->ss.fec_recovered, e->ss.fec_ratio, e->ss.frames_discarded,
               e->ss.rx.valid ? e->ss.rx.frame_delay_max_ms : 0, e->ss.peer.valid ? e->ss.peer.frame_delay_max_ms : 0,
               e->cs.retrans, e->cs.srtt, e->cs.rto, e->cs.cwnd, e->cs.inflight, e->cs.pace_rate, e->batch_us / 1000.0);
    }
}

static void report_rate(void)
{
    size_t i;
    if (g_fixed_scale && is_sender())
        printf("FIXEDSCALE scale=%d (per mille of %d B/s video, encoder feedback off)\n", g_fixed_scale, ADAPT_NOMINAL_VIDEO);
    if (g_adapt && is_anl() && is_sender()) {
        uint64_t t = now_us();
        if (g_adapt_last_us && t > g_adapt_last_us) {
            uint64_t d = (t - g_adapt_last_us) / 1000;
            g_adapt_sum_ms += d; g_adapt_wsum += d * (uint64_t)g_adapt_scale;
        }
        printf("ADAPTSUM callbacks=%llu mean_scale=%llu min_scale=%d last_scale=%d (per mille of %d B/s video)\n",
               (unsigned long long)g_adapt_calls, g_adapt_sum_ms ? (unsigned long long)(g_adapt_wsum / g_adapt_sum_ms) : 1000ull,
               g_adapt_min, g_adapt_scale, ADAPT_NOMINAL_VIDEO);
    }
    if (!g_rate_diag || !is_anl()) return;
    printf("RATE proto=%s side=%s metric=target_payload_Bps callbacks=%llu recorded=%zu dropped=%llu start_mono_us=%llu\n",
           proto_name[g_proto], is_sender() ? "sender" : "receiver",
           (unsigned long long)g_rate_calls, g_nrate, (unsigned long long)g_rate_dropped,
           (unsigned long long)g_t0_us);
    for (i = 0; i < g_nrate; i++) {
        const rate_event *e = &g_rate_events[i];
        const anl_stats *s = &e->stats;
        long long elapsed = g_t0_us ? ((long long)e->mono_us - (long long)g_t0_us) / 1000 : -1;
        printf("RATE_CHANGE mono_us=%llu t_ms=%lld protocol_ms=%u previous_Bps=%u target_Bps=%u"
               " bw_Bps=%u pace_Bps=%u srtt_ms=%u min_rtt_ms=%u cwnd=%u inflight=%u"
               " app_limited=%d bw_age_ms=%u retrans=%u wire_bytes=%llu\n",
               (unsigned long long)e->mono_us, elapsed, e->protocol_ms, e->previous, s->target_rate,
               s->bw_estimate, s->pace_rate, s->srtt, s->min_rtt, s->cwnd, s->inflight,
               s->bw_app_limited, s->bw_estimate_age_ms, s->retrans,
               (unsigned long long)e->wire_bytes);
    }
}

static void report_sender(double secs)
{
    int i;
    uint32_t srtt = 0, rtx = 0;
    if (is_anl()) {
        anl_stats st;
        anl_get_stats(g_anl, &st);
        srtt = st.srtt; rtx = st.retrans;
        printf("SENDER %s bw_estimate_kbps=%.0f target_kbps=%.0f min_rtt=%u\n", proto_name[g_proto],
               st.bw_estimate * 8.0 / 1000, st.target_rate * 8.0 / 1000, st.min_rtt);
    } else {
        for (i = 1; i < NFLOW; i++) {
            if (g_kcp[i] == NULL) continue;
            if ((uint32_t)g_kcp[i]->rx_srtt > srtt) srtt = (uint32_t)g_kcp[i]->rx_srtt;
            rtx += g_kcp[i]->xmit;
        }
    }
    for (i = 1; i < NFLOW; i++) {
        flow *f = &g_fl[i];
        if (!flow_active(i)) continue;
        printf("SENDER %s %s sent=%u app_drop=%u\n", proto_name[g_proto], f->name, f->sent, f->app_drop);
    }
    printf("SENDER %s wire_kbps=%.0f pkts=%llu emulated_drop=%llu srtt=%u xmit=%u secs=%.1f\n", proto_name[g_proto],
           g_tx_bytes * 8.0 / 1000.0 / secs, (unsigned long long)g_tx_pkts, (unsigned long long)g_tx_dropped, srtt, rtx, secs);
    printf("CLOCK refresh=%d batches=%llu refreshes=%llu max_batch_pkts=%u max_batch_ms=%.1f max_input_lag_ms=%u\n", g_clock_refresh,
           (unsigned long long)g_clk_batches, (unsigned long long)g_clk_refreshes, g_clk_max_pkts, g_clk_max_us / 1000.0, g_clk_max_lag);
}

/*--------------------------------------------------------------------
 * main loop
 *-------------------------------------------------------------------*/
/* --proto tcp: the stream test over one kernel TCP connection. The sender
   writes for --dur seconds from the connect; the receiver counts bytes per
   second from the first byte, reported like the UDP stream test. */
static int tcp_run(void)
{
    int fd, one = 1;                            /* default buffers: kernel autotuning */
    uint64_t t0 = now_us(), stop_us, end_us;
    static char buf[64 << 10];
    if (g_test != 2) { fprintf(stderr, "--proto tcp: stream test only\n"); return 2; }
    stop_us = t0 + (uint64_t)(g_dur + 120) * 1000000u;
    if (g_server) {
        struct sockaddr_in sa;
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        struct pollfd pfd;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)g_port);
        sa.sin_addr.s_addr = INADDR_ANY;
        if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(ls, 1) < 0) { perror("tcp listen"); return 1; }
        pfd.fd = ls; pfd.events = POLLIN; pfd.revents = 0;
        if (poll(&pfd, 1, (int)((stop_us - t0) / 1000)) <= 0) { printf("TIMEOUT tcp started=0\n"); return 0; }
        fd = accept(ls, NULL, NULL);
        close(ls);
    } else {
        struct addrinfo hints, *res;
        char port[16];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        snprintf(port, sizeof(port), "%d", g_port);
        if (getaddrinfo(g_host, port, &hints, &res) != 0) { fprintf(stderr, "resolve %s failed\n", g_host); return 1; }
        for (;;) {                                  /* the server may start a little later */
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) break;
            close(fd);
            if (now_us() - t0 > 20000000u) { printf("TIMEOUT tcp connect\n"); return 0; }
            usleep(200000);
        }
        freeaddrinfo(res);
    }
    if (fd < 0) { perror("tcp accept"); return 1; }
    end_us = now_us() + (uint64_t)g_dur * 1000000u;
    if (is_sender()) {
#ifdef __linux__
        struct tcp_info ti;
        socklen_t tl = sizeof(ti);
        socklen_t cl;
#endif
        char cc[32] = "?";
        uint64_t sent = 0;
        memset(buf, 'x', sizeof(buf));
        while (now_us() < end_us) {
            ssize_t n = send(fd, buf, sizeof(buf), MSG_NOSIGNAL);
            if (n <= 0) break;
            sent += (uint64_t)n;
        }
#ifdef __linux__
        memset(&ti, 0, sizeof(ti));
        cl = sizeof(cc);
        getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl);
        getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, &cl);
        cc[sizeof(cc) - 1] = 0;
        printf("SENDER tcp cc=%s sent=%llu retrans=%u rtt_ms=%.1f cwnd=%u secs=%d\n", cc, (unsigned long long)sent,
               ti.tcpi_total_retrans, ti.tcpi_rtt / 1000.0, ti.tcpi_snd_cwnd, g_dur);
#else                                               /* no TCP_INFO (macOS): bytes only */
        printf("SENDER tcp cc=%s sent=%llu secs=%d\n", cc, (unsigned long long)sent, g_dur);
#endif
        shutdown(fd, SHUT_WR);
        while (recv(fd, buf, sizeof(buf), 0) > 0) {}
    } else {
        for (;;) {
            struct pollfd pfd;
            ssize_t n;
            pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
            if (poll(&pfd, 1, 1000) < 0 || now_us() > stop_us) break;
            if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR))) continue;
            n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            {
                uint64_t t = now_us(), sec;
                if (g_bulk_first_us == 0) { g_bulk_first_us = t; report_timebase("rx_first", t); }
                g_bulk_rcvd += (uint64_t)n;
                sec = (t - g_bulk_first_us) / 1000000u;
                if (sec < MAXSEC) g_sec_bytes[sec] += (uint64_t)n;
            }
        }
        report_receiver();
    }
    close(fd);
    return 0;
}

/* A/K are protocol datagrams, including ACK/control; P/Q/H are probes. */
static int rx_emulated_drop(const char *in)
{
    if (in[0] != 'A' && in[0] != 'K') return 0;
    g_rx_proto_packets++;
    if (g_rx_loss > 0 && (rnd() % 1000000) < (uint64_t)(g_rx_loss * 10000)) {
        g_rx_proto_dropped++;
        return 1;
    }
    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: realnet server|client [--host H] [--port P] [--proto anl|anlfec|anlauto|kcp|kcpdrop|tcp]\n"
                    "       [--test media|bulk] [--dir up|down] [--dur S] [--bulk MB] [--loss P] [--seed N] [--init-cwnd N]\n"
                    "       [--pace-rate BYTES_PER_S] [--pace-burst BYTES] [--start-rate BYTES_PER_S (0 off)]\n"
                    "       [--rx-loss 0..15] (receive-side random protocol loss after physical network)\n"
                    "       [--rcv-deadline MS (-1 lifetime, 0 off)] [--fec-rtt-auto 0|1] [--fec-ratio 0..100 (0 adaptive)]\n"
                    "       [--fec-ratio-audio N] [--fec-ratio-video N] (per-flow override, 0 adaptive)\n"
                    "       [--rcv-deadline-audio MS] [--rcv-deadline-video MS] (per-flow receiver gap wait)\n"
                    "       [--prio-audio 0..3] [--prio-video 0..3] (stream priority, 0 highest; default audio 0, video 1)\n"
                    "       [--adapt 0|1] (media sender: video frame sizes follow the target_rate callback)\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int i;
    uint64_t t0, start_us = 0, end_us = 0, last_rx_us = 0, last_hello_us = 0, stop_us, last_trace_us = 0, last_mdiag_us = 0;
    int started = 0, got_any = 0, pinged = 0, failed = 0;
    uint64_t ping_sent_us[20] = { 0 };
    double rtt_min = 1e9, rtt_sum = 0; int rtt_n = 0;
    if (argc < 2) usage();
    g_server = !strcmp(argv[1], "server");
    if (!g_server && strcmp(argv[1], "client")) usage();
    for (i = 2; i < argc; i++) {
        const char *a = argv[i], *nx = i + 1 < argc ? argv[i + 1] : NULL;
        if (!nx) usage();
        if (!strcmp(a, "--host")) g_host = nx;
        else if (!strcmp(a, "--port")) g_port = atoi(nx);
        else if (!strcmp(a, "--proto")) {
            int p;
            for (p = 0; p < 6; p++) if (!strcmp(nx, proto_name[p])) g_proto = p;
        } else if (!strcmp(a, "--test")) g_test = !strcmp(nx, "bulk") ? 1 : !strcmp(nx, "stream") ? 2 : !strcmp(nx, "mixed") ? 3 : 0;
        else if (!strcmp(a, "--dir")) g_up = strcmp(nx, "down") != 0;
        else if (!strcmp(a, "--dur")) g_dur = atoi(nx);
        else if (!strcmp(a, "--bulk")) g_bulk_mb = atoi(nx);
        else if (!strcmp(a, "--wnd")) g_wnd = atoi(nx);
        else if (!strcmp(a, "--interval")) g_interval = atoi(nx);
        else if (!strcmp(a, "--init-cwnd")) {
            g_init_cwnd = atoi(nx);
            if (g_init_cwnd < 1 || g_init_cwnd > ANL_MAX_WND) usage();
        }
        else if (!strcmp(a, "--pace-rate")) {
            g_pace_rate = atoi(nx);
            if (g_pace_rate < 0) usage();
        }
        else if (!strcmp(a, "--pace-burst")) {
            g_pace_burst = atoi(nx);
            if (g_pace_burst < 0) usage();
        }
        else if (!strcmp(a, "--start-rate")) {
            g_start_rate = atoi(nx);
            if (g_start_rate < 0) usage();
        }
        else if (!strcmp(a, "--loss")) {
            g_loss = atof(nx);
            if (!isfinite(g_loss) || g_loss < 0 || g_loss > 15) usage();
        }
        else if (!strcmp(a, "--rx-loss")) {
            char *end;
            g_rx_loss = strtod(nx, &end);
            if (end == nx || *end || !isfinite(g_rx_loss) || g_rx_loss < 0 || g_rx_loss > 15) usage();
        }
        else if (!strcmp(a, "--rcv-deadline")) {
            g_rcv_deadline = atoi(nx);
            if (g_rcv_deadline < -1) usage();
        }
        else if (!strcmp(a, "--rcv-deadline-audio") || !strcmp(a, "--rcv-deadline-video")) {
            int v = atoi(nx);
            if (v < -1) usage();
            g_rcv_deadline_flow[a[15] == 'a' ? 1 : 2] = v;
        }
        else if (!strcmp(a, "--fec-ratio-audio") || !strcmp(a, "--fec-ratio-video")) {
            int v = atoi(nx);
            if (v < 0 || v > 100) usage();
            g_fec_ratio_flow[a[12] == 'a' ? 1 : 2] = v;
        }
        else if (!strcmp(a, "--adapt")) g_adapt = atoi(nx) != 0;
        else if (!strcmp(a, "--prio-audio") || !strcmp(a, "--prio-video")) {
            int v = atoi(nx);
            if (v < 0 || v > 3) usage();
            g_prio_flow[a[7] == 'a' ? 1 : 2] = v;
        }
        else if (!strcmp(a, "--fec-ratio")) {
            g_fec_ratio = atoi(nx);
            if (g_fec_ratio < 0 || g_fec_ratio > 100) usage();
        }
        else if (!strcmp(a, "--fec-rtt-auto")) {
            g_fec_rtt_auto = atoi(nx);
            if (g_fec_rtt_auto < 0 || g_fec_rtt_auto > 1) usage();
#ifndef ANL_FEC_RTT_AUTO
            if (g_fec_rtt_auto) { fprintf(stderr, "this protocol build has no RTT-conditional FEC\n"); return 2; }
#endif
        }
        else if (!strcmp(a, "--verify")) g_verify = atoi(nx) != 0;
        else if (!strcmp(a, "--seed")) {
            g_media_seed = (uint64_t)atoll(nx);
            g_rng ^= g_media_seed * 0x9E3779B97F4A7C15ull + (g_server ? 7 : 3);
        }
        else usage();
        i++;
    }
    if (!g_server && !g_host) usage();
    if (g_port == 0) g_port = is_anl() ? 9836 : 9837;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("RXLOSS_CONFIG probability_pct=%.1f scope=protocol_datagrams receive_point=after_network\n", g_rx_loss);
    if ((g_fec_ratio >= 0 || g_fec_ratio_flow[1] >= 0 || g_fec_ratio_flow[2] >= 0) && g_fec_rtt_auto) usage();   /* one FEC policy at a time */
    if (is_anl() && (g_test == 0 || g_test == 3))
        printf("POLICY proto=%s rcv_deadline=%d rcv_deadline_audio=%d rcv_deadline_video=%d fec_rtt_auto=%d fec_ratio=%d fec_ratio_audio=%d fec_ratio_video=%d prio_audio=%d prio_video=%d (-2=library_default, -1=proto default)\n",
               proto_name[g_proto], g_rcv_deadline, g_rcv_deadline_flow[1], g_rcv_deadline_flow[2], g_fec_rtt_auto, g_fec_ratio, g_fec_ratio_flow[1], g_fec_ratio_flow[2],
               g_prio_flow[1] >= 0 ? g_prio_flow[1] : 0, g_prio_flow[2] >= 0 ? g_prio_flow[2] : 1);
    g_timebase = getenv("REALNET_TIMEBASE") && atoi(getenv("REALNET_TIMEBASE")) != 0;
    if (g_proto == P_TCP) return tcp_run();
    if (g_test == 0 || g_test == 3)
        printf("WORKLOAD media=frame_v1 seed=%llu\n", (unsigned long long)g_media_seed);
    {
        const char *clock_mode = getenv("REALNET_CLOCK");
        g_clock_refresh = clock_mode && atoi(clock_mode) > 0;
        g_mdiag = getenv("REALNET_MDIAG") && atoi(getenv("REALNET_MDIAG")) > 0;
        if (getenv("REALNET_FIXED_SCALE")) {
            g_fixed_scale = atoi(getenv("REALNET_FIXED_SCALE"));
            if (g_fixed_scale < 1 || g_fixed_scale > 1000) { fprintf(stderr, "REALNET_FIXED_SCALE: 1..1000 per mille\n"); exit(2); }
        }
        if (getenv("REALNET_VIDEO_MAX")) {
            g_adapt_max = atoi(getenv("REALNET_VIDEO_MAX"));
            if (g_adapt_max < 1000 || g_adapt_max > 20000) { fprintf(stderr, "REALNET_VIDEO_MAX: 1000..20000 per mille\n"); exit(2); }
        }
        g_rate_diag = getenv("REALNET_RATE") && atoi(getenv("REALNET_RATE")) > 0;
        g_drive_check = getenv("REALNET_DRIVE") && !strcmp(getenv("REALNET_DRIVE"), "check");
    }
    flows_init();
    if (g_prio_flow[1] >= 0) g_fl[1].prio = g_prio_flow[1];
    if (g_prio_flow[2] >= 0) g_fl[2].prio = g_prio_flow[2];

    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fd < 0) { perror("socket"); return 1; }
    {
        int sz = 4 << 20;
        setsockopt(g_fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
        setsockopt(g_fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    }
    if (g_server) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)g_port);
        sa.sin_addr.s_addr = INADDR_ANY;
        if (bind(g_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
        printf("WORKLOAD_READY proto=%s port=%d test=%d\n", proto_name[g_proto], g_port, g_test);
    } else {
        struct addrinfo hints, *res;
        char port[16];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        snprintf(port, sizeof(port), "%d", g_port);
        if (getaddrinfo(g_host, port, &hints, &res) != 0) { fprintf(stderr, "resolve %s failed\n", g_host); return 1; }
        memcpy(&g_peer, res->ai_addr, res->ai_addrlen);
        g_peerlen = res->ai_addrlen;
        freeaddrinfo(res);
    }
#ifdef REALNET_INTERNAL
    g_tx_diag.enabled = getenv("REALNET_TXDIAG") && atoi(getenv("REALNET_TXDIAG")) != 0;
    g_fec_diag.enabled = getenv("REALNET_FECCOST") && atoi(getenv("REALNET_FECCOST")) != 0;
#endif
    ep_create();
    t0 = now_us();
    /* the client pings first (20 x 50 ms) to learn the path, then the test runs;
       the server waits for the client's hello; nobody waits longer than this */
    stop_us = t0 + (uint64_t)(g_dur + 120) * 1000000u;

    for (;;) {
        struct pollfd pfd;
        uint64_t t = now_us();
        int r;
        pfd.fd = g_fd; pfd.events = POLLIN; pfd.revents = 0;
        if (g_drive_check && is_anl()) {
            /* sleep until the protocol's next timer, the next frame or ping / hello;
               at most 100 ms (diagnostic samples, the end of the test) */
            uint32_t nm = now_ms();
            int32_t to = ms_diff(g_next_upd, nm);
            if (to > 100) to = 100;
            if (started && is_sender()) {
                for (i = 1; i <= 2; i++) if (flow_active(i) && g_fl[i].next_us < end_us) {
                    int64_t d = ((int64_t)g_fl[i].next_us - (int64_t)t + 999) / 1000;
                    if (d < to) to = (int32_t)d;
                }
            }
            if (!g_server) {
                int64_t d = ((int64_t)(last_hello_us + 200000u) - (int64_t)t + 999) / 1000;
                if (d < to) to = (int32_t)d;
                if (pinged < 20) { d = ((int64_t)(t0 + (uint64_t)pinged * 50000u) - (int64_t)t + 999) / 1000; if (d < to) to = (int32_t)d; }
                if (!started) { d = ((int64_t)(t0 + 1200000u) - (int64_t)t + 999) / 1000; if (d < to) to = (int32_t)d; }
            }
            r = poll(&pfd, 1, to > 0 ? to : 0);
            if (ms_diff(now_ms(), g_next_upd) >= 0) ep_update(now_ms());
        } else {
            r = poll(&pfd, 1, 1);
            /* the protocols take RTT samples against the time of their last update:
               give them the current time before the datagrams (anliu.h, anl_input) */
            ep_update(now_ms());
        }
        if (r > 0 && (pfd.revents & POLLIN)) {
            char in[2048];
            struct sockaddr_storage from;
            socklen_t fl = sizeof(from);
            ssize_t n;
            uint64_t b0 = now_us();
            uint32_t bn = 0;
            while ((n = recvfrom(g_fd, in, sizeof(in), MSG_DONTWAIT, (struct sockaddr *)&from, &fl)) > 0) {
                bn++;
                g_rx_bytes += (uint64_t)n + 28;
                g_rx_pkts++;
                if (g_server && g_peerlen == 0) {
                    memcpy(&g_peer, &from, fl); g_peerlen = fl;
                    /* a server that waited for its first client longer than the
                       idle timeout (30 s, SERVER default) is dead before the test
                       starts (anl_stream_open fails ANL_EDEAD): start it over */
                    if (is_anl() && anl_state(g_anl) < 0) { anl_release(g_anl); ep_create(); }
                }
                last_rx_us = now_us();
                if (rx_emulated_drop(in)) {
                    fl = sizeof(from);
                    if (g_clock_refresh && now_us() - b0 > 5000) break;
                    continue;
                }
                if (in[0] == 'P' && n >= 9) {                               /* ping: echo */
                    char q[16]; memcpy(q, in + 1, 8); udp_send('Q', q, 8);
                } else if (in[0] == 'Q' && n >= 9) {
                    uint64_t st; double rtt;
                    memcpy(&st, in + 1, 8);
                    rtt = (now_us() - st) / 1000.0;
                    if (rtt < rtt_min) rtt_min = rtt;
                    rtt_sum += rtt; rtt_n++;
                } else if (in[0] == 'H') {
                    /* hello: the server now knows the client's address */
                } else if (in[0] == 'A' && is_anl()) {
                    ep_input(in + 1, (int)n - 1); got_any = 1;
                } else if (in[0] == 'K' && !is_anl()) {
                    ep_input(in + 1, (int)n - 1); got_any = 1;
                }
                fl = sizeof(from);
                /* refresh mode: at most 5 ms per batch, so the updates made inside it
                   cannot keep the loop going and starve the rest of the main loop */
                if (g_clock_refresh && now_us() - b0 > 5000) break;
            }
            g_clk_batches++;
            if (bn > g_clk_max_pkts) g_clk_max_pkts = bn;
            if (now_us() - b0 > g_clk_max_us) g_clk_max_us = (uint32_t)(now_us() - b0);
            if (now_us() - b0 > g_clk_int_max_us) g_clk_int_max_us = (uint32_t)(now_us() - b0);
        }
        t = now_us();
        /* client: ping, then hello until the test starts, keep the NAT open */
        if (!g_server) {
            if (pinged < 20 && t >= t0 + (uint64_t)pinged * 50000u) {
                ping_sent_us[pinged] = t;
                udp_send('P', (const char *)&ping_sent_us[pinged], 8);
                pinged++;
            }
            if (t - last_hello_us >= 200000u) { udp_send('H', "h", 1); last_hello_us = t; }
        }
        /* the test starts after the pings (client) / at the first hello (server) */
        if (!started && ((!g_server && t >= t0 + 1200000u) || (g_server && g_peerlen > 0))) {
            started = 1;
            start_us = t;
            report_timebase("traffic_start", t);
            g_t0_us = t;
            end_us = start_us + (uint64_t)g_dur * 1000000u;
            if (is_sender()) {
                ep_open_streams();
                for (i = 1; i < NFLOW; i++) { g_fl[i].start_us = g_fl[i].next_us = start_us; }
            }
            if (!g_server) printf("PATH ping rtt_min=%.1f rtt_avg=%.1f replies=%d/20\n", rtt_min, rtt_n ? rtt_sum / rtt_n : 0, rtt_n);
        }
        if (started && is_sender()) {
            if (g_test == 0 || g_test == 3) gen_media(t, end_us);
            if (g_test != 0) gen_bulk(t, end_us);
        }
        if (!g_drive_check || !is_anl()) ep_update(now_ms());
        else {
            if (ms_diff(now_ms(), g_next_upd) >= 0) ep_update(now_ms());
            g_next_upd = anl_check(g_anl, now_ms());
        }
        rx_frames();
#ifdef REALNET_INTERNAL
        if (started && is_sender() && is_anl() && g_test >= 2) zwnd_sample(t, start_us);
#endif
        if (g_mdiag && started && (g_test == 0 || g_test == 3) && is_anl() && t - last_mdiag_us >= 100000u) {
            int j;
            last_mdiag_us = t;
            for (j = 1; j <= 2; j++) {
                mdiag_t e;
                if (g_h[j] == NULL) continue;
                memset(&e, 0, sizeof(e));
                e.t_ms = (uint32_t)((t - start_us) / 1000u); e.id = j; e.batch_us = g_clk_int_max_us;
                anl_stream_get_stats(g_h[j], &e.ss);
                anl_get_stats(g_anl, &e.cs);
                MDIAG_PUSH(g_mdt, g_nmdt, g_capmdt, e);
            }
            g_clk_int_max_us = 0;
        }
        if (started && is_sender() && is_anl() && getenv("REALNET_TRACE") && t - last_trace_us >= (uint64_t)atoi(getenv("REALNET_TRACE")) * 1000u) {
            anl_stats st;
            last_trace_us = t;
            anl_get_stats(g_anl, &st);
            fprintf(stderr, "TRACE t=%.1f st=%d cwnd=%u infl=%u bw=%u pace=%u srtt=%u minrtt=%u rtx=%u short=%d target=%u",
                    (t - start_us) / 1e6, st.cc_state, st.cwnd, st.inflight, st.bw_estimate, st.pace_rate, st.srtt, st.min_rtt, st.retrans,
                    st.capacity_short, st.target_rate);
#ifdef REALNET_INTERNAL
            fprintf(stderr, " btl=%u lo=%u hi=%llu ph=%d lr=%u qfall=%u q=%d rto_rd=%d rmin=%u burst=%u app=%d lt=%d lt.rate=%u lt.k=%u lt.span=%u rto=%d qflat=%u probed=%d",
                    g_anl->btl_bw, g_anl->bw_lo, (unsigned long long)g_anl->inflight_hi, g_anl->probe_phase, g_anl->loss_rate,
                    g_anl->path.qfall, bbr_queue_signal(g_anl), tdiff(g_anl->round_count, g_anl->rto_round) < 0, g_anl->prev_round_min_rtt,
                    g_anl->burst_bw, g_anl->app_limited != 0, g_anl->lt.state, g_anl->lt.rate, g_anl->lt.k, g_anl->lt.span, g_anl->rx_rto, g_anl->path.qflat, g_anl->path.min_rtt_probed);
            fprintf(stderr, " lt.hold=%u lt.bad=%d lt.from=%u lt.tail=%u lt.skip=%u lt.res=%u lt.prev_rate=%u lt.prev_loss=%u lt.post_startup=%u qprobe=%u",
                    g_anl->lt.hold, g_anl->lt.bad, g_anl->lt.from, g_anl->lt.tail, g_anl->lt.skip, g_anl->lt.res,
                    g_anl->lt.prev_rate, g_anl->lt.prev_loss, g_anl->lt.post_startup, g_anl->path.qflat_probe);
#endif
            fprintf(stderr, "\n");
        }
#ifdef REALNET_INTERNAL
        /* limiter events: one line whenever the policer detector or the BBR state changes
           (interval ends show as lt.hold / lt.k / lt.rate steps), between the periodic lines */
        if (started && is_sender() && is_anl() && getenv("REALNET_TRACE")) {
            static int ev_init, ev_lt, ev_bad, ev_st;
            static uint32_t ev_k, ev_rate, ev_hold, ev_tail, ev_skip, ev_prev;
            if (!ev_init || ev_lt != g_anl->lt.state || ev_k != g_anl->lt.k || ev_rate != g_anl->lt.rate || ev_hold != g_anl->lt.hold
                || ev_tail != g_anl->lt.tail || ev_skip != g_anl->lt.skip || ev_prev != g_anl->lt.prev_rate || ev_st != (int)g_anl->bbr_state) {
                anl_stats es;
                anl_get_stats(g_anl, &es);
                ev_init = 1; ev_lt = g_anl->lt.state; ev_k = g_anl->lt.k; ev_rate = g_anl->lt.rate; ev_hold = g_anl->lt.hold;
                ev_tail = g_anl->lt.tail; ev_skip = g_anl->lt.skip; ev_prev = g_anl->lt.prev_rate; ev_st = (int)g_anl->bbr_state; ev_bad = g_anl->lt.bad;
                fprintf(stderr, "LTEV t=%.3f st=%d lt=%d k=%u rate=%u prev_rate=%u prev_loss=%u res=%u hold=%u bad=%d from=%u tail=%u skip=%u rounds=%u btl=%u lo=%u pace=%u minrtt=%u lr=%u q=%d rtx=%u lt.post_startup=%u qprobe=%u now=%u\n",
                        (t - start_us) / 1e6, ev_st, ev_lt, ev_k, ev_rate, ev_prev, g_anl->lt.prev_loss, g_anl->lt.res, ev_hold, ev_bad,
                        g_anl->lt.from, ev_tail, ev_skip, g_anl->lt.rounds, g_anl->btl_bw, g_anl->bw_lo, es.pace_rate, g_anl->min_rtt,
                        g_anl->loss_rate, bbr_queue_signal(g_anl), es.retrans, g_anl->lt.post_startup, g_anl->path.qflat_probe, g_anl->current);
            }
        }
#endif
        /* End: media gets 3 s to drain; reliable bulk / stream wait for their
           send queues to empty, bounded by stop_us. Keep the normal receive
           loop while draining; the final linger only answers late ACKs.
           The receiver stops 5 s after the last datagram. */
        if (started && is_sender()) {
            int done = g_test == 0 ? t >= end_us + 3000000u
                     : g_test == 2 ? (t >= end_us && ep_waitsnd(3) == 0)
                     : g_test == 3 ? (t >= end_us + 3000000u && ep_waitsnd(3) == 0)
                                   : (g_bulk_sent >= ((uint64_t)g_bulk_mb << 20) && ep_waitsnd(3) == 0 && t >= start_us + 1000000u);
            if (done || t >= stop_us) {
                if (!done) failed = 1;
                double secs = (t - start_us) / 1e6;
                uint64_t linger = t + 2000000u;
                while (now_us() < linger) {                 /* answer the last ACKs */
                    char in[2048]; ssize_t n = recv(g_fd, in, sizeof(in), MSG_DONTWAIT);
                    if (n > 0) {
                        g_rx_bytes += (uint64_t)n + 28;
                        g_rx_pkts++;
                        if (!rx_emulated_drop(in) && in[0] == (is_anl() ? 'A' : 'K')) ep_input(in + 1, (int)n - 1);
                    }
                    ep_update(now_ms());
                    usleep(1000);
                }
                report_sender(g_test == 1 ? secs : g_dur);
#ifdef REALNET_INTERNAL
                if (is_anl() && g_test >= 2) {
                    if (g_zw_start_us) {            /* a span still open at the end is closed here */
                        uint64_t d = t - g_zw_start_us;
                        g_zw_total_us += d; g_zw_n1 += d >= 1000000u;
                        if (d > g_zw_max_us) { g_zw_max_us = d; g_zw_max_at_us = g_zw_start_us - start_us; }
                    }
                    printf("ZWND spans=%u spans_1s=%u total_ms=%.1f max_ms=%.1f max_at_s=%.1f (bulk new data queued, peer window 0)\n",
                           g_zw_n, g_zw_n1, g_zw_total_us / 1000.0, g_zw_max_us / 1000.0, g_zw_max_at_us / 1e6);
                }
#endif
                break;
            }
        }
        /* Duration-based receivers survive a pause inside the requested
           window; fixed-volume bulk retains its idle completion. */
        if (started && !is_sender() && got_any && (g_test == 1 || t >= end_us) &&
            t - last_rx_us > 5000000u) {
            report_receiver();
            printf("RECEIVER %s rx_kbps=%.0f ack_kbps=%.0f\n", proto_name[g_proto],
                   g_rx_bytes * 8.0 / 1000.0 / ((last_rx_us - start_us) / 1e6), g_tx_bytes * 8.0 / 1000.0 / ((last_rx_us - start_us) / 1e6));
            break;
        }
        if (t >= stop_us) {
            failed = 1;
            printf("TIMEOUT %s started=%d got_any=%d\n", proto_name[g_proto], started, got_any);
            if (!is_sender()) report_receiver();
            break;
        }
    }
    printf("RXLOSS probability_pct=%.1f proto_packets=%llu dropped_packets=%llu\n", g_rx_loss,
           (unsigned long long)g_rx_proto_packets, (unsigned long long)g_rx_proto_dropped);
    printf("DATAGRAM_COST tx_ipudp_bytes=%llu rx_ipudp_bytes=%llu tx_packets=%llu rx_packets=%llu\n",
           (unsigned long long)g_tx_bytes, (unsigned long long)g_rx_bytes,
           (unsigned long long)g_tx_pkts, (unsigned long long)g_rx_pkts);
    report_mdiag();
    report_rate();
    if (is_anl()) {
        int state = anl_state(g_anl), queued = ep_waitsnd(3);
        printf("HEALTH state=%d input_errors=%llu output_errors=%llu payload_errors=%llu checked_bytes=%llu queued=%d sent_bytes=%llu received_bytes=%llu\n",
               state, (unsigned long long)g_input_errors, (unsigned long long)g_output_errors,
               (unsigned long long)g_payload_errors, (unsigned long long)g_checked_bytes, queued,
               (unsigned long long)g_bulk_sent, (unsigned long long)g_bulk_rcvd);
        {
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            printf("DRIVE mode=%s updates=%llu cpu_user_ms=%ld cpu_sys_ms=%ld\n", g_drive_check ? "check" : "poll1ms", g_updates,
                   (long)ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000, (long)ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000);
        }
        if (state || g_input_errors || g_output_errors || g_payload_errors) failed = 1;
        if (is_sender() && g_test && queued) failed = 1;
#ifdef REALNET_INTERNAL
        tx_diag_print(g_anl, "final");
        fec_diag_print(g_anl);
        if (g_fec_diag.enabled && g_fec_diag.accounting_errors) failed = 1;
#endif
        anl_release(g_anl);
    } else for (i = 1; i < NFLOW; i++) if (g_kcp[i]) ikcp_release(g_kcp[i]);
    for (i = 1; i < NFLOW; i++) { free(g_fl[i].owd); free(g_fl[i].owdk); }
    free(g_mds); free(g_mdr); free(g_mdt);
    free(g_rate_events);
    close(g_fd);
    return failed;
}
