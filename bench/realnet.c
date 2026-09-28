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
 *   --dir   up (client sends) | down (server sends)
 *   --dur S       media: seconds of traffic (default 60)
 *   --bulk MB     bulk: megabytes (default 16)
 *   --wnd N       bulk / stream: send and receive window in segments (default 1024;
 *                 about 1 MB, 30 Mbps at 280 ms RTT)
 *   --loss P      extra random loss in % on every datagram sent (both ends)
 *   --interval MS AnLiu cfg.interval (default 10)
 *   --seed N
 *
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
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef REALNET_INTERNAL
#include "anliu.h"
static void trace_lt_interval(const anl_t *, uint32_t, uint32_t, uint32_t, uint32_t, int);
#define ANL_POLICER_TRACE trace_lt_interval
#include "../anliu.c"       /* build without ../anliu.c: REALNET_TRACE shows BBR internals */
#undef ANL_POLICER_TRACE
#elif defined(ANL_V2)
#include "anliuv2.h"
#else
#include "anliu.h"
#endif
#include "ikcp.h"

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
static int g_proto = P_ANL, g_test = 0 /* 0 media, 1 bulk, 2 stream */, g_up = 1, g_server = 0;
static int g_dur = 60, g_bulk_mb = 16, g_port = 0, g_wnd = 1024, g_interval = 10;      /* 0: anl 9836, kcp 9837 */
static double g_loss = 0;
static int g_verify;
static uint64_t g_input_errors, g_output_errors, g_payload_errors, g_checked_bytes;
static uint64_t g_rng = 88172645463325252ull;
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
static uint32_t g_protocol_ms;  /* timestamp actually supplied to ep_update */
static uint64_t g_clk_batches, g_clk_refreshes;
static uint32_t g_clk_max_pkts, g_clk_max_us, g_clk_max_lag;

static anl_t *g_anl;
static anl_stream_t *g_h[NFLOW];
static ikcpcb *g_kcp[NFLOW];

/* bulk */
static uint64_t g_bulk_sent, g_bulk_rcvd, g_bulk_first_us, g_bulk_done_us;
#define MAXSEC 3600
static uint64_t g_sec_bytes[MAXSEC];      /* stream: bytes received in each second after the first byte */

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}
static uint32_t now_ms(void) { return (uint32_t)(now_us() / 1000); }

static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}
static int rnd_range(int a, int b) { return a >= b ? a : a + (int)(rnd() % (uint32_t)(b - a + 1)); }

static int is_anl(void) { return g_proto <= P_ANLAUTO; }
static int is_sender(void) { return g_server ? !g_up : g_up; }

#ifdef REALNET_INTERNAL
/* Completed intervals, including local measurements lost when the detector
   resets its counters. "after" still has that interval's byte counters. */
static void trace_lt_interval(const anl_t *w, uint32_t dur, uint32_t rate,
                              uint32_t loss, uint32_t counted, int after)
{
    uint32_t sent = w->sent_wire - w->lt_sent0;
    const anl_stream_t *bulk = g_h[3];
    if (!is_sender() || !getenv("REALNET_TRACE")) return;
    fprintf(stderr, "LTINT now=%u stage=%s st=%d ph=%d lt=%d k=%u from=%u tail=%u bad=%d hold=%u left=%u span=%u rounds=%u dur=%u"
            " sent=%u infl0=%llu infl1=%llu delivered=%llu lost=%llu loss=%u counted=%u"
            " rate=%u ref_loss=%u prev_rate=%u prev_loss=%u res=%u compensated=%u base=%u floor=%u probe=%u send_rate=%u pace=%u applied_pace=%u"
            " cwnd=%u infl=%u queued=%d sendable=%d rmt_wnd=%u snd_span=%u snd_queued=%u snd_buf=%u"
            " minrtt=%u qprobe=%u lag_ms=%d\n",
            w->current, after ? "after" : "before", w->bbr_state, w->probe_phase, w->lt_state, w->lt_k, w->lt_from,
            w->lt_tail, w->lt_bad, w->lt_hold, w->lt_left, w->lt_span, w->lt_rounds, dur,
            sent, (unsigned long long)w->lt_infl0, (unsigned long long)bbr_inflight_bytes(w),
            (unsigned long long)w->lt_rd, (unsigned long long)w->lt_lost, loss, counted,
            rate, w->lt_ref_loss, w->lt_prev_rate, w->lt_prev_loss, w->lt_res,
            sat32((uint64_t)rate * 1000 / (1000 - w->lt_res)), w->lt_rate, w->lt_rate / 8 * 7,
            bbr_lt_probe_rate(w), sat32((uint64_t)sent * 1000 / dur), compute_pace_rate(w), w->pace_rate,
            w->cwnd, w->inflight_segs, has_queued_data(w), has_new_data(w), bulk ? bulk->rmt_wnd : 0,
            bulk ? bulk->snd_nxt - bulk->snd_una : 0, bulk ? bulk->nsnd_que : 0, bulk ? bulk->nsnd_buf : 0,
            w->min_rtt, w->qflat_probe, tdiff(now_ms(), w->current));
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

static int anl_out(const char *buf, int len, anl_t *w, void *user)
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
    a->kcp_thr = 10;
    v->name = "video"; v->id = 2; v->semi = 1; v->prio = 1; v->wnd = 512;
    v->period_ms = 33; v->gop = 30; v->key_min = 25000; v->key_max = 35000; v->size_min = 2500; v->size_max = 3500;
    v->max_age = 500; v->budget_ms = 300; v->until_key = 1; v->kcp_thr = 140000 / 2 / 1376 + 1;
    b->name = "bulk"; b->id = 3; b->semi = 0; b->prio = 3; b->wnd = g_wnd; b->budget_ms = 1000000;
}

static int flow_active(int id) { return g_test == 0 ? (id == 1 || id == 2) : id == 3; }

static void flow_opt(const flow *f, anl_stream_opt *o)
{
    anl_stream_opt_default(o, f->semi ? ANL_SEMI : ANL_RELIABLE);
    o->tag = f->id;
    o->prio = f->prio;
    o->snd_wnd = o->rcv_wnd = f->wnd;
    if (f->semi) {
        o->max_age_ms = f->max_age;
        o->drop_until_key = f->until_key;
        if (g_proto == P_ANLFEC) { o->fec = 1; o->fec_ratio = 25; }
        if (g_proto == P_ANLAUTO) { o->fec = 1; o->fec_ratio = 0; }
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
        g_anl = anl_create(0x5a5a0001, &cfg, NULL);
        anl_setoutput(g_anl, anl_out);
        anl_set_accept(g_anl, accept_cb);
        anl_update(g_anl, now_ms());
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
    if (is_anl()) { anl_update(g_anl, now); return; }
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
    if (is_anl()) { if (anl_input(g_anl, d, len) < 0) g_input_errors++; return; }
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
        if (!f->semi) return anl_stream_send(g_h[f->id], buf, len) < 0;
        r = anl_stream_send_frame(g_h[f->id], key ? ANL_FRAME_KEY : 0, buf, len, NULL);
        return r != 0;
    }
    if (g_proto == P_KCPDROP && f->semi) {
        int w = (int)g_kcp[f->id]->nsnd_que;
        if (key) f->dropping = 0;
        if (!key && (f->dropping || w > f->kcp_thr)) {
            if (f->until_key) f->dropping = 1;
            return 1;
        }
    }
    r = ikcp_send(g_kcp[f->id], buf, len);
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
        if (g_fl[id].semi) return anl_stream_recv_frame(g_h[id], buf, cap, &fi);
        return anl_stream_recv(g_h[id], buf, cap);
    }
    return g_kcp[id] ? ikcp_recv(g_kcp[id], buf, cap) : -1;
}

/*--------------------------------------------------------------------
 * traffic
 *-------------------------------------------------------------------*/
static char g_buf[1 << 18];

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
        while (t >= f->next_us && f->next_us < end_us) {
            int key = f->gop && (f->seq % (uint32_t)f->gop) == 0;
            int len = key ? rnd_range(f->key_min, f->key_max) : rnd_range(f->size_min, f->size_max);
            put_hdr(g_buf, f, key, f->seq, now_us());
            memset(g_buf + HDR, (int)(f->seq & 0xff), (size_t)(len - HDR));
            if (ep_send(f, g_buf, len, key) != 0) f->app_drop++;
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
    uint64_t total = g_test == 2 ? (t < end_us ? ~0ull : g_bulk_sent) : (uint64_t)g_bulk_mb << 20;
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
                if (g_bulk_first_us == 0) g_bulk_first_us = t;
                g_bulk_rcvd += (uint64_t)r;
                sec = (t - g_bulk_first_us) / 1000000u;
                if (sec < MAXSEC) g_sec_bytes[sec] += (uint64_t)r;
                if (g_test == 2) continue;
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
    if (g_test == 2) {
        int n = g_dur < MAXSEC ? g_dur : MAXSEC, k;
        static double v[MAXSEC];
        double sum = 0;
        for (k = 0; k < n; k++) { v[k] = g_sec_bytes[k] * 8.0 / 1e6; sum += v[k]; }
        for (k = 1; k < n; k++) {                       /* insertion sort, n <= 3600 */
            double x = v[k]; int j = k - 1;
            while (j >= 0 && v[j] > x) { v[j + 1] = v[j]; j--; }
            v[j + 1] = x;
        }
        if (getenv("REALNET_SECS")) {
            printf("SECS");
            for (k = 0; k < n; k++) printf(" %.0f", g_sec_bytes[k] * 8.0 / 1e6);
            printf("\n");
        }
        printf("RESULT %s stream secs=%d bytes=%llu avg_Mbps=%.2f min_Mbps=%.2f p10_Mbps=%.2f p50_Mbps=%.2f max_Mbps=%.2f\n",
               proto_name[g_proto], n, (unsigned long long)g_bulk_rcvd, sum / n, v[0], v[n / 10], v[n / 2], v[n - 1]);
    }
    if (g_test == 1) {
        double s = g_bulk_done_us ? (g_bulk_done_us - g_bulk_first_us) / 1e6 : -1;
        printf("RESULT %s bulk bytes=%llu done_s=%.2f goodput_KBps=%.0f\n", proto_name[g_proto],
               (unsigned long long)g_bulk_rcvd, s, s > 0 ? g_bulk_rcvd / 1024.0 / s : 0);
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
        struct tcp_info ti;
        socklen_t tl = sizeof(ti);
        char cc[32] = "?";
        socklen_t cl = sizeof(cc);
        uint64_t sent = 0;
        memset(buf, 'x', sizeof(buf));
        while (now_us() < end_us) {
            ssize_t n = send(fd, buf, sizeof(buf), MSG_NOSIGNAL);
            if (n <= 0) break;
            sent += (uint64_t)n;
        }
        memset(&ti, 0, sizeof(ti));
        getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl);
        getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, cc, &cl);
        cc[sizeof(cc) - 1] = 0;
        printf("SENDER tcp cc=%s sent=%llu retrans=%u rtt_ms=%.1f cwnd=%u secs=%d\n", cc, (unsigned long long)sent,
               ti.tcpi_total_retrans, ti.tcpi_rtt / 1000.0, ti.tcpi_snd_cwnd, g_dur);
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
                if (g_bulk_first_us == 0) g_bulk_first_us = t;
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

static void usage(void)
{
    fprintf(stderr, "usage: realnet server|client [--host H] [--port P] [--proto anl|anlfec|anlauto|kcp|kcpdrop|tcp]\n"
                    "       [--test media|bulk] [--dir up|down] [--dur S] [--bulk MB] [--loss P] [--seed N]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    int i;
    uint64_t t0, start_us = 0, end_us = 0, last_rx_us = 0, last_hello_us = 0, stop_us, last_trace_us = 0;
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
        } else if (!strcmp(a, "--test")) g_test = !strcmp(nx, "bulk") ? 1 : !strcmp(nx, "stream") ? 2 : 0;
        else if (!strcmp(a, "--dir")) g_up = strcmp(nx, "down") != 0;
        else if (!strcmp(a, "--dur")) g_dur = atoi(nx);
        else if (!strcmp(a, "--bulk")) g_bulk_mb = atoi(nx);
        else if (!strcmp(a, "--wnd")) g_wnd = atoi(nx);
        else if (!strcmp(a, "--interval")) g_interval = atoi(nx);
        else if (!strcmp(a, "--loss")) g_loss = atof(nx);
        else if (!strcmp(a, "--verify")) g_verify = atoi(nx) != 0;
        else if (!strcmp(a, "--seed")) g_rng ^= (uint64_t)atoll(nx) * 0x9E3779B97F4A7C15ull + (g_server ? 7 : 3);
        else usage();
        i++;
    }
    if (!g_server && !g_host) usage();
    if (g_port == 0) g_port = is_anl() ? 9836 : 9837;
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (g_proto == P_TCP) return tcp_run();
    {
        const char *clock_mode = getenv("REALNET_CLOCK");
        g_clock_refresh = clock_mode && atoi(clock_mode) > 0;
    }
    flows_init();

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
        r = poll(&pfd, 1, 1);
        /* the protocols take RTT samples against the time of their last update:
           give them the current time before the datagrams (anliu.h, anl_input) */
        ep_update(now_ms());
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
                if (g_server && g_peerlen == 0) { memcpy(&g_peer, &from, fl); g_peerlen = fl; }
                last_rx_us = now_us();
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
            end_us = start_us + (uint64_t)g_dur * 1000000u;
            if (is_sender()) {
                ep_open_streams();
                for (i = 1; i < NFLOW; i++) { g_fl[i].start_us = g_fl[i].next_us = start_us; }
            }
            if (!g_server) printf("PATH ping rtt_min=%.1f rtt_avg=%.1f replies=%d/20\n", rtt_min, rtt_n ? rtt_sum / rtt_n : 0, rtt_n);
        }
        if (started && is_sender()) {
            if (g_test == 0) gen_media(t, end_us);
            else gen_bulk(t, end_us);
        }
        ep_update(now_ms());
        rx_frames();
        if (started && is_sender() && is_anl() && getenv("REALNET_TRACE") && t - last_trace_us >= (uint64_t)atoi(getenv("REALNET_TRACE")) * 1000u) {
            anl_stats st;
            last_trace_us = t;
            anl_get_stats(g_anl, &st);
            fprintf(stderr, "TRACE t=%.1f st=%d cwnd=%u infl=%u bw=%u pace=%u srtt=%u minrtt=%u rtx=%u",
                    (t - start_us) / 1e6, st.cc_state, st.cwnd, st.inflight, st.bw_estimate, st.pace_rate, st.srtt, st.min_rtt, st.retrans);
#ifdef REALNET_INTERNAL
            fprintf(stderr, " btl=%u lo=%u hi=%llu ph=%d lr=%u qfall=%u q=%d rto_rd=%d rmin=%u burst=%u app=%d lt=%d lt_rate=%u lt_k=%u lt_span=%u rto=%d qflat=%u probed=%d",
                    g_anl->btl_bw, g_anl->bw_lo, (unsigned long long)g_anl->inflight_hi, g_anl->probe_phase, g_anl->loss_rate,
                    g_anl->qfall, bbr_queue_signal(g_anl), tdiff(g_anl->round_count, g_anl->rto_round) < 0, g_anl->prev_round_min_rtt,
                    g_anl->burst_bw, g_anl->app_limited != 0, g_anl->lt_state, g_anl->lt_rate, g_anl->lt_k, g_anl->lt_span, g_anl->rx_rto, g_anl->qflat, g_anl->min_rtt_probed);
            fprintf(stderr, " lt_hold=%u lt_bad=%d lt_from=%u lt_tail=%u lt_skip=%u lt_res=%u lt_prev_rate=%u lt_prev_loss=%u post_su=%u qprobe=%u",
                    g_anl->lt_hold, g_anl->lt_bad, g_anl->lt_from, g_anl->lt_tail, g_anl->lt_skip, g_anl->lt_res,
                    g_anl->lt_prev_rate, g_anl->lt_prev_loss, g_anl->post_startup, g_anl->qflat_probe);
#endif
            fprintf(stderr, "\n");
        }
#ifdef REALNET_INTERNAL
        /* limiter events: one line whenever the policer detector or the BBR state changes
           (interval ends show as lt_hold / lt_k / lt_rate steps), between the periodic lines */
        if (started && is_sender() && is_anl() && getenv("REALNET_TRACE")) {
            static int ev_init, ev_lt, ev_bad, ev_st;
            static uint32_t ev_k, ev_rate, ev_hold, ev_tail, ev_skip, ev_prev;
            if (!ev_init || ev_lt != g_anl->lt_state || ev_k != g_anl->lt_k || ev_rate != g_anl->lt_rate || ev_hold != g_anl->lt_hold
                || ev_tail != g_anl->lt_tail || ev_skip != g_anl->lt_skip || ev_prev != g_anl->lt_prev_rate || ev_st != (int)g_anl->bbr_state) {
                anl_stats es;
                anl_get_stats(g_anl, &es);
                ev_init = 1; ev_lt = g_anl->lt_state; ev_k = g_anl->lt_k; ev_rate = g_anl->lt_rate; ev_hold = g_anl->lt_hold;
                ev_tail = g_anl->lt_tail; ev_skip = g_anl->lt_skip; ev_prev = g_anl->lt_prev_rate; ev_st = (int)g_anl->bbr_state; ev_bad = g_anl->lt_bad;
                fprintf(stderr, "LTEV t=%.3f st=%d lt=%d k=%u rate=%u prev_rate=%u prev_loss=%u res=%u hold=%u bad=%d from=%u tail=%u skip=%u rounds=%u btl=%u lo=%u pace=%u minrtt=%u lr=%u q=%d rtx=%u post_su=%u qprobe=%u now=%u\n",
                        (t - start_us) / 1e6, ev_st, ev_lt, ev_k, ev_rate, ev_prev, g_anl->lt_prev_loss, g_anl->lt_res, ev_hold, ev_bad,
                        g_anl->lt_from, ev_tail, ev_skip, g_anl->lt_rounds, g_anl->btl_bw, g_anl->bw_lo, es.pace_rate, g_anl->min_rtt,
                        g_anl->loss_rate, bbr_queue_signal(g_anl), es.retrans, g_anl->post_startup, g_anl->qflat_probe, g_anl->current);
            }
        }
#endif
        /* end: the sender after the traffic plus 3 s of drain (bulk: once
           delivered and drained); the receiver 5 s after the last datagram */
        if (started && is_sender()) {
            int done = g_test == 0 ? t >= end_us + 3000000u
                     : g_test == 2 ? t >= end_us + 1000000u
                                   : (g_bulk_sent >= ((uint64_t)g_bulk_mb << 20) && ep_waitsnd(3) == 0 && t >= start_us + 1000000u);
            if (done || t >= stop_us) {
                if (!done) failed = 1;
                double secs = (t - start_us) / 1e6;
                uint64_t linger = t + 2000000u;
                while (now_us() < linger) {                 /* answer the last ACKs */
                    char in[2048]; ssize_t n = recv(g_fd, in, sizeof(in), MSG_DONTWAIT);
                    if (n > 0 && in[0] == (is_anl() ? 'A' : 'K')) ep_input(in + 1, (int)n - 1);
                    ep_update(now_ms());
                    usleep(1000);
                }
                report_sender(g_test == 1 ? secs : g_dur);
                break;
            }
        }
        if (started && !is_sender() && got_any && t - last_rx_us > 5000000u) {
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
    if (is_anl()) {
        int state = anl_state(g_anl), queued = ep_waitsnd(3);
        printf("HEALTH state=%d input_errors=%llu output_errors=%llu payload_errors=%llu checked_bytes=%llu queued=%d sent_bytes=%llu received_bytes=%llu\n",
               state, (unsigned long long)g_input_errors, (unsigned long long)g_output_errors,
               (unsigned long long)g_payload_errors, (unsigned long long)g_checked_bytes, queued,
               (unsigned long long)g_bulk_sent, (unsigned long long)g_bulk_rcvd);
        if (state || g_input_errors || g_output_errors || g_payload_errors) failed = 1;
        if (is_sender() && g_test && queued) failed = 1;
        anl_release(g_anl);
    } else for (i = 1; i < NFLOW; i++) if (g_kcp[i]) ikcp_release(g_kcp[i]);
    for (i = 1; i < NFLOW; i++) { free(g_fl[i].owd); free(g_fl[i].owdk); }
    close(g_fd);
    return failed;
}
