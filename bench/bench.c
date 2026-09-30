/*
 * bench.c - AnLiu vs ikcp comparison benchmark on a simulated network.
 *
 * Build (from AnLiu/bench):
 *   gcc -std=gnu99 -O2 -Wall -Wextra -I. -I.. bench.c ../anliu.c ikcp.c -o anl_bench -lm
 *
 * Usage:
 *   ./anl_bench                      s1..s5 + crypto on the default matrix
 *   ./anl_bench s3 --loss 10 --rtt 200 --dur 120
 *   ./anl_bench soak --soak 3600     long run, phase-changing network, timeline
 *   ./anl_bench --quick --csv out.csv
 *
 * Scenarios (all data flows A -> B, B only sends ACKs):
 *   s1  reliable bulk transfer        s2  reliable interactive 200 B / 20 ms
 *   s3  video 30 fps (semi)           s4  audio 160 B / 20 ms (semi)
 *   s5  audio + video + bulk over a 5 Mbps bottleneck
 *   soak  audio + video + interactive + bulk, network phases cycle, clock wraps
 *   crypto  per-datagram input cost (real clock)
 *
 * Virtual clock, 1 ms steps; runs are deterministic for a given --seed.
 * On ikcp, semi-reliable flows are sent reliably ("kcp") or with an
 * application-level drop policy on ikcp_waitsnd ("kcp+drop").
 */
#define _POSIX_C_SOURCE 200809L
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "anliu.h"
#include "ikcp.h"

#define MAXF        6
#define IPUDP_HDR   28          /* IPv4 + UDP header, counted in bandwidth */
#define MTU         1400
#define KCP_CONV0   0x1000

/*=====================================================================
 * random
 *===================================================================*/
static uint32_t rnd_next(uint64_t *s)
{
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return (uint32_t)(x >> 32);
}
static double rnd_unit(uint64_t *s) { return rnd_next(s) / 4294967296.0; }
static int rnd_range(uint64_t *s, int lo, int hi) { return hi <= lo ? lo : lo + (int)(rnd_next(s) % (uint32_t)(hi - lo + 1)); }

/*=====================================================================
 * memory accounting (both libraries accept an allocator hook)
 *===================================================================*/
typedef union { size_t n; long double pad; } mhdr;
static int64_t g_mem_live[2], g_mem_peak[2];

static void *mt_alloc(int k, size_t n)
{
    mhdr *h = (mhdr *)malloc(sizeof(mhdr) + n);
    if (h == NULL) return NULL;
    h->n = n;
    g_mem_live[k] += (int64_t)n;
    if (g_mem_live[k] > g_mem_peak[k]) g_mem_peak[k] = g_mem_live[k];
    return h + 1;
}
static void mt_free(int k, void *p)
{
    mhdr *h;
    if (p == NULL) return;
    h = (mhdr *)p - 1;
    g_mem_live[k] -= (int64_t)h->n;
    free(h);
}
static void *anl_m(size_t n) { return mt_alloc(0, n); }
static void anl_f(void *p) { mt_free(0, p); }
static void *kcp_m(size_t n) { return mt_alloc(1, n); }
static void kcp_f(void *p) { mt_free(1, p); }

/*=====================================================================
 * warnings / findings
 *===================================================================*/
static int g_errors, g_warnings;
static char g_label[160];
static char *g_find[4096];
static int g_nfind;

/* level 2 = correctness error (exit code 1), level 1 = suspicious behaviour */
static void finding(int level, const char *fmt, ...)
{
    char buf[512];
    int n;
    va_list ap;
    n = snprintf(buf, sizeof(buf), "%s %s: ", level >= 2 ? "ERROR" : "WARN ", g_label);
    va_start(ap, fmt);
    vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
    va_end(ap);
    if (level >= 2) g_errors++; else g_warnings++;
    if (g_nfind < (int)(sizeof(g_find) / sizeof(g_find[0]))) g_find[g_nfind++] = strdup(buf);
}

/*=====================================================================
 * network link model
 *===================================================================*/
typedef struct linkcfg {
    double loss;        /* 0..1 average loss */
    double burst;       /* > 1: Gilbert-Elliott with this mean burst length */
    int delay;          /* one-way ms */
    int jitter;         /* +- ms, packets may reorder */
    int bw_kbps;        /* bottleneck, 0 = unlimited */
    int qdelay;         /* bottleneck buffer depth in ms of queueing */
    double dup;         /* duplicate probability */
    int shift;          /* --rttshift: extra one-way delay the path switches on and off (route changes) */
    int shift_ms;       /* ... mean stay in each state, ms */
} linkcfg;

typedef struct pkt {
    struct pkt *prev, *next;
    uint64_t at;
    int len;
    char data[];
} pkt;

typedef struct dir {
    linkcfg c;
    int bad;
    uint64_t last_step;     /* burst model: time of the last state step + 1 */
    double free_at;
    uint64_t last_at;
    pkt *head, *tail;
    uint64_t rng;
    uint64_t pkts, bytes, lost_rand, lost_queue, delivered;
    double tokens, tok_t;   /* --policer: token bucket (bytes), time of the last refill */
    double tbf_tokens, tbf_t;   /* --tbf: the bottleneck as a token bucket shaper: bytes, last refill (ms) */
    int shifted;            /* --rttshift: the extra delay is on */
    uint64_t shift_until;   /* ... until */
} dir;

enum { P_ANL, P_KCP };

typedef struct variant {
    const char *name;
    int proto;
    int fec;            /* AnLiu stream FEC for semi flows */
    int drop;           /* ikcp application drop policy for semi flows */
} variant;

static const variant V_ANL  = { "anl",      P_ANL, 0, 0 };
static const variant V_ANLF = { "anl+fec",  P_ANL, 1, 0 };
static const variant V_KCP  = { "kcp",      P_KCP, 0, 0 };
static const variant V_KCPD = { "kcp+drop", P_KCP, 0, 1 };

struct sim;

typedef struct ep {
    struct sim *s;
    int side;
    int proto;
    anl_t *anl;
    anl_stream_t *h[MAXF];      /* AnLiu stream handle per flow (tag = flow sid) */
    ikcpcb *kcp[MAXF];
    uint64_t prng;              /* AnLiu padding / PRNG: seeded, so a run is reproducible */
} ep;

/*=====================================================================
 * flows
 *===================================================================*/
enum { F_BULK, F_INTER, F_VIDEO, F_AUDIO };

typedef struct flow {
    const char *name;
    int kind, sid, semi, prio;
    int snd_wnd, rcv_wnd;
    int fec, max_age, until_key;
    /* generator */
    int period_ms, size_min, size_max, key_min, key_max, gop, msg_size;
    uint64_t bulk_total;        /* 0 = unlimited */
    int bulk_rate;              /* bytes/s, 0 = saturate */
    int budget_ms;              /* on-time budget beyond one-way delay + jitter */
    int kcp_drop, kcp_thr, dropping;
    int send_err;
    uint64_t next_t, start_t;
    double credit;
    uint32_t seq;
    uint64_t offered;
    uint32_t app_drop, proto_drop, keys_sent;
    /* receiver */
    int rcv_any;
    uint32_t rcv_last;
    uint32_t delivered, ontime, keys_dlv;
    uint64_t rcv_bytes;
    uint32_t corrupt, order_err, gap, fno_bad;
    uint64_t lost_before_sum;
    uint32_t *lat; size_t nlat, caplat;
    uint64_t last_progress, max_stall, done_t;
    /* soak window snapshots */
    uint32_t w_seq, w_dlv, w_ontime; size_t w_lat; uint64_t w_bytes;
    /* soak outage recovery */
    uint64_t outage_end; int recovering;
} flow;

typedef struct sim {
    uint64_t t;             /* ms since start */
    uint32_t clk0;          /* protocol clock = clk0 + t */
    dir d[2];
    ep e[2];
    flow *fl;
    int nfl;
    const variant *v;
    int blackhole;
    int capture;
    char *cap[256]; int caplen[256]; int ncap;
} sim;

static uint32_t now32(const sim *s) { return s->clk0 + (uint32_t)s->t; }

/*---------------------------------------------------------------------
 * link
 *-------------------------------------------------------------------*/
static void dir_insert(dir *d, pkt *p)
{
    pkt *q = d->tail;
    while (q && q->at > p->at) q = q->prev;
    p->prev = q;
    p->next = q ? q->next : d->head;
    if (p->next) p->next->prev = p; else d->tail = p;
    if (q) q->next = p; else d->head = p;
}

/* Gilbert-Elliott: one state step per packet, plus one per idle millisecond
 * (at most 100) - a burst lasts a stretch of time, not a number of our own
 * packets. Stepping only per packet made a sender that sends one lone
 * retransmission every few seconds stay in the bad state for tens of seconds. */
static int link_lost(dir *d, uint64_t now)
{
    const linkcfg *c = &d->c;
    if (c->loss <= 0) return 0;
    if (c->loss >= 1) return 1;
    if (c->burst > 1) {
        double p_bg = 1.0 / c->burst;
        double p_gb = p_bg * c->loss / (1.0 - c->loss);
        uint64_t idle = now > d->last_step ? now - d->last_step : 0, k;
        if (idle > 100) idle = 100;
        for (k = 0; k <= idle; k++) {
            if (d->bad) { if (rnd_unit(&d->rng) < p_bg) d->bad = 0; }
            else if (rnd_unit(&d->rng) < p_gb) d->bad = 1;
        }
        d->last_step = now + 1;
        return d->bad;
    }
    return rnd_unit(&d->rng) < c->loss;
}

static int g_pol_kbps, g_pol_kb = 64;     /* --policer: token bucket rate, depth (0 = off) */
static int g_step_rtt = 50;                /* --step-rtt: bwstep path RTT, ms */
static int g_tbf_kb;                       /* --tbf: the bottleneck is a token bucket shaper (tc tbf) with this
                                              burst in KB: a burst of that size passes at once after an idle
                                              period, the rest waits for tokens (up to qdelay), 0 = plain FIFO */

static void sim_send(sim *s, int from, const char *buf, int len)
{
    dir *d = &s->d[from];
    double t = (double)s->t, extra = 0, delay;
    uint64_t at;
    pkt *p;

    if (s->capture && from == 0 && s->ncap < 256) {
        s->cap[s->ncap] = (char *)malloc((size_t)len);
        memcpy(s->cap[s->ncap], buf, (size_t)len);
        s->caplen[s->ncap++] = len;
    }
    if (s->blackhole) return;
    d->pkts++;
    d->bytes += (uint64_t)len;
    if (g_pol_kbps > 0) {       /* a policer: over the rate beyond the bucket is dropped, no queue */
        double cap = g_pol_kb * 1024.0;
        if (d->tok_t == 0 && d->tokens == 0) { d->tokens = cap; d->tok_t = t; }
        d->tokens += (t - d->tok_t) * g_pol_kbps / 8.0;
        if (d->tokens > cap) d->tokens = cap;
        d->tok_t = t;
        if (d->tokens < len + IPUDP_HDR) { d->lost_queue++; return; }
        d->tokens -= len + IPUDP_HDR;
    }
    if (d->c.bw_kbps > 0 && g_tbf_kb > 0) {
        /* tc tbf: tokens fill at the rate up to the burst; a packet leaves
           when it has its tokens - a full bucket lets a burst out at line
           rate, a delivery-rate sample over it reads far above the rate */
        double cap = g_tbf_kb * 1024.0, size = len + IPUDP_HDR, rate = d->c.bw_kbps / 8.0;  /* bytes per ms */
        double avail;
        if (d->tbf_t == 0 && d->tbf_tokens == 0) { d->tbf_tokens = cap; d->tbf_t = t; }
        /* tbf_t may lie ahead of t: the last packet took the tokens up to then */
        avail = d->tbf_tokens + (t - d->tbf_t) * rate;
        if (avail > cap) avail = cap;
        if (avail >= size) { d->tbf_tokens = avail - size; d->tbf_t = t; extra = 0; }
        else {
            double wait = (size - avail) / rate;
            if (wait > d->c.qdelay) { d->lost_queue++; return; }
            d->tbf_tokens = 0;
            d->tbf_t = t + wait;                /* tokens accumulate again after this departure */
            extra = wait;
        }
    } else if (d->c.bw_kbps > 0) {
        double ser = (len + IPUDP_HDR) * 8.0 / d->c.bw_kbps;     /* ms */
        double start = d->free_at > t ? d->free_at : t;
        if (start - t > d->c.qdelay) { d->lost_queue++; return; }
        d->free_at = start + ser;
        extra = d->free_at - t;
    }
    if (link_lost(d, s->t)) { d->lost_rand++; return; }
    delay = d->c.delay + extra;
    /* the path's own RTT moves between two values for a second or so at a
       time (a cross-border path over changing routes): every sample of a
       round sits above min_rtt without any queue */
    if (d->c.shift > 0 && d->c.shift_ms > 0) {
        if (s->t >= d->shift_until) {
            d->shifted = !d->shifted;
            d->shift_until = s->t + (uint64_t)rnd_range(&d->rng, d->c.shift_ms / 2, d->c.shift_ms * 3 / 2);
        }
        if (d->shifted) delay += d->c.shift;
    }
    if (d->c.jitter > 0) delay += rnd_range(&d->rng, -d->c.jitter, d->c.jitter);
    if (delay < 0) delay = 0;
    at = s->t + (uint64_t)ceil(delay);
    if (d->c.jitter == 0 && at < d->last_at) at = d->last_at;
    d->last_at = at;

    p = (pkt *)malloc(sizeof(pkt) + (size_t)len);
    p->at = at; p->len = len;
    memcpy(p->data, buf, (size_t)len);
    dir_insert(d, p);
    if (d->c.dup > 0 && rnd_unit(&d->rng) < d->c.dup) {
        pkt *q = (pkt *)malloc(sizeof(pkt) + (size_t)len);
        q->at = at + 1 + rnd_next(&d->rng) % 10; q->len = len;
        memcpy(q->data, buf, (size_t)len);
        dir_insert(d, q);
    }
}

static void dir_free(dir *d)
{
    while (d->head) { pkt *p = d->head; d->head = p->next; free(p); }
    d->tail = NULL;
}

/*---------------------------------------------------------------------
 * endpoint abstraction
 *-------------------------------------------------------------------*/
static int g_fast = 1;
static int g_init_cwnd;         /* --init-cwnd; 0 keeps the library default */

static int anl_out(const char *buf, int len, anl_t *w, void *user)
{
    ep *e = (ep *)user;
    (void)w;
    sim_send(e->s, e->side, buf, len);
    return 0;
}

static int kcp_out(const char *buf, int len, ikcpcb *k, void *user)
{
    ep *e = (ep *)user;
    (void)k;
    sim_send(e->s, e->side, buf, len);
    return 0;
}

static int anl_accept_flow(anl_t *w, anl_stream_t *st, anl_stream_opt *opt, void *user);

static uint64_t g_seed;         /* --seed (defined below) */

/* deterministic PRNG for AnLiu (padding lengths change the timing of a run) */
static void ep_rng(void *user, uint8_t *buf, size_t n)
{
    ep *e = (ep *)user;
    while (n--) {
        e->prng ^= e->prng << 13; e->prng ^= e->prng >> 7; e->prng ^= e->prng << 17;
        *buf++ = (uint8_t)(e->prng >> 24);
    }
}

static void ep_create(sim *s, int side, int proto)
{
    ep *e = &s->e[side];
    memset(e, 0, sizeof(*e));
    e->s = s; e->side = side; e->proto = proto;
    if (proto == P_ANL) {
        anl_config cfg;
        anl_config_default(&cfg, side == 0 ? ANL_ROLE_CLIENT : ANL_ROLE_SERVER);
        memset(cfg.psk, 0x5a, sizeof(cfg.psk));
        cfg.mtu = MTU;
        cfg.rng = ep_rng;
        e->prng = g_seed * 0x2545F4914F6CDD1DULL + (uint64_t)side * 0x9E3779B97F4A7C15ULL + 1;
        if (g_fast) cfg.interval = 10;
        if (g_init_cwnd) cfg.init_cwnd = g_init_cwnd;
        e->anl = anl_create(0x5a5a0001, &cfg, e);
        anl_setoutput(e->anl, anl_out);
        anl_set_accept(e->anl, anl_accept_flow);
        anl_update(e->anl, now32(s));
    }
}

static int g_abr = 0;              /* bwstep without the bulk flow: 1 = --abr (video follows
                                      stats.target_rate), 2 = --nobulk (fixed video bitrate) */
static int g_fec_ratio = -1;       /* --fec-ratio: FEC redundancy in %, 0 = adaptive (-1 = library default) */
static int g_rcv_deadline = -2;    /* -2 = library default, -1 = inherit lifetime, 0 = off */
static int g_fec_auto = 0;         /* --fec-auto: the FEC variants use ANL_FEC_RTT_AUTO (the semi default) */

static void flow_opt(const flow *f, anl_stream_opt *o)
{
    anl_stream_opt_default(o, f->semi ? ANL_SEMI : ANL_RELIABLE);
    o->tag = f->sid;
    o->prio = f->prio;
    o->snd_wnd = f->snd_wnd;
    o->rcv_wnd = f->rcv_wnd;
    if (f->semi) {
        o->fec = f->fec;
        if (g_fec_ratio >= 0) o->fec_ratio = g_fec_ratio;
#ifdef ANL_FEC_RTT_AUTO
        if (g_fec_auto && f->fec) o->fec = ANL_FEC_RTT_AUTO;
#endif
        o->max_age_ms = f->max_age;
        if (g_rcv_deadline >= -1) o->rcv_deadline_ms = g_rcv_deadline;
        o->drop_until_key = f->until_key;
    }
}

/* receiving side: the flow is identified by the tag, same options as the opener */
static int anl_accept_flow(anl_t *w, anl_stream_t *st, anl_stream_opt *opt, void *user)
{
    ep *e = (ep *)user;
    int i, tag = anl_stream_tag(st);
    (void)w;
    for (i = 0; i < e->s->nfl; i++) {
        if (e->s->fl[i].sid != tag) continue;
        flow_opt(&e->s->fl[i], opt);
        e->h[tag] = st;
        return 0;
    }
    return -1;
}

/* AnLiu: the opening side (0) opens, the other side gets the stream in anl_accept_flow */
static void ep_open(ep *e, const flow *f)
{
    if (e->proto == P_ANL) {
        anl_stream_opt o;
        int err = 0;
        if (e->side != 0) return;
        flow_opt(f, &o);
        e->h[f->sid] = anl_stream_open(e->anl, &o, &err);
        if (e->h[f->sid] == NULL) finding(2, "anl_stream_open flow %d failed %d", f->sid, err);
    } else {
        ikcpcb *k = ikcp_create(KCP_CONV0 + (IUINT32)f->sid, e);
        ikcp_setoutput(k, kcp_out);
        ikcp_setmtu(k, MTU);
        ikcp_wndsize(k, f->snd_wnd, f->rcv_wnd);
        if (g_fast) ikcp_nodelay(k, 1, 10, 2, 1);
        else ikcp_nodelay(k, 0, 100, 0, 0);
        e->kcp[f->sid] = k;
    }
}

static void ep_update(ep *e, uint32_t now)
{
    int i;
    if (e->proto == P_ANL) { anl_update(e->anl, now); return; }
    for (i = 0; i < MAXF; i++) if (e->kcp[i]) ikcp_update(e->kcp[i], now);
}

static void ep_input(ep *e, const char *data, int len)
{
    if (e->proto == P_ANL) {
        anl_input(e->anl, data, len);
    } else {
        IUINT32 conv = ikcp_getconv(data);
        uint32_t sid = conv - KCP_CONV0;
        if (sid < MAXF && e->kcp[sid]) ikcp_input(e->kcp[sid], data, len);
    }
}

static int ep_waitsnd(ep *e, int sid)
{
    if (e->proto == P_ANL) return anl_stream_waitsnd(e->h[sid]);
    return e->kcp[sid] ? ikcp_waitsnd(e->kcp[sid]) : 0;
}

/* 0 sent, 1 dropped by protocol, 2 dropped by app policy, <0 error */
static int ep_send(ep *e, flow *f, const char *buf, int len, int key)
{
    int r;
    if (e->proto == P_ANL) {
        if (!f->semi) return anl_stream_send(e->h[f->sid], buf, len);
        r = anl_stream_send_frame(e->h[f->sid], key ? ANL_FRAME_KEY : 0, buf, len, NULL);
        return r == ANL_EDROPPED ? 1 : r;
    }
    if (f->kcp_drop) {
        /* backlog = segments handed to ikcp but not yet sent (in-flight segments
           waiting for an ACK are not congestion: at 200 ms RTT audio always has
           ~10 of them) */
        int w = (int)e->kcp[f->sid]->nsnd_que;
        if (key) f->dropping = 0;
        if (!key && (f->dropping || w > f->kcp_thr)) {
            if (f->until_key) f->dropping = 1;
            return 2;
        }
    }
    r = ikcp_send(e->kcp[f->sid], buf, len);
    return r < 0 ? -100 + r : 0;
}

static int ep_recv(ep *e, flow *f, char *buf, int cap, anl_frame_info *info)
{
    info->frame_no = 0xffffffffu;
    if (e->proto == P_ANL) {
        if (e->h[f->sid] == NULL) return ANL_EAGAIN;
        if (f->semi) return anl_stream_recv_frame(e->h[f->sid], buf, cap, info);
        return anl_stream_recv(e->h[f->sid], buf, cap);
    }
    return ikcp_recv(e->kcp[f->sid], buf, cap);
}

static int ep_alive(const ep *e)
{
    int i;
    if (e->proto == P_ANL) return anl_state(e->anl) == 0;
    for (i = 0; i < MAXF; i++) if (e->kcp[i] && e->kcp[i]->state != 0) return 0;
    return 1;
}

typedef struct cstats { uint32_t srtt, rto, cwnd, rtx; int64_t rcvbuf; } cstats;

static void ep_stats(const ep *e, cstats *c)
{
    int i, n = 0;
    memset(c, 0, sizeof(*c));
    if (e->proto == P_ANL) {
        anl_stats st;
        anl_get_stats(e->anl, &st);
        c->srtt = st.srtt; c->rto = st.rto; c->cwnd = st.cwnd; c->rtx = st.retrans; c->rcvbuf = st.rcv_bytes;
        return;
    }
    for (i = 0; i < MAXF; i++) {
        const ikcpcb *k = e->kcp[i];
        if (k == NULL) continue;
        if (n == 0 || (uint32_t)k->rx_srtt > c->srtt) { c->srtt = (uint32_t)k->rx_srtt; c->rto = (uint32_t)k->rx_rto; }
        c->cwnd += k->cwnd;
        c->rtx += k->xmit;
        c->rcvbuf += (int64_t)(k->nrcv_buf + k->nrcv_que) * (int64_t)k->mss;
        n++;
    }
}

static void ep_release(ep *e)
{
    int i;
    if (e->anl) anl_release(e->anl);
    for (i = 0; i < MAXF; i++) if (e->kcp[i]) ikcp_release(e->kcp[i]);
    memset(e->kcp, 0, sizeof(e->kcp));
    e->anl = NULL;
}

/*---------------------------------------------------------------------
 * payload: seq(4) t_send(4) len(4) sid(1) key(1) pad(2) + pattern
 *-------------------------------------------------------------------*/
#define PHDR 16

static uint8_t pat(uint32_t seq, int sid, int i)
{
    return (uint8_t)((seq * 2654435761u + (uint32_t)i * 40503u + (uint32_t)sid * 97u) >> 13);
}

static void w32(char *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t r32(const char *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static void make_payload(char *buf, int len, uint32_t seq, uint32_t t, int sid, int key)
{
    int i;
    w32(buf, seq); w32(buf + 4, t); w32(buf + 8, (uint32_t)len);
    buf[12] = (char)sid; buf[13] = (char)key; buf[14] = buf[15] = 0;
    for (i = PHDR; i < len; i++) buf[i] = (char)pat(seq, sid, i);
}

static int check_payload(const char *buf, int len, int sid)
{
    int i;
    uint32_t seq;
    if (len < PHDR || r32(buf + 8) != (uint32_t)len || buf[12] != (char)sid) return 0;
    seq = r32(buf);
    for (i = PHDR; i < len; i++) if (buf[i] != (char)pat(seq, sid, i)) return 0;
    return 1;
}

/*---------------------------------------------------------------------
 * flow presets
 *-------------------------------------------------------------------*/
static void flow_init(flow *f, const char *name, int kind, int sid)
{
    memset(f, 0, sizeof(*f));
    f->name = name; f->kind = kind; f->sid = sid; f->prio = 2;
    f->snd_wnd = 128; f->rcv_wnd = 128;
}

static void flow_bulk(flow *f, int sid, uint64_t total, int rate)
{
    flow_init(f, "bulk", F_BULK, sid);
    f->msg_size = 8192; f->bulk_total = total; f->bulk_rate = rate; f->prio = 3;
    f->budget_ms = 1000000;
}

static void flow_inter(flow *f, int sid)
{
    flow_init(f, "inter", F_INTER, sid);
    f->period_ms = 20; f->size_min = f->size_max = 200; f->budget_ms = 150; f->prio = 1;
}

static void flow_audio(flow *f, int sid, const variant *v)
{
    flow_init(f, "audio", F_AUDIO, sid);
    f->semi = 1; f->prio = 0;
    f->snd_wnd = f->rcv_wnd = 512;
    f->period_ms = 20; f->size_min = f->size_max = 160;
    f->max_age = 200; f->budget_ms = 150;
    f->fec = v->fec;
    f->kcp_drop = v->drop; f->kcp_thr = f->max_age / f->period_ms;     /* 10 frames = max_age */
}

static void flow_video(flow *f, int sid, const variant *v)
{
    flow_init(f, "video", F_VIDEO, sid);
    f->semi = 1; f->prio = 1;
    f->snd_wnd = f->rcv_wnd = 512;
    f->period_ms = 33; f->gop = 30;
    f->key_min = 25000; f->key_max = 35000; f->size_min = 2500; f->size_max = 3500;
    f->max_age = 500; f->until_key = 1; f->budget_ms = 300;
    f->fec = v->fec;
    /* unsent backlog of max_age: ~140 KB/s * 0.5 s / mss */
    f->kcp_drop = v->drop; f->kcp_thr = 140000 / 2 / 1376 + 1;
}

/*---------------------------------------------------------------------
 * traffic generation and reception
 *-------------------------------------------------------------------*/
static char g_buf[1 << 18];
static uint64_t g_trng;

static void lat_push(flow *f, uint32_t v)
{
    if (f->nlat == f->caplat) {
        f->caplat = f->caplat ? f->caplat * 2 : 4096;
        f->lat = (uint32_t *)realloc(f->lat, f->caplat * sizeof(uint32_t));
    }
    f->lat[f->nlat++] = v;
}

static int gen_one(sim *s, flow *f, int len, int key)
{
    int r;
    if (len < PHDR) len = PHDR;
    make_payload(g_buf, len, f->seq, (uint32_t)s->t, f->sid, key);
    r = ep_send(&s->e[0], f, g_buf, len, key);
    f->seq++;
    f->offered += (uint64_t)len;
    if (key) f->keys_sent++;
    if (r == 1) f->proto_drop++;
    else if (r == 2) f->app_drop++;
    else if (r < 0 && !f->send_err) {
        f->send_err = r;
        finding(r == ANL_EDEAD ? 1 : 2, "%s send failed r=%d len=%d at t=%.3f s", f->name, r, len, s->t / 1000.0);
    }
    return r;
}

static void flow_gen(sim *s, flow *f)
{
    switch (f->kind) {
    case F_BULK: {
        int lim = f->snd_wnd * 2;
        if (f->bulk_rate > 0) {
            f->credit += f->bulk_rate / 1000.0;
            if (f->credit > f->msg_size * 4) f->credit = f->msg_size * 4;
        }
        while ((f->bulk_total == 0 || f->offered < f->bulk_total) && ep_waitsnd(&s->e[0], f->sid) < lim) {
            int len = f->msg_size;
            if (f->bulk_rate > 0) { if (f->credit < len) break; f->credit -= len; }
            if (f->bulk_total && f->offered + (uint64_t)len > f->bulk_total) len = (int)(f->bulk_total - f->offered);
            if (gen_one(s, f, len, 0) < 0) break;
        }
        break;
    }
    case F_INTER:
    case F_AUDIO:
        while (s->t >= f->next_t) {
            gen_one(s, f, rnd_range(&g_trng, f->size_min, f->size_max), 0);
            f->next_t += (uint64_t)f->period_ms;
        }
        break;
    case F_VIDEO:
        while (s->t >= f->next_t) {
            int key = (f->seq % (uint32_t)f->gop) == 0;
            int len = key ? rnd_range(&g_trng, f->key_min, f->key_max) : rnd_range(&g_trng, f->size_min, f->size_max);
            if (g_abr == 1 && s->v->proto == P_ANL) {
                /* an encoder at target_rate less the audio (DESIGN 6.10): frame sizes
                   scaled from the nominal ~117 KB/s, key / P ratio kept */
                anl_stats st;
                double nominal = ((f->key_min + f->key_max) / 2.0 + (f->gop - 1) * (f->size_min + f->size_max) / 2.0) / f->gop * 30;
                anl_get_stats(s->e[0].anl, &st);
                if (st.target_rate > 0) {
                    double rate = st.target_rate > 16000 ? st.target_rate - 8000.0 : 8000.0;
                    len = (int)(len * rate / nominal);
                    if (len < 200) len = 200;
                    if (len > (int)sizeof(g_buf) / 2) len = (int)sizeof(g_buf) / 2;   /* 128 KB: the buffer is 256 KB */
                }
            }
            gen_one(s, f, len, key);
            f->next_t = f->start_t + (uint64_t)(f->seq + 1) * 1000 / 30;
        }
        break;
    }
}

static void flow_recv(sim *s, flow *f)
{
    ep *b = &s->e[1];
    for (;;) {
        anl_frame_info info;
        uint32_t seq, lat, owd;
        int r = ep_recv(b, f, g_buf, (int)sizeof(g_buf), &info);
        if (r < 0) break;
        if (!check_payload(g_buf, r, f->sid)) {
            if (getenv("BENCH_DEBUG") && f->corrupt < 5) {
                int off = PHDR;
                uint32_t sq = r >= 4 ? r32(g_buf) : 0;
                while (off < r && g_buf[off] == (char)pat(sq, f->sid, off)) off++;
                fprintf(stderr, "corrupt %s t=%llu got_len=%d hdr_seq=%u hdr_len=%u hdr_sid=%d first_bad=%d info.frame_no=%u last=%u\n",
                        f->name, (unsigned long long)s->t, r, sq, r >= 12 ? r32(g_buf + 8) : 0, r >= 13 ? g_buf[12] : -1,
                        off, info.frame_no, f->rcv_last);
            }
            f->corrupt++;
            continue;
        }
        seq = r32(g_buf);
        if (f->rcv_any && (int32_t)(seq - f->rcv_last) <= 0) f->order_err++;
        if (!f->semi && seq != (f->rcv_any ? f->rcv_last + 1 : 0)) f->gap++;
        if (b->proto == P_ANL && f->semi) {
            if (info.frame_no != seq) f->fno_bad++;
            f->lost_before_sum += info.lost_before;
        }
        f->rcv_last = seq; f->rcv_any = 1;
        f->delivered++;
        f->rcv_bytes += (uint64_t)r;
        if (g_buf[13]) f->keys_dlv++;
        lat = (uint32_t)s->t - r32(g_buf + 4);
        lat_push(f, lat);
        owd = (uint32_t)(s->d[0].c.delay + s->d[0].c.jitter);
        if (lat <= owd + (uint32_t)f->budget_ms) f->ontime++;
        f->last_progress = s->t;
        if (f->recovering && r32(g_buf + 4) >= f->outage_end) {
            f->recovering = 0;
            if (s->t - f->outage_end > 3000) finding(1, "%s resumed %llu ms after outage end", f->name, (unsigned long long)(s->t - f->outage_end));
        }
        if (f->kind == F_BULK && f->bulk_total && f->rcv_bytes >= f->bulk_total && f->done_t == 0) f->done_t = s->t;
    }
    /* stall: reliable flow with pending data and no delivery */
    if (!f->semi && f->delivered < f->seq - f->app_drop) {
        uint64_t st = s->t - f->last_progress;
        if (st > f->max_stall) f->max_stall = st;
    } else {
        f->last_progress = s->t;
    }
}

/*---------------------------------------------------------------------
 * one simulation run
 *-------------------------------------------------------------------*/
typedef struct fres {
    const char *name;
    int semi, kind;
    uint32_t sent, delivered, ontime, keys_sent, keys_dlv, app_drop, proto_drop, skipped, fec_rec;
    double dlv, ontm, p50, p95, p99, pmax, gput, done_s, stall_s;
} fres;

typedef struct rres {
    const variant *v;
    double up_kbps, dn_kbps, cost, dur_s;
    uint64_t up_pkts, dn_pkts, qdrop;
    cstats cs;
    int alive;
    int64_t mem_peak;
    int nf;
    fres f[MAXF];
} rres;

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static void percentiles(const uint32_t *v, size_t n, double *p50, double *p95, double *p99, double *pmax)
{
    uint32_t *t;
    if (n == 0) { *p50 = *p95 = *p99 = *pmax = NAN; return; }
    t = (uint32_t *)malloc(n * sizeof(uint32_t));
    memcpy(t, v, n * sizeof(uint32_t));
    qsort(t, n, sizeof(uint32_t), cmp_u32);
    *p50 = t[(n - 1) * 50 / 100];
    *p95 = t[(n - 1) * 95 / 100];
    *p99 = t[(n - 1) * 99 / 100];
    *pmax = t[n - 1];
    free(t);
}

static void sim_init(sim *s, const variant *v, const linkcfg *lc, uint32_t clk0, uint64_t seed)
{
    int i;
    memset(s, 0, sizeof(*s));
    s->v = v;
    s->clk0 = clk0;
    for (i = 0; i < 2; i++) {
        s->d[i].c = *lc;
        s->d[i].rng = seed * 0x9E3779B97F4A7C15ULL + (uint64_t)i * 0x632BE59BD9B4E019ULL + 1;
    }
    g_trng = seed * 0xD1B54A32D192ED03ULL + 7;
    g_mem_peak[0] = g_mem_live[0];
    g_mem_peak[1] = g_mem_live[1];
    ep_create(s, 0, v->proto);
    ep_create(s, 1, v->proto);
}

static void sim_tick(sim *s, int generate);

static void sim_add_flows(sim *s, flow *fl, int n)
{
    int i, k;
    uint64_t t0 = s->t;
    s->fl = fl; s->nfl = n;
    for (i = 0; i < n; i++) {
        ep_open(&s->e[0], &fl[i]);
        ep_open(&s->e[1], &fl[i]);
    }
    /* AnLiu: wait until the peer has accepted every stream (one RTT) */
    for (k = 0; k < 5000 && s->v->proto == P_ANL; k++) {
        int ready = 1;
        for (i = 0; i < n; i++) ready &= s->e[1].h[fl[i].sid] != NULL;
        if (ready) break;
        sim_tick(s, 0);
    }
    /* start on the same phase of the flush interval as ikcp (which starts at t0):
       otherwise a periodic flow waits a fixed, RTT-dependent part of the interval
       for every message */
    while (s->v->proto == P_ANL && (s->t - t0) % (uint64_t)(g_fast ? 10 : 100) != 0) sim_tick(s, 0);
    for (i = 0; i < n; i++) {
        fl[i].start_t = fl[i].next_t = s->t;
        fl[i].last_progress = s->t;
    }
}

static void sim_tick(sim *s, int generate)
{
    int i, k;
    uint32_t now;
    s->t++;
    now = now32(s);
    for (k = 0; k < 2; k++) {
        dir *d = &s->d[k];
        while (d->head && d->head->at <= s->t) {
            pkt *p = d->head;
            d->head = p->next;
            if (d->head) d->head->prev = NULL; else d->tail = NULL;
            d->delivered++;
            ep_input(&s->e[1 - k], p->data, p->len);
            free(p);
        }
    }
    if (generate) for (i = 0; i < s->nfl; i++) flow_gen(s, &s->fl[i]);
    ep_update(&s->e[0], now);
    ep_update(&s->e[1], now);
    for (i = 0; i < s->nfl; i++) flow_recv(s, &s->fl[i]);
}

static int flows_done(const sim *s)
{
    int i;
    for (i = 0; i < s->nfl; i++) {
        const flow *f = &s->fl[i];
        if (f->kind == F_BULK && f->bulk_total && f->done_t == 0) return 0;
    }
    return 1;
}

/* collect results, run sanity detectors, release everything */
static void sim_finish(sim *s, rres *r, double gen_s)
{
    int i;
    double wire_up, wire_dn, useful = 0;
    memset(r, 0, sizeof(*r));
    r->v = s->v;
    r->dur_s = gen_s;
    r->alive = ep_alive(&s->e[0]) && ep_alive(&s->e[1]);
    ep_stats(&s->e[0], &r->cs);
    wire_up = (double)s->d[0].bytes + (double)s->d[0].pkts * IPUDP_HDR;
    wire_dn = (double)s->d[1].bytes + (double)s->d[1].pkts * IPUDP_HDR;
    r->up_pkts = s->d[0].pkts; r->dn_pkts = s->d[1].pkts;
    r->qdrop = s->d[0].lost_queue;
    r->up_kbps = wire_up * 8 / 1000 / gen_s;
    r->dn_kbps = wire_dn * 8 / 1000 / gen_s;
    r->nf = s->nfl;
    for (i = 0; i < s->nfl; i++) {
        flow *f = &s->fl[i];
        fres *x = &r->f[i];
        x->name = f->name; x->semi = f->semi; x->kind = f->kind;
        x->sent = f->seq; x->delivered = f->delivered; x->ontime = f->ontime;
        x->keys_sent = f->keys_sent; x->keys_dlv = f->keys_dlv;
        x->app_drop = f->app_drop; x->proto_drop = f->proto_drop;
        if (s->e[0].proto == P_ANL && f->semi) {
            anl_stream_stats a, b;
            anl_stream_get_stats(s->e[0].h[f->sid], &a);
            if (s->e[1].h[f->sid]) anl_stream_get_stats(s->e[1].h[f->sid], &b);
            else memset(&b, 0, sizeof(b));
            x->proto_drop = a.frames_dropped;
            x->skipped = b.frames_skipped;
            x->fec_rec = b.fec_recovered;
        }
        x->dlv = f->seq ? 100.0 * f->delivered / f->seq : 0;
        x->ontm = f->seq ? 100.0 * f->ontime / f->seq : 0;
        if (f->kind == F_BULK && f->bulk_total) x->dlv = 100.0 * (double)f->rcv_bytes / (double)f->bulk_total;
        percentiles(f->lat, f->nlat, &x->p50, &x->p95, &x->p99, &x->pmax);
        x->done_s = f->done_t ? f->done_t / 1000.0 : NAN;
        x->gput = (double)f->rcv_bytes / 1024.0 / (f->done_t ? f->done_t / 1000.0 : gen_s);
        x->stall_s = f->max_stall / 1000.0;
        useful += (double)f->rcv_bytes;

        /* correctness */
        if (f->corrupt) finding(2, "%s: %u corrupted messages", f->name, f->corrupt);
        if (f->order_err) finding(2, "%s: %u out-of-order deliveries", f->name, f->order_err);
        if (f->gap) finding(2, "%s: %u gaps on a reliable flow", f->name, f->gap);
        if (f->fno_bad) finding(2, "%s: %u frames with frame_no != app seq", f->name, f->fno_bad);
        if (s->e[0].proto == P_ANL && f->semi && f->rcv_any && f->delivered + f->lost_before_sum != (uint64_t)f->rcv_last + 1)
            finding(2, "%s: lost_before accounting %u + %llu != %u", f->name, f->delivered,
                    (unsigned long long)f->lost_before_sum, f->rcv_last + 1);
        free(f->lat); f->lat = NULL;
    }
    r->cost = useful > 0 ? (wire_up + wire_dn) / useful : NAN;
    r->mem_peak = g_mem_peak[s->v->proto == P_ANL ? 0 : 1];
    ep_release(&s->e[0]);
    ep_release(&s->e[1]);
    dir_free(&s->d[0]);
    dir_free(&s->d[1]);
    if (g_mem_live[0] != 0 || g_mem_live[1] != 0) {
        finding(2, "memory not released after anl/ikcp release: anl=%lld kcp=%lld bytes",
                (long long)g_mem_live[0], (long long)g_mem_live[1]);
        g_mem_live[0] = g_mem_live[1] = 0;
    }
}

/*=====================================================================
 * matrix scenarios
 *===================================================================*/
typedef struct point { double loss; int rtt; double burst; int jitter; int bw; } point;

static int g_dur = 60, g_bw = 20000, g_bw5 = 5000, g_qdelay = 100;
static int g_shift, g_shift_ms = 1500;  /* --rttshift MS [--rttshift-ms MS]: s1..s5 links */
static int g_av;                        /* --av: s3 is audio (prio 0) + video (prio 1), no bulk */
static int g_bulk_wnd = 128;       /* s1: snd/rcv window of the bulk flow (--wnd) */
static int g_bulk_mb = 4, g_bulk_cap = 300;
static uint64_t g_seed = 1;
static FILE *g_csv;

enum { S1 = 1, S2, S3, S4, S5 };
static const char *scen_name[] = { "", "s1-bulk", "s2-interactive", "s3-video", "s4-audio", "s5-mixed" };

static linkcfg point_link(const point *p)
{
    linkcfg c;
    memset(&c, 0, sizeof(c));
    c.loss = p->loss;
    c.burst = p->burst;
    c.delay = p->rtt / 2;
    c.jitter = p->jitter;
    c.bw_kbps = p->bw;
    c.qdelay = g_qdelay;
    c.shift = g_shift;
    c.shift_ms = g_shift_ms;
    return c;
}

static int build_flows(int sc, const variant *v, flow *fl)
{
    switch (sc) {
    case S1: flow_bulk(&fl[0], 0, (uint64_t)g_bulk_mb << 20, 0); fl[0].snd_wnd = fl[0].rcv_wnd = g_bulk_wnd; return 1;
    case S2: flow_inter(&fl[0], 0); return 1;
    case S3:
        if (g_av) { flow_audio(&fl[0], 0, v); flow_video(&fl[1], 1, v); return 2; }
        flow_video(&fl[0], 0, v); return 1;
    case S4: flow_audio(&fl[0], 0, v); return 1;
    case S5:
        flow_audio(&fl[0], 0, v);
        flow_video(&fl[1], 1, v);
        flow_bulk(&fl[2], 2, 0, 0);
        return 3;
    }
    return 0;
}

static int g_cctrace = -1;
static int g_cctrace_ms = 1000;             /* soak trace period, BENCH_CC=<ms> */
static void cc_trace(sim *s)
{
                anl_stats st;
                anl_get_stats(s->e[0].anl, &st);
                fprintf(stderr, "t=%5.1f st=%u cwnd=%u infl=%u bw=%u app=%u minrtt=%u srtt=%u pace=%u retx=%llu short=%d target=%u\n", s->t / 1000.0,
                        (unsigned)st.cc_state, (unsigned)st.cwnd, (unsigned)st.inflight, (unsigned)st.bw_estimate,
                        (unsigned)st.bw_app_limited, (unsigned)st.min_rtt, (unsigned)st.srtt, (unsigned)st.pace_rate,
                        (unsigned long long)st.retrans, st.capacity_short, (unsigned)st.target_rate);
            }
static void run_point(int sc, const variant *v, const point *p, rres *r)
{
    sim s;
    flow fl[MAXF];
    linkcfg lc = point_link(p);
    uint64_t gen_ms, cap_ms;
    double gen_s;

    if (g_cctrace < 0) g_cctrace = getenv("BENCH_CC") != NULL;
    snprintf(g_label, sizeof(g_label), "[%s %s loss=%.0f%%%s rtt=%d%s]", scen_name[sc], v->name, p->loss * 100,
             p->burst > 1 ? " burst" : "", p->rtt, p->jitter ? " jitter" : "");
    sim_init(&s, v, &lc, 1000, g_seed);
    sim_add_flows(&s, fl, build_flows(sc, v, fl));
    if (sc == S1) {
        cap_ms = (uint64_t)g_bulk_cap * 1000;
        while (!flows_done(&s) && s.t < cap_ms && ep_alive(&s.e[0]) && ep_alive(&s.e[1])) {
            sim_tick(&s, 1);
            if (g_cctrace && v->proto == P_ANL && s.t % 500 == 0) cc_trace(&s);
        }
        gen_s = (fl[0].done_t ? fl[0].done_t : s.t) / 1000.0;
        if (!fl[0].done_t) finding(1, "bulk transfer incomplete after %.0f s (%.1f%%)", s.t / 1000.0,
                                   100.0 * (double)fl[0].rcv_bytes / (double)fl[0].bulk_total);
    } else {
        gen_ms = (uint64_t)g_dur * 1000;
        while (s.t < gen_ms) {
            sim_tick(&s, 1);
            if (g_cctrace && v->proto == P_ANL && s.t % 500 == 0) cc_trace(&s);
        }
        gen_s = s.t / 1000.0;
        while (s.t < gen_ms + 3000) sim_tick(&s, 0);       /* drain */
    }
    sim_finish(&s, r, gen_s);

    /* behaviour detectors */
    if (!r->alive) finding(1, "connection dead (dead_link)");
    {
        int i;
        for (i = 0; i < r->nf; i++) {
            fres *x = &r->f[i];
            if (p->loss == 0 && x->semi && x->dlv < 99.99 && p->bw >= 20000) finding(1, "%s delivered %.2f%% with 0%% loss", x->name, x->dlv);
            if (!x->semi && x->stall_s > 5) finding(1, "%s stalled %.1f s with data pending", x->name, x->stall_s);
            if (v->fec && x->semi && p->loss >= 0.03 && x->fec_rec == 0) finding(1, "%s: FEC on but nothing recovered", x->name);
        }
    }
    if (p->loss < 0.2 && p->bw == 0 && r->cs.srtt > 0) {
        double err = fabs((double)r->cs.srtt - p->rtt);
        if (err > 50 && err > p->rtt * 0.5) finding(1, "srtt %u ms vs true rtt %d ms", r->cs.srtt, p->rtt);
    }
    if (r->mem_peak > (64 << 20)) finding(1, "peak memory %.1f MB", r->mem_peak / 1048576.0);
}

/* variants per scenario */
static int scen_variants(int sc, const variant **vs)
{
    int n = 0;
    vs[n++] = &V_ANL;
    if (sc == S3 || sc == S4 || sc == S5) vs[n++] = &V_ANLF;
    vs[n++] = &V_KCP;
    if (sc == S3 || sc == S4 || sc == S5) vs[n++] = &V_KCPD;
    return n;
}

static void csv_row(int sc, const point *p, const rres *r, const fres *x)
{
    if (!g_csv) return;
    fprintf(g_csv, "%s,%s,%s,%.1f,%.0f,%d,%d,%d,%.1f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.2f,%.2f,%.0f,%.0f,%.0f,%.0f,%.1f,%.2f,%.1f,%.1f,%.3f,%llu,%llu,%llu,%u,%u,%u,%u,%d,%.1f\n",
            scen_name[sc], r->v->name, x->name, p->loss * 100, p->burst, p->rtt, p->jitter, p->bw, r->dur_s,
            x->sent, x->delivered, x->ontime, x->keys_sent, x->keys_dlv, x->app_drop, x->proto_drop, x->skipped, x->fec_rec,
            x->dlv, x->ontm, x->p50, x->p95, x->p99, x->pmax, x->gput, x->done_s, r->up_kbps, r->dn_kbps, r->cost,
            (unsigned long long)r->up_pkts, (unsigned long long)r->dn_pkts, (unsigned long long)r->qdrop,
            r->cs.srtt, r->cs.rto, r->cs.cwnd, r->cs.rtx, r->alive, r->mem_peak / 1024.0);
}

static void print_header(int sc)
{
    if (sc == S1)
        printf("%-12s %-9s %-6s %7s %9s %9s %8s %6s %6s %6s %6s %s\n", "link", "variant", "flow",
               "done(s)", "gput KB/s", "up kbps", "dn kbps", "cost", "srtt", "rtx", "memKB", "notes");
    else
        printf("%-12s %-9s %-6s %6s %6s %6s %6s %6s %6s %8s %8s %6s %6s %6s %s\n", "link", "variant", "flow",
               "dlv%", "ontm%", "p50", "p95", "p99", "max", "up kbps", "dn kbps", "cost", "srtt", "rtx", "notes");
}

static void link_str(const point *p, char *out, size_t n)
{
    snprintf(out, n, "%g%%%s/%d%s", p->loss * 100, p->burst > 1 ? "b" : "", p->rtt, p->jitter ? "j" : "");
}

static void print_row(int sc, const point *p, const rres *r, int fi)
{
    const fres *x = &r->f[fi];
    char ls[32], notes[128] = "";
    size_t k = 0;
    link_str(p, ls, sizeof(ls));
    if (!r->alive) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "DEAD ");
    if (x->semi && x->proto_drop) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "sdrop=%u ", x->proto_drop);
    if (x->app_drop) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "adrop=%u ", x->app_drop);
    if (x->skipped) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "skip=%u ", x->skipped);
    if (x->fec_rec) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "fec=%u ", x->fec_rec);
    if (x->keys_sent) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "key=%u/%u ", x->keys_dlv, x->keys_sent);
    if (x->kind == F_BULK && sc == S5) k += (size_t)snprintf(notes + k, sizeof(notes) - k, "gput=%.0fKB/s ", x->gput);
    if (fi > 0) ls[0] = 0;
    if (sc == S1)
        printf("%-12s %-9s %-6s %7.1f %9.0f %9.0f %8.0f %6.3f %6u %6u %6.0f %s\n", ls, r->v->name, x->name,
               x->done_s, x->gput, r->up_kbps, r->dn_kbps, r->cost, r->cs.srtt, r->cs.rtx, r->mem_peak / 1024.0, notes);
    else if (fi == 0)
        printf("%-12s %-9s %-6s %6.1f %6.1f %6.0f %6.0f %6.0f %6.0f %8.0f %8.0f %6.3f %6u %6u %s\n", ls, r->v->name, x->name,
               x->dlv, x->ontm, x->p50, x->p95, x->p99, x->pmax, r->up_kbps, r->dn_kbps, r->cost, r->cs.srtt, r->cs.rtx, notes);
    else
        printf("%-12s %-9s %-6s %6.1f %6.1f %6.0f %6.0f %6.0f %6.0f %8s %8s %6s %6s %6s %s\n", ls, "", x->name,
               x->dlv, x->ontm, x->p50, x->p95, x->p99, x->pmax, "", "", "", "", "", notes);
}

/* per-scenario summary accumulators, indexed by variant order */
typedef struct summ {
    const char *name;
    int n;
    double ontm, dlv, p95, up, cost, gput, done;
    int dead;
} summ;

static void run_scenario(int sc, const point *pts, int npts)
{
    const variant *vs[4];
    int nv = scen_variants(sc, vs), i, j, fi;
    summ sm[4];
    memset(sm, 0, sizeof(sm));
    for (j = 0; j < nv; j++) sm[j].name = vs[j]->name;

    printf("\n==== %s ", scen_name[sc]);
    switch (sc) {
    case S1: printf("(reliable, %d MB, msg 8 KB, wnd %d)", g_bulk_mb, g_bulk_wnd); break;
    case S2: printf("(reliable, 200 B every 20 ms, %d s, on-time = owd+jitter+150 ms)", g_dur); break;
    case S3: printf("(%ssemi, 30 fps GOP 30, I 25-35 KB, P 2.5-3.5 KB, max_age 500, %d s, on-time = owd+jitter+300 ms%s)",
                    g_av ? "audio prio0 + video prio1; video: " : "", g_dur,
                    g_shift ? " ; rtt shift on" : ""); break;
    case S4: printf("(semi, 160 B every 20 ms, max_age 200, %d s, on-time = owd+jitter+150 ms)", g_dur); break;
    case S5: printf("(audio prio0 + video prio1 + bulk prio3, %d kbps bottleneck, %d s)", g_bw5, g_dur); break;
    }
    printf(" ====\n");
    print_header(sc);
    for (i = 0; i < npts; i++) {
        point p = pts[i];
        if (sc == S5) p.bw = g_bw5;
        for (j = 0; j < nv; j++) {
            rres r;
            run_point(sc, vs[j], &p, &r);
            for (fi = 0; fi < r.nf; fi++) { print_row(sc, &p, &r, fi); csv_row(sc, &p, &r, &r.f[fi]); }
            sm[j].n++;
            sm[j].dead += !r.alive;
            sm[j].up += r.up_kbps;
            sm[j].cost += r.cost;
            sm[j].ontm += r.f[0].ontm;
            sm[j].dlv += r.f[0].dlv;
            sm[j].p95 += isnan(r.f[0].p95) ? 0 : r.f[0].p95;
            sm[j].gput += r.f[r.nf - 1].gput;
            sm[j].done += isnan(r.f[0].done_s) ? g_bulk_cap : r.f[0].done_s;
        }
        if (nv > 1) printf("\n");
    }
    printf("-- %s averages over %d link conditions --\n", scen_name[sc], npts);
    for (j = 0; j < nv; j++) {
        summ *m = &sm[j];
        double n = m->n ? m->n : 1;
        if (sc == S1)
            printf("   %-9s done %.1f s  gput %.0f KB/s  up %.0f kbps  cost %.3f  dead %d\n", m->name,
                   m->done / n, m->gput / n, m->up / n, m->cost / n, m->dead);
        else
            printf("   %-9s %s dlv %.1f%%  ontime %.1f%%  p95 %.0f ms  up %.0f kbps  cost %.3f%s  dead %d\n", m->name,
                   sc == S5 ? "audio" : "", m->dlv / n, m->ontm / n, m->p95 / n, m->up / n, m->cost / n,
                   sc == S5 ? "" : "", m->dead);
    }
}

/*=====================================================================
 * soak: long run, network phases, clock wrap, timeline
 *===================================================================*/
static int g_soak = 3600, g_phase = 60, g_sample = 60;

typedef struct phase { const char *name; linkcfg c; int outage_ms; } phase;

static const phase g_phases[] = {
    { "good",    { 0.00, 0, 20,  0, 20000, 100, 0.00 , 0, 0 }, 0 },
    { "rand5",   { 0.05, 0, 50,  0, 20000, 100, 0.01 , 0, 0 }, 0 },
    { "burst5",  { 0.05, 4, 50,  0, 20000, 100, 0.00 , 0, 0 }, 0 },
    { "heavy20", { 0.20, 0, 100, 20, 20000, 100, 0.00 , 0, 0 }, 0 },
    { "bw2m",    { 0.005, 0, 30, 0, 2000,  200, 0.00 , 0, 0 }, 0 },
    { "outage",  { 0.00, 0, 30,  0, 20000, 100, 0.00 , 0, 0 }, 5000 },
    { "hirtt",   { 0.01, 0, 200, 40, 20000, 100, 0.00 , 0, 0 }, 0 },
};
#define NPHASE ((int)(sizeof(g_phases) / sizeof(g_phases[0])))

static void soak_run(const variant *v)
{
    sim s;
    flow fl[MAXF];
    int nf = 0, i, cur = -1;
    uint64_t end = (uint64_t)g_soak * 1000, next_sample = (uint64_t)g_sample * 1000;
    uint64_t snap_up = 0, snap_up_pkts = 0;
    uint32_t snap_rtx = 0;
    int64_t good_mem[256]; int ngood = 0;
    linkcfg lc = g_phases[0].c;
    rres r;

    if (g_cctrace < 0) g_cctrace = getenv("BENCH_CC") != NULL;
    if (g_cctrace && atoi(getenv("BENCH_CC")) > 0) g_cctrace_ms = atoi(getenv("BENCH_CC"));
    snprintf(g_label, sizeof(g_label), "[soak %s]", v->name);
    /* start the protocol clock 30 s before uint32 wrap */
    sim_init(&s, v, &lc, 0xFFFFFFFFu - 30000u, g_seed);
    flow_audio(&fl[nf++], 0, v);
    flow_video(&fl[nf++], 1, v);
    flow_inter(&fl[nf++], 2);
    flow_bulk(&fl[nf++], 3, 0, 250000);
    fl[0].fec = v->fec;
    sim_add_flows(&s, fl, nf);

    printf("\n==== soak %s: %d s, phase %d s, clock starts at 0x%08x (wraps at t=30 s) ====\n",
           v->name, g_soak, g_phase, s.clk0);
    printf("%6s %-8s | %-15s | %-21s | %-9s | %-9s | %5s %5s %5s %5s | %6s | %7s %7s\n", "t(s)", "phase",
           "audio dlv/p95", "video dlv/ontm/p95", "inter p99", "bulk KB/s", "srtt", "rto", "cwnd", "rtx", "upkbps",
           "memKB", "rcvKB");

    while (s.t < end) {
        int ph = (int)((s.t / 1000 / (uint64_t)g_phase) % NPHASE);
        uint64_t in_phase = s.t % ((uint64_t)g_phase * 1000);
        if (ph != cur) {
            if (cur == 0) good_mem[ngood < 256 ? ngood++ : 255] = g_mem_live[v->proto == P_ANL ? 0 : 1];
            cur = ph;
            s.d[0].c = s.d[1].c = g_phases[ph].c;
        }
        if (g_phases[ph].outage_ms) {
            double l = in_phase < (uint64_t)g_phases[ph].outage_ms ? 1.0 : 0.0;
            if (s.d[0].c.loss != l) {
                s.d[0].c.loss = s.d[1].c.loss = l;
                if (l == 0) for (i = 0; i < nf; i++) { fl[i].outage_end = s.t; fl[i].recovering = 1; }
            }
        }
        sim_tick(&s, 1);
        if (g_cctrace && v->proto == P_ANL && s.t % (uint64_t)g_cctrace_ms == 0) cc_trace(&s);
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) {
            finding(1, "connection dead at t=%.1f s in phase %s", s.t / 1000.0, g_phases[ph].name);
            break;
        }
        if (s.t >= next_sample) {
            double w = g_sample;
            double a50, a95, a99, amax, v95, i99, x;
            cstats cs;
            flow *A = &fl[0], *V = &fl[1], *I = &fl[2], *B = &fl[3];
            ep_stats(&s.e[0], &cs);
            percentiles(A->lat + A->w_lat, A->nlat - A->w_lat, &a50, &a95, &a99, &amax);
            percentiles(V->lat + V->w_lat, V->nlat - V->w_lat, &x, &v95, &a99, &amax);
            percentiles(I->lat + I->w_lat, I->nlat - I->w_lat, &x, &x, &i99, &amax);
            printf("%6.0f %-8s | %5.1f%% %6.0fms | %5.1f%% %5.1f%% %6.0fms | %6.0fms | %9.1f | %5u %5u %5u %5u | %6.0f | %7.0f %7.0f\n",
                   s.t / 1000.0, g_phases[ph].name,
                   A->seq > A->w_seq ? 100.0 * (A->delivered - A->w_dlv) / (A->seq - A->w_seq) : 0, a95,
                   V->seq > V->w_seq ? 100.0 * (V->delivered - V->w_dlv) / (V->seq - V->w_seq) : 0,
                   V->seq > V->w_seq ? 100.0 * (V->ontime - V->w_ontime) / (V->seq - V->w_seq) : 0, v95,
                   i99, (double)(B->rcv_bytes - B->w_bytes) / 1024.0 / w,
                   cs.srtt, cs.rto, cs.cwnd, cs.rtx - snap_rtx,
                   ((double)(s.d[0].bytes - snap_up) + (double)(s.d[0].pkts - snap_up_pkts) * IPUDP_HDR) * 8 / 1000 / w,
                   g_mem_live[v->proto == P_ANL ? 0 : 1] / 1024.0, cs.rcvbuf / 1024.0);
            for (i = 0; i < nf; i++) {
                fl[i].w_seq = fl[i].seq; fl[i].w_dlv = fl[i].delivered; fl[i].w_ontime = fl[i].ontime;
                fl[i].w_lat = fl[i].nlat; fl[i].w_bytes = fl[i].rcv_bytes;
            }
            snap_up = s.d[0].bytes; snap_up_pkts = s.d[0].pkts; snap_rtx = cs.rtx;
            next_sample += (uint64_t)g_sample * 1000;
        }
    }
    {
        uint64_t stop = s.t + 3000;
        while (s.t < stop) sim_tick(&s, 0);
    }
    for (i = 0; i < nf; i++) {
        if (fl[i].max_stall > 15000) finding(1, "%s stalled up to %.1f s", fl[i].name, fl[i].max_stall / 1000.0);
        if (fl[i].semi) printf("   %s: %u frames, frame_no/sn wraps crossed ~%u\n", fl[i].name, fl[i].seq, fl[i].seq / 65536);
    }
    if (ngood >= 3 && good_mem[ngood - 1] > good_mem[1] * 2 + (256 << 10))
        finding(1, "memory in 'good' phase grows: cycle1 %.0f KB -> last %.0f KB",
                good_mem[1] / 1024.0, good_mem[ngood - 1] / 1024.0);
    sim_finish(&s, &r, s.t / 1000.0);
    printf("-- totals: ");
    for (i = 0; i < r.nf; i++) {
        fres *x = &r.f[i];
        printf("%s dlv %.1f%% ontime %.1f%% p95 %.0f ms; ", x->name, x->dlv, x->ontm, x->p95);
    }
    printf("\n   up %.0f kbps, dn %.0f kbps, cost %.3f, peak mem %.0f KB, alive %d\n",
           r.up_kbps, r.dn_kbps, r.cost, r.mem_peak / 1024.0, r.alive);
}

/*=====================================================================
 * bwstep: the bottleneck changes every phase; bandwidth estimation and
 * congestion control (DESIGN 6.8)
 *===================================================================*/
static const int g_steps_kbps[] = { 8000, 2000, 5000, 1000, 8000 };
#define NSTEP ((int)(sizeof(g_steps_kbps) / sizeof(g_steps_kbps[0])))
static int g_step_s = 10;
static double g_step_loss = 0;

static void bwstep_run(const variant *v)
{
    if (g_cctrace < 0) g_cctrace = getenv("BENCH_CC") != NULL;
    if (g_cctrace && atoi(getenv("BENCH_CC")) > 0) g_cctrace_ms = atoi(getenv("BENCH_CC"));
    sim s;
    flow fl[MAXF];
    int nf = 0, i, cur = -1, nest = 0;
    uint64_t end = (uint64_t)NSTEP * g_step_s * 1000;
    uint64_t snap_up = 0, snap_pkts = 0, next_est = 0;
    double est_sum = 0, util_sum = 0, ratio_sum = 0;
    int nratio = 0;
    linkcfg lc = { g_step_loss, 0, g_step_rtt / 2, 0, g_steps_kbps[0], 100, 0.0, 0, 0 };
    rres r;

    snprintf(g_label, sizeof(g_label), "[bwstep %s]", v->name);
    sim_init(&s, v, &lc, 1000, g_seed);
    flow_audio(&fl[nf++], 0, v);
    flow_video(&fl[nf++], 1, v);
    if (!g_abr) {
        flow_bulk(&fl[nf++], 3, 0, 0);
        fl[2].prio = 3;
    }
    sim_add_flows(&s, fl, nf);
    printf("\n==== bwstep%s %s: bottleneck %d", g_abr == 1 ? " (abr: video follows target_rate)" : g_abr ? " (no bulk)" : "", v->name, g_steps_kbps[0]);
    for (i = 1; i < NSTEP; i++) printf(" -> %d", g_steps_kbps[i]);
    printf(" kbps, %d s each, rtt %d ms, loss %.0f%%, queue 100 ms%s ====\n", g_step_s, g_step_rtt, g_step_loss * 100,
           g_tbf_kb ? " (tbf)" : "");
    printf("%-6s | %8s %8s %6s | %6s | %-15s | %-15s | %9s\n", "kbps", "est kbps", "est/bw", "util", "srtt",
           "audio dlv/p95", "video ontm/p95", g_abr ? "video kbps" : "bulk KB/s");

    while (s.t < end) {
        int ph = (int)(s.t / 1000 / (uint64_t)g_step_s);
        if (ph != cur) {
            cur = ph;
            s.d[0].c.bw_kbps = s.d[1].c.bw_kbps = g_steps_kbps[ph];
        }
        sim_tick(&s, 1);
        if (g_cctrace > 0 && v->proto == P_ANL && s.t % (uint64_t)g_cctrace_ms == 0) cc_trace(&s);
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) { finding(1, "connection dead at t=%.1f s", s.t / 1000.0); break; }
        /* the estimate, sampled every 100 ms after the first 3 s of a phase */
        if (s.t >= next_est) {
            next_est = s.t + 100;
            if (v->proto == P_ANL && s.t % ((uint64_t)g_step_s * 1000) >= 3000) {
                anl_stats st;
                anl_get_stats(s.e[0].anl, &st);
                est_sum += st.bw_estimate * 8.0 / 1000;
                nest++;
            }
        }
        if (s.t % ((uint64_t)g_step_s * 1000) == 0) {           /* phase report */
            double w = g_step_s, a50, a95, a99, amax, v95, x, est = nest ? est_sum / nest : 0;
            double up = ((double)(s.d[0].bytes - snap_up) + (double)(s.d[0].pkts - snap_pkts) * IPUDP_HDR) * 8 / 1000 / w;
            int kbps = g_steps_kbps[ph - 1 < 0 ? 0 : (s.t / 1000 / (uint64_t)g_step_s) - 1];
            flow *A = &fl[0], *V = &fl[1], *B = &fl[g_abr ? 1 : 2];
            cstats cs;
            ep_stats(&s.e[0], &cs);
            percentiles(A->lat + A->w_lat, A->nlat - A->w_lat, &a50, &a95, &a99, &amax);
            percentiles(V->lat + V->w_lat, V->nlat - V->w_lat, &x, &v95, &a99, &amax);
            printf("%6d | %8.0f %8.2f %5.0f%% | %6u | %5.1f%% %6.0fms | %5.1f%% %6.0fms | %9.1f\n",
                   kbps, est, est / kbps, 100.0 * up / kbps, cs.srtt,
                   A->seq > A->w_seq ? 100.0 * (A->delivered - A->w_dlv) / (A->seq - A->w_seq) : 0, a95,
                   V->seq > V->w_seq ? 100.0 * (V->ontime - V->w_ontime) / (V->seq - V->w_seq) : 0, v95,
                   g_abr ? (double)(B->rcv_bytes - B->w_bytes) * 8 / 1000 / w : (double)(B->rcv_bytes - B->w_bytes) / 1024.0 / w);
            if (nest) { ratio_sum += est / kbps; nratio++; }
            util_sum += up / kbps;
            for (i = 0; i < nf; i++) {
                fl[i].w_seq = fl[i].seq; fl[i].w_dlv = fl[i].delivered; fl[i].w_ontime = fl[i].ontime;
                fl[i].w_lat = fl[i].nlat; fl[i].w_bytes = fl[i].rcv_bytes;
            }
            snap_up = s.d[0].bytes; snap_pkts = s.d[0].pkts;
            est_sum = 0; nest = 0;
        }
    }
    sim_finish(&s, &r, s.t / 1000.0);
    printf("-- totals: ");
    for (i = 0; i < r.nf; i++) {
        fres *xx = &r.f[i];
        printf("%s dlv %.1f%% ontime %.1f%% p95 %.0f ms; ", xx->name, xx->dlv, xx->ontm, xx->p95);
    }
    printf("\n   mean est/bw %.2f, mean util %.0f%%, alive %d\n", nratio ? ratio_sum / nratio : 0, 100.0 * util_sum / NSTEP, r.alive);
}

/*=====================================================================
 * crypto / input cost (real clock)
 *===================================================================*/
static double wall_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void bench_input_cost(const variant *v)
{
    sim s;
    flow fl[1];
    linkcfg lc;
    int i, n = 200000;
    double t0, t1, avg = 0;
    static char junk[64][MTU];

    memset(&lc, 0, sizeof(lc));
    lc.delay = 1;
    snprintf(g_label, sizeof(g_label), "[crypto %s]", v->name);
    sim_init(&s, v, &lc, 1000, g_seed);
    flow_video(&fl[0], 0, v);
    sim_add_flows(&s, fl, 1);
    for (i = 0; i < 50; i++) sim_tick(&s, 0);
    s.capture = 1;
    make_payload(g_buf, 100000, 0, 0, 0, 1);
    ep_send(&s.e[0], &fl[0], g_buf, 100000, 1);
    for (i = 0; i < 2000 && s.ncap < 128; i++) sim_tick(&s, 0);
    s.capture = 0;
    s.blackhole = 1;
    for (i = 0; i < s.ncap; i++) avg += s.caplen[i];
    avg /= s.ncap ? s.ncap : 1;

    t0 = wall_ms();
    for (i = 0; i < n; i++) ep_input(&s.e[1], s.cap[i % s.ncap], s.caplen[i % s.ncap]);
    t1 = wall_ms();
    printf("   %-4s valid datagrams (avg %4.0f B): %7.0f ns/pkt  %6.2f Mpps  %6.2f Gbps\n", v->name, avg,
           (t1 - t0) * 1e6 / n, n / (t1 - t0) / 1e3, n * avg * 8 / (t1 - t0) / 1e6);
    if (v->proto == P_ANL) {
        for (i = 0; i < 64; i++) { int j; for (j = 0; j < MTU; j++) junk[i][j] = (char)rnd_next(&g_trng); }
        t0 = wall_ms();
        for (i = 0; i < n; i++) ep_input(&s.e[1], junk[i & 63], MTU);
        t1 = wall_ms();
        printf("   %-4s forged datagrams (1400 B):   %7.0f ns/pkt  %6.2f Mpps  %6.2f Gbps  (one core)\n", v->name,
               (t1 - t0) * 1e6 / n, n / (t1 - t0) / 1e3, n * 1400.0 * 8 / (t1 - t0) / 1e6);
    }
    for (i = 0; i < s.ncap; i++) free(s.cap[i]);
    s.blackhole = 0;
    {
        rres r;
        s.nfl = 0;
        sim_finish(&s, &r, 1);
    }
    free(fl[0].lat);
}

/*=====================================================================
 * main
 *===================================================================*/
static int parse_list(const char *s, double *out, int max)
{
    int n = 0;
    while (*s && n < max) {
        char *e;
        out[n++] = strtod(s, &e);
        if (e == s) break;
        s = *e == ',' ? e + 1 : e;
    }
    return n;
}

static void usage(void)
{
    printf("usage: anl_bench [s1 s2 s3 s4 s5 soak crypto all] [options]\n"
           "  --loss L,..     loss percents (default 0,1,3,5,10,20,30)\n"
           "  --rtt R,..      rtt ms (default 20,100,300)\n"
           "  --burst N       extra rows: 5%% loss with mean burst N (default 4, 0 = off)\n"
           "  --jitter PCT    extra rows: 1%% loss, jitter = PCT%% of one-way delay, reorder (default 30, 0 = off)\n"
           "  --rttshift MS   s1..s5: the path adds MS one-way delay for random stays (--rttshift-ms mean, 1500),\n"
           "                  each direction on its own: RTT moves between rtt, rtt+MS, rtt+2*MS without a queue\n"
           "  --av            s3: audio (prio 0) + video (prio 1) on one connection, no bulk\n"
           "  --bw KBPS       bottleneck for s1..s4 (default 20000, 0 = unlimited)\n"
           "  --bw5 KBPS      bottleneck for s5 (default 5000)\n"
           "  --dur S         s2..s5 duration (default 60)\n"
           "  --bulk MB       s1 size (default 4)\n"
           "  --wnd N         s1 bulk snd/rcv window in segments (default 128)\n"
           "  --init-cwnd N   AnLiu initial congestion window (default from library)\n"
           "  --fec-ratio N   FEC flows: redundancy in %%, 1..100, 0 = adaptive (default 25)\n"
           "  --fec-auto      FEC flows: ANL_FEC_RTT_AUTO, the semi-reliable default (overrides --fec-ratio)\n"
           "  --rcv-deadline MS  semi gap wait: -1 = local lifetime, 0 = off (default from library)\n"
           "  bwstep          bottleneck steps 8/2/5/1/8 Mbps: bandwidth estimate, utilisation, latency\n"
           "  --step S        bwstep: seconds per step (default 10); --step-loss P: loss %%; --step-rtt MS: path RTT (50)\n"
           "  --qdelay MS     bottleneck buffer in ms of queueing (default 100; small = policer-like)\n"
           "  --policer KBPS  token-bucket policer in front of the bottleneck (drops, no queue); --pbucket KB depth (64)\n"
           "  --tbf KB        the bottleneck is a token-bucket shaper (tc tbf) with this burst (0 = plain FIFO)\n"
           "  --abr           bwstep: no bulk flow, the video bitrate follows stats.target_rate\n"
           "  --nobulk        bwstep: no bulk flow, fixed video bitrate (the baseline for --abr)\n"
           "  --soak S        soak duration (default 3600), --phase S (60), --sample S (60)\n"
           "  --profile fast|default   protocol parameters (default fast)\n"
           "  --seed N  --csv FILE  --quick\n");
}

int main(int argc, char **argv)
{
    double loss[32] = { 0, 1, 3, 5, 10, 20, 30 }, rtt[32] = { 20, 100, 300 };
    int nloss = 7, nrtt = 3, burst = 4, jitter = 30, i, j;
    int want[8] = { 0 }, any = 0, soak = 0, crypto = 0, bwstep = 0;
    point pts[512];
    int npts = 0;

    anl_allocator(anl_m, anl_f);
    ikcp_allocator(kcp_m, kcp_f);
    setvbuf(stdout, NULL, _IOLBF, 0);

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *nx = i + 1 < argc ? argv[i + 1] : "";
        if (a[0] == 's' && a[1] >= '1' && a[1] <= '5' && a[2] == 0) { want[a[1] - '0'] = 1; any = 1; }
        else if (!strcmp(a, "soak")) { soak = 1; any = 1; }
        else if (!strcmp(a, "bwstep")) { bwstep = 1; any = 1; }
        else if (!strcmp(a, "--qdelay")) { g_qdelay = atoi(nx); i++; }
        else if (!strcmp(a, "--policer")) { g_pol_kbps = atoi(nx); i++; }
        else if (!strcmp(a, "--pbucket")) { g_pol_kb = atoi(nx); i++; }
        else if (!strcmp(a, "--tbf")) { g_tbf_kb = atoi(nx); i++; }
        else if (!strcmp(a, "--step-rtt")) { g_step_rtt = atoi(nx); i++; }
        else if (!strcmp(a, "--abr")) g_abr = 1;
        else if (!strcmp(a, "--nobulk")) g_abr = 2;
        else if (!strcmp(a, "--step")) { g_step_s = atoi(nx); i++; }
        else if (!strcmp(a, "--step-loss")) { g_step_loss = atof(nx) / 100.0; i++; }
        else if (!strcmp(a, "crypto")) { crypto = 1; any = 1; }
        else if (!strcmp(a, "all")) { for (j = 1; j <= 5; j++) want[j] = 1; soak = crypto = 1; any = 1; }
        else if (!strcmp(a, "--loss")) { nloss = parse_list(nx, loss, 32); i++; }
        else if (!strcmp(a, "--rtt")) { nrtt = parse_list(nx, rtt, 32); i++; }
        else if (!strcmp(a, "--burst")) { burst = atoi(nx); i++; }
        else if (!strcmp(a, "--jitter")) { jitter = atoi(nx); i++; }
        else if (!strcmp(a, "--bw")) { g_bw = atoi(nx); i++; }
        else if (!strcmp(a, "--bw5")) { g_bw5 = atoi(nx); i++; }
        else if (!strcmp(a, "--dur")) { g_dur = atoi(nx); i++; }
        else if (!strcmp(a, "--bulk")) { g_bulk_mb = atoi(nx); i++; }
        else if (!strcmp(a, "--wnd")) { g_bulk_wnd = atoi(nx); i++; }
        else if (!strcmp(a, "--init-cwnd")) {
            g_init_cwnd = atoi(nx); i++;
            if (g_init_cwnd < 1 || g_init_cwnd > ANL_MAX_WND) { usage(); return 2; }
        }
        else if (!strcmp(a, "--fec-ratio")) { g_fec_ratio = atoi(nx); i++; }
        else if (!strcmp(a, "--fec-auto")) g_fec_auto = 1;
        else if (!strcmp(a, "--rcv-deadline")) {
            g_rcv_deadline = atoi(nx); i++;
            if (g_rcv_deadline < -1) { usage(); return 2; }
        }
        else if (!strcmp(a, "--soak")) { g_soak = atoi(nx); i++; }
        else if (!strcmp(a, "--phase")) { g_phase = atoi(nx); i++; }
        else if (!strcmp(a, "--sample")) { g_sample = atoi(nx); i++; }
        else if (!strcmp(a, "--seed")) { g_seed = strtoull(nx, NULL, 10); i++; }
        else if (!strcmp(a, "--rttshift")) { g_shift = atoi(nx); i++; }
        else if (!strcmp(a, "--rttshift-ms")) { g_shift_ms = atoi(nx); i++; }
        else if (!strcmp(a, "--av")) g_av = 1;
        else if (!strcmp(a, "--profile")) { g_fast = strcmp(nx, "default") != 0; i++; }
        else if (!strcmp(a, "--csv")) { g_csv = fopen(nx, "w"); i++; }
        else if (!strcmp(a, "--quick")) {
            nloss = 3; loss[0] = 0; loss[1] = 5; loss[2] = 20;
            nrtt = 2; rtt[0] = 50; rtt[1] = 200; g_dur = 20;
        }
        else { usage(); return 2; }
    }
    if (!any) { for (j = 1; j <= 5; j++) want[j] = 1; crypto = 1; }
    if (g_dur <= 0 || g_soak <= 0 || g_phase <= 0 || g_sample <= 0) { usage(); return 2; }

    for (i = 0; i < nloss; i++)
        for (j = 0; j < nrtt; j++) {
            point p = { loss[i] / 100.0, (int)rtt[j], 0, 0, g_bw };
            pts[npts++] = p;
        }
    for (j = 0; j < nrtt && burst > 1; j++) { point p = { 0.05, (int)rtt[j], burst, 0, g_bw }; pts[npts++] = p; }
    for (j = 0; j < nrtt && jitter > 0; j++) {
        point p = { 0.01, (int)rtt[j], 0, (int)rtt[j] / 2 * jitter / 100, g_bw };
        if (p.jitter < 1) p.jitter = 1;
        pts[npts++] = p;
    }

    if (g_csv)
        fprintf(g_csv, "scenario,variant,flow,loss_pct,burst,rtt_ms,jitter_ms,bw_kbps,dur_s,sent,delivered,ontime,keys_sent,keys_dlv,"
                       "app_drop,proto_drop,skipped,fec_rec,dlv_pct,ontime_pct,p50,p95,p99,max,gput_KBps,done_s,"
                       "up_kbps,dn_kbps,cost,up_pkts,dn_pkts,queue_drop,srtt,rto,cwnd,rtx,alive,mem_peak_KB\n");

    printf("AnLiu vs ikcp  profile=%s  seed=%llu  bw=%d kbps (queue %d ms)  bandwidth includes %d B IP/UDP per packet\n",
           g_fast ? "fast (anl: interval=10; kcp: nodelay 1,10,2,1)" : "default", (unsigned long long)g_seed, g_bw, g_qdelay, IPUDP_HDR);
    if (g_init_cwnd) printf("AnLiu init_cwnd=%d segments\n", g_init_cwnd);
    printf("columns: dlv%% delivered/sent  ontm%% delivered within budget  p50..max latency ms  up = A->B wire  "
           "dn = B->A wire  cost = wire bytes (both dirs) per delivered payload byte\n");
    printf("link: loss%%[b=burst]/rtt[j=jitter]\n");

    for (j = 1; j <= 5; j++) if (want[j]) run_scenario(j, pts, npts);
    if (soak) { soak_run(&V_ANLF); soak_run(&V_KCPD); }
    if (bwstep) { bwstep_run(&V_ANL); bwstep_run(&V_ANLF); if (!g_abr) bwstep_run(&V_KCP); }
    if (crypto) {
        printf("\n==== input cost per datagram (real clock, this machine) ====\n");
        bench_input_cost(&V_ANL);
        bench_input_cost(&V_KCP);
    }

    printf("\n==== findings: %d error(s), %d warning(s) ====\n", g_errors, g_warnings);
    for (i = 0; i < g_nfind; i++) { printf("  %s\n", g_find[i]); free(g_find[i]); }
    if (g_csv) fclose(g_csv);
    return g_errors ? 1 : 0;
}
