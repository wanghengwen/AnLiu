/*
 * harness.h - AnLiu loopback simulator and shared test helpers (DESIGN.md M6).
 * Included first by testcases/main.c, which builds the whole suite (see there).
 *
 * anliu.c is included directly so that the crypto primitives (static) can be
 * checked against known-answer vectors.
 */
#include "../anliu.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { g_fail++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/*---------------------------------------------------------------------
 * deterministic random
 *-------------------------------------------------------------------*/
static uint64_t g_seed = 0x9E3779B97F4A7C15ULL;
static uint64_t g_seed0;                /* the run's seed: a test that starts from it does not depend on what ran before */
static uint32_t rnd(void)
{
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 7; g_seed ^= g_seed << 17;
    return (uint32_t)(g_seed >> 16);
}
static int rnd_pct(void) { return (int)(rnd() % 100); }

/*---------------------------------------------------------------------
 * network simulator
 *-------------------------------------------------------------------*/
typedef struct pkt {
    struct pkt *next;
    uint32_t deliver_at;
    int to;
    int len;
    char data[9000];
} pkt;

typedef struct net {
    int loss_pct, dup_pct, min_delay, max_delay;
    int reflect;                    /* send packets back to the sender */
    uint32_t drop_at[4];            /* != 0: drop the datagrams with these n->sent numbers */
    int block[2];                   /* drop everything this side sends (a one-way outage) */
    int max_len[2];                 /* != 0: drop what this side sends longer than this (a size blackhole) */
    int reorder;                    /* 1 = jitter may reorder datagrams; 0 = FIFO path */
    uint32_t last_at[2];            /* last scheduled delivery per direction (FIFO) */
    int bandwidth_bps;              /* 0 = unlimited; otherwise a bottleneck queue */
    int queue_limit;                /* max queued packets at the bottleneck */
    uint32_t link_free_at[2];
    int link_queued[2];
    pkt *queue, *qtail;             /* by delivery time; most arrive at the tail */
    uint32_t now;
    long sent, lost, delivered;
    uint64_t wire_bytes[2];         /* datagram bytes plus IPv4/UDP overhead, by sender */
    anl_t *ep[2];
    int ep_idx[2];
    /* captured datagram for replay tests */
    char cap[2048]; int cap_len; int cap_from;
    uint32_t burst_window_bytes[2]; uint32_t burst_window_start[2]; uint32_t max_burst[2];
    int clock_ppm[2];               /* this side's clock runs this much fast (0: the net's clock) */
    uint32_t clock_t0;              /* net_start: where the clocks part */
} net;

/* an endpoint's clock: the net's, plus clock_ppm since the start (net_start) */
static uint32_t ep_clock(const net *n, int i)
{
    return n->now + (uint32_t)((int64_t)(int32_t)(n->now - n->clock_t0) * n->clock_ppm[i] / 1000000);
}

static void net_enqueue(net *n, int to, const char *data, int len, uint32_t at)
{
    pkt *p = (pkt *)malloc(sizeof(pkt)), **pp;
    p->deliver_at = at; p->to = to; p->len = len; memcpy(p->data, data, (size_t)len);
    if (n->queue && (int32_t)(n->qtail->deliver_at - at) <= 0) { p->next = NULL; n->qtail->next = p; n->qtail = p; return; }
    for (pp = &n->queue; *pp && (int32_t)((*pp)->deliver_at - at) <= 0; pp = &(*pp)->next) ;
    p->next = *pp; *pp = p;
    if (p->next == NULL) n->qtail = p;
}

static int net_output(char *buf, int len, anl_t *w, void *user)
{
    int *idx = (int *)user;
    net *n = (net *)((char *)idx - offsetof(net, ep_idx) - (size_t)(*idx) * sizeof(int));
    int from = *idx, to = n->reflect ? from : 1 - from;
    uint32_t delay;
    (void)w;
    n->sent++;
    n->wire_bytes[from] += (uint64_t)len + 28;
    {
        int d;
        for (d = 0; d < 4; d++)
            if (n->drop_at[d] != 0 && (uint32_t)n->sent == n->drop_at[d]) { n->lost++; return 0; }
    }
    if (n->block[from] || (n->max_len[from] && len > n->max_len[from])) { n->lost++; return 0; }
    /* burst measurement over a 5 ms window */
    if ((int32_t)(n->now - n->burst_window_start[from]) >= 5) { n->burst_window_start[from] = n->now; n->burst_window_bytes[from] = 0; }
    n->burst_window_bytes[from] += (uint32_t)len;
    if (n->burst_window_bytes[from] > n->max_burst[from]) n->max_burst[from] = n->burst_window_bytes[from];

    if (n->cap_len == 0 && len > 60 && from == 0) { memcpy(n->cap, buf, (size_t)len); n->cap_len = len; n->cap_from = from; }
    if (rnd_pct() < n->loss_pct) { n->lost++; return 0; }
    delay = (uint32_t)n->min_delay + (n->max_delay > n->min_delay ? rnd() % (uint32_t)(n->max_delay - n->min_delay) : 0);
    if (!n->reorder && (int32_t)(n->now + delay - n->last_at[from]) < 0) delay = n->last_at[from] - n->now;
    n->last_at[from] = n->now + delay;
    if (n->bandwidth_bps > 0) {
        uint32_t serial = (uint32_t)((uint64_t)len * 8000 / (uint64_t)n->bandwidth_bps) + 1;
        uint32_t start = (int32_t)(n->link_free_at[from] - n->now) > 0 ? n->link_free_at[from] : n->now;
        if (n->queue_limit > 0 && (int32_t)(start - n->now) > (int32_t)(serial * (uint32_t)n->queue_limit)) { n->lost++; return 0; }
        n->link_free_at[from] = start + serial;
        delay += start + serial - n->now;
    }
    net_enqueue(n, to, buf, len, n->now + delay);
    if (rnd_pct() < n->dup_pct) net_enqueue(n, to, buf, len, n->now + delay + 1 + rnd() % 10);
    return 0;
}

static void net_deliver(net *n)
{
    while (n->queue && (int32_t)(n->queue->deliver_at - n->now) <= 0) {
        pkt *p = n->queue;
        n->queue = p->next;
        if (n->queue == NULL) n->qtail = NULL;
        n->delivered++;
        anl_input(n->ep[p->to], p->data, p->len);
        free(p);
    }
}

static void net_free(net *n)
{
    while (n->queue) { pkt *p = n->queue; n->queue = p->next; free(p); }
}

/* deterministic padding / PRNG so that a test run is reproducible from g_seed */
static void det_rng(void *user, uint8_t *buf, size_t n)
{
    (void)user;
    while (n--) *buf++ = (uint8_t)rnd();
}

static void net_init(net *n, anl_config *ca, anl_config *cb)
{
    memset(n, 0, sizeof(*n));
    n->ep_idx[0] = 0; n->ep_idx[1] = 1;
    n->min_delay = 20; n->max_delay = 40;
    n->now = 1000;
    anl_config_default(ca, ANL_ROLE_CLIENT);
    anl_config_default(cb, ANL_ROLE_SERVER);
    memset(ca->psk, 0x42, 32);
    memset(cb->psk, 0x42, 32);
    ca->rng = cb->rng = det_rng;
}

/* accept callback shared by all tests: records the handle per side and sid and
 * applies the local options the test wants on the accepting side */
#define G_PEER_SIDS (1 << 15)              /* sids the tests index g_peer by */
static anl_stream_t *g_peer[2][G_PEER_SIDS];
static const anl_stream_opt *g_peer_opt[2];
static int g_acc[2], g_acc_reject_mod, g_acc_rcv_wnd;

static int acc_cb(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    int side = *(int *)user, sid = anl_stream_id(s);
    (void)w;
    if (g_acc_reject_mod && sid % g_acc_reject_mod == 2) return -1;
    if (g_peer_opt[side]) {
        anl_stream_opt keep = *opt;
        *opt = *g_peer_opt[side];
        opt->mode = keep.mode; opt->stream = keep.stream; opt->tag = keep.tag;
    }
    if (g_acc_rcv_wnd) opt->rcv_wnd = g_acc_rcv_wnd;
    if (sid < G_PEER_SIDS) g_peer[side][sid] = s;
    g_acc[side]++;
    return 0;
}

static void net_start(net *n, const anl_config *ca, const anl_config *cb)
{
    memset(g_peer, 0, sizeof(g_peer));
    g_peer_opt[0] = g_peer_opt[1] = NULL;
    /* FIFO / link state relative to the clock (a test may start it past 2^31) */
    n->last_at[0] = n->last_at[1] = n->link_free_at[0] = n->link_free_at[1] = n->now;
    n->burst_window_start[0] = n->burst_window_start[1] = n->now;
    n->clock_t0 = n->now;
    g_acc[0] = g_acc[1] = 0; g_acc_reject_mod = 0; g_acc_rcv_wnd = 0;
    n->ep[0] = anl_create(0x11223344, ca, &n->ep_idx[0]);
    n->ep[1] = anl_create(0x11223344, cb, &n->ep_idx[1]);
    anl_setoutput(n->ep[0], net_output);
    anl_setoutput(n->ep[1], net_output);
    anl_set_accept(n->ep[0], acc_cb);
    anl_set_accept(n->ep[1], acc_cb);
    anl_update(n->ep[0], n->now);
    anl_update(n->ep[1], n->now);
}

static void net_stop(net *n)
{
    anl_release(n->ep[0]);
    anl_release(n->ep[1]);
    net_free(n);
}

/* advance one millisecond */
static void net_tick(net *n)
{
    n->now++;
    net_deliver(n);
    anl_update(n->ep[0], ep_clock(n, 0));
    anl_update(n->ep[1], ep_clock(n, 1));
}

/*---------------------------------------------------------------------
 * 1. known-answer tests
 *-------------------------------------------------------------------*/
static void hex2bin(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}
