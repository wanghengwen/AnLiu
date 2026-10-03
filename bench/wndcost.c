/*
 * wndcost.c - CPU cost of large windows (DESIGN 5.1): one reliable bulk
 * stream over a simulated bottleneck (bandwidth, propagation RTT, tail-drop
 * queue, random loss), stepped in 1 ms. Prints the delivered rate and the
 * process CPU time per simulated second and per delivered segment, so that
 * the per-segment cost can be compared across window sizes / BDPs.
 *
 * Build: cc -std=gnu99 -O2 -I.. wndcost.c ../anliu.c -o wndcost -lm
 * Usage: wndcost MBps rtt_ms loss_permille wnd seconds [seed]
 */
#include "anliu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct pkt {
    struct pkt *next;
    uint32_t at;
    int len;
    char data[1500];
} pkt;

typedef struct dirq {
    pkt *head, *tail;
    uint64_t free_at_us;            /* bottleneck busy until (microseconds) */
} dirq;

static uint64_t g_rng = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}

static dirq g_q[2];
static anl_t *g_ep[2];
static int g_idx[2] = { 0, 1 };
static uint32_t g_now;
static uint64_t g_bps;              /* bytes per second */
static uint32_t g_owd, g_loss, g_qlimit_us;
static uint64_t g_drops, g_tx;

static int out(char *buf, int len, anl_t *w, void *user)
{
    int from = *(int *)user;
    dirq *q = &g_q[from];
    uint64_t now_us = (uint64_t)g_now * 1000, start;
    pkt *p;
    (void)w;
    g_tx++;
    if (g_loss && rnd() % 1000 < g_loss) { g_drops++; return 0; }
    start = q->free_at_us > now_us ? q->free_at_us : now_us;
    if (start - now_us > g_qlimit_us) { g_drops++; return 0; }
    q->free_at_us = start + (uint64_t)(len + 28) * 1000000 / g_bps;
    p = (pkt *)malloc(sizeof(pkt));
    p->next = NULL;
    p->at = (uint32_t)((q->free_at_us + 999) / 1000) + g_owd;
    p->len = len;
    memcpy(p->data, buf, (size_t)len);
    if (q->tail) q->tail->next = p; else q->head = p;
    q->tail = p;
    return 0;
}

static void deliver(int from)
{
    dirq *q = &g_q[from];
    while (q->head && (int32_t)(q->head->at - g_now) <= 0) {
        pkt *p = q->head;
        q->head = p->next;
        if (q->head == NULL) q->tail = NULL;
        anl_input(g_ep[1 - from], p->data, p->len);
        free(p);
    }
}

static anl_stream_t *g_rx;
static int acc(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    (void)w; (void)opt; (void)user;
    g_rx = s;
    return 0;
}

static double cpu_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    anl_config c[2];
    anl_stream_opt o;
    anl_stream_t *tx;
    static char buf[65536];
    uint64_t got = 0;
    double t0, t1;
    int i, wnd, secs;
    uint32_t end;
    if (argc < 6) {
        fprintf(stderr, "usage: %s MBps rtt_ms loss_permille wnd seconds [seed]\n", argv[0]);
        return 2;
    }
    g_bps = (uint64_t)(atof(argv[1]) * 1e6);
    g_owd = (uint32_t)atoi(argv[2]) / 2;
    g_loss = (uint32_t)atoi(argv[3]);
    wnd = atoi(argv[4]);
    secs = atoi(argv[5]);
    if (argc > 6) g_rng ^= (uint64_t)strtoull(argv[6], NULL, 0) * 0x2545F4914F6CDD1DULL;
    g_qlimit_us = (uint32_t)atoi(argv[2]) * 1000;    /* a queue of one RTT */

    for (i = 0; i < 2; i++) {
        anl_config_default(&c[i], i);
        memset(c[i].psk, 7, sizeof(c[i].psk));
        c[i].interval = 10;
        c[i].rcv_limit_bytes = 0;
    }
    g_now = 1000;
    for (i = 0; i < 2; i++) {
        g_ep[i] = anl_create(0x5a5a, &c[i], &g_idx[i]);
        if (g_ep[i] == NULL) { fprintf(stderr, "anl_create failed\n"); return 1; }
        anl_setoutput(g_ep[i], out);
        anl_update(g_ep[i], g_now);
    }
    anl_set_accept(g_ep[1], acc);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.stream = 1;
    o.snd_wnd = o.rcv_wnd = wnd;
    o.prio = 1;
    tx = anl_stream_open(g_ep[0], &o, &i);
    if (tx == NULL) { fprintf(stderr, "open failed %d\n", i); return 1; }
    memset(buf, 0x33, sizeof(buf));

    t0 = cpu_s();
    end = g_now + (uint32_t)secs * 1000;
    while ((int32_t)(g_now - end) < 0) {
        g_now++;
        deliver(0);
        deliver(1);
        anl_update(g_ep[0], g_now);
        anl_update(g_ep[1], g_now);
        while (anl_stream_waitsnd(tx) < 2 * wnd) {
            if (anl_stream_send(tx, buf, sizeof(buf)) < 0) break;
        }
        if (g_rx) {
            int n;
            while ((n = anl_stream_recv(g_rx, buf, sizeof(buf))) > 0) got += (uint64_t)n;
        }
    }
    t1 = cpu_s();
    {
        anl_stats s;
        double segs = (double)got / 1368.0;
        anl_get_stats(g_ep[0], &s);
        printf("bw %.1f MB/s rtt %d loss %u/1000 wnd %d: got %.2f MB/s, srtt %u cwnd %u retrans %u drops %llu | "
               "cpu %.3f s per sim s, %.0f ns/seg\n",
               atof(argv[1]), atoi(argv[2]), g_loss, wnd, got / 1e6 / secs, s.srtt, s.cwnd, s.retrans,
               (unsigned long long)g_drops, (t1 - t0) / secs, segs > 0 ? (t1 - t0) * 1e9 / segs : 0.0);
    }
    return 0;
}
