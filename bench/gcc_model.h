/* A model of WebRTC's Google Congestion Control (send-side, transport-cc),
 * for comparing its target rate with AnLiu's (media_loss MEDIA_LOSS_RATE=gcc
 * or gccd). After draft-ietf-rmcat-gcc-02 and libwebrtc's goog_cc:
 *
 * - feedback: every GCC_FB_MS the receiver reports arrival times (and losses)
 *   of the forward datagrams; it reaches the sender a one-way delay later
 *   (the reverse path is not shaped; lost feedback is not modelled);
 * - delay-based: packets in groups of GCC_BURST_MS send time; per group the
 *   delay variation (arrival delta - send delta) feeds the trendline filter
 *   (smoothing 0.9, window 20, gain 4), compared with an adaptive threshold
 *   (12.5 ms start, k_up 0.0087, k_down 0.039, 6..600) - overuse after 10 ms
 *   and two samples above it with a rising trend;
 * - AIMD: overuse -> 0.85 x acknowledged throughput, then hold; normal ->
 *   increase, multiplicative 8%/s, additive (one packet per response time
 *   rtt + 100 ms) near the link capacity estimate; at most 1.5 x throughput
 *   + 10 kbit/s;
 * - loss-based (v1; not in gccd): loss <= 2% -> +8% at most once a second,
 *   > 10% -> x (1 - loss / 2) at most once per 300 ms + rtt, otherwise hold;
 *   the target is the smaller of the two;
 * - start 300 kbit/s with the initial exponential probes (3x, 6x, then 2x
 *   the result while a probe gets at least 70% of its rate). A probe's
 *   result is min(probe rate, link rate) x (1 - random loss) one RTT later;
 *   probe padding is not sent (slightly in GCC's favour). ALR probing is
 *   not modelled.
 * Rates in bit/s. */
#include <math.h>

#define GCC_FB_MS       50
#define GCC_BURST_MS    5
#define GCC_WIN         20
#define GCC_MAXREC      65536

typedef struct { double send, at; int len, lost; } gcc_rec;
typedef struct {
    int on, loss_based;
    double target, delay_rate, loss_rate, max_rate;
    /* receiver side: records not yet reported; feedback in flight */
    gcc_rec rec[GCC_MAXREC]; int nrec;
    struct { double due; int from, to; } fb[256]; int nfb;
    gcc_rec rep[GCC_MAXREC * 2]; int nrep;         /* reported records (ring) */
    double next_fb;
    /* inter-arrival groups */
    int g_have; double g_first_send, g_last_send, g_last_at; int g_size;
    int p_have; double p_last_send, p_last_at;
    /* trendline */
    double acc, smoothed, first_at; int nd; double tx[GCC_WIN], ty[GCC_WIN]; int tn, th;
    double trend, prev_trend, thr, last_thr_at, over_time; int over_cnt;
    int usage;                                      /* 0 normal, 1 over, -1 under */
    /* AIMD */
    int state;                                      /* 0 hold, 1 increase, 2 decrease */
    double last_change, link_est, link_var; int link_have;
    /* acknowledged throughput: bytes per arrival time over 500 ms */
    double ack_t[4096]; int ack_b[4096]; int ack_h, ack_n;
    /* loss-based */
    int lb_sent, lb_lost; double lb_last_inc, lb_last_dec;
    /* probing */
    int probe_stage; double probe_rate, probe_due;
    unsigned overuses, decreases;
} gcc_t;

static void gcc_init(gcc_t *g, int loss_based, double max_rate)
{
    memset(g, 0, sizeof(*g));
    g->on = 1; g->loss_based = loss_based; g->max_rate = max_rate;
    g->target = g->delay_rate = g->loss_rate = 300000;
    g->thr = 12.5; g->link_var = 0.4;
    g->probe_stage = 1; g->probe_rate = 3 * 300000; g->probe_due = 0;
}

/* the simulator: a forward datagram sent at `send` (ms) arrived at `at` or was lost */
static void gcc_on_packet(gcc_t *g, double send, double at, int len, int lost)
{
    if (!g->on || g->nrec >= GCC_MAXREC) return;
    g->rec[g->nrec].send = send; g->rec[g->nrec].at = at;
    g->rec[g->nrec].len = len; g->rec[g->nrec].lost = lost;
    g->nrec++;
}

static void gcc_link_update(gcc_t *g, double kbps)
{
    double a = 0.05, err;
    if (!g->link_have) { g->link_est = kbps; g->link_have = 1; return; }
    g->link_est = (1 - a) * g->link_est + a * kbps;
    err = g->link_est - kbps;
    g->link_var = (1 - a) * g->link_var + a * err * err / (g->link_est > 1 ? g->link_est : 1);
    if (g->link_var < 0.4) g->link_var = 0.4;
    if (g->link_var > 2.5) g->link_var = 2.5;
}
static double gcc_link_dev(const gcc_t *g) { return sqrt(g->link_var * g->link_est); }

static double gcc_throughput(gcc_t *g, double now)
{
    double sum = 0, t0 = now - 500;
    int i;
    for (i = 0; i < g->ack_n; i++) {
        int k = (g->ack_h - 1 - i) & 4095;
        if (g->ack_t[k] < t0) break;
        sum += g->ack_b[k];
    }
    return sum * 8 / 0.5;
}

static void gcc_trend(gcc_t *g, double d, double at, double send_delta)
{
    double mx = 0, my = 0, num = 0, den = 0, slope;
    int i, n;
    g->acc += d;
    g->smoothed = 0.9 * g->smoothed + 0.1 * g->acc;
    if (g->nd == 0) g->first_at = at;
    g->nd++;
    g->tx[g->th] = at - g->first_at; g->ty[g->th] = g->smoothed;
    g->th = (g->th + 1) % GCC_WIN;
    if (g->tn < GCC_WIN) g->tn++;
    if (g->tn < GCC_WIN) return;
    n = g->tn;
    for (i = 0; i < n; i++) { mx += g->tx[i]; my += g->ty[i]; }
    mx /= n; my /= n;
    for (i = 0; i < n; i++) { num += (g->tx[i] - mx) * (g->ty[i] - my); den += (g->tx[i] - mx) * (g->tx[i] - mx); }
    slope = den > 0 ? num / den : 0;
    g->prev_trend = g->trend;
    g->trend = (g->nd < 60 ? g->nd : 60) * slope * 4;
    /* detector */
    {
        double t = g->trend, dt = g->last_thr_at > 0 ? at - g->last_thr_at : 0;
        if (t > g->thr) {
            g->over_time += send_delta > 0 ? send_delta : GCC_BURST_MS;
            g->over_cnt++;
            if (g->over_time > 10 && g->over_cnt > 1 && t >= g->prev_trend) {
                g->over_time = 0; g->over_cnt = 0; g->usage = 1; g->overuses++;
            }
        } else if (t < -g->thr) { g->over_time = -1; g->over_cnt = 0; g->usage = -1; }
        else { g->over_time = -1; g->over_cnt = 0; g->usage = 0; }
        if (fabs(t) <= g->thr + 15) {
            double k = fabs(t) < g->thr ? 0.039 : 0.0087;
            if (dt > 100) dt = 100;
            g->thr += k * (fabs(t) - g->thr) * dt;
            if (g->thr < 6) g->thr = 6;
            if (g->thr > 600) g->thr = 600;
        }
        g->last_thr_at = at;
    }
}

static void gcc_group_packet(gcc_t *g, const gcc_rec *r)
{
    if (!g->g_have) {
        g->g_have = 1; g->g_first_send = g->g_last_send = r->send; g->g_last_at = r->at; g->g_size = r->len;
        return;
    }
    if (r->send - g->g_first_send <= GCC_BURST_MS) {    /* same group */
        if (r->send > g->g_last_send) g->g_last_send = r->send;
        if (r->at > g->g_last_at) g->g_last_at = r->at;
        g->g_size += r->len;
        return;
    }
    /* the group is complete */
    if (g->p_have) {
        double sd = g->g_last_send - g->p_last_send, ad = g->g_last_at - g->p_last_at;
        gcc_trend(g, ad - sd, g->g_last_at, sd);
    }
    g->p_have = 1; g->p_last_send = g->g_last_send; g->p_last_at = g->g_last_at;
    g->g_first_send = g->g_last_send = r->send; g->g_last_at = r->at; g->g_size = r->len;
}

static void gcc_aimd(gcc_t *g, double now, double rtt)
{
    double thr = gcc_throughput(g, now), cur = g->delay_rate, dt = g->last_change > 0 ? now - g->last_change : 0;
    if (g->usage == 1 && g->state != 2) g->state = 2;
    else if (g->usage == 0 && g->state == 0) g->state = 1;
    else if (g->usage == -1) g->state = 0;
    if (g->state == 1) {
        double inc;
        if (g->link_have && cur / 1000 > g->link_est + 3 * gcc_link_dev(g)) g->link_have = 0;
        if (g->link_have) {
            double resp = rtt + 100, bpf = cur / 30, ppf = ceil(bpf / (8 * 1200)), pkt = bpf / (ppf > 0 ? ppf : 1);
            double per_s = pkt * 1000 / resp;
            if (per_s < 4000) per_s = 4000;
            inc = per_s * (dt > 1000 ? 1000 : dt) / 1000;
        } else {
            inc = cur * (pow(1.08, (dt > 1000 ? 1000 : dt) / 1000.0) - 1);
            if (inc < 1000 * dt / 1000) inc = 1000 * dt / 1000;
        }
        /* not above 1.5 x the throughput + 10 kbit/s, never below the current rate */
        if (thr > 0 && cur + inc > 1.5 * thr + 10000) cur = cur > 1.5 * thr + 10000 ? cur : 1.5 * thr + 10000;
        else cur += inc;
    } else if (g->state == 2) {
        double dec = 0.85 * thr;
        if (g->link_have && thr / 1000 < g->link_est - 3 * gcc_link_dev(g)) g->link_have = 0;
        if (dec > cur && g->link_have) dec = 0.85 * g->link_est * 1000;
        if (thr > 0 && dec < cur) { cur = dec; g->decreases++; }
        if (thr > 0) gcc_link_update(g, thr / 1000);
        g->state = 0;
    }
    if (cur > g->max_rate) cur = g->max_rate;
    if (cur < 30000) cur = 30000;
    g->delay_rate = cur;
    g->last_change = now;
}

static void gcc_loss_update(gcc_t *g, double now, double rtt)
{
    double loss;
    if (g->lb_sent < 20) return;
    loss = (double)g->lb_lost / g->lb_sent;
    if (loss <= 0.02) {
        if (now - g->lb_last_inc >= 1000) { g->loss_rate = g->loss_rate * 1.08 + 1000; g->lb_last_inc = now; }
    } else if (loss > 0.10) {
        if (now - g->lb_last_dec >= 300 + rtt) { g->loss_rate *= 1 - 0.5 * loss; g->lb_last_dec = now; }
    }
    g->lb_sent = g->lb_lost = 0;
}

/* once per simulated ms: link_kbps and loss for the probe model, rtt (ms) for the response time */
static void gcc_tick(gcc_t *g, double now, double owd, double rtt, double link_kbps, double rand_loss)
{
    int i;
    if (!g->on) return;
    /* initial exponential probing */
    if (g->probe_stage && now >= g->probe_due) {
        if (g->probe_due > 0) {
            double got = g->probe_rate, cap = link_kbps > 0 ? link_kbps * 1000 : 1e12;
            if (got > cap) got = cap;
            got *= 1 - rand_loss;
            if (got > g->delay_rate) g->delay_rate = got > g->max_rate ? g->max_rate : got;
            if (got > g->loss_rate) g->loss_rate = g->delay_rate;
            if (got >= 0.7 * g->probe_rate && g->probe_rate < g->max_rate) {
                g->probe_rate = g->probe_stage == 1 ? 6 * 300000 : 2 * got;
                g->probe_stage++;
            } else g->probe_stage = 0;
        }
        if (g->probe_stage) g->probe_due = now + rtt + GCC_FB_MS;
    }
    /* the receiver sends feedback for what has arrived (or is known lost) */
    if (now >= g->next_fb) {
        int k = 0, from = g->nrep;
        for (i = 0; i < g->nrec; i++) {
            gcc_rec *r = &g->rec[i];
            if (r->lost ? r->send + owd <= now : r->at <= now) {
                if (g->nrep < GCC_MAXREC * 2) g->rep[g->nrep++] = *r;
            } else g->rec[k++] = *r;
        }
        g->nrec = k;
        if (g->nrep > from && g->nfb < 256) {
            g->fb[g->nfb].due = now + owd; g->fb[g->nfb].from = from; g->fb[g->nfb].to = g->nrep; g->nfb++;
        }
        g->next_fb = now + GCC_FB_MS;
    }
    /* the sender gets feedback */
    while (g->nfb > 0 && g->fb[0].due <= now) {
        int a = g->fb[0].from, b = g->fb[0].to, j;
        /* in arrival order within the report */
        for (j = a; j < b; j++) {
            gcc_rec *r = &g->rep[j];
            g->lb_sent++;
            if (r->lost) { g->lb_lost++; continue; }
            g->ack_t[g->ack_h] = r->at; g->ack_b[g->ack_h] = r->len;
            g->ack_h = (g->ack_h + 1) & 4095; if (g->ack_n < 4096) g->ack_n++;
            gcc_group_packet(g, r);
        }
        memmove(g->fb, g->fb + 1, (size_t)(g->nfb - 1) * sizeof(g->fb[0])); g->nfb--;
        gcc_aimd(g, now, rtt);
        if (g->loss_based) gcc_loss_update(g, now, rtt);
        /* drop the reported records no feedback in flight refers to */
        {
            int base = g->nfb > 0 ? g->fb[0].from : g->nrep, q;
            if (base > 0) {
                memmove(g->rep, g->rep + base, (size_t)(g->nrep - base) * sizeof(g->rep[0]));
                g->nrep -= base;
                for (q = 0; q < g->nfb; q++) { g->fb[q].from -= base; g->fb[q].to -= base; }
            }
        }
    }
    g->target = g->loss_based && g->loss_rate < g->delay_rate ? g->loss_rate : g->delay_rate;
    if (g->loss_based && g->loss_rate > g->delay_rate) g->loss_rate = g->delay_rate;
}
