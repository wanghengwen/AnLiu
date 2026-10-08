/* Deterministic capacity-vs-random-loss comparison for the policer detector.
 * Build from the repository root:
 *   cc -std=gnu99 -O2 -I. bench/capacity_step.c bench/ikcp.c -lm -o /tmp/anl_capacity_step
 * Usage: anl_capacity_step [RTT_ms=100] [middle_loss_percent=0] [phase_ms=75000] [seed=1]
 *                         [high_kbps=30000] [low_kbps=10000] [bucket_KiB=4096] [message_bytes=8192]
 * With zero middle loss: capacity high -> low -> high (default 30 -> 10 -> 30 Mbps).
 * Otherwise: capacity stays high, bidirectional loss 0 -> supplied -> 0.
 * Short-RTT / low-rate example: 1 0 15000 1 8000 3000 32 1024
 * Phase length must be a positive multiple of the 5 s reporting interval.
 * Exit status checks delivery integrity/liveness; compare phase throughput
 * and retransmissions separately, since passing alone is not a performance check.
 */
#include "../anliu.c"
#define main bench_main
#include "bench.c"
#undef main
int main(int argc, char **argv)
{
    sim s;
    flow f;
    rres result;
    int rtt = argc > 1 ? atoi(argv[1]) : 100;
    int cur = -1;
    int period = argc > 3 ? atoi(argv[3]) : 75000;
    int loss_step = argc > 2 ? atoi(argv[2]) : 0;
    uint64_t last_bytes = 0, last_wire = 0;
    uint32_t last_rtx = 0;
    int rates[] = {30000, 10000, 30000};
    int bucket = argc > 7 ? atoi(argv[7]) : 4096;
    int message = argc > 8 ? atoi(argv[8]) : 8192;
    linkcfg lc = {0, 0, 0, 0, 1000000, 100, 0};
    if (argc > 5) rates[0] = rates[2] = atoi(argv[5]);
    if (argc > 6) rates[1] = atoi(argv[6]);
    if (rtt < 1 || rtt > 10000 || loss_step < 0 || loss_step > 99 ||
        period < 5000 || period > 3600000 || period % 5000 ||
        rates[0] < 1 || rates[0] > 1000000 || rates[1] < 1 || rates[1] > rates[0] ||
        bucket < 2 || bucket > 1048576 || message < 16 || message > 65536) {
        fprintf(stderr, "invalid RTT, loss, phase duration, rates, bucket or message size\n");
        return 2;
    }
    if (loss_step) rates[1] = rates[0];
    lc.delay = rtt / 2.0;
    g_pol_kbps = rates[0];
    g_pol_kb = bucket;
    g_seed = argc > 4 ? (uint64_t)atoi(argv[4]) : 1;
    snprintf(g_label, sizeof(g_label), "policer-step");
    sim_init(&s, &V_ANL, &lc, 1000, g_seed);
    flow_bulk(&f, 0, 0, 0);
    f.msg_size = message;
    f.snd_wnd = f.rcv_wnd = 4096;
    sim_add_flows(&s, &f, 1);
    while (s.t < (uint64_t)period * 3) {
        int phase = (int)(s.t / period);
        if (phase != cur) {
            cur = phase;
            g_pol_kbps = rates[phase];
            if (loss_step) s.d[0].c.loss = s.d[1].c.loss = phase == 1 ? loss_step / 100.0 : 0;
        }
        sim_tick(&s, 1);
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) {
            anl_t *w = s.e[0].anl;
            anl_stream *st = s.e[0].h[f.sid];
            anl_node *pos;
            const anl_seg *most = NULL;
            for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
                const anl_seg *seg = QENTRY(pos, anl_seg, node);
                if (!most || seg->xmit > most->xmit) most = seg;
            }
            printf("FAIL dead t=%llu sender=%d receiver=%d lt=%d rate=%u pace=%u hold=%u"
                   " max_xmit=%u sn=%u last_rtx=%u\n", (unsigned long long)s.t,
                   w->state, s.e[1].anl->state, w->lt.state, w->lt.rate, w->pace_rate,
                   w->lt.hold, most ? most->xmit : 0, most ? most->sn : 0,
                   most ? (unsigned)most->rack_rtx : 0);
            sim_finish(&s, &result, s.t / 1000.0);
            return 1;
        }
        if (s.t % 5000 == 0) {
            anl_stats stats;
            anl_t *w = s.e[0].anl;
            anl_get_stats(w, &stats);
            printf("t=%llu capacity=%d gput=%.3f wire=%.3f rtx=%u lt=%d k=%u base=%u bw=%u\n",
                (unsigned long long)s.t, rates[cur],
                (f.rcv_bytes - last_bytes) * 8.0 / 5000000.0,
                (s.d[0].bytes - last_wire) * 8.0 / 5000000.0,
                w->retrans_total - last_rtx, w->lt.state, w->lt.k, w->lt.rate, stats.bw_estimate);
            last_bytes = f.rcv_bytes; last_wire = s.d[0].bytes; last_rtx = w->retrans_total;
        }
    }
    sim_finish(&s, &result, period * 3 / 1000.0);
    printf("complete alive=%d total_rtx=%u errors=%u/%u/%u\n", result.alive, result.cs.rtx, f.corrupt, f.order_err, f.gap);
    return !result.alive || f.corrupt || f.order_err || f.gap;
}
