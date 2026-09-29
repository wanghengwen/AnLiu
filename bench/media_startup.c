/* Cold-start audio/video test, using bench.c's deterministic network model.
 * Build: cc -std=gnu99 -O2 -I. bench/media_startup.c anliu.c bench/ikcp.c -lm -o /tmp/anl_media_startup
 * Usage: anl_media_startup [init_cwnd=16] [bw_kbps=2000] [RTT_ms=280]
 *        [loss_percent=0] [queue_ms=100] [seed=1] [duration_s=60] [first_key_bytes=33975]
 *        [rcv_deadline_ms=-1] [fec_mode=-1: RTT-auto, 0: off, 1: adaptive always]
 * Both directions have the specified rate/loss/queue.
 * Frames start immediately after stream open, as in realnet (no warm-up).
 * Phases refer to generation time: 0..2 s, 2..20 s, 20 s onward. Extra delay subtracts
 * the known one-way propagation delay, not the measured minimum. A sender
 * abandoning an unacknowledged frame is counted separately from receiver loss.
 */
#define main benchmark_main
#include "bench.c"
#undef main

typedef struct {
    uint32_t sent, received, ontime;
    uint32_t *lat;
} startup_phase;

static int media_phase(uint64_t ms) { return ms < 2000 ? 0 : ms < 20000 ? 1 : 2; }

int main(int argc, char **argv)
{
    sim s;
    flow fl[2];
    startup_phase m[2][3] = {{{0}}};
    int wnd = argc > 1 ? atoi(argv[1]) : 16;
    int bw = argc > 2 ? atoi(argv[2]) : 2000;
    int rtt = argc > 3 ? atoi(argv[3]) : 280;
    int loss = argc > 4 ? atoi(argv[4]) : 0;
    int queue = argc > 5 ? atoi(argv[5]) : 100;
    int seed = argc > 6 ? atoi(argv[6]) : 1;
    int duration = argc > 7 ? atoi(argv[7]) : 60;
    int first_key = argc > 8 ? atoi(argv[8]) : 33975;
    int deadline = argc > 9 ? atoi(argv[9]) : -1;
    int fec_mode = argc > 10 ? atoi(argv[10]) : -1;
    int i, k, errors = 0, first_key_delay = -1;
    cstats cs;
    linkcfg lc = {0};
    if (wnd < 1 || wnd > ANL_MAX_WND || bw < 1 || rtt < 1 || rtt > 10000 ||
        loss < 0 || loss > 50 || queue < 1 || seed < 1 || duration < 3 || duration > 600 ||
        first_key < PHDR || first_key > 100000 || deadline < -1 || fec_mode < -1 || fec_mode > 1) return 2;
#ifndef ANL_FEC_RTT_AUTO
    if (fec_mode == -1) { fprintf(stderr, "this protocol build has no RTT-conditional FEC\n"); return 2; }
#endif
    g_init_cwnd = wnd; g_seed = (uint64_t)seed; g_fec_ratio = 0;
    g_rcv_deadline = deadline;
    lc.delay = rtt / 2.0; lc.bw_kbps = bw; lc.loss = loss / 100.0; lc.qdelay = queue;
    sim_init(&s, &V_ANLF, &lc, 1000, g_seed);
    flow_audio(&fl[0], 0, &V_ANLF);
    flow_video(&fl[1], 1, &V_ANLF);
    fl[0].fec = fl[1].fec = fec_mode;
    s.fl = fl; s.nfl = 2;
    for (i = 0; i < 2; i++) {
        ep_open(&s.e[0], &fl[i]);
        for (k = 0; k < 3; k++) {
            m[i][k].lat = malloc((size_t)(duration * 50 + 2) * sizeof(uint32_t));
            if (!m[i][k].lat) return 2;
        }
    }
    printf("CONFIG init_cwnd=%d bw=%d rtt=%d loss=%d queue=%d seed=%d duration=%d first_key=%d deadline=%d fec=%d\n",
           wnd, bw, rtt, loss, queue, seed, duration, first_key, deadline, fec_mode);
    while (s.t < (uint64_t)duration * 1000 + 5000) {
        s.t++;
        for (k = 0; k < 2; k++) {
            dir *d = &s.d[k];
            while (d->head && d->head->at <= s.t) {
                pkt *p = d->head;
                d->head = p->next;
                if (d->head) d->head->prev = NULL; else d->tail = NULL;
                d->delivered++;
                ep_input(&s.e[1 - k], p->data, p->len);
                free(p);
            }
        }
        if (s.t < (uint64_t)duration * 1000) for (i = 0; i < 2; i++) {
            flow *f = &fl[i];
            if (s.t >= f->next_t) {
                int key = f->gop && f->seq % (uint32_t)f->gop == 0;
                int len = key ? rnd_range(&g_trng, f->key_min, f->key_max)
                              : rnd_range(&g_trng, f->size_min, f->size_max);
                if (i == 1 && f->seq == 0) len = first_key;
                m[i][media_phase(s.t)].sent++;
                if (gen_one(&s, f, len, key) < 0) errors++;
                f->next_t = i == 0 ? (uint64_t)f->seq * 20 : (uint64_t)f->seq * 1000 / 30;
            }
        }
        ep_update(&s.e[0], now32(&s));
        ep_update(&s.e[1], now32(&s));
        for (i = 0; i < 2; i++) {
            flow *f = &fl[i];
            anl_frame_info fi;
            int len;
            while ((len = ep_recv(&s.e[1], f, g_buf, sizeof(g_buf), &fi)) >= 0) {
                uint32_t seq, generated, latency;
                startup_phase *p;
                if (!check_payload(g_buf, len, f->sid)) { errors++; continue; }
                seq = r32(g_buf); generated = r32(g_buf + 4); latency = (uint32_t)s.t - generated;
                if ((f->rcv_any && seq <= f->rcv_last) || fi.frame_no != seq) errors++;
                f->rcv_any = 1; f->rcv_last = seq;
                p = &m[i][media_phase(generated)];
                if (p->received >= (uint32_t)(duration * 50 + 2)) return 1;
                p->lat[p->received++] = latency;
                if (latency <= rtt / 2.0 + f->budget_ms) p->ontime++;
                if (i == 1 && seq == 0) first_key_delay = (int)latency;
            }
        }
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) { errors++; break; }
        if (s.t == 2000 || s.t == 20000 || s.t == (uint64_t)duration * 1000) {
            anl_stream_stats a, v;
            anl_stream_get_stats(s.e[0].h[0], &a);
            anl_stream_get_stats(s.e[0].h[1], &v);
            ep_stats(&s.e[0], &cs);
            printf("POLICY_SAMPLE ms=%llu srtt=%u audio_ratio=%u video_ratio=%u wire_up=%llu wire_down=%llu\n",
                   (unsigned long long)s.t, cs.srtt, a.fec_ratio, v.fec_ratio,
                   (unsigned long long)(s.d[0].bytes + s.d[0].pkts * IPUDP_HDR),
                   (unsigned long long)(s.d[1].bytes + s.d[1].pkts * IPUDP_HDR));
        }
    }
    for (i = 0; i < 2; i++) {
        anl_stream_stats ss;
        anl_stream_get_stats(s.e[0].h[i], &ss);
        for (k = 0; k < 3; k++) {
            double p50, p95, p99, pmax;
            startup_phase *p = &m[i][k];
            percentiles(p->lat, p->received, &p50, &p95, &p99, &pmax);
            printf("FLOW id=%d phase=%d sent=%u received=%u missing=%u ontime=%u p99_extra=%.1f max_extra=%.1f\n",
                   i, k, p->sent, p->received, p->sent - p->received, p->ontime,
                   p99 - rtt / 2.0, pmax - rtt / 2.0);
            free(p->lat);
        }
        printf("SENDER id=%d abandoned=%u retrans=%u\n", i, ss.frames_dropped, ss.retrans);
    }
    ep_stats(&s.e[0], &cs);
    printf("TOTAL first_key_extra=%.1f retrans=%u queue_drop=%llu errors=%d wire_up=%llu wire_down=%llu\n",
           first_key_delay < 0 ? NAN : first_key_delay - rtt / 2.0, cs.rtx,
           (unsigned long long)s.d[0].lost_queue, errors,
           (unsigned long long)(s.d[0].bytes + s.d[0].pkts * IPUDP_HDR),
           (unsigned long long)(s.d[1].bytes + s.d[1].pkts * IPUDP_HDR));
    ep_release(&s.e[0]); ep_release(&s.e[1]); dir_free(&s.d[0]); dir_free(&s.d[1]);
    return errors != 0;
}
