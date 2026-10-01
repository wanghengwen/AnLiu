/* Deterministic high-loss media probe. Build (no separate anliu.c):
 * cc -std=gnu99 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
 *    -I. bench/media_loss.c bench/ikcp.c -lm -o /tmp/anl_media_loss
 * Args: bandwidth_kbps RTT_ms loss_percent seed duration_s [loss_stop_s=0]
 * Same frame_v1 workload / capped encoder feedback as realnet --adapt 1.
 * The link has 100 ms queue depth and independent loss in both directions.
 * Extra delay subtracts propagation (unlike realnet's measured minimum).
 */
#include "../anliu.h"
static void loss_data(const anl_t *, const anl_stream_t *, const void *, uint32_t, int);
static void loss_parity(const anl_t *, int, uint32_t);
#define ANL_DATA_SEG_TRACE(w, st, bytes, first) loss_data(w, st, seg, bytes, first)
#define ANL_PARITY_SEG_TRACE loss_parity
#include "../anliu.c"
#define main benchmark_main
#include "bench.c"
#undef main

static const anl_t *owner;
static uint64_t first_bytes[2], retry_bytes[2], parity_bytes[2];
static unsigned max_xmit[2][30001], latency_ms[2][30001], frame_bytes[2][30001];
static int scale = 1000;
static void loss_data(const anl_t *w, const anl_stream_t *st, const void *p, uint32_t bytes, int first)
{
    const anl_seg *seg = p;
    int id = st->tag;
    if (w != owner || id < 0 || id > 1) return;
    if (first) first_bytes[id] += bytes; else retry_bytes[id] += bytes;
    if (seg->frame_no < 30001 && max_xmit[id][seg->frame_no] < seg->xmit + 1)
        max_xmit[id][seg->frame_no] = seg->xmit + 1;
}
static void loss_parity(const anl_t *w, int sid, uint32_t bytes)
{
    if (w == owner && sget(w, sid)->tag <= 1) parity_bytes[sget(w, sid)->tag] += bytes;
}
static void loss_adapt(anl_t *w, uint32_t target, void *user)
{
    int64_t video = (int64_t)target - 8000;
    (void)w; (void)user;
    scale = video <= 0 ? 100 : (int)(video * 1000 / 117500);
    if (scale > 1000) scale = 1000;
    if (scale < 100) scale = 100;
}
static int loss_size(const flow *f, int key, uint64_t seed)
{
    int a = key ? f->key_min : f->size_min, b = key ? f->key_max : f->size_max;
    uint64_t x = seed + ((uint64_t)f->seq + 1) * 0x9e3779b97f4a7c15ull
        + (uint64_t)(f->sid + 1) * 0xd1b54a32d192ed03ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    x ^= x >> 31;
    a += (int)(x % (uint32_t)(b - a + 1));
    if (f->sid == 1) { a = a * scale / 1000; if (a < 200) a = 200; }
    return a;
}
int main(int argc, char **argv)
{
    sim s;
    flow f[2];
    linkcfg lc = {0};
    int bw = argc > 1 ? atoi(argv[1]) : 5000, rtt = argc > 2 ? atoi(argv[2]) : 100;
    int loss = argc > 3 ? atoi(argv[3]) : 20, seed = argc > 4 ? atoi(argv[4]) : 1;
    int duration = argc > 5 ? atoi(argv[5]) : 120, stop = argc > 6 ? atoi(argv[6]) : 0;
    uint64_t scale_sum = 0, gate_ms = 0, short_ms = 0;
    int i, k, errors = 0;
    if (bw < 1 || rtt < 1 || rtt > 10000 || loss < 0 || loss > 20 || seed < 1 ||
        duration < 3 || duration > 600 || stop < 0 || stop > duration) return 2;
    g_seed = seed; g_fec_ratio = 0; g_init_cwnd = 16;
    lc.delay = rtt / 2; lc.bw_kbps = bw; lc.loss = loss / 100.0; lc.qdelay = 100;
    sim_init(&s, &V_ANLF, &lc, 1000, g_seed);
    owner = s.e[0].anl;
    anl_set_rate_callback(s.e[0].anl, loss_adapt);
    flow_audio(&f[0], 0, &V_ANLF); flow_video(&f[1], 1, &V_ANLF);
    s.fl = f; s.nfl = 2;
    for (i = 0; i < 2; i++) { f[i].fec = ANL_FEC_RTT_AUTO; ep_open(&s.e[0], &f[i]); }
    printf("CONFIG bw=%d rtt=%d loss=%d seed=%d duration=%d stop=%d\n", bw, rtt, loss, seed, duration, stop);
    while (s.t < (uint64_t)duration * 1000 + 5000) {
        s.t++;
        if (stop && s.t == (uint64_t)stop * 1000) s.d[0].c.loss = s.d[1].c.loss = 0;
        for (k = 0; k < 2; k++) while (s.d[k].head && s.d[k].head->at <= s.t) {
            pkt *p = s.d[k].head;
            s.d[k].head = p->next;
            if (p->next) p->next->prev = NULL; else s.d[k].tail = NULL;
            ep_input(&s.e[1-k], p->data, p->len); free(p);
        }
        if (s.t < (uint64_t)duration * 1000) {
            scale_sum += scale; gate_ms += s.e[0].h[1]->fec_gate; short_ms += s.e[0].anl->capacity_short;
            for (i = 0; i < 2; i++) if (s.t >= f[i].next_t) {
                int key = i && f[i].seq % 30 == 0;
                int len = loss_size(&f[i], key, seed);
                frame_bytes[i][f[i].seq] = (unsigned)len;
                if (gen_one(&s, &f[i], len, key) < 0) errors++;
                f[i].next_t = i ? (uint64_t)f[i].seq * 1000 / 30 : (uint64_t)f[i].seq * 20;
            }
        }
        ep_update(&s.e[0], now32(&s)); ep_update(&s.e[1], now32(&s));
        for (i = 0; i < 2; i++) {
            anl_frame_info fi;
            int len;
            while ((len = ep_recv(&s.e[1], &f[i], g_buf, sizeof(g_buf), &fi)) >= 0) {
                uint32_t seq = r32(g_buf);
                if (!check_payload(g_buf, len, i) || seq >= 30001 || fi.frame_no != seq ||
                    (f[i].rcv_any && seq <= f[i].rcv_last)) { errors++; continue; }
                f[i].rcv_any = 1; f[i].rcv_last = seq;
                latency_ms[i][seq] = (uint32_t)s.t - r32(g_buf + 4) + 1;
            }
        }
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) { errors++; break; }
        if (getenv("MEDIA_LOSS_DIAG") && s.t % 200 == 0 && s.t <= (uint64_t)duration * 1000) {
            anl_t *w = s.e[0].anl;
            printf("BUDGET ms=%llu srtt=%d rmin=%u bw=%u pace=%u target=%u par_rate=%u tokens=%lld pay=%u delivered=%u offered=%u unsent=%u short=%d gate=%d audio_par=%llu video_par=%llu video_retry=%llu wire=%llu drops=%llu\n",
                (unsigned long long)s.t,w->rx_srtt,umin32(w->rate_rtt_min,w->rate_rtt_old),bbr_bw(w),w->pace_rate,
                w->rate_target,w->par_rate,(long long)w->par_tokens,w->pay_avg,w->dlv_avg,w->off_avg,w->unsent_avg,
                w->capacity_short,s.e[0].h[1]->fec_gate,(unsigned long long)parity_bytes[0],
                (unsigned long long)parity_bytes[1],(unsigned long long)retry_bytes[1],
                (unsigned long long)(s.d[0].bytes+s.d[0].pkts*IPUDP_HDR),(unsigned long long)s.d[0].lost_queue);
        }
        if (s.t % 10000 == 0 && s.t <= (uint64_t)duration * 1000) {
            anl_t *w = s.e[0].anl; anl_stream *v = s.e[0].h[1];
            printf("SAMPLE ms=%llu srtt=%d loss=%u gate=%d need=%u key_need=%u scale=%d short=%d parity_video=%llu\n",
                (unsigned long long)s.t, w->rx_srtt, w->fec_loss, v->fec_gate,
                fec_repair_ms(w, v, v->fec_frame_avg), fec_repair_ms(w, v, v->fec_key_bytes), scale,
                w->capacity_short, (unsigned long long)parity_bytes[1]);
        }
    }
    for (i = 0; i < 2; i++) {
        unsigned received = 0, ontime = 0, keys = 0, key_on = 0, repeated = 0, repeated_late = 0;
        uint64_t ontime_bytes = 0;
        for (k = 0; k < (int)f[i].seq; k++) {
            unsigned lat = latency_ms[i][k];
            int on = lat && lat - 1 <= (unsigned)(lc.delay + f[i].budget_ms);
            received += lat != 0; ontime += on;
            if (on) ontime_bytes += frame_bytes[i][k];
            if (i && k % 30 == 0) { keys++; key_on += on; }
            if (max_xmit[i][k] >= 3) { repeated++; repeated_late += !on; }
            if (getenv("MEDIA_LOSS_FRAMES")) printf("FRAME id=%d seq=%d latency=%d xmit=%u\n", i,k,lat ? (int)lat-1:-1,max_xmit[i][k]);
        }
        printf("FLOW id=%d sent=%u received=%u ontime=%u keys=%u key_ontime=%u repeated=%u repeated_late=%u first=%llu retry=%llu parity=%llu generated_bytes=%llu ontime_bytes=%llu\n",
            i,f[i].seq,received,ontime,keys,key_on,repeated,repeated_late,
            (unsigned long long)first_bytes[i],(unsigned long long)retry_bytes[i],(unsigned long long)parity_bytes[i],
            (unsigned long long)f[i].offered,(unsigned long long)ontime_bytes);
    }
    printf("TOTAL wire=%llu queue_drop=%llu scale=%.3f gate_ms=%llu short_ms=%llu errors=%d\n",
        (unsigned long long)(s.d[0].bytes + s.d[0].pkts * IPUDP_HDR), (unsigned long long)s.d[0].lost_queue,
        scale_sum / (duration * 1000.0), (unsigned long long)gate_ms, (unsigned long long)short_ms, errors);
    ep_release(&s.e[0]); ep_release(&s.e[1]); dir_free(&s.d[0]); dir_free(&s.d[1]);
    return errors != 0;
}
