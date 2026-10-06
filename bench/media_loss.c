/* Deterministic high-loss media probe. Build (no separate anliu.c):
 * cc -std=gnu99 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
 *    -I. bench/media_loss.c bench/ikcp.c -lm -o /tmp/anl_media_loss
 * Args: bandwidth_kbps RTT_ms loss_percent seed duration_s [loss_stop_s=0]
 *       [interval_ms=10] [event=none|pause|delay] [start_s=30]
 *       [event_duration_s=20] [extra_one_way_ms=200]
 * Same frame_v1 workload / capped encoder feedback as realnet --adapt 1;
 * MEDIA_LOSS_FIXED_SCALE=<100..1000> fixes the video at that per mille instead;
 * MEDIA_LOSS_VIDEO_MAX=<per mille> lets the encoder follow the target up to that
 * scale (default 1000, ~940 kbit/s of video; 8000 ~7.5 Mbit/s);
 * MEDIA_LOSS_AUDIO_ONLY=1 sends no video; MEDIA_LOSS_TBF_KB=<n> makes the
 * bottleneck a token-bucket shaper with an n KB bucket (tc tbf); MEDIA_LOSS_BURST=<n>
 * loses in Gilbert-Elliott bursts of mean length n (same average loss).
 * MEDIA_LOSS_RATE=gcc|gccd: the encoder follows a model of WebRTC's GCC
 * (bench/gcc_model.h; gccd without its loss-based part) instead of AnLiu's
 * target, and AnLiu's pace is capped at 2.5x the GCC target (WebRTC's pacer);
 * the transport, its window and FEC stay AnLiu's. Event "bw" sets
 * the bottleneck to extra_one_way_ms kbit/s for the event's duration.
 * The link has 100 ms queue depth and independent loss in both directions.
 * Timely media uses the original propagation delay as its minimum baseline;
 * an event's extra delay consumes that same delivery budget. A delivery pause
 * retains datagrams instead of adding random packet loss.
 * LAT: extra delay percentiles of the received frames and how many made the
 * budget + 100 ms. SIM_VIDEO_FEC_DEADLINE=<ms> sets the video fec_deadline_ms,
 * SIM_VIDEO_LATENCY_RTT=<N> its latency_rtt, SIM_VIDEO_LATENCY=<ms> the video
 * budget (max_age = budget + 200 ms).
 * RTX: retransmissions by trigger (RTO, RACK; _cov: the segment was covered by
 * a parity block) and how many reached a receiver that already had the data
 * (dup_*); FECCNT: what fed the adaptive ratio. MEDIA_LOSS_RTX=1 traces each.
 */
#include "../anliu.h"
static void loss_data(const anl_t *, const anl_stream_t *, const void *, uint32_t, int);
static void loss_parity(const anl_t *, int, uint32_t);
static void loss_commit(const anl_t *, uint32_t, int);
static void loss_trim(const anl_t *, uint32_t);
static void loss_block(const anl_t *, const anl_stream_t *, uint32_t, uint32_t, uint32_t, int);
#define ANL_DATA_SEG_TRACE(w, st, bytes, first) loss_data(w, st, seg, bytes, first)
#define ANL_PARITY_SEG_TRACE loss_parity
#define ANL_SEG_COMMIT_TRACE loss_commit
#define ANL_SEG_TRIM_TRACE loss_trim
#define ANL_FEC_BLOCK_TRACE(w, st, k, m) loss_block(w, st, k, m, lmax, key)
static void loss_rtx(const anl_t *, const anl_stream_t *, const void *, int);
static void loss_dup(const anl_t *, const anl_stream_t *, uint32_t);
#define ANL_RTX_TRACE(w, st, seg, why) loss_rtx(w, st, seg, why)
#define ANL_DUP_TRACE(w, st, sn) loss_dup(w, st, sn)
static unsigned fec_counts[2][4];
#define ANL_FEC_COUNT_TRACE(w, st, lost) do { if ((st)->tag <= 1 && (lost) >= 0 && (lost) < 4) fec_counts[(st)->tag][lost]++; } while (0)
#include "../anliu.c"
#include "gcc_model.h"
static gcc_t g_gcc;
#define SIM_SEND_HOOK(s, from, len, at, lost) do { if ((from) == 0) gcc_on_packet(&g_gcc, (double)(s)->t, (at), (len) + IPUDP_HDR, (lost)); } while (0)
#define main benchmark_main
#include "bench.c"
#undef main

static const anl_t *owner;
static uint64_t first_bytes[2], retry_bytes[2], parity_bytes[2];
static uint64_t *last_cost;
static void loss_commit(const anl_t *w, uint32_t bytes, int data)
{
    (void)bytes; (void)data;
    if (w == owner) last_cost = NULL;
}
static void loss_trim(const anl_t *w, uint32_t bytes)
{
    if (w == owner && last_cost) *last_cost -= bytes;
}
static unsigned max_xmit[2][30001], latency_ms[2][30001], frame_bytes[2][30001];
static unsigned sent_ms[2][30001], received_ms[2][30001];
static unsigned blocks[2], small_blocks[2];
static uint64_t block_data[2], block_parities[2];
static int scale = 1000;
static int audio_only;      /* MEDIA_LOSS_AUDIO_ONLY: no video frames */
/* MEDIA_LOSS_DRIVE=check: anl_update driven by anl_check (at most
   MEDIA_LOSS_DRIVE_MAX ms apart, default 10) and before every input / send
   whose millisecond differs, like an event loop - instead of every ms */
static int drive_check, drive_max = 10;
/* MEDIA_LOSS_ORDER=legacy: each ms input, frames, then anl_update (as
   before); default: anl_update first, then input and frames - what an
   application's loop does (realnet: poll, update, receive, generate) */
static int order_legacy;
static uint32_t drv_last[2], drv_next[2];
static unsigned long long drv_updates[2];
static void drv_update(sim *s, int k, uint32_t t)
{
    anl_t *w = s->e[k].anl;
    anl_update(w, t);
    drv_last[k] = t;
    drv_updates[k]++;
}
static void drv_rearm(sim *s, int k, uint32_t t)
{
    uint32_t n = anl_check(s->e[k].anl, t);
    if ((int32_t)(n - (t + (uint32_t)drive_max)) > 0) n = t + (uint32_t)drive_max;
    drv_next[k] = n;
}
static void drv_touch(sim *s, int k, uint32_t t)
{
    if (drive_check && drv_last[k] != t) drv_update(s, k, t);
}
static int fixed_scale;     /* MEDIA_LOSS_FIXED_SCALE: video at this per mille, encoder feedback off */
static int scale_max = 1000;    /* MEDIA_LOSS_VIDEO_MAX */
static void loss_block(const anl_t *w, const anl_stream_t *st, uint32_t k, uint32_t m, uint32_t lmax, int key)
{
    int id = st->tag;
    if (w != owner || id < 0 || id > 1) return;
    blocks[id]++; block_data[id] += k; block_parities[id] += m;
    small_blocks[id] += k * lmax <= FEC_SMALL_BLOCK;
    if (getenv("MEDIA_LOSS_BLOCKS"))
        printf("BLOCK ms=%u id=%d k=%u m=%u lmax=%u key=%d frame_avg=%u\n", w->current, id, k, m, lmax, key, st->fec_frame_avg);
}
static unsigned rtx_why[2][4], rtx_cov[2][4], dup_rx[2], dup_why[2][4];
static unsigned char last_why[2][65536];
static void loss_rtx(const anl_t *w, const anl_stream_t *st, const void *p, int why)
{
    const anl_seg *seg = p;
    int id = st->tag;
    if (w != owner || id < 0 || id > 1 || why < 0 || why > 3) return;
    rtx_why[id][why]++;
    last_why[id][seg->sn & 65535] = (unsigned char)why;
    if (getenv("MEDIA_LOSS_RTX")) printf("RTXEV ms=%u id=%d why=%d sn=%u xmit=%u sent=%u age=%d rto=%u srtt=%d var=%d fec_ts=%u resend=%u\n", w->current, id, why, seg->sn, seg->xmit, seg->ts_sent, (int)(w->current-seg->ts_sent), seg->rto, w->rx_srtt, w->rx_rttval, seg->fec_ts, seg->resendts);
    if (seg->fec_ts) rtx_cov[id][why]++;
}
static void loss_dup(const anl_t *w, const anl_stream_t *st, uint32_t sn)
{
    int id = st->tag;
    if (w == owner || id < 0 || id > 1) return;
    dup_rx[id]++;
    dup_why[id][last_why[id][sn & 65535] & 3]++;
    if (getenv("MEDIA_LOSS_RTX")) printf("DUPEV ms=%u id=%d sn=%u why=%d\n", w->current, id, sn, last_why[id][sn & 65535]);
}
static void loss_data(const anl_t *w, const anl_stream_t *st, const void *p, uint32_t bytes, int first)
{
    const anl_seg *seg = p;
    int id = st->tag;
    if (w != owner || id < 0 || id > 1) return;
    if (first) first_bytes[id] += bytes; else retry_bytes[id] += bytes;
    last_cost = first ? &first_bytes[id] : &retry_bytes[id];
    if (seg->frame_no < 30001 && max_xmit[id][seg->frame_no] < seg->xmit + 1)
        max_xmit[id][seg->frame_no] = seg->xmit + 1;
}
static void loss_parity(const anl_t *w, int sid, uint32_t bytes)
{
    if (w == owner && sget(w, sid)->tag <= 1) {
        last_cost = &parity_bytes[sget(w, sid)->tag];
        *last_cost += bytes;
    }
}
static void loss_adapt(anl_t *w, uint32_t target, void *user)
{
    int64_t video = (int64_t)target - 8000;
    (void)w; (void)user;
    if (fixed_scale || g_gcc.on) return;
    scale = video <= 0 ? 100 : (int)(video * 1000 / 117500);
    if (scale > scale_max) scale = scale_max;
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
    int interval = argc > 7 ? atoi(argv[7]) : 10;
    const char *event = argc > 8 ? argv[8] : "none";
    int event_start = argc > 9 ? atoi(argv[9]) : 30;
    int event_duration = argc > 10 ? atoi(argv[10]) : 20;
    int event_delay = argc > 11 ? atoi(argv[11]) : 200;
    int event_on, event_end = event_start + event_duration;
    uint64_t scale_sum = 0, gate_ms = 0, short_ms = 0;
    int i, k, errors = 0;
    if (bw < 1 || rtt < 1 || rtt > 10000 || loss < 0 || loss > 20 || seed < 1 ||
        duration < 3 || duration > 600 || stop < 0 || stop > duration ||
        (interval != 10 && interval != 20) ||
        (strcmp(event, "none") && strcmp(event, "pause") && strcmp(event, "delay") && strcmp(event, "bw")) ||
        event_start < 0 || event_duration < 1 || event_delay < 0 || event_delay > 10000 ||
        (strcmp(event, "none") && event_end >= duration)) return 2;
    g_seed = seed; g_fec_ratio = 0; g_init_cwnd = 16;
    if (getenv("MEDIA_LOSS_TBF_KB")) g_tbf_kb = atoi(getenv("MEDIA_LOSS_TBF_KB"));
    g_fast = interval == 10;
    lc.delay = rtt / 2; lc.bw_kbps = bw; lc.loss = loss / 100.0; lc.qdelay = 100;
    if (getenv("MEDIA_LOSS_BURST")) lc.burst = atof(getenv("MEDIA_LOSS_BURST"));
    sim_init(&s, &V_ANLF, &lc, 1000, g_seed);
    owner = s.e[0].anl;
    if (getenv("MEDIA_LOSS_FIXED_SCALE")) {
        fixed_scale = atoi(getenv("MEDIA_LOSS_FIXED_SCALE"));
        if (fixed_scale < 100 || fixed_scale > 1000) return 2;
        scale = fixed_scale;
    }
    audio_only = getenv("MEDIA_LOSS_AUDIO_ONLY") != NULL;
    if (getenv("MEDIA_LOSS_VIDEO_MAX")) {
        scale_max = atoi(getenv("MEDIA_LOSS_VIDEO_MAX"));
        if (scale_max < 1000 || scale_max > 20000) return 2;
    }
    drive_check = getenv("MEDIA_LOSS_DRIVE") && !strcmp(getenv("MEDIA_LOSS_DRIVE"), "check");
    order_legacy = getenv("MEDIA_LOSS_ORDER") && !strcmp(getenv("MEDIA_LOSS_ORDER"), "legacy");
    if (getenv("MEDIA_LOSS_DRIVE_MAX")) drive_max = atoi(getenv("MEDIA_LOSS_DRIVE_MAX"));
    anl_set_rate_callback(s.e[0].anl, loss_adapt);
    if (getenv("MEDIA_LOSS_RATE") && strcmp(getenv("MEDIA_LOSS_RATE"), "anl")) {
        const char *m = getenv("MEDIA_LOSS_RATE");
        if (strcmp(m, "gcc") && strcmp(m, "gccd")) return 2;
        /* the encoder's maximum with audio, over a payload share of 2/3 */
        gcc_init(&g_gcc, !strcmp(m, "gcc"), ((double)scale_max * 117500 / 1000 + 8000) * 8 * 1.5);
        if (!fixed_scale) scale = 100 + 0 * scale;      /* GCC starts at 300 kbit/s: the encoder too */
    }
    flow_audio(&f[0], 0, &V_ANLF); flow_video(&f[1], 1, &V_ANLF);
    s.fl = f; s.nfl = 2;
    /* MEDIA_LOSS_FEC_OFF=1: both flows without FEC (retransmission only) */
    for (i = 0; i < 2; i++) { f[i].fec = getenv("MEDIA_LOSS_FEC_OFF") ? 0 : ANL_FEC_RTT_AUTO; ep_open(&s.e[0], &f[i]); }
    printf("CONFIG bw=%d rtt=%d loss=%d seed=%d duration=%d stop=%d interval=%u event=%s event_start=%d event_duration=%d event_delay=%d\n", bw, rtt, loss, seed, duration, stop, s.e[0].anl->interval, event, event_start, event_duration, event_delay);
    while (s.t < (uint64_t)duration * 1000 + 5000) {
        s.t++;
        event_on = s.t >= (uint64_t)event_start * 1000 && s.t < (uint64_t)event_end * 1000;
        if (!drive_check && !order_legacy) {
            ep_update(&s.e[0], now32(&s)); ep_update(&s.e[1], now32(&s));
            drv_updates[0]++; drv_updates[1]++;
        }
        s.d[0].c.delay = s.d[1].c.delay = lc.delay + (event_on && !strcmp(event, "delay") ? event_delay : 0);
        if (!strcmp(event, "bw")) s.d[0].c.bw_kbps = event_on ? event_delay : bw;
        if (g_gcc.on) {
            anl_t *w = s.e[0].anl;
            double rtt = w->rx_srtt > 0 ? w->rx_srtt : 2.0 * s.d[0].c.delay;
            gcc_tick(&g_gcc, (double)s.t, (double)s.d[0].c.delay, rtt, (double)s.d[0].c.bw_kbps, lc.loss);
            /* WebRTC's pacer: 2.5 x the target (pacing_factor), a cap on AnLiu's own pace */
            w->pace_rate_cfg = (uint32_t)(g_gcc.target / 8 * 2.5);
            if (!fixed_scale && s.t % 10 == 0) {
                /* the target is for everything sent: the encoder gets the payload share */
                int64_t video = (int64_t)(g_gcc.target / 8 * (w->rate_share ? w->rate_share : 230) / 256) - 8000;
                scale = video <= 0 ? 100 : (int)(video * 1000 / 117500);
                if (scale > scale_max) scale = scale_max;
                if (scale < 100) scale = 100;
            }
        }
        if (stop && s.t == (uint64_t)stop * 1000) s.d[0].c.loss = s.d[1].c.loss = 0;
        for (k = 0; k < 2; k++) while (!(event_on && !strcmp(event, "pause")) && s.d[k].head && s.d[k].head->at <= s.t) {
            pkt *p = s.d[k].head;
            s.d[k].head = p->next;
            if (p->next) p->next->prev = NULL; else s.d[k].tail = NULL;
            drv_touch(&s, 1 - k, now32(&s));
            ep_input(&s.e[1-k], p->data, p->len); free(p);
            if (drive_check) drv_rearm(&s, 1 - k, now32(&s));
        }
        if (s.t < (uint64_t)duration * 1000) {
            scale_sum += scale; gate_ms += s.e[0].h[1]->fec_gate; short_ms += s.e[0].anl->capacity_short;
            for (i = 0; i < 2; i++) if (s.t >= f[i].next_t && !(i == 1 && audio_only)) {
                int key = i && f[i].seq % 30 == 0;
                int len = loss_size(&f[i], key, seed);
                frame_bytes[i][f[i].seq] = (unsigned)len;
                sent_ms[i][f[i].seq] = (unsigned)s.t;
                drv_touch(&s, 0, now32(&s));
                if (gen_one(&s, &f[i], len, key) < 0) errors++;
                if (drive_check) drv_rearm(&s, 0, now32(&s));
                f[i].next_t = i ? (uint64_t)f[i].seq * 1000 / 30 : (uint64_t)f[i].seq * 20;
            }
        }
        if (!drive_check) {
            if (order_legacy) {
                ep_update(&s.e[0], now32(&s)); ep_update(&s.e[1], now32(&s));
                drv_updates[0]++; drv_updates[1]++;
            }
        } else for (k = 0; k < 2; k++) if ((int32_t)(now32(&s) - drv_next[k]) >= 0) {
            drv_update(&s, k, now32(&s));
            drv_rearm(&s, k, now32(&s));
        }
        for (i = 0; i < 2; i++) {
            anl_frame_info fi;
            int len;
            while ((len = ep_recv(&s.e[1], &f[i], g_buf, sizeof(g_buf), &fi)) >= 0) {
                uint32_t seq = r32(g_buf);
                if (!check_payload(g_buf, len, i) || seq >= 30001 || fi.frame_no != seq ||
                    (f[i].rcv_any && seq <= f[i].rcv_last)) { errors++; continue; }
                f[i].rcv_any = 1; f[i].rcv_last = seq;
                latency_ms[i][seq] = (uint32_t)s.t - r32(g_buf + 4) + 1;
                received_ms[i][seq] = (unsigned)s.t;
            }
        }
        if (!ep_alive(&s.e[0]) || !ep_alive(&s.e[1])) { errors++; break; }
        if (getenv("MEDIA_LOSS_DIAG") && s.t % 200 == 0 && s.t <= (uint64_t)duration * 1000) {
            anl_t *w = s.e[0].anl;
            printf("ENC ms=%llu scale=%d gcc_target=%.0f gcc_delay=%.0f gcc_loss=%.0f trend=%.2f thr=%.2f usage=%d\n",
                (unsigned long long)s.t, scale, g_gcc.target, g_gcc.delay_rate, g_gcc.loss_rate, g_gcc.trend, g_gcc.thr, g_gcc.usage);
            printf("BUDGET ms=%llu srtt=%d rmin=%u bw=%u pace=%u target=%u par_rate=%u tokens=%lld pay=%u delivered=%u offered=%u unsent=%u short=%d gate=%d audio_par=%llu video_par=%llu video_retry=%llu wire=%llu drops=%llu\n",
                (unsigned long long)s.t,w->rx_srtt,umin32(w->rate_rtt_min,w->rate_rtt_old),bbr_bw(w),w->pace_rate,
                w->rate_target,w->par_rate,(long long)w->par_tokens,w->pay_avg,w->dlv_avg,w->off_avg,w->unsent_avg,
                w->capacity_short,s.e[0].h[1]->fec_gate,(unsigned long long)parity_bytes[0],
                (unsigned long long)parity_bytes[1],(unsigned long long)retry_bytes[1],
                (unsigned long long)(s.d[0].bytes+s.d[0].pkts*IPUDP_HDR),(unsigned long long)s.d[0].lost_queue);
            printf("STATE ms=%llu rto=%d cwnd=%u inflight_bytes=%llu pace_tokens=%lld cs_test=%u cs_recover=%u audio_queued=%u video_queued=%u audio_pending=%u video_pending=%u\n",
                (unsigned long long)s.t,w->rx_rto,w->cwnd,(unsigned long long)bbr_inflight_bytes(w),(long long)w->pace_tokens,
                w->cs_test_ts,w->cs_recover,s.e[0].h[0]->nsnd_que,s.e[0].h[1]->nsnd_que,
                s.e[0].h[0]->nsnd_buf,s.e[0].h[1]->nsnd_buf);
            printf("POLICER ms=%llu state=%d rate=%u from=%u hold=%u rounds=%u k=%u\n",
                (unsigned long long)s.t,w->lt_state,w->lt_rate,w->lt_from,w->lt_hold,w->lt_rounds,w->lt_k);
            {
                const anl_stream *a = s.e[0].h[0], *b = s.e[1].h[0];
                printf("AUDIOSTATE ms=%llu remote_wnd=%u fwd_pending=%d fwd_ts=%u fwd_rto=%u peer_open=%d recv_nxt=%u recv_buf=%u recv_queue=%u block_since=%u gate=%d\n",
                    (unsigned long long)s.t,a->rmt_wnd,a->fwd_pending,a->fwd_ts,a->fwd_rto,b!=NULL,
                    b?b->rcv_nxt:0,b?b->nrcv_buf:0,b?b->nrcv_que:0,b?b->block_since:0,a->fec_gate);
            }
        }
        if (s.t % 10000 == 0 && s.t <= (uint64_t)duration * 1000) {
            anl_t *w = s.e[0].anl; anl_stream *v = s.e[0].h[1];
            printf("SAMPLE ms=%llu ratio=%d/%d srtt=%d loss=%u gate=%d need=%u key_need=%u scale=%d short=%d parity_video=%llu\n",
                (unsigned long long)s.t, s.e[0].h[0]->fec_ratio, v->fec_ratio, w->rx_srtt, w->fec_loss, v->fec_gate,
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
        {
            /* LAT: extra delay of the received frames (over the propagation
               delay) - percentiles and on time at a budget 100 ms looser */
            static unsigned ex[65536];
            unsigned n = 0, on_loose = 0, j, t;
            for (k = 0; k < (int)f[i].seq && n < 65536; k++) {
                unsigned lat = latency_ms[i][k];
                if (!lat) continue;
                ex[n++] = lat - 1 > (unsigned)lc.delay ? lat - 1 - (unsigned)lc.delay : 0;
                on_loose += lat - 1 <= (unsigned)(lc.delay + f[i].budget_ms + 100);
            }
            for (j = 1; j < n; j++) for (t = j; t > 0 && ex[t - 1] > ex[t]; t--) { unsigned x = ex[t]; ex[t] = ex[t - 1]; ex[t - 1] = x; }
            printf("LAT id=%d p50=%u p95=%u p99=%u ontime_loose=%u\n", i, n ? ex[n / 2] : 0, n ? ex[n * 95 / 100] : 0, n ? ex[n * 99 / 100] : 0, on_loose);
        }
        printf("FECCNT id=%d sent=%u lost=%u late=%u slow=%u\n", i, fec_counts[i][0], fec_counts[i][1], fec_counts[i][2], fec_counts[i][3]);
        printf("RTX id=%d rto=%u rto_cov=%u rack=%u rack_cov=%u dup_rx=%u dup_rto=%u dup_rack=%u\n", i, rtx_why[i][2], rtx_cov[i][2], rtx_why[i][3], rtx_cov[i][3], dup_rx[i], dup_why[i][2], dup_why[i][3]);
        printf("BLOCKSUM id=%d blocks=%u small_blocks=%u data=%llu parities=%llu\n", i,blocks[i],small_blocks[i],(unsigned long long)block_data[i],(unsigned long long)block_parities[i]);
        if (strcmp(event, "none") || getenv("MEDIA_LOSS_WINDOWS")) {
            unsigned first_received = 0, first_ontime = 0, first_key = 0;
            unsigned window_sent[600] = {0}, window_on[600] = {0}, window_keys[600] = {0};
            uint64_t window_bytes[600] = {0};
            for (k = 0; k < (int)f[i].seq; k++) {
                unsigned sec = sent_ms[i][k] / 1000, lat = latency_ms[i][k];
                int on = lat && lat - 1 <= (unsigned)(lc.delay + f[i].budget_ms);
                if (sec >= (unsigned)duration) { errors++; continue; }
                window_sent[sec]++; window_on[sec] += on;
                if (on) window_bytes[sec] += frame_bytes[i][k];
                if (i && k % 30 == 0) window_keys[sec] += on;
                /* Only new frames generated after the event count as recovery. */
                if (sent_ms[i][k] >= (unsigned)event_end * 1000 && lat) {
                    if (!first_received || received_ms[i][k] < first_received) first_received = received_ms[i][k];
                    if (on && (!first_ontime || received_ms[i][k] < first_ontime)) first_ontime = received_ms[i][k];
                    if (on && i && k % 30 == 0 && (!first_key || received_ms[i][k] < first_key)) first_key = received_ms[i][k];
                }
            }
            for (k = 0; k < duration; k++)
                printf("WINDOW id=%d sec=%d sent=%u ontime=%u ontime_bytes=%llu key_ontime=%u\n", i,k,window_sent[k],window_on[k],(unsigned long long)window_bytes[k],window_keys[k]);
            if (strcmp(event, "none"))
                printf("RECOVERY id=%d received_ms=%d ontime_ms=%d key_ms=%d\n", i,first_received ? (int)first_received-event_end*1000:-1,first_ontime ? (int)first_ontime-event_end*1000:-1,first_key ? (int)first_key-event_end*1000:-1);
        }
    }
    if (g_gcc.on) printf("GCCSUM overuses=%u decreases=%u\n", g_gcc.overuses, g_gcc.decreases);
    printf("DRIVE mode=%s updates_sender=%llu updates_receiver=%llu\n", drive_check ? "check" : order_legacy ? "1ms-legacy" : "1ms", drv_updates[0], drv_updates[1]);
    printf("TOTAL wire=%llu queue_drop=%llu scale=%.3f gate_ms=%llu short_ms=%llu errors=%d pkts=%llu rev_wire=%llu rev_pkts=%llu\n",
        (unsigned long long)(s.d[0].bytes + s.d[0].pkts * IPUDP_HDR), (unsigned long long)s.d[0].lost_queue,
        scale_sum / (duration * 1000.0), (unsigned long long)gate_ms, (unsigned long long)short_ms, errors,
        (unsigned long long)s.d[0].pkts, (unsigned long long)(s.d[1].bytes + s.d[1].pkts * IPUDP_HDR), (unsigned long long)s.d[1].pkts);
    ep_release(&s.e[0]); ep_release(&s.e[1]); dir_free(&s.d[0]); dir_free(&s.d[1]);
    return errors != 0;
}
