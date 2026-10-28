/* target rate, delay report, outage, scheduler, review tests. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

/* The same traffic must give the same recommendation on either side of the
 * wrapping wire counter. Payload and delivery totals are 64-bit counters. */
static void test_target_rate_wrap(void)
{
    anl_t plain, wrapped;
    uint32_t targets[2];
    int i;
    memset(&plain, 0, sizeof(plain));
    plain.mss = 1200;
    plain.current = 1000;
    plain.rate.ts = 800;
    plain.rate.share = 230;
    plain.btl_bw = 250000;
    plain.rx_srtt = 100;
    plain.sent_wire = 100000;
    plain.rate.wire0 = plain.sent_wire;
    plain.rate_cb = rate_cb;
    wrapped = plain;
    wrapped.sent_wire = UINT32_MAX - 29999;
    wrapped.rate.wire0 = wrapped.sent_wire;
    g_rate_calls = 0;
    for (i = 0; i < 3; i++) {
        plain.current += 200;
        wrapped.current += 200;
        plain.sent_wire += 60000;
        wrapped.sent_wire += 60000;
        plain.tx_payload += 40000;
        wrapped.tx_payload += 40000;
        /* Exercise feedback with acknowledged payload as well as sent bytes. */
        plain.rate.delivered_pay += 40000;
        wrapped.rate.delivered_pay += 40000;
        rate_update(&plain);
        targets[0] = g_rate;
        rate_update(&wrapped);
        targets[1] = g_rate;
        CHECK(plain.rate.share == wrapped.rate.share,
              "wire counter wrap preserves payload share (%u / %u)", plain.rate.share, wrapped.rate.share);
        CHECK(plain.rate.target == wrapped.rate.target && targets[0] == targets[1],
              "wire counter wrap preserves rate and callback (%u / %u)", plain.rate.target, wrapped.rate.target);
    }
    CHECK(g_rate_calls >= 2, "rate callbacks exercised across wire counter wrap");
}

/* A queued key-frame burst can be acknowledged unevenly across adjacent
   rate steps. Draining it must not undo a congestion cut in one ACK batch. */
static void test_target_rate_queued_ack_burst(void)
{
    anl_t w;
    uint32_t cut, rebound;
    memset(&w, 0, sizeof(w));
    w.mss = 1200;
    w.current = 1000; w.rate.ts = 800;
    w.rate.share = 256;
    w.btl_bw = 250000;
    w.rx_srtt = 360;
    w.rate.rtt_ts = 800; w.rate.rtt_min = w.rate.rtt_old = 180;
    w.rate.target = 100000;
    w.sent_wire = 10000; w.tx_payload = 10000; w.delivered = 10000;
    rate_update(&w);
    cut = w.rate.target;
    CHECK(cut <= 50000, "queued low delivery cuts promptly (%u)", cut);

    /* The next ACK batch covers four times as much payload, but the RTT
       still contains the same queue. This is not four times the capacity. */
    w.current += 200;
    w.sent_wire += 40000; w.tx_payload += 40000; w.delivered += 40000;
    rate_update(&w);
    rebound = w.rate.target;
    CHECK(rebound <= cut + cut / 20,
          "queued ACK burst cannot bypass the 25%%/s rise limit (%u -> %u)", cut, rebound);

    w.current += 200;
    w.sent_wire += 4000; w.tx_payload += 4000; w.delivered += 4000;
    rate_update(&w);
    CHECK(w.rate.target < rebound / 2,
          "upward smoothing does not delay a further delivery cut (%u -> %u)", rebound, w.rate.target);

    /* Sustained delivery loss has a separate ceiling based on several
       steps. A single sparse ACK step must not lock the encoder far below
       that already conservative ceiling while the queue drains. */
    w.current += 200;
    w.rate.steps = 5;
    w.rate.target = 20000;
    w.rate.pay_avg_prev = w.rate.pay_avg = 160000;
    w.rate.dlv_avg = 80000;
    ST_SET(w.rate.f, CS_F_LOSS);
    w.sent_wire += 40000; w.tx_payload += 40000;
    w.delivered += 40000; w.rate.delivered_pay += 40000;
    rate_update(&w);
    CHECK(w.rate.target > 21000 && w.rate.target <= 72000,
          "queued ACK catch-up recovers within the sustained delivery ceiling (%u)", w.rate.target);
}

static void test_target_rate_reports(void)
{
    anl_t w;
    memset(&w, 0, sizeof(w));
    w.rate.share = 256;
    w.rx_srtt = 100;
    w.current = w.prx_at = 1000;
    ST_SET(w.in_f, IN_F_PRX); w.prx_ms = 1000; w.prx_bytes = 100000;
    CHECK(rate_report_pay(&w) == 0, "first report only establishes a snapshot");
    w.current = w.prx_at = 1100; w.prx_ms += 100; w.prx_bytes += 10000;
    w.sent_wire += 10000;
    CHECK(rate_report_pay(&w) == 0, "short reports accumulate for a full control step");
    w.current = w.prx_at = 1200; w.prx_ms += 100; w.prx_bytes += 10000;
    w.sent_wire += 10000;
    CHECK(rate_report_pay(&w) == 100000, "arrival rate uses the peer's elapsed time");
    w.current = 1300;
    CHECK(rate_report_pay(&w) == 100000, "a fresh sample spans the gap between reports");
    w.current = 1401;
    CHECK(rate_report_pay(&w) == 0, "a missing report cannot keep a stale rate alive");
    w.current = w.prx_at = 1600; w.prx_ms += 1000; w.prx_bytes += 900000;
    CHECK(rate_report_pay(&w) == 0, "resuming reports first discards the old interval");
    w.current = w.prx_at = 1800; w.prx_ms += 1000; w.prx_bytes += 900000;
    CHECK(rate_report_pay(&w) == 0, "compressed reports do not invent capacity");
    w.current = w.prx_at = 4000;
    CHECK(rate_report_pay(&w) == 0, "an idle interval establishes a new snapshot");
    w.current = w.prx_at = 4200; w.prx_ms += 200; w.prx_bytes += 10000;
    w.sent_wire += 10000;
    CHECK(rate_report_pay(&w) == 50000, "ordinary reports recover after the idle interval");
    w.current = w.prx_at = 4400; w.prx_ms += 200; w.prx_bytes += 10000;
    w.sent_wire += 1000;
    CHECK(rate_report_pay(&w) == 0, "backlog far above recent sending is rejected, not clamped to a false low rate");
    w.current = w.prx_at = 4600; w.prx_ms += 200; w.prx_bytes += 10000;
    w.sent_wire += 10000;
    CHECK(rate_report_pay(&w) == 50000, "a rejected sample does not poison the next interval");

    memset(&w, 0, sizeof(w));
    w.rate.share = 256; w.rx_srtt = 100;
    w.current = w.prx_at = UINT32_MAX - 99;
    ST_SET(w.in_f, IN_F_PRX); w.prx_ms = 1000; w.prx_bytes = 100000;
    w.sent_wire = UINT32_MAX - 9999;
    CHECK(rate_report_pay(&w) == 0, "snapshot before local clock wrap");
    w.current += 200; w.prx_at = w.current; w.prx_ms += 200; w.prx_bytes += 20000;
    w.sent_wire += 20000;
    CHECK(rate_report_pay(&w) == 100000, "arrival sampling survives local clock and sent-byte counter wrap");

    /* A slower path still delivers 100 kB/s, even when old frames expire
       before their ACKs arrive. */
    memset(&w, 0, sizeof(w));
    w.mss = 1200; w.rate.share = 256; w.btl_bw = 375000;
    w.rx_srtt = 360; w.rate.rtt_min = w.rate.rtt_old = 100;
    w.current = w.prx_at = w.rate.ts = w.rate.rtt_ts = 800;
    ST_SET(w.in_f, IN_F_PRX); w.prx_ms = 1000; w.prx_bytes = 100000;
    w.rate.target = 300000; w.rate.delivered_pay = 60000;
    w.rate.steps = 5; w.rate.dlv_avg = w.rate.pay_avg = w.rate.pay_avg_prev = 300000;
    (void)rate_report_pay(&w);
    w.current = w.prx_at = 1000; w.prx_ms += 200; w.prx_bytes += 20000;
    w.sent_wire = 60000; w.tx_payload = 60000; w.delivered = 60000;
    rate_update(&w);
    CHECK(w.rate.target == 270000, "arrival alone cannot replace feedback while the model is still stale (%u)", w.rate.target);
    w.current = w.prx_at = 1200; w.prx_ms += 200; w.prx_bytes += 20000;
    w.sent_wire += 20000; w.tx_payload += 20000;
    w.btl_bw = 125000;
    ST_SET(w.rate.f, CS_F_SHORT | CS_F_LOSS);
    w.rate.dlv_avg = 1000;
    rate_update(&w);
    CHECK(w.rate.target == 90000, "expired ACKs do not hide a draining queue (%u)", w.rate.target);
    w.current = w.prx_at = 1400; w.prx_ms += 200; w.prx_bytes += 20000;
    w.sent_wire += 20000; w.tx_payload += 20000;
    w.rx_srtt = 100; w.rate.dlv_avg = 20000;
    rate_update(&w);
    CHECK(w.rate.target == 48000, "without a queue the ACK ceiling and minimum window still apply (%u)", w.rate.target);
}

static void test_target_rate(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stats st;
    static char buf[200000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    uint32_t hi = 0, lo = 0, frames = 0;
    uint64_t tail_sum = 0, drop_sum = 0;
    int i, tail_n = 0, drop_n = 0;
    printf("[target_rate: an encoder follows it, 3 Mbps link, rtt 40 ms; 1 Mbps after 30 s]\n");
    net_init(&n, &ca, &cb);
    n.bandwidth_bps = 3000000;
    n.queue_limit = 60;
    net_start(&n, &ca, &cb);
    anl_set_rate_callback(n.ep[0], rate_cb);
    g_rate = 0; g_rate_calls = 0;
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 40000; i++) {
        uint32_t rate = g_rate ? g_rate : 60000;            /* bytes/s; 480 kbps before the first value */
        net_tick(&n);
        if (i % 33 == 0) {
            int len = (int)umin32(rate / 30, sizeof(buf));
            fill_pattern(buf, len, frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, len, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) ;
        if (i == 30000) { hi = g_rate; n.bandwidth_bps = 1000000; }
        if (i >= 32000 && i < 34000 && i % 100 == 0) { drop_sum += g_rate; drop_n++; }
        if (i >= 35000 && i % 100 == 0) { tail_sum += g_rate; tail_n++; }
    }
    lo = (uint32_t)(drop_sum / (uint64_t)drop_n);
    anl_get_stats(n.ep[0], &st);
    printf("  target after 30 s: %u B/s (link 375000), 2..4 s after the drop: %u B/s (link 125000), last 5 s %u on average; %d callbacks\n",
           hi, lo, (uint32_t)(tail_sum / (uint64_t)tail_n), g_rate_calls);
    CHECK(hi >= 375000 * 3 / 10 && hi <= 375000 * 11 / 10, "ramped up towards the link (%u)", hi);  /* the estimate varies by a few % */
    CHECK(lo <= 125000, "followed the drop within 2..4 s (%u)", lo);
    CHECK(tail_sum / (uint64_t)tail_n >= 125000 / 2 && tail_sum / (uint64_t)tail_n <= 125000, "settled below the new link (%u)",
          (uint32_t)(tail_sum / (uint64_t)tail_n));
    CHECK(st.target_rate > 0, "target_rate in the stats (%u)", st.target_rate);
    CHECK(g_rate_calls > 2, "callbacks (%d)", g_rate_calls);
    net_stop(&n);
}

/* Full-suite RNG states that exposed the post-drop feedback collapse.
   Preserve the caller's sequence so this regression does not change the
   random network of unrelated tests. The same end-to-end bounds apply. */
static void test_target_rate_drop_replay(void)
{
    static const uint64_t states[] = {
        0x12b4ba65884038a4ULL, 0x10558d6c05b9d5c5ULL,
        0xaf192a57cde035d5ULL, 0x2c85e17823fecb33ULL
    };
    uint64_t saved = g_seed;
    unsigned i;
    for (i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
        g_seed = states[i];
        test_target_rate();
    }
    g_seed = saved;
}

/* delay reports (DESIGN 6.9): the receiver measures, the sender learns */
static int g_reports;
static uint32_t g_report_frames;
static void report_cb(anl_t *w, anl_stream_t *s, const anl_delay_report *r, void *user)
{
    (void)w; (void)s; (void)user;
    if (r->valid) { g_reports++; g_report_frames += r->frames; }
}

static void test_delay_report(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats sa, sb;
    static char buf[20000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, frames = 0;
    printf("[delay report: video 30 fps, one-way delay 40..60 ms, 5%% loss]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = 40; n.max_delay = 60;
    n.loss_pct = 5;
    net_start(&n, &ca, &cb);
    anl_set_report_callback(n.ep[0], report_cb);
    g_reports = 0; g_report_frames = 0;
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 10000; i++) {
        net_tick(&n);
        if (i % 33 == 0) {
            fill_pattern(buf, 6000, (uint32_t)frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 6000, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) ;
    }
    anl_stream_get_stats(a, &sa);
    anl_stream_get_stats(b, &sb);
    printf("  receiver: jitter %u ms, queue %u/%u ms, frame delay %u/%u ms (avg/max), %u frames in the last interval\n",
           sb.rx.jitter_ms, sb.rx.qdelay_avg_ms, sb.rx.qdelay_max_ms, sb.rx.frame_delay_avg_ms, sb.rx.frame_delay_max_ms, sb.rx.frames);
    printf("  sender:   %d reports (%u frames in all), the last %u ms old: jitter %u ms, frame delay max %u ms\n",
           g_reports, g_report_frames, sa.peer.age_ms, sa.peer.jitter_ms, sa.peer.frame_delay_max_ms);
    CHECK(sb.rx.valid, "receiver measured");
    /* reports are not resent (5% loss) and an interval without new data sends none */
    CHECK(g_report_frames >= (uint32_t)frames * 7 / 10, "reports cover the frames (%u of %d)", g_report_frames, frames);
    CHECK(sb.rx.jitter_ms >= 1 && sb.rx.jitter_ms <= 20, "jitter within the path's 20 ms spread (%u)", sb.rx.jitter_ms);
    CHECK(sb.rx.qdelay_max_ms <= 40, "queue delay: the jitter spread only (%u)", sb.rx.qdelay_max_ms);
    CHECK(sa.peer.valid && g_reports >= 30, "sender got reports (%d)", g_reports);
    CHECK(sa.peer.age_ms <= 600, "the last report is recent (%u ms): reports are not resent", sa.peer.age_ms);
    CHECK(sa.peer.jitter_ms == sb.rx.jitter_ms || sa.peer.age_ms > 0, "report carries the receiver's numbers");
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 9. network outage: FWD / data retransmissions must back off
 *-------------------------------------------------------------------*/
/* The receiver is absent (every datagram lost both ways) for absent_ms after
 * the sender starts - a receiver process launched late, or a start-up
 * blackhole - then the path opens: rtt 200 ms, `loss`% loss, 5 Mbit/s. The
 * realnet media workload: audio 160 B / 20 ms (max_age 200), video 30 fps
 * GOP 30 with key frames of 25..35 KB (max_age 500, drop_until_key),
 * init_cwnd 16. Before the first RTT sample the sender's semi-reliable frames
 * are never retransmitted (they expire before the initial RTO of 600 ms fires,
 * DESIGN 7.3) - a fresh window goes out every RTO and the sender's una runs
 * ahead of the receiver's rcv_nxt (still 0). Once the gap exceeds rcv_wnd
 * (512 audio segments, about 19 s here) the receiver can store nothing until
 * a FWD arrives, and the FWD had backed off to 6..60 s (DESIGN 7.4, 13.29).
 * Expected: audio and a key frame within 1.5 s of the path opening, whatever
 * the absence. */
static void test_start_absent(int absent_ms, int loss)
{
    net n; anl_config ca, cb; anl_stream_opt oa, ov;
    anl_stream_t *a, *v, *pa = NULL, *pv = NULL;
    static char buf[40000];
    anl_frame_info fi;
    int i, err = 0, r, sa, sv, t_srtt = -1, t_audio = -1, t_key = -1, audio_5s = 0, audio_sent_5s = 0, key_5s = 0;
    int t_open = absent_ms, end = absent_ms + 20000;
    uint32_t una_open = 0;
    printf("[start: receiver absent for %d ms, then rtt 200 / %d%% loss / 5 Mbit: audio + video, init_cwnd 16]\n", absent_ms, loss);
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 100;
    n.bandwidth_bps = 5000000; n.queue_limit = 40;
    ca.init_cwnd = cb.init_cwnd = 16;
    cb.idle_timeout_ms = 120000;    /* the receiver exists but is unreachable; its 30 s server idle timeout is not the subject */
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&oa, ANL_SEMI); oa.max_age_ms = 200; oa.prio = 0;
    anl_stream_opt_default(&ov, ANL_SEMI); ov.max_age_ms = 500; ov.prio = 1; ov.drop_until_key = 1;
    a = anl_stream_open(n.ep[0], &oa, &err); sa = anl_stream_id(a);
    v = anl_stream_open(n.ep[0], &ov, &err); sv = anl_stream_id(v);
    CHECK(a != NULL && v != NULL, "streams open (%d)", err);
    if (a == NULL || v == NULL) { net_stop(&n); return; }
    for (i = 0; i < end; i++) {
        n.loss_pct = i < absent_ms ? 100 : loss;
        net_tick(&n);
        if (i % 20 == 0) {
            fill_pattern(buf, 160, (uint32_t)i);
            anl_stream_send_frame(a, 0, buf, 160, NULL);
            if (i >= t_open && i < t_open + 5000) audio_sent_5s++;
        }
        if (i % 33 == 0) {
            int key = (i / 33) % 30 == 0, len = key ? 25000 + (int)(rnd() % 10000) : 2500 + (int)(rnd() % 1000);
            fill_pattern(buf, len, (uint32_t)i);
            anl_stream_send_frame(v, key ? ANL_FRAME_KEY : 0, buf, len, NULL);
        }
        if (t_srtt < 0 && n.ep[0]->rx_srtt > 0) t_srtt = i - t_open;
        if (pa == NULL) pa = g_peer[1][sa];
        if (pv == NULL) pv = g_peer[1][sv];
        if (pa) while ((r = anl_stream_recv_frame(pa, buf, sizeof(buf), &fi)) > 0) {
            if (t_audio < 0) t_audio = i - t_open;
            if (i < t_open + 5000) audio_5s++;
        }
        if (pv) while ((r = anl_stream_recv_frame(pv, buf, sizeof(buf), &fi)) > 0) {
            if (fi.flags & ANL_FRAME_KEY) { if (t_key < 0) t_key = i - t_open; if (i < t_open + 5000) key_5s++; }
        }
        if (i == t_open) una_open = ((anl_stream *)a)->snd_una;
        CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "alive at t=%d ms", i);
        if (anl_state(n.ep[0]) != 0) break;
    }
    printf("  sender una at open %u (rcv_wnd 512); after the path opened: first RTT sample +%d ms, first audio +%d ms,"
           " first key frame +%d ms; first 5 s: audio %d/%d, key frames %d/5\n",
           una_open, t_srtt, t_audio, t_key, audio_5s, audio_sent_5s, key_5s);
    CHECK(t_srtt >= 0 && t_srtt <= 1000, "first RTT sample within 1 s of the path opening (%d ms)", t_srtt);
    CHECK(t_audio >= 0 && t_audio <= 1500, "audio within 1.5 s of the path opening (%d ms)", t_audio);
    /* key frames: 25..35 KB through a 16-segment window at 10% loss - a lost
       one waits for the next GOP (1 s); before the fix nothing arrived at all */
    CHECK(t_key >= 0 && t_key <= 5000, "a key frame within 5 s of the path opening (%d ms)", t_key);
    CHECK(audio_5s * 100 >= audio_sent_5s * 60, "audio in the first 5 s (%d/%d)", audio_5s, audio_sent_5s);
    net_stop(&n);
}

static void test_outage(void)
{
    net n; anl_config ca, cb; anl_stream_opt os, orl;
    anl_stream_t *a, *b, *ra, *rb, *ca2, *cb2;
    char buf[2000];
    anl_frame_info fi;
    int i, frames_after = 0, rel_got = 0, r, t_resume = -1;
    printf("[network outage: 5 s blackout with semi + reliable streams, one closed during the outage]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 30;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&os, ANL_SEMI);
    os.max_age_ms = 200;
    anl_stream_opt_default(&orl, ANL_RELIABLE);
    a = open_pair(&n, 0, &os, NULL, &b);
    ra = open_pair(&n, 0, &orl, NULL, &rb);
    ca2 = open_pair(&n, 0, &orl, NULL, &cb2);
    if (!b || !rb || !cb2) { net_stop(&n); return; }
    for (i = 0; i < 12000; i++) {
        n.loss_pct = (i >= 2000 && i < 7000) ? 100 : 0;
        net_tick(&n);
        if (i % 20 == 0) { fill_pattern(buf, 160, (uint32_t)i); anl_stream_send_frame(a, 0, buf, 160, NULL); }
        if (i % 100 == 0 && i < 9000) { fill_pattern(buf, 1000, (uint32_t)(i / 100)); anl_stream_send(ra, buf, 1000); }
        if (i == 3000) anl_stream_close(ca2);                     /* closed in the middle of the outage */
        while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            if (i >= 7000) { frames_after++; if (t_resume < 0) t_resume = i - 7000; }
        }
        while ((r = anl_stream_recv(rb, buf, sizeof(buf))) > 0) {
            CHECK(check_pattern(buf, r, (uint32_t)rel_got), "reliable message %d", rel_got);
            rel_got++;
        }
        CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "alive at t=%d ms", i);
        if (anl_state(n.ep[0]) != 0) break;
    }
    printf("  audio resumed %d ms after the outage, %d frames after; reliable %d/90 messages\n", t_resume, frames_after, rel_got);
    CHECK(t_resume >= 0 && t_resume < 3000 && frames_after > 150, "semi stream resumes");
    CHECK(rel_got == 90, "reliable stream delivered everything (%d)", rel_got);
    /* a close during the outage (DESIGN 6.1): gone here at once, its CLOSE
       repeated until the path is back and the peer's RST confirms it */
    CHECK(stream_count(n.ep[0], NULL) == 2 && stream_state(cb2) == ANL_STREAM_CLOSED && nclos(n.ep[0]) == 0,
          "close during the outage: freed here, the peer told after it, confirmed (%d / %d / %u)",
          stream_count(n.ep[0], NULL), stream_state(cb2), nclos(n.ep[0]));
    net_stop(&n);
}

/* Releasing old FRESH ACKs after a pause must not change the RTT model.
 * A genuine long-delay confirmation still has to update it. */
static void test_rtt_stale_ack(void)
{
    net n;
    anl_config ca, cb;
    anl_t *w;
    anl_stream *st;
    char packet[64], received[16], *p;
    int i, before;
    uint32_t echo, next;
    printf("[rtt: old/duplicate FRESH ACK and a newly acknowledged segment]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 90;
    ca.interval = cb.interval = 10;
    net_start(&n, &ca, &cb);
    CHECK(anl_send(n.ep[0], "baseline", 8) == 0, "send baseline sample");
    for (i = 0; i < 2000; i++) net_tick(&n);
    CHECK(anl_recv(n.ep[1], received, sizeof(received)) == 8, "receive baseline sample");
    w = n.ep[0]; st = w->dflt; before = w->rx_srtt;
    CHECK(before > 0 && st->nsnd_buf == 0, "real ACK established RTT and retired baseline");
    p = plain_hdr(packet, n.ep[1], w->conv, ANL_VERSION << 6, (uint16_t)w->current);
    p = enc_sid(p, SEG_ACK, st->sid); p = enc8(p, ACK_F_FRESH);
    p = enc24(p, st->snd_una & SN_MASK); p = enc16(p, st->rcv_wnd);
    p = enc16(p, (uint16_t)(w->current - 5000)); p = enc_varint(p, 0);
    CHECK(anl_input_plain(w, packet, p-packet) == 0, "valid old ACK accepted");
    CHECK(w->rx_srtt == before, "old ACK cannot pollute RTT (%d -> %d)", before, w->rx_srtt);
    (void)plain_hdr(packet, n.ep[1], w->conv, ANL_VERSION << 6, (uint16_t)w->current);   /* the same ACK in a new datagram */
    CHECK(anl_input_plain(w, packet, p-packet) == 0, "valid duplicate ACK accepted");
    CHECK(w->rx_srtt == before, "duplicate ACK cannot pollute RTT");
    CHECK(anl_send(w, "fresh", 5) == 0, "send a genuine new segment");
    CHECK(st->nsnd_buf == 1, "new segment remains live");
    echo = w->current; next = st->snd_nxt;
    n.now += 1000; anl_update(w, n.now);
    before = w->rx_srtt;
    p = plain_hdr(packet, n.ep[1], w->conv, ANL_VERSION << 6, (uint16_t)w->current);
    p = enc_sid(p, SEG_ACK, st->sid); p = enc8(p, ACK_F_FRESH);
    p = enc24(p, next & SN_MASK); p = enc16(p, st->rcv_wnd);
    p = enc16(p, (uint16_t)echo); p = enc_varint(p, 0);
    CHECK(anl_input_plain(w, packet, p-packet) == 0 && st->nsnd_buf == 0, "real ACK retires new data");
    CHECK(w->rx_srtt != before && abs(w->rx_srtt - 1000) < abs(before - 1000), "new ACK still learns a legitimate RTT (%d -> %d)", before, w->rx_srtt);
    net_stop(&n);
}

/* Regression cases for pacing across flushes, connection timers and accounting. */
static void test_review_scheduler(int low_prio)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream *a, *b; char data[100000]; int i;
    puts("[weighted scheduler retains quotas across pacing wakes]");
    net_init(&n, &ca, &cb); ca.pace_rate = 10000; ca.pace_burst = 1400;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE); o.prio = 0;
    a = anl_stream_open(n.ep[0], &o, NULL);
    o.prio = low_prio; b = anl_stream_open(n.ep[0], &o, NULL);
    for (i = 0; i < 200; i++) net_tick(&n);
    memset(data, 42, sizeof(data));
    CHECK(anl_stream_send(a, data, sizeof(data)) == 0 && anl_stream_send(b, data, sizeof(data)) == 0, "enqueue saturated streams");
    for (i = 0; i < 5000; i++) net_tick(&n);
    CHECK(a->snd_nxt > 10 && b->snd_nxt >= 3, "both streams progress: %u/%u", a->snd_nxt, b->snd_nxt);
    if (low_prio == 0) CHECK(a->snd_nxt <= b->snd_nxt + 8, "same-priority round bounded: %u/%u", a->snd_nxt, b->snd_nxt);
    else CHECK(a->snd_nxt <= (b->snd_nxt + 1) * 8, "8:1 weighted round bounded: %u/%u", a->snd_nxt, b->snd_nxt);
    /* Closing a partially served stream must leave the remaining round usable. */
    anl_stream_close(a);
    { uint32_t before = b->snd_nxt;
      for (i = 0; i < 500; i++) net_tick(&n);
      CHECK(b->snd_nxt > before, "scheduler continues after close"); }
    net_stop(&n);
}

/* a connection with nothing pending is not looked at every interval: the
 * keepalive (or the idle timeout) is its next wake; anything queued, in
 * flight or to be acknowledged brings the interval back */
static void test_check_quiet(void)
{
    net n; anl_config ca, cb; char buf[100]; int i;
    puts("[anl_check: a quiet connection waits for the keepalive, not the interval]");
    net_init(&n, &ca, &cb);
    ca.keepalive_ms = cb.keepalive_ms = 3000;
    net_start(&n, &ca, &cb);
    CHECK(anl_check(n.ep[0], n.now) - n.now <= (uint32_t)ca.interval, "opening (OPEN unanswered): within an interval");
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(conn_quiet(n.ep[0]) && conn_quiet(n.ep[1]), "both ends quiet once the OPENs are answered");
    CHECK(anl_check(n.ep[0], n.now) - n.now > 1000 && anl_check(n.ep[0], n.now) - n.now <= 3000,
          "quiet: the next look is the keepalive, not the interval");
    memset(buf, 1, sizeof buf);
    anl_stream_send(anl_default_stream(n.ep[0]), buf, sizeof buf);
    CHECK(!conn_quiet(n.ep[0]) && anl_check(n.ep[0], n.now) - n.now <= (uint32_t)ca.interval, "data queued: within an interval");
    for (i = 0; i < 300 && !(conn_quiet(n.ep[0]) && conn_quiet(n.ep[1])); i++) net_tick(&n);
    CHECK(i < 300, "quiet again once acknowledged, with the receiver's ACKs out (%d ms)", i);
    while (anl_stream_recv(anl_default_stream(n.ep[1]), buf, sizeof buf) > 0) ;
    for (i = 0; i < 4000; i++) net_tick(&n);
    CHECK(anl_state(n.ep[0]) >= 0 && anl_state(n.ep[1]) >= 0 && conn_quiet(n.ep[0]) && conn_quiet(n.ep[1]),
          "keepalives came and went: alive and quiet");
    net_stop(&n);
}

/* byte-stream appends grow the queued tail in place or by doubling: the bytes
 * arrive in order whatever the write sizes; the connection getters */
static void test_stream_append(void)
{
    net n; anl_config ca, cb; static char out[200000], in[200000]; int i, sent = 0, got = 0, r, ok = 1;
    puts("[byte stream: many small writes, getters]");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    CHECK(anl_conv(n.ep[0]) == anl_conv(n.ep[1]) && anl_conv(n.ep[0]) != 0, "anl_conv");
    {
        void *u = anl_get_user(n.ep[0]);            /* the harness's own: swap and restore */
        anl_set_user(n.ep[0], &n);
        CHECK(anl_get_user(n.ep[0]) == (void *)&n, "anl_set_user / anl_get_user");
        anl_set_user(n.ep[0], u);
    }
    CHECK(anl_stream_mode(anl_default_stream(n.ep[0])) == ANL_RELIABLE, "anl_stream_mode");
    for (i = 0; i < 4000; i++) {
        int len = 1 + (int)(i * 7 % 61), k;
        for (k = 0; k < len; k++) out[sent + k] = (char)(i + k * 3);
        r = anl_send(n.ep[0], out + sent, len);
        if (r < 0) break;
        sent += len;
    }
    CHECK(sent > 100000, "small writes accepted (%d bytes)", sent);
    for (i = 0; i < 20000 && got < sent; i++) {
        net_tick(&n);
        while ((r = anl_recv(n.ep[1], in + got, (int)sizeof in - got)) > 0) got += r;
    }
    ok = got == sent && memcmp(in, out, (size_t)sent) == 0;
    CHECK(ok, "all bytes in order (%d of %d)", got, sent);
    net_stop(&n);
}

static int review_sink(char *buf, int len, anl_t *w, void *user)
{ (void)buf; (void)len; (void)w; (void)user; return 0; }

static void test_review_timers(void)
{
    uint32_t starts[2] = {1000, 0xffffffe6u}; int i;
    puts("[check wakes for keepalive and idle timeout, including clock wrap]");
    for (i = 0; i < 2; i++) {
        anl_config c; anl_t *w; uint32_t t = starts[i]; uint64_t sent;
        anl_config_default(&c, ANL_ROLE_SERVER);
        c.interval = 5000; c.keepalive_ms = 50; c.idle_timeout_ms = 100;
        w = anl_create(1, &c, NULL); anl_setoutput(w, review_sink); anl_update(w, t);
        sent = w->tx_dg;
        CHECK(anl_check(w, t) == t + 50, "keepalive is next timer");
        CHECK(anl_check(w, t + 51) == t + 51, "overdue timer wakes now");
        anl_update(w, t + 50);
        CHECK(w->tx_dg == sent + 1, "keepalive sent before periodic flush");
        CHECK(anl_check(w, t + 50) == t + 100, "idle deadline is next");
        anl_update(w, t + 100);
        CHECK(anl_state(w) == -1, "idle timeout fires on time");
        anl_release(w);
    }
}

static void test_review_backlog(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_t *a, *b;
    anl_stream_stats st; char data[3000], out[4000]; int i, total = 0, got;
    puts("[byte-stream append backlog counts all unacknowledged bytes]");
    net_init(&n, &ca, &cb); net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE); o.stream = 1;
    a = open_pair(&n, 0, &o, NULL, &b); memset(data, 42, sizeof(data));
    CHECK(anl_stream_send(a, data, 100) == 0 && anl_stream_send(a, data, 100) == 0, "append small writes");
    anl_stream_get_stats(a, &st); CHECK(st.backlog_bytes == 200, "merged backlog=%u", st.backlog_bytes);
    CHECK(anl_stream_send(a, data, sizeof(data)) == 0, "append plus new segments");
    anl_stream_get_stats(a, &st); CHECK(st.backlog_bytes == 3200, "full backlog=%u", st.backlog_bytes);
    for (i = 0; i < 1000; i++) {
        net_tick(&n);
        while ((got = anl_stream_recv(b, out, sizeof(out))) >= 0) total += got;
    }
    anl_stream_get_stats(a, &st);
    CHECK(total == 3200 && st.backlog_bytes == 0 && st.wait_snd == 0, "delivered and accounted: %d/%u", total, st.backlog_bytes);
    net_stop(&n);
}

static void test_review_gf_tables(void)
{
    unsigned a, b;
    puts("[immutable GF tables match polynomial multiplication]");
    for (a = 0; a < 256; a++) for (b = 0; b < 256; b++) {
        unsigned x = a, y = b, product = 0;
        while (y) { if (y & 1) product ^= x; y >>= 1; x <<= 1; if (x & 256) x ^= 0x11d; }
        CHECK(gf_mul((uint8_t)a, (uint8_t)b) == product, "GF product %u * %u", a, b);
    }
    for (a = 1; a < 256; a++) CHECK(gf_mul((uint8_t)a, gf_inv((uint8_t)a)) == 1, "GF inverse %u", a);
}

/* Replay the exact random states at entry to the failing run_fec_gate
 * scenarios (after the earlier scenarios in each historical test). These checks
 * complement, and do not replace, the fixed-window assertions above. */
static void test_fec_gate_finite_flight(void)
{
    static const uint64_t video_rng[] = { UINT64_C(0x709b4771c57e81c8), UINT64_C(0x0269a3c42ff29859) };
    uint64_t saved_rng = g_seed;
    gate_observation d;
    uint32_t repaired;
    int got, open, j;
    printf("[FEC gate: evidence onset and finite-flight delivery replay]\n");
    g_seed = UINT64_C(0xac81a8851fccbd0a);
    g_gate_noreport = 1;
    g_gate_observe = &d;
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 200, 160, 20, 140, 5, 20000, &repaired, &got);
    CHECK(d.first_hard_ms > 3000, "historical audio: no hard loss yet at sample-window start (%d)", d.first_hard_ms);
    CHECK(d.first_protected_ms >= d.first_hard_ms && d.first_protected_ms - d.first_hard_ms <= d.opening_budget_ms,
          "audio protection promptly follows hard evidence (%d -> %d)", d.first_hard_ms, d.first_protected_ms);
    CHECK(open && d.evidence_samples > 100 && d.protected_samples == d.evidence_samples,
          "audio protection stays on after opening (%d/%d)", d.protected_samples, d.evidence_samples);
    CHECK(d.total >= 985 && d.total + (int)d.skipped == 1000,
          "finite audio flight delivered and accounted (%d + %u)", d.total, d.skipped);
    g_gate_observe = NULL;
    g_gate_noreport = 0;
    for (j = 0; j < 2; j++) {
        g_seed = video_rng[j];
        g_gate_deadline_cfg = 300;
        g_gate_latency_rtt = 4;
        g_gate_observe = &d;
        open = run_fec_gate(ANL_FEC_RTT_AUTO, 1200, 3000, 33, 125, 5, 8000, &repaired, &got);
        CHECK(!open && repaired == 0 && d.repaired == 0, "video replay: retransmissions only (%d, %u -> %u)", open, repaired, d.repaired);
        CHECK(d.total == 243 && d.skipped == 0, "finite video flight loses no frame (%d, %u)", d.total, d.skipped);
        CHECK(g_gate_deadline >= 996 && g_gate_deadline <= 1040 && d.max_delivery_ms <= (int)g_gate_deadline,
              "every video frame arrives within its own deadline (%d <= %u)", d.max_delivery_ms, g_gate_deadline);
        g_gate_observe = NULL;
        g_gate_latency_rtt = 0;
        g_gate_deadline_cfg = 0;
    }
    g_seed = saved_rng;
}

/* ANL_TEST_ONLY: substrings of test names separated by '|', any of them selects the test */
/* A peer holding the PSK crafts parities whose rebuild carries a frame flag
 * on a reliable stream: the delivery resets the stream inside the decode,
 * which frees the receive cache - the decode and the parity handling must
 * not touch it after that (one lost packet, then two of one block). */
static void test_fec_rebuild_reset(void)
{
    static const char payload[8] = "abcdefg";
    int lost;
    printf("[fec: a rebuild that resets its stream does not touch the freed cache]\n");
    for (lost = 1; lost <= 2; lost++) {
        anl_config cfg; anl_stream_opt o; anl_t *w; anl_stream *st;
        uint8_t c[2][64], body[80];
        uint32_t l[2], lm, i, j;
        char *p;
        anl_config_default(&cfg, ANL_ROLE_CLIENT);
        memset(cfg.psk, 9, 32);
        w = anl_create(0x5eed, &cfg, NULL);
        anl_setoutput(w, cap_output);
        anl_stream_opt_default(&o, ANL_RELIABLE);
        o.fec = 1; o.fec_ratio = 50;
        st = (anl_stream *)anl_stream_open(w, &o, NULL);
        CHECK(st != NULL, "FEC stream");
        if (st == NULL) { anl_release(w); continue; }
        memset(c, 0, sizeof(c));
        l[0] = canon_build(c[0], 0, F_HAS_FRAME, 7, payload, sizeof(payload));    /* sn 0: resets */
        l[1] = canon_build(c[1], 0, 0, 0, payload, sizeof(payload));
        lm = lost == 2 && l[1] > l[0] ? l[1] : l[0];
        for (j = 0; j < (uint32_t)lost; j++) {
            p = (char *)body;
            p = enc24(p, 0);
            *p++ = (char)lost; *p++ = (char)lost; *p++ = (char)j;     /* k, m, j */
            for (i = 0; i < lm; i++)
                *p++ = (char)(gf_mul(fec_coef(j, 0), c[0][i]) ^ (lost == 2 ? gf_mul(fec_coef(j, 1), c[1][i]) : 0));
            handle_parity(w, st, (const char *)body, (uint32_t)(p - (char *)body), w->current);
        }
        printf("  %d lost: stream %s, rebuilt %u\n", lost, st->state == ANL_STREAM_CLOSED ? "reset" : "open", st->fec_recovered);
        CHECK(st->state == ANL_STREAM_CLOSED && st->fc->cache == NULL, "the rebuild reset the stream and freed the cache");
        anl_release(w);
    }
}
