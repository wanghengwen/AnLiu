/* priority, key frames, receiver deadline and skip, FEC buffers. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

static void test_priority(void)
{
    static const char *cc[2] = { "BBR (default)", "BBR capped at 2.8 Mbps (cfg.pace_rate)" };
    int nc;
    printf("[priority: control (reliable 200 B / 50 ms) vs video (~3.6 Mbps) on a 3 Mbps link, rtt 40 ms, 1%% loss]\n");
    printf("  default stream: strict priority; other streams: %d levels, weighted round robin %u:%u:%u:%u\n", ANL_MAX_PRIO,
           prio_weight[0], prio_weight[1], prio_weight[2], prio_weight[3]);
    for (nc = 0; nc < 2; nc++) {
        prio_result r[5];
        static const char *name[5] = { "control alone", "ctrl on default stream", "ctrl prio 0, video prio 2",
                                       "both prio 2", "ctrl prio 3, video prio 0" };
        int k;
        run_priority(-1, 2, 0, nc, &r[0]);
        run_priority(-1, 2, 1, nc, &r[1]);
        run_priority(0, 2, 1, nc, &r[2]);
        run_priority(2, 2, 1, nc, &r[3]);
        run_priority(3, 0, 1, nc, &r[4]);
        printf("  %s\n", cc[nc]);
        for (k = 0; k < 5; k++)
            printf("    %-26s ctrl p50 %4.0f p99 %4.0f max %4.0f ms (%u/%u)  max ctrl unsent %d seg  video %u/%u\n",
                   name[k], r[k].p50, r[k].p99, r[k].max, r[k].got, r[k].sent, r[k].max_wait, r[k].vgot, r[k].vframes);
        /* inside AnLiu the control stream is never queued behind video
           (BBR: at most until video frees the shared cwnd) */
        for (k = 1; k <= 2; k++) {
            CHECK(r[k].max_wait <= (nc ? 2 : 4), "%s: at most %d unsent control segments (%d)", name[k], nc ? 2 : 4, r[k].max_wait);
            CHECK(r[k].got == r[k].sent, "%s: control delivered with video running (%u/%u)", name[k], r[k].got, r[k].sent);
            /* paced below the link: one retransmission (RTO ~100 ms) plus queueing at most */
            if (nc) CHECK(r[k].p99 <= 250, "%s paced below the link: ctrl p99 %.0f ms", name[k], r[k].p99);
        }
    }
}

/*---------------------------------------------------------------------
 * 8. key frames: undecodable P frames are dropped (DESIGN 7.6)
 *-------------------------------------------------------------------*/
static void test_key_sender_purge(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss; anl_frame_info fi;
    char buf[8000];
    uint32_t fno;
    int i, r;
    anl_stream_t *a, *b;
    printf("[key frames A: sender drops in-flight P frames of an abandoned key frame]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 200; o.drop_until_key = 1;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);

    n.loss_pct = 100;                           /* K0 P1 P2 are sent but never arrive */
    for (i = 0; i < 3; i++) {
        fill_pattern(buf, i ? 1000 : 4000, (uint32_t)i);
        CHECK(anl_stream_send_frame(a, i ? 0 : ANL_FRAME_KEY, buf, i ? 1000 : 4000, &fno) == 0 && fno == (uint32_t)i, "send frame %d", i);
        net_tick(&n);
    }
    for (i = 0; i < 50 && a->nsnd_que > 0; i++) net_tick(&n);   /* the key frame's parities take pacing tokens */
    CHECK(a->nsnd_buf >= 3 && a->nsnd_que == 0, "all three frames in flight (%u / %u)", a->nsnd_buf, a->nsnd_que);
    for (i = 0; i < 1000 && a->nsnd_buf > 0; i++) net_tick(&n);
    anl_stream_get_stats(a, &ss);
    CHECK(a->nsnd_buf == 0, "K0 abandoned on retransmission, P1 P2 dropped with it (%u left)", a->nsnd_buf);
    CHECK(ss.frames_dropped == 3, "three frames dropped (%u)", ss.frames_dropped);
    CHECK(ST_ON(a->out, STO_FWD) && a->sm->fwd_una == a->snd_nxt, "one FWD to snd_nxt");
    CHECK(anl_stream_send_frame(a, 0, buf, 500, &fno) == ANL_EDROPPED && fno == 3, "P3 refused until a key frame");

    n.loss_pct = 0;
    fill_pattern(buf, 3000, 4);
    CHECK(anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 3000, &fno) == 0 && fno == 4, "K4 accepted");
    for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi); }
    CHECK(r == 3000 && fi.frame_no == 4 && fi.flags == ANL_FRAME_KEY && fi.lost_before == 4 && check_pattern(buf, r, 4),
          "receiver gets K4 first, lost_before 4 (r=%d fno=%u lost=%u)", r, fi.frame_no, fi.lost_before);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(anl_stream_recv_frame(b, buf, sizeof(buf), &fi) == ANL_EAGAIN, "no stale P frame afterwards");
    CHECK(!ST_ON(a->out, STO_FWD), "FWD acknowledged");
    net_stop(&n);
}

/* A full receiver drains, but its window-opening ACK is lost. With no data
   in flight there is no retransmission to rescue the sender: WASK must do it. */
static void test_window_reopen_loss(void)
{
    int lose_probe;
    printf("[window: lost reopen ACK recovers on the measured RTO]\n");
    for (lose_probe = 0; lose_probe <= 1; lose_probe++) {
        net n; anl_config ca, cb; anl_stream_opt opt; anl_stream_t *a, *b;
        char data[16000]; int i, size, got = ANL_EAGAIN; uint32_t start, rto;
        net_init(&n, &ca, &cb);
        n.min_delay = n.max_delay = 10;
        ca.interval = cb.interval = 10;
        ca.pad_max = cb.pad_max = 0;
        ca.keepalive_ms = cb.keepalive_ms = 0;
        net_start(&n, &ca, &cb);
        anl_stream_opt_default(&opt, ANL_RELIABLE);
        opt.snd_wnd = opt.rcv_wnd = 8;
        a = open_pair(&n, 0, &opt, &opt, &b);
        if (!b) { net_stop(&n); continue; }
        for (i = 0; i < 200; i++) net_tick(&n);
        size = (int)a->mss * 8;
        CHECK(size <= (int)sizeof(data), "test message fits");
        fill_pattern(data, size, 7);
        CHECK(anl_stream_send(a, data, size) == 0, "fill peer window");
        for (i = 0; i < 2000 && (a->rmt_wnd != 0 || a->nsnd_buf != 0); i++) net_tick(&n);
        CHECK(a->rmt_wnd == 0 && a->nsnd_buf == 0 && b->nrcv_que == 8,
              "peer full, every sent fragment acknowledged");
        CHECK(anl_stream_recv(b, data, sizeof(data)) == size && check_pattern(data, size, 7),
              "application drains receiver");
        n.loss_pct = 100;
        for (i = 0; i < 100 && ST_ON(b->out, STO_TELL); i++) net_tick(&n);
        n.loss_pct = 0;
        CHECK(!ST_ON(b->out, STO_TELL) && a->rmt_wnd == 0 && wnd_unused(b) == 8,
              "opening ACK was sent and lost, sender retains stale zero window");
        rto = (uint32_t)n.ep[0]->rx_rto; start = n.now;
        CHECK(anl_stream_send(a, "resume", 7) == 0, "queue data behind stale window");
        for (i = 0; i <= ca.interval && a->probe_wait == 0; i++) net_tick(&n);
        CHECK(a->probe_wait == rto, "first probe follows the measured RTO (%u vs %u)", a->probe_wait, rto);
        if (lose_probe) n.drop_at[0] = (uint32_t)n.sent + 1;
        for (i = 0; i < (int)(4 * rto + 8 * ca.interval); i++) {
            net_tick(&n);
            got = anl_stream_recv(b, data, sizeof(data));
            if (got >= 0) break;
        }
        CHECK(got == 7 && memcmp(data, "resume", 7) == 0,
              "resume after lost opening ACK%s within RTT-aware bound (elapsed=%u rto=%u)",
              lose_probe ? " and first probe" : "", n.now - start, rto);
        CHECK(a->rmt_wnd > 0 && a->probe_wait == 0, "positive window cancels persistence backoff");
        if (!lose_probe) {
            uint32_t next; long sent0;
            for (i = 0; i < 100; i++) net_tick(&n);
            fill_pattern(data, size, 9);
            CHECK(anl_stream_send(a, data, size) == 0, "fill window a second time");
            for (i = 0; i < 2000 && (a->rmt_wnd != 0 || a->nsnd_buf != 0); i++) net_tick(&n);
            CHECK(a->rmt_wnd == 0 && b->nrcv_que == 8, "application keeps the peer window full");
            next = a->snd_nxt; sent0 = n.sent; rto = (uint32_t)n.ep[0]->rx_rto;
            CHECK(anl_stream_send(a, "waiting", 8) == 0, "queue while receiver deliberately holds data");
            for (i = 0; i < (int)(20 * rto); i++) net_tick(&n);
            CHECK(a->snd_nxt == next && a->nsnd_que == 1, "probes never override a genuinely closed window");
            CHECK(a->probe_wait > rto && a->probe_wait <= PROBE_LIMIT && n.sent - sent0 <= 20,
                  "persistent zero window still backs off, without busy probing (%ld packets)", n.sent - sent0);
        }
        net_stop(&n);
    }
}

static void test_receiver_deadline_default(void)
{
    int policy;
    printf("[semi: receiver default deadline advances without sender FWD]\n");
    for (policy = -1; policy <= 3; policy++) {
        net n; anl_config ca, cb; anl_stream_opt o, op; anl_frame_info fi;
        anl_stream_t *a, *b;
        char buf[100];
        int i, r = ANL_EAGAIN, dropped_ack = 0;
        uint32_t start, received_at = 0;
        net_init(&n, &ca, &cb);
        /* 1 ms one way: a retransmission would still come within the 40 ms
           lifetime, so this is the local timer's wait, not the skip of a
           hopeless hole (rcv_hole_hopeless, test_rcv_hole_echo) */
        n.min_delay = n.max_delay = 1;
        ca.pad_max = cb.pad_max = 0;
        net_start(&n, &ca, &cb);
        anl_stream_opt_default(&o, ANL_SEMI);
        CHECK(o.rcv_deadline_ms == -1, "semi defaults to a share of the local frame lifetime");
        o.fec = 0; o.max_age_ms = 10000;
        op = o; op.max_age_ms = 40;
        if (policy >= 0) op.rcv_deadline_ms = policy ? 20 : 0;
        a = open_pair(&n, 0, &o, &op, &b);
        if (!b) { net_stop(&n); continue; }
        for (i = 0; i < 200; i++) net_tick(&n);
        n.loss_pct = 100;
        fill_pattern(buf, sizeof(buf), 0);
        CHECK(anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) == 0, "send missing frame");
        n.loss_pct = 0;
        fill_pattern(buf, sizeof(buf), 1);
        CHECK(anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) == 0, "send subsequent frame");
        CHECK(a->snd_nxt == 2, "both frames left the sender before it stopped");
        start = n.now;
        /* Keep delivering ACKs, but stop the sender timer: the receiver must
           advance without retransmission/FWD and report skips as retirement. */
        for (i = 0; i < 150; i++) {
            pkt **pp = &n.queue;
            n.now++;
            n.ep[0]->current = n.now; /* timestamp only: no sender retransmission timer */
            while (*pp) {
                pkt *p = *pp;
                if (tdiff(n.now, p->deliver_at) < 0) { pp = &p->next; continue; }
                *pp = p->next;
                if (p->to == 0 && ((policy == 2 && b->frames_skipped && !dropped_ack) ||
                                  (policy == 3 && !b->frames_skipped))) dropped_ack++;
                else anl_input(n.ep[p->to], p->data, p->len);
                free(p);
            }
            if (i == 100) { ST_SET(b->out, STO_TELL); ctl_mark(b); } /* repeat a lost window ACK */
            anl_update(n.ep[1], n.now);
            if (r < 0) {
                r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi);
                if (r >= 0) received_at = n.now;
            }
        }
        if (policy == 0) CHECK(r == ANL_EAGAIN, "explicit zero keeps waiting");
        else {
            int deadline = policy == -1 ? 40 * RCV_WAIT_PCT / 100 : 20;     /* -1: 3/5 of max_age */
            CHECK(r == (int)sizeof(buf) && fi.frame_no == 1 && fi.lost_before == 1 &&
                  check_pattern(buf, sizeof(buf), 1), "skip missing frame, preserve next frame and loss count");
            CHECK(received_at - start >= (uint32_t)(1 + deadline) &&
                  received_at - start <= (uint32_t)(1 + deadline + 2 * cb.interval),
                  "local timer bounds gap wait (elapsed=%u)", received_at - start);
            handle_fwd(n.ep[1], b, 1);
            CHECK(anl_stream_recv_frame(b, buf, sizeof(buf), &fi) == ANL_EAGAIN,
                  "late FWD cannot redeliver or rewind");
        }
        CHECK(n.ep[0]->delivered == sizeof(buf) + SEG_WIRE_OVH,
              "only the actually received frame gets congestion-control credit (%llu)",
              (unsigned long long)n.ep[0]->delivered);
        if (policy >= 2) CHECK(dropped_ack > 0, "exercise loss of a skip ACK or its earlier SACK");
        if (policy != 0) CHECK(a->nsnd_buf == 0, "skipped prefix retires even after ACK loss");
        CHECK(!ST_ON(a->out, STO_FWD) && a->frames_dropped == 0, "sender did not abandon the frame");
        net_stop(&n);
    }
}

static int g_skip_packets, g_skip_acks, g_skip_want;
static uint32_t g_skip_watermark;

static int skip_ack_output(char *wire, int len, anl_t *w, void *user)
{
    uint8_t plain[2048];
    const char *p, *end;
    int size = siv_open(&w->keys, w->role, (const uint8_t *)wire, (size_t)len, plain);
    int marker = 0;
    (void)user;
    CHECK(len <= (int)w->mtu && size >= ANL_HDR_SIZE, "valid bounded ACK datagram");
    if (size < ANL_HDR_SIZE) return 0;
    p = (const char *)plain + ANL_HDR_SIZE; end = (const char *)plain + size;
    g_skip_packets++;
    while (p < end) {
        uint8_t b0 = dec8(&p);
        int type = b0 >> 6;
        uint32_t hi;
        if ((b0 & SID_F) && dec_varint(&p, end, &hi) < 0) break;
        if (type == SEG_CTRL) {
            uint8_t sub = dec8(&p); uint32_t n = 0;
            CHECK(dec_varint(&p, end, &n) == 0 && n == 4 && sub == CTRL_RCV_SKIP,
                  "only the retirement marker precedes these ACKs");
            if (end - p < 4) break;
            CHECK(dec32(&p) == g_skip_watermark, "full 32-bit skip watermark survives wrap");
            marker = 1;
        } else if (type == SEG_ACK) {
            uint32_t n = 0, i, v;
            CHECK(marker == g_skip_want, "each split ACK shares a datagram with its retirement marker");
            if (end - p < ACK_FIX) break;
            (void)dec8(&p); p += 7;                     /* una(3) wnd(2) echo(2) */
            CHECK(dec_varint(&p, end, &n) == 0, "SACK count");
            for (i = 0; i < 2 * n; i++) CHECK(dec_varint(&p, end, &v) == 0, "SACK range");
            g_skip_acks++;
        } else { CHECK(0, "unexpected segment type in ACK test"); break; }
    }
    return 0;
}

static void test_receiver_skip_ack_fragments(void)
{
    anl_config cfg; anl_stream_opt opt; anl_t *w; anl_stream *st; int i;
    printf("[semi: atomic skip marker with split SACKs and sequence wrap]\n");
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    cfg.mtu = 128; cfg.pad_max = 0; cfg.rng = det_rng;
    w = anl_create(7, &cfg, NULL);
    CHECK(w != NULL, "create small-MTU connection");
    if (!w) return;
    anl_update(w, 1000);
    anl_stream_opt_default(&opt, ANL_SEMI); opt.fec = 0;
    st = stream_create(w, 2, &opt);
    CHECK(st != NULL, "create receiver stream");
    if (!st) { anl_release(w); return; }
    st->state = ANL_STREAM_OPEN; st->rcv_nxt = 100;
    ST_SET(st->trk, STT_SKIP); st->sm->rcv_skip_una = 50;
    for (i = 0; i < 200; i++) {
        anl_seg *s = seg_new(w, 0);
        CHECK(s != NULL, "allocate received segment");
        if (!s) break;
        s->sn = 101u + (uint32_t)i * 2;
        CHECK(rcv_link(st, s, run_find(st, s->sn)), "link received segment");
    }
    g_skip_packets = g_skip_acks = 0; g_skip_want = 1; g_skip_watermark = 50;
    anl_setoutput(w, skip_ack_output);
    write_ack_segs(w, st, 0); dg_seal(w);
    CHECK(g_skip_acks > 1 && g_skip_packets > 1, "small MTU forced several ACK datagrams");
    free_runs(st);
    free_rcv_list(w, &st->rcv_buf, &st->nrcv_buf);
    g_skip_watermark = st->sm->rcv_skip_una = 0xfffffff0u;
    st->rcv_nxt = st->sm->rcv_skip_una + ANL_MAX_WND - 1;
    write_ack_segs(w, st, 0); dg_seal(w);
    CHECK(ST_ON(st->trk, STT_SKIP), "still repeat the marker before the sending window has passed it");
    g_skip_want = 0; st->rcv_nxt++;
    write_ack_segs(w, st, 0); dg_seal(w);
    CHECK(!ST_ON(st->trk, STT_SKIP), "stop the marker once the bounded sending window proves retirement");
    anl_release(w);
}

/* A receiver skip (RCV_SKIP) that retires a prefix past the point a pending
   FWD asks the peer to skip to answers the FWD, as an ACK's una does:
   otherwise the FWD went on being resent until a later ACK. */
static int null_output(char *buf, int len, anl_t *w, void *user)
{
    (void)buf; (void)len; (void)w; (void)user;
    return 0;
}

/* run_hole: audio frames of 160 B every 20 ms, max_age 200, FEC off, 5% loss
 * both ways, one-way delay `delay`; frames later than 150 ms past it */
static void run_hole(int delay, int *late, int *got, uint32_t *echo_rtt)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    static char buf[2000];
    int i, sent = 0;
    *late = *got = 0; *echo_rtt = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = delay;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 200;
    o.fec = 0;
    /* the whole lifetime, as before the default became 3/5 of it: this is
       about the hopeless-hole rule, not the default wait (which at 60 ms RTT
       gives up on some second retransmissions: test_receiver_deadline_default) */
    o.rcv_deadline_ms = o.max_age_ms;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.loss_pct = 5;
    for (i = 0; i < 21000; i++) {
        net_tick(&n);
        if (i % 20 == 0 && sent < 1000) {
            fill_pattern(buf, 160, (uint32_t)sent);
            anl_stream_send_frame(a, 0, buf, 160, NULL);
            sent++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) {
            (*got)++;
            if (i - (int)fi.frame_no * 20 > delay + 150) (*late)++;
        }
    }
    *echo_rtt = n.ep[1]->echo_rtt;
    CHECK(anl_state(n.ep[0]) >= 0 && anl_state(n.ep[1]) >= 0, "connection stays alive");
    net_stop(&n);
}

/* A receive-only peer learns the RTT from CTRL_ECHO, and a hole a
 * retransmission can no longer fill within the lifetime is skipped at once:
 * the frames behind it are not held back (DESIGN 5.5, 7.5). Audio, 170 ms
 * RTT, max_age 200, FEC off, 5% loss: before, each loss held the next frames
 * until the 200 ms deadline */
static void test_rcv_hole_echo(void)
{
    int late, got;
    uint32_t er;
    printf("[semi: receiver RTT from CTRL_ECHO, hopeless holes skipped at once]\n");
    run_hole(85, &late, &got, &er);
    printf("  rtt 170 ms, 5%% loss, audio max_age 200, FEC off: echo rtt %u ms, %d of %d frames later than 150 ms\n", er, late, got);
    CHECK(er >= 165 && er <= 200, "receiver RTT from echoes (%u)", er);
    CHECK(late * 100 <= got, "frames behind a lost one not held back (%d of %d late)", late, got);
    /* 60 ms RTT: a retransmission is in time - wait for it, as before */
    run_hole(30, &late, &got, &er);
    printf("  rtt 60 ms: echo rtt %u ms, %d of 1000 frames delivered\n", er, got);
    CHECK(got >= 990, "short RTT: retransmissions fill the holes (%d)", got);
}

/* A peer's ts runs a little ahead of where our clock puts it: our current
 * is the time of the last update, and the two clocks' rates differ. Clamped
 * to that estimate (peer_ts may not pass ref, DESIGN 4.2), peer_ts fell
 * behind the peer's clock for good, and CTRL_ECHO, which echoes it, gave the
 * receive-only peer an RTT that grew with the drift: at a 100 ms path its
 * rcv_hole_hopeless soon skipped every hole a retransmission still filled
 * (real paths: 101 ms RTT read as 116..122 ms, audio at 15% loss lost what
 * retransmissions had saved). Receiver clock 2000 ppm fast, 100 s */
static void test_echo_clock_rate(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    static char buf[2000];
    int i, sent = 0, got = 0;
    printf("[semi: a peer clock running fast does not lengthen the echo RTT]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 50;
    n.clock_ppm[1] = 2000;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 200;
    o.fec = 0;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.loss_pct = 5;
    for (i = 0; i < 101000; i++) {
        net_tick(&n);
        if (i % 20 == 0 && sent < 5000) {
            fill_pattern(buf, 160, (uint32_t)sent);
            anl_stream_send_frame(a, 0, buf, 160, NULL);
            sent++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) got++;
    }
    printf("  rtt 100 ms, receiver clock +2000 ppm, 100 s: echo rtt %u ms, %d of %d frames delivered\n",
           n.ep[1]->echo_rtt, got, sent);
    CHECK(n.ep[1]->echo_rtt >= 95 && n.ep[1]->echo_rtt <= 115, "echo rtt stays at the path's (%u)", n.ep[1]->echo_rtt);
    CHECK(got * 100 >= sent * 99, "retransmissions still fill the holes (%d of %d)", got, sent);
    CHECK(anl_state(n.ep[0]) >= 0 && anl_state(n.ep[1]) >= 0, "connection stays alive");
    net_stop(&n);
}

static void test_rcv_skip_clears_fwd(void)
{
    anl_config cfg; anl_stream_opt opt; anl_t *w; anl_stream *st;
    char data[200], pl[64], *p;
    uint32_t una, retired;
    int i, r;
    printf("[semi: a receiver skip past a pending FWD answers it]\n");
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    cfg.pad_max = 0; cfg.rng = det_rng;
    w = anl_create(7, &cfg, NULL);
    CHECK(w != NULL, "create connection");
    if (!w) return;
    anl_setoutput(w, null_output);
    anl_update(w, 1000);
    anl_stream_opt_default(&opt, ANL_SEMI); opt.fec = 0;
    st = (anl_stream *)anl_stream_open(w, &opt, NULL);
    CHECK(st != NULL, "open semi stream");
    if (!st) { anl_release(w); return; }
    for (i = 0; i < 6; i++) {
        memset(data, i, sizeof(data));
        CHECK(anl_stream_send_frame((anl_stream_t *)st, 0, data, sizeof(data), NULL) >= 0, "queue frame %d", i);
    }
    anl_update(w, 1010);
    anl_flush(w);
    una = st->snd_una;
    CHECK(tdiff(st->snd_nxt, una) >= 4, "frames in flight (%u)", st->snd_nxt - una);
    retired = una + 3;
    ST_SET(st->out, STO_FWD); st->sm->fwd_una = retired; st->sm->fwd_ts = w->current + 1000;
    p = plain_hdr(pl, NULL, w->conv, ANL_VERSION << 6, (uint16_t)w->current);
    p = enc_sid(p, SEG_CTRL, st->sid); p = enc8(p, CTRL_RCV_SKIP); p = enc_varint(p, SKIP_BODY);
    p = enc32(p, retired);
    r = anl_input_plain(w, pl, (long)(p - pl));
    CHECK(r == ANL_OK, "skip input (%d)", r);
    CHECK(st->snd_una == retired, "the skipped prefix is retired (una %u, want %u)", st->snd_una, retired);
    CHECK(!ST_ON(st->out, STO_FWD), "the FWD it reached is answered");
    anl_release(w);
}

/* one frame (#10) is lost; the receiver skips it by rcv_deadline */
static void run_key_receiver(int rcv_drop, uint32_t *delivered, uint32_t *discarded, int *bad)
{
    net n; anl_config ca, cb; anl_stream_opt o, op; anl_stream_stats ss; anl_frame_info fi;
    char buf[4000];
    uint32_t sent = 0, last = 0, lost_sum = 0;
    int i, r, have = 0, chain = 0;
    anl_stream_t *a, *b;
    *delivered = 0; *discarded = 0; *bad = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 50;                          /* frame 10 stays lost: abandoned rather than retransmitted (RACK) */
    op = o;                                     /* receiver-side options live on the accepting side */
    op.rcv_deadline_ms = 30;
    op.rcv_drop_until_key = rcv_drop;
    a = open_pair(&n, 0, &o, &op, &b);
    if (!b) { *bad = 1; net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);
    for (i = 0; i < 2500; i++) {
        net_tick(&n);
        if (i % 33 == 0 && sent < 60) {
            int key = sent % 30 == 0;
            fill_pattern(buf, 1000, sent);
            if (sent == 10) n.loss_pct = 100;         /* frame 10 (one datagram) is lost */
            anl_stream_send_frame(a, key ? ANL_FRAME_KEY : 0, buf, 1000, NULL);
            n.loss_pct = 0;
            sent++;
        }
        while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            if (!check_pattern(buf, r, fi.frame_no)) (*bad)++;
            if (have && fi.frame_no != last + 1 + fi.lost_before) (*bad)++;
            /* decoder model: a P frame needs an unbroken chain from its key frame */
            if (fi.flags & ANL_FRAME_KEY) chain = 1;
            else if (fi.lost_before) chain = 0;
            if (!chain && rcv_drop) (*bad)++;                  /* undecodable frame delivered */
            lost_sum += fi.lost_before;
            last = fi.frame_no; have = 1;
            (*delivered)++;
        }
    }
    anl_stream_get_stats(b, &ss);
    *discarded = ss.frames_discarded;
    if (*delivered + lost_sum != last + 1) (*bad)++;
    net_stop(&n);
}

static void test_key_receiver_discard(void)
{
    uint32_t d0, x0, d1, x1;
    int b0, b1;
    printf("[key frames B: receiver discards undecodable P frames (rcv_drop_until_key)]\n");
    run_key_receiver(0, &d0, &x0, &b0);
    run_key_receiver(1, &d1, &x1, &b1);
    printf("  off: delivered %u, discarded %u    on: delivered %u, discarded %u (frames 11..29 are undecodable)\n", d0, x0, d1, x1);
    CHECK(b0 == 0 && b1 == 0, "content / accounting / decodability (%d, %d)", b0, b1);
    CHECK(d0 == 59 && x0 == 0, "off: every frame but #10 delivered (%u, %u)", d0, x0);
    CHECK(d1 == 40 && x1 == 19, "on: frames 11..29 discarded, 0..9 and 30..59 delivered (%u, %u)", d1, x1);
}

/* RTT-conditional FEC (ANL_FEC_RTT_AUTO, DESIGN 8.6): a stream of `size`-byte
 * frames every `period` ms, max_age (fec_deadline = max_age / 2) over a path
 * with `delay` ms each way and `loss` %; returns whether the gate is open
 * after `ms` and the peer's FEC repairs */
static int g_gate_noreport;             /* run_fec_gate: the peer sends no delay reports */
static int g_gate_open_pct;             /* ... % of 100 ms samples after 3 s with parity on */
static int g_gate_latency_rtt;          /* ... the sender's latency_rtt */
static int g_gate_deadline_cfg;         /* ... and fec_deadline_ms */
static uint32_t g_gate_deadline;        /* ... its fec_deadline at the end */
/* Optional finite-flight diagnostics. The original fixed-window assertions
 * still use `got` and g_gate_open_pct, before any draining takes place. */
typedef struct gate_observation {
    int first_hard_ms, first_protected_ms, opening_budget_ms;
    int protected_samples, evidence_samples;
    int total, tail, last_tail_ms, max_delivery_ms;
    uint32_t skipped, repaired;
} gate_observation;
static gate_observation *g_gate_observe;

static void gate_observe_frame(gate_observation *d, const char *buf, int len,
                               const anl_frame_info *fi, int elapsed, int period)
{
    int age = elapsed - (int)fi->frame_no * period;
    CHECK(check_pattern(buf, len, fi->frame_no), "gate replay: frame content (%u)", fi->frame_no);
    CHECK(fi->frame_no == (uint32_t)d->total + d->skipped + fi->lost_before,
          "gate replay: ordered frame accounting (%u)", fi->frame_no);
    d->skipped += fi->lost_before;
    d->total++;
    if (age > d->max_delivery_ms) d->max_delivery_ms = age;
}

static int fec_gate_on(const anl_stream_t *st) { return st->fc != NULL && ST_ON(st->fc->tx_f, FCT_GATE); }

static int run_fec_gate(int fec, int max_age, int size, int period, int delay, int loss, int ms, uint32_t *repaired, int *got)
{
    net n; anl_config ca, cb; anl_stream_opt o, op; anl_stream_stats ss;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    static char buf[40000];
    int i, r, sent = 0, open, samples = 0, on = 0;
    gate_observation *d = g_gate_observe;
    if (d) { memset(d, 0, sizeof(*d)); d->first_hard_ms = d->first_protected_ms = -1; }
    *repaired = 0; *got = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = delay;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = max_age;
    o.fec = fec;
    op = o;
    op.report = !g_gate_noreport;
    o.latency_rtt = g_gate_latency_rtt;
    o.fec_deadline_ms = g_gate_deadline_cfg;
    a = open_pair(&n, 0, &o, &op, &b);
    if (!b) { net_stop(&n); return -1; }
    n.loss_pct = loss;
    if (d) d->opening_budget_ms = FEC_BLOCK_MS + period + 2 * ca.interval;
    for (i = 0; i < ms; i++) {
        net_tick(&n);
        if (i % period == 0) {
            fill_pattern(buf, size, (uint32_t)sent);
            anl_stream_send_frame(a, size > 10000 ? ANL_FRAME_KEY : 0, buf, size, NULL);
            sent++;
        }
        if (i >= 3000 && i % 100 == 0) { anl_stream_get_stats(a, &ss); samples++; on += ss.fec_ratio != 0; }
        if (d && n.ep[0]->fec_loss_ts) {
            if (d->first_hard_ms < 0) d->first_hard_ms = i;
            if (fec_gate_on(a) && d->first_protected_ms < 0) d->first_protected_ms = i;
            if (d->first_protected_ms >= 0 && i % 100 == 0) {
                d->evidence_samples++;
                d->protected_samples += fec_gate_on(a);
            }
        }
        while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) >= 0) {
            (*got)++;
            if (d) gate_observe_frame(d, buf, r, &fi, i, period);
        }
    }
    g_gate_open_pct = samples ? on * 100 / samples : 0;
    g_gate_deadline = ((anl_stream *)a)->fc ? ((anl_stream *)a)->fc->fec_deadline : 0;   /* 0: FEC off */
    anl_stream_get_stats(a, &ss);
    open = ss.fec_ratio != 0;
    anl_stream_get_stats(b, &ss);
    *repaired = ss.fec_recovered;
    if (d) {
        uint64_t saved_rng = g_seed;
        /* Stop generating, keep loss and both endpoints running through the
         * final frame's sender lifetime and a round trip. Restore the RNG
         * so a diagnostic tail cannot change the next scenario's packets. */
        for (i = 0; i < max_age + 2 * delay; i++) {
            net_tick(&n);
            while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) >= 0) {
                gate_observe_frame(d, buf, r, &fi, ms + i, period);
                d->tail++;
                d->last_tail_ms = i + 1;
            }
        }
        g_seed = saved_rng;
        anl_stream_get_stats(b, &ss);
        d->repaired = ss.fec_recovered;
        printf("  finite flight: cutoff %d, total %d/%d, tail %d through +%d ms, skipped %u, max delivery %d ms; "
               "hard_loss_ms=%d, protected_ms=%d, protected samples %d/%d, repairs %u\n",
               *got, d->total, sent, d->tail, d->last_tail_ms, d->skipped, d->max_delivery_ms,
               d->first_hard_ms, d->first_protected_ms, d->protected_samples, d->evidence_samples, d->repaired);
    }
    CHECK(anl_state(n.ep[0]) >= 0 && anl_state(n.ep[1]) >= 0, "connection stays alive");
    net_stop(&n);
    return open;
}

/* FEC buffers only while parities may come of them (DESIGN 8.7): on a
 * lossless path the encoder's copies and the receive cache go; once the path
 * loses on a long RTT they come back and repair; lossless again, they go */
static long fec_buf_bytes(const anl_t *w)
{
    long t = 0;
    const anl_node *nd;
    uint32_t j;
    for (nd = w->slist.next; nd != &w->slist; nd = nd->next) {
        const anl_stream *st = STREAM_OF(nd);
        if (st->fc == NULL) continue;
        if (st->fc->fec_slot) for (j = 0; j < FEC_K_MAX; j++) t += st->fc->fec_slot[j].cap;
        if (st->fc->fec_out) for (j = 0; j < FEC_M_MAX; j++) t += st->fc->fec_out[j].cap;
        if (st->fc->cache) for (j = 0; j < st->fc->cache_n; j++) t += st->fc->cache[j].cap;
        if (st->fc->pcache) for (j = 0; j < st->fc->pcache_n; j++) t += st->fc->pcache[j].cap;
    }
    return t;
}

static void test_fec_buffers_release(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *v, *pv;
    anl_stream_stats ss;
    static char buf[40000];
    int i, frames = 0;
    long tx_busy = 0, rx_busy = 0;
    printf("[fec buffers: released on a lossless path, back when it loses]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 120;
    ca.interval = cb.interval = 10;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.drop_until_key = 1;
    v = open_pair(&n, 0, &o, NULL, &pv);
    if (!pv) { net_stop(&n); return; }
    for (i = 0; i < 160000; i++) {
        if (i == 40000) n.loss_pct = 5;
        if (i == 100000) n.loss_pct = 0;
        if (i % 33 == 0) {                      /* 30 fps, a key frame every 2 s */
            int key = frames++ % 60 == 0;
            anl_stream_send_frame(v, key ? ANL_FRAME_KEY : 0, buf, key ? 20000 : 4000, NULL);
        }
        net_tick(&n);
        while (anl_stream_recv_frame(pv, buf, sizeof(buf), NULL) > 0) ;
        if (i == 39999) {
            CHECK(fec_buf_bytes(n.ep[0]) == 0 && fec_buf_bytes(n.ep[1]) == 0, "lossless 40 s: no FEC buffers (%ld / %ld)",
                  fec_buf_bytes(n.ep[0]), fec_buf_bytes(n.ep[1]));
            anl_stream_get_stats(pv, &ss);
            CHECK(ss.fec_recovered == 0, "nothing rebuilt yet (%u)", ss.fec_recovered);
        }
        if (i >= 60000 && i < 100000) {
            if (fec_buf_bytes(n.ep[0]) > 0) tx_busy++;
            if (fec_buf_bytes(n.ep[1]) > 0) rx_busy++;
        }
    }
    anl_stream_get_stats(pv, &ss);
    CHECK(tx_busy > 30000 && rx_busy > 30000, "with 5%% loss the buffers are back (%ld / %ld ms of 40000)", tx_busy, rx_busy);
    CHECK(ss.fec_recovered > 50, "and repair (%u rebuilt)", ss.fec_recovered);
    CHECK(fec_buf_bytes(n.ep[0]) == 0 && fec_buf_bytes(n.ep[1]) == 0, "lossless again 60 s: gone again (%ld / %ld)",
          fec_buf_bytes(n.ep[0]), fec_buf_bytes(n.ep[1]));
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* latency_rtt (DESIGN 8.6): the application waits N round trips - the FEC
 * deadline follows N x min RTT up to max_age, and video a retransmission
 * repairs within it gets no parity */
static void test_latency_rtt(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    uint32_t rep;
    int open, got, err = 0;
    printf("[semi: latency_rtt - the FEC deadline follows the RTT]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.latency_rtt = 3;
    CHECK(anl_stream_open(n.ep[0], &o, &err) == NULL && err == ANL_EINVAL, "reliable stream: refused (%d)", err);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.latency_rtt = 17; err = 0;
    CHECK(anl_stream_open(n.ep[0], &o, &err) == NULL && err == ANL_EINVAL, "17 round trips: refused (%d)", err);
    net_stop(&n);
    /* video, 250 ms RTT, 5% loss, fec_deadline 300 ms: a repair (with the
       second retry the loss asks for) does not fit - parity */
    g_gate_deadline_cfg = 300;
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 1200, 3000, 33, 125, 5, 8000, &rep, &got);
    printf("  video, rtt 250 ms, 5%% loss, deadline 300, max_age 1200:  gate %d, deadline %u ms\n", open, g_gate_deadline);
    CHECK(open == 1 && g_gate_deadline == 300, "configured deadline: parity (%d, %u)", open, g_gate_deadline);
    /* four round trips: about 1000 ms - retransmission only (the last frames
       are still on their way when the run ends) */
    g_gate_latency_rtt = 4;
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 1200, 3000, 33, 125, 5, 8000, &rep, &got);
    printf("  ... latency_rtt 4:  gate %d, deadline %u ms, %d of 243 frames\n", open, g_gate_deadline, got);
    CHECK(open == 0 && g_gate_deadline >= 996 && g_gate_deadline <= 1040, "4 x min RTT: no parity (%d, %u)", open, g_gate_deadline);
    CHECK(got >= 230, "frames delivered by retransmission (%d)", got);
    /* never past max_age: the sender gives the frame up there */
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 800, 3000, 33, 125, 5, 8000, &rep, &got);
    printf("  ... latency_rtt 4, max_age 800:  gate %d, deadline %u ms\n", open, g_gate_deadline);
    CHECK(g_gate_deadline == 800, "capped at max_age (%u)", g_gate_deadline);
    g_gate_deadline_cfg = 0;
    g_gate_latency_rtt = 0;
}

static void test_fec_rtt_default(void)
{
    uint32_t rep;
    int open, got;
    anl_stream_opt o;
    printf("[semi: default FEC gate - one repair against fec_deadline, loss, hysteresis]\n");
    anl_stream_opt_default(&o, ANL_SEMI);
    CHECK(o.fec == ANL_FEC_RTT_AUTO, "semi default is conditional adaptive FEC");
    /* audio, deadline 100 ms: a repair takes 1.5 RTT + detection */
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 200, 160, 20, 140, 5, 6000, &rep, &got);
    printf("  audio, rtt 280 ms, 5%% loss:  gate %d, %u repairs, %d of 300 frames\n", open, rep, got);
    CHECK(open == 1 && rep > 0, "long RTT with loss: parity (gate %d, %u repairs)", open, rep);
    /* the peer does not report (an old peer, report = 0 - or a host whose
       clock had passed 2^31, real network): the gate must not flap on a
       loss estimate that then sees no repairs. 20 s: the old estimate
       decayed below its threshold every 15 s or so */
    g_gate_noreport = 1;
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 200, 160, 20, 140, 5, 20000, &rep, &got);
    g_gate_noreport = 0;
    printf("  ... peer without reports, 20 s: gate %d, on in %d%% of the samples, %u repairs, %d of 1000 frames\n", open, g_gate_open_pct, rep, got);
    CHECK(open == 1 && g_gate_open_pct >= 98, "audio stays protected without peer reports (%d%%)", g_gate_open_pct);
    CHECK(got >= 985, "audio delivered without peer reports (%d of 1000)", got);
    open = run_fec_gate(0, 200, 160, 20, 140, 5, 6000, &rep, &got);
    CHECK(open == 0 && rep == 0, "explicit off: no parity (%d, %u)", open, rep);
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 200, 160, 20, 15, 5, 6000, &rep, &got);
    printf("  audio, rtt 30 ms, 5%% loss:   gate %d, %u repairs\n", open, rep);
    CHECK(open == 0 && rep == 0, "a retransmission makes the deadline: no parity (%d, %u)", open, rep);
    /* the old rule compared srtt with max_age: 280 > 200 opened it without loss */
    /* audio is protected until three loss windows (450 packets, 9 s of
       audio alone) have seen no loss at all, then the gate closes */
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 200, 160, 20, 140, 0, 14000, &rep, &got);
    printf("  audio, rtt 280 ms, no loss, 14 s:  gate %d\n", open);
    CHECK(open == 0, "no loss: no parity however long the RTT (%d)", open);
    /* video, max_age 500 (deadline 250): 250 ms RTT is below max_age - the
       old rule never protected it (real network: video on time 59..84%) */
    open = run_fec_gate(ANL_FEC_RTT_AUTO, 500, 3000, 33, 125, 5, 8000, &rep, &got);
    printf("  video, rtt 250 ms, 5%% loss:  gate %d, %u repairs, %d frames\n", open, rep, got);
    CHECK(open == 1 && rep > 0, "video below max_age but beyond one repair: parity (%d, %u)", open, rep);
#ifdef FEC_GATE_HOLD_MS
    {
        /* the switching rule itself, on a stream without traffic */
        anl_config c; anl_t *w; anl_stream_t *s; int err;
        anl_config_default(&c, ANL_ROLE_CLIENT);
        w = anl_create(1, &c, NULL);
        anl_update(w, 1000);
        o.max_age_ms = 200;                         /* deadline 100 */
        s = anl_stream_open(w, &o, &err);
        CHECK(s != NULL, "open");
        if (s) {
            w->fec_loss_valid = 2; w->fec_loss = 3000;          /* 4.6%, a full window */
            w->fec_loss_ts = w->current | 1;                    /* ... with a loss just now */
            w->rx_srtt = 0; fec_gate_update(w, s);
            CHECK(!ST_ON(s->fc->tx_f, FCT_GATE), "unknown RTT: closed");
            w->rx_srtt = 200; fec_gate_update(w, s);
            CHECK(ST_ON(s->fc->tx_f, FCT_GATE), "repair 300+ ms > 100: open");
            w->rx_srtt = 50; fec_gate_update(w, s);
            CHECK(ST_ON(s->fc->tx_f, FCT_GATE) && fec_repair_ms(w, s, 0, 0, 0) <= 100 && fec_repair_ms(w, s, 0, 0, 0) * 4 >= 300,
                  "between 3/4 deadline and deadline: stays open (repair %u)", fec_repair_ms(w, s, 0, 0, 0));
            w->rx_srtt = 20; fec_gate_update(w, s);
            CHECK(ST_ON(s->fc->tx_f, FCT_GATE), "below 3/4 deadline, but held for 2 s");
            w->current += FEC_GATE_HOLD_MS + 1; fec_gate_update(w, s);
            CHECK(!ST_ON(s->fc->tx_f, FCT_GATE), "... then closed");
            w->current += FEC_GATE_HOLD_MS + 1;
            w->rx_srtt = 200; w->fec_loss = 400; fec_gate_update(w, s);
            CHECK(!ST_ON(s->fc->tx_f, FCT_GATE), "0.6%% loss does not open it");
            w->fec_loss = 700; fec_gate_update(w, s);
            CHECK(ST_ON(s->fc->tx_f, FCT_GATE), "1.1%% loss opens it");
            w->current += FEC_GATE_HOLD_MS + 1;
            w->fec_loss = 400; fec_gate_update(w, s);
            CHECK(ST_ON(s->fc->tx_f, FCT_GATE), "0.6%% loss keeps it open (hysteresis)");
            w->fec_loss = 100; fec_gate_update(w, s);
            CHECK(!ST_ON(s->fc->tx_f, FCT_GATE), "0.15%% loss closes it");
            CHECK(s->mss == w->mss - ANL_FEC_OVERHEAD, "switching never changes the MSS");
        }
        anl_release(w);
    }
#endif
}
