/* delay reports, FEC first key / repair / auto. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

/* The first key frame (DESIGN 8.6): the loss rate is not known yet, so with
 * drop_until_key it gets parities. One fragment lost, rtt 300 ms: rebuilt
 * from them about 100 ms after it was sent; a retransmission would come a
 * round trip later. */
/* Delay reports (DESIGN 6.9) on a host whose millisecond clock has passed
 * 2^31: the first interval "started" at 0, in the future by signed
 * comparison - no interval ever closed and the peer got no report (real
 * network, every batch on that host: no repairs in the FEC loss estimate). */
static void test_report_late_clock(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats sa, sb;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    char buf[200];
    int i, sent = 0;
    printf("[delay reports on a host whose clock passed 2^31]\n");
    net_init(&n, &ca, &cb);
    n.now = 0x90000000u;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 0;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 2000; i++) {
        net_tick(&n);
        if (i % 20 == 0) { fill_pattern(buf, 160, (uint32_t)sent); anl_stream_send_frame(a, 0, buf, 160, NULL); sent++; }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) >= 0) ;
    }
    anl_stream_get_stats(a, &sa);
    anl_stream_get_stats(b, &sb);
    CHECK(sb.rx.valid && sb.rx.frames > 0, "the receiver closes measurement intervals (valid %d, %u frames)", sb.rx.valid, sb.rx.frames);
    CHECK(sa.peer.valid && sa.peer.age_ms < 1000, "the sender has a recent report (valid %d, age %u)", sa.peer.valid, sa.peer.age_ms);
    net_stop(&n);
}

static void test_fec_first_key(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss; anl_frame_info fi;
    static char buf[40000];
    anl_stream_t *a, *b;
    uint32_t t0;
    int i, r, ms = -1;
    printf("[fec: the first key frame is protected while loss is unknown, rtt 300 ms]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 150;
    ca.pad_max = cb.pad_max = 0;
    ca.init_cwnd = 32;                              /* the frame fits in the first flight */
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.drop_until_key = 1;                           /* video: max_age 500, deadline 250 */
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.drop_at[0] = (uint32_t)n.sent + 5;            /* the 5th datagram of the key frame */
    t0 = n.now;
    fill_pattern(buf, 26000, 0);
    CHECK(anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 26000, NULL) == 0, "send the key frame");
    for (i = 0; i < 1500 && ms < 0; i++) {
        net_tick(&n);
        if ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            CHECK(r == 26000 && check_pattern(buf, r, 0), "key frame content");
            ms = (int)(n.now - t0);
        }
    }
    anl_stream_get_stats(b, &ss);
    printf("  complete after %d ms (one way 150), rebuilt %u\n", ms, ss.fec_recovered);
    CHECK(ss.fec_recovered >= 1 && ms >= 0 && ms < 150 + 250, "rebuilt from parity within 250 ms of one way (%d ms, %u)", ms, ss.fec_recovered);
    net_stop(&n);
}

/* FEC (DESIGN 8): Reed-Solomon over blocks of up to 100 ms. With rtt 400 ms a
   retransmission takes at least 600 ms; the parities arrive about 300 ms after
   the data - so a frame complete within 400 ms was rebuilt by FEC. m parities
   repair any m lost packets of a block, not only one per group as with XOR. */
static void run_fec_repair(int frags, int ratio, const int *drop, int ndrop, uint32_t *recovered, int *ms)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss; anl_frame_info fi;
    static char buf[20000];
    anl_stream_t *a, *b;
    uint32_t base, t0;
    int i, r, len = frags * 1300;
    *ms = -1;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 200;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = ratio;
    o.max_age_ms = 2000;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 1500; i++) net_tick(&n);        /* srtt settles */
    base = (uint32_t)n.sent;
    t0 = n.now;
    for (i = 0; i < ndrop; i++) n.drop_at[i] = base + (uint32_t)drop[i];
    fill_pattern(buf, len, 7);
    CHECK(anl_stream_send_frame(a, ANL_FRAME_KEY, buf, len, NULL) == 0, "send frame");
    for (i = 0; i < 1000 && *ms < 0; i++) {
        net_tick(&n);
        if ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            CHECK(r == len && check_pattern(buf, r, 7), "frame content");
            *ms = (int)(n.now - t0);
        }
    }
    anl_stream_get_stats(b, &ss);
    *recovered = ss.fec_recovered;
    net_stop(&n);
}

static void test_fec_repair(void)
{
    static const int last[1] = { 3 }, three[3] = { 1, 4, 8 }, burst[4] = { 3, 4, 5, 6 };
    uint32_t rec;
    int ms;
    printf("[fec: Reed-Solomon repair, rtt 400 ms (a retransmission takes >= 600 ms)]\n");
    run_fec_repair(3, 20, last, 1, &rec, &ms);
    printf("  3 fragments, 1 parity, the last fragment lost:       complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 1 && ms >= 0 && ms < 400, "last fragment rebuilt by FEC (%u, %d ms)", rec, ms);
    run_fec_repair(8, 50, three, 3, &rec, &ms);
    printf("  8 fragments, 4 parities, 3 scattered fragments lost: complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 3 && ms >= 0 && ms < 400, "three lost fragments of one block rebuilt (%u, %d ms)", rec, ms);
    run_fec_repair(8, 50, burst, 4, &rec, &ms);
    printf("  8 fragments, 4 parities, a burst of 4 lost:          complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 4 && ms >= 0 && ms < 400, "a burst of four rebuilt (%u, %d ms)", rec, ms);
}

/* adaptive redundancy (fec_ratio 0, DESIGN 8.5): down to the floor on a
 * clean link, up where FEC alone would miss, down again when the loss ends */
static void run_fec_auto(int deadline, int *ratio, int *got, int *frames)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss;
    static char buf[20000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, phase;
    *got = *frames = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 50;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 0; o.fec_deadline_ms = deadline;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (phase = 0; phase < 3; phase++) {
        n.loss_pct = phase == 1 ? 15 : 0;
        for (i = 0; i < 20000; i++) {
            net_tick(&n);
            if (i % 33 == 0) {
                fill_pattern(buf, 6000, (uint32_t)*frames);
                anl_stream_send_frame(a, *frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 6000, NULL);
                (*frames)++;
            }
            while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) (*got)++;
        }
        anl_stream_get_stats(a, &ss);
        ratio[phase] = (int)ss.fec_ratio;
    }
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

static int input_test_report(anl_t *w, anl_stream_t *st, uint32_t ts, uint16_t recovered)
{
    char buf[128], *p;
    int i;
    p = plain_hdr(buf, NULL, w->conv, ANL_VERSION << 6, (uint16_t)ts);
    p = enc_sid(p, SEG_CTRL, st->sid); p = enc8(p, CTRL_REPORT); p = enc_varint(p, REPORT_BODY);
    for (i = 0; i < 7; i++) p = enc16(p, 0);
    p = enc16(p, recovered);
    p = enc32(p, w->prx_last);
    p = enc16(p, (uint16_t)w->current);
    return anl_input_plain(w, buf, (long)(p - buf));
}

/* a REPORT with the connection's rx_bytes after the delay/FEC fields */
static int input_test_report_rx_echo(anl_t *w, anl_stream_t *st, uint32_t ts, uint32_t rx, uint32_t echo)
{
    char buf[128], *p;
    int i;
    p = plain_hdr(buf, NULL, w->conv, ANL_VERSION << 6, (uint16_t)ts);
    p = enc_sid(p, SEG_CTRL, st->sid); p = enc8(p, CTRL_REPORT); p = enc_varint(p, REPORT_BODY);
    for (i = 0; i < 8; i++) p = enc16(p, 0);
    p = enc32(p, rx);
    p = enc16(p, (uint16_t)echo);
    return anl_input_plain(w, buf, (long)(p - buf));
}

static int input_test_report_rx(anl_t *w, anl_stream_t *st, uint32_t ts, uint32_t rx)
{
    return input_test_report_rx_echo(w, st, ts, rx, w->current);
}

/* rx_bytes (DESIGN 6.9): the newest report by the peer's clock moves the
 * connection's count on; older and duplicate reports do not;
 * lost reports are covered by the next one; the count wraps */
static void test_report_rx_bytes(void)
{
    anl_config c;
    anl_stream_opt o;
    anl_t *w;
    anl_stream_t *a, *b;
    int err;
    printf("[reports: rx_bytes - newest only, lost / reordered / duplicate, wrap]\n");
    anl_config_default(&c, ANL_ROLE_CLIENT);
    w = anl_create(1, &c, NULL);
    CHECK(w != NULL, "create connection");
    if (!w) return;
    anl_update(w, 1000);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    CHECK(o.report == 1, "reliable streams report by default");
    anl_stream_opt_default(&o, ANL_SEMI);
    a = anl_stream_open(w, &o, &err); b = anl_stream_open(w, &o, &err);
    CHECK(a && b, "open two streams");
    if (!a || !b) { anl_release(w); return; }
    CHECK(input_test_report_rx(w, a, 100, 0xffff0000u) == 0, "first report");
    CHECK(ST_ON(w->in_f, IN_F_PRX) && w->prx_bytes == 0 && w->prx_ms == 0, "the first report is the baseline");
    CHECK(input_test_report_rx(w, a, 200, 0xffff0000u + 50000) == 0 && w->prx_bytes == 50000 && w->prx_ms == 100,
          "100 ms later, 50000 more (%llu bytes, %llu ms)", (unsigned long long)w->prx_bytes, (unsigned long long)w->prx_ms);
    CHECK(input_test_report_rx(w, a, 150, 0xffff0000u + 30000) == 0 && w->prx_bytes == 50000 && w->prx_ms == 100,
          "a reordered older report changes nothing");
    CHECK(input_test_report_rx(w, a, 200, 0xffff0000u + 50000) == 0 && w->prx_bytes == 50000 && w->prx_ms == 100,
          "a duplicate changes nothing");
    CHECK(input_test_report_rx(w, b, 180, 0xffff0000u + 40000) == 0 && w->prx_bytes == 50000 && w->prx_ms == 100,
          "another stream's report older than the newest changes nothing");
    /* reports at 300 and 400 lost: the next covers them; across the 2^32 wrap */
    CHECK(input_test_report_rx(w, b, 500, 0xffff0000u + 250000) == 0 && w->prx_bytes == 250000 && w->prx_ms == 400,
          "a later report covers the lost ones, across the wrap (%llu bytes, %llu ms)",
          (unsigned long long)w->prx_bytes, (unsigned long long)w->prx_ms);
    anl_release(w);
}

/* rx_bytes counts what arrives from the network, whatever becomes of it:
 * without loss every data and parity segment sent once arrives once (the
 * same estimate as sent_wire); with loss less, never more */
static void test_report_rx_count(int loss_pct)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    static char buf[4000];
    anl_frame_info fi;
    int i;
    printf("[reports: rx_bytes against sent_wire, %d%% loss]\n", loss_pct);
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 40;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 300; o.drop_until_key = 1;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.loss_pct = loss_pct;
    for (i = 0; i < 10000; i++) {
        if (i % 33 == 0) anl_stream_send_frame(a, i % 990 == 0 ? ANL_FRAME_KEY : 0, buf, i % 990 == 0 ? 3000 : 1000, NULL);
        net_tick(&n);
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) >= 0) ;
    }
    n.loss_pct = 0;
    for (i = 0; i < 2000; i++) { net_tick(&n); while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) >= 0) ; }
    printf("  sent_wire %u, rx_bytes %u, reported to the sender %llu over %llu ms\n", n.ep[0]->sent_wire, n.ep[1]->rx_net,
           (unsigned long long)n.ep[0]->prx_bytes, (unsigned long long)n.ep[0]->prx_ms);
    if (loss_pct == 0) CHECK(n.ep[1]->rx_net == n.ep[0]->sent_wire, "no loss: everything sent arrived (%u / %u)", n.ep[1]->rx_net, n.ep[0]->sent_wire);
    else CHECK(n.ep[1]->rx_net < n.ep[0]->sent_wire, "with loss: less arrived than was sent (%u / %u)", n.ep[1]->rx_net, n.ep[0]->sent_wire);
    CHECK(ST_ON(n.ep[0]->in_f, IN_F_PRX) && n.ep[0]->prx_bytes <= n.ep[1]->rx_net && n.ep[0]->prx_ms > 9000,
          "the sender learns it from the reports (%llu bytes over %llu ms)", (unsigned long long)n.ep[0]->prx_bytes, (unsigned long long)n.ep[0]->prx_ms);
    net_stop(&n);
}

static int ordered_report_callbacks;
static void ordered_report_cb(anl_t *w, anl_stream_t *st, const anl_delay_report *r, void *user)
{
    (void)w; (void)st; (void)r; (void)user;
    ordered_report_callbacks++;
}

static void test_fec_report_order(void)
{
    anl_config c;
    anl_stream_opt o;
    anl_t *w;
    anl_stream_t *a, *b;
    anl_stream_stats ss;
    int err;
    printf("[fec reports: reordered counters, duplicate age, lost reports and clock/counter wrap]\n");
    anl_config_default(&c, ANL_ROLE_CLIENT);
    w = anl_create(1, &c, NULL);
    CHECK(w != NULL, "create connection");
    if (!w) return;
    anl_update(w, 1000);
    anl_stream_opt_default(&o, ANL_SEMI); o.fec = 1; o.fec_ratio = 0;
    a = anl_stream_open(w, &o, &err); b = anl_stream_open(w, &o, &err);
    CHECK(a && b, "open report streams");
    if (!a || !b) { anl_release(w); return; }
    ordered_report_callbacks = 0;
    anl_set_report_callback(w, ordered_report_cb);
    CHECK(input_test_report(w, a, 100, 100) == 0, "first report");
    anl_update(w, 1010);
    CHECK(input_test_report(w, a, 200, 101) == 0, "one more recovered loss");
    anl_update(w, 1020);
    CHECK(input_test_report(w, a, 100, 100) == 0, "old datagram remains valid");
    CHECK(a->rpp->peer_rp.fec_recovered == 101 && w->fl_lost == 1, "old report cannot invent a counter wrap");
    CHECK(input_test_report(w, a, 200, 101) == 0, "duplicate datagram remains valid");
    anl_stream_get_stats(a, &ss);
    CHECK(ss.peer.age_ms == 10 && ordered_report_callbacks == 2, "old/duplicate reports do not refresh stats or callbacks");
    CHECK(input_test_report(w, a, 400, 104) == 0, "new report after a missing interval");
    CHECK(w->fl_lost == 4, "cumulative report covers the missed interval");
    /* Each stream has its own ordering. Both 32-bit peer time and the 16-bit
       recovered count wrap, while this connection has seen later times on a. */
    CHECK(input_test_report(w, b, 0xffffff00u, 65534) == 0, "other stream's first report");
    CHECK(input_test_report(w, b, 0x20u, 1) == 0, "new report across both wraps");
    CHECK(input_test_report(w, b, 0xffffff50u, 65535) == 0, "late report from before the wrap");
    CHECK(b->rpp->peer_rp.fec_recovered == 1 && w->fl_lost == 7 && ordered_report_callbacks == 5, "wrap adds three real recoveries only");
    fec_loss_add(w, 200, 0, 0);
    CHECK(w->fec_loss == 7u * 65536u / 200u, "loss estimate uses seven recoveries, not 65536 (%u)", w->fec_loss);
    anl_release(w);
}

/* adaptive redundancy (fec_ratio 0, DESIGN 8.5): down to the floor on a
 * clean link, up where FEC alone would miss the deadline, down again when the
 * loss ends; not up where a retransmission makes the deadline anyway */
static void test_fec_auto(void)
{
    int r[3], tight, got, frames;
    printf("[fec: adaptive redundancy, video 30 fps, rtt 100 ms: 0%% / 15%% / 0%% loss, 20 s each]\n");
    run_fec_auto(100, r, &got, &frames);
    printf("  deadline 100 ms (a retransmission is late): ratio %d%% / %d%% / %d%%, %d of %d frames delivered\n",
           r[0], r[1], r[2], got, frames);
    CHECK(r[0] == FEC_AUTO_MIN, "clean link: down to the floor (%d)", r[0]);
    CHECK(r[1] >= 50, "15%% loss: raised (%d)", r[1]);
    CHECK(r[2] < r[1], "loss over: lowered again (%d)", r[2]);
    tight = r[1];
    run_fec_auto(0, r, &got, &frames);
    printf("  deadline 250 ms (max_age / 2, a retransmission makes it): ratio %d%% / %d%% / %d%%, %d of %d delivered\n",
           r[0], r[1], r[2], got, frames);
    /* raised little if at all: only a lost retransmission (15% of the losses at 15%) is late */
    CHECK(r[1] <= 70 && r[1] < tight, "15%% loss, retransmissions in time: raised less (%d vs %d)", r[1], tight);
    CHECK(got >= frames * 99 / 100, "frames delivered (%d of %d)", got, frames);
}

/* Replay a completed measurement interval. Its transition round has already
 * been excluded. Byte-valued inflight counts reproduce the diagnostic log's
 * estimates exactly without constructing unrelated packet queues. */
static void policer_interval(anl_t *w, uint32_t dur, uint32_t sent,
                             uint32_t infl0, uint32_t infl1, uint64_t delivered, uint64_t lost)
{
    w->lt.ts = 1;
    w->current = dur + 1;
    w->lt.rounds = BBR_LT_ROUNDS - 1;
    ST_CLR(w->lt.f, LT_F_SKIP); w->lt.bad = 0;
    w->lt.rd = w->lt.lost = 0;
    w->lt.sent0 = w->sent_wire;
    w->sent_wire += sent;
    w->lt.infl0 = infl0;
    w->avg_seg = 1;
    w->inflight_segs = infl1;
    bbr_policer(w, delivered, lost, 0);
}
