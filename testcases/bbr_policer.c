/* BBR policer, report intervals, delivery windows. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

/* The rate from the peer's reports (rx_bytes) when they cover at least half
 * the interval, ACK-based otherwise; an initial test fed at its rate that
 * delivered under 7/8 of it is repeated once at what it delivered */
static void test_bbr_policer_reports(void)
{
    anl_t w;
    printf("[bbr: policer rate from the peer's reports; one retest below a draining bucket]\n");
    memset(&w, 0, sizeof(w));
    /* watching, 40% lost: the interval's rate becomes prev_rate */
    w.prx_bytes = 600000; w.prx_ms = 400;           /* the reports: 1.5 MB/s over the whole interval */
    ST_SET(w.lt.f, LT_F_PRX); w.prx_at = 401;
    policer_interval(&w, 400, 800000, 0, 0, 300000, 200000);
    CHECK(w.lt.state == LT_WATCH && w.lt.prev_rate == 1500000, "covered by reports: their rate (%u)", w.lt.prev_rate);
    memset(&w, 0, sizeof(w));
    w.prx_bytes = 600000; w.prx_ms = 150;           /* under half the interval */
    ST_SET(w.lt.f, LT_F_PRX); w.prx_at = 401;
    policer_interval(&w, 400, 800000, 0, 0, 300000, 200000);
    CHECK(w.lt.prev_rate == 750000, "too little coverage: ACK-based (%u)", w.lt.prev_rate);

    /* the initial test at 2 MB/s, fed, delivers 1.5 MB/s with 25% lost */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_TESTING; w.lt.from = LT_FROM_INITIAL; w.lt.rate = 2000000; w.lt.ref_loss = 300;
    w.prx_bytes = 450000; w.prx_ms = 300;
    policer_interval(&w, 300, 600000, 0, 0, 450000, 150000);
    CHECK(w.lt.state == LT_TESTING && ST_ON(w.lt.f, LT_F_RETEST) && w.lt.rate == 1500000, "retest at what it delivered (%d, %u)", w.lt.state, w.lt.rate);
    /* ... where the loss is gone: confirmed */
    w.prx_bytes = 0; w.prx_ms = 0;
    w.lt.prx_b0 = w.lt.prx_ms0 = 0;
    w.prx_bytes = 449000; w.prx_ms = 300;
    policer_interval(&w, 300, 450000, 0, 0, 449000, 1000);
    CHECK(w.lt.state == LT_PROBING && w.lt.from == LT_FROM_INITIAL, "the retest passes: probe (%d)", w.lt.state);

    /* random loss over an eighth (15%): the retest fails as well - no further retest */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_TESTING; w.lt.from = LT_FROM_INITIAL; w.lt.rate = 2000000; w.lt.ref_loss = 150;
    w.prx_bytes = 510000; w.prx_ms = 300;
    policer_interval(&w, 300, 600000, 0, 0, 510000, 90000);
    CHECK(w.lt.state == LT_TESTING && ST_ON(w.lt.f, LT_F_RETEST) && w.lt.rate == 1700000, "15%% lost at the test rate: one retest (%u)", w.lt.rate);
    w.lt.prx_b0 = w.lt.prx_ms0 = 0;
    w.prx_bytes = 433500; w.prx_ms = 300;
    policer_interval(&w, 300, 510000, 0, 0, 433500, 76500);
    CHECK(w.lt.state == LT_WATCH && w.lt.hold == 48, "still 15%% lost: random, no second retest (%d, %u)", w.lt.state, w.lt.hold);

    /* an app-limited test that sent under 7/8 of its rate: no retest */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_TESTING; w.lt.from = LT_FROM_INITIAL; w.lt.rate = 1500000; w.lt.ref_loss = 300;
    w.prx_bytes = 80000; w.prx_ms = 300;
    policer_interval(&w, 300, 120000, 0, 0, 80000, 40000);
    CHECK(!ST_ON(w.lt.f, LT_F_RETEST) && w.lt.state == LT_WATCH, "underfed: no retest (%d)", w.lt.state);

    memset(&w, 0, sizeof(w));
    w.lt.state = LT_TESTING; w.lt.from = LT_FROM_INITIAL; w.lt.rate = 1500000; w.lt.ref_loss = 300;
    w.lt.ts = 1; w.current = 301; w.lt.rounds = BBR_LT_ROUNDS - 1;
    w.sent_wire = 120000;
    bbr_policer(&w, 80000, 40000, 1);
    CHECK(w.lt.state == LT_TESTING && ST_ON(w.lt.f, LT_F_FEED_WAIT) && !ST_ON(w.lt.f, LT_F_SKIP) && w.lt.rate == 1500000,
          "underfed media test waits once at the same pace");
    w.current = 601; w.lt.rounds = BBR_LT_ROUNDS - 1; w.sent_wire += 120000;
    bbr_policer(&w, 80000, 40000, 1);
    CHECK(w.lt.state == LT_WATCH && w.lt.hold == BBR_LT_SPAN, "a second underfed interval ends the test");
}

/* Drive real REPORT parsing across a missing-report gap and a new pace.
 * A newly arriving snapshot may cover old traffic; it is only a baseline.
 * Two snapshots from the new interval can measure its delivery instead. */
static void test_bbr_report_intervals(void)
{
    anl_config c; anl_stream_opt o;
    anl_t *w; anl_stream_t *s; int err;
    char buf[128], *p;
    printf("[bbr: missing reports and pace changes cannot reuse old delivery]\n");
    anl_config_default(&c, ANL_ROLE_CLIENT);
    w = anl_create(1, &c, NULL);
    CHECK(w != NULL, "create");
    if (!w) return;
    anl_update(w, 100);
    anl_stream_opt_default(&o, ANL_SEMI);
    s = anl_stream_open(w, &o, &err);
    CHECK(s != NULL, "open");
    if (!s) { anl_release(w); return; }
    CHECK(input_test_report_rx(w, s, 100, 100000) == 0, "old snapshot");
    w->current = 1001; bbr_lt_begin(w, 1);
    w->current = 1301;
    CHECK(input_test_report_rx(w, s, 1300, 2050000) == 0, "report after the gap");
    w->lt.rounds = BBR_LT_ROUNDS - 1;
    w->sent_wire += 250000;
    bbr_policer(w, 150000, 100000, 0);
    CHECK(w->lt.prev_rate == 500000, "one snapshot cannot turn old traffic into this interval's rate (%u)", w->lt.prev_rate);

    w->current = 2001; w->lt.prev_rate = 0; bbr_lt_begin(w, 1);
    w->current = 2051;
    CHECK(input_test_report_rx_echo(w, s, 2000, 2900000, 1900) == 0,
          "delayed snapshot from before the new pace");
    CHECK(!ST_ON(w->lt.f, LT_F_PRX), "arrival after the transition is not proof of a new snapshot");
    w->current = 2101;
    CHECK(input_test_report_rx(w, s, 2100, 3000000) == 0, "new baseline");
    w->current = 2301;
    CHECK(input_test_report_rx(w, s, 2300, 3100000) == 0, "200 ms at 500 kB/s");
    CHECK(input_test_report_rx(w, s, 2200, 3050000) == 0, "reordered snapshot ignored");
    w->current = 2401;
    w->lt.rounds = BBR_LT_ROUNDS - 1;
    w->sent_wire += 250000;
    bbr_policer(w, 150000, 100000, 0);
    CHECK(w->lt.prev_rate == 500000, "two new snapshots recover network delivery despite missing ACK credit (%u)", w->lt.prev_rate);

    w->current = 3001; w->lt.prev_rate = 0; ST_SET(w->lt.f, LT_F_SKIP); w->lt.pace_ts = 3000;
    bbr_policer(w, 100000, 10000, 0);
    CHECK(!ST_ON(w->lt.f, LT_F_PRX), "pace transition discards the report baseline");
    w->current = 3301;
    CHECK(input_test_report_rx(w, s, 3300, 9000000) == 0, "first snapshot after transition");
    w->lt.rounds = BBR_LT_ROUNDS - 1; w->sent_wire += 250000;
    bbr_policer(w, 150000, 100000, 0);
    CHECK(w->lt.prev_rate == 500000, "transition also excludes the old report interval (%u)", w->lt.prev_rate);

    w->current = 20001; bbr_lt_begin(w, 1);
    w->current = 20301;
    w->last_rx = w->current;       /* keepalives continued while reports were idle */
    CHECK(input_test_report_rx(w, s, 20300, 16000000) == 0, "first report after idling");
    w->lt.prev_rate = 0; w->lt.rounds = BBR_LT_ROUNDS - 1; w->sent_wire += 250000;
    bbr_policer(w, 150000, 100000, 0);
    CHECK(w->lt.prev_rate == 500000, "idle time is not a measurement of the resumed path (%u)", w->lt.prev_rate);

    /* a short REPORT is skipped like any short control segment: the rest
       of the datagram (here a full REPORT) still counts */
    {
        uint32_t last0 = w->prx_last, ts0 = w->prx_ts;
        p = plain_hdr(buf, NULL, w->conv, ANL_VERSION << 6, 20400);
        p = enc_sid(p, SEG_CTRL, s->sid); p = enc8(p, CTRL_REPORT); p = enc_varint(p, 16);
        memset(p, 0, 16); p += 16;
        p = enc_sid(p, SEG_CTRL, s->sid); p = enc8(p, CTRL_REPORT); p = enc_varint(p, REPORT_BODY);
        memset(p, 0, REPORT_BODY - 6); p += REPORT_BODY - 6;
        p = enc32(p, 16100000); p = enc16(p, (uint16_t)w->current);
        CHECK(anl_input_plain(w, buf, (long)(p - buf)) == 0, "a short REPORT is skipped, not a format error");
        CHECK(w->prx_last == 16100000 && w->prx_ts != ts0 && last0 != w->prx_last,
              "the full REPORT after it in the same datagram still counts (%u)", w->prx_last);
    }
    anl_release(w);
}

static void test_report_epoch_wrap(void)
{
    anl_config c; anl_stream_opt o; anl_t *w; anl_stream_t *s; int err;
    printf("[reports: sender echo across 16-bit and local 32-bit clock wrap]\n");
    anl_config_default(&c, ANL_ROLE_CLIENT);
    w = anl_create(1, &c, NULL);
    CHECK(w != NULL, "create");
    if (!w) return;
    anl_update(w, 0xffffff00u);
    anl_stream_opt_default(&o, ANL_SEMI);
    s = anl_stream_open(w, &o, &err);
    CHECK(s != NULL, "open");
    if (!s) { anl_release(w); return; }
    CHECK(input_test_report_rx(w, s, 1000, 0) == 0, "initial snapshot");
    w->current = 0xfffffff0u; bbr_lt_begin(w, 1);
    w->current = 0x10;
    CHECK(input_test_report_rx_echo(w, s, 1200, 200000, 0xffffffd0u) == 0, "delayed pre-wrap snapshot");
    CHECK(!ST_ON(w->lt.f, LT_F_PRX), "old phase stays old across wrap");
    w->current = 0x30;
    CHECK(input_test_report_rx_echo(w, s, 1220, 220000, 0x20) == 0 && ST_ON(w->lt.f, LT_F_PRX),
          "post-wrap echo establishes the new baseline");
    w->current = 0x130;
    CHECK(input_test_report_rx_echo(w, s, 1476, 348000, 0x120) == 0, "second eligible snapshot");
    w->current = 0x1f1; w->sent_wire += 250000; w->lt.rounds = BBR_LT_ROUNDS - 1;
    bbr_policer(w, 128000, 50000, 0);
    CHECK(w->lt.prev_rate == 500000, "wrapped interval uses the two new snapshots (%u)", w->lt.prev_rate);
    anl_release(w);
}

static void test_bbr_policer_probes(void)
{
    anl_t w;
    int wrap;
    printf("[bbr: underfed tails, real capacity loss and exhausted probe bursts]\n");
    for (wrap = 0; wrap < 2; wrap++) {
        memset(&w, 0, sizeof(w));
        w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 1; ST_SET(w.lt.f, LT_F_TAIL);
        w.lt.rate = 6006981; w.lt.res = 4; w.lt.span = 16;
        if (wrap) w.sent_wire = 0xfffffc17u;
        /* J1, tr16d_hz2zjg: only 4.46 MB/s sent at a 7.51 MB/s target,
           26 per mille lost; old code lowered the rate to 5256104. */
        policer_interval(&w, 678, 3021818, 770286, 1258346, 2466360, 62186);
        CHECK(w.lt.state == LT_POLICED && w.lt.rate == 6006981, "underfed tail keeps the known rate (wrap=%d)", wrap);
        CHECK(w.lt.left == 16 && w.lt.span == 16, "inconclusive tail does not extend the probe wait");
    }
    /* Same offered load, but a severe real delivery loss must still reduce
       the estimate. A blanket send-rate guard would discard this evidence. */
    w.lt.state = LT_PROBING; ST_SET(w.lt.f, LT_F_TAIL);
    policer_interval(&w, 678, 3021818, 770286, 1258346, 800000, 2000000);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate < 6006981, "lossy capacity drop still lowers the rate");

    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_INITIAL; w.lt.k = 1; ST_SET(w.lt.f, LT_F_TAIL);
    w.lt.rate = 6006981; w.lt.res = 4; w.lt.span = 16;
    policer_interval(&w, 678, 3021818, 770286, 1258346, 2466360, 62186);
    /* the test's rate stands until the next probe (an app-limited media
       stream rarely feeds the tail; giving up left it 3-10x above the policer) */
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 6006981 && w.lt.left == 16,
          "underfed first confirmation keeps the tested rate as the ceiling");

    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 3;
    w.lt.rate = 5256104; w.lt.res = 4; w.lt.span = 32;
    /* J4: k=3 still delivers the burst; at k=4 sending grows, delivery
       falls and loss rises to 192 per mille. Do not accelerate to k=5. */
    policer_interval(&w, 682, 6098444, 1550121, 1568158, 6080526, 0);
    CHECK(w.lt.state == LT_PROBING && w.lt.k == 4 && !ST_ON(w.lt.f, LT_F_TAIL), "delivery follows the probe before the bucket empties");
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt.state == LT_PROBING && w.lt.k == 4 && ST_ON(w.lt.f, LT_F_TAIL), "probe measures the ceiling before further acceleration");

    w.lt.state = LT_PROBING; w.lt.k = 4; ST_CLR(w.lt.f, LT_F_TAIL); w.lt.prev_rate = 8915727;
    w.lt.res = 200;
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt.k == 5 && !ST_ON(w.lt.f, LT_F_TAIL), "delivery dip with residual random loss alone is inconclusive");
    w.lt.k = 4; ST_CLR(w.lt.f, LT_F_TAIL); w.lt.prev_rate = 8915727; w.lt.res = 4;
    policer_interval(&w, 682, 1800000, 0, 0, 1500000, 300000);
    CHECK(w.lt.k == 5 && !ST_ON(w.lt.f, LT_F_TAIL), "reduced offered load does not prove a new ceiling");
    w.min_rtt = 100; w.prev_round_min_rtt = 200;
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt.state == LT_WATCH && w.lt.hold == 48, "long-RTT queued probe still yields immediately to congestion control");

    /* a stall: the first probe step queued, but delivery collapsed under a
       quarter of the rate (real network, 10 Mbit policer at 20 ms: 9..130 kB/s
       for a few hundred ms) - no verdict, the tested rate stands */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_INITIAL; w.lt.k = 1; w.lt.rate = 1200000; w.lt.span = 8;
    w.min_rtt = 20; w.prev_round_min_rtt = 60;
    policer_interval(&w, 300, 30000, 0, 0, 27000, 3000);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 1200000 && w.lt.left == 8, "queued stall in the first probe: tested rate kept (%d, %u)", w.lt.state, w.lt.rate);
    /* STARTUP: two intervals over a quarter lost at the encoder's ramp
       (real network, 1.6 / 2.0 s, 46 / 50 kB/s on a 30 Mbit path) start no
       test; the same after STARTUP do */
    memset(&w, 0, sizeof(w));
    w.bbr_state = ANL_BBR_STARTUP;
    policer_interval(&w, 420, 48000, 0, 0, 19000, 21000);
    policer_interval(&w, 420, 99000, 0, 0, 21000, 29000);
    CHECK(w.lt.state == LT_WATCH, "no policer test in STARTUP (%d)", w.lt.state);
    /* a STARTUP interval is evidence: paired with one after STARTUP, the
       test starts (a 1 MB bucket at 100 ms in simulation, STARTUP's exit
       between the two) */
    memset(&w, 0, sizeof(w));
    w.bbr_state = ANL_BBR_STARTUP;
    policer_interval(&w, 420, 1200000, 0, 0, 680000, 500000);
    w.bbr_state = ANL_BBR_PROBE_BW;
    policer_interval(&w, 420, 1250000, 0, 0, 620000, 600000);
    CHECK(w.lt.state == LT_TESTING, "a pair across STARTUP's exit starts the test (%d)", w.lt.state);
    /* a FIFO's queue: delivery at about the rate - congestion control's */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_INITIAL; w.lt.k = 1; w.lt.rate = 1200000; w.lt.span = 8;
    w.min_rtt = 20; w.prev_round_min_rtt = 60;
    policer_interval(&w, 300, 450000, 0, 0, 360000, 0);
    CHECK(w.lt.state == LT_WATCH && w.lt.hold == 48, "queued probe delivering the rate still yields to congestion control (%d)", w.lt.state);

    /* J8, ab17b_zjg2lsj_v16d: an underfed k=2 tail still loses 152 per
       mille. The low-loss guard must not widen with the nominal probe. */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 2; ST_SET(w.lt.f, LT_F_TAIL);
    w.lt.rate = 3537950; w.lt.res = 1; w.lt.span = 16;
    policer_interval(&w, 321, 623968, 0, 0, 529108, 84320);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3095701, "moderate loss must still allow a rate reduction at k=2");

    /* J4, ab17_hz2zjg_v17: delivery falls 5.2% while loss rises to 149
       per mille. A 1/16 decline threshold continued accelerating here. */
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 1;
    w.lt.rate = 6225626; w.lt.res = 0; w.lt.span = 16;
    policer_interval(&w, 745, 5717950, 1442960, 1434472, 5726382, 0);
    CHECK(w.lt.k == 2 && !ST_ON(w.lt.f, LT_F_TAIL), "probe still advances while delivery follows");
    policer_interval(&w, 759, 6472614, 1629696, 1604232, 5528230, 837930);
    CHECK(w.lt.state == LT_PROBING && w.lt.k == 2 && ST_ON(w.lt.f, LT_F_TAIL), "5.2 percent fall with rising loss stops further acceleration");
}

/* J8: a recovering ceiling can flatten gradually rather than falling by
 * more than 1/32 in any one interval. Do not exhaust the probe at 5x an old
 * low base while its actual delivery has already stopped following it. */
static void test_bbr_policer_plateau(void)
{
    anl_t w;
    int wrap, run, k;
    const uint32_t raw[2][2][6] = {
        { {301, 985490, 4244, 5305, 925412, 59024},
          {300, 1056108, 7427, 1061, 896954, 163370} },
        { {300, 982328, 5305, 8488, 919088, 61132},
          {300, 1052946, 11671, 6366, 893792, 160208} }
    };
    printf("[bbr: recovering ceiling plateaus, residual loss and insufficient probe load]\n");
    for (wrap = 0; wrap < 2; wrap++) for (run = 0; run < 2; run++) {
        const uint32_t (*a)[6] = raw[run];
        memset(&w, 0, sizeof(w));
        w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 10; w.lt.span = 8;
        w.lt.rate = run ? 948950 : 948600;
        if (wrap) w.sent_wire = 0xfffffc17u;
        policer_interval(&w, a[0][0], a[0][1], a[0][2], a[0][3], a[0][4], a[0][5]);
        CHECK(w.lt.k == 11 && !ST_ON(w.lt.f, LT_F_TAIL), "initial slight excess still permits the next step");
        policer_interval(&w, a[1][0], a[1][1], a[1][2], a[1][3], a[1][4], a[1][5]);
        CHECK(w.lt.state == LT_PROBING && w.lt.k == 11 && ST_ON(w.lt.f, LT_F_TAIL),
              "J8 raw run %d stops on flattened delivery (wrap=%d)", run + 1, wrap);
    }
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 1; w.lt.rate = 948600; w.lt.span = 8;
    for (k = 1; k <= BBR_LT_PROBE_MAX && w.lt.state == LT_PROBING && !ST_ON(w.lt.f, LT_F_TAIL); k++) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        uint32_t delivered = umin32(sent, 900000);  /* 3 MB/s, no bucket overshoot */
        policer_interval(&w, 300, sent, 0, 0, delivered, sent - delivered);
    }
    CHECK(w.lt.state == LT_PROBING && ST_ON(w.lt.f, LT_F_TAIL), "a flat ceiling is measured without a delivery dip");
    if (w.lt.state == LT_PROBING && ST_ON(w.lt.f, LT_F_TAIL)) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        policer_interval(&w, 300, sent, 0, 0, 900000, sent - 900000);
        CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3000000, "tail confirms the newly available capacity");
    }
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 11; w.lt.rate = 948600;
    w.lt.prev_rate = 2000000;
    /* Only 2.2 MB/s offered at a 3.56 MB/s target. About 10% loss and a
       near-flat delivery rate cannot establish the path's ceiling. */
    policer_interval(&w, 300, 660000, 0, 0, 594000, 66000);
    CHECK(w.lt.k == 12 && !ST_ON(w.lt.f, LT_F_TAIL), "an underfed plateau does not establish a ceiling");
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 11; w.lt.rate = 750000;
    w.lt.prev_rate = 2300000;
    policer_interval(&w, 300, 840000, 0, 0, 726000, 114000);
    CHECK(w.lt.k == 12 && !ST_ON(w.lt.f, LT_F_TAIL), "delivery still grows with the offered probe");
    memset(&w, 0, sizeof(w));
    w.lt.state = LT_PROBING; w.lt.from = LT_FROM_RETEST; w.lt.k = 1; w.lt.rate = 948600; w.lt.res = 200;
    for (k = 1; k <= BBR_LT_PROBE_MAX && w.lt.state == LT_PROBING; k++) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        uint32_t delivered = sent * 4 / 5;
        policer_interval(&w, 300, sent, 0, 0, delivered, sent - delivered);
        CHECK(!ST_ON(w.lt.f, LT_F_TAIL), "unchanged residual random loss does not set a ceiling (step %d)", k);
    }
    CHECK(w.lt.state == LT_WATCH, "probe budget can still end without a measured ceiling");
}

static void policer_confirmed(anl_t *w)
{
    memset(w, 0, sizeof(*w));
    w->lt.state = LT_POLICED;
    w->lt.rate = 3541495;
    w->lt.res = 2;
    w->lt.left = 32;
    w->lt.span = 64;
}

static void test_bbr_policer_pacing(void)
{
    anl_t w;
    int i;
    static const uint32_t intervals[] = {1, 10, 20};
    printf("[bbr: execute low-rate policer trials below the ordinary pacing floor]\n");
    for (i = 0; i < 3; i++) {
        memset(&w, 0, sizeof(w));
        w.mss = 1368; w.interval = intervals[i]; w.rx_srtt = 1;
        w.pacing_gain = BBR_UNIT; w.btl_bw = 527000;
        /* J12 tcv_v5_f19: the old floor forced 547200 instead of 358360. */
        w.lt.state = LT_TESTING; w.lt.from = LT_FROM_RETEST; w.lt.rate = 358360;
        CHECK(compute_pace_rate(&w) == 358360, "execute the requested trial (interval=%u)", w.interval);
        w.lt.state = LT_POLICED;
        CHECK(compute_pace_rate(&w) == 358360, "keep a confirmed low ceiling");
        w.lt.state = LT_PROBING; w.lt.k = 1;
        CHECK(compute_pace_rate(&w) == 447950, "allow the explicit quarter-rate probe");
        w.lt.k = 4;
        CHECK(compute_pace_rate(&w) == 716720, "probe can discover recovered capacity");
        w.pace_rate_cfg = 100000;
        CHECK(compute_pace_rate(&w) == 100000, "configured rate cap still wins");
    }
    w.pace_rate_cfg = 0; w.lt.state = LT_WATCH; w.interval = 10;
    CHECK(compute_pace_rate(&w) == 547200, "ordinary BBR keeps its pacing floor");
}

static void test_bbr_policer_capacity_change(void)
{
    anl_t w;
    uint32_t trial, left;
    printf("[bbr: verify a lower ceiling, reject random loss, recover the old rate]\n");
    policer_confirmed(&w);
    /* ab20: two stable low-rate intervals after the first mixed interval. */
    policer_interval(&w, 327, 459544, 0, 0, 363630, 95914);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495, "one low interval is inconclusive");
    policer_interval(&w, 329, 462706, 0, 0, 363630, 99076);
    CHECK(w.lt.state == LT_TESTING && w.lt.from == LT_FROM_RETEST && w.lt.rate < 1200000,
          "stable excess loss starts a lower-rate trial");
    CHECK(w.lt.save_btl == 3541495 && ST_ON(w.lt.f, LT_F_SKIP), "trial preserves the confirmed rate and excludes transition");
    trial = w.lt.rate;
    policer_interval(&w, 400, 445600, 0, 0, 445600, 0);
    CHECK(w.lt.state == LT_PROBING && w.lt.from == LT_FROM_RETEST && w.lt.rate == trial && w.lt.span == BBR_LT_SPAN,
          "loss falls at the executed trial rate: verify its ceiling");
    CHECK(w.lt.recover_rate == 3541495, "remember the capacity that may return");
    policer_interval(&w, 400, 556000, 0, 0, 444000, 112000);
    CHECK(ST_ON(w.lt.f, LT_F_TAIL), "excess probe loss starts tail measurement");
    policer_interval(&w, 400, 556000, 0, 0, 444000, 112000);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 1110000 && w.lt.span == BBR_LT_SPAN,
          "confirmed lower ceiling bypasses the old ceiling's 7/8 floor and long backoff");
    w.lt.state = LT_PROBING; w.lt.k = 8; ST_SET(w.lt.f, LT_F_TAIL);
    policer_interval(&w, 400, 1332000, 0, 0, 1300000, 32000);
    CHECK(w.lt.state == LT_POLICED && w.lt.recover_rate == 0 && w.lt.span == 2 * BBR_LT_SPAN,
          "capacity recovered: resume ordinary probe backoff");

    policer_confirmed(&w);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt.state == LT_TESTING, "new 30 percent random loss is suspicious but not yet a lower ceiling");
    left = w.lt.left;
    policer_interval(&w, 400, 992800, 0, 0, 694960, 297840);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495 && w.lt.recover_rate == 0,
          "loss persists after slowing: restore the confirmed ceiling");
    CHECK(w.lt.left == left && w.lt.hold == left && w.lt.span == 64,
          "failed trial preserves the previous probe schedule");
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495, "cooldown prevents repeated trials of unchanged random loss");

    policer_confirmed(&w);
    policer_interval(&w, 327, 459544, 0, 0, 363630, 95914);
    policer_interval(&w, 329, 462706, 0, 0, 363630, 99076);
    policer_interval(&w, 400, 200000, 0, 0, 200000, 0);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495 && w.lt.recover_rate == 0,
          "loss-free but underfed trial does not confirm a capacity fall");

    policer_confirmed(&w);
    policer_interval(&w, 400, 1400000, 0, 0, 900000, 500000);
    policer_interval(&w, 400, 650000, 0, 0, 440000, 210000);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495, "mixed transition and low interval do not form a stable pair");
    policer_interval(&w, 400, 650000, 0, 0, 440000, 210000);
    CHECK(w.lt.state == LT_TESTING, "two subsequent low intervals can start a trial");

    policer_confirmed(&w);
    w.lt.res = 300;
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt.state == LT_POLICED && w.lt.rate == 3541495, "known residual loss is not evidence of a capacity fall");
}

static void test_bbr_policer_residual_refresh(void)
{
    anl_t w;
    uint32_t old_rate, trial_bytes, corrected;
    int scenario, wrap;
    printf("[bbr: remeasure stale residual below the ceiling, preserve real random loss]\n");
    for (wrap = 0; wrap < 2; wrap++) for (scenario = 0; scenario < 4; scenario++) {
        policer_confirmed(&w);
        w.lt.rate = 1040000; w.lt.res = 84; w.lt.left = 1; w.lt.span = 8;
        if (wrap) w.sent_wire = 0xfffffc17u;
        old_rate = w.lt.rate;
        corrected = old_rate * 916 / 1000;
        /* About 7% steady loss no longer exceeds residual+100, so the
           capacity-fall detector cannot repair the old 84-per-mille value. */
        policer_interval(&w, 300, 312000, 0, 0, 290160, 21840);
        CHECK(w.lt.state == LT_TESTING && w.lt.from == LT_FROM_RESIDUAL && w.lt.rate < corrected,
              "periodic probe measures below old delivery, scenario=%d wrap=%d", scenario, wrap);
        trial_bytes = w.lt.rate * 3 / 10;
        if (scenario == 1) {
            /* Real 8.4% random loss persists even below the ceiling. */
            policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes * 916 / 1000, trial_bytes * 84 / 1000);
        } else if (scenario == 2) {
            /* A receive-window/app stall is not a loss-free capacity test. */
            policer_interval(&w, 300, trial_bytes / 2, 0, 0, trial_bytes / 2, 0);
        } else {
            policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes, 0);
            CHECK(w.lt.state == LT_TESTING && w.lt.res == 84, "one quiet interval cannot erase the residual");
            if (scenario == 3) {
                /* A second interval contradicts the first: retain the old value. */
                policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes * 9 / 10, trial_bytes / 10);
            } else {
                policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes, 0);
            }
        }
        CHECK(w.lt.state == LT_PROBING && w.lt.from == LT_FROM_RETEST && w.lt.k == 1 && ST_ON(w.lt.f, LT_F_SKIP),
              "recheck returns to a bounded capacity probe");
        if (scenario == 0) {
            CHECK(w.lt.res == 0 && w.lt.rate == corrected, "remove stale compensation after two clean intervals");
            policer_interval(&w, 300, 357240, 0, 0, 285000, 72240);
            policer_interval(&w, 300, 357240, 0, 0, 285000, 72240);
            CHECK(w.lt.state == LT_POLICED && w.lt.rate == 950000, "probe reconfirms the actual ceiling");
        } else CHECK(w.lt.res == 84 && w.lt.rate == old_rate, "inconclusive recheck preserves residual and ceiling");
        if (scenario == 2) CHECK(!ST_ON(w.lt.f, LT_F_RES_CHECKED), "underfed check remains eligible for a later retry");
    }
    policer_confirmed(&w);
    w.lt.rate = 1040000; w.lt.res = 84; w.lt.left = 1; ST_SET(w.lt.f, LT_F_RES_CHECKED);
    policer_interval(&w, 300, 312000, 0, 0, 285792, 26208);
    CHECK(w.lt.state == LT_PROBING && w.lt.from == LT_FROM_RETEST, "already checked random loss does not delay every capacity probe");
    w.lt.state = LT_POLICED; w.lt.left = 2;
    policer_interval(&w, 300, 312000, 0, 0, 293280, 18720);
    CHECK(w.lt.state == LT_POLICED, "one newly lower-loss interval is inconclusive");
    policer_interval(&w, 300, 312000, 0, 0, 293280, 18720);
    CHECK(w.lt.state == LT_TESTING && w.lt.from == LT_FROM_RESIDUAL, "persistent lower loss permits another residual check");
}

static void test_bbr_policer_queue_recheck(void)
{
    anl_t w;
    int initial;
    printf("[bbr: transient queued interval must not erase an established policer]\n");
    for (initial = 0; initial < 2; initial++) {
        policer_confirmed(&w);
        w.lt.state = LT_PROBING; w.lt.from = initial ? LT_FROM_INITIAL : LT_FROM_RETEST;
        w.lt.k = 1; w.lt.rate = 951805; w.lt.res = 3;
        w.min_rtt = 1; w.prev_round_min_rtt = 20;
        /* j8d pn r5: at k=1 a queue-tainted interval delivered all 344658
           bytes, but old code discarded the ceiling and waited 48 intervals. */
        policer_interval(&w, 301, 344658, 0, 0, 344658, 0);
        if (initial) {
            CHECK(w.lt.state == LT_WATCH, "initial detection still rejects a queued path");
            continue;
        }
        CHECK(w.lt.state == LT_PROBING && w.lt.k == 1 && w.lt.rate == 951805 && !w.lt.hold,
              "repeat the same bounded step after a transient queue signal");
        w.prev_round_min_rtt = 1;
        policer_interval(&w, 301, 344658, 0, 0, 344658, 0);
        CHECK(w.lt.state == LT_PROBING && w.lt.k == 2, "clean next interval resumes capacity discovery");
        w.prev_round_min_rtt = 20;
        policer_interval(&w, 301, 420000, 0, 0, 344658, 75342);
        CHECK(w.lt.state == LT_PROBING && w.lt.k == 2, "nonconsecutive queue events do not count as persistent");
        policer_interval(&w, 301, 420000, 0, 0, 344658, 75342);
        CHECK(w.lt.state == LT_WATCH && w.lt.hold == 48, "consecutive queue evidence still releases the ceiling");
    }
}

/* Frequent ACKs must not evict the history needed to smooth short-RTT
 * samples, including with the default interval and across clock wrap. */
/* Congestive loss (loss + queue signal) on an app-limited round (DESIGN 6.8):
 * bw_lo does not fall below the round's send rate - what the sender needed
 * and the path carried - while the smoothed loss stays under 1/8, and
 * inflight_hi is not bounded by such a round; a network-limited round cuts
 * both as before; an app-limited round with heavy loss (the application
 * offers more than a slower bottleneck) cuts bw_lo as before. */
static void app_limited_round(anl_t *w, int app_limited, uint64_t delivered, uint64_t lost, uint32_t sent, uint32_t loss_rate)
{
    memset(w, 0, sizeof(*w));
    w->interval = 10; w->mss = 1400; w->avg_seg = 1300; w->init_cwnd = 16;
    w->min_rtt = 70; w->min_rtt_ts = 1;
    w->round_min_rtt = 105;                     /* every RTT of the round well above min_rtt: a queue signal */
    w->btl_bw = 250000; w->bw_round[0] = 250000;     /* 0.7x of it is below the 200 kB/s sent */
    w->cwnd = 30;
    w->bbr_state = ANL_BBR_PROBE_BW; w->probe_phase = BBR_CRUISE;
    w->pacing_gain = BBR_UNIT; w->cwnd_gain = BBR_CWND_GAIN;
    w->round_ts = 1000; w->current = 1100;      /* a 100 ms round */
    w->round_sent0 = 5000; w->sent_wire = 5000 + sent;
    w->delivered = delivered; w->lost_bytes = lost;
    w->round_bw = 150000;                       /* its best sample: the application's own rate */
    w->loss_rate = loss_rate;
    bbr_round_end(w, app_limited);
}

static void test_bbr_app_limited_loss(void)
{
    anl_t w;
    uint32_t beta = (uint32_t)(250000ull * BBR_BETA / BBR_UNIT);
    printf("[bbr: congestive loss on an app-limited round keeps the sender's rate]\n");
    /* 8% of an 11-segment round lost, 200 kB/s sent (retransmissions and parities included) */
    app_limited_round(&w, 1, 15000, 1300, 20000, 0);
    CHECK(w.bw_lo == 200000, "app-limited: bw_lo is the round's send rate (%u)", w.bw_lo);
    CHECK(w.inflight_hi == 0, "app-limited: inflight_hi not bounded (%llu)", (unsigned long long)w.inflight_hi);
    CHECK(w.round_sent0 == w.sent_wire, "the next round's send count starts here");
    /* the same round network-limited: the 0.7x cut and the inflight bound as before */
    app_limited_round(&w, 0, 15000, 1300, 20000, 0);
    CHECK(w.bw_lo == beta, "network-limited: bw_lo 0.7x (%u vs %u)", w.bw_lo, beta);
    CHECK(w.inflight_hi != 0 && w.inflight_hi <= 28000, "network-limited: inflight_hi bounded (%llu)", (unsigned long long)w.inflight_hi);
    /* app-limited but 60% lost: the application offers more than the path takes */
    app_limited_round(&w, 1, 6000, 9000, 20000, 0);
    CHECK(w.bw_lo == beta, "app-limited, heavy loss: cut as before (%u)", w.bw_lo);
    CHECK(w.inflight_hi == 0, "app-limited, heavy loss: inflight_hi still not bounded");
    /* app-limited, a mild round, but the smoothed loss already at 16% */
    app_limited_round(&w, 1, 15000, 1300, 20000, 40);
    CHECK(w.bw_lo == beta, "app-limited, loss persisting: cut as before (%u)", w.bw_lo);
    /* the send-rate floor never exceeds what a clean cut would leave when the sender sent less */
    app_limited_round(&w, 1, 15000, 1300, 12000, 0);
    CHECK(w.bw_lo == beta, "app-limited, sent below 0.7x: 0.7x stands (%u)", w.bw_lo);
}

static void test_bbr_delivery_window(void)
{
    static const int intervals[] = { 1, 10, 20, 100, 5000 };
    static const uint32_t starts[] = { 1000, 0xfffffff0u, 0xffffdff0u };
    size_t i, j;
    printf("[bbr: delivery window survives frequent updates and clock wrap]\n");
    for (i = 0; i < sizeof(intervals) / sizeof(intervals[0]); i++) {
        for (j = 0; j < sizeof(starts) / sizeof(starts[0]); j++) {
            anl_t w;
            uint32_t t, span = umax32((uint32_t)intervals[i], 10);
            memset(&w, 0, sizeof(w));
            w.interval = intervals[i];
            for (t = 0; t <= 3 * span; t++) {
                w.current = starts[j] + t;
                w.delivered = (uint64_t)t * 1000;
                bbr_dw_checkpoint(&w);
                bbr_dw_checkpoint(&w);    /* another ACK in the same tick */
            }
            CHECK(bbr_window_bw(&w, span) == 1000000,
                  "interval %d, start %u: window rate %u", w.interval, starts[j], bbr_window_bw(&w, span));
            if (w.interval == 1) {
                bbr_sample rs;
                memset(&rs, 0, sizeof(rs));
                w.min_rtt = 1; w.avg_seg = w.mss = 1000;
                w.next_round_delivered = w.delivered + 1;
                w.delivered_ts = w.current;
                w.delivered += 5000;      /* a compressed ACK at this tick */
                rs.prior_delivered = w.delivered - 5000;
                rs.prior_ts = w.current - 1;
                rs.send_ts = w.current;
                rs.first_sent = w.current - 1;
                bbr_on_ack(&w, &rs);
                CHECK(w.btl_bw <= 2000000, "1 ms updates still smooth compressed ACKs: %u", w.btl_bw);
                rs.app_limited = 1;
                bbr_on_ack(&w, &rs);
                CHECK(w.btl_bw == 5000000, "app-limited bursts retain their rate sample: %u", w.btl_bw);
            }
        }
    }
}

/* a path of about 1 ms (loopback, LAN): min_rtt / 2 is 0, a rate sample's
 * send interval may be 0 too (divided by it once, found on a real network) */
static void test_tiny_rtt(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[40000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, frames = 0, got = 0;
    printf("[tiny rtt: one-way delay 0..1 ms, video 30 fps, 5%% loss]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = 0; n.max_delay = 1;
    n.loss_pct = 5;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 0;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 5000; i++) {
        net_tick(&n);
        if (i % 33 == 0) {
            int len = frames % 30 == 0 ? 30000 : 3000;
            fill_pattern(buf, len, (uint32_t)frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, len, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) got++;
    }
    printf("  %d of %d frames delivered\n", got, frames);
    CHECK(got >= frames * 95 / 100, "frames delivered (%d of %d)", got, frames);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* adaptive FEC on two streams (DESIGN 8.5): audio learns the loss from the
 * connection estimate (video's packets and the peer's repair counts), not
 * only from its own 50 packets/s */
/* Adaptive audio over rtt 280 ms, max_age 200 ms: every frame is abandoned
 * locally before its ACK can return. The old code counted each such expiry
 * as an FEC failure although the peer had the frame (rebuilt, its ACK on
 * the way) and drove the ratio to 100%. Only the peer's skips count now. */
static void run_fec_expiry(int loss, int *ratio, int *got, int *sent, uint32_t *par)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss;
    static char buf[2000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i;
    *got = *sent = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 140;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 0; o.max_age_ms = 200;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.loss_pct = loss;
    for (i = 0; i < 20000; i++) {
        net_tick(&n);
        if (i % 20 == 0) {
            fill_pattern(buf, 160, (uint32_t)*sent);
            if (anl_stream_send_frame(a, 0, buf, 160, NULL) == 0) (*sent)++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) >= 0) (*got)++;
    }
    anl_stream_get_stats(a, &ss);
    *ratio = (int)ss.fec_ratio;
    *par = n.ep[0]->sent_wire;                      /* all bytes: parity dominates the difference */
    net_stop(&n);
}
