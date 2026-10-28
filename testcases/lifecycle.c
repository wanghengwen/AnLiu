/* stream lifecycle, sids, options, carrier switch, limits. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

static void test_stream_lifecycle(int loss)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static anl_stream_t *mine[2][LC_N];
    static int got[2][LC_N], sids[2][LC_N];
    static char buf[4000];
    anl_stream_t *list[512];
    int side, i, k, r, iter, all;
    printf("[stream lifecycle: both sides open %d streams, loss=%d%%]\n", LC_N, loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    memset(got, 0, sizeof(got));

    /* client (side 0) gets even sids from 2, server (side 1) odd; tag = index */
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i++) {
            int sid;
            o.tag = side * 1000 + i;
            mine[side][i] = anl_stream_open(n.ep[side], &o, NULL);
            sid = sids[side][i] = anl_stream_id(mine[side][i]);
            CHECK(mine[side][i] && sid > 0 && sid % 2 == side, "auto sid %d on side %d", sid, side);
            fill_pattern(buf, 1000 + i, (uint32_t)(side * 1000 + i));
            CHECK(anl_stream_send(mine[side][i], buf, 1000 + i) == 0, "send on opened stream");
        }

    /* each side reads what the other side opened (identified by tag) and echoes it */
    for (iter = 0, all = 0; iter < 30000 && !all; iter++) {
        net_tick(&n);
        for (side = 0; side < 2; side++) {
            int cnt = anl_readable(n.ep[side], list, 512);
            for (k = 0; k < cnt && k < 512; k++) {
                anl_stream_t *s = list[k];
                int tag = anl_stream_tag(s), opener = tag / 1000, idx = tag % 1000;
                if (s == anl_default_stream(n.ep[side])) continue;
                r = anl_stream_recv(s, buf, sizeof(buf));
                if (r < 0) { CHECK(0, "readable stream sid %d r=%d", anl_stream_id(s), r); continue; }
                if (opener != side) {
                    CHECK(check_pattern(buf, r, (uint32_t)tag), "request content tag %d", tag);
                    CHECK(g_peer[side][anl_stream_id(s)] == s, "accept callback saw this handle");
                    anl_stream_send(s, buf, r);
                } else {
                    CHECK(s == mine[side][idx] && check_pattern(buf, r, (uint32_t)tag), "echo content tag %d", tag);
                    got[side][idx] = 1;
                }
            }
        }
        for (all = 1, side = 0; side < 2; side++) for (i = 0; i < LC_N; i++) all &= got[side][i];
    }
    CHECK(all, "every stream echoed its request");
    CHECK(g_acc[0] == LC_N && g_acc[1] == LC_N, "accept callbacks %d / %d", g_acc[0], g_acc[1]);

    /* every handle is closed by its owner; even i: opener first, odd i: acceptor first */
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i += 2) CHECK(anl_stream_close(mine[side][i]) == 0, "close opener");
    for (side = 0; side < 2; side++)
        for (i = 1; i < LC_N; i += 2) CHECK(anl_stream_close(g_peer[1 - side][sids[side][i]]) == 0, "close acceptor");
    for (iter = 0; iter < 300; iter++) net_tick(&n);
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i++) {
            anl_stream_t *other = g_peer[1 - side][sids[side][i]];
            if (i % 2) CHECK(anl_stream_close(mine[side][i]) == 0, "close opener after the peer");
            else CHECK(anl_stream_close(other) == 0, "close acceptor after the peer");
        }
    for (iter = 0; iter < 20000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); iter++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "all streams freed (%d / %d)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));
    if (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)) { dump_streams("A", n.ep[0]); dump_streams("B", n.ep[1]); }
    for (iter = 0; iter < 20000 && (nclos(n.ep[0]) || nclos(n.ep[1])); iter++) net_tick(&n);
    CHECK(n.ep[0]->nstab == 1 && n.ep[1]->nstab == 1, "only the default stream holds a sid (%u / %u)", n.ep[0]->nstab, n.ep[1]->nstab);
    CHECK(nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "every close confirmed (%u / %u)", nclos(n.ep[0]), nclos(n.ep[1]));
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d ms, both sides empty after the close\n", (int)(n.now - 1000));
    net_stop(&n);
}

/* the hold follows ts_window (DESIGN 6.1): a sid of the peer's rests
 * ts_window + 1 s after its stream went, the opener keeps nothing (it never
 * uses the sid again); a CLOSE nobody answers is given up on, the
 * connection stays alive */
static void test_sid_hold(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    int sid, i;
    anl_stream_t *a, *b, *a2, *b2;
    printf("[sid hold: follows ts_window; CLOSE given up]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    ca.ts_window_ms = cb.ts_window_ms = 3000;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    sid = anl_stream_id(a);
    anl_stream_close(a);
    for (i = 0; i < 1000 && (nclos(n.ep[0]) || stream_state(b) != ANL_STREAM_CLOSED); i++) net_tick(&n);
    anl_stream_close(b);
    CHECK(nclos(n.ep[0]) == 0 && sid_hold_ms(n.ep[0]) == 4000, "closed and confirmed; hold %u ms with a 3 s ts window",
          sid_hold_ms(n.ep[0]));
    CHECK(!sid_held(n.ep[0], sid) && n.ep[0]->nsrec == 0 && sid_held(n.ep[1], sid), "held at the acceptor, nothing kept at the opener");
    for (i = 0; i < 3500; i++) net_tick(&n);
    CHECK(sid_held(n.ep[1], sid), "still held 3.5 s later");
    for (i = 0; i < 600; i++) net_tick(&n);
    CHECK(!sid_held(n.ep[1], sid) && n.ep[1]->nsrec == 0, "hold over at 4 s, the record gone");

    /* a CLOSE never answered: given up after dead_link sends, the connection alive */
    a2 = open_pair(&n, 0, &o, NULL, &b2);
    if (!b2) { net_stop(&n); return; }
    sid = anl_stream_id(a2);
    n.block[0] = 1;
    anl_stream_close(a2);
    for (i = 0; i < 200000 && nclos(n.ep[0]); i++) net_tick(&n);
    CHECK(nclos(n.ep[0]) == 0 && i > 60000 && i < 120000, "CLOSE given up after %d ms", i);
    printf("  CLOSE given up after %d ms\n", i);
    CHECK(anl_state(n.ep[0]) == 0 && n.ep[0]->nsrec == 0, "connection alive, nothing kept (%d, %u)", anl_state(n.ep[0]), n.ep[0]->nsrec);
    n.block[0] = 0;
    anl_stream_close(b2);
    net_stop(&n);
}

/* a path that loses one segment over and over while the rest gets through (a
 * size blackhole: large datagrams lost, small ones not): RACK keeps finding
 * the segment lost from the peer's other ACKs. Its retransmissions back off,
 * so dead_link takes minutes - at a fixed spacing of an RTO it took 20 round
 * trips, and the connection died with the peer alive (real path, 2.7 s) */
/* anl_set_option (ANL_OPT_*): one connection moving between a datagram
 * carrier and a stream carrier */
static uint64_t tx_dg_of(anl_t *w) { anl_stats st; anl_get_stats(w, &st); return st.tx_datagrams; }
static int xfer(net *n, anl_stream_t *a, anl_stream_t *b, int total, uint32_t seed)
{
    static char buf[70000];
    int sent = 0, got = 0, iter, r;
    for (iter = 0; iter < 200000 && got < total; iter++) {
        if (sent < total && anl_stream_waitsnd(a) < 64) {
            int len = total - sent < 5000 ? total - sent : 5000;
            { int i; for (i = 0; i < len; i++) buf[i] = (char)(uint8_t)((seed + (uint32_t)(sent + i)) * 31u + 7u); }
            if (anl_stream_send(a, buf, len) == 0) sent += len;
        }
        net_tick(n);
        while ((r = anl_stream_recv(b, buf, sizeof(buf))) > 0) {
            { int i, bad = 0; for (i = 0; i < r; i++) if (buf[i] != (char)(uint8_t)((seed + (uint32_t)(got + i)) * 31u + 7u)) bad = 1; CHECK(!bad, "content at %d", got); }
            got += r;
        }
    }
    return got == total;
}

static void test_set_option_mtu(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    uint64_t tx;
    printf("[ANL_OPT_MTU: 1200 -> 8000 -> 1200 on a running connection]\n");
    net_init(&n, &ca, &cb);
    ca.mtu = cb.mtu = 1200; ca.mtu_max = cb.mtu_max = 9000;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.stream = 1; o.snd_wnd = 256; o.rcv_wnd = 512;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    CHECK(anl_set_option(n.ep[0], ANL_OPT_MTU, 9001) == ANL_EINVAL, "above mtu_max refused");
    CHECK(anl_set_option(n.ep[0], ANL_OPT_MTU, 100) == ANL_EINVAL, "too small refused");
    n.max_len[0] = 1200;
    CHECK(xfer(&n, a, b, 600000, 1), "1200: delivered");
    tx = tx_dg_of(n.ep[0]);
    CHECK(anl_set_option(n.ep[0], ANL_OPT_MTU, 8000) == 0 && anl_set_option(n.ep[1], ANL_OPT_MTU, 8000) == 0, "grown");
    n.max_len[0] = 0;
    CHECK(xfer(&n, a, b, 600000, 2), "8000: delivered");
    CHECK(tx_dg_of(n.ep[0]) - tx < 600000 / 4000, "large datagrams: few (%llu)", (unsigned long long)(tx_dg_of(n.ep[0]) - tx));
    /* shrink with large segments still queued: they go out as they are cut, the rest at 1200 */
    {
        static char buf[70000];
        int i; for (i = 0; i < 60000; i++) buf[i] = (char)(uint8_t)((3u + (uint32_t)i) * 31u + 7u);
        CHECK(anl_stream_send(a, buf, 60000) == 0, "queue large");
        CHECK(anl_set_option(n.ep[0], ANL_OPT_MTU, 1200) == 0, "shrunk with data queued");
    }
    {
        static char buf[70000];
        int got = 0, r, i;
        for (i = 0; i < 100000 && got < 60000; i++) {
            net_tick(&n);
            while ((r = anl_stream_recv(b, buf + got, (int)sizeof(buf) - got)) > 0) got += r;
        }
        int bad = 0;
        for (i = 0; i < got; i++) if (buf[i] != (char)(uint8_t)((3u + (uint32_t)i) * 31u + 7u)) bad = 1;
        CHECK(got == 60000 && !bad, "old large segments delivered after the shrink (%d)", got);
    }
    n.max_len[0] = 1200;
    CHECK(xfer(&n, a, b, 300000, 4), "1200 again: new segments fit");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "alive");
    net_stop(&n);
}

static void test_set_option_loss(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    anl_stats st;
    printf("[ANL_OPT_FAST_RETRANS / RTO_MIN / CC_IGNORE_LOSS: a carrier with deep queues and a timer that fires]\n");
    net_init(&n, &ca, &cb);
    ca.fast_retrans = 0; ca.rto_min_ms = 400; ca.cc_ignore_loss = 1;
    n.min_delay = 20; n.max_delay = 40; n.loss_pct = 3;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.stream = 1; o.snd_wnd = 512; o.rcv_wnd = 1024;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    CHECK(xfer(&n, a, b, 1500000, 5), "delivered with only the timeout retransmitting");
    anl_get_stats(n.ep[0], &st);
    CHECK(st.rto >= 400, "rto %u >= rto_min", st.rto);
    CHECK(n.ep[0]->lt.state == LT_WATCH, "no policer detection (%d)", n.ep[0]->lt.state);
    CHECK(n.ep[0]->inflight_hi == 0, "no inflight bound");
    CHECK(anl_set_option(n.ep[0], ANL_OPT_RTO_MIN, 800) == 0 && anl_set_option(n.ep[0], ANL_OPT_FAST_RETRANS, 1) == 0 &&
          anl_set_option(n.ep[0], ANL_OPT_CC_IGNORE_LOSS, 0) == 0, "switched back at run time");
    anl_get_stats(n.ep[0], &st);
    CHECK(st.rto >= 800, "rto raised at once (%u)", st.rto);
    CHECK(anl_set_option(n.ep[0], ANL_OPT_FAST_RETRANS, 2) == ANL_EINVAL && anl_set_option(n.ep[0], 99, 0) == ANL_EINVAL, "bad values refused");
    CHECK(xfer(&n, a, b, 300000, 6), "delivered after the switch");
    net_stop(&n);
}

/* anl_stream_fec_pause: no parity while paused, back on resume */
static void test_fec_pause(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss;
    static char buf[20000];
    anl_stream_t *a, *b, *plain;
    anl_frame_info fi;
    uint64_t tx[3];
    int phase, i, f = 0, got = 0, r;
    printf("[fec pause: parity stops and resumes on a running stream]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 50;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    plain = anl_default_stream(n.ep[0]);
    CHECK(anl_stream_fec_pause(plain, 1) == ANL_EMODE, "a stream without FEC: EMODE");
    for (phase = 0; phase < 3; phase++) {
        uint64_t t0 = tx_dg_of(n.ep[0]);
        CHECK(anl_stream_fec_pause(a, phase == 1) == 0, "pause call");
        for (i = 0; i < 3000; i++) {
            net_tick(&n);
            if (i % 30 == 0 && i < 2700) {
                fill_pattern(buf, 6000, (uint32_t)f);
                CHECK(anl_stream_send_frame(a, 0, buf, 6000, NULL) == 0, "send frame");
                f++;
            }
            while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) got++;
        }
        tx[phase] = tx_dg_of(n.ep[0]) - t0;
        anl_stream_get_stats(a, &ss);
        printf("  phase %d: %llu datagrams, fec_ratio %u\n", phase, (unsigned long long)tx[phase], ss.fec_ratio);
        if (phase == 1) CHECK(ss.fec_ratio == 0, "no ratio reported while paused");
    }
    CHECK(tx[1] * 10 < tx[0] * 8, "paused sends fewer datagrams (%llu vs %llu)", (unsigned long long)tx[1], (unsigned long long)tx[0]);
    CHECK(tx[2] * 10 > tx[0] * 9, "resumed sends parity again (%llu vs %llu)", (unsigned long long)tx[2], (unsigned long long)tx[0]);
    CHECK(got == f, "all frames delivered (%d of %d)", got, f);
    net_stop(&n);
}

/* ANL_OPT_CARRIER: UDP -> TCP -> UDP on one connection */
static void test_carrier_switch(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    anl_stats st;
    int v = 0, i, start;
    printf("[carrier switch: datagram -> stream -> datagram, the old path's flight lost]\n");
    net_init(&n, &ca, &cb);
    ca.mtu = cb.mtu = 1200; ca.mtu_max = cb.mtu_max = 9000;
    n.min_delay = n.max_delay = 20;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.stream = 1; o.snd_wnd = 512; o.rcv_wnd = 1024;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    CHECK(anl_set_option(n.ep[0], 77, 0) == ANL_EINVAL, "unknown option");
    CHECK(anl_set_option(n.ep[0], ANL_OPT_CARRIER, 2) == ANL_EINVAL, "unknown carrier");
    CHECK(xfer(&n, a, b, 300000, 7), "datagram carrier");
    CHECK(anl_set_option(n.ep[0], ANL_OPT_CARRIER, ANL_CARRIER_STREAM) == 0 && anl_set_option(n.ep[0], ANL_OPT_MTU, 8000) == 0, "to stream");
    anl_get_option(n.ep[0], ANL_OPT_RTO_MIN, &v);
    CHECK(v >= 1000, "stream rto floor (%d)", v);
    anl_get_option(n.ep[0], ANL_OPT_FAST_RETRANS, &v);
    CHECK(v == 0, "no fast retransmission");
    /* a stream carrier: nothing is lost, queues come and go */
    n.min_delay = 20; n.max_delay = 600;
    CHECK(xfer(&n, a, b, 600000, 8), "stream carrier with queueing delay");
    anl_get_stats(n.ep[0], &st);
    CHECK(n.ep[0]->lt.state == LT_WATCH && n.ep[0]->inflight_hi == 0, "bandwidth model untouched by the delay");
    /* back to datagrams while a flight is in the old path's queue and lost */
    {
        static char buf[70000];
        int got = 0, r, sent = 0;
        for (i = 0; i < 40000; i++) buf[i] = (char)(uint8_t)((9u + (uint32_t)i) * 31u + 7u);
        n.min_delay = n.max_delay = 20;
        n.block[0] = 1;                                 /* the flight dies with the old path */
        while (sent < 40000) { r = anl_stream_send(a, buf + sent, 40000 - sent < 5000 ? 40000 - sent : 5000); if (r != 0) break; sent += 5000; }
        for (i = 0; i < 100; i++) net_tick(&n);
        n.block[0] = 0;
        CHECK(anl_set_option(n.ep[0], ANL_OPT_CARRIER, ANL_CARRIER_DGRAM) == 0 && anl_set_option(n.ep[0], ANL_OPT_MTU, 1200) == 0, "back to datagrams");
        anl_get_option(n.ep[0], ANL_OPT_RTO_MIN, &v);
        CHECK(v == 30, "rto floor restored (%d)", v);
        start = (int)n.now;
        for (i = 0; i < 20000 && got < 40000; i++) {
            net_tick(&n);
            while ((r = anl_stream_recv(b, buf + got, (int)sizeof(buf) - got)) > 0) got += r;
        }
        printf("  recovered %d ms after the switch\n", (int)n.now - start);
        CHECK(got == 40000, "all data delivered (%d)", got);
        CHECK((int)n.now - start < 1500, "lost flight recovered at the datagram RTO, not the stream one (%d ms)", (int)n.now - start);
    }
    net_stop(&n);
}

static void test_rack_repeat_backoff(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    char buf[4000];
    int i, r, got = 0, small = 0;
    printf("[a segment lost over and over while the peer acknowledges the rest: no death in seconds]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 50;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    n.max_len[0] = 300;
    fill_pattern(buf, 3000, 41);
    anl_stream_send(a, buf, 3000);
    for (i = 0; i < 10000; i++) {
        if (i % 20 == 0) anl_send(n.ep[0], "tick", 4);       /* small datagrams: the peer's ACKs go on */
        net_tick(&n);
        while (anl_recv(n.ep[1], buf, sizeof(buf)) == 4) small++;
        if (anl_state(n.ep[0]) < 0) break;
    }
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "alive after 10 s of the large segments lost (%d ms)", i);
    CHECK(small > 400, "the small datagrams got through (%d)", small);
    n.max_len[0] = 0;
    for (i = 0; i < 120000 && got < 3000; i++) {
        net_tick(&n);
        while ((r = anl_stream_recv(b, buf + got, (int)sizeof(buf) - got)) > 0) got += r;
        while (anl_recv(n.ep[1], buf + 3500, 100) > 0) ;
    }
    CHECK(got == 3000 && check_pattern(buf, 3000, 41), "delivered %d ms after the path took them again (%d)", i, got);
    printf("  delivered %d ms after the path came back\n", i);
    net_stop(&n);
}

/* sids (DESIGN 6.1): each open takes the next one of our parity, none is
 * used twice; a sid of the peer's rests 2 s after its stream went, a late
 * first datagram of that stream gets RST, not a new stream */
static void test_sid_lifecycle(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    char buf[2000], pl[64], *q;
    int sid, i, r, acc;
    anl_stream_t *a, *b, *a2, *b2, *a3, *b3;
    printf("[sid lifecycle: the next sid each time, held 2 s after the stream went, late first datagram gets RST]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    n.ep[0]->sid_next = 300;                        /* 2-byte sid encoding */
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    sid = anl_stream_id(a);
    CHECK(sid == 300, "sid 300 (%d)", sid);
    fill_pattern(buf, 1500, 11);
    anl_stream_send(a, buf, 1500);
    for (i = 0, r = -1; i < 500 && r < 0; i++) { net_tick(&n); r = anl_stream_recv(b, buf, sizeof(buf)); }
    CHECK(r == 1500 && check_pattern(buf, r, 11), "data (%d)", r);

    anl_stream_close(a);
    for (i = 0; i < 1000 && (nclos(n.ep[0]) || stream_state(b) != ANL_STREAM_CLOSED); i++) net_tick(&n);
    CHECK(nclos(n.ep[0]) == 0 && stream_state(b) == ANL_STREAM_CLOSED, "closed, the peer dropped it, confirmed");
    anl_stream_close(b);
    CHECK(sid_held(n.ep[1], 300) && n.ep[0]->nsrec == 0, "sid 300 held at the peer, nothing kept here");
    a2 = anl_stream_open(n.ep[0], &o, NULL);
    CHECK(a2 && anl_stream_id(a2) == 302, "the next open takes the next sid (%d)", a2 ? anl_stream_id(a2) : -1);
    for (i = 0; i < 300; i++) net_tick(&n);

    /* the old stream's first datagram (parameters, sn 0) arriving now: RST, nothing created */
    acc = g_acc[1];
    q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
    q = enc_sid(q, SEG_DATA, 300); q = enc8(q, F_OPEN); q = enc24(q, 0);
    q = enc8(q, 0); q = enc16(q, 256); q = enc16(q, 0);       /* open body: reliable, rcv_wnd 256, tag 0 */
    q = enc_varint(q, 4); memcpy(q, "late", 4); q += 4;
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK && g_acc[1] == acc && sget(n.ep[1], 300) == NULL, "late first datagram inside the hold: no stream (%d, %d accepts)",
          r, g_acc[1] - acc);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 1 && stream_count(n.ep[1], NULL) == 1 && sget(n.ep[0], 302) != NULL,
          "only the new stream on either side (%d / %d)", stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));

    /* parameters with the reserved ob bits set, on the default stream and on
       one of the receiver's own sids: the bits are ignored, these go by the mode */
    {
        anl_stream_t *own = open_pair(&n, 1, &o, NULL, &b2), *mine2 = b2;
        q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
        q = enc_sid(q, SEG_DATA, 0); q = enc8(q, F_OPEN); q = enc24(q, (n.ep[1]->dflt->rcv_nxt - 1) & SN_MASK);
        q = enc8(q, (uint8_t)((5 << 2) | OB_STREAM)); q = enc16(q, 4096); q = enc16(q, 0);
        q = enc_varint(q, 0);                                   /* an sn behind rcv_nxt: nothing delivered */
        q = enc_sid(q, SEG_DATA, own ? anl_stream_id(own) : 1); q = enc8(q, F_OPEN); q = enc24(q, 0);
        q = enc8(q, (uint8_t)(9 << 2)); q = enc16(q, 256); q = enc16(q, 0);
        q = enc_varint(q, 0);
        r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
        CHECK(r == ANL_OK && anl_default_stream(n.ep[1])->state != ANL_STREAM_CLOSED, "the default stream stays (%d)", r);
        CHECK(own && stream_state(own) != ANL_STREAM_CLOSED && sget(n.ep[1], anl_stream_id(own)) == own, "our own stream stays");
        CHECK(anl_send(n.ep[1], "dflt", 4) == 0, "send on the default stream");
        for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_recv(n.ep[0], buf, sizeof(buf)); }
        CHECK(r == 4, "default stream works (%d)", r);
        if (own) anl_stream_close(own);
        for (i = 0; i < 1000 && mine2 && stream_state(mine2) != ANL_STREAM_CLOSED; i++) net_tick(&n);
        if (mine2) anl_stream_close(mine2);
    }

    /* the hold over: sid 300 is not used again all the same */
    for (i = 0; i < 2200; i++) net_tick(&n);
    CHECK(!sid_held(n.ep[1], 300), "hold over");
    a3 = open_pair(&n, 0, &o, NULL, &b3);
    CHECK(a3 && anl_stream_id(a3) == 304, "sid 304 (%d)", a3 ? anl_stream_id(a3) : -1);
    if (!b3) { net_stop(&n); return; }
    fill_pattern(buf, 700, 22);
    anl_stream_send(a3, buf, 700);
    for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_stream_recv(b3, buf, sizeof(buf)); }
    CHECK(r == 700 && check_pattern(buf, r, 22), "data on the third stream (%d)", r);

    /* a late RST and a late CLOSE of the stream that went: nothing here
       changes, the CLOSE is answered and the sid rests again */
    q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
    q = enc_sid(q, SEG_CTRL, 300); q = enc8(q, CTRL_RST); q = enc_varint(q, 0);
    q = enc_sid(q, SEG_CTRL, 300); q = enc8(q, CTRL_CLOSE); q = enc_varint(q, 0);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK && sget(n.ep[1], 300) == NULL && sid_held(n.ep[1], 300) && stream_state(b3) == ANL_STREAM_OPEN,
          "late RST / CLOSE of the stream that went: the sid rests, the others stay (%d)", r);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_state(a3) == ANL_STREAM_OPEN && stream_state(b3) == ANL_STREAM_OPEN, "... on both sides");
    anl_stream_send(a3, buf, 700);
    for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_stream_recv(b3, buf, sizeof(buf)); }
    CHECK(r == 700, "data after it (%d)", r);

    /* closed by the acceptor this time: it rests there once the opener's RST confirms, the opener keeps nothing */
    anl_stream_close(b3);
    for (i = 0; i < 1000 && (nclos(n.ep[1]) || stream_state(a3) != ANL_STREAM_CLOSED); i++) net_tick(&n);
    CHECK(nclos(n.ep[1]) == 0 && stream_state(a3) == ANL_STREAM_CLOSED, "the acceptor's close confirmed");
    CHECK(sid_held(n.ep[1], 304) && !sid_held(n.ep[0], 304), "held at the acceptor, not at the opener");
    anl_stream_close(a3);
    a3 = anl_stream_open(n.ep[0], &o, NULL);
    CHECK(a3 && anl_stream_id(a3) == 306, "the next sid, 306 (%d)", a3 ? anl_stream_id(a3) : -1);
    if (a3) anl_stream_close(a3);              /* the OPEN went out at open, the CLOSE right after */
    anl_stream_close(a2);
    b2 = g_peer[1][302];
    for (i = 0; i < 1000 && (nclos(n.ep[0]) || (b2 && stream_state(b2) != ANL_STREAM_CLOSED)); i++) net_tick(&n);
    if (b2) anl_stream_close(b2);
    if (g_peer[1][306]) anl_stream_close(g_peer[1][306]);   /* accepted before the CLOSE came, if at all */
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0 && nclos(n.ep[0]) == 0, "all gone (%d / %d, %u closing)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL), nclos(n.ep[0]));

    /* one 45 s old (between half and a whole wrap of the 16-bit ts) extends
       to a ts in the future: it must not move the window - it did, and every
       genuine datagram after it was stale for 20 s */
    {
        uint64_t stale0 = n.ep[1]->rx_stale;
        q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)(n.now - 45000));
        r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
        CHECK(r == ANL_OK, "45 s old datagram: ts extended into the future (%d)", r);
        fill_pattern(buf, 700, 23);
        anl_send(n.ep[0], buf, 700);
        for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_recv(n.ep[1], buf, sizeof(buf)); }
        CHECK(r == 700 && check_pattern(buf, r, 23) && n.ep[1]->rx_stale == stale0,
              "genuine data right after it (%d, %u stale)", r, (unsigned)(n.ep[1]->rx_stale - stale0));
    }

    /* sid wire format: type(2) | L(1) | F(1) | sid[3:0] [sid >> 4 as a varint]; F with a zero
       or a non-minimal extension is not the one encoding of the sid and drops the datagram */
    {
        int k;
        for (k = 0; k < 2; k++) {
            q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
            q = enc8(q, (uint8_t)((SEG_FWD << 6) | SID_F | (sid & SID_LO_MASK)));
            if (k == 0) q = enc8(q, 0);                     /* zero */
            else { q = enc8(q, (uint8_t)(0x80 | ((sid >> SID_LO_BITS) & 0x7f))); q = enc8(q, 0); }   /* padded */
            q = enc24(q, 0);
            r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
            CHECK(r == ANL_EFORMAT, "non-canonical sid extension %d rejected (%d)", k, r);
        }
    }
    net_stop(&n);
}

/* socket-like lifetime: the peer resets a stream, the handle stays valid */
static void test_handle_lifetime(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    char buf[64];
    int i;
    printf("[handle lifetime: reset by the peer, handle kept after the stream is gone, new stream meanwhile]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    anl_stream_set_user(anl_default_stream(n.ep[0]), &n);
    CHECK(anl_stream_get_user(anl_default_stream(n.ep[0])) == &n && anl_stream_conn(anl_default_stream(n.ep[0])) == n.ep[0], "user / conn");
    n.ep[1]->sid_next = 41;                         /* server opens sid 41 */
    b = open_pair(&n, 1, &o, NULL, &a);
    if (!a) { net_stop(&n); return; }
    anl_stream_send(b, "last words", 10);
    for (i = 0; i < 4000 && anl_stream_waitsnd(b) > 0; i++) net_tick(&n);
    anl_stream_close(b);
    for (i = 0; i < 1000 && stream_state(a) != ANL_STREAM_CLOSED; i++) net_tick(&n);
    CHECK(anl_stream_recv(a, buf, sizeof(buf)) == 10 && memcmp(buf, "last words", 10) == 0, "data before the close is readable");
    CHECK(stream_count(n.ep[0], NULL) == 1 && a->state == ANL_STREAM_CLOSED, "handle held, sid released");
    CHECK(stream_state(a) == ANL_STREAM_CLOSED && anl_stream_recv(a, buf, sizeof(buf)) == ANL_ECLOSED, "handle still answers");
    /* the server opens the next stream while the client still holds the old handle */
    {
        anl_stream_t *a2 = NULL;
        b = open_pair(&n, 1, &o, NULL, &a2);
        CHECK(a2 != NULL && a2 != a && anl_stream_id(a2) == 43 && anl_stream_id(b) == 43, "new stream on sid 43");
    }
    CHECK(stream_count(n.ep[0], NULL) == 2, "new stream next to the old handle (%d)", stream_count(n.ep[0], NULL));
    CHECK(anl_stream_close(g_peer[0][43]) == 0 && anl_stream_close(a) == 0 && stream_count(n.ep[0], NULL) <= 1, "close both");
    net_stop(&n);
}

/* The wire-v1 sequence wrap must preserve real messages and parity recovery,
 * including on a sid that uses the two-byte extension. Seed the
 * empty endpoints near the boundary instead of sending 16 million segments. */
static void test_wire_v1_wrap(int semi)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    char buf[4000];
    uint32_t start = 0xfffff8u;
    int i, r, sent = 0, got = 0;
    printf("[wire v1: extended sid, 24-bit sequence wrap, %s]\n", semi ? "FEC frames" : "reliable");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 25;
    net_start(&n, &ca, &cb);
    n.ep[0]->sid_next = 8192;
    anl_stream_opt_default(&o, semi ? ANL_SEMI : ANL_RELIABLE);
    o.fec = semi; o.fec_ratio = 100;
    if (semi) { o.max_age_ms = 5000; o.rcv_deadline_ms = 0; }
    a = open_pair(&n, 0, &o, &o, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);
    a->snd_una = a->snd_nxt = b->rcv_nxt = start;
    /* One known initial data loss exercises parity, then ordinary 10% loss
       also exercises ACK retries without changing the loss ceiling. */
    n.drop_at[0] = (uint32_t)n.sent + 1;
    n.loss_pct = 10;
    for (i = 0; i < 10000 && (got < 32 || (!semi && anl_stream_waitsnd(a) > 0)); i++) {
        if (sent < 32 && i % 20 == 0) {
            fill_pattern(buf, sizeof(buf), (uint32_t)sent);
            r = semi ? anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) :
                       anl_stream_send(a, buf, sizeof(buf));
            CHECK(r == 0, "enqueue message %d (%d)", sent, r);
            sent++;
        }
        net_tick(&n);
        while ((r = semi ? anl_stream_recv_frame(b, buf, sizeof(buf), &fi) :
                           anl_stream_recv(b, buf, sizeof(buf))) > 0) {
            CHECK(r == (int)sizeof(buf) && check_pattern(buf, r, (uint32_t)got),
                  "message %d intact and in order across the wrap (%d)", got, r);
            if (semi) CHECK(fi.frame_no == (uint32_t)got && fi.lost_before == 0,
                            "frame numbering across sequence wrap");
            got++;
        }
    }
    CHECK(sent == 32 && got == 32, "all messages delivered across wrap (%d/%d)", got, sent);
    CHECK(a->snd_nxt > 0x1000000u && b->rcv_nxt > 0x1000000u, "both crossed 24-bit boundary");
    if (semi) CHECK(b->fec_recovered > 0, "parity actually repaired lost data (%u)", b->fec_recovered);
    else CHECK(anl_stream_waitsnd(a) == 0, "every segment acknowledged across the wrap");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

static void test_accept_limits(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *s[8];
    int i, r, open_ok = 0, refused = 0, err;
    char buf[100];
    printf("[accept: callback reject / options]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    g_acc_reject_mod = 8; g_acc_rcv_wnd = 99;       /* the callback cannot change rcv_wnd */
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.rcv_wnd = 77;
    for (i = 0; i < 8; i++) {
        s[i] = anl_stream_open(n.ep[0], &o, &err);
        CHECK(s[i] && err == 0, "open %d (%d)", i, err);
        anl_stream_send(s[i], "hello", 5);
    }
    for (i = 0; i < 1000; i++) net_tick(&n);
    for (i = 0; i < 8; i++) {
        anl_stream_stats ss;
        anl_stream_get_stats(s[i], &ss);
        if (ss.state == ANL_STREAM_OPEN) {
            anl_stream_t *peer = g_peer[1][anl_stream_id(s[i])];
            open_ok++;
            CHECK(peer && peer->rcv_wnd == 77 && s[i]->rcv_wnd == 77, "rcv_wnd is the opener's on both ends (%u)", peer ? peer->rcv_wnd : 0);
            r = peer ? anl_stream_recv(peer, buf, sizeof(buf)) : -1;
            CHECK(r == 5, "accepted stream delivered (%d)", r);
        } else {
            refused++;
            CHECK(ss.state == ANL_STREAM_CLOSED, "refused stream closed by RST (%d)", ss.state);
            CHECK(anl_stream_send(s[i], "x", 1) == ANL_ECLOSED, "send on refused stream");
        }
    }
    /* the callback refuses sids 2 and 10 */
    CHECK(open_ok == 6 && refused == 2 && g_acc[1] == 6, "6 accepted, 2 refused (%d / %d / cb %d)", open_ok, refused, g_acc[1]);
    CHECK(n.ep[1]->nstab == 7, "server holds 6 peer streams and the default one (%u)", n.ep[1]->nstab);
    o.tag = 70000;
    CHECK(anl_stream_open(n.ep[0], &o, &err) == NULL && err == ANL_EINVAL, "tag out of range");
    net_stop(&n);
}

/* a peer that opens a stream and closes it in the same datagram, over and
 * over, while the application only uses the default stream: the closed
 * handles count against ANL_MAX_STREAMS (DESIGN 6.1), so their structs and
 * what arrived on them stay bounded; once the application releases them,
 * the peer's opens are accepted again */
static void test_closed_handles_bounded(void)
{
    anl_t *w = hostile_victim();
    anl_stats st;
    anl_stream_t *list[ANL_MAX_STREAMS];
    char pl[64], buf[16], *p;
    int i, k, cnt, ok = 1;
    printf("[closed handles: a peer's open + close flood stays bounded]\n");
    if (w == NULL) return;
    for (i = 0; i < 500; i++) {
        p = plain_hdr(pl, NULL, w->conv, ANL_VERSION << 6, (uint16_t)w->current);
        p = hostile_data(p, 2 + 2 * i, 0, 1, 64);
        p = enc_sid(p, SEG_CTRL, 2 + 2 * i); p = enc8(p, CTRL_CLOSE); p = enc_varint(p, 0);
        ok &= anl_input_plain(w, pl, (int)(p - pl)) == ANL_OK;
    }
    anl_get_stats(w, &st);
    CHECK(ok, "500 open + close datagrams taken");
    CHECK(stream_count(w, NULL) == ANL_MAX_STREAMS - 1 && st.streams == 1 && st.streams_held == ANL_MAX_STREAMS - 1,
          "the closed handles fill the table (%d structs, %u + %u held)", stream_count(w, NULL), st.streams, st.streams_held);

    cnt = anl_readable(w, list, ANL_MAX_STREAMS);
    CHECK(cnt == ANL_MAX_STREAMS - 1, "all readable (%d)", cnt);
    for (k = 0; k < cnt && k < ANL_MAX_STREAMS; k++) {
        CHECK(anl_stream_recv(list[k], buf, sizeof(buf)) == 1 && anl_stream_recv(list[k], buf, sizeof(buf)) == ANL_ECLOSED,
              "the byte that came before the close, then ECLOSED");
        anl_stream_close(list[k]);
    }
    p = plain_hdr(pl, NULL, w->conv, ANL_VERSION << 6, (uint16_t)w->current);
    p = hostile_data(p, 2000, 0, 1, 64);
    CHECK(anl_input_plain(w, pl, (int)(p - pl)) == ANL_OK && sget(w, 2000) != NULL, "released: the next open is accepted");
    anl_release(w);
}

/* ANL_MAX_STREAMS streams, both sides' and the default one, hold a sid at once
 * (DESIGN 6.1): an open beyond that is ANL_EBUSY, a peer's open beyond it gets
 * RST, and a stream that is over gives its place back */
static void test_max_streams(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *list[ANL_MAX_STREAMS], *mine[ANL_MAX_STREAMS], *y, *z, *x;
    char buf[64];
    int i, r, k, nopen = 0, nread = 0, iter, err;
    printf("[max streams: %d on a connection]\n", ANL_MAX_STREAMS);
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.snd_wnd = 4; o.rcv_wnd = 4;
    for (;;) {
        anl_stream_t *s = anl_stream_open(n.ep[0], &o, &err);
        if (s == NULL) { CHECK(err == ANL_EBUSY, "a full table: EBUSY (%d)", err); break; }
        mine[nopen++] = s;
        snprintf(buf, sizeof(buf), "s%d", anl_stream_id(s));
        anl_stream_send(s, buf, (int)strlen(buf) + 1);
    }
    CHECK(nopen == ANL_MAX_STREAMS - 1, "%d opens besides the default stream", nopen);
    for (iter = 0; iter < 10000 && nread < nopen; iter++) {
        int cnt;
        net_tick(&n);
        cnt = anl_readable(n.ep[1], list, ANL_MAX_STREAMS);
        for (k = 0; k < cnt && k < ANL_MAX_STREAMS; k++) {
            int sid = anl_stream_id(list[k]);
            r = anl_stream_recv(list[k], buf, sizeof(buf));
            snprintf(buf + 32, 32, "s%d", sid);
            CHECK(r > 0 && strcmp(buf, buf + 32) == 0 && sid % 2 == 0 && g_peer[1][sid] == list[k], "message on sid %d", sid);
            nread++;
        }
    }
    CHECK(nread == nopen, "one message on each stream (%d)", nread);
    CHECK(n.ep[1]->nstab == ANL_MAX_STREAMS, "the peer holds them all (%u)", n.ep[1]->nstab);
    CHECK(anl_stream_open(n.ep[1], &o, &err) == NULL && err == ANL_EBUSY, "nor can the peer open one more (%d)", err);

    /* one closed: a place free on each side. Both sides take it at once, so
       each one's open arrives at a full table and is refused */
    anl_stream_close(g_peer[1][anl_stream_id(mine[0])]);
    anl_stream_close(mine[0]);
    for (iter = 0; iter < 3000 && (stream_count(n.ep[0], NULL) != nopen - 1 || stream_count(n.ep[1], NULL) != nopen - 1 ||
                                   nclos(n.ep[0]) || nclos(n.ep[1])); iter++)
        net_tick(&n);
    CHECK(n.ep[0]->nstab == ANL_MAX_STREAMS - 1 && n.ep[1]->nstab == ANL_MAX_STREAMS - 1, "a place free (%u / %u)",
          n.ep[0]->nstab, n.ep[1]->nstab);
    y = anl_stream_open(n.ep[1], &o, &err);
    z = anl_stream_open(n.ep[0], &o, &err);
    CHECK(y && z, "both open (%d)", err);
    if (y) anl_stream_send(y, "y", 1);
    if (z) anl_stream_send(z, "z", 1);
    for (i = 0; i < 1000; i++) net_tick(&n);
    CHECK(y && z && stream_state(y) == ANL_STREAM_CLOSED && stream_state(z) == ANL_STREAM_CLOSED,
          "both refused by a full peer (%d / %d)", y ? stream_state(y) : -1, z ? stream_state(z) : -1);
    if (y) anl_stream_close(y);
    if (z) anl_stream_close(z);
    CHECK(nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "refused streams are not told again");
    x = anl_stream_open(n.ep[0], &o, &err);
    CHECK(x != NULL, "the place is free again (%d)", err);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(x && stream_state(x) == ANL_STREAM_OPEN && g_peer[1][anl_stream_id(x)] != NULL, "and the peer accepts it (%d)",
          x ? stream_state(x) : -1);
    mine[0] = x;
    for (i = 0; i < nopen; i++) {
        int sid = mine[i] ? anl_stream_id(mine[i]) : 0;
        if (mine[i] == NULL) continue;
        if (g_peer[1][sid]) anl_stream_close(g_peer[1][sid]);
        anl_stream_close(mine[i]);
    }
    for (iter = 0; iter < 20000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); iter++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "all freed (%d / %d)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  closed and freed after %d more ms\n", iter);
    net_stop(&n);
}

/* a proxy's pattern (DESIGN 6.1): streams opened, used and closed for good,
 * thousands of them, with loss and (then) duplicated datagrams. No sid is
 * used twice: a late segment of a stream that went finds no stream */
static void test_sid_churn(int loss, int TOTAL)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    enum { BATCH = ANL_MAX_STREAMS - 1 };
    static anl_stream_t *a[BATCH];
    char buf[3000];
    int i, j, r, done = 0, got = 0, open_fail = 0;
    uint32_t top = 0;
    printf("[sid churn: %d streams opened and closed, %d%% loss%s]\n", TOTAL, loss, loss ? ", 5% duplicated" : "");
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    n.dup_pct = loss ? 5 : 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    while (done < TOTAL) {
        int nb = TOTAL - done < BATCH ? TOTAL - done : BATCH;
        for (j = 0; j < nb; j++) {
            a[j] = anl_stream_open(n.ep[0], &o, NULL);
            if (!a[j]) { open_fail++; continue; }
            fill_pattern(buf, 2500, (uint32_t)anl_stream_id(a[j]));
            anl_stream_send(a[j], buf, 2500);
            top = umax32(top, (uint32_t)anl_stream_id(a[j]));
        }
        for (i = 0; i < 60000; i++) {
            int left = 0;
            net_tick(&n);
            /* the sender closes once everything is acknowledged (or the
               receiver's RST to a retransmission reset the stream) */
            for (j = 0; j < nb; j++)
                if (a[j] && anl_stream_waitsnd(a[j]) == 0) { anl_stream_close(a[j]); a[j] = NULL; }
            {
                anl_stream_t *list[BATCH];
                int k, cnt = anl_readable(n.ep[1], list, BATCH);
                for (k = 0; k < cnt && k < BATCH; k++) {
                    r = anl_stream_recv(list[k], buf, sizeof(buf));
                    CHECK(r == 2500 && check_pattern(buf, r, (uint32_t)anl_stream_id(list[k])), "data on sid %d (%d)",
                          anl_stream_id(list[k]), r);
                    if (r == 2500) got++;
                    anl_stream_close(list[k]);          /* the whole message is here */
                }
            }
            if (stream_count(n.ep[0], &left) == 0 && stream_count(n.ep[1], NULL) == 0 &&
                nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0) break;   /* every place free again */
        }
        if (i == 60000) {
            printf("  batch at %d timed out (%d streams delivered so far)\n", done, got);
            dump_streams("A", n.ep[0]);
            dump_streams("B", n.ep[1]);
        }
        done += nb;
    }
    if (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)) {
        int shown = 0;
        const anl_node *q;
        for (q = n.ep[0]->slist.next; q != &n.ep[0]->slist && shown < 3; q = q->next)
            if (!ST_ON(STREAM_OF(q)->cfg, STC_STRICT)) { shown++; dump_streams("A", n.ep[0]); break; }
        printf("    state %d/%d cwnd %u inflight %u rmt_wnd %u pace %u\n", anl_state(n.ep[0]), anl_state(n.ep[1]),
               n.ep[0]->cwnd, n.ep[0]->inflight_segs, STREAM_OF(n.ep[0]->slist.prev)->rmt_wnd, n.ep[0]->pace_rate);
    }
    printf("  done after %u ms of simulated time\n", n.now - 1000);
    CHECK(open_fail == 0, "every open succeeded (%d failed)", open_fail);
    CHECK(got == TOTAL, "every stream delivered its data (%d / %d)", got, TOTAL);
    /* one sid per stream ever opened */
    CHECK(top == sid_first(ANL_ROLE_CLIENT) + 2u * (uint32_t)(TOTAL - open_fail - 1), "sids never used twice: the highest was %u for %d streams", top, TOTAL);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "all freed (%d / %d)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    /* every hold over, nothing kept; the next open gets the next sid */
    for (i = 0; i < SID_HOLD_MS + 200; i++) net_tick(&n);
    {
        anl_stream_t *x = anl_stream_open(n.ep[0], &o, NULL);
        CHECK(n.ep[0]->nsrec == 0 && n.ep[1]->nsrec == 0, "no record left (%u / %u)", n.ep[0]->nsrec, n.ep[1]->nsrec);
        CHECK(x && anl_stream_id(x) == (int)top + 2, "the next sid (%d)", x ? anl_stream_id(x) : -1);
        if (x) anl_stream_close(x);
    }
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 7. priority: a video stream must not block a control stream
 *-------------------------------------------------------------------*/
static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

typedef struct prio_result { double p50, p99, max; uint32_t sent, got, vframes, vgot; int max_wait; } prio_result;

/* control: reliable 200 B every 50 ms, on the default stream (ctrl_prio < 0)
 * or on its own stream; video: semi 30 fps, I 40 KB / P 15 KB (~3.6 Mbps)
 * over a 3 Mbps bottleneck; video = 0 runs the control stream alone.
 * capped: BBR with cfg.pace_rate = 2.8 Mbps, below the link (a known uplink
 * quota): no queue builds at the bottleneck - the latency floor for control. */
static void run_priority(int ctrl_prio, int video_prio, int video, int nc, prio_result *res)   /* nc: rate capped */
{
    net n; anl_config ca, cb; anl_stream_opt oc, ov;
    static char buf[70000];
    static uint32_t lat[2000];
    static char rec[8192];
    uint32_t nlat = 0, ctrl_seq = 0, vseq = 0, vgot = 0;
    int i, r, nrec = 0;
    const int T = 20000;
    anl_stream_t *cs, *cr, *vs = NULL, *vr = NULL;

    res->max_wait = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    n.loss_pct = 1;
    n.bandwidth_bps = 3000000; n.queue_limit = 40;
    if (nc) ca.pace_rate = 350000;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&oc, ANL_RELIABLE);
    oc.prio = ctrl_prio < 0 ? 0 : ctrl_prio; oc.flush_on_send = 1;
    anl_stream_opt_default(&ov, ANL_SEMI);
    ov.prio = video_prio; ov.max_age_ms = 500; ov.drop_until_key = 1;
    if (ctrl_prio < 0) { cs = anl_default_stream(n.ep[0]); cr = anl_default_stream(n.ep[1]); }
    else cs = open_pair(&n, 0, &oc, NULL, &cr);
    if (video) vs = open_pair(&n, 0, &ov, NULL, &vr);
    if (!cr || (video && !vr)) { net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);

    for (i = 0; i < T; i++) {
        uint32_t now = n.now;
        net_tick(&n);
        if (i % 50 == 0 && i < T - 1500) {           /* last 1.5 s: drain what is in flight */
            memset(buf, 0, 200);
            memcpy(buf, &ctrl_seq, 4); memcpy(buf + 4, &now, 4);
            /* message framing on the (byte stream) default stream: fixed 200 B records */
            CHECK(anl_stream_send(cs, buf, 200) == 0, "control send");
            ctrl_seq++;
        }
        if (video && i % 33 == 0 && i < T - 1500) {
            int key = vseq % 30 == 0, len = key ? 40000 : 15000;
            fill_pattern(buf, len, vseq);
            r = anl_stream_send_frame(vs, key ? ANL_FRAME_KEY : 0, buf, len, NULL);
            CHECK(r == 0 || r == ANL_EDROPPED, "video send %d", r);
            vseq++;
        }
        if ((int)cs->nsnd_que > res->max_wait) res->max_wait = (int)cs->nsnd_que;
        /* a byte stream may return several records at once: reassemble 200 B records */
        while ((r = anl_stream_recv(cr, rec + nrec, (int)sizeof(rec) - nrec)) > 0) {
            int off = 0;
            nrec += r;
            for (; nrec - off >= 200; off += 200) {
                uint32_t t0;
                memcpy(&t0, rec + off + 4, 4);
                if (nlat < 2000) lat[nlat++] = n.now - t0;
            }
            memmove(rec, rec + off, (size_t)(nrec - off));
            nrec -= off;
        }
        CHECK(r == ANL_EAGAIN, "control recv %d", r);
        if (video) {
            anl_frame_info fi;
            while ((r = anl_stream_recv_frame(vr, buf, sizeof(buf), &fi)) > 0) vgot++;
        }
    }
    qsort(lat, nlat, sizeof(uint32_t), cmp_u32);
    res->p50 = nlat ? lat[nlat / 2] : 0;
    res->p99 = nlat ? lat[(nlat - 1) * 99 / 100] : 0;
    res->max = nlat ? lat[nlat - 1] : 0;
    res->sent = ctrl_seq; res->got = nlat; res->vframes = vseq; res->vgot = vgot;
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}
