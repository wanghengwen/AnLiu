/* reflection, replay, violations, close, pacing, demux, fuzz. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

/*---------------------------------------------------------------------
 * 4. reflection, stale replay, protocol violation, close, pacing, demux
 *-------------------------------------------------------------------*/
static void test_reflect(void)
{
    net n; anl_config ca, cb; anl_stats st;
    char buf[100];
    int i;
    printf("[reflect]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    for (i = 0; i < 200; i++) net_tick(&n);
    n.reflect = 1;
    for (i = 0; i < 20; i++) { fill_pattern(buf, 100, (uint32_t)i); anl_send(n.ep[0], buf, 100); }
    for (i = 0; i < 1000; i++) net_tick(&n);
    anl_get_stats(n.ep[0], &st);
    CHECK(st.rx_auth_fail > 0, "reflected packets fail auth (%llu)", (unsigned long long)st.rx_auth_fail);
    CHECK(anl_peeksize(n.ep[0]) == ANL_EAGAIN, "reflected data not accepted");
    net_stop(&n);
}

/* datagram pn (DESIGN 4.3): a datagram taken once is not taken again, nor
 * one more than PN_WIN behind the largest; one reordered inside the window
 * is; the ts window still drops a datagram sent long ago */
static void test_replay(void)
{
    net n; anl_config ca, cb; anl_stats st;
    char buf[100], pl[64], *q;
    int i, r;
    uint32_t pn, pn_max;
    printf("[replay: pn window, ts window]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 5;
    net_start(&n, &ca, &cb);
    for (i = 0; i < 100; i++) net_tick(&n);
    fill_pattern(buf, 100, 1);
    n.cap_len = 0;
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(n.cap_len > 0 && anl_recv(n.ep[1], buf, sizeof(buf)) == 100, "captured and delivered a datagram");
    r = anl_input(n.ep[1], n.cap, n.cap_len);
    anl_get_stats(n.ep[1], &st);
    CHECK(r == ANL_EREPLAY && st.rx_replay == 1, "the same datagram again: a replay (%d, %llu)", r, (unsigned long long)st.rx_replay);
    CHECK(anl_recv(n.ep[1], buf, sizeof(buf)) == ANL_EAGAIN, "nothing delivered by it");

    /* a pn skipped by the sender, arriving after later ones: reordering, taken once */
    pn = n.ep[0]->tx_pn++;
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(anl_recv(n.ep[1], buf, sizeof(buf)) == 100 && tdiff(n.ep[1]->rx_pn_max, pn) > 0, "later datagrams taken first");
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK, "reordered inside the window: taken (%d)", r);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY, "... once (%d)", r);

    /* PN_WIN or more behind the largest: dropped unseen, whatever its ts */
    pn_max = n.ep[1]->rx_pn_max;
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn_max - PN_WIN);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY, "below the window (%d)", r);
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn_max - PN_WIN + 1);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK, "the oldest pn inside the window (%d)", r);
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn_max - 0x80000000u);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY, "half the pn circle behind (%d)", r);

    /* a fresh pn with a ts 3 s back: the ts window (DESIGN 4.2) */
    q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)(n.now - 3000));
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    anl_get_stats(n.ep[1], &st);
    CHECK(r == ANL_ESTALE && st.rx_stale == 1, "old ts, new pn: stale (%d)", r);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_ESTALE, "a stale datagram's pn is not taken: stale again, not a replay (%d)", r);

    /* a jump of more than PN_WIN ahead (the sender went on while nothing
       arrived here): taken, everything behind the new window is out */
    pn = n.ep[0]->tx_pn + 2 * PN_WIN;
    n.ep[0]->tx_pn = pn + 1;
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK && n.ep[1]->rx_pn_max == pn, "a jump ahead taken (%d)", r);
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn_max + 1);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY, "what the jump left behind is out (%d)", r);
    fill_pattern(buf, 100, 2);
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(anl_recv(n.ep[1], buf, sizeof(buf)) == 100 && check_pattern(buf, 100, 2), "the connection goes on after the jump");

    /* ahead is at most PN_AHEAD up, not half the circle: past 2^31 datagrams
       pn 0 (a replay of the first ones, or a restart) is behind, not new */
    pn_max = n.ep[1]->rx_pn_max;
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, pn_max + PN_AHEAD + 1);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY && n.ep[1]->rx_pn_max == pn_max, "further than PN_AHEAD up: out (%d)", r);
    n.ep[0]->tx_pn = 0x90000000u;
    anl_send(n.ep[0], buf, 100);
    n.ep[1]->rx_pn_max = 0x90000000u - 1;              /* as if 2.4e9 datagrams had come before */
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(anl_recv(n.ep[1], buf, sizeof(buf)) == 100 && n.ep[1]->rx_pn_max == 0x90000000u, "pn past 2^31 taken");
    q = pl; q = enc32(q, 0x11223344); q = enc8(q, ANL_VERSION << 6); q = enc16(q, (uint16_t)n.now); q = enc32(q, 0);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_EREPLAY, "pn 0 after 2^31: out (%d)", r);
    n.ep[0]->tx_pn = 0xffffffffu;
    n.ep[1]->rx_pn_max = 0xffffffffu - 1;
    fill_pattern(buf, 100, 3);
    anl_send(n.ep[0], buf, 100);
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(anl_recv(n.ep[1], buf, sizeof(buf)) == 100 && anl_recv(n.ep[1], buf, sizeof(buf)) == 100 && n.ep[1]->rx_pn_max < 16,
          "the pn wraps on (%u)", n.ep[1]->rx_pn_max);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* a peer that sends FWD on a reliable stream puts it into the error state */
static void test_violation(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    char pl[32], *q = pl, buf[16];
    int i, r;
    printf("[protocol violation: FWD on a reliable stream]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
    q = enc_sid(q, SEG_FWD, anl_stream_id(b));
    q = enc24(q, 5);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK, "input (%d)", r);
    CHECK(stream_state(b) == ANL_STREAM_CLOSED, "B stream reset (%d)", stream_state(b));
    CHECK(anl_stream_recv(b, buf, sizeof(buf)) == ANL_ECLOSED, "recv on reset stream");
    CHECK(anl_stream_send(b, "x", 1) == ANL_ECLOSED, "send on reset stream");
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_state(a) == ANL_STREAM_CLOSED, "A got the RST (%d)", stream_state(a));
    CHECK(anl_stream_send(a, "x", 1) == ANL_ECLOSED, "send after RST");
    CHECK(anl_stream_close(b) == 0 && anl_stream_close(a) == 0, "both handles released");
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "both freed");
    CHECK(anl_send(n.ep[0], "ok", 2) == 0 && anl_state(n.ep[0]) == 0, "connection survives");
    net_stop(&n);
}

/* The default stream cannot be closed by either side (anliu.h): a segment
   breaking its rules - what resets any other stream - is dropped, and sid 0
   keeps working with its byte stream intact (DESIGN 6.1) */
static void test_default_violation(void)
{
    static const char *what[4] = { "DATA with a frame number", "FWD", "OPEN declaring semi-reliable",
                                   "OPEN declaring a message stream" };
    net n; anl_config ca, cb;
    char pl[64], *q, buf[3000];
    int v, i, r;
    uint64_t seed0 = g_seed;        /* restored at the end: later tests see the random sequence as before */
    printf("[protocol violation on the default stream: dropped, sid 0 stays]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    for (v = 0; v < 4; v++) {
        uint32_t nxt0 = n.ep[1]->dflt->rcv_nxt, sn = nxt0 & SN_MASK;   /* the next byte-stream slot */
        q = plain_hdr(pl, n.ep[0], 0x11223344, ANL_VERSION << 6, (uint16_t)n.now);
        if (v == 0) {
            q = enc_sid(q, SEG_DATA, 0); q = enc8(q, F_HAS_FRAME); q = enc24(q, sn);
            q = enc16(q, 0); q = enc_varint(q, 4); memcpy(q, "evil", 4); q += 4;
        } else if (v == 1) {
            q = enc_sid(q, SEG_FWD, ANL_SID_DEFAULT); q = enc24(q, (sn + 5) & SN_MASK);
        } else {
            q = enc_sid(q, SEG_DATA, 0); q = enc8(q, F_OPEN); q = enc24(q, sn);
            q = enc8(q, v == 2 ? OB_SEMI : 0); q = enc16(q, 4096); q = enc16(q, 0);
            q = enc_varint(q, 4); memcpy(q, "evil", 4); q += 4;
        }
        r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
        CHECK(r == ANL_OK, "%s: input (%d)", what[v], r);
        CHECK(sget(n.ep[1], ANL_SID_DEFAULT) == n.ep[1]->dflt && n.ep[1]->dflt->state != ANL_STREAM_CLOSED,
              "%s: the default stream stays (state %d)", what[v], n.ep[1]->dflt->state);
        CHECK(n.ep[1]->dflt->rcv_nxt == nxt0 && QEMPTY(&n.ep[1]->dflt->rcv_buf) && anl_peeksize(n.ep[1]) == ANL_EAGAIN,
              "%s: nothing of it stored", what[v]);
        /* both directions still carry the byte stream, unchanged */
        fill_pattern(buf, 2500, (uint32_t)v);
        CHECK(anl_send(n.ep[0], buf, 2500) == 0 && anl_send(n.ep[1], buf, 2500) == 0, "%s: send on sid 0", what[v]);
        for (i = 0, r = 0; i < 1000 && r < 2500; i++) {
            int k;
            net_tick(&n);
            while ((k = anl_recv(n.ep[1], buf + r, (int)sizeof(buf) - r)) > 0) r += k;
        }
        CHECK(r == 2500 && check_pattern(buf, r, (uint32_t)v), "%s: bytes arrive intact (%d)", what[v], r);
        for (i = 0, r = 0; i < 1000 && r < 2500; i++) {
            int k;
            net_tick(&n);
            while ((k = anl_recv(n.ep[0], buf + r, (int)sizeof(buf) - r)) > 0) r += k;
        }
        CHECK(r == 2500 && check_pattern(buf, r, (uint32_t)v), "%s: and back (%d)", what[v], r);
    }
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connection alive");
    net_stop(&n);
    g_seed = seed0;
}

/* segments cut before the peer answered carry the stream parameters and are
   OPEN_BODY smaller; later ones use the full connection mss (DESIGN 5.2) */
static void test_seg_size(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[4 * 1400];
    anl_stream_t *a, *b = NULL;
    uint32_t mss, before;
    int i, r, got = 0;
    printf("[segment size before / after the peer answered]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    mss = n.ep[0]->mss;
    CHECK(mss == (uint32_t)ca.mtu - ANL_OVERHEAD - DATA_HDR_MAX, "connection mss %u excludes the stream parameters", mss);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = anl_stream_open(n.ep[0], &o, NULL);
    CHECK(a && a->state == ANL_STREAM_OPENING, "peer not heard yet");
    fill_pattern(buf, (int)mss, 0);
    CHECK(anl_stream_send(a, buf, (int)mss) == 0 && a->nsnd_que == 2, "mss bytes before the answer: 2 segments (%u)", a->nsnd_que);
    CHECK(qfirst_seg(&a->snd_queue)->len == mss - OPEN_BODY, "first segment mss - OPEN_BODY");
    for (i = 0; i < 3000 && a->state == ANL_STREAM_OPENING; i++) net_tick(&n);
    CHECK(a->state == ANL_STREAM_OPEN, "peer answered");
    fill_pattern(buf, 3 * (int)mss, 1);
    before = a->nsnd_que + a->nsnd_buf;
    r = anl_stream_send(a, buf, 3 * (int)mss);
    CHECK(r == 0 && a->nsnd_que + a->nsnd_buf - before == 3, "3 * mss bytes after the answer: 3 segments (%u)", a->nsnd_que + a->nsnd_buf - before);
    for (i = 0; i < 3000 && got < 2; i++) {
        anl_stream_t *list[4];
        int k, cnt;
        net_tick(&n);
        cnt = anl_readable(n.ep[1], list, 4);
        for (k = 0; k < cnt && k < 4; k++) {
            if (list[k] == anl_default_stream(n.ep[1])) continue;
            b = list[k];
            while ((r = anl_stream_recv(b, buf, sizeof(buf))) > 0) {
                CHECK(r == (int)mss * (got ? 3 : 1) && check_pattern(buf, r, (uint32_t)got), "message %d intact (%d)", got, r);
                got++;
            }
        }
    }
    CHECK(got == 2, "both messages delivered (%d)", got);
    net_stop(&n);
}

/* close is local (DESIGN 6.1): the opener sends, waits until everything is
 * acknowledged and closes. Nothing goes to the peer, which keeps its end; its
 * next segment for the stream gets RST */
/* a closed stream's peer is told (DESIGN 6.1): its end is over, the data it
 * had received in order stays readable, then ECLOSED; the closer's place is
 * held until the peer's RST confirms */
static void test_close_notify(int loss)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stats st;
    char buf[5000];
    int i, got = 0, r = 0, t_close;
    anl_stream_t *a, *b;
    printf("[close: the peer is told, unread data stays readable, loss=%d%%]\n", loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.tag = 4242;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 10; i++) { fill_pattern(buf, 4000, (uint32_t)i); CHECK(anl_stream_send(a, buf, 4000) == 0, "send"); }
    for (i = 0; i < 20000 && anl_stream_waitsnd(a) > 0; i++) net_tick(&n);
    CHECK(anl_stream_waitsnd(a) == 0 && anl_stream_tag(b) == 4242, "all 10 messages acknowledged, none read yet");
    t_close = (int)n.now;
    CHECK(anl_stream_close(a) == 0 && stream_count(n.ep[0], NULL) == 0, "closed, handle gone at once");
    anl_get_stats(n.ep[0], &st);
    CHECK(st.streams == 1 && st.streams_closing == 1, "the place is held until the peer confirms (%u / %u)",
          st.streams, st.streams_closing);
    for (i = 0; i < 20000 && (stream_state(b) != ANL_STREAM_CLOSED || nclos(n.ep[0]) > 0); i++) net_tick(&n);
    CHECK(stream_state(b) == ANL_STREAM_CLOSED, "the peer's end is over (%d)", stream_state(b));
    CHECK(nclos(n.ep[0]) == 0, "the peer's RST confirmed it, %d ms after the close", (int)n.now - t_close);
    CHECK(n.ep[1]->nstab == 1 && stream_count(n.ep[1], NULL) == 1, "the peer's place is free, its handle kept");
    CHECK(anl_stream_send(b, "y", 1) == ANL_ECLOSED, "send: ECLOSED");
    while ((r = anl_stream_recv(b, buf, sizeof(buf))) > 0) { CHECK(r == 4000 && check_pattern(buf, r, (uint32_t)got), "content %d", got); got++; }
    CHECK(got == 10 && r == ANL_ECLOSED, "the 10 messages read after the close, then ECLOSED (%d, %d)", got, r);
    CHECK(anl_stream_peeksize(b) == ANL_ECLOSED, "peeksize: ECLOSED");
    anl_stream_close(b);                    /* over already: nothing to tell */
    CHECK(stream_count(n.ep[1], NULL) == 0 && nclos(n.ep[1]) == 0, "freed after close, no CLOSE of its own");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  confirmed %d ms after the close\n", (int)n.now - t_close);
    net_stop(&n);
}

/* the CLOSE handshake under one-way outages (DESIGN 6.1): the closer holds
 * its place until the peer's RST, so an open after a close never reaches a
 * peer still full; a lost CLOSE or RST is repeated; a stream closed before
 * the peer heard of it is never created there; both sides closing at once */
static void test_close_confirm(int loss)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stats st;
    anl_stream_t *mine[ANL_MAX_STREAMS], *s, *x;
    char buf[64];
    int i, k, nopen = 0, err, sid, acc;
    uint32_t rto0;
    printf("[close confirmed by the peer's RST, one-way outages, loss=%d%%]\n", loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.snd_wnd = 4; o.rcv_wnd = 4;

    /* a full table on both sides, all opened here */
    while ((s = anl_stream_open(n.ep[0], &o, &err)) != NULL) {
        mine[nopen++] = s;
        anl_stream_send(s, "m", 1);
    }
    for (i = 0; i < 20000; i++) {
        net_tick(&n);
        for (k = 0; k < nopen && g_peer[1][mine[k]->sid] && mine[k]->state == ANL_STREAM_OPEN; k++) ;
        if (k == nopen) break;
    }
    CHECK(nopen == ANL_MAX_STREAMS - 1 && n.ep[1]->nstab == ANL_MAX_STREAMS, "both tables full (%d / %u)", nopen, n.ep[1]->nstab);

    /* 1. the CLOSE is lost for 3 s: the place stays taken here */
    n.block[0] = 1;
    sid = anl_stream_id(mine[0]);
    anl_stream_close(mine[0]);
    mine[0] = NULL;
    rto0 = 0;
    for (i = 0; i < 3000; i++) { net_tick(&n); if (i == 0) rto0 = srec_find(n.ep[0], sid)->rto; }
    anl_get_stats(n.ep[0], &st);
    CHECK(st.streams == ANL_MAX_STREAMS - 1 && st.streams_closing == 1, "closing: %u streams + %u closing", st.streams, st.streams_closing);
    CHECK(anl_stream_open(n.ep[0], &o, &err) == NULL && err == ANL_EBUSY, "no open while the peer may still be full (%d)", err);
    CHECK(srec_find(n.ep[0], sid)->rto > rto0 && srec_find(n.ep[0], sid)->rto <= 5000, "CLOSE resent with backoff (rto %u -> %u)",
          rto0, srec_find(n.ep[0], sid)->rto);
    CHECK(g_peer[1][sid] && stream_state(g_peer[1][sid]) == ANL_STREAM_OPEN, "the peer has not heard");
    n.block[0] = 0;
    for (i = 0; i < 20000 && nclos(n.ep[0]); i++) net_tick(&n);
    CHECK(nclos(n.ep[0]) == 0 && stream_state(g_peer[1][sid]) == ANL_STREAM_CLOSED && n.ep[1]->nstab == ANL_MAX_STREAMS - 1,
          "confirmed %d ms after the path came back, the peer's place free (%u)", i, n.ep[1]->nstab);
    anl_stream_close(g_peer[1][sid]);
    x = anl_stream_open(n.ep[0], &o, &err);
    CHECK(x != NULL, "the place is free again (%d)", err);
    if (x) anl_stream_send(x, "n", 1);
    for (i = 0; i < 20000 && x && (stream_state(x) != ANL_STREAM_OPEN || !g_peer[1][anl_stream_id(x)]); i++) net_tick(&n);
    CHECK(x && stream_state(x) == ANL_STREAM_OPEN && g_peer[1][anl_stream_id(x)], "and the peer accepts it (%d)",
          x ? stream_state(x) : -1);
    mine[0] = x;

    /* 2. the RST is lost: the peer's end is over, ours waits, CLOSE answered again later */
    n.block[1] = 1;
    sid = anl_stream_id(mine[1]);
    anl_stream_close(mine[1]);
    mine[1] = NULL;
    for (i = 0; i < 20000 && (!g_peer[1][sid] || stream_state(g_peer[1][sid]) != ANL_STREAM_CLOSED); i++) net_tick(&n);
    for (i = 0; i < 2000; i++) net_tick(&n);
    CHECK(stream_state(g_peer[1][sid]) == ANL_STREAM_CLOSED && nclos(n.ep[0]) == 1, "the peer dropped it, the RST lost (%u)",
          nclos(n.ep[0]));
    anl_stream_close(g_peer[1][sid]);       /* the handle goes; the sid stays used there */
    n.block[1] = 0;
    for (i = 0; i < 20000 && nclos(n.ep[0]); i++) net_tick(&n);
    CHECK(nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "a later CLOSE gets the RST from no state (%d ms)", i);

    /* 3. closed before the peer heard of it: never created there */
    n.block[0] = 1;
    acc = g_acc[1];
    s = anl_stream_open(n.ep[0], &o, &err);
    CHECK(s != NULL, "open (%d)", err);
    if (s) {
        sid = anl_stream_id(s);
        anl_stream_send(s, "lost", 4);
        for (i = 0; i < 300; i++) net_tick(&n);
        anl_stream_close(s);
        n.block[0] = 0;
        for (i = 0; i < 20000 && nclos(n.ep[0]); i++) net_tick(&n);
        CHECK(nclos(n.ep[0]) == 0 && g_acc[1] == acc && n.ep[1]->nstab == ANL_MAX_STREAMS - 1,
              "confirmed, nothing created at the peer (%d accepts)", g_acc[1] - acc);
        CHECK(sid_held(n.ep[1], sid), "the sid is held there");
    }

    /* 4. both ends close at once */
    for (k = 2; k < 6; k++) {
        sid = anl_stream_id(mine[k]);
        anl_stream_close(g_peer[1][sid]);
        anl_stream_close(mine[k]);
        mine[k] = NULL;
    }
    CHECK(nclos(n.ep[0]) == 4 && nclos(n.ep[1]) == 4, "4 closing on each side");
    for (i = 0; i < 20000 && (nclos(n.ep[0]) || nclos(n.ep[1])); i++) net_tick(&n);
    CHECK(nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "each one's CLOSE confirms the other's (%d ms)", i);

    for (k = 0; k < nopen; k++) {
        if (!mine[k]) continue;
        sid = anl_stream_id(mine[k]);
        if (g_peer[1][sid]) anl_stream_close(g_peer[1][sid]);
        anl_stream_close(mine[k]);
    }
    for (i = 0; i < 20000 && (nclos(n.ep[0]) || nclos(n.ep[1]) || n.ep[1]->nstab > 1); i++) net_tick(&n);
    CHECK(n.ep[0]->nstab == 1 && n.ep[1]->nstab == 1 && nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "all freed and confirmed");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    (void)buf;
    net_stop(&n);
}

/* a semi-reliable stream closed by its sender: the frames stop, the
 * receiver's end is over. Closed by its receiver: the sender's sends return
 * ANL_ECLOSED (DESIGN 6.1) */
static void test_semi_close(int loss, int by_receiver)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[20000];
    int i, r, frames = 0, got = 0, late = 0, t_close = 0, t_eof = -1, at_close = -1;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    printf("[semi-reliable close by the %s, loss=%d%%]\n", by_receiver ? "receiver" : "sender", loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 6000 && t_eof < 0; i++) {
        net_tick(&n);
        if (a && i % 33 == 0) {                             /* 30 fps, 12 KB frames */
            fill_pattern(buf, 12000, (uint32_t)frames);
            r = anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 12000, NULL);
            if (r == ANL_ECLOSED) t_eof = i;                /* the receiver closed: RST */
            else frames++;
        }
        if (b) while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            CHECK(r == 12000 && check_pattern(buf, r, fi.frame_no), "frame %u intact", fi.frame_no);
            got++;
            if (at_close >= 0 && fi.frame_no >= (uint32_t)at_close) late++;    /* never sent */
        }
        if (i == 2000) {                                    /* frames are in flight */
            t_close = i;
            at_close = frames;
            if (by_receiver) { anl_stream_close(b); b = NULL; }
            else { anl_stream_close(a); a = NULL; }
        }
    }
    CHECK(got > 0, "frames delivered before the close (%d of %d)", got, frames);
    if (by_receiver) CHECK(t_eof >= 0 && t_eof - t_close < 2000, "the sender's frames got RST %d ms after the close", t_eof - t_close);
    else CHECK(late == 0 && b && stream_state(b) == ANL_STREAM_CLOSED, "no frame after the close, the receiver's end over (%d after, state %d)",
               late, b ? stream_state(b) : -1);
    if (a) anl_stream_close(a);
    if (b) anl_stream_close(b);
    for (i = 0; i < 20000 && (nclos(n.ep[0]) || nclos(n.ep[1])); i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "both sides freed");
    CHECK(nclos(n.ep[0]) == 0 && nclos(n.ep[1]) == 0, "the close confirmed");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d of %d frames delivered\n", got, frames);
    net_stop(&n);
}

static void test_pacing(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[200000];
    int i;
    anl_stream_t *a, *b;
    printf("[pacing]\n");
    net_init(&n, &ca, &cb);
    ca.pace_rate = 2000000;          /* 2 MB/s: upper bound on the BBR rate */
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 300; i++) net_tick(&n);
    n.max_burst[0] = 0;
    fill_pattern(buf, 200000, 1);
    anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 200000, NULL);
    /* the warm-up sent no data: the frame starts BBR from STARTUP, 4~5 round
       trips from 16 segments up to 2 MB/s, then 100 ms at 2 MB/s */
    for (i = 0; i < 600; i++) net_tick(&n);
    /* 2 MB/s over a 5 ms window = 10 KB, plus bucket 4*mtu and one datagram of slack */
    CHECK(n.max_burst[0] <= 10000 + 4 * 1400 + 1400, "max 5ms burst %u bytes", n.max_burst[0]);
    CHECK(anl_stream_peeksize(b) == 200000, "frame arrived (%d)", anl_stream_peeksize(b));
    printf("  max 5 ms burst: %u bytes, frame arrived after <= 600 ms\n", n.max_burst[0]);
    net_stop(&n);
}

/* capture callback for the demux test */
static char g_cap[2048];
static int g_caplen;
static int cap_output(char *buf, int len, anl_t *w, void *user)
{
    (void)w; (void)user;
    memcpy(g_cap, buf, (size_t)len);
    g_caplen = len;
    return 0;
}

static void test_demux(void)
{
    anl_config ca, cb; anl_t *a, *b, *c;
    char plain[2048];
    uint32_t conv = 0;
    int r;
    printf("[demux: peek_conv without keys, then anl_input]\n");
    anl_config_default(&ca, ANL_ROLE_CLIENT);
    anl_config_default(&cb, ANL_ROLE_SERVER);
    memset(ca.psk, 7, 32); memset(cb.psk, 7, 32);
    a = anl_create(0xabcdef01, &ca, NULL);
    b = anl_create(0xabcdef01, &cb, NULL);
    anl_setoutput(a, cap_output);
    g_caplen = 0;
    anl_update(a, 10); anl_update(b, 10);
    anl_send(a, "hello", 5);                    /* default stream: flush_on_send */
    CHECK(g_caplen > 0, "A emitted a datagram");
    r = anl_peek_conv(g_cap, g_caplen, &conv);
    CHECK(r == ANL_OK && conv == 0xabcdef01, "peek_conv without keys r=%d conv=%08x", r, conv);
    CHECK(anl_peek_conv(g_cap, ANL_OVERHEAD - 1, &conv) == ANL_EFORMAT, "too short for a conv");
    CHECK(anl_peek_conv(NULL, g_caplen, &conv) == ANL_EINVAL, "no data");
    /* the conv on the wire is no constant: masked by tag bytes */
    {
        const uint8_t *t = (const uint8_t *)g_cap;
        uint32_t raw = (uint32_t)t[12] | (uint32_t)t[13] << 8 | (uint32_t)t[14] << 16 | (uint32_t)t[15] << 24;
        uint8_t off = (uint8_t)(1 + (t[0] & 7));
        uint32_t mask = (uint32_t)t[off] | (uint32_t)t[off + 1] << 8 | (uint32_t)t[off + 2] << 16 | (uint32_t)t[off + 3] << 24;
        CHECK((raw ^ mask) == 0xabcdef01, "wire conv = conv ^ tag[%u..%u]", off, off + 3);
    }
    r = anl_input(b, g_cap, g_caplen);
    CHECK(r == ANL_OK, "anl_input of the peeked datagram ok (%d)", r);
    r = anl_recv(b, plain, sizeof(plain));
    CHECK(r == 5 && memcmp(plain, "hello", 5) == 0, "B got the data (%d)", r);
    /* a changed conv is caught by the tag, not by the lookup */
    c = anl_create(0xabcdef02, &cb, NULL);
    anl_update(c, 10);
    g_cap[12] ^= 0x03;                      /* the low conv bits: 01 -> 02 after unmasking */
    r = anl_peek_conv(g_cap, g_caplen, &conv);
    CHECK(r == ANL_OK && conv == 0xabcdef02, "tampered conv peeks as %08x", conv);
    r = anl_input(c, g_cap, g_caplen);
    CHECK(r == ANL_EAUTH, "tampered conv fails authentication (%d)", r);
    anl_release(a); anl_release(b); anl_release(c);
}

/* the output callback may rewrite the clear 16 bytes in place (e.g. encrypt
   them); the receiver undoes it in its own buffer before anl_peek_conv /
   anl_input */
static int g_xor_calls;
static int xor16_output(char *buf, int len, anl_t *w, void *user)
{
    int i;
    for (i = 0; i < 16 && i < len; i++) buf[i] ^= (char)(0x5a + i);
    g_xor_calls++;
    return cap_output(buf, len, w, user);
}

static void test_output_rewrite(void)
{
    anl_config ca, cb; anl_t *a, *b;
    char buf[2048];
    uint32_t conv = 0;
    int r, i, len;
    printf("[output callback: rewrite the clear header in place]\n");
    anl_config_default(&ca, ANL_ROLE_CLIENT);
    anl_config_default(&cb, ANL_ROLE_SERVER);
    memset(ca.psk, 9, 32); memset(cb.psk, 9, 32);
    a = anl_create(0x01020304, &ca, NULL);
    b = anl_create(0x01020304, &cb, NULL);
    anl_setoutput(a, xor16_output);
    g_caplen = 0; g_xor_calls = 0;
    anl_update(a, 10); anl_update(b, 10);
    anl_send(a, "rewritten", 9);
    CHECK(g_caplen > 0 && g_xor_calls >= 1, "datagram sent through the rewriting callback (%d)", g_xor_calls);
    len = g_caplen;
    memcpy(buf, g_cap, (size_t)len);
    r = anl_input(b, buf, len);
    CHECK(r == ANL_EAUTH, "not undone: authentication fails (%d)", r);
    for (i = 0; i < 16; i++) buf[i] ^= (char)(0x5a + i);
    CHECK(anl_peek_conv(buf, len, &conv) == ANL_OK && conv == 0x01020304, "undone: conv %08x", conv);
    r = anl_input(b, buf, len);
    CHECK(r == ANL_OK, "undone: accepted (%d)", r);
    r = anl_recv(b, buf, sizeof(buf));
    CHECK(r == 9 && memcmp(buf, "rewritten", 9) == 0, "data through the rewrite (%d)", r);
    anl_release(a); anl_release(b);
}

/*---------------------------------------------------------------------
 * 5. fuzz: mutate authenticated plaintext, feed through the internal anl_input_plain
 *-------------------------------------------------------------------*/
static void test_fuzz(void)
{
    net n; anl_config ca, cb; anl_stream_opt o1, o2;
    char plain[2048], buf[3000];
    int i, iters = 20000;
    anl_stream_t *a1, *b1, *a2, *b2;
    printf("[fuzz %d mutated datagrams]\n", iters);
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o1, ANL_RELIABLE);
    anl_stream_opt_default(&o2, ANL_SEMI);
    o2.fec = 1; o2.fec_ratio = 50;               /* several parities per block: RS decode on fuzzed input */
    a1 = open_pair(&n, 0, &o1, NULL, &b1);
    a2 = open_pair(&n, 0, &o2, NULL, &b2);
    for (i = 0; i < 300; i++) {
        net_tick(&n);
        if (i % 3 == 0 && a1 && a2) {
            fill_pattern(buf, 3000, (uint32_t)i);
            anl_stream_send(a1, buf, 3000);
            anl_stream_send_frame(a2, 0, buf, 2500, NULL);
            anl_send(n.ep[0], buf, 700);
        }
    }
    for (i = 0; i < iters; i++) {
        int len, j;
        len = ANL_HDR_SIZE + (int)(rnd() % 300);
        for (j = 0; j < len; j++) plain[j] = (char)(uint8_t)rnd();
        (void)plain_hdr(plain, n.ep[0], 0x11223344, (uint8_t)((rnd() % 4 == 0) ? (rnd() & 0xff) : 0), (uint16_t)n.now);
        /* bias: sometimes start with a plausible segment header on a live sid */
        if (rnd() % 2) {
            static const int sids[4] = { 0, 1, 2, 4 };
            char *p = plain + ANL_HDR_SIZE;
            (void)enc_sid(p, (int)(rnd() % 4), sids[rnd() % 4]);
        }
        (void)anl_input_plain(n.ep[1], plain, len);
        if (i % 50 == 0) net_tick(&n);
    }
    (void)b1; (void)b2;
    CHECK(1, "no crash");
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 6. stream lifecycle: both sides open, accept callback, close, free
 *-------------------------------------------------------------------*/
#define LC_N ((ANL_MAX_STREAMS - 1) / 2)    /* per side: both sides' fill the table */
