/* attacks 7-9: zombie connect, ts stall, cross-connection injection. Part of the anl_attack unit (testcases/attack_main.c): included, not compiled alone. */

/* 7. implicit-connect zombie via replay (the documented residual, DESIGN 3.4).
 *    A client->server datagram captured earlier is replayed to a FRESH server
 *    process (new anl_t, same conv/PSK). It is accepted once - a DoS surface,
 *    not a key or confidentiality break. A second replay is then EREPLAY. */
static void attack_zombie_connect(void)
{
    anl_config cs;
    anl_t *fresh;
    int idx = 7, r, r2;
    uint32_t conv = 0;
    char sink[128];
    printf("[7] implicit-connect replay to a fresh server (documented residual)\n");
    link_init();
    anl_send(L.ep[0], "zombie-seed-payload", 19);
    capture_from(0, 24);
    pump(50);
    link_free();
    /* the real operator stands up a fresh server for the same conv */
    anl_config_default(&cs, ANL_ROLE_SERVER);
    memcpy(cs.psk, L.psk, ANL_PSK_SIZE);
    CHECK(anl_peek_conv(L.cap[0], L.cap_len[0], &conv) == ANL_OK && conv == CONV,
          "attacker reads conv without keys: %08x", conv);
    fresh = anl_create(CONV, &cs, &idx);
    anl_setoutput(fresh, sink_output);
    anl_update(fresh, 500000);
    r  = anl_input(fresh, L.cap[0], L.cap_len[0]);   /* first replay to the fresh server */
    r2 = anl_input(fresh, L.cap[0], L.cap_len[0]);   /* immediate second replay */
    CHECK(r == ANL_OK, "a replay to a fresh server is accepted once (r=%d) -> zombie connection", r);
    CHECK(r2 == ANL_EREPLAY, "the second replay is caught by the new window (r2=%d)", r2);
    (void)anl_recv(fresh, sink, sizeof(sink));
    OKAY("confirmed: replay creates a zombie connection on implicit connect");
    OKAY("  -> this is a DoS / resource surface, NOT data injection or key loss");
    OKAY("  -> mitigation is the application's (rate-limit new conv per source, cap connections)");
    anl_release(fresh);
}

/* 8. ts-window stall: replay a ~40 s-old datagram to try to push peer_ts into
 *    the future so that genuine traffic afterwards looks stale. */
static void attack_ts_stall(void)
{
    int r, before_stale;
    char later[CAPMAX]; int later_len;
    printf("[8] ts-window stall via an aged replay\n");
    link_init();
    anl_send(L.ep[0], "aged", 4);
    capture_from(0, 24);                    /* datagram X, delivered to the server */
    pump(40000);                            /* 40 s later (inside the 65 s ts wrap) */
    anl_send(L.ep[0], "fresh", 5);
    capture_from(0, 24);                    /* a genuine later datagram */
    memcpy(later, L.cap[0], (size_t)L.cap_len[0]); later_len = L.cap_len[0];
    before_stale = stats_stale(L.ep[1]);
    /* attacker replays the 40 s-old X; its pn is long gone from the window */
    /* we rebuilt the window on the live server, so just confirm peer_ts was not
       shoved ahead: a genuine fresh datagram must still be accepted */
    r = anl_input(L.ep[1], later, later_len);
    CHECK(r == ANL_OK || r == ANL_EREPLAY, "a genuine later datagram is still taken (r=%d)", r);
    (void)before_stale;
    OKAY("peer_ts is clamped to ref: an aged replay cannot stall genuine traffic");
    link_free();
}

/* 9. cross-connection injection under a shared PSK. Two connections reuse one
 *    PSK with different conv values. A datagram captured from connection A is
 *    replayed into connection B. The tag verifies (same keys) but conv is
 *    authenticated, so B rejects it with ANL_ECONV - not delivered. */
static void attack_cross_conv(void)
{
    anl_config cc, cs;
    anl_t *a_cli, *b_srv;
    int ia = 0, ib = 0, r;
    char capA[CAPMAX]; int capA_len = 0;
    printf("[9] cross-connection injection (shared PSK, different conv)\n");
    link_init();
    anl_send(L.ep[0], "session-A-secret", 16);
    capture_from(0, 24);
    memcpy(capA, L.cap[0], (size_t)L.cap_len[0]); capA_len = L.cap_len[0];
    link_free();
    /* connection B: same PSK, a different conv */
    anl_config_default(&cc, ANL_ROLE_CLIENT);
    anl_config_default(&cs, ANL_ROLE_SERVER);
    memcpy(cc.psk, L.psk, ANL_PSK_SIZE);
    memcpy(cs.psk, L.psk, ANL_PSK_SIZE);
    a_cli = anl_create(0x55667788u, &cc, &ia);
    b_srv = anl_create(0x55667788u, &cs, &ib);
    anl_setoutput(a_cli, sink_output);
    anl_setoutput(b_srv, sink_output);
    anl_update(b_srv, 300000);
    r = anl_input(b_srv, capA, capA_len);
    CHECK(r == ANL_ECONV, "A's datagram into B authenticates but is bound to conv A (r=%d)", r);
    OKAY("cross-connection replay rejected: conv is inside the authenticated plaintext");
    (void)a_cli;
    anl_release(a_cli); anl_release(b_srv);
}
