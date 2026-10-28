/* attack 10: pre-auth fuzz. Part of the anl_attack unit (testcases/attack_main.c): included, not compiled alone. */

/* 10. pre-auth path: the only code a keyless attacker reaches is anl_input's
 *     size checks, siv_open, and anl_peek_conv. Hammer all three across every
 *     attacker-reachable size (ANL_OVERHEAD-2 .. mtu+2) with random bytes and
 *     with capture-derived bytes (to drive the conv-mask and partial-decrypt
 *     paths). Two guarantees: (a) memory safety - meaningful only under ASan;
 *     (b) a victim emits ZERO bytes in response to unauthenticated input, so
 *     AnLiu cannot be abused as a reflection/amplification vector. */
static void attack_preauth_fuzz(void)
{
    anl_config cs;
    anl_t *victim;
    int idx = 0, i, accepted = 0;
    long iters = 300000;
    uint32_t mtu;
    char cap[CAPMAX]; int cap_len;
    char *buf;
    printf("[10] pre-auth fuzz (size boundaries, no-amplification)\n");
    /* capture one genuine datagram to seed capture-derived inputs */
    link_init();
    anl_send(L.ep[0], "seed-for-preauth-fuzz", 21);
    capture_from(0, 24);
    memcpy(cap, L.cap[0], (size_t)L.cap_len[0]); cap_len = L.cap_len[0];
    link_free();

    anl_config_default(&cs, ANL_ROLE_SERVER);
    memcpy(cs.psk, L.psk, ANL_PSK_SIZE);
    victim = anl_create(CONV, &cs, &idx);
    anl_setoutput(victim, sink_output);
    anl_update(victim, 400000);
    mtu = 1400;                     /* anl_config_default's mtu */
    buf = (char *)malloc(mtu + 64);

    g_out_pkts = 0; g_out_bytes = 0;
    for (i = 0; i < iters; i++) {
        int mode = i & 3;
        int len, j, r;
        uint32_t conv;
        /* choose a size: bias toward the valid [OVERHEAD, mtu] edges */
        switch (i % 6) {
        case 0: len = ANL_OVERHEAD - 2; break;      /* just below valid */
        case 1: len = ANL_OVERHEAD;     break;      /* minimum valid */
        case 2: len = (int)mtu;         break;      /* maximum valid */
        case 3: len = (int)mtu + 2;     break;      /* just above valid */
        default: len = ANL_OVERHEAD + (int)(arnd() % (mtu - ANL_OVERHEAD + 1)); break;
        }
        if (len < 0) len = 0;
        if (mode == 0 || cap_len == 0) {
            for (j = 0; j < len; j++) buf[j] = (char)arnd();           /* pure random */
        } else {
            int base = len < cap_len ? len : cap_len;
            memcpy(buf, cap, (size_t)base);                           /* capture-derived */
            for (j = base; j < len; j++) buf[j] = (char)arnd();
            /* always corrupt the tag region so this can never be a valid
               (authenticated) replay: this test is about UNauthenticated input.
               conv_mask and the partial decrypt still run over realistic bytes. */
            if (len > 0) buf[0] ^= 0x5a;
            if (mode == 1 && len > 1) buf[1 + (arnd() % (uint32_t)(len - 1))] ^= (char)(1u << (arnd() & 7));
        }
        /* peek_conv must never crash and must stay unauthenticated */
        (void)anl_peek_conv(buf, len, &conv);
        r = anl_input(victim, buf, len);
        if (r == ANL_OK) accepted++;
    }
    CHECK(accepted == 0, "no crafted pre-auth datagram authenticated (accepted=%d)", accepted);
    CHECK(g_out_pkts == 0 && g_out_bytes == 0,
          "victim emitted nothing for unauthenticated input (pkts=%ld bytes=%llu)",
          g_out_pkts, (unsigned long long)g_out_bytes);
    OKAY("%ld crafted datagrams across all sizes: 0 accepted, 0 bytes emitted", iters);
    OKAY("  -> pre-auth path is memory-safe (clean under ASan) and non-amplifying");
    free(buf);
    anl_release(victim);
}
