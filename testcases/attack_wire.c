/* attacks 1-6: replay, reflection, byte flips, length, forgery, malleability. Part of the anl_attack unit (testcases/attack_main.c): included, not compiled alone. */

/*=====================================================================
 * attacks
 *====================================================================*/

/* 1. verbatim replay of a freshly captured client->server datagram */
static void attack_replay_verbatim(void)
{
    int r, before;
    printf("[1] verbatim replay (same live connection)\n");
    link_init();
    anl_send(L.ep[0], "hello-from-client", 17);
    capture_from(0, 24);                    /* a client->server datagram, delivered too */
    pump(50);
    before = stats_replay(L.ep[1]);
    r = anl_input(L.ep[1], L.cap[0], L.cap_len[0]);   /* attacker re-injects the same bytes */
    CHECK(r == ANL_EREPLAY, "replayed datagram must be EREPLAY, got %d", r);
    CHECK(stats_replay(L.ep[1]) == before + 1, "replay counter advanced");
    OKAY("replay rejected by the packet-number window (EREPLAY)");
    link_free();
}

/* 2. reflection: a client->server datagram bounced back to the client */
static void attack_reflection(void)
{
    int r, before;
    printf("[2] reflection (A->B datagram fed back to A)\n");
    link_init();
    anl_send(L.ep[0], "reflect-me", 10);
    capture_from(0, 24);
    before = stats_auth_fail(L.ep[0]);
    r = anl_input(L.ep[0], L.cap[0], L.cap_len[0]);   /* feed the client its own datagram */
    CHECK(r == ANL_EAUTH, "reflected datagram must be EAUTH (wrong direction key), got %d", r);
    CHECK(stats_auth_fail(L.ep[0]) == before + 1, "auth-fail counter advanced");
    OKAY("reflection rejected: the direction key makes A reject A's own packet");
    link_free();
}

/* 3. exhaustive single-byte tamper at every wire offset, re-injected to the
 *    intended receiver. None may authenticate; none may deliver attacker data. */
static void attack_byteflip(void)
{
    int off, bit, accepted = 0, delivered = 0, n;
    char buf[CAPMAX];
    printf("[3] exhaustive single-byte / single-bit tamper\n");
    link_init();
    anl_send(L.ep[0], "tamper-target-payload", 21);
    capture_from(0, 24);
    pump(50);
    n = L.cap_len[0];
    for (off = 0; off < n; off++) {
        for (bit = 0; bit < 8; bit++) {
            char sink[64]; int r;
            memcpy(buf, L.cap[0], (size_t)n);
            buf[off] ^= (char)(1u << bit);
            r = anl_input(L.ep[1], buf, n);
            if (r == ANL_OK) {
                accepted++;
                while ((r = anl_recv(L.ep[1], sink, sizeof(sink))) > 0) delivered++;
            }
        }
    }
    CHECK(accepted == 0, "no single-byte tamper authenticated (accepted=%d)", accepted);
    CHECK(delivered == 0, "no tampered payload delivered (delivered=%d)", delivered);
    OKAY("all %d one-bit mutations across %d bytes rejected", n * 8, n);
    link_free();
}

/* 4. truncation and extension of a valid captured datagram */
static void attack_length(void)
{
    char buf[CAPMAX + 16];
    int r, n, cut, rejected = 0, tries = 0;
    printf("[4] truncation / extension\n");
    link_init();
    anl_send(L.ep[0], "length-games-xxxxxxxxxxxx", 25);
    capture_from(0, 40);
    pump(50);
    n = L.cap_len[0];
    for (cut = 1; cut < n - ANL_OVERHEAD + 1 && cut < 40; cut++) {
        r = anl_input(L.ep[1], L.cap[0], n - cut);
        tries++;
        if (r != ANL_OK) rejected++;
    }
    /* extension: append attacker bytes */
    memcpy(buf, L.cap[0], (size_t)n);
    { int i; for (i = 0; i < 16; i++) buf[n + i] = (char)arnd(); }
    r = anl_input(L.ep[1], buf, n + 16);
    tries++; if (r != ANL_OK) rejected++;
    CHECK(rejected == tries, "every truncation/extension rejected (%d/%d)", rejected, tries);
    OKAY("length changes rejected: length is under the tag");
    link_free();
}

/* 5. blind forgery at scale: random datagrams of plausible shape */
static void attack_blind_forgery(void)
{
    const long N = 4000000;        /* 4M attempts */
    long i, accepted = 0;
    char buf[200];
    int len = 23 + 40;
    printf("[5] blind forgery (%ld random datagrams)\n", N);
    link_init();
    /* establish peer_ts/pn so the victim is a normal running connection */
    anl_send(L.ep[0], "warmup", 6);
    capture_from(0, 24); pump(50);
    for (i = 0; i < N; i++) {
        int j, r;
        for (j = 0; j < len; j++) buf[j] = (char)arnd();
        r = anl_input(L.ep[1], buf, len);
        if (r == ANL_OK) accepted++;
    }
    CHECK(accepted == 0, "no blind forgery authenticated in %ld tries (accepted=%ld)", N, accepted);
    OKAY("0/%ld forged; 96-bit tag => expected ~%.1e accepts", N, (double)N / 79228162514264337593543950336.0);
    link_free();
}

/* 6. ciphertext malleability: flip bits only in the encrypted segment region of
 *    a valid DATA datagram, trying to alter the delivered plaintext (a SIV must
 *    make this impossible - the tag covers the plaintext). */
static void attack_malleability(void)
{
    char buf[CAPMAX], sink[128];
    int n, i, accepted = 0, delivered = 0, r;
    printf("[6] ciphertext malleability on a DATA datagram\n");
    link_init();
    anl_send(L.ep[0], "the-quick-brown-fox-jumps", 25);
    capture_from(0, 40);
    pump(50);
    n = L.cap_len[0];
    /* the encrypted region starts after tag(12)+conv(4) = offset 16 */
    for (i = 16; i < n; i++) {
        memcpy(buf, L.cap[0], (size_t)n);
        buf[i] ^= 0x01;
        r = anl_input(L.ep[1], buf, n);
        if (r == ANL_OK) { accepted++; while (anl_recv(L.ep[1], sink, sizeof(sink)) > 0) delivered++; }
    }
    CHECK(accepted == 0 && delivered == 0, "no mauled ciphertext delivered (acc=%d del=%d)", accepted, delivered);
    OKAY("ciphertext is non-malleable: every edit in the encrypted region fails the tag");
    link_free();
}
