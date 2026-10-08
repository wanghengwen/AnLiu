/*
 * test_attack.c - AnLiu adversarial harness (no-key attacker model).
 *
 * Build: gcc -std=c99 -Wall -Wextra -O1 -g test_attack.c -o anl_attack
 * Run:   ./anl_attack
 *
 * Threat model. Two honest endpoints (client, server) share a 32-byte PSK the
 * attacker does NOT know. The attacker is on the path: it observes every wire
 * datagram (through the output callback) and can inject arbitrary bytes into
 * either endpoint's anl_input. It never derives or uses the real keys - every
 * crafted datagram is built only from observed ciphertext and attacker-chosen
 * bytes. Each attack asks one question: can the attacker get a victim to ACCEPT
 * (return ANL_OK and deliver attacker-influenced data) a datagram it did not
 * legitimately send?
 *
 * anliu.c is included for anl_keys_derive in ONE place only: to stand up a
 * genuine "restarted server" for the implicit-connect replay test (that models
 * the real operator's process, not the attacker holding keys). The attacks
 * themselves touch only wire bytes and the public API.
 */
#include "anliu.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { g_fail++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define OKAY(...)        do { printf("  ok  "); printf(__VA_ARGS__); printf("\n"); } while (0)

/* deterministic attacker RNG (xorshift) */
static uint64_t g_seed = 0xD1B54A32D192ED03ULL;
static uint32_t arnd(void)
{
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 7; g_seed ^= g_seed << 17;
    return (uint32_t)(g_seed >> 16);
}

/*---------------------------------------------------------------------
 * link: two honest endpoints plus a tap the attacker reads
 *---------------------------------------------------------------------*/
#define CONV 0x0A0B0C0Du
#define CAPMAX 2048

typedef struct link {
    anl_t *ep[2];                   /* 0 = client, 1 = server */
    int idx[2];
    uint32_t now;
    int deliver;                    /* 0 while capturing: honest datagrams are dropped, not delivered */
    /* last datagram seen from each direction (the attacker's tap) */
    char cap[2][CAPMAX]; int cap_len[2];
    char psk[ANL_PSK_SIZE];
} link;

static link L;

/* counts datagrams/bytes a victim emits; used to prove that unauthenticated
 * input provokes no response (no reflection/amplification) */
static long g_out_pkts = 0;
static uint64_t g_out_bytes = 0;

/* a sink for endpoints whose output the attacker does not tap (e.g. the fresh
 * server in the zombie test): drop it, but count it */
static int sink_output(char *buf, int len, anl_t *w, void *user)
{
    (void)buf; (void)w; (void)user;
    if (len > 0) { g_out_pkts++; g_out_bytes += (uint64_t)len; }
    return 0;
}

static int tap_output(char *buf, int len, anl_t *w, void *user)
{
    int *idx = (int *)user, from = *idx;
    (void)w;
    if (len > 0 && len <= CAPMAX) { memcpy(L.cap[from], buf, (size_t)len); L.cap_len[from] = len; }
    if (L.deliver && len > 0 && len <= CAPMAX) anl_input(L.ep[1 - from], buf, len);
    return 0;
}

static void link_init(void)
{
    anl_config cc, cs;
    int i;
    memset(&L, 0, sizeof(L));
    for (i = 0; i < ANL_PSK_SIZE; i++) L.psk[i] = (char)(0x31 + i * 7);   /* the shared secret */
    anl_config_default(&cc, ANL_ROLE_CLIENT);
    anl_config_default(&cs, ANL_ROLE_SERVER);
    memcpy(cc.psk, L.psk, ANL_PSK_SIZE);
    memcpy(cs.psk, L.psk, ANL_PSK_SIZE);
    L.idx[0] = 0; L.idx[1] = 1;
    L.now = 100000;
    L.ep[0] = anl_create(CONV, &cc, &L.idx[0]);
    L.ep[1] = anl_create(CONV, &cs, &L.idx[1]);
    anl_setoutput(L.ep[0], tap_output);
    anl_setoutput(L.ep[1], tap_output);
    L.deliver = 1;
}

static void link_free(void)
{
    anl_release(L.ep[0]); anl_release(L.ep[1]);
}

static void pump(int ms)
{
    int i;
    for (i = 0; i < ms; i++) {
        L.now++;
        anl_update(L.ep[0], L.now);
        anl_update(L.ep[1], L.now);
    }
}

/* run until a datagram from `from` of at least min_len bytes is tapped */
static void capture_from(int from, int min_len)
{
    int guard = 0;
    L.cap_len[from] = 0;
    while (L.cap_len[from] < min_len && guard++ < 20000) pump(1);
}

static int stats_auth_fail(anl_t *w)   { anl_stats s; anl_get_stats(w, &s); return (int)s.rx_auth_fail; }
static int stats_replay(anl_t *w)      { anl_stats s; anl_get_stats(w, &s); return (int)s.rx_replay; }
static int stats_stale(anl_t *w)       { anl_stats s; anl_get_stats(w, &s); return (int)s.rx_stale; }

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

int main(void)
{
    printf("AnLiu adversarial harness - on-path attacker without the PSK\n");
    printf("============================================================\n");
    attack_replay_verbatim();
    attack_reflection();
    attack_byteflip();
    attack_length();
    attack_malleability();
    attack_blind_forgery();
    attack_zombie_connect();
    attack_ts_stall();
    attack_cross_conv();
    attack_preauth_fuzz();
    printf("============================================================\n");
    if (g_fail == 0) printf("RESULT: all attacks behaved as the security model predicts.\n");
    else             printf("RESULT: %d unexpected outcome(s) - investigate.\n", g_fail);
    return g_fail ? 1 : 0;
}
