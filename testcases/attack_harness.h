/*
 * attack_harness.h - AnLiu adversarial harness (no-key attacker model): shared link,
 * capture and statistics helpers. Included first by testcases/attack_main.c.
 *
 * Build: gcc -std=c99 -Wall -Wextra -O1 -g testcases/attack_main.c -o anl_attack
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
#include "../anliu.c"

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
