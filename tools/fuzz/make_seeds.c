/*
 * make_seeds.c - seed inputs for fuzz_peer: a client opens a reliable and a
 * semi-reliable FEC stream and sends media; the plaintext of what it sends
 * (DATA with the stream parameters, ACK, PARITY, FWD, CLOSE ...) is written
 * in fuzz_peer's input format. Each seed starts with the client's first
 * datagrams (the streams' parameters), then a run of later ones.
 *
 * Usage: make_seeds DIR
 */
#include "../../anliu.c"

#include <stdio.h>
#include <string.h>

#define CAP_MAX   4096
#define SEED_RUN  6

static anl_keys g_keys;
static uint8_t g_cap[CAP_MAX][1400];
static int g_cap_len[CAP_MAX], g_ncap;

/* datagrams in flight, delivered between clock steps: an output callback
   must not call into the library (anliu.h) */
#define QMAX 1024
typedef struct { char d[1500]; int len; } dgram;
static dgram g_q[2][QMAX];          /* [0] to the server, [1] to the client */
static int g_qn[2];

static void enqueue(int to, const char *buf, int len)
{
    if (g_qn[to] < QMAX && len <= (int)sizeof(g_q[0][0].d)) {
        memcpy(g_q[to][g_qn[to]].d, buf, (size_t)len);
        g_q[to][g_qn[to]++].len = len;
    }
}

static int cli_out(char *buf, int len, anl_t *w, void *user)
{
    int r;
    (void)w; (void)user;
    if (g_ncap < CAP_MAX && len <= (int)sizeof(g_cap[0]) + ANL_TAG_SIZE) {
        r = siv_open(&g_keys, ANL_ROLE_CLIENT, (const uint8_t *)buf, (size_t)len, g_cap[g_ncap]);
        if (r > 0) g_cap_len[g_ncap++] = r;
    }
    enqueue(0, buf, len);
    return 0;
}

static int srv_out(char *buf, int len, anl_t *w, void *user)
{
    (void)w; (void)user;
    enqueue(1, buf, len);           /* the client needs the ACKs to keep sending */
    return 0;
}

static void deliver(anl_t *cli, anl_t *srv)
{
    int i, n;
    for (n = g_qn[0], g_qn[0] = 0, i = 0; i < n; i++) anl_input(srv, g_q[0][i].d, g_q[0][i].len);
    for (n = g_qn[1], g_qn[1] = 0, i = 0; i < n; i++) anl_input(cli, g_q[1][i].d, g_q[1][i].len);
}

static void put(FILE *f, int i)
{
    uint8_t l[2];
    l[0] = (uint8_t)(g_cap_len[i] & 0xff);
    l[1] = (uint8_t)(g_cap_len[i] >> 8);
    fwrite(l, 1, 2, f);
    fwrite(g_cap[i], 1, (size_t)g_cap_len[i], f);
}

int main(int argc, char **argv)
{
    anl_config cc, cs;
    anl_stream_opt o;
    anl_t *cli, *srv;
    anl_stream_t *rel, *semi;
    static char buf[4000];
    uint32_t now = 100000, seed = 1;
    int i, j, nseeds = 0;
    if (argc < 2) { fprintf(stderr, "usage: %s DIR\n", argv[0]); return 2; }
    anl_config_default(&cc, ANL_ROLE_CLIENT);
    anl_config_default(&cs, ANL_ROLE_SERVER);
    for (i = 0; i < ANL_PSK_SIZE; i++) cc.psk[i] = cs.psk[i] = (uint8_t)(0x20 + i);
    anl_keys_derive(&g_keys, cc.psk);
    cli = anl_create(0x11223344u, &cc, NULL);
    srv = anl_create(0x11223344u, &cs, NULL);
    anl_setoutput(cli, cli_out);
    anl_setoutput(srv, srv_out);
    anl_update(cli, now);
    anl_update(srv, now);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    rel = anl_stream_open(cli, &o, NULL);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1;
    o.fec_ratio = 50;
    semi = anl_stream_open(cli, &o, NULL);
    for (i = 0; i < 1000; i++) {
        now += 5;
        anl_update(cli, now);
        anl_update(srv, now);
        deliver(cli, srv);
        if (i % 2 == 0) {
            for (j = 0; j < (int)sizeof(buf); j++) { seed = seed * 1103515245u + 12345u; buf[j] = (char)(seed >> 16); }
            anl_stream_send(rel, buf, 1800);
            anl_stream_send_frame(semi, i % 20 == 0 ? ANL_FRAME_KEY : 0, buf, 1200 + i % 900, NULL);
            anl_send(cli, buf, 300);
        }
    }
    anl_stream_close(rel);
    anl_stream_close(semi);
    for (i = 0; i < 400; i++) { now += 5; anl_update(cli, now); anl_update(srv, now); deliver(cli, srv); }

    for (i = 2; i + SEED_RUN <= g_ncap; i += SEED_RUN) {
        char path[1024];
        FILE *f;
        snprintf(path, sizeof(path), "%s/seed_%04d", argv[1], nseeds++);
        if ((f = fopen(path, "wb")) == NULL) { perror(path); return 1; }
        put(f, 0);
        put(f, 1);
        for (j = i; j < i + SEED_RUN; j++) put(f, j);
        fclose(f);
    }
    printf("%d datagrams captured, %d seeds in %s\n", g_ncap, nseeds, argv[1]);
    anl_release(cli);
    anl_release(srv);
    return 0;
}
