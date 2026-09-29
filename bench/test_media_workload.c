/* Socket-free regression: identical seeds must generate identical media even
 * when protocol, endpoint role, timer batching and loss RNG consumption differ.
 * Build: cc -std=gnu99 -O2 -I. bench/test_media_workload.c anliu.c bench/ikcp.c -lm -o /tmp/test_media_workload
 */
#define main realnet_main
#include "realnet.c"
#undef main
#include <assert.h>

typedef struct { int len, key; } frame_shape;
static frame_shape expected[2][2][50];

static void generate(int seed, int proto, int server, unsigned step, int reference)
{
    uint64_t start = now_us(), end = start + 1000000;
    size_t j;
    int i, changed = 0, seen[2] = {0};
    g_proto = proto; g_server = server; g_test = server ? 3 : 0;
    g_media_seed = (uint64_t)seed;
    g_rng = 88172645463325252ull ^ (uint64_t)seed;
    g_mdiag = 1; g_nmds = 0;
    flows_init(); ep_create(); ep_open_streams();
    for (i = 1; i <= 2; i++) g_fl[i].start_us = g_fl[i].next_us = start;
    /* Include the final catch-up call so both schedules generate one second. */
    for (j = 0; j < 1000000 + step; j += step) {
        if (!reference) for (i = 0; i < 97; i++) (void)rnd();
        gen_media(start + j, end);
    }
    assert(g_nmds == 80);
    for (j = 0; j < g_nmds; j++) {
        const mdiag_s *e = &g_mds[j];
        frame_shape *p = &expected[seed - 1][e->id - 1][e->seq];
        assert(e->seq == (uint32_t)seen[e->id - 1]++);
        if (reference) { p->len = (int)e->len; p->key = e->key; }
        else { assert(p->len == (int)e->len); assert(p->key == e->key); }
        if (e->id == 1) assert(e->len == 160);
        else {
            assert(e->len >= (e->key ? 25000u : 2500u));
            assert(e->len <= (e->key ? 35000u : 3500u));
            if (seed == 2 && expected[0][1][e->seq].len != (int)e->len) changed++;
        }
    }
    assert(seen[0] == 50 && seen[1] == 30);
    if (seed == 2) assert(changed > 0);
    if (g_anl) { anl_release(g_anl); g_anl = NULL; }
    memset(g_h, 0, sizeof(g_h));
    for (i = 1; i < NFLOW; i++) if (g_kcp[i]) { ikcp_release(g_kcp[i]); g_kcp[i] = NULL; }
}

int main(void)
{
    int seed, proto, role;
    for (seed = 1; seed <= 2; seed++) {
        generate(seed, P_ANL, 0, 1000, 1);
        for (proto = P_ANL; proto <= P_KCPDROP; proto++)
            for (role = 0; role <= 1; role++) generate(seed, proto, role, 101000, 0);
    }
    free(g_mds);
    puts("media workload reproducibility passed");
    return 0;
}
