/* Diagnostics regression, entirely in-process; no sockets.
 * cc -std=gnu99 -O2 -DREALNET_INTERNAL -I. bench/test_tx_diag.c bench/ikcp.c -lm -o /tmp/test_tx_diag
 * /tmp/test_tx_diag
 */
#define main realnet_main
#include "realnet.c"
#undef main
#include <assert.h>

static uint64_t outbytes;
static int sink(const char *p, int len, anl_t *w, void *u)
{
    (void)p; (void)w; (void)u; outbytes += (uint32_t)len; return 0;
}
static void balance(const anl_t *w, int64_t initial)
{
    assert(initial + (int64_t)g_tx_diag.earned - (int64_t)g_tx_diag.clipped -
           (int64_t)g_tx_diag.spent == w->pace_tokens);
    assert(g_tx_diag.spent + g_tx_diag.control == outbytes);
}
int main(void)
{
    anl_config cfg; anl_t *w; anl_stream *st; tx_diag states;
    char data[32768] = {0}; int64_t initial; uint64_t before;
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    cfg.pad_max = 0; cfg.interval = 10; cfg.pace_rate = 100000;
    w = anl_create(3, &cfg, NULL); assert(w);
    anl_setoutput(w, sink); initial = w->pace_tokens;
    g_tx_diag.enabled = 1;
    anl_update(w, 0xfffffff0u); tx_diag_observe(&g_tx_diag, w);
    anl_update(w, 4); tx_diag_observe(&g_tx_diag, w); /* 20 ms across wrap */
    assert(g_tx_diag.refill_ms == 20 && g_tx_diag.clipped > 0);
    assert(g_tx_diag.empty_ms == 20 && g_tx_diag.elapsed == 20);
    balance(w, initial);
    assert(anl_send(w, data, sizeof(data)) == 0);
    tx_diag_observe(&g_tx_diag, w); balance(w, initial);
    for (uint32_t t = 5; t < 1005; t++) {
        anl_update(w, t); tx_diag_observe(&g_tx_diag, w); balance(w, initial);
    }
    assert(g_tx_diag.spent > 0 && g_tx_diag.flush_n > 0);
    assert(g_tx_diag.retrans_seg_bytes > 0);
    before = g_tx_diag.earned;
    anl_update(w, w->current); tx_diag_observe(&g_tx_diag, w);
    assert(g_tx_diag.earned == before); balance(w, initial);

    /* Controlled held states: a per-stream window must not be called app
       starvation, and independent cwnd/pacing limits must both be visible. */
    memset(&states, 0, sizeof(states)); states.enabled = 1;
    st = w->dflt; assert(st->nsnd_que > 0);
    st->rmt_wnd = 0; w->pace_tokens = 10000;
    tx_diag_observe(&states, w);
    w->current += 15; tx_diag_observe(&states, w);
    assert(states.window_ms == 15 && states.empty_ms == 0);
    st->rmt_wnd = ANL_MAX_WND; w->inflight_segs = w->cwnd; w->pace_tokens = -1;
    tx_diag_observe(&states, w);
    w->current += 25; tx_diag_observe(&states, w);
    assert(states.window_ms == 15 && states.cwnd_ms == 25 && states.pace_ms == 25);
    w->inflight_segs = 0; w->pace_tokens = 10000;
    tx_diag_observe(&states, w);
    w->current += 10; tx_diag_observe(&states, w);
    assert(states.ready_ms == 10 && states.elapsed == 50);
    printf("diagnostic conservation and sampled-state checks passed\n");
    anl_release(w); return 0;
}
