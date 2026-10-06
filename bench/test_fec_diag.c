/* Socket-free FECCOST accounting on loss/retransmission and FEC paths.
 * cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic bench/test_fec_diag.c -o /tmp/test_fec_diag
 */
#include "../anliu.h"
static void trace_seg_commit(const anl_t *, uint32_t, int);
static void trace_seg_trim(const anl_t *, uint32_t);
static void trace_data_seg(const anl_t *, const anl_stream_t *, uint32_t, int);
static void trace_parity_seg(const anl_t *, int, uint32_t);
static void trace_fec_block(const anl_t *, const anl_stream_t *, uint32_t, uint32_t);
static void trace_diag_output(const anl_t *, uint32_t, int);
#define ANL_SEG_COMMIT_TRACE trace_seg_commit
#define ANL_SEG_TRIM_TRACE trace_seg_trim
#define ANL_DATA_SEG_TRACE trace_data_seg
#define ANL_PARITY_SEG_TRACE trace_parity_seg
#define ANL_FEC_BLOCK_TRACE trace_fec_block
#define ANL_TX_OUTPUT_TRACE trace_diag_output
#define main original_test_main
#include "../test.c"
#undef main
#include "fec_diag.h"

static uint64_t observed_bytes, observed_datagrams;
static void trace_diag_output(const anl_t *w, uint32_t bytes, int paced)
{
    (void)paced;
    if (fec_diag_active(w)) { observed_bytes += bytes; observed_datagrams++; }
    fec_diag_output(w, bytes);
}

static void run_cost(int fec)
{
    net n;
    anl_config ca, cb;
    anl_stream_opt o;
    anl_stream_t *a, *b;
    char buf[500];
    int i, received = 0;
    uint64_t segments = 0;
    memset(&g_fec_diag, 0, sizeof(g_fec_diag));
    observed_bytes = observed_datagrams = 0;
    net_init(&n, &ca, &cb); n.loss_pct = 10; n.min_delay = 10; n.max_delay = 20;
    net_start(&n, &ca, &cb);
    g_fec_diag.enabled = 1; g_fec_diag.owner = n.ep[0];
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.tag = fec ? 2 : 1; o.fec = fec; o.fec_ratio = 50;
    a = open_pair(&n, 0, &o, NULL, &b);
    CHECK(a && b, "open byte-accounting stream");
    if (!a || !b) { net_stop(&n); return; }
    for (i = 0; i < 100; i++) {
        fill_pattern(buf, sizeof(buf), (uint32_t)i);
        CHECK(anl_stream_send(a, buf, sizeof(buf)) == 0, "enqueue payload");
    }
    for (i = 0; i < 10000 && (received < 100 || anl_stream_waitsnd(a)); i++) {
        int len;
        net_tick(&n);
        while ((len = anl_stream_recv(b, buf, sizeof(buf))) >= 0) {
            CHECK(len == (int)sizeof(buf) && check_pattern(buf, len, (uint32_t)received), "ordered payload");
            received++;
        }
    }
    for (i = 0; i < 4; i++) {
        const fec_diag_bytes *s = &g_fec_diag.sent[i], *p = &g_fec_diag.pending[i];
        segments += s->first + s->retry + s->parity;
        CHECK(!p->first && !p->retry && !p->parity, "no buffered data segments after flush");
    }
    CHECK(received == 100 && anl_stream_waitsnd(a) == 0, "all bytes delivered and acknowledged");
    CHECK(g_fec_diag.output == observed_bytes && g_fec_diag.datagrams == observed_datagrams, "all output accounted once");
    CHECK(g_fec_diag.output == segments + g_fec_diag.control + g_fec_diag.overhead, "exact serialized-byte conservation");
    CHECK(!g_fec_diag.accounting_errors && !g_fec_diag.pending_control, "complete valid datagrams");
    CHECK(g_fec_diag.sent[o.tag].first > 50000 && g_fec_diag.control > 0 && g_fec_diag.overhead > 0, "payload, control and encapsulation observed");
    if (fec) {
        CHECK(g_fec_diag.sent[2].parity > 0 && g_fec_diag.blocks[2] > 0, "actual parity and coding blocks observed");
        CHECK(g_fec_diag.parity_datagrams[2] > 0 && g_fec_diag.parity_output[2] <= g_fec_diag.output,
              "pure parity datagrams are a subset of output (mixed datagrams excluded)");
    }
    else CHECK(g_fec_diag.sent[1].retry > 0 && !g_fec_diag.sent[1].parity, "retransmissions without FEC");
    fec_diag_print(n.ep[0]);
    net_stop(&n);
}

/* Known wire lengths, independent of data_seg_size and residual accounting. */
static void run_exact_cost(void)
{
    anl_config c; anl_t *w; anl_seg *s; uint8_t parity[200] = {0}; int kind;
    anl_config_default(&c, ANL_ROLE_CLIENT); c.pad_max = 0;
    w = anl_create(1, &c, NULL); anl_setoutput(w, review_sink);
    w->dflt->peer_opened = 1;
    s = seg_new(100); memset(s->data, 42, 100);
    for (kind = 0; kind < 5; kind++) {
        memset(&g_fec_diag, 0, sizeof(g_fec_diag));
        g_fec_diag.enabled = 1; g_fec_diag.owner = w;
        dg_begin(w);
        if (kind <= 2) { s->xmit = kind == 1 ? 1 : 0; write_data_seg(w, w->dflt, s); }
        if (kind == 2 || kind == 3) write_ctrl_seg(w, 0, CTRL_PARITY, parity, sizeof(parity));
        if (kind == 4) write_ctrl_seg(w, 0, CTRL_ECHO, parity, ECHO_BODY);
        dg_seal(w);
        CHECK(!g_fec_diag.accounting_errors && g_fec_diag.overhead == ANL_OVERHEAD, "exact encapsulation kind=%d: %llu", kind, (unsigned long long)g_fec_diag.overhead);
        if (kind == 0) CHECK(g_fec_diag.sent[0].first == 105 && g_fec_diag.output == 124, "last DATA omits one-byte length");
        if (kind == 1) CHECK(g_fec_diag.sent[0].retry == 105 && g_fec_diag.output == 124, "last retransmit omits length");
        if (kind == 2) CHECK(g_fec_diag.sent[0].first == 106 && g_fec_diag.sent[0].parity == 202 && !g_fec_diag.parity_datagrams[0], "mixed DATA/PARITY: only last segment loses length");
        if (kind == 3) CHECK(g_fec_diag.sent[0].parity == 202 && g_fec_diag.parity_output[0] == 221 && g_fec_diag.parity_datagrams[0] == 1, "pure parity omits two-byte length");
        if (kind == 4) CHECK(g_fec_diag.control == 5 && g_fec_diag.output == 24, "last control omits length");
    }
    seg_free(s); anl_release(w);
    memset(&g_fec_diag, 0, sizeof(g_fec_diag));
}

int main(void)
{
    run_exact_cost();
    run_cost(0); run_cost(1);
    if (g_fail) return 1;
    puts("FEC byte accounting passed");
    return 0;
}
