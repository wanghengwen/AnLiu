/* Socket-free FECCOST accounting on loss/retransmission and FEC paths.
 * cc -std=c99 -O2 -Wall -Wextra -Werror -pedantic bench/test_fec_diag.c -o /tmp/test_fec_diag
 */
#include "../anliu.h"
static void trace_seg_commit(const anl_t *, uint32_t, int);
static void trace_data_seg(const anl_t *, const anl_stream_t *, uint32_t, int);
static void trace_parity_seg(const anl_t *, int, uint32_t);
static void trace_fec_block(const anl_t *, const anl_stream_t *, uint32_t, uint32_t);
static void trace_diag_output(const anl_t *, uint32_t, int);
#define ANL_SEG_COMMIT_TRACE trace_seg_commit
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
        CHECK(g_fec_diag.parity_datagrams[2] > 0 && g_fec_diag.parity_output[2] > g_fec_diag.sent[2].parity,
              "whole parity datagrams include their own encapsulation");
    }
    else CHECK(g_fec_diag.sent[1].retry > 0 && !g_fec_diag.sent[1].parity, "retransmissions without FEC");
    fec_diag_print(n.ep[0]);
    net_stop(&n);
}

int main(void)
{
    run_cost(0); run_cost(1);
    if (g_fail) return 1;
    puts("FEC byte accounting passed");
    return 0;
}
