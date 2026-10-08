/*
 * fuzz_peer.c - libFuzzer target for the receive path under the "peer holds
 * the PSK" model (SECURITY_AUDIT.md 4). A key holder can make any plaintext
 * authenticate, so what it reaches is anl_input_plain: the datagram header
 * and every segment type. The fuzzer input is fed there directly - what
 * siv_open hands the parser after a successful check.
 *
 * Each input runs on a fresh connection (a server with a reliable stream and
 * a semi-reliable FEC stream of its own; the peer may open more), so a
 * finding replays from its input alone. The input is a sequence of
 * datagrams, each a 2-byte little-endian length and that many bytes; the
 * conv and version bits are set right so the segments get parsed, ts and pn
 * stay fuzzed. Besides the sanitizers, the target checks after every
 * datagram that the default stream is still there and that no stream holds
 * more than its window.
 *
 * Build (Clang): cmake -DANLIU_BUILD_FUZZERS=ON, or
 *   clang -fsanitize=fuzzer,address,undefined -g -O1 -I../.. fuzz_peer.c
 * Seeds: make_seeds.c writes datagrams of a real exchange in this format.
 */
#include "../../anliu.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_CONV   0x11223344u
#define FUZZ_DGRAMS 64          /* datagrams per input at most */

static int drop_output(char *buf, int len, anl_t *w, void *user)
{
    (void)buf; (void)len; (void)w; (void)user;
    return 0;
}

static int accept_all(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    (void)w; (void)s; (void)opt; (void)user;
    return 0;
}

static anl_t *victim_create(uint32_t now)
{
    anl_config cs;
    anl_stream_opt o;
    anl_t *w;
    int i;
    anl_config_default(&cs, ANL_ROLE_SERVER);
    for (i = 0; i < ANL_PSK_SIZE; i++) cs.psk[i] = (uint8_t)(0x20 + i);
    cs.idle_timeout_ms = 0;
    w = anl_create(FUZZ_CONV, &cs, NULL);
    if (w == NULL) abort();
    anl_setoutput(w, drop_output);
    anl_set_accept(w, accept_all);
    anl_update(w, now);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    (void)anl_stream_open(w, &o, NULL);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1;
    o.fec_ratio = 50;
    (void)anl_stream_open(w, &o, NULL);
    return w;
}

static void drain(anl_t *w)
{
    anl_stream_t *list[ANL_MAX_STREAMS];
    static char buf[1 << 16];
    anl_frame_info fi;
    int n, i;
    n = anl_readable(w, list, ANL_MAX_STREAMS);
    for (i = 0; i < n && i < ANL_MAX_STREAMS; i++) {
        while (anl_stream_recv(list[i], buf, sizeof(buf)) > 0) { }
        while (anl_stream_recv_frame(list[i], buf, sizeof(buf), &fi) > 0) { }
    }
    while (anl_recv(w, buf, sizeof(buf)) > 0) { }
}

/* what no peer may break, whatever it sends */
static void check_invariants(const anl_t *w)
{
    uint32_t i;
    if (sget(w, ANL_SID_DEFAULT) != w->dflt || w->dflt->state != ANL_STREAM_OPEN) {
        fprintf(stderr, "invariant: the default stream is gone\n");
        abort();
    }
    for (i = 0; i < w->nstab; i++) {
        const anl_stream *st = w->stab[i];
        if (st->nrcv_buf > st->rcv_wnd || st->nrcv_que > st->rcv_wnd) {
            fprintf(stderr, "invariant: sid %d holds %u + %u segments, window %u\n",
                    st->sid, st->nrcv_buf, st->nrcv_que, st->rcv_wnd);
            abort();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *p = data, *end = data + size;
    uint32_t now = 100000;
    anl_t *w = victim_create(now);
    char dg[2048];
    int k;

    for (k = 0; k < FUZZ_DGRAMS && end - p >= 2; k++) {
        size_t n = (size_t)p[0] | ((size_t)p[1] << 8), len;
        p += 2;
        len = n < (size_t)(end - p) ? n : (size_t)(end - p);
        if (len > sizeof(dg)) len = sizeof(dg);
        memcpy(dg, p, len);
        p += len;
        if (len >= ANL_HDR_SIZE) {
            (void)enc32(dg, FUZZ_CONV);
            dg[4] = (char)((ANL_VERSION << 6) | (dg[4] & FLG_PAD));
        }
        (void)anl_input_plain(w, dg, (long)len);
        check_invariants(w);
        drain(w);
        now += 5;
        anl_update(w, now);         /* timers, deadlines and retransmissions over what arrived */
        check_invariants(w);
    }
    anl_update(w, now + 1000);
    check_invariants(w);
    anl_release(w);
    return 0;
}
