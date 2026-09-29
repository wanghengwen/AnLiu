/*
 * test.c - AnLiu loopback simulator and test suite (DESIGN.md M6).
 *
 * Build:  gcc -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined test.c -o anl_test
 * Run:    ./anl_test
 *
 * anliu.c is included directly so that the crypto primitives (static) can be
 * checked against known-answer vectors.
 */
#include "anliu.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { g_fail++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/*---------------------------------------------------------------------
 * deterministic random
 *-------------------------------------------------------------------*/
static uint64_t g_seed = 0x9E3779B97F4A7C15ULL;
static uint32_t rnd(void)
{
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 7; g_seed ^= g_seed << 17;
    return (uint32_t)(g_seed >> 16);
}
static int rnd_pct(void) { return (int)(rnd() % 100); }

/*---------------------------------------------------------------------
 * network simulator
 *-------------------------------------------------------------------*/
typedef struct pkt {
    struct pkt *next;
    uint32_t deliver_at;
    int to;
    int len;
    char data[2048];
} pkt;

typedef struct net {
    int loss_pct, dup_pct, min_delay, max_delay;
    int reflect;                    /* send packets back to the sender */
    uint32_t drop_at[4];            /* != 0: drop the datagrams with these n->sent numbers */
    int reorder;                    /* 1 = jitter may reorder datagrams; 0 = FIFO path */
    uint32_t last_at[2];            /* last scheduled delivery per direction (FIFO) */
    int bandwidth_bps;              /* 0 = unlimited; otherwise a bottleneck queue */
    int queue_limit;                /* max queued packets at the bottleneck */
    uint32_t link_free_at[2];
    int link_queued[2];
    pkt *queue;
    uint32_t now;
    long sent, lost, delivered;
    anl_t *ep[2];
    int ep_idx[2];
    /* captured datagram for replay tests */
    char cap[2048]; int cap_len; int cap_from;
    uint32_t burst_window_bytes[2]; uint32_t burst_window_start[2]; uint32_t max_burst[2];
} net;

static void net_enqueue(net *n, int to, const char *data, int len, uint32_t at)
{
    pkt *p = (pkt *)malloc(sizeof(pkt)), **pp;
    p->deliver_at = at; p->to = to; p->len = len; memcpy(p->data, data, (size_t)len);
    for (pp = &n->queue; *pp && (int32_t)((*pp)->deliver_at - at) <= 0; pp = &(*pp)->next) ;
    p->next = *pp; *pp = p;
}

static int net_output(const char *buf, int len, anl_t *w, void *user)
{
    int *idx = (int *)user;
    net *n = (net *)((char *)idx - offsetof(net, ep_idx) - (size_t)(*idx) * sizeof(int));
    int from = *idx, to = n->reflect ? from : 1 - from;
    uint32_t delay;
    (void)w;
    n->sent++;
    {
        int d;
        for (d = 0; d < 4; d++)
            if (n->drop_at[d] != 0 && (uint32_t)n->sent == n->drop_at[d]) { n->lost++; return 0; }
    }
    /* burst measurement over a 5 ms window */
    if ((int32_t)(n->now - n->burst_window_start[from]) >= 5) { n->burst_window_start[from] = n->now; n->burst_window_bytes[from] = 0; }
    n->burst_window_bytes[from] += (uint32_t)len;
    if (n->burst_window_bytes[from] > n->max_burst[from]) n->max_burst[from] = n->burst_window_bytes[from];

    if (n->cap_len == 0 && len > 60 && from == 0) { memcpy(n->cap, buf, (size_t)len); n->cap_len = len; n->cap_from = from; }
    if (rnd_pct() < n->loss_pct) { n->lost++; return 0; }
    delay = (uint32_t)n->min_delay + (n->max_delay > n->min_delay ? rnd() % (uint32_t)(n->max_delay - n->min_delay) : 0);
    if (!n->reorder && (int32_t)(n->now + delay - n->last_at[from]) < 0) delay = n->last_at[from] - n->now;
    n->last_at[from] = n->now + delay;
    if (n->bandwidth_bps > 0) {
        uint32_t serial = (uint32_t)((uint64_t)len * 8000 / (uint64_t)n->bandwidth_bps) + 1;
        uint32_t start = (int32_t)(n->link_free_at[from] - n->now) > 0 ? n->link_free_at[from] : n->now;
        if (n->queue_limit > 0 && (int32_t)(start - n->now) > (int32_t)(serial * (uint32_t)n->queue_limit)) { n->lost++; return 0; }
        n->link_free_at[from] = start + serial;
        delay += start + serial - n->now;
    }
    net_enqueue(n, to, buf, len, n->now + delay);
    if (rnd_pct() < n->dup_pct) net_enqueue(n, to, buf, len, n->now + delay + 1 + rnd() % 10);
    return 0;
}

static void net_deliver(net *n)
{
    while (n->queue && (int32_t)(n->queue->deliver_at - n->now) <= 0) {
        pkt *p = n->queue;
        n->queue = p->next;
        n->delivered++;
        anl_input(n->ep[p->to], p->data, p->len);
        free(p);
    }
}

static void net_free(net *n)
{
    while (n->queue) { pkt *p = n->queue; n->queue = p->next; free(p); }
}

/* deterministic padding / PRNG so that a test run is reproducible from g_seed */
static void det_rng(void *user, uint8_t *buf, size_t n)
{
    (void)user;
    while (n--) *buf++ = (uint8_t)rnd();
}

static void net_init(net *n, anl_config *ca, anl_config *cb)
{
    memset(n, 0, sizeof(*n));
    n->ep_idx[0] = 0; n->ep_idx[1] = 1;
    n->min_delay = 20; n->max_delay = 40;
    n->now = 1000;
    anl_config_default(ca, ANL_ROLE_CLIENT);
    anl_config_default(cb, ANL_ROLE_SERVER);
    memset(ca->psk, 0x42, 32);
    memset(cb->psk, 0x42, 32);
    ca->rng = cb->rng = det_rng;
}

/* accept callback shared by all tests: records the handle per side and sid and
 * applies the local options the test wants on the accepting side */
static anl_stream_t *g_peer[2][ANL_MAX_STREAMS];
static const anl_stream_opt *g_peer_opt[2];
static int g_acc[2], g_acc_reject_mod, g_acc_rcv_wnd;

static int acc_cb(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    int side = *(int *)user, sid = anl_stream_id(s);
    (void)w;
    if (g_acc_reject_mod && sid % g_acc_reject_mod == 2) return -1;
    if (g_peer_opt[side]) {
        anl_stream_opt keep = *opt;
        *opt = *g_peer_opt[side];
        opt->mode = keep.mode; opt->stream = keep.stream; opt->tag = keep.tag;
    }
    if (g_acc_rcv_wnd) opt->rcv_wnd = g_acc_rcv_wnd;
    g_peer[side][sid] = s;
    g_acc[side]++;
    return 0;
}

static void net_start(net *n, const anl_config *ca, const anl_config *cb)
{
    memset(g_peer, 0, sizeof(g_peer));
    g_peer_opt[0] = g_peer_opt[1] = NULL;
    g_acc[0] = g_acc[1] = 0; g_acc_reject_mod = 0; g_acc_rcv_wnd = 0;
    n->ep[0] = anl_create(0x11223344, ca, &n->ep_idx[0]);
    n->ep[1] = anl_create(0x11223344, cb, &n->ep_idx[1]);
    anl_setoutput(n->ep[0], net_output);
    anl_setoutput(n->ep[1], net_output);
    anl_set_accept(n->ep[0], acc_cb);
    anl_set_accept(n->ep[1], acc_cb);
    anl_update(n->ep[0], n->now);
    anl_update(n->ep[1], n->now);
}

static void net_stop(net *n)
{
    anl_release(n->ep[0]);
    anl_release(n->ep[1]);
    net_free(n);
}

/* advance one millisecond */
static void net_tick(net *n)
{
    n->now++;
    net_deliver(n);
    anl_update(n->ep[0], n->now);
    anl_update(n->ep[1], n->now);
}

/*---------------------------------------------------------------------
 * 1. known-answer tests
 *-------------------------------------------------------------------*/
static void hex2bin(const char *hex, uint8_t *out, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_kat(void)
{
    uint8_t key[32], nonce[12], out[64], exp[128];
    size_t i;
    printf("[kat]\n");

    /* RFC 8439 2.3.2 block function */
    for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
    hex2bin("000000090000004a00000000", nonce, 12);
    chacha20_block(key, 1, nonce, out);
    hex2bin("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", exp, 64);
    CHECK(memcmp(out, exp, 64) == 0, "chacha20 block vector");

    /* RFC 8439 2.4.2 encryption */
    {
        const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        uint8_t buf[128];
        size_t len = strlen(pt);
        memcpy(buf, pt, len);
        hex2bin("000000000000004a00000000", nonce, 12);
        chacha20_xor(key, nonce, 1, buf, len);
        hex2bin("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", exp, len);
        CHECK(memcmp(buf, exp, len) == 0, "chacha20 encryption vector");
    }

    /* SipHash-2-4-128 reference vectors, key 00..0f, msg 00..len-1 */
    {
        uint8_t k[16], msg[16], tag[16];
        for (i = 0; i < 16; i++) { k[i] = (uint8_t)i; msg[i] = (uint8_t)i; }
        siphash128(k, msg, 0, tag);
        hex2bin("a3817f04ba25a8e66df67214c7550293", exp, 16);
        CHECK(memcmp(tag, exp, 16) == 0, "siphash128 len 0");
        siphash128(k, msg, 1, tag);
        hex2bin("da87c1d86b99af44347659119b22fc45", exp, 16);
        CHECK(memcmp(tag, exp, 16) == 0, "siphash128 len 1");
    }

    /* SIV round trip, direction separation, tamper detection */
    {
        anl_keys keys;
        uint8_t psk[32], wire[200], plain[200];
        int r;
        for (i = 0; i < 32; i++) psk[i] = (uint8_t)(0xa0 + i);
        anl_keys_derive(&keys, psk);
        CHECK(memcmp(keys.enc[0], keys.enc[1], 32) != 0, "direction keys differ");
        memset(wire, 0, sizeof(wire));
        for (i = 0; i < 100; i++) wire[ANL_TAG_SIZE + i] = (uint8_t)(i * 7);
        siv_seal(&keys, 0, wire, 100);
        r = siv_open(&keys, 0, wire, 112, plain);
        CHECK(r == 100, "siv open ok (%d)", r);
        for (i = 0; i < 100 && r == 100; i++) CHECK(plain[i] == (uint8_t)(i * 7), "siv plaintext byte %zu", i);
        r = siv_open(&keys, 1, wire, 112, plain);
        CHECK(r == ANL_EAUTH, "reflected datagram rejected (%d)", r);
        wire[50] ^= 1;
        r = siv_open(&keys, 0, wire, 112, plain);
        CHECK(r == ANL_EAUTH, "tampered datagram rejected (%d)", r);
    }

    /* varint */
    {
        char b[8]; const char *p; uint32_t v;
        uint32_t vals[] = { 0, 1, 127, 128, 16383, 16384, VARINT_MAX };
        for (i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
            char *e = enc_varint(b, vals[i]);
            p = b;
            CHECK(dec_varint(&p, b + 8, &v) == 0 && v == vals[i] && p == e && (e - b) == varint_size(vals[i]),
                  "varint %u", vals[i]);
        }
    }
}

/*---------------------------------------------------------------------
 * helpers for streams
 *-------------------------------------------------------------------*/
static void fill_pattern(char *buf, int len, uint32_t seed)
{
    int i;
    for (i = 0; i < len; i++) buf[i] = (char)(uint8_t)((seed * 2654435761u + (uint32_t)i * 40503u) >> 13);
}

static int check_pattern(const char *buf, int len, uint32_t seed)
{
    int i;
    for (i = 0; i < len; i++) if (buf[i] != (char)(uint8_t)((seed * 2654435761u + (uint32_t)i * 40503u) >> 13)) return 0;
    return 1;
}

/* opens a stream on side `from` and runs the network until the other side has
 * accepted it; `peer` (or `mine` when NULL) gives the accepting side's options */
static anl_stream_t *open_pair(net *n, int from, const anl_stream_opt *mine, const anl_stream_opt *peer,
                               anl_stream_t **other)
{
    int err = 0, i, sid;
    anl_stream_t *s = anl_stream_open(n->ep[from], mine, &err);
    *other = NULL;
    CHECK(s != NULL, "anl_stream_open failed (%d)", err);
    if (s == NULL) return NULL;
    sid = anl_stream_id(s);
    g_peer[1 - from][sid] = NULL;               /* forget an earlier incarnation of this sid */
    g_peer_opt[1 - from] = peer ? peer : mine;
    /* before the first RTT sample STREAM_OPEN is resent after 0.2, 0.6, 1.4,
       3.0 s (RTO_DEF, doubling) */
    for (i = 0; i < 6000 && g_peer[1 - from][sid] == NULL; i++) net_tick(n);
    g_peer_opt[1 - from] = NULL;
    *other = g_peer[1 - from][sid];
    CHECK(*other != NULL, "peer accepted sid %d", sid);
    return s;
}

/* stream structs in the connection besides the default one (incl. handles
 * the application still holds after the stream is over) */
static int stream_count(const anl_t *w, int *detached)
{
    const anl_node *n;
    int c = 0, d = 0;
    for (n = w->slist.next; n != &w->slist; n = n->next) {
        if (STREAM_OF(n)->strict) continue;
        c++;
        if (STREAM_OF(n)->detached) d++;
    }
    if (detached) *detached = d;
    return c;
}

/* diagnostics: remaining non-default streams */
static void dump_streams(const char *who, const anl_t *w)
{
    const anl_node *n;
    for (n = w->slist.next; n != &w->slist; n = n->next) {
        const anl_stream *st = STREAM_OF(n);
        if (st->strict) continue;
        printf("    %s sid %d state %d detached %d released %d peer_opened %d peer_closed %d peer_released %d "
               "close_xmit %u snd que/buf %u/%u rcv_nxt %u peer_final %u rcvq %u ack %d\n",
               who, st->sid, st->state, st->detached, st->app_released, st->peer_opened, st->peer_closed,
               st->peer_released, st->close_xmit, st->nsnd_que, st->nsnd_buf, st->rcv_nxt, st->peer_final_sn,
               st->nrcv_que, st->ack_pending);
    }
}

static int stream_state(const anl_stream_t *s)
{
    anl_stream_stats ss;
    anl_stream_get_stats(s, &ss);
    return ss.state;
}

/*---------------------------------------------------------------------
 * 2. default stream and reliable streams
 *-------------------------------------------------------------------*/
static void test_default_stream(void)
{
    net n; anl_config ca, cb; anl_stream_stats ss;
    static char buf[200000], out[200000];
    int i, r, got[2] = { 0, 0 }, side;
    const int total = 150000;
    printf("[default stream: usable at once, byte stream, windows from config]\n");
    net_init(&n, &ca, &cb);
    n.loss_pct = 5;
    cb.default_rcv_wnd = 700;
    net_start(&n, &ca, &cb);
    CHECK(anl_stream_id(anl_default_stream(n.ep[0])) == ANL_SID_DEFAULT, "default stream is sid 0");
    CHECK(anl_stream_close(anl_default_stream(n.ep[0])) == ANL_EINVAL, "default stream cannot be closed");
    /* no handshake: send right after anl_create, in 3 uneven chunks, both directions */
    fill_pattern(buf, total, 77);
    for (side = 0; side < 2; side++) {
        CHECK(anl_send(n.ep[side], buf, 1) == 0, "send before any datagram was exchanged");
        CHECK(anl_send(n.ep[side], buf + 1, 70000) == 0, "send 70000");
        CHECK(anl_send(n.ep[side], buf + 70001, total - 70001) == 0, "send rest");
    }
    for (i = 0; i < 20000 && (got[0] < total || got[1] < total); i++) {
        net_tick(&n);
        for (side = 0; side < 2; side++)
            while ((r = anl_recv(n.ep[side], out + got[side], sizeof(out) - (size_t)got[side])) > 0) got[side] += r;
    }
    CHECK(got[0] == total && got[1] == total && memcmp(out, buf, (size_t)total) == 0, "byte stream intact (%d / %d)", got[0], got[1]);
    anl_stream_get_stats(anl_default_stream(n.ep[0]), &ss);
    CHECK(ss.state == ANL_STREAM_OPEN && ss.rmt_wnd <= 700, "A heard B, B's window is 700 (%d, %u)", ss.state, ss.rmt_wnd);
    anl_stream_get_stats(anl_default_stream(n.ep[1]), &ss);
    CHECK(ss.state == ANL_STREAM_OPEN && ss.rmt_wnd <= 1200 && ss.rmt_wnd > 700, "B heard A, A's window is 1200 (%d, %u)", ss.state, ss.rmt_wnd);
    CHECK(n.ep[1]->dflt->rcv_wnd == 700 && n.ep[0]->dflt->rcv_wnd == 1200, "windows from config");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d bytes each way in %d ms with 5%% loss\n", total, i);
    net_stop(&n);
}

static void test_reliable(int loss, int stream_mode)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[70000];
    uint32_t sent[2] = { 0, 0 }, rcvd[2] = { 0, 0 };
    const uint32_t total = 300;
    uint32_t stream_pos[2] = { 0, 0 };
    int side, done = 0, iter;
    anl_stream_t *s[2];

    printf("[reliable loss=%d%% stream=%d]\n", loss, stream_mode);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss; n.dup_pct = 2;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.stream = stream_mode;
    o.snd_wnd = 128;
    o.rcv_wnd = 256;
    s[0] = open_pair(&n, 0, &o, NULL, &s[1]);
    if (!s[1]) { net_stop(&n); return; }

    for (iter = 0; iter < 200000 && !done; iter++) {
        net_tick(&n);
        for (side = 0; side < 2; side++) {
            /* producer: variable sized messages, keep queue bounded */
            if (sent[side] < total && anl_stream_waitsnd(s[side]) < 64) {
                int len = stream_mode ? 1 + (int)(rnd() % 3000) : 1 + (int)(rnd() % 60000);
                int r;
                if (stream_mode) {
                    int i;
                    for (i = 0; i < len; i++) buf[i] = (char)(uint8_t)((stream_pos[side] + (uint32_t)i) * 31u + 7u);
                    stream_pos[side] += (uint32_t)len;
                } else {
                    fill_pattern(buf, len, sent[side]);
                }
                r = anl_stream_send(s[side], buf, len);
                if (r == 0) sent[side]++;
                else if (stream_mode) stream_pos[side] -= (uint32_t)len;
                CHECK(r == 0 || r == ANL_ETOOBIG, "send r=%d", r);
            }
            for (;;) {
                int r = anl_stream_recv(s[side], buf, sizeof(buf));
                if (r < 0) { CHECK(r == ANL_EAGAIN, "recv r=%d", r); break; }
                if (stream_mode) {
                    int i;
                    for (i = 0; i < r; i++) {
                        if (buf[i] != (char)(uint8_t)((rcvd[side] + (uint32_t)i) * 31u + 7u)) { CHECK(0, "stream content mismatch at %u", rcvd[side] + (uint32_t)i); break; }
                    }
                    rcvd[side] += (uint32_t)r;
                } else {
                    CHECK(check_pattern(buf, r, rcvd[side]), "message %u content", rcvd[side]);
                    rcvd[side]++;
                }
            }
        }
        if (stream_mode) done = rcvd[0] == stream_pos[1] && rcvd[1] == stream_pos[0] && sent[0] == total && sent[1] == total;
        else done = rcvd[0] == total && rcvd[1] == total;
    }
    CHECK(done, "transfer completed (A got %u, B got %u)", rcvd[0], rcvd[1]);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    {
        anl_stats st; anl_get_stats(n.ep[0], &st);
        printf("  %d ms, srtt=%u rto=%u cwnd=%u retrans=%u tx=%llu rx=%llu\n", (int)(n.now - 1000), st.srtt, st.rto, st.cwnd, st.retrans,
               (unsigned long long)st.tx_datagrams, (unsigned long long)st.rx_datagrams);
    }
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 3. semi-reliable frames
 *-------------------------------------------------------------------*/
static void test_semi(int loss, int fec, int bandwidth_kbps)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[70000];
    uint32_t frames = 0, delivered = 0, last_fno = 0, lost_total = 0, bad = 0;
    int have_last = 0, iter;
    uint32_t next_frame_at;
    anl_stream_t *a, *b;

    printf("[semi loss=%d%% fec=%d bw=%dkbps]\n", loss, fec, bandwidth_kbps);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss; n.min_delay = 15; n.max_delay = 25;
    n.bandwidth_bps = bandwidth_kbps * 1000; n.queue_limit = 30;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = fec; o.fec_ratio = 25;
    o.max_age_ms = 300;
    o.rcv_deadline_ms = 400;
    o.drop_until_key = 1;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    next_frame_at = n.now + 100;

    for (iter = 0; iter < 8000; iter++) {
        net_tick(&n);
        if ((int32_t)(n.now - next_frame_at) >= 0 && frames < 200) {
            uint32_t fno = 0xffffffffu;
            int key = (frames % 30) == 0;
            int len = key ? 20000 + (int)(rnd() % 10000) : 1500 + (int)(rnd() % 4000);
            int r;
            next_frame_at += 33;
            fill_pattern(buf, len, frames);
            r = anl_stream_send_frame(a, key ? ANL_FRAME_KEY : 0, buf, len, &fno);
            CHECK(r == 0 || r == ANL_EDROPPED, "send_frame r=%d", r);
            CHECK(fno == frames, "frame_no assigned %u expected %u", fno, frames);
            frames++;
        }
        for (;;) {
            anl_frame_info info;
            int r = anl_stream_recv_frame(b, buf, sizeof(buf), &info);
            if (r < 0) { CHECK(r == ANL_EAGAIN, "recv_frame r=%d", r); break; }
            if (!check_pattern(buf, r, info.frame_no)) bad++;
            if (have_last) {
                CHECK((int32_t)(info.frame_no - last_fno) > 0, "frame order %u after %u", info.frame_no, last_fno);
                CHECK(info.lost_before == info.frame_no - last_fno - 1, "lost_before %u", info.lost_before);
            }
            lost_total += info.lost_before;
            last_fno = info.frame_no; have_last = 1;
            delivered++;
        }
    }
    CHECK(bad == 0, "corrupted frames: %u", bad);
    CHECK(delivered > 0, "some frames delivered");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    {
        anl_stream_stats ss0, ss1; anl_stats st;
        anl_stream_get_stats(a, &ss0);
        anl_stream_get_stats(b, &ss1);
        anl_get_stats(n.ep[0], &st);
        printf("  sent=%u delivered=%u lost=%u dropped(snd)=%u skipped(rcv)=%u fec_recovered=%u retrans=%u srtt=%u pace=%u B/s\n",
               frames, delivered, lost_total, ss0.frames_dropped, ss1.frames_skipped, ss1.fec_recovered, st.retrans, st.srtt, st.pace_rate);
        if (fec && loss > 0) CHECK(ss1.fec_recovered > 0, "fec recovered something");
        if (bandwidth_kbps > 0 && bandwidth_kbps < 1500) CHECK(ss0.frames_dropped > 0, "congested link drops frames at sender");
        CHECK(delivered + lost_total == last_fno + 1, "accounting: delivered + lost == last+1");
    }
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 4. reflection, stale replay, protocol violation, close, pacing, demux
 *-------------------------------------------------------------------*/
static void test_reflect(void)
{
    net n; anl_config ca, cb; anl_stats st;
    char buf[100];
    int i;
    printf("[reflect]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    for (i = 0; i < 200; i++) net_tick(&n);
    n.reflect = 1;
    for (i = 0; i < 20; i++) { fill_pattern(buf, 100, (uint32_t)i); anl_send(n.ep[0], buf, 100); }
    for (i = 0; i < 1000; i++) net_tick(&n);
    anl_get_stats(n.ep[0], &st);
    CHECK(st.rx_auth_fail > 0, "reflected packets fail auth (%llu)", (unsigned long long)st.rx_auth_fail);
    CHECK(anl_peeksize(n.ep[0]) == ANL_EAGAIN, "reflected data not accepted");
    net_stop(&n);
}

static void test_stale(void)
{
    net n; anl_config ca, cb;
    char buf[100];
    int i, r;
    printf("[stale replay]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 5;
    net_start(&n, &ca, &cb);
    for (i = 0; i < 100; i++) net_tick(&n);
    fill_pattern(buf, 100, 1);
    n.cap_len = 0;
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(n.cap_len > 0, "captured a datagram");
    r = anl_input(n.ep[1], n.cap, n.cap_len);
    CHECK(r == ANL_OK, "replay inside window accepted as duplicate (%d)", r);
    for (i = 0; i < 2500; i++) net_tick(&n);        /* keep traffic flowing to advance peer_ts */
    anl_send(n.ep[0], buf, 100);
    for (i = 0; i < 100; i++) net_tick(&n);
    r = anl_input(n.ep[1], n.cap, n.cap_len);
    CHECK(r == ANL_ESTALE, "replay outside window rejected (%d)", r);
    net_stop(&n);
}

/* a peer that sends FWD on a reliable stream puts it into the error state */
static void test_violation(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    char pl[32], *q = pl, buf[16];
    int i, r;
    printf("[protocol violation: FWD on a reliable stream]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    q = enc32(q, 0x11223344); q = enc8(q, 0); q = enc32(q, n.now);
    q = enc_sid(q, SEG_FWD, anl_stream_id(b));
    q = enc16(q, 5);
    r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
    CHECK(r == ANL_OK, "input (%d)", r);
    CHECK(stream_state(b) == ANL_STREAM_CLOSED, "B stream reset (%d)", stream_state(b));
    CHECK(anl_stream_recv(b, buf, sizeof(buf)) == ANL_ECLOSED, "recv on reset stream");
    CHECK(anl_stream_send(b, "x", 1) == ANL_ECLOSED, "send on reset stream");
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_state(a) == ANL_STREAM_CLOSED, "A got the RST (%d)", stream_state(a));
    CHECK(anl_stream_send(a, "x", 1) == ANL_ECLOSED, "send after RST");
    CHECK(anl_stream_close(b) == 0 && anl_stream_close(a) == 0, "both handles released");
    for (i = 0; i < 3000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "both freed");
    CHECK(anl_send(n.ep[0], "ok", 2) == 0 && anl_state(n.ep[0]) == 0, "connection survives");
    net_stop(&n);
}

/* segments cut before the peer answered carry the stream parameters and are
   OPEN_BODY smaller; later ones use the full connection mss (DESIGN 5.2) */
static void test_seg_size(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[4 * 1400];
    anl_stream_t *a, *b = NULL;
    uint32_t mss, before;
    int i, r, got = 0;
    printf("[segment size before / after the peer answered]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    mss = n.ep[0]->mss;
    CHECK(mss == (uint32_t)ca.mtu - ANL_OVERHEAD - DATA_HDR_MAX, "connection mss %u excludes the stream parameters", mss);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    a = anl_stream_open(n.ep[0], &o, NULL);
    CHECK(a && !a->peer_opened, "peer not heard yet");
    fill_pattern(buf, (int)mss, 0);
    CHECK(anl_stream_send(a, buf, (int)mss) == 0 && a->nsnd_que == 2, "mss bytes before the answer: 2 segments (%u)", a->nsnd_que);
    CHECK(qfirst_seg(&a->snd_queue)->len == mss - OPEN_BODY, "first segment mss - OPEN_BODY");
    for (i = 0; i < 3000 && !a->peer_opened; i++) net_tick(&n);
    CHECK(a->peer_opened, "peer answered");
    fill_pattern(buf, 3 * (int)mss, 1);
    before = a->nsnd_que + a->nsnd_buf;
    r = anl_stream_send(a, buf, 3 * (int)mss);
    CHECK(r == 0 && a->nsnd_que + a->nsnd_buf - before == 3, "3 * mss bytes after the answer: 3 segments (%u)", a->nsnd_que + a->nsnd_buf - before);
    for (i = 0; i < 3000 && got < 2; i++) {
        anl_stream_t *list[4];
        int k, cnt;
        net_tick(&n);
        cnt = anl_readable(n.ep[1], list, 4);
        for (k = 0; k < cnt && k < 4; k++) {
            if (list[k] == anl_default_stream(n.ep[1])) continue;
            b = list[k];
            while ((r = anl_stream_recv(b, buf, sizeof(buf))) > 0) {
                CHECK(r == (int)mss * (got ? 3 : 1) && check_pattern(buf, r, (uint32_t)got), "message %d intact (%d)", got, r);
                got++;
            }
        }
    }
    CHECK(got == 2, "both messages delivered (%d)", got);
    net_stop(&n);
}

/* the opener sends and closes at once; the peer reads everything, then EOF */
static void test_open_close(int loss)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    char buf[5000];
    int i, got = 0, r = 0, eof = 0;
    anl_stream_t *a, *b = NULL;
    printf("[open, send, close at once; peer reads to end of stream, loss=%d%%]\n", loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.tag = 4242;
    a = anl_stream_open(n.ep[0], &o, NULL);
    for (i = 0; i < 10; i++) { fill_pattern(buf, 4000, (uint32_t)i); CHECK(anl_stream_send(a, buf, 4000) == 0, "send before peer open"); }
    CHECK(anl_stream_close(a) == 0, "close right away, handle released");
    for (i = 0; i < 20000 && !eof; i++) {        /* 15% loss: a segment may need ~7 retransmissions (backoff) */
        anl_stream_t *list[4];
        int k, cnt;
        net_tick(&n);
        cnt = anl_readable(n.ep[1], list, 4);
        for (k = 0; k < cnt && k < 4; k++) {
            if (list[k] == anl_default_stream(n.ep[1])) continue;
            b = list[k];
            while ((r = anl_stream_recv(b, buf, sizeof(buf))) > 0) { CHECK(check_pattern(buf, r, (uint32_t)got), "content %d", got); got++; }
            if (r == ANL_ECLOSED) eof = 1;
        }
    }
    CHECK(b && anl_stream_tag(b) == 4242, "peer sees the tag");
    CHECK(got == 10 && eof, "peer read 10 messages then end of stream (%d, eof %d)", got, eof);
    CHECK(b && anl_stream_send(b, "x", 1) == ANL_ECLOSED, "send on a stream the peer closed");
    /* CLOSE exchange under loss: each round (CLOSE there, answer back) fails
       with ~28% at 15% loss both ways, and the CLOSE interval grows x1.5 per
       retry: a few failed rounds in a row take several seconds */
    for (i = 0; i < 30000 && stream_count(n.ep[0], NULL); i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0, "opener side freed (%d ms)", i);
    CHECK(stream_count(n.ep[1], NULL) == 1, "peer handle kept until the application closes it");
    CHECK(b && stream_state(b) == ANL_STREAM_CLOSED && anl_stream_recv(b, buf, sizeof(buf)) == ANL_ECLOSED, "held handle still answers");
    if (b) anl_stream_close(b);
    for (i = 0; i < 100 && stream_count(n.ep[1], NULL); i++) net_tick(&n);
    CHECK(stream_count(n.ep[1], NULL) == 0, "freed after close");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* a semi-reliable stream is aborted by close (DESIGN 6.1): frames in flight
 * are dropped, the peer sees the end of the stream about one RTT later, and
 * both sides free the stream - closed by the sender or by the receiver */
static void test_semi_abort(int loss, int by_receiver)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[20000];
    int i, r, frames = 0, got = 0, eof = 0, t_close = 0, t_eof = -1;
    anl_stream_t *a, *b;
    anl_frame_info fi;
    printf("[semi-reliable abort by the %s, loss=%d%%]\n", by_receiver ? "receiver" : "sender", loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 20000 && t_eof < 0; i++) {
        net_tick(&n);
        if (a && i % 33 == 0) {                             /* 30 fps, 12 KB frames */
            fill_pattern(buf, 12000, (uint32_t)frames);
            r = anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 12000, NULL);
            if (r == ANL_ECLOSED) { t_eof = i; break; }     /* receiver aborted: the sender learns */
            frames++;
        }
        if (b) while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            CHECK(r == 12000 && check_pattern(buf, r, fi.frame_no), "frame %u intact", fi.frame_no);
            got++;
        }
        if (b && r == ANL_ECLOSED) { eof = 1; t_eof = i; }
        if (i == 2000) {                                    /* frames are in flight */
            t_close = i;
            if (by_receiver) { anl_stream_close(b); b = NULL; }
            else { anl_stream_close(a); a = NULL; }
        }
    }
    CHECK(got > 0, "frames delivered before the abort (%d of %d)", got, frames);
    CHECK(t_eof >= 0, "the %s learnt of the abort", by_receiver ? "sender" : "receiver");
    /* the CLOSE may be lost a few times (backoff x1.5 from RTO) */
    CHECK(t_eof >= 0 && t_eof - t_close < 5000, "abort seen %d ms after close", t_eof - t_close);
    if (a) anl_stream_close(a);
    if (b) anl_stream_close(b);
    for (i = 0; i < 20000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "both sides freed (%d ms)", i);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d of %d frames delivered, abort seen after %d ms%s\n", got, frames, t_eof - t_close, eof ? " (end of stream)" : "");
    net_stop(&n);
}

static void test_pacing(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[200000];
    int i;
    anl_stream_t *a, *b;
    printf("[pacing]\n");
    net_init(&n, &ca, &cb);
    ca.pace_rate = 2000000;          /* 2 MB/s: upper bound on the BBR rate */
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 300; i++) net_tick(&n);
    n.max_burst[0] = 0;
    fill_pattern(buf, 200000, 1);
    anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 200000, NULL);
    /* the warm-up sent no data: the frame starts BBR from STARTUP, 4~5 round
       trips from 16 segments up to 2 MB/s, then 100 ms at 2 MB/s */
    for (i = 0; i < 600; i++) net_tick(&n);
    /* 2 MB/s over a 5 ms window = 10 KB, plus bucket 4*mtu and one datagram of slack */
    CHECK(n.max_burst[0] <= 10000 + 4 * 1400 + 1400, "max 5ms burst %u bytes", n.max_burst[0]);
    CHECK(anl_stream_peeksize(b) == 200000, "frame arrived (%d)", anl_stream_peeksize(b));
    printf("  max 5 ms burst: %u bytes, frame arrived after <= 600 ms\n", n.max_burst[0]);
    net_stop(&n);
}

/* capture callback for the demux test */
static char g_cap[2048];
static int g_caplen;
static int cap_output(const char *buf, int len, anl_t *w, void *user)
{
    (void)w; (void)user;
    memcpy(g_cap, buf, (size_t)len);
    g_caplen = len;
    return 0;
}

static void test_demux(void)
{
    anl_keys keys; anl_config ca, cb; anl_t *a, *b;
    char plain[2048];
    uint32_t conv = 0;
    int r;
    printf("[demux: peek_conv + input_plain]\n");
    anl_config_default(&ca, ANL_ROLE_CLIENT);
    anl_config_default(&cb, ANL_ROLE_SERVER);
    memset(ca.psk, 7, 32); memset(cb.psk, 7, 32);
    a = anl_create(0xabcdef01, &ca, NULL);
    b = anl_create(0xabcdef01, &cb, NULL);
    anl_setoutput(a, cap_output);
    g_caplen = 0;
    anl_update(a, 10); anl_update(b, 10);
    anl_send(a, "hello", 5);                    /* default stream: flush_on_send */
    CHECK(g_caplen > 0, "A emitted a datagram");
    anl_keys_derive(&keys, cb.psk);
    r = anl_peek_conv(&keys, ANL_ROLE_SERVER, g_cap, g_caplen, &conv, plain);
    CHECK(r > 0 && conv == 0xabcdef01, "peek_conv r=%d conv=%08x", r, conv);
    r = anl_peek_conv(&keys, ANL_ROLE_CLIENT, g_cap, g_caplen, &conv, plain);
    CHECK(r == ANL_EAUTH, "peek with wrong role fails (%d)", r);
    r = anl_peek_conv(&keys, ANL_ROLE_SERVER, g_cap, g_caplen, &conv, plain);
    r = anl_input_plain(b, plain, r);
    CHECK(r == ANL_OK, "input_plain ok (%d)", r);
    r = anl_recv(b, plain, sizeof(plain));
    CHECK(r == 5 && memcmp(plain, "hello", 5) == 0, "B got the data via input_plain (%d)", r);
    anl_release(a); anl_release(b);
}

/*---------------------------------------------------------------------
 * 5. fuzz: mutate authenticated plaintext, feed through anl_input_plain
 *-------------------------------------------------------------------*/
static void test_fuzz(void)
{
    net n; anl_config ca, cb; anl_stream_opt o1, o2;
    char plain[2048], buf[3000];
    int i, iters = 20000;
    anl_stream_t *a1, *b1, *a2, *b2;
    printf("[fuzz %d mutated datagrams]\n", iters);
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o1, ANL_RELIABLE);
    anl_stream_opt_default(&o2, ANL_SEMI);
    o2.fec = 1; o2.fec_ratio = 50;               /* several parities per block: RS decode on fuzzed input */
    a1 = open_pair(&n, 0, &o1, NULL, &b1);
    a2 = open_pair(&n, 0, &o2, NULL, &b2);
    for (i = 0; i < 300; i++) {
        net_tick(&n);
        if (i % 3 == 0 && a1 && a2) {
            fill_pattern(buf, 3000, (uint32_t)i);
            anl_stream_send(a1, buf, 3000);
            anl_stream_send_frame(a2, 0, buf, 2500, NULL);
            anl_send(n.ep[0], buf, 700);
        }
    }
    for (i = 0; i < iters; i++) {
        int len, j;
        len = 9 + (int)(rnd() % 300);
        for (j = 0; j < len; j++) plain[j] = (char)(uint8_t)rnd();
        {
            char *p = plain;
            p = enc32(p, 0x11223344);
            p = enc8(p, (uint8_t)((rnd() % 4 == 0) ? (rnd() & 0xff) : 0));
            (void)enc32(p, n.now);
        }
        /* bias: sometimes start with a plausible segment header on a live sid */
        if (rnd() % 2) {
            static const int sids[4] = { 0, 1, 2, 4 };
            char *p = plain + 9;
            (void)enc_sid(p, (int)(rnd() % 4), sids[rnd() % 4]);
        }
        (void)anl_input_plain(n.ep[1], plain, len);
        if (i % 50 == 0) net_tick(&n);
    }
    (void)b1; (void)b2;
    CHECK(1, "no crash");
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 6. stream lifecycle: both sides open, accept callback, close, free
 *-------------------------------------------------------------------*/
#define LC_N 100

static void test_stream_lifecycle(int loss)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static anl_stream_t *mine[2][LC_N];
    static int got[2][LC_N], sids[2][LC_N];
    static char buf[4000];
    anl_stream_t *list[512];
    int side, i, k, r, iter, all;
    printf("[stream lifecycle: both sides open %d streams, loss=%d%%]\n", LC_N, loss);
    net_init(&n, &ca, &cb);
    n.loss_pct = loss;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    memset(got, 0, sizeof(got));

    /* client (side 0) gets even sids from 2, server (side 1) odd; tag = index */
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i++) {
            int sid;
            o.tag = side * 1000 + i;
            mine[side][i] = anl_stream_open(n.ep[side], &o, NULL);
            sid = sids[side][i] = anl_stream_id(mine[side][i]);
            CHECK(mine[side][i] && sid > 0 && sid % 2 == side, "auto sid %d on side %d", sid, side);
            fill_pattern(buf, 1000 + i, (uint32_t)(side * 1000 + i));
            CHECK(anl_stream_send(mine[side][i], buf, 1000 + i) == 0, "send on opened stream");
        }

    /* each side reads what the other side opened (identified by tag) and echoes it */
    for (iter = 0, all = 0; iter < 30000 && !all; iter++) {
        net_tick(&n);
        for (side = 0; side < 2; side++) {
            int cnt = anl_readable(n.ep[side], list, 512);
            for (k = 0; k < cnt && k < 512; k++) {
                anl_stream_t *s = list[k];
                int tag = anl_stream_tag(s), opener = tag / 1000, idx = tag % 1000;
                if (s == anl_default_stream(n.ep[side])) continue;
                r = anl_stream_recv(s, buf, sizeof(buf));
                if (r < 0) { CHECK(0, "readable stream sid %d r=%d", anl_stream_id(s), r); continue; }
                if (opener != side) {
                    CHECK(check_pattern(buf, r, (uint32_t)tag), "request content tag %d", tag);
                    CHECK(g_peer[side][anl_stream_id(s)] == s, "accept callback saw this handle");
                    anl_stream_send(s, buf, r);
                } else {
                    CHECK(s == mine[side][idx] && check_pattern(buf, r, (uint32_t)tag), "echo content tag %d", tag);
                    got[side][idx] = 1;
                }
            }
        }
        for (all = 1, side = 0; side < 2; side++) for (i = 0; i < LC_N; i++) all &= got[side][i];
    }
    CHECK(all, "every stream echoed its request");
    CHECK(g_acc[0] == LC_N && g_acc[1] == LC_N, "accept callbacks %d / %d", g_acc[0], g_acc[1]);

    /* every handle is closed by its owner; even i: opener first, odd i: acceptor first */
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i += 2) CHECK(anl_stream_close(mine[side][i]) == 0, "close opener");
    for (side = 0; side < 2; side++)
        for (i = 1; i < LC_N; i += 2) CHECK(anl_stream_close(g_peer[1 - side][sids[side][i]]) == 0, "close acceptor");
    for (iter = 0; iter < 300; iter++) net_tick(&n);
    for (side = 0; side < 2; side++)
        for (i = 0; i < LC_N; i++) {
            anl_stream_t *other = g_peer[1 - side][sids[side][i]];
            if (i % 2) CHECK(anl_stream_close(mine[side][i]) == 0, "close opener after the peer");
            else CHECK(anl_stream_close(other) == 0, "close acceptor after the peer");
        }
    for (iter = 0; iter < 20000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); iter++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "all streams freed (%d / %d)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));
    if (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)) { dump_streams("A", n.ep[0]); dump_streams("B", n.ep[1]); }
    CHECK(n.ep[0]->npeer_streams == 0 && n.ep[1]->npeer_streams == 0, "peer stream counters back to 0");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d ms, both sides empty after the close\n", (int)(n.now - 1000));
    net_stop(&n);
}

/* a sid is used once per connection: never handed out again after close; a
 * stale first datagram of a finished stream gets RST and creates nothing */
static void test_sid_once(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    char buf[2000], old[2048];
    int sid, i, r, oldlen;
    anl_stream_t *a, *b, *a2, *b2;
    printf("[sid used once: no reuse after close, stale first datagram gets RST]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    n.ep[0]->next_sid = 300;                        /* 2-byte sid encoding */
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    sid = anl_stream_id(a);
    CHECK(sid == 300, "sid 300 (%d)", sid);
    n.cap_len = 0;
    fill_pattern(buf, 1500, 11);
    anl_stream_send(a, buf, 1500);                  /* first data: carries the stream parameters */
    for (i = 0, r = -1; i < 500 && r < 0; i++) { net_tick(&n); r = anl_stream_recv(b, buf, sizeof(buf)); }
    CHECK(r == 1500 && check_pattern(buf, r, 11), "data (%d)", r);
    CHECK(n.cap_len > 0, "captured the first data datagram");
    memcpy(old, n.cap, (size_t)n.cap_len);
    oldlen = n.cap_len;

    anl_stream_close(a);
    anl_stream_close(b);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "both sides freed right after the close");
    a2 = anl_stream_open(n.ep[0], &o, NULL);
    CHECK(a2 && anl_stream_id(a2) == 302, "sid 300 is never reused (%d)", anl_stream_id(a2));
    anl_stream_close(a2);                           /* open + close, nothing sent: the peer still sees it */
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(g_peer[1][302] != NULL && anl_stream_peeksize(g_peer[1][302]) == ANL_ECLOSED, "peer got the empty stream, at end");
    if (g_peer[1][302]) anl_stream_close(g_peer[1][302]);
    for (i = 0; i < 1500; i++) net_tick(&n);

    /* the first datagram of the finished stream (parameters included) is
       replayed inside the ts window: RST, no new stream on either side */
    {
        int acc = g_acc[1];
        r = anl_input(n.ep[1], old, oldlen);
        CHECK(r == ANL_OK, "stale datagram inside the ts window is authenticated (%d)", r);
        CHECK(g_acc[1] == acc, "no stream created by the stale datagram (%d -> %d)", acc, g_acc[1]);
        for (i = 0; i < 300; i++) net_tick(&n);
        CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "still nothing on either side");
    }

    /* the next stream works normally */
    a2 = open_pair(&n, 0, &o, NULL, &b2);
    if (!b2) { net_stop(&n); return; }
    CHECK(anl_stream_id(a2) == 304 && anl_stream_id(b2) == 304, "next sid 304 (%d)", anl_stream_id(a2));
    fill_pattern(buf, 700, 22);
    anl_stream_send(a2, buf, 700);
    for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_stream_recv(b2, buf, sizeof(buf)); }
    CHECK(r == 700 && check_pattern(buf, r, 22), "data on the next stream (%d)", r);
    r = anl_input(n.ep[1], old, oldlen);
    CHECK(r == ANL_ESTALE, "old datagram now outside the ts window (%d)", r);

    /* sid wire format: type(2) | reserved(1) | sid(13); a set reserved bit drops the datagram */
    {
        char pl[32], *q = pl;
        q = enc32(q, 0x11223344);
        q = enc8(q, 0);
        q = enc32(q, n.now);
        q = enc8(q, (uint8_t)((SEG_FWD << 6) | SID_RSV | ((sid >> 8) & SID_HI_MASK)));
        q = enc8(q, (uint8_t)sid);
        q = enc16(q, 0);
        r = anl_input_plain(n.ep[1], pl, (long)(q - pl));
        CHECK(r == ANL_EFORMAT, "reserved sid bit rejected (%d)", r);
    }
    net_stop(&n);
}

/* socket-like lifetime: the peer resets a stream, the handle stays valid */
static void test_handle_lifetime(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *a, *b;
    char buf[64];
    int i;
    printf("[handle lifetime: peer closes, handle kept after the stream is gone, new stream meanwhile]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    anl_stream_set_user(anl_default_stream(n.ep[0]), &n);
    CHECK(anl_stream_get_user(anl_default_stream(n.ep[0])) == &n && anl_stream_conn(anl_default_stream(n.ep[0])) == n.ep[0], "user / conn");
    n.ep[1]->next_sid = 41;                         /* server opens sid 41 */
    b = open_pair(&n, 1, &o, NULL, &a);
    if (!a) { net_stop(&n); return; }
    anl_stream_send(b, "last words", 10);
    anl_stream_close(b);
    for (i = 0; i < 4000; i++) net_tick(&n);
    CHECK(anl_stream_recv(a, buf, sizeof(buf)) == 10 && memcmp(buf, "last words", 10) == 0, "data before the close is readable");
    CHECK(anl_stream_recv(a, buf, sizeof(buf)) == ANL_ECLOSED, "then end of stream");
    for (i = 0; i < 100; i++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 1 && a->detached, "handle held, sid released");
    CHECK(stream_state(a) == ANL_STREAM_CLOSED && anl_stream_recv(a, buf, sizeof(buf)) == ANL_ECLOSED, "handle still answers");
    /* the server opens the next stream while the client still holds the old handle */
    {
        anl_stream_t *a2 = NULL;
        b = open_pair(&n, 1, &o, NULL, &a2);
        CHECK(a2 != NULL && a2 != a && anl_stream_id(a2) == 43 && anl_stream_id(b) == 43, "new stream on sid 43");
    }
    CHECK(stream_count(n.ep[0], NULL) == 2, "new stream next to the old handle (%d)", stream_count(n.ep[0], NULL));
    CHECK(anl_stream_close(g_peer[0][43]) == 0 && anl_stream_close(a) == 0 && stream_count(n.ep[0], NULL) <= 1, "close both");
    net_stop(&n);
}

static void test_accept_limits(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    anl_stream_t *s[8];
    int i, r, open_ok = 0, refused = 0, err;
    char buf[100];
    printf("[accept: callback reject / options, max_peer_streams]\n");
    net_init(&n, &ca, &cb);
    cb.max_peer_streams = 5;
    net_start(&n, &ca, &cb);
    g_acc_reject_mod = 8; g_acc_rcv_wnd = 99;       /* the callback cannot change rcv_wnd */
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.rcv_wnd = 77;
    for (i = 0; i < 8; i++) {
        s[i] = anl_stream_open(n.ep[0], &o, &err);
        CHECK(s[i] && err == 0, "open %d (%d)", i, err);
        anl_stream_send(s[i], "hello", 5);
    }
    for (i = 0; i < 1000; i++) net_tick(&n);
    for (i = 0; i < 8; i++) {
        anl_stream_stats ss;
        anl_stream_get_stats(s[i], &ss);
        if (ss.state == ANL_STREAM_OPEN) {
            anl_stream_t *peer = g_peer[1][anl_stream_id(s[i])];
            open_ok++;
            CHECK(peer && peer->rcv_wnd == 77 && s[i]->rcv_wnd == 77, "rcv_wnd is the opener's on both ends (%u)", peer ? peer->rcv_wnd : 0);
            r = peer ? anl_stream_recv(peer, buf, sizeof(buf)) : -1;
            CHECK(r == 5, "accepted stream delivered (%d)", r);
        } else {
            refused++;
            CHECK(ss.state == ANL_STREAM_CLOSED, "refused stream closed by RST (%d)", ss.state);
            CHECK(anl_stream_send(s[i], "x", 1) == ANL_ECLOSED, "send on refused stream");
        }
    }
    CHECK(open_ok == 5 && refused == 3 && g_acc[1] == 5, "5 accepted, 3 refused (%d / %d / cb %d)", open_ok, refused, g_acc[1]);
    CHECK(n.ep[1]->npeer_streams == 5, "server holds 5 peer streams (%u)", n.ep[1]->npeer_streams);
    o.tag = 70000;
    CHECK(anl_stream_open(n.ep[0], &o, &err) == NULL && err == ANL_EINVAL, "tag out of range");
    net_stop(&n);
}

static void test_max_streams(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static anl_stream_t *list[ANL_MAX_STREAMS];
    static anl_stream_t *mine[2][ANL_MAX_STREAMS / 2];
    static unsigned char seen[ANL_MAX_STREAMS];
    char buf[64];
    int side, i, r, k, nread = 0, iter, err, nopen[2] = { 0, 0 };
    printf("[max streams: %d incl. the default stream, both sides open]\n", ANL_MAX_STREAMS);
    net_init(&n, &ca, &cb);
    ca.max_peer_streams = cb.max_peer_streams = ANL_MAX_STREAMS;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_RELIABLE);
    o.snd_wnd = 4; o.rcv_wnd = 4;
    for (side = 0; side < 2; side++) {
        for (;;) {
            anl_stream_t *s = anl_stream_open(n.ep[side], &o, &err);
            if (s == NULL) { CHECK(err == ANL_EBUSY, "no free sid left on side %d (%d)", side, err); break; }
            mine[side][nopen[side]++] = s;
            snprintf(buf, sizeof(buf), "s%d", anl_stream_id(s));
            anl_stream_send(s, buf, (int)strlen(buf) + 1);
        }
    }
    CHECK(nopen[0] + nopen[1] + 1 == ANL_MAX_STREAMS, "client %d + server %d + default = %d", nopen[0], nopen[1], ANL_MAX_STREAMS);
    memset(seen, 0, sizeof(seen));
    for (iter = 0; iter < 60000 && nread < ANL_MAX_STREAMS - 1; iter++) {
        net_tick(&n);
        for (side = 0; side < 2; side++) {
            int cnt = anl_readable(n.ep[side], list, ANL_MAX_STREAMS);
            for (k = 0; k < cnt; k++) {
                int sid = anl_stream_id(list[k]);
                r = anl_stream_recv(list[k], buf, sizeof(buf));
                snprintf(buf + 32, 32, "s%d", sid);
                CHECK(r > 0 && strcmp(buf, buf + 32) == 0 && sid % 2 != side && !seen[sid], "message on sid %d", sid);
                seen[sid] = 1;
                nread++;
            }
        }
    }
    CHECK(nread == ANL_MAX_STREAMS - 1, "one message on each stream (%d)", nread);
    printf("  all %d streams carried data after %d ms\n", nread, iter);
    for (side = 0; side < 2; side++)
        for (i = 0; i < nopen[side]; i++) {
            anl_stream_close(g_peer[1 - side][anl_stream_id(mine[side][i])]);
            anl_stream_close(mine[side][i]);
        }
    for (iter = 0; iter < 20000 && (stream_count(n.ep[0], NULL) || stream_count(n.ep[1], NULL)); iter++) net_tick(&n);
    CHECK(stream_count(n.ep[0], NULL) == 0 && stream_count(n.ep[1], NULL) == 0, "all freed (%d / %d)",
          stream_count(n.ep[0], NULL), stream_count(n.ep[1], NULL));
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  closed and freed after %d more ms\n", iter);
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 7. priority: a video stream must not block a control stream
 *-------------------------------------------------------------------*/
static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

typedef struct prio_result { double p50, p99, max; uint32_t sent, got, vframes, vgot; int max_wait; } prio_result;

/* control: reliable 200 B every 50 ms, on the default stream (ctrl_prio < 0)
 * or on its own stream; video: semi 30 fps, I 40 KB / P 15 KB (~3.6 Mbps)
 * over a 3 Mbps bottleneck; video = 0 runs the control stream alone.
 * capped: BBR with cfg.pace_rate = 2.8 Mbps, below the link (a known uplink
 * quota): no queue builds at the bottleneck - the latency floor for control. */
static void run_priority(int ctrl_prio, int video_prio, int video, int nc, prio_result *res)   /* nc: rate capped */
{
    net n; anl_config ca, cb; anl_stream_opt oc, ov;
    static char buf[70000];
    static uint32_t lat[2000];
    static char rec[8192];
    uint32_t nlat = 0, ctrl_seq = 0, vseq = 0, vgot = 0;
    int i, r, nrec = 0;
    const int T = 20000;
    anl_stream_t *cs, *cr, *vs = NULL, *vr = NULL;

    res->max_wait = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    n.loss_pct = 1;
    n.bandwidth_bps = 3000000; n.queue_limit = 40;
    if (nc) ca.pace_rate = 350000;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&oc, ANL_RELIABLE);
    oc.prio = ctrl_prio < 0 ? 0 : ctrl_prio; oc.flush_on_send = 1;
    anl_stream_opt_default(&ov, ANL_SEMI);
    ov.prio = video_prio; ov.max_age_ms = 500; ov.drop_until_key = 1;
    if (ctrl_prio < 0) { cs = anl_default_stream(n.ep[0]); cr = anl_default_stream(n.ep[1]); }
    else cs = open_pair(&n, 0, &oc, NULL, &cr);
    if (video) vs = open_pair(&n, 0, &ov, NULL, &vr);
    if (!cr || (video && !vr)) { net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);

    for (i = 0; i < T; i++) {
        uint32_t now = n.now;
        net_tick(&n);
        if (i % 50 == 0 && i < T - 1500) {           /* last 1.5 s: drain what is in flight */
            memset(buf, 0, 200);
            memcpy(buf, &ctrl_seq, 4); memcpy(buf + 4, &now, 4);
            /* message framing on the (byte stream) default stream: fixed 200 B records */
            CHECK(anl_stream_send(cs, buf, 200) == 0, "control send");
            ctrl_seq++;
        }
        if (video && i % 33 == 0 && i < T - 1500) {
            int key = vseq % 30 == 0, len = key ? 40000 : 15000;
            fill_pattern(buf, len, vseq);
            r = anl_stream_send_frame(vs, key ? ANL_FRAME_KEY : 0, buf, len, NULL);
            CHECK(r == 0 || r == ANL_EDROPPED, "video send %d", r);
            vseq++;
        }
        if ((int)cs->nsnd_que > res->max_wait) res->max_wait = (int)cs->nsnd_que;
        /* a byte stream may return several records at once: reassemble 200 B records */
        while ((r = anl_stream_recv(cr, rec + nrec, (int)sizeof(rec) - nrec)) > 0) {
            int off = 0;
            nrec += r;
            for (; nrec - off >= 200; off += 200) {
                uint32_t t0;
                memcpy(&t0, rec + off + 4, 4);
                if (nlat < 2000) lat[nlat++] = n.now - t0;
            }
            memmove(rec, rec + off, (size_t)(nrec - off));
            nrec -= off;
        }
        CHECK(r == ANL_EAGAIN, "control recv %d", r);
        if (video) {
            anl_frame_info fi;
            while ((r = anl_stream_recv_frame(vr, buf, sizeof(buf), &fi)) > 0) vgot++;
        }
    }
    qsort(lat, nlat, sizeof(uint32_t), cmp_u32);
    res->p50 = nlat ? lat[nlat / 2] : 0;
    res->p99 = nlat ? lat[(nlat - 1) * 99 / 100] : 0;
    res->max = nlat ? lat[nlat - 1] : 0;
    res->sent = ctrl_seq; res->got = nlat; res->vframes = vseq; res->vgot = vgot;
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

static void test_priority(void)
{
    static const char *cc[2] = { "BBR (default)", "BBR capped at 2.8 Mbps (cfg.pace_rate)" };
    int nc;
    printf("[priority: control (reliable 200 B / 50 ms) vs video (~3.6 Mbps) on a 3 Mbps link, rtt 40 ms, 1%% loss]\n");
    printf("  default stream: strict priority; other streams: %d levels, weighted round robin %u:%u:%u:%u\n", ANL_MAX_PRIO,
           prio_weight[0], prio_weight[1], prio_weight[2], prio_weight[3]);
    for (nc = 0; nc < 2; nc++) {
        prio_result r[5];
        static const char *name[5] = { "control alone", "ctrl on default stream", "ctrl prio 0, video prio 2",
                                       "both prio 2", "ctrl prio 3, video prio 0" };
        int k;
        run_priority(-1, 2, 0, nc, &r[0]);
        run_priority(-1, 2, 1, nc, &r[1]);
        run_priority(0, 2, 1, nc, &r[2]);
        run_priority(2, 2, 1, nc, &r[3]);
        run_priority(3, 0, 1, nc, &r[4]);
        printf("  %s\n", cc[nc]);
        for (k = 0; k < 5; k++)
            printf("    %-26s ctrl p50 %4.0f p99 %4.0f max %4.0f ms (%u/%u)  max ctrl unsent %d seg  video %u/%u\n",
                   name[k], r[k].p50, r[k].p99, r[k].max, r[k].got, r[k].sent, r[k].max_wait, r[k].vgot, r[k].vframes);
        /* inside AnLiu the control stream is never queued behind video
           (BBR: at most until video frees the shared cwnd) */
        for (k = 1; k <= 2; k++) {
            CHECK(r[k].max_wait <= (nc ? 2 : 4), "%s: at most %d unsent control segments (%d)", name[k], nc ? 2 : 4, r[k].max_wait);
            CHECK(r[k].got == r[k].sent, "%s: control delivered with video running (%u/%u)", name[k], r[k].got, r[k].sent);
            /* paced below the link: one retransmission (RTO ~100 ms) plus queueing at most */
            if (nc) CHECK(r[k].p99 <= 250, "%s paced below the link: ctrl p99 %.0f ms", name[k], r[k].p99);
        }
    }
}

/*---------------------------------------------------------------------
 * 8. key frames: undecodable P frames are dropped (DESIGN 7.6)
 *-------------------------------------------------------------------*/
static void test_key_sender_purge(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss; anl_frame_info fi;
    char buf[8000];
    uint32_t fno;
    int i, r;
    anl_stream_t *a, *b;
    printf("[key frames A: sender drops in-flight P frames of an abandoned key frame]\n");
    net_init(&n, &ca, &cb);
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 200; o.drop_until_key = 1;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);

    n.loss_pct = 100;                           /* K0 P1 P2 are sent but never arrive */
    for (i = 0; i < 3; i++) {
        fill_pattern(buf, i ? 1000 : 4000, (uint32_t)i);
        CHECK(anl_stream_send_frame(a, i ? 0 : ANL_FRAME_KEY, buf, i ? 1000 : 4000, &fno) == 0 && fno == (uint32_t)i, "send frame %d", i);
        net_tick(&n);
    }
    CHECK(a->nsnd_buf >= 3 && a->nsnd_que == 0, "all three frames in flight (%u / %u)", a->nsnd_buf, a->nsnd_que);
    for (i = 0; i < 1000 && a->nsnd_buf > 0; i++) net_tick(&n);
    anl_stream_get_stats(a, &ss);
    CHECK(a->nsnd_buf == 0, "K0 abandoned on retransmission, P1 P2 dropped with it (%u left)", a->nsnd_buf);
    CHECK(ss.frames_dropped == 3, "three frames dropped (%u)", ss.frames_dropped);
    CHECK(a->fwd_pending && a->fwd_una == a->snd_nxt, "one FWD to snd_nxt");
    CHECK(anl_stream_send_frame(a, 0, buf, 500, &fno) == ANL_EDROPPED && fno == 3, "P3 refused until a key frame");

    n.loss_pct = 0;
    fill_pattern(buf, 3000, 4);
    CHECK(anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 3000, &fno) == 0 && fno == 4, "K4 accepted");
    for (i = 0, r = -1; i < 1000 && r < 0; i++) { net_tick(&n); r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi); }
    CHECK(r == 3000 && fi.frame_no == 4 && fi.flags == ANL_FRAME_KEY && fi.lost_before == 4 && check_pattern(buf, r, 4),
          "receiver gets K4 first, lost_before 4 (r=%d fno=%u lost=%u)", r, fi.frame_no, fi.lost_before);
    for (i = 0; i < 300; i++) net_tick(&n);
    CHECK(anl_stream_recv_frame(b, buf, sizeof(buf), &fi) == ANL_EAGAIN, "no stale P frame afterwards");
    CHECK(!a->fwd_pending, "FWD acknowledged");
    net_stop(&n);
}

/* A full receiver drains, but its window-opening ACK is lost. With no data
   in flight there is no retransmission to rescue the sender: WASK must do it. */
static void test_window_reopen_loss(void)
{
    int lose_probe;
    printf("[window: lost reopen ACK recovers on the measured RTO]\n");
    for (lose_probe = 0; lose_probe <= 1; lose_probe++) {
        net n; anl_config ca, cb; anl_stream_opt opt; anl_stream_t *a, *b;
        char data[16000]; int i, size, got = ANL_EAGAIN; uint32_t start, rto;
        net_init(&n, &ca, &cb);
        n.min_delay = n.max_delay = 10;
        ca.interval = cb.interval = 10;
        ca.pad_max = cb.pad_max = 0;
        ca.keepalive_ms = cb.keepalive_ms = 0;
        net_start(&n, &ca, &cb);
        anl_stream_opt_default(&opt, ANL_RELIABLE);
        opt.snd_wnd = opt.rcv_wnd = 8;
        a = open_pair(&n, 0, &opt, &opt, &b);
        if (!b) { net_stop(&n); continue; }
        for (i = 0; i < 200; i++) net_tick(&n);
        size = (int)a->mss * 8;
        CHECK(size <= (int)sizeof(data), "test message fits");
        fill_pattern(data, size, 7);
        CHECK(anl_stream_send(a, data, size) == 0, "fill peer window");
        for (i = 0; i < 2000 && (a->rmt_wnd != 0 || a->nsnd_buf != 0); i++) net_tick(&n);
        CHECK(a->rmt_wnd == 0 && a->nsnd_buf == 0 && b->nrcv_que == 8,
              "peer full, every sent fragment acknowledged");
        CHECK(anl_stream_recv(b, data, sizeof(data)) == size && check_pattern(data, size, 7),
              "application drains receiver");
        n.loss_pct = 100;
        for (i = 0; i < 100 && b->probe_tell; i++) net_tick(&n);
        n.loss_pct = 0;
        CHECK(!b->probe_tell && a->rmt_wnd == 0 && wnd_unused(n.ep[1], b) == 8,
              "opening ACK was sent and lost, sender retains stale zero window");
        rto = (uint32_t)n.ep[0]->rx_rto; start = n.now;
        CHECK(anl_stream_send(a, "resume", 7) == 0, "queue data behind stale window");
        for (i = 0; i <= ca.interval && a->probe_wait == 0; i++) net_tick(&n);
        CHECK(a->probe_wait == rto, "first probe follows the measured RTO (%u vs %u)", a->probe_wait, rto);
        if (lose_probe) n.drop_at[0] = (uint32_t)n.sent + 1;
        for (i = 0; i < (int)(4 * rto + 8 * ca.interval); i++) {
            net_tick(&n);
            got = anl_stream_recv(b, data, sizeof(data));
            if (got >= 0) break;
        }
        CHECK(got == 7 && memcmp(data, "resume", 7) == 0,
              "resume after lost opening ACK%s within RTT-aware bound (elapsed=%u rto=%u)",
              lose_probe ? " and first probe" : "", n.now - start, rto);
        CHECK(a->rmt_wnd > 0 && a->probe_wait == 0, "positive window cancels persistence backoff");
        if (!lose_probe) {
            uint32_t next; long sent0;
            for (i = 0; i < 100; i++) net_tick(&n);
            fill_pattern(data, size, 9);
            CHECK(anl_stream_send(a, data, size) == 0, "fill window a second time");
            for (i = 0; i < 2000 && (a->rmt_wnd != 0 || a->nsnd_buf != 0); i++) net_tick(&n);
            CHECK(a->rmt_wnd == 0 && b->nrcv_que == 8, "application keeps the peer window full");
            next = a->snd_nxt; sent0 = n.sent; rto = (uint32_t)n.ep[0]->rx_rto;
            CHECK(anl_stream_send(a, "waiting", 8) == 0, "queue while receiver deliberately holds data");
            for (i = 0; i < (int)(20 * rto); i++) net_tick(&n);
            CHECK(a->snd_nxt == next && a->nsnd_que == 1, "probes never override a genuinely closed window");
            CHECK(a->probe_wait > rto && a->probe_wait <= PROBE_LIMIT && n.sent - sent0 <= 20,
                  "persistent zero window still backs off, without busy probing (%ld packets)", n.sent - sent0);
        }
        net_stop(&n);
    }
}

static void test_receiver_deadline_default(void)
{
    int policy;
    printf("[semi: receiver default deadline advances without sender FWD]\n");
    for (policy = -1; policy <= 3; policy++) {
        net n; anl_config ca, cb; anl_stream_opt o, op; anl_frame_info fi;
        anl_stream_t *a, *b;
        char buf[100];
        int i, r = ANL_EAGAIN, dropped_ack = 0;
        uint32_t start, received_at = 0;
        net_init(&n, &ca, &cb);
        n.min_delay = n.max_delay = 10;
        ca.pad_max = cb.pad_max = 0;
        net_start(&n, &ca, &cb);
        anl_stream_opt_default(&o, ANL_SEMI);
        CHECK(o.rcv_deadline_ms == -1, "semi defaults to the local frame lifetime");
        o.fec = 0; o.max_age_ms = 10000;
        op = o; op.max_age_ms = 40;
        if (policy >= 0) op.rcv_deadline_ms = policy ? 20 : 0;
        a = open_pair(&n, 0, &o, &op, &b);
        if (!b) { net_stop(&n); continue; }
        for (i = 0; i < 200; i++) net_tick(&n);
        n.loss_pct = 100;
        fill_pattern(buf, sizeof(buf), 0);
        CHECK(anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) == 0, "send missing frame");
        n.loss_pct = 0;
        fill_pattern(buf, sizeof(buf), 1);
        CHECK(anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) == 0, "send subsequent frame");
        CHECK(a->snd_nxt == 2, "both frames left the sender before it stopped");
        start = n.now;
        /* Keep delivering ACKs, but stop the sender timer: the receiver must
           advance without retransmission/FWD and report skips as retirement. */
        for (i = 0; i < 150; i++) {
            pkt **pp = &n.queue;
            n.now++;
            n.ep[0]->current = n.now; /* timestamp only: no sender retransmission timer */
            while (*pp) {
                pkt *p = *pp;
                if (tdiff(n.now, p->deliver_at) < 0) { pp = &p->next; continue; }
                *pp = p->next;
                if (p->to == 0 && ((policy == 2 && b->frames_skipped && !dropped_ack) ||
                                  (policy == 3 && !b->frames_skipped))) dropped_ack++;
                else anl_input(n.ep[p->to], p->data, p->len);
                free(p);
            }
            if (i == 100) { b->probe_tell = 1; ctl_mark(b); } /* repeat a lost window ACK */
            anl_update(n.ep[1], n.now);
            if (r < 0) {
                r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi);
                if (r >= 0) received_at = n.now;
            }
        }
        if (policy == 0) CHECK(r == ANL_EAGAIN, "explicit zero keeps waiting");
        else {
            int deadline = policy == -1 ? 40 : 20;
            CHECK(r == (int)sizeof(buf) && fi.frame_no == 1 && fi.lost_before == 1 &&
                  check_pattern(buf, sizeof(buf), 1), "skip missing frame, preserve next frame and loss count");
            CHECK(received_at - start >= (uint32_t)(10 + deadline) &&
                  received_at - start <= (uint32_t)(10 + deadline + 2 * cb.interval),
                  "local timer bounds gap wait (elapsed=%u)", received_at - start);
            handle_fwd(n.ep[1], b, 1);
            CHECK(anl_stream_recv_frame(b, buf, sizeof(buf), &fi) == ANL_EAGAIN,
                  "late FWD cannot redeliver or rewind");
        }
        CHECK(n.ep[0]->delivered == sizeof(buf) + SEG_WIRE_OVH,
              "only the actually received frame gets congestion-control credit (%llu)",
              (unsigned long long)n.ep[0]->delivered);
        if (policy >= 2) CHECK(dropped_ack > 0, "exercise loss of a skip ACK or its earlier SACK");
        if (policy != 0) CHECK(a->nsnd_buf == 0, "skipped prefix retires even after ACK loss");
        CHECK(!a->fwd_pending && a->frames_dropped == 0, "sender did not abandon the frame");
        net_stop(&n);
    }
}

static int g_skip_packets, g_skip_acks, g_skip_want;
static uint32_t g_skip_watermark;

static int skip_ack_output(const char *wire, int len, anl_t *w, void *user)
{
    uint8_t plain[2048];
    const char *p, *end;
    int size = siv_open(&w->keys, w->role, (const uint8_t *)wire, (size_t)len, plain);
    int marker = 0;
    (void)user;
    CHECK(len <= (int)w->mtu && size >= ANL_HDR_SIZE, "valid bounded ACK datagram");
    if (size < ANL_HDR_SIZE) return 0;
    p = (const char *)plain + ANL_HDR_SIZE; end = (const char *)plain + size;
    g_skip_packets++;
    while (p < end) {
        int type = dec8(&p) >> 6;
        (void)dec8(&p);
        if (type == SEG_CTRL) {
            uint8_t sub = dec8(&p); uint32_t n = 0;
            CHECK(dec_varint(&p, end, &n) == 0 && n == 4 && sub == CTRL_RCV_SKIP,
                  "only the retirement marker precedes these ACKs");
            if (end - p < 4) break;
            CHECK(dec32(&p) == g_skip_watermark, "full 32-bit skip watermark survives wrap");
            marker = 1;
        } else if (type == SEG_ACK) {
            uint32_t n = 0, i, v;
            CHECK(marker == g_skip_want, "each split ACK shares a datagram with its retirement marker");
            if (end - p < 9) break;
            p += 9;
            CHECK(dec_varint(&p, end, &n) == 0, "SACK count");
            for (i = 0; i < 2 * n; i++) CHECK(dec_varint(&p, end, &v) == 0, "SACK range");
            g_skip_acks++;
        } else { CHECK(0, "unexpected segment type in ACK test"); break; }
    }
    return 0;
}

static void test_receiver_skip_ack_fragments(void)
{
    anl_config cfg; anl_stream_opt opt; anl_t *w; anl_stream *st; int i;
    printf("[semi: atomic skip marker with split SACKs and sequence wrap]\n");
    anl_config_default(&cfg, ANL_ROLE_CLIENT);
    cfg.mtu = 128; cfg.pad_max = 0; cfg.rng = det_rng;
    w = anl_create(7, &cfg, NULL);
    CHECK(w != NULL, "create small-MTU connection");
    if (!w) return;
    anl_update(w, 1000);
    anl_stream_opt_default(&opt, ANL_SEMI); opt.fec = 0;
    st = stream_create(w, 2, &opt);
    CHECK(st != NULL, "create receiver stream");
    if (!st) { anl_release(w); return; }
    st->peer_opened = 1; st->rcv_nxt = 100;
    st->rcv_skip_valid = 1; st->rcv_skip_una = 50;
    for (i = 0; i < 200; i++) {
        anl_seg *s = seg_new(0);
        CHECK(s != NULL, "allocate received segment");
        if (!s) break;
        s->sn = 101u + (uint32_t)i * 2;
        qadd_tail(&s->node, &st->rcv_buf); st->nrcv_buf++;
    }
    g_skip_packets = g_skip_acks = 0; g_skip_want = 1; g_skip_watermark = 50;
    anl_setoutput(w, skip_ack_output);
    write_ack_segs(w, st); dg_seal(w);
    CHECK(g_skip_acks > 1 && g_skip_packets > 1, "small MTU forced several ACK datagrams");
    free_rcv_list(w, &st->rcv_buf, &st->nrcv_buf);
    g_skip_watermark = st->rcv_skip_una = 0xfffffff0u;
    st->rcv_nxt = st->rcv_skip_una + ANL_MAX_WND - 1;
    write_ack_segs(w, st); dg_seal(w);
    CHECK(st->rcv_skip_valid, "still repeat the marker before the sending window has passed it");
    g_skip_want = 0; st->rcv_nxt++;
    write_ack_segs(w, st); dg_seal(w);
    CHECK(!st->rcv_skip_valid, "stop the marker once the bounded sending window proves retirement");
    anl_release(w);
}

/* one frame (#10) is lost; the receiver skips it by rcv_deadline */
static void run_key_receiver(int rcv_drop, uint32_t *delivered, uint32_t *discarded, int *bad)
{
    net n; anl_config ca, cb; anl_stream_opt o, op; anl_stream_stats ss; anl_frame_info fi;
    char buf[4000];
    uint32_t sent = 0, last = 0, lost_sum = 0;
    int i, r, have = 0, chain = 0;
    anl_stream_t *a, *b;
    *delivered = 0; *discarded = 0; *bad = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 20;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.max_age_ms = 50;                          /* frame 10 stays lost: abandoned rather than retransmitted (RACK) */
    op = o;                                     /* receiver-side options live on the accepting side */
    op.rcv_deadline_ms = 30;
    op.rcv_drop_until_key = rcv_drop;
    a = open_pair(&n, 0, &o, &op, &b);
    if (!b) { *bad = 1; net_stop(&n); return; }
    for (i = 0; i < 200; i++) net_tick(&n);
    for (i = 0; i < 2500; i++) {
        net_tick(&n);
        if (i % 33 == 0 && sent < 60) {
            int key = sent % 30 == 0;
            fill_pattern(buf, 1000, sent);
            if (sent == 10) n.loss_pct = 100;         /* frame 10 (one datagram) is lost */
            anl_stream_send_frame(a, key ? ANL_FRAME_KEY : 0, buf, 1000, NULL);
            n.loss_pct = 0;
            sent++;
        }
        while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            if (!check_pattern(buf, r, fi.frame_no)) (*bad)++;
            if (have && fi.frame_no != last + 1 + fi.lost_before) (*bad)++;
            /* decoder model: a P frame needs an unbroken chain from its key frame */
            if (fi.flags & ANL_FRAME_KEY) chain = 1;
            else if (fi.lost_before) chain = 0;
            if (!chain && rcv_drop) (*bad)++;                  /* undecodable frame delivered */
            lost_sum += fi.lost_before;
            last = fi.frame_no; have = 1;
            (*delivered)++;
        }
    }
    anl_stream_get_stats(b, &ss);
    *discarded = ss.frames_discarded;
    if (*delivered + lost_sum != last + 1) (*bad)++;
    net_stop(&n);
}

static void test_key_receiver_discard(void)
{
    uint32_t d0, x0, d1, x1;
    int b0, b1;
    printf("[key frames B: receiver discards undecodable P frames (rcv_drop_until_key)]\n");
    run_key_receiver(0, &d0, &x0, &b0);
    run_key_receiver(1, &d1, &x1, &b1);
    printf("  off: delivered %u, discarded %u    on: delivered %u, discarded %u (frames 11..29 are undecodable)\n", d0, x0, d1, x1);
    CHECK(b0 == 0 && b1 == 0, "content / accounting / decodability (%d, %d)", b0, b1);
    CHECK(d0 == 59 && x0 == 0, "off: every frame but #10 delivered (%u, %u)", d0, x0);
    CHECK(d1 == 40 && x1 == 19, "on: frames 11..29 discarded, 0..9 and 30..59 delivered (%u, %u)", d1, x1);
}

static void test_fec_rtt_default(void)
{
    int mode, delay;
    printf("[semi: default FEC protects deadlines shorter than RTT]\n");
    for (mode = 0; mode < 2; mode++) for (delay = 30; delay <= 140; delay += 110) {
        net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss;
        anl_stream_t *a, *b;
        anl_frame_info fi;
        char buf[100];
        int i, r, received = 0;
        net_init(&n, &ca, &cb);
        n.min_delay = n.max_delay = delay;
        ca.pad_max = cb.pad_max = 0;
        net_start(&n, &ca, &cb);
        anl_stream_opt_default(&o, ANL_SEMI);
        CHECK(o.fec == ANL_FEC_RTT_AUTO, "semi default is conditional adaptive FEC");
        o.max_age_ms = 200;
        if (!mode) o.fec = 0;
        a = open_pair(&n, 0, &o, &o, &b);
        if (!b) { net_stop(&n); continue; }
        CHECK(anl_send(n.ep[0], "rtt", 3) == 0, "prime the shared connection RTT with reliable data");
        for (i = 0; i < 1000; i++) net_tick(&n);
        anl_stream_get_stats(a, &ss);
        CHECK((ss.fec_ratio != 0) == (mode && delay == 140), "parity follows measured RTT");
        if (mode) {
            int32_t saved = n.ep[0]->rx_srtt;
            n.ep[0]->rx_srtt = 0;
            CHECK(!fec_active(n.ep[0], a), "unknown RTT waits for a sample");
            n.ep[0]->rx_srtt = 200;
            CHECK(!fec_active(n.ep[0], a), "equal lifetime and RTT does not enable parity");
            n.ep[0]->rx_srtt = 201;
            CHECK(fec_active(n.ep[0], a), "crossing the lifetime enables parity without changing MSS");
            n.ep[0]->rx_srtt = saved;
        }
        n.drop_at[0] = (uint32_t)n.sent + 1;
        for (i = 0; i < 8; i++) {
            fill_pattern(buf, sizeof(buf), (uint32_t)i);
            CHECK(anl_stream_send_frame(a, 0, buf, sizeof(buf), NULL) == 0, "queue protected data");
        }
        for (i = 0; i < 1500; i++) {
            net_tick(&n);
            while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) >= 0) {
                CHECK(r == (int)sizeof(buf) && check_pattern(buf, r, fi.frame_no), "repaired frame content");
                received++;
            }
        }
        anl_stream_get_stats(b, &ss);
        if (mode && delay == 140) {
            CHECK(ss.fec_recovered > 0 && received == 8,
                  "default long-RTT parity repairs the missing frame (%u repairs, %d frames)", ss.fec_recovered, received);
        } else CHECK(ss.fec_recovered == 0, "short RTT or explicit off does not repair with parity");
        CHECK(anl_state(n.ep[0]) >= 0 && anl_state(n.ep[1]) >= 0, "connection stays alive");
        net_stop(&n);
    }
}

/* FEC (DESIGN 8): Reed-Solomon over blocks of up to 100 ms. With rtt 400 ms a
   retransmission takes at least 600 ms; the parities arrive about 300 ms after
   the data - so a frame complete within 400 ms was rebuilt by FEC. m parities
   repair any m lost packets of a block, not only one per group as with XOR. */
static void run_fec_repair(int frags, int ratio, const int *drop, int ndrop, uint32_t *recovered, int *ms)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss; anl_frame_info fi;
    static char buf[20000];
    anl_stream_t *a, *b;
    uint32_t base, t0;
    int i, r, len = frags * 1300;
    *ms = -1;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 200;
    ca.pad_max = cb.pad_max = 0;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = ratio;
    o.max_age_ms = 2000;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 1500; i++) net_tick(&n);        /* srtt settles */
    base = (uint32_t)n.sent;
    t0 = n.now;
    for (i = 0; i < ndrop; i++) n.drop_at[i] = base + (uint32_t)drop[i];
    fill_pattern(buf, len, 7);
    CHECK(anl_stream_send_frame(a, ANL_FRAME_KEY, buf, len, NULL) == 0, "send frame");
    for (i = 0; i < 1000 && *ms < 0; i++) {
        net_tick(&n);
        if ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            CHECK(r == len && check_pattern(buf, r, 7), "frame content");
            *ms = (int)(n.now - t0);
        }
    }
    anl_stream_get_stats(b, &ss);
    *recovered = ss.fec_recovered;
    net_stop(&n);
}

static void test_fec_repair(void)
{
    static const int last[1] = { 3 }, three[3] = { 1, 4, 8 }, burst[4] = { 3, 4, 5, 6 };
    uint32_t rec;
    int ms;
    printf("[fec: Reed-Solomon repair, rtt 400 ms (a retransmission takes >= 600 ms)]\n");
    run_fec_repair(3, 20, last, 1, &rec, &ms);
    printf("  3 fragments, 1 parity, the last fragment lost:       complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 1 && ms >= 0 && ms < 400, "last fragment rebuilt by FEC (%u, %d ms)", rec, ms);
    run_fec_repair(8, 50, three, 3, &rec, &ms);
    printf("  8 fragments, 4 parities, 3 scattered fragments lost: complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 3 && ms >= 0 && ms < 400, "three lost fragments of one block rebuilt (%u, %d ms)", rec, ms);
    run_fec_repair(8, 50, burst, 4, &rec, &ms);
    printf("  8 fragments, 4 parities, a burst of 4 lost:          complete after %d ms, rebuilt %u\n", ms, rec);
    CHECK(rec == 4 && ms >= 0 && ms < 400, "a burst of four rebuilt (%u, %d ms)", rec, ms);
}

/* adaptive redundancy (fec_ratio 0, DESIGN 8.5): down to the floor on a
 * clean link, up where FEC alone would miss, down again when the loss ends */
static void run_fec_auto(int deadline, int *ratio, int *got, int *frames)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats ss;
    static char buf[20000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, phase;
    *got = *frames = 0;
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 50;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 0; o.fec_deadline_ms = deadline;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (phase = 0; phase < 3; phase++) {
        n.loss_pct = phase == 1 ? 20 : 0;
        for (i = 0; i < 20000; i++) {
            net_tick(&n);
            if (i % 33 == 0) {
                fill_pattern(buf, 6000, (uint32_t)*frames);
                anl_stream_send_frame(a, *frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 6000, NULL);
                (*frames)++;
            }
            while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) (*got)++;
        }
        anl_stream_get_stats(a, &ss);
        ratio[phase] = (int)ss.fec_ratio;
    }
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

static int input_test_report(anl_t *w, anl_stream_t *st, uint32_t ts, uint16_t recovered)
{
    char buf[128], *p = buf;
    int i;
    p = enc32(p, w->conv); p = enc8(p, ANL_VERSION << 6); p = enc32(p, ts);
    p = enc_sid(p, SEG_CTRL, st->sid); p = enc8(p, CTRL_REPORT); p = enc_varint(p, REPORT_BODY);
    for (i = 0; i < 7; i++) p = enc16(p, 0);
    p = enc16(p, recovered);
    return anl_input_plain(w, buf, (long)(p - buf));
}

static int ordered_report_callbacks;
static void ordered_report_cb(anl_t *w, anl_stream_t *st, const anl_delay_report *r, void *user)
{
    (void)w; (void)st; (void)r; (void)user;
    ordered_report_callbacks++;
}

static void test_fec_report_order(void)
{
    anl_config c;
    anl_stream_opt o;
    anl_t *w;
    anl_stream_t *a, *b;
    anl_stream_stats ss;
    int err;
    printf("[fec reports: reordered counters, duplicate age, lost reports and clock/counter wrap]\n");
    anl_config_default(&c, ANL_ROLE_CLIENT);
    w = anl_create(1, &c, NULL);
    CHECK(w != NULL, "create connection");
    if (!w) return;
    anl_update(w, 1000);
    anl_stream_opt_default(&o, ANL_SEMI); o.fec = 1; o.fec_ratio = 0;
    a = anl_stream_open(w, &o, &err); b = anl_stream_open(w, &o, &err);
    CHECK(a && b, "open report streams");
    if (!a || !b) { anl_release(w); return; }
    ordered_report_callbacks = 0;
    anl_set_report_callback(w, ordered_report_cb);
    CHECK(input_test_report(w, a, 100, 100) == 0, "first report");
    anl_update(w, 1010);
    CHECK(input_test_report(w, a, 200, 101) == 0, "one more recovered loss");
    anl_update(w, 1020);
    CHECK(input_test_report(w, a, 100, 100) == 0, "old datagram remains valid");
    CHECK(a->peer_rp.fec_recovered == 101 && w->fl_lost == 1, "old report cannot invent a counter wrap");
    CHECK(input_test_report(w, a, 200, 101) == 0, "duplicate datagram remains valid");
    anl_stream_get_stats(a, &ss);
    CHECK(ss.peer.age_ms == 10 && ordered_report_callbacks == 2, "old/duplicate reports do not refresh stats or callbacks");
    CHECK(input_test_report(w, a, 400, 104) == 0, "new report after a missing interval");
    CHECK(w->fl_lost == 4, "cumulative report covers the missed interval");
    /* Each stream has its own ordering. Both 32-bit peer time and the 16-bit
       recovered count wrap, while this connection has seen later times on a. */
    CHECK(input_test_report(w, b, 0xffffff00u, 65534) == 0, "other stream's first report");
    CHECK(input_test_report(w, b, 0x20u, 1) == 0, "new report across both wraps");
    CHECK(input_test_report(w, b, 0xffffff50u, 65535) == 0, "late report from before the wrap");
    CHECK(b->peer_rp.fec_recovered == 1 && w->fl_lost == 7 && ordered_report_callbacks == 5, "wrap adds three real recoveries only");
    fec_loss_add(w, 200, 0);
    CHECK(w->fec_loss == (7u * 65536u / 200u) / 4u, "loss estimate uses seven recoveries, not 65536");
    anl_release(w);
}

/* adaptive redundancy (fec_ratio 0, DESIGN 8.5): down to the floor on a
 * clean link, up where FEC alone would miss the deadline, down again when the
 * loss ends; not up where a retransmission makes the deadline anyway */
static void test_fec_auto(void)
{
    int r[3], tight, got, frames;
    printf("[fec: adaptive redundancy, video 30 fps, rtt 100 ms: 0%% / 20%% / 0%% loss, 20 s each]\n");
    run_fec_auto(100, r, &got, &frames);
    printf("  deadline 100 ms (a retransmission is late): ratio %d%% / %d%% / %d%%, %d of %d frames delivered\n",
           r[0], r[1], r[2], got, frames);
    CHECK(r[0] == FEC_AUTO_MIN, "clean link: down to the floor (%d)", r[0]);
    CHECK(r[1] >= 50, "20%% loss: raised (%d)", r[1]);
    CHECK(r[2] < r[1], "loss over: lowered again (%d)", r[2]);
    tight = r[1];
    run_fec_auto(0, r, &got, &frames);
    printf("  deadline 250 ms (max_age / 2, a retransmission makes it): ratio %d%% / %d%% / %d%%, %d of %d delivered\n",
           r[0], r[1], r[2], got, frames);
    /* raised a little: a lost retransmission (4% of the losses at 20%) is late */
    CHECK(r[1] <= 70 && r[1] < tight, "20%% loss, retransmissions in time: raised less (%d vs %d)", r[1], tight);
    CHECK(got >= frames * 99 / 100, "frames delivered (%d of %d)", got, frames);
}

/* Replay a completed measurement interval. Its transition round has already
 * been excluded. Byte-valued inflight counts reproduce the diagnostic log's
 * estimates exactly without constructing unrelated packet queues. */
static void policer_interval(anl_t *w, uint32_t dur, uint32_t sent,
                             uint32_t infl0, uint32_t infl1, uint64_t delivered, uint64_t lost)
{
    w->lt_ts = 1;
    w->current = dur + 1;
    w->lt_rounds = BBR_LT_ROUNDS - 1;
    w->lt_skip = w->lt_bad = 0;
    w->lt_rd = w->lt_lost = 0;
    w->lt_sent0 = w->sent_wire;
    w->sent_wire += sent;
    w->lt_infl0 = infl0;
    w->avg_seg = 1;
    w->inflight_segs = infl1;
    bbr_policer(w, delivered, lost, 0);
}

static void test_bbr_policer_probes(void)
{
    anl_t w;
    int wrap;
    printf("[bbr: underfed tails, real capacity loss and exhausted probe bursts]\n");
    for (wrap = 0; wrap < 2; wrap++) {
        memset(&w, 0, sizeof(w));
        w.lt_state = 3; w.lt_from = 2; w.lt_k = 1; w.lt_tail = 1;
        w.lt_rate = 6006981; w.lt_res = 4; w.lt_span = 16;
        if (wrap) w.sent_wire = 0xfffffc17u;
        /* J1, tr16d_hz2zjg: only 4.46 MB/s sent at a 7.51 MB/s target,
           26 per mille lost; old code lowered the rate to 5256104. */
        policer_interval(&w, 678, 3021818, 770286, 1258346, 2466360, 62186);
        CHECK(w.lt_state == 2 && w.lt_rate == 6006981, "underfed tail keeps the known rate (wrap=%d)", wrap);
        CHECK(w.lt_left == 16 && w.lt_span == 16, "inconclusive tail does not extend the probe wait");
    }
    /* Same offered load, but a severe real delivery loss must still reduce
       the estimate. A blanket send-rate guard would discard this evidence. */
    w.lt_state = 3; w.lt_tail = 1;
    policer_interval(&w, 678, 3021818, 770286, 1258346, 800000, 2000000);
    CHECK(w.lt_state == 2 && w.lt_rate < 6006981, "lossy capacity drop still lowers the rate");

    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 1; w.lt_k = 1; w.lt_tail = 1;
    w.lt_rate = 6006981; w.lt_res = 4; w.lt_span = 16;
    policer_interval(&w, 678, 3021818, 770286, 1258346, 2466360, 62186);
    CHECK(w.lt_state == 0, "underfed first confirmation does not establish a ceiling");

    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 3;
    w.lt_rate = 5256104; w.lt_res = 4; w.lt_span = 32;
    /* J4: k=3 still delivers the burst; at k=4 sending grows, delivery
       falls and loss rises to 192 per mille. Do not accelerate to k=5. */
    policer_interval(&w, 682, 6098444, 1550121, 1568158, 6080526, 0);
    CHECK(w.lt_state == 3 && w.lt_k == 4 && !w.lt_tail, "delivery follows the probe before the bucket empties");
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt_state == 3 && w.lt_k == 4 && w.lt_tail, "probe measures the ceiling before further acceleration");

    w.lt_state = 3; w.lt_k = 4; w.lt_tail = 0; w.lt_prev_rate = 8915727;
    w.lt_res = 200;
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt_k == 5 && !w.lt_tail, "delivery dip with residual random loss alone is inconclusive");
    w.lt_k = 4; w.lt_tail = 0; w.lt_prev_rate = 8915727; w.lt_res = 4;
    policer_interval(&w, 682, 1800000, 0, 0, 1500000, 300000);
    CHECK(w.lt_k == 5 && !w.lt_tail, "reduced offered load does not prove a new ceiling");
    w.min_rtt = 100; w.prev_round_min_rtt = 200;
    policer_interval(&w, 682, 6660226, 1668953, 1770809, 5296350, 1009732);
    CHECK(w.lt_state == 0 && w.lt_hold == 48, "long-RTT queued probe still yields immediately to congestion control");

    /* J8, ab17b_zjg2lsj_v16d: an underfed k=2 tail still loses 152 per
       mille. The low-loss guard must not widen with the nominal probe. */
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 2; w.lt_tail = 1;
    w.lt_rate = 3537950; w.lt_res = 1; w.lt_span = 16;
    policer_interval(&w, 321, 623968, 0, 0, 529108, 84320);
    CHECK(w.lt_state == 2 && w.lt_rate == 3095701, "moderate loss must still allow a rate reduction at k=2");

    /* J4, ab17_hz2zjg_v17: delivery falls 5.2% while loss rises to 149
       per mille. A 1/16 decline threshold continued accelerating here. */
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 1;
    w.lt_rate = 6225626; w.lt_res = 0; w.lt_span = 16;
    policer_interval(&w, 745, 5717950, 1442960, 1434472, 5726382, 0);
    CHECK(w.lt_k == 2 && !w.lt_tail, "probe still advances while delivery follows");
    policer_interval(&w, 759, 6472614, 1629696, 1604232, 5528230, 837930);
    CHECK(w.lt_state == 3 && w.lt_k == 2 && w.lt_tail, "5.2 percent fall with rising loss stops further acceleration");
}

/* J8: a recovering ceiling can flatten gradually rather than falling by
 * more than 1/32 in any one interval. Do not exhaust the probe at 5x an old
 * low base while its actual delivery has already stopped following it. */
static void test_bbr_policer_plateau(void)
{
    anl_t w;
    int wrap, run, k;
    const uint32_t raw[2][2][6] = {
        { {301, 985490, 4244, 5305, 925412, 59024},
          {300, 1056108, 7427, 1061, 896954, 163370} },
        { {300, 982328, 5305, 8488, 919088, 61132},
          {300, 1052946, 11671, 6366, 893792, 160208} }
    };
    printf("[bbr: recovering ceiling plateaus, residual loss and insufficient probe load]\n");
    for (wrap = 0; wrap < 2; wrap++) for (run = 0; run < 2; run++) {
        const uint32_t (*a)[6] = raw[run];
        memset(&w, 0, sizeof(w));
        w.lt_state = 3; w.lt_from = 2; w.lt_k = 10; w.lt_span = 8;
        w.lt_rate = run ? 948950 : 948600;
        if (wrap) w.sent_wire = 0xfffffc17u;
        policer_interval(&w, a[0][0], a[0][1], a[0][2], a[0][3], a[0][4], a[0][5]);
        CHECK(w.lt_k == 11 && !w.lt_tail, "initial slight excess still permits the next step");
        policer_interval(&w, a[1][0], a[1][1], a[1][2], a[1][3], a[1][4], a[1][5]);
        CHECK(w.lt_state == 3 && w.lt_k == 11 && w.lt_tail,
              "J8 raw run %d stops on flattened delivery (wrap=%d)", run + 1, wrap);
    }
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 1; w.lt_rate = 948600; w.lt_span = 8;
    for (k = 1; k <= BBR_LT_PROBE_MAX && w.lt_state == 3 && !w.lt_tail; k++) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        uint32_t delivered = umin32(sent, 900000);  /* 3 MB/s, no bucket overshoot */
        policer_interval(&w, 300, sent, 0, 0, delivered, sent - delivered);
    }
    CHECK(w.lt_state == 3 && w.lt_tail, "a flat ceiling is measured without a delivery dip");
    if (w.lt_state == 3 && w.lt_tail) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        policer_interval(&w, 300, sent, 0, 0, 900000, sent - 900000);
        CHECK(w.lt_state == 2 && w.lt_rate == 3000000, "tail confirms the newly available capacity");
    }
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 11; w.lt_rate = 948600;
    w.lt_prev_rate = 2000000;
    /* Only 2.2 MB/s offered at a 3.56 MB/s target. About 10% loss and a
       near-flat delivery rate cannot establish the path's ceiling. */
    policer_interval(&w, 300, 660000, 0, 0, 594000, 66000);
    CHECK(w.lt_k == 12 && !w.lt_tail, "an underfed plateau does not establish a ceiling");
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 11; w.lt_rate = 750000;
    w.lt_prev_rate = 2300000;
    policer_interval(&w, 300, 840000, 0, 0, 726000, 114000);
    CHECK(w.lt_k == 12 && !w.lt_tail, "delivery still grows with the offered probe");
    memset(&w, 0, sizeof(w));
    w.lt_state = 3; w.lt_from = 2; w.lt_k = 1; w.lt_rate = 948600; w.lt_res = 200;
    for (k = 1; k <= BBR_LT_PROBE_MAX && w.lt_state == 3; k++) {
        uint32_t sent = bbr_lt_probe_rate(&w) * 3 / 10;
        uint32_t delivered = sent * 4 / 5;
        policer_interval(&w, 300, sent, 0, 0, delivered, sent - delivered);
        CHECK(!w.lt_tail, "unchanged residual random loss does not set a ceiling (step %d)", k);
    }
    CHECK(w.lt_state == 0, "probe budget can still end without a measured ceiling");
}

static void policer_confirmed(anl_t *w)
{
    memset(w, 0, sizeof(*w));
    w->lt_state = 2;
    w->lt_rate = 3541495;
    w->lt_res = 2;
    w->lt_left = 32;
    w->lt_span = 64;
}

static void test_bbr_policer_pacing(void)
{
    anl_t w;
    int i;
    static const uint32_t intervals[] = {1, 10, 20};
    printf("[bbr: execute low-rate policer trials below the ordinary pacing floor]\n");
    for (i = 0; i < 3; i++) {
        memset(&w, 0, sizeof(w));
        w.mss = 1368; w.interval = intervals[i]; w.rx_srtt = 1;
        w.pacing_gain = BBR_UNIT; w.btl_bw = 527000;
        /* J12 tcv_v5_f19: the old floor forced 547200 instead of 358360. */
        w.lt_state = 1; w.lt_from = 2; w.lt_rate = 358360;
        CHECK(compute_pace_rate(&w) == 358360, "execute the requested trial (interval=%u)", w.interval);
        w.lt_state = 2;
        CHECK(compute_pace_rate(&w) == 358360, "keep a confirmed low ceiling");
        w.lt_state = 3; w.lt_k = 1;
        CHECK(compute_pace_rate(&w) == 447950, "allow the explicit quarter-rate probe");
        w.lt_k = 4;
        CHECK(compute_pace_rate(&w) == 716720, "probe can discover recovered capacity");
        w.pace_rate_cfg = 100000;
        CHECK(compute_pace_rate(&w) == 100000, "configured rate cap still wins");
    }
    w.pace_rate_cfg = 0; w.lt_state = 0; w.interval = 10;
    CHECK(compute_pace_rate(&w) == 547200, "ordinary BBR keeps its pacing floor");
}

static void test_bbr_policer_capacity_change(void)
{
    anl_t w;
    uint32_t trial, left;
    printf("[bbr: verify a lower ceiling, reject random loss, recover the old rate]\n");
    policer_confirmed(&w);
    /* ab20: two stable low-rate intervals after the first mixed interval. */
    policer_interval(&w, 327, 459544, 0, 0, 363630, 95914);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495, "one low interval is inconclusive");
    policer_interval(&w, 329, 462706, 0, 0, 363630, 99076);
    CHECK(w.lt_state == 1 && w.lt_from == 2 && w.lt_rate < 1200000,
          "stable excess loss starts a lower-rate trial");
    CHECK(w.lt_save_btl == 3541495 && w.lt_skip, "trial preserves the confirmed rate and excludes transition");
    trial = w.lt_rate;
    policer_interval(&w, 400, 445600, 0, 0, 445600, 0);
    CHECK(w.lt_state == 3 && w.lt_from == 2 && w.lt_rate == trial && w.lt_span == BBR_LT_SPAN,
          "loss falls at the executed trial rate: verify its ceiling");
    CHECK(w.lt_recover_rate == 3541495, "remember the capacity that may return");
    policer_interval(&w, 400, 556000, 0, 0, 444000, 112000);
    CHECK(w.lt_tail, "excess probe loss starts tail measurement");
    policer_interval(&w, 400, 556000, 0, 0, 444000, 112000);
    CHECK(w.lt_state == 2 && w.lt_rate == 1110000 && w.lt_span == BBR_LT_SPAN,
          "confirmed lower ceiling bypasses the old ceiling's 7/8 floor and long backoff");
    w.lt_state = 3; w.lt_k = 8; w.lt_tail = 1;
    policer_interval(&w, 400, 1332000, 0, 0, 1300000, 32000);
    CHECK(w.lt_state == 2 && w.lt_recover_rate == 0 && w.lt_span == 2 * BBR_LT_SPAN,
          "capacity recovered: resume ordinary probe backoff");

    policer_confirmed(&w);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt_state == 1, "new 30 percent random loss is suspicious but not yet a lower ceiling");
    left = w.lt_left;
    policer_interval(&w, 400, 992800, 0, 0, 694960, 297840);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495 && w.lt_recover_rate == 0,
          "loss persists after slowing: restore the confirmed ceiling");
    CHECK(w.lt_left == left && w.lt_hold == left && w.lt_span == 64,
          "failed trial preserves the previous probe schedule");
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495, "cooldown prevents repeated trials of unchanged random loss");

    policer_confirmed(&w);
    policer_interval(&w, 327, 459544, 0, 0, 363630, 95914);
    policer_interval(&w, 329, 462706, 0, 0, 363630, 99076);
    policer_interval(&w, 400, 200000, 0, 0, 200000, 0);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495 && w.lt_recover_rate == 0,
          "loss-free but underfed trial does not confirm a capacity fall");

    policer_confirmed(&w);
    policer_interval(&w, 400, 1400000, 0, 0, 900000, 500000);
    policer_interval(&w, 400, 650000, 0, 0, 440000, 210000);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495, "mixed transition and low interval do not form a stable pair");
    policer_interval(&w, 400, 650000, 0, 0, 440000, 210000);
    CHECK(w.lt_state == 1, "two subsequent low intervals can start a trial");

    policer_confirmed(&w);
    w.lt_res = 300;
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    policer_interval(&w, 400, 1416000, 0, 0, 991200, 424800);
    CHECK(w.lt_state == 2 && w.lt_rate == 3541495, "known residual loss is not evidence of a capacity fall");
}

static void test_bbr_policer_residual_refresh(void)
{
    anl_t w;
    uint32_t old_rate, trial_bytes, corrected;
    int scenario, wrap;
    printf("[bbr: remeasure stale residual below the ceiling, preserve real random loss]\n");
    for (wrap = 0; wrap < 2; wrap++) for (scenario = 0; scenario < 4; scenario++) {
        policer_confirmed(&w);
        w.lt_rate = 1040000; w.lt_res = 84; w.lt_left = 1; w.lt_span = 8;
        if (wrap) w.sent_wire = 0xfffffc17u;
        old_rate = w.lt_rate;
        corrected = old_rate * 916 / 1000;
        /* About 7% steady loss no longer exceeds residual+100, so the
           capacity-fall detector cannot repair the old 84-per-mille value. */
        policer_interval(&w, 300, 312000, 0, 0, 290160, 21840);
        CHECK(w.lt_state == 1 && w.lt_from == 3 && w.lt_rate < corrected,
              "periodic probe measures below old delivery, scenario=%d wrap=%d", scenario, wrap);
        trial_bytes = w.lt_rate * 3 / 10;
        if (scenario == 1) {
            /* Real 8.4% random loss persists even below the ceiling. */
            policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes * 916 / 1000, trial_bytes * 84 / 1000);
        } else if (scenario == 2) {
            /* A receive-window/app stall is not a loss-free capacity test. */
            policer_interval(&w, 300, trial_bytes / 2, 0, 0, trial_bytes / 2, 0);
        } else {
            policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes, 0);
            CHECK(w.lt_state == 1 && w.lt_res == 84, "one quiet interval cannot erase the residual");
            if (scenario == 3) {
                /* A second interval contradicts the first: retain the old value. */
                policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes * 9 / 10, trial_bytes / 10);
            } else {
                policer_interval(&w, 300, trial_bytes, 0, 0, trial_bytes, 0);
            }
        }
        CHECK(w.lt_state == 3 && w.lt_from == 2 && w.lt_k == 1 && w.lt_skip,
              "recheck returns to a bounded capacity probe");
        if (scenario == 0) {
            CHECK(w.lt_res == 0 && w.lt_rate == corrected, "remove stale compensation after two clean intervals");
            policer_interval(&w, 300, 357240, 0, 0, 285000, 72240);
            policer_interval(&w, 300, 357240, 0, 0, 285000, 72240);
            CHECK(w.lt_state == 2 && w.lt_rate == 950000, "probe reconfirms the actual ceiling");
        } else CHECK(w.lt_res == 84 && w.lt_rate == old_rate, "inconclusive recheck preserves residual and ceiling");
        if (scenario == 2) CHECK(!w.lt_res_checked, "underfed check remains eligible for a later retry");
    }
    policer_confirmed(&w);
    w.lt_rate = 1040000; w.lt_res = 84; w.lt_left = 1; w.lt_res_checked = 1;
    policer_interval(&w, 300, 312000, 0, 0, 285792, 26208);
    CHECK(w.lt_state == 3 && w.lt_from == 2, "already checked random loss does not delay every capacity probe");
    w.lt_state = 2; w.lt_left = 2;
    policer_interval(&w, 300, 312000, 0, 0, 293280, 18720);
    CHECK(w.lt_state == 2, "one newly lower-loss interval is inconclusive");
    policer_interval(&w, 300, 312000, 0, 0, 293280, 18720);
    CHECK(w.lt_state == 1 && w.lt_from == 3, "persistent lower loss permits another residual check");
}

static void test_bbr_policer_queue_recheck(void)
{
    anl_t w;
    int initial;
    printf("[bbr: transient queued interval must not erase an established policer]\n");
    for (initial = 0; initial < 2; initial++) {
        policer_confirmed(&w);
        w.lt_state = 3; w.lt_from = initial ? 1 : 2;
        w.lt_k = 1; w.lt_rate = 951805; w.lt_res = 3;
        w.min_rtt = 1; w.prev_round_min_rtt = 20;
        /* j8d pn r5: at k=1 a queue-tainted interval delivered all 344658
           bytes, but old code discarded the ceiling and waited 48 intervals. */
        policer_interval(&w, 301, 344658, 0, 0, 344658, 0);
        if (initial) {
            CHECK(w.lt_state == 0, "initial detection still rejects a queued path");
            continue;
        }
        CHECK(w.lt_state == 3 && w.lt_k == 1 && w.lt_rate == 951805 && !w.lt_hold,
              "repeat the same bounded step after a transient queue signal");
        w.prev_round_min_rtt = 1;
        policer_interval(&w, 301, 344658, 0, 0, 344658, 0);
        CHECK(w.lt_state == 3 && w.lt_k == 2, "clean next interval resumes capacity discovery");
        w.prev_round_min_rtt = 20;
        policer_interval(&w, 301, 420000, 0, 0, 344658, 75342);
        CHECK(w.lt_state == 3 && w.lt_k == 2, "nonconsecutive queue events do not count as persistent");
        policer_interval(&w, 301, 420000, 0, 0, 344658, 75342);
        CHECK(w.lt_state == 0 && w.lt_hold == 48, "consecutive queue evidence still releases the ceiling");
    }
}

/* Frequent ACKs must not evict the history needed to smooth short-RTT
 * samples, including with the default interval and across clock wrap. */
static void test_bbr_delivery_window(void)
{
    static const int intervals[] = { 1, 10, 20, 100, 5000 };
    static const uint32_t starts[] = { 1000, 0xfffffff0u, 0xffffdff0u };
    size_t i, j;
    printf("[bbr: delivery window survives frequent updates and clock wrap]\n");
    for (i = 0; i < sizeof(intervals) / sizeof(intervals[0]); i++) {
        for (j = 0; j < sizeof(starts) / sizeof(starts[0]); j++) {
            anl_t w;
            uint32_t t, span = umax32((uint32_t)intervals[i], 10);
            memset(&w, 0, sizeof(w));
            w.interval = intervals[i];
            for (t = 0; t <= 3 * span; t++) {
                w.current = starts[j] + t;
                w.delivered = (uint64_t)t * 1000;
                bbr_dw_checkpoint(&w);
                bbr_dw_checkpoint(&w);    /* another ACK in the same tick */
            }
            CHECK(bbr_window_bw(&w, span) == 1000000,
                  "interval %d, start %u: window rate %u", w.interval, starts[j], bbr_window_bw(&w, span));
            if (w.interval == 1) {
                bbr_sample rs;
                memset(&rs, 0, sizeof(rs));
                w.min_rtt = 1; w.avg_seg = w.mss = 1000;
                w.next_round_delivered = w.delivered + 1;
                w.delivered_ts = w.current;
                w.delivered += 5000;      /* a compressed ACK at this tick */
                rs.prior_delivered = w.delivered - 5000;
                rs.prior_ts = w.current - 1;
                rs.send_ts = w.current;
                rs.first_sent = w.current - 1;
                bbr_on_ack(&w, &rs);
                CHECK(w.btl_bw <= 2000000, "1 ms updates still smooth compressed ACKs: %u", w.btl_bw);
                rs.app_limited = 1;
                bbr_on_ack(&w, &rs);
                CHECK(w.btl_bw == 5000000, "app-limited bursts retain their rate sample: %u", w.btl_bw);
            }
        }
    }
}

/* a path of about 1 ms (loopback, LAN): min_rtt / 2 is 0, a rate sample's
 * send interval may be 0 too (divided by it once, found on a real network) */
static void test_tiny_rtt(void)
{
    net n; anl_config ca, cb; anl_stream_opt o;
    static char buf[40000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, frames = 0, got = 0;
    printf("[tiny rtt: one-way delay 0..1 ms, video 30 fps, 5%% loss]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = 0; n.max_delay = 1;
    n.loss_pct = 5;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 0;
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 5000; i++) {
        net_tick(&n);
        if (i % 33 == 0) {
            int len = frames % 30 == 0 ? 30000 : 3000;
            fill_pattern(buf, len, (uint32_t)frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, len, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) got++;
    }
    printf("  %d of %d frames delivered\n", got, frames);
    CHECK(got >= frames * 95 / 100, "frames delivered (%d of %d)", got, frames);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* adaptive FEC on two streams (DESIGN 8.5): audio learns the loss from the
 * connection estimate (video's packets and the peer's repair counts), not
 * only from its own 50 packets/s */
static void test_fec_auto_shared(void)
{
    net n; anl_config ca, cb; anl_stream_opt oa, ov; anl_stream_stats sa, sv;
    static char buf[20000];
    anl_stream_t *a, *b, *va, *vb;
    anl_frame_info fi;
    int i, frames = 0, sent = 0, got = 0;
    printf("[fec: adaptive on audio (prio 1) and video (prio 2), 10%% loss, rtt 100 ms, 5 s]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 50;
    n.loss_pct = 10;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&oa, ANL_SEMI);
    oa.prio = 1; oa.fec = 1; oa.fec_ratio = 0; oa.max_age_ms = 200;
    anl_stream_opt_default(&ov, ANL_SEMI);
    ov.prio = 2; ov.fec = 1; ov.fec_ratio = 0;
    a = open_pair(&n, 0, &oa, NULL, &b);
    va = open_pair(&n, 0, &ov, NULL, &vb);
    if (!b || !vb) { net_stop(&n); return; }
    for (i = 0; i < 5000; i++) {
        net_tick(&n);
        if (i % 20 == 0) {
            fill_pattern(buf, 160, (uint32_t)sent);
            if (anl_stream_send_frame(a, 0, buf, 160, NULL) == 0) sent++;
        }
        if (i % 33 == 0) {
            fill_pattern(buf, 6000, (uint32_t)frames);
            anl_stream_send_frame(va, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 6000, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) got++;
        while (anl_stream_recv_frame(vb, buf, sizeof(buf), &fi) > 0) ;
    }
    anl_stream_get_stats(b, &sa);
    anl_stream_get_stats(vb, &sv);
    printf("  audio: %d of %d delivered, %u repaired by FEC; video: %u repaired by FEC\n", got, sent, sa.fec_recovered, sv.fec_recovered);
    CHECK(sa.fec_recovered >= 5, "audio repaired by FEC within 5 s (%u)", sa.fec_recovered);
    CHECK(got >= sent * 95 / 100, "audio delivered (%d of %d)", got, sent);
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    net_stop(&n);
}

/* target_rate (DESIGN 6.10): an encoder that follows it ramps up to the
 * link and follows a bandwidth drop */
static uint32_t g_rate;
static int g_rate_calls;
static void rate_cb(anl_t *w, uint32_t target, void *user) { (void)w; (void)user; g_rate = target; g_rate_calls++; }

/* The same traffic must give the same recommendation on either side of the
 * wrapping wire counter. Payload and delivery totals are 64-bit counters. */
static void test_target_rate_wrap(void)
{
    anl_t plain, wrapped;
    uint32_t targets[2];
    int i;
    memset(&plain, 0, sizeof(plain));
    plain.mss = 1200;
    plain.current = 1000;
    plain.rate_ts = 800;
    plain.rate_share = 230;
    plain.btl_bw = 250000;
    plain.rx_srtt = 100;
    plain.sent_wire = 100000;
    plain.rate_wire0 = plain.sent_wire;
    plain.rate_cb = rate_cb;
    wrapped = plain;
    wrapped.sent_wire = UINT32_MAX - 29999;
    wrapped.rate_wire0 = wrapped.sent_wire;
    g_rate_calls = 0;
    for (i = 0; i < 3; i++) {
        plain.current += 200;
        wrapped.current += 200;
        plain.sent_wire += 60000;
        wrapped.sent_wire += 60000;
        plain.tx_payload += 40000;
        wrapped.tx_payload += 40000;
        rate_update(&plain);
        targets[0] = g_rate;
        rate_update(&wrapped);
        targets[1] = g_rate;
        CHECK(plain.rate_share == wrapped.rate_share,
              "wire counter wrap preserves payload share (%u / %u)", plain.rate_share, wrapped.rate_share);
        CHECK(plain.rate_target == wrapped.rate_target && targets[0] == targets[1],
              "wire counter wrap preserves rate and callback (%u / %u)", plain.rate_target, wrapped.rate_target);
    }
    CHECK(g_rate_calls >= 2, "rate callbacks exercised across wire counter wrap");
}

static void test_target_rate(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stats st;
    static char buf[200000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    uint32_t hi = 0, lo = 0, frames = 0;
    uint64_t tail_sum = 0, drop_sum = 0;
    int i, tail_n = 0, drop_n = 0;
    printf("[target_rate: an encoder follows it, 3 Mbps link, rtt 40 ms; 1 Mbps after 30 s]\n");
    net_init(&n, &ca, &cb);
    n.bandwidth_bps = 3000000;
    n.queue_limit = 60;
    net_start(&n, &ca, &cb);
    anl_set_rate_callback(n.ep[0], rate_cb);
    g_rate = 0; g_rate_calls = 0;
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 40000; i++) {
        uint32_t rate = g_rate ? g_rate : 60000;            /* bytes/s; 480 kbps before the first value */
        net_tick(&n);
        if (i % 33 == 0) {
            int len = (int)umin32(rate / 30, sizeof(buf));
            fill_pattern(buf, len, frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, len, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) ;
        if (i == 30000) { hi = g_rate; n.bandwidth_bps = 1000000; }
        if (i >= 32000 && i < 34000 && i % 100 == 0) { drop_sum += g_rate; drop_n++; }
        if (i >= 35000 && i % 100 == 0) { tail_sum += g_rate; tail_n++; }
    }
    lo = (uint32_t)(drop_sum / (uint64_t)drop_n);
    anl_get_stats(n.ep[0], &st);
    printf("  target after 30 s: %u B/s (link 375000), 2..4 s after the drop: %u B/s (link 125000), last 5 s %u on average; %d callbacks\n",
           hi, lo, (uint32_t)(tail_sum / (uint64_t)tail_n), g_rate_calls);
    CHECK(hi >= 375000 * 3 / 10 && hi <= 375000 * 11 / 10, "ramped up towards the link (%u)", hi);  /* the estimate varies by a few % */
    CHECK(lo <= 125000, "followed the drop within 2..4 s (%u)", lo);
    CHECK(tail_sum / (uint64_t)tail_n >= 125000 / 2 && tail_sum / (uint64_t)tail_n <= 125000, "settled below the new link (%u)",
          (uint32_t)(tail_sum / (uint64_t)tail_n));
    CHECK(st.target_rate > 0, "target_rate in the stats (%u)", st.target_rate);
    CHECK(g_rate_calls > 2, "callbacks (%d)", g_rate_calls);
    net_stop(&n);
}

/* delay reports (DESIGN 6.9): the receiver measures, the sender learns */
static int g_reports;
static uint32_t g_report_frames;
static void report_cb(anl_t *w, anl_stream_t *s, const anl_delay_report *r, void *user)
{
    (void)w; (void)s; (void)user;
    if (r->valid) { g_reports++; g_report_frames += r->frames; }
}

static void test_delay_report(void)
{
    net n; anl_config ca, cb; anl_stream_opt o; anl_stream_stats sa, sb;
    static char buf[20000];
    anl_stream_t *a, *b;
    anl_frame_info fi;
    int i, frames = 0;
    printf("[delay report: video 30 fps, one-way delay 40..60 ms, 5%% loss]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = 40; n.max_delay = 60;
    n.loss_pct = 5;
    net_start(&n, &ca, &cb);
    anl_set_report_callback(n.ep[0], report_cb);
    g_reports = 0; g_report_frames = 0;
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 10000; i++) {
        net_tick(&n);
        if (i % 33 == 0) {
            fill_pattern(buf, 6000, (uint32_t)frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, 6000, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &fi) > 0) ;
    }
    anl_stream_get_stats(a, &sa);
    anl_stream_get_stats(b, &sb);
    printf("  receiver: jitter %u ms, queue %u/%u ms, frame delay %u/%u ms (avg/max), %u frames in the last interval\n",
           sb.rx.jitter_ms, sb.rx.qdelay_avg_ms, sb.rx.qdelay_max_ms, sb.rx.frame_delay_avg_ms, sb.rx.frame_delay_max_ms, sb.rx.frames);
    printf("  sender:   %d reports (%u frames in all), the last %u ms old: jitter %u ms, frame delay max %u ms\n",
           g_reports, g_report_frames, sa.peer.age_ms, sa.peer.jitter_ms, sa.peer.frame_delay_max_ms);
    CHECK(sb.rx.valid, "receiver measured");
    /* reports are not resent (5% loss) and an interval without new data sends none */
    CHECK(g_report_frames >= (uint32_t)frames * 7 / 10, "reports cover the frames (%u of %d)", g_report_frames, frames);
    CHECK(sb.rx.jitter_ms >= 1 && sb.rx.jitter_ms <= 20, "jitter within the path's 20 ms spread (%u)", sb.rx.jitter_ms);
    CHECK(sb.rx.qdelay_max_ms <= 40, "queue delay: the jitter spread only (%u)", sb.rx.qdelay_max_ms);
    CHECK(sa.peer.valid && g_reports >= 30, "sender got reports (%d)", g_reports);
    CHECK(sa.peer.age_ms <= 600, "the last report is recent (%u ms): reports are not resent", sa.peer.age_ms);
    CHECK(sa.peer.jitter_ms == sb.rx.jitter_ms || sa.peer.age_ms > 0, "report carries the receiver's numbers");
    net_stop(&n);
}

/*---------------------------------------------------------------------
 * 9. network outage: FWD / CLOSE / data retransmissions must back off
 *-------------------------------------------------------------------*/
static void test_outage(void)
{
    net n; anl_config ca, cb; anl_stream_opt os, orl;
    anl_stream_t *a, *b, *ra, *rb, *ca2, *cb2;
    char buf[2000];
    anl_frame_info fi;
    int i, frames_after = 0, rel_got = 0, r, t_resume = -1;
    printf("[network outage: 5 s blackout with semi + reliable streams, one closed during the outage]\n");
    net_init(&n, &ca, &cb);
    n.min_delay = n.max_delay = 30;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&os, ANL_SEMI);
    os.max_age_ms = 200;
    anl_stream_opt_default(&orl, ANL_RELIABLE);
    a = open_pair(&n, 0, &os, NULL, &b);
    ra = open_pair(&n, 0, &orl, NULL, &rb);
    ca2 = open_pair(&n, 0, &orl, NULL, &cb2);
    if (!b || !rb || !cb2) { net_stop(&n); return; }
    for (i = 0; i < 12000; i++) {
        n.loss_pct = (i >= 2000 && i < 7000) ? 100 : 0;
        net_tick(&n);
        if (i % 20 == 0) { fill_pattern(buf, 160, (uint32_t)i); anl_stream_send_frame(a, 0, buf, 160, NULL); }
        if (i % 100 == 0 && i < 9000) { fill_pattern(buf, 1000, (uint32_t)(i / 100)); anl_stream_send(ra, buf, 1000); }
        if (i == 3000) anl_stream_close(ca2);                     /* closed in the middle of the outage */
        while ((r = anl_stream_recv_frame(b, buf, sizeof(buf), &fi)) > 0) {
            if (i >= 7000) { frames_after++; if (t_resume < 0) t_resume = i - 7000; }
        }
        while ((r = anl_stream_recv(rb, buf, sizeof(buf))) > 0) {
            CHECK(check_pattern(buf, r, (uint32_t)rel_got), "reliable message %d", rel_got);
            rel_got++;
        }
        CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "alive at t=%d ms", i);
        if (anl_state(n.ep[0]) != 0) break;
    }
    printf("  audio resumed %d ms after the outage, %d frames after; reliable %d/90 messages\n", t_resume, frames_after, rel_got);
    CHECK(t_resume >= 0 && t_resume < 3000 && frames_after > 150, "semi stream resumes");
    CHECK(rel_got == 90, "reliable stream delivered everything (%d)", rel_got);
    CHECK(stream_state(cb2) == ANL_STREAM_CLOSED, "close issued during the outage completed (%d)", stream_state(cb2));
    net_stop(&n);
}

int main(void)
{
    const char *seed = getenv("ANL_TEST_SEED");    /* runs are deterministic for a given seed */
    const char *only = getenv("ANL_TEST_ONLY");     /* substring of a test name: run only those */
#define RUN(call) do { if (!only || strstr(#call, only)) call; } while (0)
    setvbuf(stdout, NULL, _IONBF, 0);
    if (seed) g_seed = 0x9E3779B97F4A7C15ULL * (strtoull(seed, NULL, 10) + 1);
    printf("seed %s\n", seed ? seed : "default");
    RUN(test_kat());
    RUN(test_demux());
    RUN(test_default_stream());
    RUN(test_reliable(0, 0));
    RUN(test_reliable(10, 0));
    RUN(test_reliable(10, 1));
    RUN(test_semi(0, 0, 0));
    RUN(test_semi(5, 0, 0));
    RUN(test_semi(5, 1, 0));
    RUN(test_semi(2, 0, 1000));
    RUN(test_reflect());
    RUN(test_stale());
    RUN(test_violation());
    RUN(test_seg_size());
    RUN(test_open_close(0));
    RUN(test_open_close(15));
    RUN(test_semi_abort(0, 0));
    RUN(test_semi_abort(10, 0));
    RUN(test_semi_abort(10, 1));
    RUN(test_pacing());
    RUN(test_stream_lifecycle(0));
    RUN(test_stream_lifecycle(10));
    RUN(test_sid_once());
    RUN(test_handle_lifetime());
    RUN(test_accept_limits());
    RUN(test_max_streams());
    RUN(test_priority());
    RUN(test_key_sender_purge());
    RUN(test_key_receiver_discard());
    RUN(test_window_reopen_loss());
    RUN(test_receiver_deadline_default());
    RUN(test_receiver_skip_ack_fragments());
    RUN(test_fec_rtt_default());
    RUN(test_fec_repair());
    RUN(test_fec_report_order());
    RUN(test_fec_auto());
    RUN(test_fec_auto_shared());
    RUN(test_bbr_delivery_window());
    RUN(test_bbr_policer_probes());
    RUN(test_bbr_policer_plateau());
    RUN(test_bbr_policer_pacing());
    RUN(test_bbr_policer_capacity_change());
    RUN(test_bbr_policer_residual_refresh());
    RUN(test_bbr_policer_queue_recheck());
    RUN(test_tiny_rtt());
    RUN(test_target_rate_wrap());
    RUN(test_target_rate());
    RUN(test_delay_report());
    RUN(test_outage());
    RUN(test_fuzz());
    if (g_fail) { printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("\nall tests passed\n");
    return 0;
}
