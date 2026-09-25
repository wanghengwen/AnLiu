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
    for (i = 0; i < 3000 && g_peer[1 - from][sid] == NULL; i++) net_tick(n);
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
    ca.resend = cb.resend = 2;
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
    ca.nodelay = cb.nodelay = 1; ca.resend = cb.resend = 2;
    n.bandwidth_bps = bandwidth_kbps * 1000; n.queue_limit = 30;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = fec; o.fec_depth = 2;
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
    for (i = 0; i < 10000 && stream_count(n.ep[0], NULL); i++) net_tick(&n);    /* CLOSE exchange under loss */
    CHECK(stream_count(n.ep[0], NULL) == 0, "opener side freed (%d ms)", i);
    CHECK(stream_count(n.ep[1], NULL) == 1, "peer handle kept until the application closes it");
    CHECK(b && stream_state(b) == ANL_STREAM_CLOSED && anl_stream_recv(b, buf, sizeof(buf)) == ANL_ECLOSED, "held handle still answers");
    if (b) anl_stream_close(b);
    for (i = 0; i < 100 && stream_count(n.ep[1], NULL); i++) net_tick(&n);
    CHECK(stream_count(n.ep[1], NULL) == 0, "freed after close");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
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
    ca.pace_rate = 2000000;          /* 2 MB/s */
    ca.nc = 1;
    net_start(&n, &ca, &cb);
    anl_stream_opt_default(&o, ANL_SEMI);
    a = open_pair(&n, 0, &o, NULL, &b);
    if (!b) { net_stop(&n); return; }
    for (i = 0; i < 300; i++) net_tick(&n);
    n.max_burst[0] = 0;
    fill_pattern(buf, 200000, 1);
    anl_stream_send_frame(a, ANL_FRAME_KEY, buf, 200000, NULL);
    for (i = 0; i < 400; i++) net_tick(&n);
    /* 2 MB/s over a 5 ms window = 10 KB, plus bucket 4*mtu and one datagram of slack */
    CHECK(n.max_burst[0] <= 10000 + 4 * 1400 + 1400, "max 5ms burst %u bytes", n.max_burst[0]);
    CHECK(anl_stream_peeksize(b) == 200000, "frame arrived (%d)", anl_stream_peeksize(b));
    printf("  max 5 ms burst: %u bytes, frame arrived after <= 400 ms\n", n.max_burst[0]);
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
    o2.fec = 1; o2.fec_depth = 3;
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
 * nc = 1 disables cwnd; the sender is then paced at 2.8 Mbps, below the link:
 * without congestion control and without a rate below the bottleneck the
 * link collapses (queue drops + RTO backoff) and no priority can help. */
static void run_priority(int ctrl_prio, int video_prio, int video, int nc, prio_result *res)
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
    ca.nc = cb.nc = nc;
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
    static const char *cc[2] = { "cwnd on (nc=0)", "cwnd off (nc=1), paced at 2.8 Mbps" };
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
           (nc=0: at most until video frees the shared cwnd) */
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
    ca.nodelay = cb.nodelay = 1; ca.resend = cb.resend = 2; ca.nc = cb.nc = 1;
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
    setvbuf(stdout, NULL, _IONBF, 0);
    if (seed) g_seed = 0x9E3779B97F4A7C15ULL * (strtoull(seed, NULL, 10) + 1);
    printf("seed %s\n", seed ? seed : "default");
    test_kat();
    test_demux();
    test_default_stream();
    test_reliable(0, 0);
    test_reliable(10, 0);
    test_reliable(10, 1);
    test_semi(0, 0, 0);
    test_semi(5, 0, 0);
    test_semi(5, 1, 0);
    test_semi(2, 0, 1000);
    test_reflect();
    test_stale();
    test_violation();
    test_seg_size();
    test_open_close(0);
    test_open_close(15);
    test_pacing();
    test_stream_lifecycle(0);
    test_stream_lifecycle(10);
    test_sid_once();
    test_handle_lifetime();
    test_accept_limits();
    test_max_streams();
    test_priority();
    test_key_sender_purge();
    test_key_receiver_discard();
    test_outage();
    test_fuzz();
    if (g_fail) { printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("\nall tests passed\n");
    return 0;
}
