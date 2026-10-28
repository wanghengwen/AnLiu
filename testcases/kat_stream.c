/* known-answer vectors, default / reliable / semi-reliable streams, allocator. Part of the anl_test unit (testcases/main.c): included, not compiled alone. */

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
        chacha20_xor(key, nonce, 1, buf, buf, len);
        hex2bin("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d", exp, len);
        CHECK(memcmp(buf, exp, len) == 0, "chacha20 encryption vector");
    }

    /* the four-block path agrees with the single block at every length
       (whole passes, a partial last pass, a tail of less than a word) */
    {
        static const size_t lens[] = {1, 3, 63, 64, 65, 100, 127, 128, 129, 191, 255, 256, 257, 300, 1200, 1400};
        static uint8_t a[1400], b[1400], ks[64];
        size_t k, n, c, ok = 1;
        for (k = 0; k < sizeof lens / sizeof lens[0]; k++) {
            n = lens[k];
            for (i = 0; i < n; i++) a[i] = b[i] = (uint8_t)(i * 7 + k);
            chacha20_xor(key, nonce, 7, a, a, n);
            for (i = 0, c = 7; i < n; c++) {         /* the reference: block by block */
                size_t m = n - i < 64 ? n - i : 64, q;
                chacha20_block(key, (uint32_t)c, nonce, ks);
                for (q = 0; q < m; q++) b[i + q] ^= ks[q];
                i += m;
            }
            if (memcmp(a, b, n) != 0) ok = 0;
        }
        CHECK(ok, "chacha20 four blocks at a time == one at a time, all lengths");
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
        wire[50] ^= 1;
        /* conv (P's first 4 bytes: 0, 7, 14, 21) goes out masked with the
           4 tag bytes from (tag[0] & 7) + 1, still authenticated */
        {
            uint8_t off = (uint8_t)(1 + (wire[0] & 7));
            uint32_t conv = 0;
            CHECK((wire[ANL_TAG_SIZE] ^ wire[off]) == 0 && (wire[ANL_TAG_SIZE + 1] ^ wire[off + 1]) == 7 &&
                  (wire[ANL_TAG_SIZE + 2] ^ wire[off + 2]) == 14 && (wire[ANL_TAG_SIZE + 3] ^ wire[off + 3]) == 21,
                  "conv masked by tag bytes from offset %u", off);
            CHECK(anl_peek_conv((const char *)wire, 112, &conv) == ANL_OK && conv == 0x150e0700u,
                  "conv read without keys (%08x)", conv);
            wire[ANL_TAG_SIZE + 2] ^= 0x40;
            r = siv_open(&keys, 0, wire, 112, plain);
            CHECK(r == ANL_EAUTH, "tampered conv rejected (%d)", r);
            wire[ANL_TAG_SIZE + 2] ^= 0x40;
            r = siv_open(&keys, 0, wire, 112, plain);
            CHECK(r == 100 && plain[2] == 14, "restored datagram opens again (%d)", r);
        }
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

/* a plaintext datagram header (DESIGN 4) as `from` would send it next: its pn
 * (taken from it, so that its genuine datagrams after this are no replays);
 * without a sender, from a counter of its own */
static char *plain_hdr(char *q, anl_t *from, uint32_t conv, uint8_t flg, uint16_t ts)
{
    static uint32_t lone = 1000;
    q = enc32(q, conv); q = enc8(q, flg); q = enc16(q, ts);
    return enc32(q, from ? from->tx_pn++ : lone++);
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
        if (ST_ON(STREAM_OF(n)->cfg, STC_STRICT)) continue;
        c++;
        if (STREAM_OF(n)->state == ANL_STREAM_CLOSED) d++;
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
        if (ST_ON(st->cfg, STC_STRICT)) continue;
        printf("    %s sid %d state %d peer_opened %d snd que/buf %u/%u snd_una/nxt %u/%u rcv_nxt %u rcvq %u ack %d\n",
               who, st->sid, st->state, st->state != ANL_STREAM_OPENING, st->nsnd_que, st->nsnd_buf, st->snd_una, st->snd_nxt,
               st->rcv_nxt, st->nrcv_que, ST_ON(st->out, STO_ACK));
    }
    {
        uint32_t i;
        for (i = 0; i < w->nsrec; i++) {
            const sid_rec *r = &w->srec[i];
            if (r->closing) printf("    %s closing sid %u (%u sent)\n", who, r->sid, r->xmit);
            else printf("    %s held sid %u for %d ms\n", who, r->sid, tdiff(r->ts, w->current));
        }
    }
}

/* sids closed here, the peer's RST not in yet */
static uint32_t nclos(const anl_t *w) { return sid_closing_count(w); }

/* a sid of the peer's resting after its stream went (DESIGN 6.1) */
static int sid_held(const anl_t *w, int sid)
{
    const sid_rec *r = srec_find(w, sid);
    return r != NULL && !r->closing && tdiff(w->current, r->ts) < 0;
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
    CHECK(ss.state == ANL_STREAM_OPEN && ss.rmt_wnd <= 4096 && ss.rmt_wnd > 700, "B heard A, A's window is the default 4096 (%d, %u)", ss.state, ss.rmt_wnd);
    CHECK(n.ep[1]->dflt->rcv_wnd == 700 && n.ep[0]->dflt->rcv_wnd == 4096, "windows from config");
    CHECK(anl_state(n.ep[0]) == 0 && anl_state(n.ep[1]) == 0, "connections alive");
    printf("  %d bytes each way in %d ms with 5%% loss\n", total, i);
    net_stop(&n);
}

/* the allocator in anl_config: user pointer, size header, a failure after
 * fail_after allocations (-1: never) */
typedef struct { size_t live; long allocs, frees, null_frees, fail_after; } alloc_acct;
typedef union { size_t n; long double align; } alloc_hdr;

static void *acct_malloc(void *user, size_t n)
{
    alloc_acct *a = (alloc_acct *)user;
    alloc_hdr *h;
    if (a->fail_after >= 0 && a->allocs >= a->fail_after) return NULL;
    h = (alloc_hdr *)malloc(sizeof(alloc_hdr) + n);
    if (h == NULL) return NULL;
    h->n = n;
    a->live += n;
    a->allocs++;
    return h + 1;
}

static void acct_free(void *user, void *p)
{
    alloc_acct *a = (alloc_acct *)user;
    alloc_hdr *h;
    if (p == NULL) { a->null_frees++; return; }
    h = (alloc_hdr *)p - 1;
    a->live -= h->n;
    a->frees++;
    free(h);
}

static void test_allocator(void)
{
    net n; anl_config ca, cb, c; anl_stream_opt o;
    alloc_acct acct[2];
    static char buf[30000];
    anl_stream_t *a, *b;
    int i, k, frames = 0, got = 0, created = 0, failed_clean = 1;
    printf("[allocator: per connection from anl_config, with its user pointer, all back at release]\n");
    memset(acct, 0, sizeof(acct));
    acct[0].fail_after = acct[1].fail_after = -1;
    net_init(&n, &ca, &cb);
    n.loss_pct = 5;
    ca.malloc_fn = cb.malloc_fn = acct_malloc;
    ca.free_fn = cb.free_fn = acct_free;
    ca.alloc_user = &acct[0];
    cb.alloc_user = &acct[1];
    net_start(&n, &ca, &cb);
    CHECK(acct[0].allocs > 0 && acct[1].allocs > 0, "each connection allocates through its own allocator (%ld, %ld)", acct[0].allocs, acct[1].allocs);
    /* a semi stream with FEC (its buffers, the receive runs, the peer's accepted stream) */
    anl_stream_opt_default(&o, ANL_SEMI);
    o.fec = 1; o.fec_ratio = 25; o.max_age_ms = 300;
    a = open_pair(&n, 0, &o, NULL, &b);
    CHECK(a != NULL && b != NULL, "stream opened");
    for (i = 0; i < 4000 && a && b; i++) {
        anl_frame_info info;
        net_tick(&n);
        if (i % 33 == 0 && frames < 60) {
            int len = frames % 30 == 0 ? 20000 : 2000;
            fill_pattern(buf, len, (uint32_t)frames);
            anl_stream_send_frame(a, frames % 30 == 0 ? ANL_FRAME_KEY : 0, buf, len, NULL);
            frames++;
        }
        while (anl_stream_recv_frame(b, buf, sizeof(buf), &info) >= 0) got++;
    }
    CHECK(got > 50, "frames delivered (%d of %d)", got, frames);
    CHECK(acct[0].live > 0 && acct[1].live > 0, "memory held while running");
    printf("  %d frames, %ld / %ld allocations, %zu / %zu bytes held before release\n",
           got, acct[0].allocs, acct[1].allocs, acct[0].live, acct[1].live);
    net_stop(&n);
    for (k = 0; k < 2; k++)
        CHECK(acct[k].live == 0 && acct[k].allocs == acct[k].frees && acct[k].null_frees == 0,
              "side %d: everything back at release (live %zu, %ld allocs, %ld frees, %ld NULL frees)",
              k, acct[k].live, acct[k].allocs, acct[k].frees, acct[k].null_frees);

    /* set both or neither */
    anl_config_default(&c, ANL_ROLE_CLIENT);
    c.malloc_fn = acct_malloc;
    CHECK(anl_create(1, &c, NULL) == NULL, "malloc_fn without free_fn refused");
    c.malloc_fn = NULL; c.free_fn = acct_free;
    CHECK(anl_create(1, &c, NULL) == NULL, "free_fn without malloc_fn refused");

    /* an allocation that fails inside anl_create: NULL, and nothing kept */
    c.malloc_fn = acct_malloc; c.free_fn = acct_free; c.alloc_user = &acct[0];
    for (k = 0; k < 64 && !created; k++) {
        anl_t *w;
        memset(&acct[0], 0, sizeof(acct[0]));
        acct[0].fail_after = k;
        w = anl_create(1, &c, NULL);
        if (w) { created = 1; anl_release(w); }
        if (acct[0].live != 0 || acct[0].allocs != acct[0].frees) failed_clean = 0;
    }
    CHECK(created && k > 1, "anl_create succeeds once enough allocations succeed (after %d)", k - 1);
    CHECK(failed_clean, "a failed anl_create gives back what it took");
    printf("  anl_create takes %d allocations; each earlier failure left nothing behind\n", k - 1);
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

/* byte stream (default stream): anl_recv reads like TCP - any length, across
 * segments - and anl_peeksize is everything readable in order */
static void test_byte_stream_read(void)
{
    net n; anl_config ca, cb; static char out[20000], in[20000]; int i, got = 0, r, peek;
    puts("[byte stream: partial and multi-segment reads, peeksize, a small window]");
    net_init(&n, &ca, &cb);
    ca.default_rcv_wnd = cb.default_rcv_wnd = 8;
    net_start(&n, &ca, &cb);
    for (i = 0; i < (int)sizeof out; i++) out[i] = (char)(i * 31 + i / 251);
    CHECK(anl_recv(n.ep[1], in, 10) == ANL_EAGAIN && anl_peeksize(n.ep[1]) == ANL_EAGAIN, "empty: ANL_EAGAIN");
    CHECK(anl_send(n.ep[0], out, 3000) >= 0, "send 3000");
    for (i = 0; i < 2000 && anl_peeksize(n.ep[1]) < 3000; i++) net_tick(&n);
    peek = anl_peeksize(n.ep[1]);
    CHECK(peek == 3000, "peeksize is all readable bytes (%d)", peek);
    CHECK(anl_recv(n.ep[1], in, 0) == 0, "len 0 reads nothing");
    r = anl_recv(n.ep[1], in, 8);
    CHECK(r == 8 && memcmp(in, out, 8) == 0, "8 bytes of a larger segment (%d)", r);
    CHECK(anl_peeksize(n.ep[1]) == 2992, "peeksize after a partial read (%d)", anl_peeksize(n.ep[1]));
    r = anl_recv(n.ep[1], in + 8, 2000);
    CHECK(r == 2000 && memcmp(in, out, 2008) == 0, "2000 bytes across segments (%d)", r);
    r = anl_recv(n.ep[1], in + 2008, 5000);
    CHECK(r == 992 && memcmp(in, out, 3000) == 0, "the rest (%d)", r);
    CHECK(anl_recv(n.ep[1], in, 10) == ANL_EAGAIN, "drained");
    /* 17000 more bytes through an 8-segment window, read 100 bytes at a time */
    for (i = 0; i < 5; i++) CHECK(anl_send(n.ep[0], out + 3000 + i * 3400, 3400) >= 0, "send chunk %d", i);
    for (i = 0; i < 20000 && got < 17000; i++) {
        net_tick(&n);
        while (got < 17000 && (r = anl_recv(n.ep[1], in + got, 100)) > 0) got += r;
    }
    CHECK(got == 17000 && memcmp(in, out + 3000, 17000) == 0, "17000 bytes read 100 at a time through a small window (%d)", got);
    net_stop(&n);
}
