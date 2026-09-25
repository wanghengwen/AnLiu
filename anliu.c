/*
 * anliu.c - AnLiu（暗流）: encrypted, multi-stream, semi-reliable ARQ over UDP.
 *
 * Implementation of DESIGN.md v0.5. Structure of this file:
 *
 *   1. utilities: allocator, byte order, varint, intrusive list
 *   2. crypto: ChaCha20 (RFC 8439), SipHash-2-4-128, SIV seal/open, KDF, PRNG
 *   3. data structures: segment, stream, connection
 *   4. datagram builder (packing segments, padding, sealing, pacing tokens)
 *   5. receive path: parsing, DATA/ACK/FWD/CTRL handling, FEC decoder
 *   6. send path: flush (ACK, CTRL, retransmit, weighted RR, FEC encoder)
 *   7. public API
 */
#include "anliu.h"

#include <stdlib.h>
#include <string.h>

/*=====================================================================
 * 1. utilities
 *====================================================================*/
static void *(*anl_malloc_hook)(size_t) = NULL;
static void (*anl_free_hook)(void *) = NULL;

static void *anl_malloc(size_t n)
{
    return anl_malloc_hook ? anl_malloc_hook(n) : malloc(n);
}

static void anl_free(void *p)
{
    if (p == NULL) return;
    if (anl_free_hook) anl_free_hook(p); else free(p);
}

void anl_allocator(void *(*new_malloc)(size_t), void (*new_free)(void *))
{
    anl_malloc_hook = new_malloc;
    anl_free_hook = new_free;
}

static int32_t tdiff(uint32_t a, uint32_t b) { return (int32_t)(a - b); }
static uint32_t umin32(uint32_t a, uint32_t b) { return a < b ? a : b; }
static uint32_t umax32(uint32_t a, uint32_t b) { return a > b ? a : b; }
static uint32_t ubound32(uint32_t lo, uint32_t v, uint32_t hi)
{
    return umin32(umax32(lo, v), hi);
}

/* 16-bit wire value -> 32-bit, relative to ref (DESIGN 5.1) */
static uint32_t extend16(uint16_t v, uint32_t ref)
{
    int16_t d = (int16_t)(uint16_t)(v - (uint16_t)ref);
    return ref + (uint32_t)(int32_t)d;
}

static char *enc8(char *p, uint8_t v) { *(uint8_t *)p = v; return p + 1; }
static char *enc16(char *p, uint16_t v)
{
    p = enc8(p, (uint8_t)(v & 0xff));
    return enc8(p, (uint8_t)(v >> 8));
}
static char *enc32(char *p, uint32_t v)
{
    p = enc16(p, (uint16_t)(v & 0xffff));
    return enc16(p, (uint16_t)(v >> 16));
}
static uint8_t dec8(const char **p) { uint8_t v = *(const uint8_t *)*p; (*p)++; return v; }
static uint16_t dec16(const char **p)
{
    uint16_t lo = dec8(p);
    uint16_t hi = dec8(p);
    return (uint16_t)(lo | (hi << 8));
}
static uint32_t dec32(const char **p)
{
    uint32_t lo = dec16(p);
    uint32_t hi = dec16(p);
    return lo | (hi << 16);
}

/* LEB128 varint, at most 3 bytes (values < 2^21) */
#define VARINT_MAX ((1u << 21) - 1)

static int varint_size(uint32_t v)
{
    return v < 0x80u ? 1 : v < 0x4000u ? 2 : 3;
}

static char *enc_varint(char *p, uint32_t v)
{
    while (v >= 0x80u) {
        p = enc8(p, (uint8_t)(0x80u | (v & 0x7fu)));
        v >>= 7;
    }
    return enc8(p, (uint8_t)v);
}

static int dec_varint(const char **p, const char *end, uint32_t *out)
{
    uint32_t v = 0;
    int i;
    for (i = 0; i < 3; i++) {
        uint8_t b;
        if (*p >= end) return -1;
        b = dec8(p);
        v |= (uint32_t)(b & 0x7fu) << (7 * i);
        if (!(b & 0x80u)) { *out = v; return 0; }
    }
    return -1;
}

/* intrusive doubly linked list, ikcp style */
typedef struct anl_node {
    struct anl_node *next, *prev;
} anl_node;

#define QINIT(q)       do { (q)->next = (q)->prev = (q); } while (0)
#define QEMPTY(q)      ((q)->next == (q))
#define QENTRY(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

static void qdel(anl_node *n)
{
    n->prev->next = n->next;
    n->next->prev = n->prev;
    n->next = n->prev = NULL;
}

static void qadd_tail(anl_node *n, anl_node *head)
{
    n->prev = head->prev;
    n->next = head;
    head->prev->next = n;
    head->prev = n;
}

static void qadd_after(anl_node *n, anl_node *pos)
{
    n->prev = pos;
    n->next = pos->next;
    pos->next->prev = n;
    pos->next = n;
}

/*=====================================================================
 * 2. crypto
 *====================================================================*/
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define CHACHA_QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

/* RFC 8439 block function: 32-byte key, 32-bit counter, 96-bit nonce */
static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16], x[16];
    int i;
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
    s[12] = counter;
    s[13] = ld32(nonce); s[14] = ld32(nonce + 4); s[15] = ld32(nonce + 8);
    memcpy(x, s, sizeof(x));
    for (i = 0; i < 10; i++) {
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) st32(out + 4 * i, x[i] + s[i]);
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t *buf, size_t len)
{
    uint8_t ks[64];
    while (len > 0) {
        size_t n = len < 64 ? len : 64, i;
        chacha20_block(key, counter++, nonce, ks);
        for (i = 0; i < n; i++) buf[i] ^= ks[i];
        buf += n;
        len -= n;
    }
}

#define ROTL64(v, n) (((v) << (n)) | ((v) >> (64 - (n))))
#define SIPROUND \
    v0 += v1; v1 = ROTL64(v1, 13); v1 ^= v0; v0 = ROTL64(v0, 32); \
    v2 += v3; v3 = ROTL64(v3, 16); v3 ^= v2;                      \
    v0 += v3; v3 = ROTL64(v3, 21); v3 ^= v0;                      \
    v2 += v1; v1 = ROTL64(v1, 17); v1 ^= v2; v2 = ROTL64(v2, 32);

static uint64_t ld64(const uint8_t *p)
{
    return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32);
}

static void st64(uint8_t *p, uint64_t v)
{
    st32(p, (uint32_t)v);
    st32(p + 4, (uint32_t)(v >> 32));
}

/* SipHash-2-4 with 128-bit output (reference construction) */
static void siphash128(const uint8_t key[16], const uint8_t *in, size_t len, uint8_t out[16])
{
    uint64_t k0 = ld64(key), k1 = ld64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1 ^ 0xeeULL;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    const uint8_t *end = in + (len & ~(size_t)7);
    int left = (int)(len & 7);

    for (; in != end; in += 8) {
        uint64_t m = ld64(in);
        v3 ^= m;
        SIPROUND; SIPROUND;
        v0 ^= m;
    }
    switch (left) {
    case 7: b |= (uint64_t)in[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)in[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)in[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)in[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)in[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)in[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)in[0];       /* fallthrough */
    default: break;
    }
    v3 ^= b;
    SIPROUND; SIPROUND;
    v0 ^= b;
    v2 ^= 0xeeULL;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    st64(out, v0 ^ v1 ^ v2 ^ v3);
    v1 ^= 0xddULL;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    st64(out + 8, v0 ^ v1 ^ v2 ^ v3);
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;
    for (i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* DESIGN 3.1: per-direction keys */
void anl_keys_derive(anl_keys *keys, const uint8_t psk[ANL_PSK_SIZE])
{
    static const uint8_t kdf_nonce[12] = { 'A','n','L','i','u','-','K','D','F','-','v','1' };
    int dir;
    for (dir = 0; dir < 2; dir++) {
        uint8_t blk[64];
        chacha20_block(psk, (uint32_t)dir, kdf_nonce, blk);
        memcpy(keys->enc[dir], blk, 32);
        memcpy(keys->mac[dir], blk + 32, 16);
        memcpy(keys->rng[dir], blk + 48, 16);
    }
}

/* Seal P in place. buf points at the tag slot; P starts at buf + ANL_TAG_SIZE
 * and is plen bytes long. */
static void siv_seal(const anl_keys *keys, int dir, uint8_t *buf, size_t plen)
{
    uint8_t tag[16];
    siphash128(keys->mac[dir], buf + ANL_TAG_SIZE, plen, tag);
    memcpy(buf, tag, ANL_TAG_SIZE);
    chacha20_xor(keys->enc[dir], buf, 0, buf + ANL_TAG_SIZE, plen);
}

/* Open a datagram: decrypt into plain, verify. Returns plaintext length or error. */
static int siv_open(const anl_keys *keys, int dir, const uint8_t *wire, size_t size, uint8_t *plain)
{
    uint8_t tag[16];
    size_t plen;
    if (size < (size_t)ANL_OVERHEAD) return ANL_EFORMAT;
    plen = size - ANL_TAG_SIZE;
    memcpy(plain, wire + ANL_TAG_SIZE, plen);
    chacha20_xor(keys->enc[dir], wire, 0, plain, plen);
    siphash128(keys->mac[dir], plain, plen, tag);
    if (!ct_equal(tag, wire, ANL_TAG_SIZE)) return ANL_EAUTH;
    return (int)plen;
}

/*=====================================================================
 * 3. data structures
 *====================================================================*/
#define SEG_DATA        0
#define SEG_ACK         1
#define SEG_FWD         2
#define SEG_CTRL        3

#define CTRL_PARITY     0x01
#define CTRL_OPEN       0x02    /* announcement only, body = open body (DESIGN 6.1) */
#define CTRL_CLOSE      0x03

#define F_OPEN          0x80    /* DATA carries the stream parameters (DESIGN 5.2) */
#define F_HAS_FRAME     0x40
#define F_KEY           0x20
#define F_FRG_MASK      0x1f

#define CLOSE_F_RST     0x01
#define CLOSE_F_OPEN    0x02    /* CLOSE carries the stream parameters */

/* stream parameters carried by DATA (F_OPEN) and CLOSE (CLOSE_F_OPEN) */
#define OPEN_BODY       5       /* ob(1) rcv_wnd(2) tag(2) */
#define OB_SEMI         0x01
#define OB_STREAM       0x02

#define FLG_PAD         0x01
#define FLG_VER_MASK    0xc0
#define FLG_RSV_MASK    0x3e

#define RTO_NDL         30
#define RTO_MIN         100
#define RTO_DEF         200
#define RTO_MAX         60000
#define PROBE_INIT      1000
#define PROBE_LIMIT     60000
#define OPEN_RTO_MAX    5000
#define KEEPALIVE_PAD   16

#define SID_BYTES       2       /* type(2) | rsv(1) | sid(13), DESIGN 5 */
#define SID_RSV         0x20    /* reserved bit in b0: sent as 0, datagram dropped if set */
#define SID_HI_MASK     0x1f
#define DATA_HDR_MAX    11      /* type|sid(2) b1 frg_ext(2) sn(2) frame(2) len(2); + OPEN_BODY until the peer is heard */
#define ACK_HDR         11      /* type|sid(2) b1 una(2) wnd(2) ts_echo(4) */
#define ACK_F_WASK      0x80    /* window probe: please answer with an ACK */
#define ACK_F_FRESH     0x40    /* data arrived since the last ACK: ts_echo is an RTT sample */
#define SACK_REPEAT     3       /* every received segment is reported in at least 3 ACKs */
#define REO_DIV         16      /* RACK reordering window starts at min_rtt / 16 */
#define REO_MULT_MAX    16      /* and grows up to min_rtt */
#define REO_DECAY       16      /* round trips without a spurious retransmission before it shrinks */
#define MIN_RTT_WIN     10000   /* min_rtt is re-learned after 10 s (path changes) */
#define PARITY_HDR      8       /* type|sid(2) sub len(2) base(2) kd */

#define SID_PAGE_SHIFT  7       /* stream table: 64 pages of 128 slots, allocated on demand */
#define SID_PAGE_SIZE   (1u << SID_PAGE_SHIFT)
#define SID_PAGES       (ANL_MAX_STREAMS >> SID_PAGE_SHIFT)
#define CANON_HDR_MAX   7       /* b1 frg_ext(2) frame(2) plen(2) */

static const uint32_t prio_weight[ANL_MAX_PRIO] = { 8, 4, 2, 1 };

typedef struct anl_seg {
    anl_node node;
    uint32_t sn;
    uint32_t frg;
    uint32_t frame_no;      /* semi: 32-bit frame number (all fragments) */
    uint32_t first_sn;      /* semi: sn of the frame's first fragment */
    uint32_t ts_enq;        /* semi: enqueue time */
    uint32_t ts_sent;       /* time of the last transmission (RACK) */
    uint32_t resendts;
    uint32_t rto;
    uint32_t lost;          /* RACK declared it lost: retransmit at the next flush */
    uint32_t xmit;          /* sender: transmissions; receiver (rcv_buf): times reported in a SACK range */
    uint8_t  flags;         /* F_HAS_FRAME | F_KEY (wire: first fragment only) */
    uint8_t  fkey;          /* semi: the frame is a key frame (every fragment) */
    uint8_t  rack_rtx;      /* the last transmission was a RACK retransmission (spurious check) */
    uint32_t len;
    char     data[1];
} anl_seg;

typedef struct fec_group {
    uint32_t k;
    uint32_t lmax;
    uint8_t *buf;
} fec_group;

typedef struct fec_centry {
    int      valid;
    uint32_t sn;
    uint32_t len;
    uint8_t *buf;
} fec_centry;

typedef struct fec_pentry {
    int      valid;
    uint32_t base;
    uint32_t k, dep, lmax;
    uint32_t ts;
    uint8_t *buf;
} fec_pentry;

typedef struct anl_stream {
    anl_node lnode;         /* w->slist */
    anl_node cnode;         /* w->ctl_list while control output is pending (next == NULL: not linked) */
    anl_t *w;
    void *user;
    int sid, tag, mode, prio, stream, flush_on_send;
    int state;              /* ANL_STREAM_OPEN .. ANL_STREAM_CLOSED */
    int strict;             /* default stream: strict priority over every other stream */
    /* the struct lives while either owner holds it: the sid table or the application */
    int detached;           /* no longer in the sid table (sid reusable), handle still held */
    int app_released;       /* the application closed its handle */
    int by_peer;
    int rst_pending;
    uint32_t rst_ts;
    uint32_t snd_wnd, rcv_wnd, rmt_wnd;
    uint32_t snd_una, snd_nxt, rcv_nxt;
    uint32_t mss;

    anl_node snd_queue, snd_buf, rcv_buf, rcv_queue;
    uint32_t nsnd_que, nsnd_buf, nrcv_buf, nrcv_que;

    int ack_pending;        /* an ACK is due */
    int ack_fresh;          /* data arrived since the last ACK: ts_echo is an RTT sample */
    uint32_t ack_ts;
    /* RACK (DESIGN 6.3): the newest datagram with data of this stream the peer
       is known to have - orders segments sent in the same millisecond */
    uint32_t rack_ts;       /* its send time (ts_echo) */
    uint32_t rack_hi;       /* highest sn the peer has reported + 1 */
    int rack_valid;
    int probe_ask, probe_tell;
    uint32_t probe_wait, ts_probe;

    /* open / close */
    int peer_opened;        /* the peer has this stream: stop sending the parameters */
    uint32_t open_ts, open_rto;
    int peer_closed, peer_released, close_answer;
    uint32_t final_sn, peer_final_sn;
    uint32_t close_ts, close_xmit, close_rto;

    /* semi-reliable */
    int max_age_ms, max_bytes, drop_until_key, rcv_deadline_ms, dropping;
    uint32_t frame_next, backlog_bytes, cur_first_sn;
    int fwd_pending;
    uint32_t fwd_una, fwd_ts, fwd_xmit, fwd_peer_una, fwd_rto;
    int frame_seen, delivered_any;
    uint32_t frame_max, last_delivered;
    /* key frames (DESIGN 7.6) */
    int rcv_drop_until_key;
    uint32_t block_since;
    int blocked;

    /* FEC */
    int fec, fec_depth, fec_flush_ms;
    fec_group *groups;
    uint32_t fec_base, fec_first_ts, fec_n;
    fec_centry *cache;
    uint32_t cache_n;
    fec_pentry *pcache;
    uint32_t pcache_n;
    int in_retry;

    /* stats */
    uint32_t retrans, frames_dropped, frames_skipped, fec_recovered;
    uint32_t frames_discarded;
} anl_stream;

struct anl_s {
    uint32_t conv;
    int role;
    anl_keys keys;
    void *user;
    anl_output_fn output;

    uint32_t mtu, mss;
    int pad_max;
    anl_rng_fn rng;
    int nodelay, interval, resend, nc, ack_nodelay;
    uint32_t init_cwnd, dead_link, ts_window, keepalive_ms, idle_timeout_ms;
    int pace_rate_cfg;
    uint32_t pace_burst, rcv_limit;

    int32_t rx_rttval, rx_srtt, rx_rto, rx_minrto;
    int reo_mult;                       /* RACK reordering window = reo_mult * min_rtt / 16 */
    uint32_t reo_inc_ts;                /* last reo_mult change: at most one per round trip */
    uint32_t reo_spur_ts;               /* last spurious RACK retransmission */
    uint32_t min_rtt, min_rtt_ts;       /* windowed minimum RTT (MIN_RTT_WIN) */
    uint32_t rack_ts, rack_rtt;         /* RACK: newest datagram the peer is known to have (any stream) */
    int rack_valid;
    uint32_t cwnd, ssthresh, incr;
    uint32_t current, ts_flush;
    int updated;
    int state;

    uint32_t peer_ts;
    int peer_ts_valid;
    uint32_t last_rx, last_tx;

    int64_t pace_tokens;
    uint32_t pace_last, pace_rate;
    int pace_blocked;

    uint32_t rcv_bytes;
    int rcv_limited;
    int rx_data_since_ack;

    anl_stream **spages[SID_PAGES];     /* sid -> stream                     */
    anl_node slist;                     /* every stream struct */
    anl_node ctl_list;                  /* streams with control output pending (flush_control) */
    uint32_t npeer_streams, max_peer_streams;
    int next_sid;                       /* sids are never reused: client 2,4,6.. server 1,3,5.. */
    uint8_t sid_bits[ANL_MAX_STREAMS / 8];  /* every sid ever used; a late first segment gets RST */
    anl_accept_fn accept_cb;
    anl_stream *dflt;                   /* default stream, sid 0 */
    uint16_t *rstq;                     /* pending RSTs for sids without any state */
    int nrstq, rstq_cap;
    uint8_t rst_bits[ANL_MAX_STREAMS / 8];  /* dedupe for rstq */

    /* datagram builder */
    char *buf;
    uint32_t ptr;
    int dg_has_data;
    char *rxbuf;
    char *scratch;      /* 2 * mtu */
    int64_t flush_budget;

    /* PRNG */
    uint8_t prng_key[32], prng_nonce[12], prng_buf[64];
    uint32_t prng_ctr;
    int prng_pos;

    /* stats */
    uint32_t retrans_total;
    uint64_t tx_dg, rx_dg, rx_auth_fail, rx_stale;
};

static anl_seg *seg_new(uint32_t len)
{
    anl_seg *s = (anl_seg *)anl_malloc(sizeof(anl_seg) + len);
    if (s == NULL) return NULL;
    memset(s, 0, sizeof(anl_seg));
    s->len = len;
    return s;
}

static void seg_free(anl_seg *s) { anl_free(s); }

static anl_seg *qfirst_seg(anl_node *head)
{
    return QEMPTY(head) ? NULL : QENTRY(head->next, anl_seg, node);
}

static anl_seg *qlast_seg(anl_node *head)
{
    return QEMPTY(head) ? NULL : QENTRY(head->prev, anl_seg, node);
}

static void free_seg_list(anl_node *head)
{
    while (!QEMPTY(head)) {
        anl_seg *s = QENTRY(head->next, anl_seg, node);
        qdel(&s->node);
        seg_free(s);
    }
}

/*--------------------------------------------------------------------
 * stream table
 *-------------------------------------------------------------------*/
#define STREAM_OF(n) QENTRY(n, anl_stream, lnode)
/* iterate w->slist; the current stream may be unlinked inside the body */
#define FOR_EACH_STREAM(w, st, n, nx) \
    for ((n) = (w)->slist.next; (n) != &(w)->slist && ((st) = STREAM_OF(n), (nx) = (n)->next, 1); (n) = (nx))

static anl_stream *sget(const anl_t *w, int sid)
{
    anl_stream **pg;
    if (sid < 0 || sid >= ANL_MAX_STREAMS) return NULL;
    pg = w->spages[sid >> SID_PAGE_SHIFT];
    return pg ? pg[sid & (SID_PAGE_SIZE - 1)] : NULL;
}

static int sput(anl_t *w, anl_stream *st)
{
    anl_stream ***pg = &w->spages[st->sid >> SID_PAGE_SHIFT];
    if (*pg == NULL) {
        *pg = (anl_stream **)anl_malloc(sizeof(anl_stream *) * SID_PAGE_SIZE);
        if (*pg == NULL) return ANL_ENOMEM;
        memset(*pg, 0, sizeof(anl_stream *) * SID_PAGE_SIZE);
    }
    (*pg)[st->sid & (SID_PAGE_SIZE - 1)] = st;
    qadd_tail(&st->lnode, &w->slist);
    return 0;
}

/* take the stream out of the sid table (the sid becomes free); it stays in slist */
static void sdetach(anl_t *w, anl_stream *st)
{
    anl_stream **pg = w->spages[st->sid >> SID_PAGE_SHIFT];
    if (!st->detached && pg && pg[st->sid & (SID_PAGE_SIZE - 1)] == st) pg[st->sid & (SID_PAGE_SIZE - 1)] = NULL;
    st->detached = 1;
}

/* schedule control output (ACK / RST / CLOSE / probe) for the next flush_control */
static void ctl_mark(anl_stream *st)
{
    if (st->cnode.next == NULL) qadd_tail(&st->cnode, &st->w->ctl_list);
}

static char *enc_sid(char *p, int type, int sid)
{
    p = enc8(p, (uint8_t)((type << 6) | ((sid >> 8) & SID_HI_MASK)));
    return enc8(p, (uint8_t)(sid & 0xff));
}

/* stream parameters chosen by the opener (DESIGN 5.2 / 6.1) */
static char *enc_open_body(char *p, const anl_stream *st)
{
    p = enc8(p, (uint8_t)((st->mode == ANL_SEMI ? OB_SEMI : 0) | (st->stream ? OB_STREAM : 0)));
    p = enc16(p, (uint16_t)st->rcv_wnd);
    return enc16(p, (uint16_t)st->tag);
}

typedef struct open_info {
    int mode, stream, tag;
    uint32_t rcv_wnd;
} open_info;

static void dec_open_body(const char **p, open_info *oi)
{
    uint8_t ob = dec8(p);
    oi->mode = (ob & OB_SEMI) ? ANL_SEMI : ANL_RELIABLE;
    oi->stream = oi->mode == ANL_RELIABLE && (ob & OB_STREAM);
    oi->rcv_wnd = dec16(p);
    oi->tag = dec16(p);
}

/* wire size of a DATA segment of st */
static uint32_t data_seg_size(const anl_stream *st, const anl_seg *seg)
{
    uint32_t n = SID_BYTES + 1 + 2 + (uint32_t)varint_size(seg->len) + seg->len;
    if (seg->frg >= 31) n += (uint32_t)varint_size(seg->frg - 31);
    if (seg->flags & F_HAS_FRAME) n += 2;
    if (!st->peer_opened) n += OPEN_BODY;
    return n;
}

/* canonical encoding for FEC (DESIGN 8.3) */
static uint32_t canon_build(uint8_t *out, uint32_t frg, uint8_t flags, uint16_t frame16,
                            const char *data, uint32_t len)
{
    char *p = (char *)out;
    uint8_t frg5 = frg >= 31 ? 31 : (uint8_t)frg;
    p = enc8(p, (uint8_t)((flags & (F_HAS_FRAME | F_KEY)) | frg5));
    if (frg >= 31) p = enc_varint(p, frg - 31);
    if (flags & F_HAS_FRAME) p = enc16(p, frame16);
    p = enc16(p, (uint16_t)len);
    memcpy(p, data, len);
    return (uint32_t)(p - (char *)out) + len;
}

/*--------------------------------------------------------------------
 * PRNG (DESIGN 3.5)
 *-------------------------------------------------------------------*/
static void prng_init(anl_t *w)
{
    uintptr_t a = (uintptr_t)w;
    uint32_t i;
    memcpy(w->prng_key, w->keys.rng[w->role], 16);
    memcpy(w->prng_key + 16, w->keys.rng[w->role], 16);
    memset(w->prng_nonce, 0, 12);
    for (i = 0; i < sizeof(a) && i < 8; i++) w->prng_nonce[i] = (uint8_t)(a >> (8 * i));
    w->prng_nonce[8] ^= (uint8_t)w->conv;
    w->prng_nonce[9] ^= (uint8_t)(w->conv >> 8);
    w->prng_nonce[10] ^= (uint8_t)(w->conv >> 16);
    w->prng_nonce[11] ^= (uint8_t)(w->conv >> 24);
    w->prng_ctr = 0;
    w->prng_pos = 64;
}

static void prng_mix(anl_t *w, uint32_t v)
{
    w->prng_nonce[4] ^= (uint8_t)v;
    w->prng_nonce[5] ^= (uint8_t)(v >> 8);
    w->prng_nonce[6] ^= (uint8_t)(v >> 16);
    w->prng_nonce[7] ^= (uint8_t)(v >> 24);
    w->prng_pos = 64;
}

static void prng_bytes(anl_t *w, uint8_t *out, size_t n)
{
    if (w->rng) { w->rng(w->user, out, n); return; }
    while (n > 0) {
        size_t take;
        if (w->prng_pos >= 64) {
            chacha20_block(w->prng_key, w->prng_ctr++, w->prng_nonce, w->prng_buf);
            w->prng_pos = 0;
        }
        take = 64 - (size_t)w->prng_pos;
        if (take > n) take = n;
        memcpy(out, w->prng_buf + w->prng_pos, take);
        w->prng_pos += (int)take;
        out += take;
        n -= take;
    }
}

/*=====================================================================
 * 4. datagram builder
 *====================================================================*/
static void pace_refill(anl_t *w);
static int stream_sendable(const anl_stream *st);

static void dg_begin(anl_t *w)
{
    w->ptr = ANL_OVERHEAD;
    w->dg_has_data = 0;
}

static uint32_t dg_room(const anl_t *w) { return w->mtu - w->ptr; }

static void dg_output(anl_t *w, int force_pad)
{
    uint8_t flg = 0;
    uint32_t room;
    char *p;

    if (w->output == NULL) { dg_begin(w); return; }

    /* random padding (DESIGN 3.5) */
    room = dg_room(w);
    if ((w->pad_max > 0 || force_pad) && room >= 1) {
        uint8_t r;
        uint32_t pm = w->pad_max > 0 ? (uint32_t)w->pad_max : KEEPALIVE_PAD;
        uint32_t n;
        prng_bytes(w, &r, 1);
        n = 1 + (r % pm);
        if (n > room) n = room;
        if (n > 1) prng_bytes(w, (uint8_t *)w->buf + w->ptr, n - 1);
        w->buf[w->ptr + n - 1] = (char)(uint8_t)n;
        w->ptr += n;
        flg |= FLG_PAD;
    }

    p = w->buf + ANL_TAG_SIZE;
    p = enc32(p, w->conv);
    p = enc8(p, flg);
    (void)enc32(p, w->current);

    siv_seal(&w->keys, w->role, (uint8_t *)w->buf, w->ptr - ANL_TAG_SIZE);
    w->output(w->buf, (int)w->ptr, w, w->user);
    w->tx_dg++;
    w->last_tx = w->current;
    if (w->dg_has_data && w->pace_rate > 0) w->pace_tokens -= (int64_t)w->ptr;
    dg_begin(w);
}

/* flush the current datagram if it carries anything */
static void dg_seal(anl_t *w)
{
    if (w->ptr > (uint32_t)ANL_OVERHEAD) dg_output(w, 0);
}

static void dg_need(anl_t *w, uint32_t size)
{
    if (dg_room(w) < size) dg_seal(w);
}

static char *dg_ptr(anl_t *w) { return w->buf + w->ptr; }

static void dg_commit(anl_t *w, uint32_t size, int is_data)
{
    w->ptr += size;
    if (is_data) w->dg_has_data = 1;
}

/* DATA segment; carries the stream parameters until the peer has been heard (DESIGN 5.2) */
static void write_data_seg(anl_t *w, const anl_stream *st, const anl_seg *seg)
{
    uint32_t size = data_seg_size(st, seg);
    char *p;
    uint8_t frg5 = seg->frg >= 31 ? 31 : (uint8_t)seg->frg;

    dg_need(w, size);
    p = dg_ptr(w);
    p = enc_sid(p, SEG_DATA, st->sid);
    p = enc8(p, (uint8_t)((st->peer_opened ? 0 : F_OPEN) | (seg->flags & (F_HAS_FRAME | F_KEY)) | frg5));
    if (seg->frg >= 31) p = enc_varint(p, seg->frg - 31);
    p = enc16(p, (uint16_t)seg->sn);
    if (seg->flags & F_HAS_FRAME) p = enc16(p, (uint16_t)seg->frame_no);
    if (!st->peer_opened) p = enc_open_body(p, st);
    p = enc_varint(p, seg->len);
    memcpy(p, seg->data, seg->len);
    dg_commit(w, size, 1);
}

static void write_fwd_seg(anl_t *w, const anl_stream *st, uint32_t new_una)
{
    char *p;
    dg_need(w, SID_BYTES + 2);
    p = dg_ptr(w);
    p = enc_sid(p, SEG_FWD, st->sid);
    (void)enc16(p, (uint16_t)new_una);
    dg_commit(w, SID_BYTES + 2, 0);
}

static void write_ctrl_seg(anl_t *w, int sid, uint8_t subtype, const uint8_t *body, uint32_t blen)
{
    uint32_t size = SID_BYTES + 1 + (uint32_t)varint_size(blen) + blen;
    char *p;
    dg_need(w, size);
    p = dg_ptr(w);
    p = enc_sid(p, SEG_CTRL, sid);
    p = enc8(p, subtype);
    p = enc_varint(p, blen);
    if (blen) memcpy(p, body, blen);
    dg_commit(w, size, subtype == CTRL_PARITY);
}

/* OPEN announcement: lets the peer create the stream before any data flows */
static void write_open_seg(anl_t *w, const anl_stream *st)
{
    uint8_t body[OPEN_BODY];
    (void)enc_open_body((char *)body, st);
    write_ctrl_seg(w, st->sid, CTRL_OPEN, body, OPEN_BODY);
}

/* CLOSE; st (optional) supplies our una - it acknowledges the peer's data, so
 * that its last segments are not left waiting for an ACK that was lost - and
 * the stream parameters while the peer has not been heard, so that a CLOSE
 * overtaking the data still creates the stream */
static void write_close_seg(anl_t *w, int sid, uint32_t final_sn, int rst, const anl_stream *st)
{
    uint8_t body[5 + OPEN_BODY];
    int open = st != NULL && !st->peer_opened && !rst;
    char *p = (char *)body;
    p = enc16(p, (uint16_t)final_sn);
    p = enc8(p, (uint8_t)((rst ? CLOSE_F_RST : 0) | (open ? CLOSE_F_OPEN : 0)));
    p = enc16(p, (uint16_t)(st != NULL ? st->rcv_nxt : 0));
    if (open) p = enc_open_body(p, st);
    write_ctrl_seg(w, sid, CTRL_CLOSE, body, (uint32_t)(p - (char *)body));
}

static uint32_t wnd_unused(const anl_t *w, const anl_stream *st)
{
    if (w->rcv_limited) return 0;
    return st->nrcv_que < st->rcv_wnd ? st->rcv_wnd - st->nrcv_que : 0;
}

/* ACK: una + SACK ranges of rcv_buf (DESIGN 5.3). A range is reported while
 * any of its segments has been reported fewer than SACK_REPEAT times, so a
 * lost ACK costs nothing as long as one of the next ones gets through. */
static void write_ack_segs(anl_t *w, anl_stream *st)
{
    uint32_t maxroom = w->mtu - ANL_OVERHEAD;
    uint8_t b1 = (uint8_t)((st->probe_ask ? ACK_F_WASK : 0) | (st->ack_fresh ? ACK_F_FRESH : 0));
    anl_node *pos = st->rcv_buf.next;
    char *rb = w->scratch + w->mtu;         /* range bytes; the segment is assembled in scratch */

    do {
        char *p = w->scratch;
        uint32_t cnt = 0, prev = st->rcv_nxt, rlen = 0, seglen;
        while (pos != &st->rcv_buf) {
            anl_seg *s = QENTRY(pos, anl_seg, node);
            anl_node *q = pos->next, *m;
            uint32_t start = s->sn, end = start + 1, need = s->xmit < SACK_REPEAT, bytes;
            while (q != &st->rcv_buf && QENTRY(q, anl_seg, node)->sn == end) {
                need |= QENTRY(q, anl_seg, node)->xmit < SACK_REPEAT;
                end++;
                q = q->next;
            }
            if (need) {
                bytes = (uint32_t)varint_size(start - prev) + (uint32_t)varint_size(end - start);
                if (ACK_HDR + (uint32_t)varint_size(cnt + 1) + rlen + bytes > maxroom) break;  /* next ACK segment */
                (void)enc_varint(enc_varint(rb + rlen, start - prev), end - start);
                rlen += bytes;
                cnt++;
                prev = end;
                for (m = pos; m != q; m = m->next) QENTRY(m, anl_seg, node)->xmit++;
            }
            pos = q;
        }
        p = enc_sid(p, SEG_ACK, st->sid);
        p = enc8(p, b1);
        p = enc16(p, (uint16_t)st->rcv_nxt);
        p = enc16(p, (uint16_t)wnd_unused(w, st));
        p = enc32(p, st->ack_ts);
        p = enc_varint(p, cnt);
        memcpy(p, rb, rlen);
        p += rlen;
        seglen = (uint32_t)(p - w->scratch);
        dg_need(w, seglen);
        memcpy(dg_ptr(w), w->scratch, seglen);
        dg_commit(w, seglen, 0);
    } while (pos != &st->rcv_buf);

    st->ack_pending = 0;
    st->ack_fresh = 0;
    st->probe_ask = 0;
    st->probe_tell = 0;
}

static void ack_schedule(anl_stream *st)
{
    st->ack_pending = 1;
    ctl_mark(st);
}

/*--------------------------------------------------------------------
 * pacing (DESIGN 6.7)
 *-------------------------------------------------------------------*/
static uint32_t compute_pace_rate(const anl_t *w)
{
    uint64_t wnd = 0, rate;
    uint32_t srtt;
    anl_node *n, *nx;
    anl_stream *st;
    if (w->pace_rate_cfg < 0) return 0;
    if (w->pace_rate_cfg > 0) return (uint32_t)w->pace_rate_cfg;
    if (w->nc) {
        FOR_EACH_STREAM(w, st, n, nx) {
            if (stream_sendable(st)) wnd += umin32(st->snd_wnd, st->rmt_wnd);
        }
    } else {
        wnd = w->cwnd;
    }
    if (wnd < 1) wnd = 1;
    srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    rate = wnd * w->mss * 1000u * 5u / 4u / srtt;
    if (rate > 0xffffffffu) rate = 0xffffffffu;
    if (rate < w->mss) rate = w->mss;
    return (uint32_t)rate;
}

static void pace_refill(anl_t *w)
{
    int32_t dt;
    w->pace_rate = compute_pace_rate(w);
    if (w->pace_rate == 0) { w->pace_tokens = (int64_t)w->pace_burst; w->pace_last = w->current; return; }
    dt = tdiff(w->current, w->pace_last);
    if (dt > 0) {
        /* idle time accumulates at most pace_burst; but while data waits for
           tokens (the last flush was pace-blocked) what the rate earns over one
           update step (at most one interval) must not be cut off, or the rate
           is capped at about pace_burst per update (~7 MB/s at a 1 ms clock)
           whatever it is */
        int64_t earned = (int64_t)w->pace_rate * dt / 1000;
        int64_t step = (int64_t)w->pace_rate * (int64_t)umin32((uint32_t)dt, w->interval) / 1000;
        int64_t cap = w->pace_blocked && step > (int64_t)w->pace_burst ? step : (int64_t)w->pace_burst;
        w->pace_tokens += earned;
        if (w->pace_tokens > cap) w->pace_tokens = cap;
    }
    w->pace_last = w->current;
}

static int pace_can_send(const anl_t *w)
{
    return w->pace_rate == 0 || w->pace_tokens > 0;
}

/* milliseconds until the bucket becomes positive again */
static uint32_t pace_wait_ms(const anl_t *w)
{
    int64_t need;
    if (w->pace_rate == 0 || w->pace_tokens > 0) return 0;
    need = 1 - w->pace_tokens;
    return (uint32_t)((need * 1000 + w->pace_rate - 1) / w->pace_rate);
}

/*=====================================================================
 * 5. stream helpers and receive path
 *====================================================================*/
static void flush_control(anl_t *w);
static void anl_flush_internal(anl_t *w);
static int has_new_data(const anl_t *w);
static int stream_opt_check(const anl_stream_opt *opt);
static anl_stream *stream_create(anl_t *w, int sid, const anl_stream_opt *opt);
static int stream_apply_local(anl_t *w, anl_stream *st, const anl_stream_opt *opt);
static int frame_peeksize(anl_t *w, anl_stream *st);

/* data may go out only while the stream is open or draining */
static int stream_sendable(const anl_stream *st)
{
    return st->state == ANL_STREAM_OPEN || st->state == ANL_STREAM_CLOSING;
}

static void rcv_bytes_add(anl_t *w, uint32_t n)
{
    w->rcv_bytes += n;
    if (w->rcv_limit && !w->rcv_limited && w->rcv_bytes >= w->rcv_limit) w->rcv_limited = 1;
}

static void rcv_bytes_sub(anl_t *w, uint32_t n)
{
    w->rcv_bytes = w->rcv_bytes >= n ? w->rcv_bytes - n : 0;
    if (w->rcv_limited && w->rcv_bytes < w->rcv_limit / 4 * 3) {
        anl_node *n, *nx;
        anl_stream *st;
        w->rcv_limited = 0;
        FOR_EACH_STREAM(w, st, n, nx) if (stream_sendable(st)) { st->probe_tell = 1; ctl_mark(st); }
    }
}

static void backlog_sub(anl_stream *st, uint32_t n)
{
    st->backlog_bytes = st->backlog_bytes >= n ? st->backlog_bytes - n : 0;
}

static void shrink_buf(anl_stream *st)
{
    anl_seg *s = qfirst_seg(&st->snd_buf);
    st->snd_una = s ? s->sn : st->snd_nxt;
}

static void fec_free(anl_stream *st)
{
    uint32_t i;
    st->fec_n = 0;                  /* an open block would be closed later on freed buffers */
    if (st->groups) {
        for (i = 0; i < (uint32_t)st->fec_depth; i++) anl_free(st->groups[i].buf);
        anl_free(st->groups);
        st->groups = NULL;
    }
    if (st->cache) {
        for (i = 0; i < st->cache_n; i++) anl_free(st->cache[i].buf);
        anl_free(st->cache);
        st->cache = NULL;
    }
    if (st->pcache) {
        for (i = 0; i < st->pcache_n; i++) anl_free(st->pcache[i].buf);
        anl_free(st->pcache);
        st->pcache = NULL;
    }
}

static void stream_free_send_side(anl_stream *st)
{
    free_seg_list(&st->snd_queue);
    free_seg_list(&st->snd_buf);
    st->nsnd_que = st->nsnd_buf = 0;
    st->backlog_bytes = 0;
    st->fwd_pending = 0;
    st->snd_una = st->snd_nxt;
}

static void free_rcv_list(anl_t *w, anl_node *head, uint32_t *count)
{
    while (!QEMPTY(head)) {
        anl_seg *s = QENTRY(head->next, anl_seg, node);
        qdel(&s->node);
        rcv_bytes_sub(w, s->len);
        seg_free(s);
    }
    *count = 0;
}

static void discard_rcv_queue(anl_t *w, anl_stream *st)
{
    free_rcv_list(w, &st->rcv_queue, &st->nrcv_que);
}

/* RST for a sid without stream state (stateless, deduped per flush) */
static void rstq_push(anl_t *w, int sid)
{
    if (w->rst_bits[sid >> 3] & (1u << (sid & 7))) return;
    if (w->nrstq == w->rstq_cap) {
        /* grow: many streams may be closed at once and must all get their RST */
        int cap = w->rstq_cap ? w->rstq_cap * 2 : 32;
        uint16_t *q = (uint16_t *)anl_malloc(sizeof(uint16_t) * (size_t)cap);
        if (q == NULL) return;
        if (w->nrstq) memcpy(q, w->rstq, sizeof(uint16_t) * (size_t)w->nrstq);
        anl_free(w->rstq);
        w->rstq = q;
        w->rstq_cap = cap;
    }
    w->rstq[w->nrstq++] = (uint16_t)sid;
    w->rst_bits[sid >> 3] |= (uint8_t)(1u << (sid & 7));
}

/* RST-style CLOSE; rate limited per RTO while the stream still exists */
static void queue_rst(anl_t *w, int sid)
{
    anl_stream *st = sget(w, sid);
    if (st == NULL) { rstq_push(w, sid); return; }
    if (st->rst_ts != 0 && tdiff(w->current, st->rst_ts) < w->rx_rto) return;
    st->rst_ts = w->current ? w->current : 1;
    st->rst_pending = 1;
    ctl_mark(st);
}

/* The stream is over on the wire: release every buffer and the sid. The struct
 * itself lives on while the application still holds the handle (DESIGN 6.1).
 * Late segments for the sid are answered with stateless RSTs. */
static void stream_free(anl_t *w, anl_stream *st)
{
    free_rcv_list(w, &st->rcv_buf, &st->nrcv_buf);
    free_rcv_list(w, &st->rcv_queue, &st->nrcv_que);
    stream_free_send_side(st);
    fec_free(st);
    st->ack_pending = st->probe_ask = st->probe_tell = st->close_answer = 0;
    if (st->rst_pending) { rstq_push(w, st->sid); st->rst_pending = 0; }
    st->state = ANL_STREAM_CLOSED;
    if (!st->detached) {
        sdetach(w, st);
        if (st->by_peer && w->npeer_streams > 0) w->npeer_streams--;
    }
    if (st->cnode.next) qdel(&st->cnode);
    if (!st->app_released) return;
    qdel(&st->lnode);
    anl_free(st);
}

/* closing handshake complete: CLOSING -> CLOSED (DESIGN 6.1); the stream is
 * freed once the application has read what is left and the last control
 * segments have gone out (control_stream) */
static void stream_try_release(anl_t *w, anl_stream *st)
{
    if (st->state != ANL_STREAM_CLOSING || !st->peer_closed) return;
    if (!st->peer_released) {
        if (st->mode == ANL_RELIABLE && (st->nsnd_buf > 0 || st->nsnd_que > 0)) return;
        if (tdiff(st->rcv_nxt, st->peer_final_sn) < 0) return;
    }
    st->state = ANL_STREAM_CLOSED;
    stream_free_send_side(st);
    fec_free(st);
    free_rcv_list(w, &st->rcv_buf, &st->nrcv_buf);
    ctl_mark(st);
}

static void stream_local_close(anl_t *w, anl_stream *st)
{
    if (st->state != ANL_STREAM_OPEN) return;
    if (st->mode == ANL_SEMI) {
        stream_free_send_side(st);
        st->final_sn = st->snd_nxt;
    } else {
        st->final_sn = st->snd_nxt + st->nsnd_que;
    }
    st->state = ANL_STREAM_CLOSING;
    st->close_ts = w->current;
    st->close_xmit = 0;
    ctl_mark(st);
}

/* protocol violation by the peer (wrong segment type for the mode, parameter
 * mismatch): reset the stream as if the peer had sent RST, and tell it so */
static void stream_reset(anl_t *w, anl_stream *st)
{
    if (st->state == ANL_STREAM_CLOSED) return;
    queue_rst(w, st->sid);
    if (!st->peer_closed) { st->peer_closed = 1; st->peer_final_sn = st->rcv_nxt; }
    st->peer_released = 1;
    stream_local_close(w, st);
    stream_try_release(w, st);
}

/* move contiguous segments from rcv_buf to rcv_queue (ikcp) */
static void move_to_queue(anl_stream *st)
{
    int moved = 0;
    while (!QEMPTY(&st->rcv_buf)) {
        anl_seg *s = qfirst_seg(&st->rcv_buf);
        if (s->sn != st->rcv_nxt || st->nrcv_que >= st->rcv_wnd) break;
        qdel(&s->node);
        st->nrcv_buf--;
        qadd_tail(&s->node, &st->rcv_queue);
        st->nrcv_que++;
        st->rcv_nxt++;
        moved = 1;
    }
    /* the rcv_deadline clock measures how long the hole at rcv_nxt has existed:
       restart it only when rcv_nxt moves, not on every arriving segment */
    if (moved) st->blocked = 0;
}

/* drop an incomplete frame at the tail of rcv_queue (semi) */
static void drop_tail_incomplete(anl_t *w, anl_stream *st)
{
    anl_seg *last = qlast_seg(&st->rcv_queue);
    if (last == NULL || last->frg == 0) return;
    for (;;) {
        anl_seg *s = qlast_seg(&st->rcv_queue);
        int first;
        if (s == NULL) break;
        first = (s->flags & F_HAS_FRAME) != 0;
        qdel(&s->node);
        st->nrcv_que--;
        rcv_bytes_sub(w, s->len);
        seg_free(s);
        if (first) break;
    }
}

/* receiver jumps to new_una (FWD or deadline), DESIGN 7.5 */
static void skip_to(anl_t *w, anl_stream *st, uint32_t new_una)
{
    while (!QEMPTY(&st->rcv_buf)) {
        anl_seg *s = qfirst_seg(&st->rcv_buf);
        if (tdiff(s->sn, new_una) >= 0) break;
        qdel(&s->node);
        st->nrcv_buf--;
        rcv_bytes_sub(w, s->len);
        seg_free(s);
    }
    drop_tail_incomplete(w, st);
    st->rcv_nxt = new_una;
    st->frames_skipped++;
    move_to_queue(st);
    st->block_since = 0;
    st->blocked = 0;
    st->ack_pending = 1;
    ctl_mark(st);
}

/* the stream a segment without stream parameters belongs to; any segment from
 * the peer proves that it has the stream (DESIGN 6.1) */
static anl_stream *stream_for_input(anl_t *w, int sid, int *urgent)
{
    anl_stream *st = sget(w, sid);
    if (st == NULL) return NULL;            /* unknown sid: the caller decides (RST or drop) */
    if (st->state == ANL_STREAM_CLOSED) { queue_rst(w, sid); *urgent = 1; return NULL; }
    st->peer_opened = 1;
    return st;
}

static int sid_used(const anl_t *w, int sid)
{
    return (w->sid_bits[sid >> 3] >> (sid & 7)) & 1;
}

static void sid_mark_used(anl_t *w, int sid)
{
    w->sid_bits[sid >> 3] |= (uint8_t)(1u << (sid & 7));
}

/*--------------------------------------------------------------------
 * FEC decoder (DESIGN 8.4)
 *-------------------------------------------------------------------*/
static void handle_data(anl_t *w, anl_stream *st, uint32_t sn, uint32_t frg, uint8_t flags,
                        uint16_t frame16, const char *data, uint32_t len, uint32_t ts, int recovered);

static void fec_cache_add(anl_stream *st, uint32_t sn, uint32_t frg, uint8_t flags,
                          uint16_t frame16, const char *data, uint32_t len)
{
    fec_centry *e;
    if (st->cache == NULL || len + CANON_HDR_MAX > st->mss + CANON_HDR_MAX) return;
    e = &st->cache[sn % st->cache_n];
    e->valid = 1;
    e->sn = sn;
    e->len = canon_build(e->buf, frg, flags, frame16, data, len);
}

/* returns 0 = done (drop parity), 1 = keep waiting */
static int fec_try_recover(anl_t *w, anl_stream *st, uint32_t base, uint32_t k, uint32_t dep,
                           uint32_t lmax, const uint8_t *parity, uint32_t ts)
{
    uint8_t *acc = (uint8_t *)w->scratch;
    uint32_t i, nmiss = 0, missing = 0;
    const char *p, *end;
    uint32_t frg, plen, b1;
    uint16_t frame16 = 0;
    uint8_t flags;

    if (lmax > w->mtu) return 0;
    memcpy(acc, parity, lmax);
    for (i = 0; i < k; i++) {
        uint32_t sn = base + i * dep;
        fec_centry *e = &st->cache[sn % st->cache_n];
        if (e->valid && e->sn == sn) {
            uint32_t j;
            if (e->len > lmax) return 0;
            for (j = 0; j < e->len; j++) acc[j] ^= e->buf[j];
        } else if (tdiff(sn, st->rcv_nxt) < 0) {
            return 0;               /* delivered or skipped but evicted: give up */
        } else {
            nmiss++;
            missing = sn;
        }
    }
    if (nmiss == 0) return 0;
    if (nmiss > 1) return 1;
    if (tdiff(missing, st->rcv_nxt + st->rcv_wnd) >= 0) return 0;

    /* parse the recovered canonical encoding */
    p = (const char *)acc;
    end = p + lmax;
    if (p >= end) return 0;
    b1 = dec8(&p);
    flags = (uint8_t)(b1 & (F_HAS_FRAME | F_KEY));
    frg = b1 & F_FRG_MASK;
    if (frg == 31) {
        uint32_t ext;
        if (dec_varint(&p, end, &ext) < 0) return 0;
        frg = 31 + ext;
    }
    if (flags & F_HAS_FRAME) {
        if (end - p < 2) return 0;
        frame16 = dec16(&p);
    }
    if (end - p < 2) return 0;
    plen = dec16(&p);
    if ((uint32_t)(end - p) < plen) return 0;
    st->fec_recovered++;
    handle_data(w, st, missing, frg, flags, frame16, p, plen, ts, 1);
    return 0;
}

static void fec_retry_pending(anl_t *w, anl_stream *st)
{
    uint32_t i;
    if (st->pcache == NULL || st->in_retry) return;
    st->in_retry = 1;
    for (i = 0; i < st->pcache_n; i++) {
        fec_pentry *e = &st->pcache[i];
        if (!e->valid) continue;
        if (tdiff(w->current, e->ts) > w->rx_rto) { e->valid = 0; continue; }
        if (fec_try_recover(w, st, e->base, e->k, e->dep, e->lmax, e->buf, e->ts) == 0) e->valid = 0;
    }
    st->in_retry = 0;
}

static void handle_parity(anl_t *w, anl_stream *st, const char *body, uint32_t blen, uint32_t ts)
{
    const char *p = body;
    uint32_t base, k, dep, lmax, i, oldest = 0;
    uint8_t kd;
    if (!st->fec || st->cache == NULL || blen < 3) return;
    base = extend16(dec16(&p), st->rcv_nxt);
    kd = dec8(&p);
    k = ((kd >> 4) & 7u) + 1;
    dep = (kd & 15u) + 1;
    lmax = blen - 3;
    if (lmax > st->mss + CANON_HDR_MAX) return;
    if (fec_try_recover(w, st, base, k, dep, lmax, (const uint8_t *)p, ts) == 0) return;
    /* keep it until the missing members arrive or one RTO passes */
    for (i = 0; i < st->pcache_n; i++) {
        if (!st->pcache[i].valid) { oldest = i; break; }
        if (tdiff(st->pcache[i].ts, st->pcache[oldest].ts) < 0) oldest = i;
    }
    st->pcache[oldest].valid = 1;
    st->pcache[oldest].base = base;
    st->pcache[oldest].k = k;
    st->pcache[oldest].dep = dep;
    st->pcache[oldest].lmax = lmax;
    st->pcache[oldest].ts = w->current;
    memcpy(st->pcache[oldest].buf, p, lmax);
}

/*--------------------------------------------------------------------
 * DATA
 *-------------------------------------------------------------------*/
static void handle_data(anl_t *w, anl_stream *st, uint32_t sn, uint32_t frg, uint8_t flags,
                        uint16_t frame16, const char *data, uint32_t len, uint32_t ts, int recovered)
{
    anl_seg *seg, *p;
    anl_node *pos;
    int repeat = 0;

    if (st->mode == ANL_RELIABLE && (flags & F_HAS_FRAME)) { stream_reset(w, st); return; }

    if (!recovered) { st->ack_ts = ts; st->ack_fresh = 1; }
    if (tdiff(sn, st->rcv_nxt + st->rcv_wnd) >= 0) return;
    ack_schedule(st);
    if (tdiff(sn, st->rcv_nxt) < 0) return;

    /* find insert position from the tail */
    for (pos = st->rcv_buf.prev; pos != &st->rcv_buf; pos = pos->prev) {
        p = QENTRY(pos, anl_seg, node);
        if (p->sn == sn) { repeat = 1; break; }
        if (tdiff(sn, p->sn) > 0) break;
    }
    if (repeat) {
        /* the sender retransmitted it: it may not have heard of it, report again */
        p->xmit = 0;
        return;
    }

    seg = seg_new(len);
    if (seg == NULL) return;
    seg->sn = sn;
    seg->frg = frg;
    seg->flags = flags;
    if (flags & F_HAS_FRAME) {
        uint32_t ref = st->frame_seen ? st->frame_max : 0;
        seg->frame_no = extend16(frame16, ref);
        if (!st->frame_seen || tdiff(seg->frame_no, st->frame_max) > 0) st->frame_max = seg->frame_no;
        st->frame_seen = 1;
    }
    memcpy(seg->data, data, len);
    qadd_after(&seg->node, pos);
    st->nrcv_buf++;
    rcv_bytes_add(w, len);

    if (st->fec) {
        fec_cache_add(st, sn, frg, flags, frame16, data, len);
    }
    move_to_queue(st);
    if (st->app_released) discard_rcv_queue(w, st);        /* nobody will read it */
    if (st->fec && !recovered) fec_retry_pending(w, st);
}

/*--------------------------------------------------------------------
 * ACK
 *-------------------------------------------------------------------*/
static int parse_una(anl_stream *st, uint32_t una)
{
    int n = 0;
    while (!QEMPTY(&st->snd_buf)) {
        anl_seg *s = qfirst_seg(&st->snd_buf);
        if (tdiff(una, s->sn) <= 0) break;
        qdel(&s->node);
        st->nsnd_buf--;
        backlog_sub(st, s->len);
        seg_free(s);
        n++;
    }
    return n;
}

/* RACK reordering window (DESIGN 6.3): min_rtt / 16 - queueing delay must not
 * widen it - times reo_mult, which grows after spurious RACK retransmissions;
 * at most srtt. Semi-reliable streams always use the narrowest window: a late
 * frame is as bad as a lost one, a spurious retransmission only costs bytes. */
static uint32_t reo_wnd(const anl_t *w, const anl_stream *st)
{
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    uint32_t base = w->min_rtt > 0 ? w->min_rtt : srtt;
    uint32_t mult = st->mode == ANL_SEMI ? 1u : (uint32_t)w->reo_mult;
    uint32_t r = base * mult / REO_DIV;
    return umax32(umin32(r, srtt), 1);
}

/* Is there evidence against seg: a datagram sent after it has reached the
 * peer? Any stream counts - all share one datagram sequence, and the peer
 * acknowledges every stream in the same flush - so a low-rate stream is not
 * left to RTO while a busy one keeps delivering. Within the stream, segments
 * sent in the same millisecond are ordered by sn. */
static int rack_candidate(const anl_t *w, const anl_stream *st, const anl_seg *seg)
{
    if (seg->xmit == 0 || seg->lost) return 0;
    if (w->rack_valid && tdiff(seg->ts_sent, w->rack_ts) < 0) return 1;
    return st->rack_valid && tdiff(seg->ts_sent, st->rack_ts) <= 0 && tdiff(seg->sn, st->rack_hi) < 0;
}

/* RACK loss detection (RFC 8985): a segment sent before the newest delivered
 * datagram is lost once it has been outstanding for that one's RTT plus the
 * reordering window. Runs on every ACK and on every flush (the timer). */
static int rack_detect(anl_t *w, anl_stream *st)
{
    anl_node *pos;
    uint32_t wait;
    int marked = 0;
    if (!w->rack_valid || w->resend <= 0) return 0;
    wait = w->rack_rtt + reo_wnd(w, st);
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        if (rack_candidate(w, st, s) && tdiff(w->current, s->ts_sent + wait) >= 0) { s->lost = 1; marked++; }
    }
    if (marked && w->reo_mult > 1) {
        /* shrink by one step per round trip once REO_DECAY round trips have
           passed without a spurious retransmission (RFC 8985 reo_wnd_persist) */
        uint32_t rtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
        if (tdiff(w->current, w->reo_spur_ts) >= (int32_t)(REO_DECAY * rtt) && tdiff(w->current, w->reo_inc_ts) >= (int32_t)rtt) {
            w->reo_mult--;
            w->reo_inc_ts = w->current ? w->current : 1;
        }
    }
    return marked;
}

static void cwnd_grow(anl_t *w, int nacked)
{
    uint32_t cap = 0;
    int i;
    anl_node *n, *nx;
    anl_stream *st;
    if (w->nc || nacked <= 0) return;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st)) {
            cap += st->rmt_wnd;
            if (cap > ANL_MAX_WND) break;
        }
    }
    if (cap > ANL_MAX_WND) cap = ANL_MAX_WND;
    if (cap == 0) return;
    for (i = 0; i < nacked && w->cwnd < cap; i++) {
        uint32_t mss = w->mss;
        if (w->cwnd < w->ssthresh) {
            w->cwnd++;
            w->incr += mss;
        } else {
            if (w->incr < mss) w->incr = mss;
            w->incr += (mss * mss) / w->incr + (mss / 16);
            if ((w->cwnd + 1) * mss <= w->incr) w->cwnd = (w->incr + mss - 1) / mss;
        }
    }
    if (w->cwnd > cap) { w->cwnd = cap; w->incr = cap * w->mss; }
}

static void update_ack(anl_t *w, int32_t rtt)
{
    int32_t rto;
    if (w->min_rtt == 0 || (uint32_t)rtt <= w->min_rtt || tdiff(w->current, w->min_rtt_ts) > MIN_RTT_WIN) {
        w->min_rtt = umax32((uint32_t)rtt, 1);
        w->min_rtt_ts = w->current;
    }
    if (w->rx_srtt == 0) {
        w->rx_srtt = rtt;
        w->rx_rttval = rtt / 2;
    } else {
        int32_t delta = rtt - w->rx_srtt;
        if (delta < 0) delta = -delta;
        w->rx_rttval = (3 * w->rx_rttval + delta) / 4;
        w->rx_srtt = (7 * w->rx_srtt + rtt) / 8;
        if (w->rx_srtt < 1) w->rx_srtt = 1;
    }
    rto = w->rx_srtt + (w->interval > 4 * w->rx_rttval ? w->interval : 4 * w->rx_rttval);
    w->rx_rto = (int32_t)ubound32((uint32_t)w->rx_minrto, (uint32_t)rto, RTO_MAX);
}

/* una + SACK ranges (DESIGN 5.3), then RACK loss detection (DESIGN 6.3).
 * rng holds n (gap, len) pairs. Returns the number of segments acknowledged;
 * *lost counts the segments newly declared lost. */
static int handle_ack(anl_t *w, anl_stream *st, uint8_t b1, uint16_t una16, uint16_t wnd,
                      uint32_t ts_echo, const uint32_t *rng, uint32_t n, int *lost)
{
    uint32_t una, i, hi;
    anl_node *pos;
    int acked = 0, spurious = 0;
    st->rmt_wnd = wnd;
    if (b1 & ACK_F_WASK) { st->probe_tell = 1; ack_schedule(st); }
    una = extend16(una16, st->snd_una);
    if (tdiff(una, st->snd_nxt) > 0) una = st->snd_una;         /* garbage: ignore */

    /* una, then the ranges (ascending): one walk over snd_buf */
    hi = una;
    pos = st->snd_buf.next;
    for (i = 0; i <= n; i++) {
        uint32_t start, end;
        if (i == 0) { start = st->snd_una - 0x8000u; end = una; }   /* everything below una */
        else {
            start = hi + rng[2 * i - 2];
            end = start + rng[2 * i - 1];
            if (tdiff(end, st->snd_nxt) > 0) break;               /* beyond what was sent: garbage */
            hi = end;
        }
        while (pos != &st->snd_buf) {
            anl_seg *s = QENTRY(pos, anl_seg, node);
            anl_node *next = pos->next;
            if (tdiff(s->sn, end) >= 0) break;
            if (tdiff(s->sn, start) >= 0) {
                /* Eifel (RFC 3522): acknowledged by a peer whose newest datagram
                   was sent before our RACK retransmission - the original made it,
                   the retransmission was spurious (only reordered) */
                if (s->rack_rtx && (b1 & ACK_F_FRESH) && tdiff(ts_echo, s->ts_sent) < 0) spurious = 1;
                qdel(&s->node);
                st->nsnd_buf--;
                backlog_sub(st, s->len);
                seg_free(s);
                acked++;
            }
            pos = next;
        }
    }
    shrink_buf(st);

    if (spurious) {
        /* tolerate more reordering: double reo_mult (1 2 4 .. 16), at most once
           per round trip - one reordering episode causes many spurious ones */
        w->reo_spur_ts = w->current;
        if (w->reo_mult < REO_MULT_MAX &&
            (w->reo_inc_ts == 0 || tdiff(w->current, w->reo_inc_ts) >= (w->rx_srtt > 0 ? w->rx_srtt : RTO_DEF))) {
            w->reo_mult = w->reo_mult * 2 > REO_MULT_MAX ? REO_MULT_MAX : w->reo_mult * 2;
            w->reo_inc_ts = w->current ? w->current : 1;
        }
    }
    /* RACK: remember the newest datagram the peer has, then look for losses */
    if (b1 & ACK_F_FRESH) {
        if (!w->rack_valid || tdiff(ts_echo, w->rack_ts) >= 0) {
            int32_t rtt = tdiff(w->current, ts_echo);
            w->rack_ts = ts_echo;
            w->rack_rtt = rtt > 0 ? (uint32_t)rtt : 0;
            w->rack_valid = 1;
        }
        if (!st->rack_valid || tdiff(ts_echo, st->rack_ts) >= 0) st->rack_ts = ts_echo;
        if (!st->rack_valid || tdiff(hi, st->rack_hi) > 0) st->rack_hi = hi;
        st->rack_valid = 1;
        *lost += rack_detect(w, st);
    }

    if (st->fwd_pending) {
        if (tdiff(una, st->fwd_una) >= 0) st->fwd_pending = 0;
        else if (tdiff(una, st->fwd_peer_una) > 0) { st->fwd_xmit = 0; st->fwd_rto = 0; }  /* peer is making progress */
    }
    st->fwd_peer_una = una;
    return acked;
}

/*--------------------------------------------------------------------
 * FWD / CTRL
 *-------------------------------------------------------------------*/
static void handle_fwd(anl_t *w, anl_stream *st, uint16_t una16)
{
    uint32_t new_una;
    if (st->mode != ANL_SEMI) { stream_reset(w, st); return; }
    new_una = extend16(una16, st->rcv_nxt);
    st->ack_pending = 1;
    ctl_mark(st);
    if (tdiff(new_una, st->rcv_nxt) <= 0) return;
    skip_to(w, st, new_una);
}

/* The peer opened a sid unknown here: auto-accept (DESIGN 6.1). The stream is
 * created first so that the callback gets its handle; the local options the
 * callback returns are applied afterwards. mode / stream / tag / rcv_wnd are
 * the opener's and cannot be changed. */
static anl_stream *accept_stream(anl_t *w, int sid, const open_info *oi)
{
    anl_stream_opt opt;
    anl_stream *st;
    if (sid == ANL_SID_DEFAULT || w->npeer_streams >= w->max_peer_streams) return NULL;
    anl_stream_opt_default(&opt, oi->mode);
    opt.stream = oi->stream;
    opt.tag = oi->tag;
    opt.rcv_wnd = (int)ubound32(1, oi->rcv_wnd, ANL_MAX_WND);
    st = stream_create(w, sid, &opt);
    if (st == NULL) return NULL;
    st->by_peer = 1;
    st->peer_opened = 1;
    w->npeer_streams++;
    if (w->accept_cb) {
        if (w->accept_cb(w, st, &opt, w->user) < 0) goto refuse;
        opt.mode = oi->mode;
        opt.stream = oi->stream;
        opt.tag = oi->tag;
        opt.rcv_wnd = (int)st->rcv_wnd;
        if (stream_opt_check(&opt) != 0 || stream_apply_local(w, st, &opt) != 0) goto refuse;
    }
    return st;
refuse:
    st->app_released = 1;
    stream_free(w, st);
    return NULL;
}

/* the stream a DATA / CLOSE carrying the stream parameters belongs to; created
 * on first sight. A sid is used once per connection: a late first segment of
 * a stream that is already gone gets RST instead of a new stream. */
static anl_stream *stream_for_open(anl_t *w, int sid, const open_info *oi, int *urgent)
{
    anl_stream *st = sget(w, sid);
    if (st == NULL) {
        if (w->state < 0 || sid_used(w, sid)) { queue_rst(w, sid); *urgent = 1; return NULL; }
        sid_mark_used(w, sid);
        if ((st = accept_stream(w, sid, oi)) == NULL) { queue_rst(w, sid); *urgent = 1; return NULL; }
        return st;
    }
    if (st->state == ANL_STREAM_CLOSED) { queue_rst(w, sid); *urgent = 1; return NULL; }
    st->peer_opened = 1;
    if (oi->mode != st->mode || (oi->mode == ANL_RELIABLE && oi->stream != st->stream)) {
        stream_reset(w, st);
        return NULL;
    }
    return st;
}

static void handle_close(anl_t *w, int sid, const char *body, uint32_t blen, int *urgent)
{
    const char *p = body;
    uint16_t final16, una16;
    uint8_t flags;
    int rst, has_open;
    open_info oi;
    anl_stream *st;
    if (blen < 5) return;
    final16 = dec16(&p);
    flags = dec8(&p);
    una16 = dec16(&p);
    rst = (flags & CLOSE_F_RST) != 0;
    has_open = (flags & CLOSE_F_OPEN) != 0;
    if (has_open) {
        if (blen < 5 + OPEN_BODY) return;
        dec_open_body(&p, &oi);
    }
    if (has_open && !rst) {
        st = stream_for_open(w, sid, &oi, urgent);
    } else {
        st = sget(w, sid);
        if (st == NULL || st->state == ANL_STREAM_CLOSED) {
            /* peer closes a stream we do not have (any more) */
            if (!rst) { queue_rst(w, sid); *urgent = 1; }
            return;
        }
        if (!rst) st->peer_opened = 1;
    }
    if (st == NULL) return;
    if (!rst) {
        /* the peer's una: acknowledges our data like an ACK */
        uint32_t una = extend16(una16, st->snd_una);
        if (tdiff(una, st->snd_una) > 0 && tdiff(una, st->snd_nxt) <= 0) {
            parse_una(st, una);
            shrink_buf(st);
            if (st->fwd_pending && tdiff(una, st->fwd_una) >= 0) st->fwd_pending = 0;
        }
    }
    if (!st->peer_closed) {
        st->peer_closed = 1;
        st->peer_final_sn = extend16(final16, st->rcv_nxt);
    }
    if (rst) st->peer_released = 1;
    else st->close_answer = 1;              /* answer every CLOSE: our answer may have been lost */
    stream_local_close(w, st);
    ctl_mark(st);
    *urgent = 1;
    stream_try_release(w, st);
}

/*--------------------------------------------------------------------
 * datagram parsing (DESIGN 3.3 step 5 onwards)
 *-------------------------------------------------------------------*/
int anl_input_plain(anl_t *w, const char *plain, long size)
{
    const char *p, *end;
    uint32_t conv, ts;
    uint8_t flg;
    int had_data = 0, urgent = 0, have_echo = 0, acked = 0, lost = 0;
    uint32_t max_echo = 0;
    uint32_t *snbuf = (uint32_t *)w->scratch;
    uint32_t snbuf_cap = (w->mtu * 2) / sizeof(uint32_t);

    if (w == NULL || plain == NULL) return ANL_EINVAL;
    if (size < ANL_HDR_SIZE || (uint32_t)size > w->mtu) return ANL_EFORMAT;

    p = plain;
    end = plain + size;
    conv = dec32(&p);
    flg = dec8(&p);
    ts = dec32(&p);
    if ((flg & FLG_VER_MASK) != (ANL_VERSION << 6) || (flg & FLG_RSV_MASK)) return ANL_EFORMAT;
    if (conv != w->conv) return ANL_ECONV;
    if (w->peer_ts_valid && tdiff(ts, w->peer_ts) < -(int32_t)w->ts_window) {
        w->rx_stale++;
        return ANL_ESTALE;
    }
    if (!w->peer_ts_valid || tdiff(ts, w->peer_ts) > 0) w->peer_ts = ts;
    w->peer_ts_valid = 1;
    w->last_rx = w->current;
    w->rx_dg++;

    if (flg & FLG_PAD) {
        uint32_t n = (uint8_t)end[-1];
        if (n == 0 || n > (uint32_t)(end - p)) return ANL_EFORMAT;
        end -= n;
    }

    while (p < end) {
        uint8_t b0;
        int type, sid;
        anl_stream *st;
        if (end - p < SID_BYTES) return ANL_EFORMAT;
        b0 = dec8(&p);
        if (b0 & SID_RSV) return ANL_EFORMAT;
        type = b0 >> 6;
        sid = ((b0 & SID_HI_MASK) << 8) | dec8(&p);

        if (type == SEG_DATA) {
            uint8_t b1, flags;
            uint32_t frg, len;
            uint16_t sn16, frame16 = 0;
            open_info oi;
            if (end - p < 3) return ANL_EFORMAT;
            b1 = dec8(&p);
            flags = (uint8_t)(b1 & (F_HAS_FRAME | F_KEY));
            frg = b1 & F_FRG_MASK;
            if (frg == 31) {
                uint32_t ext;
                if (dec_varint(&p, end, &ext) < 0) return ANL_EFORMAT;
                frg = 31 + ext;
            }
            if (end - p < 2) return ANL_EFORMAT;
            sn16 = dec16(&p);
            if (flags & F_HAS_FRAME) {
                if (end - p < 2) return ANL_EFORMAT;
                frame16 = dec16(&p);
            }
            if (b1 & F_OPEN) {
                if (end - p < OPEN_BODY) return ANL_EFORMAT;
                dec_open_body(&p, &oi);
            }
            if (dec_varint(&p, end, &len) < 0) return ANL_EFORMAT;
            if ((uint32_t)(end - p) < len) return ANL_EFORMAT;
            had_data = 1;
            if (b1 & F_OPEN) {
                urgent = 1;                 /* let the opener learn quickly that we have the stream */
                st = stream_for_open(w, sid, &oi, &urgent);
            } else {
                st = stream_for_input(w, sid, &urgent);
                if (st == NULL && sget(w, sid) == NULL) {
                    /* data for a stream that no longer exists here: the sender
                       still waits for an ACK, tell it to give up */
                    queue_rst(w, sid);
                    urgent = 1;
                }
            }
            if (st) {
                handle_data(w, st, extend16(sn16, st->rcv_nxt), frg, flags, frame16, p, len, ts, 0);
                stream_try_release(w, st);
            }
            p += len;
        } else if (type == SEG_ACK) {
            uint8_t b1;
            uint16_t una16, wnd;
            uint32_t ts_echo, n, i, span = 0;
            if (end - p < ACK_HDR - SID_BYTES) return ANL_EFORMAT;
            b1 = dec8(&p);
            una16 = dec16(&p);
            wnd = dec16(&p);
            ts_echo = dec32(&p);
            if (dec_varint(&p, end, &n) < 0) return ANL_EFORMAT;
            if (2 * n > snbuf_cap) return ANL_EFORMAT;
            for (i = 0; i < n; i++) {
                uint32_t gap, len;
                if (dec_varint(&p, end, &gap) < 0 || dec_varint(&p, end, &len) < 0) return ANL_EFORMAT;
                span += gap + len;
                if (gap == 0 || len == 0 || span > ANL_MAX_WND) return ANL_EFORMAT;
                snbuf[2 * i] = gap;
                snbuf[2 * i + 1] = len;
            }
            if (b1 & ACK_F_WASK) urgent = 1;
            st = stream_for_input(w, sid, &urgent);
            if (st) {
                acked += handle_ack(w, st, b1, una16, wnd, ts_echo, snbuf, n, &lost);
                if ((b1 & ACK_F_FRESH) && (!have_echo || tdiff(ts_echo, max_echo) > 0)) { max_echo = ts_echo; have_echo = 1; }
                stream_try_release(w, st);
            }
        } else if (type == SEG_FWD) {
            uint16_t una16;
            if (end - p < 2) return ANL_EFORMAT;
            una16 = dec16(&p);
            urgent = 1;
            st = stream_for_input(w, sid, &urgent);
            if (st) handle_fwd(w, st, una16);
        } else {
            uint8_t sub;
            uint32_t blen;
            if (end - p < 2) return ANL_EFORMAT;
            sub = dec8(&p);
            if (dec_varint(&p, end, &blen) < 0) return ANL_EFORMAT;
            if ((uint32_t)(end - p) < blen) return ANL_EFORMAT;
            if (sub == CTRL_PARITY) {
                st = stream_for_input(w, sid, &urgent);
                if (st) handle_parity(w, st, p, blen, ts);
            } else if (sub == CTRL_OPEN && blen >= OPEN_BODY) {
                open_info oi;
                const char *q = p;
                dec_open_body(&q, &oi);
                urgent = 1;
                st = stream_for_open(w, sid, &oi, &urgent);
                if (st) { st->probe_tell = 1; ctl_mark(st); }   /* a window ACK tells the opener we have it */
            } else if (sub == CTRL_CLOSE) {
                handle_close(w, sid, p, blen, &urgent);
            }
            p += blen;                      /* unknown subtypes are skipped */
        }
    }

    if (have_echo && w->updated) {
        int32_t rtt = tdiff(w->current, max_echo);
        if (rtt >= 0 && rtt <= (int32_t)RTO_MAX) update_ack(w, rtt);   /* ignore garbage echoes */
    }
    cwnd_grow(w, acked);

    /* ACK clocking (DESIGN 6.4): the window just opened or RACK found a loss -
       send now instead of at the next interval. Only without cwnd (nc = 1):
       the ikcp-style cwnd has no delay signal, and sending on every ACK keeps
       the bottleneck queue full instead of leaving the gaps of the interval */
    if (w->nc && w->updated && w->state >= 0 && (lost > 0 || (acked > 0 && has_new_data(w)))) anl_flush_internal(w);

    if (w->ack_nodelay && w->updated) {
        if (had_data) w->rx_data_since_ack++;
        if (w->rx_data_since_ack >= 2 || urgent) flush_control(w);
    }
    return ANL_OK;
}

int anl_peek_conv(const anl_keys *keys, int role, const char *data, long size,
                  uint32_t *conv, char *plain)
{
    int r;
    const char *p;
    if (keys == NULL || data == NULL || plain == NULL || (role != 0 && role != 1)) return ANL_EINVAL;
    if (size < ANL_OVERHEAD || size > 65535) return ANL_EFORMAT;
    r = siv_open(keys, 1 - role, (const uint8_t *)data, (size_t)size, (uint8_t *)plain);
    if (r < 0) return r;
    p = plain;
    if (conv) *conv = dec32(&p);
    return r;
}

int anl_input(anl_t *w, const char *data, long size)
{
    int r;
    if (w == NULL || data == NULL) return ANL_EINVAL;
    if (size < ANL_OVERHEAD || (uint32_t)size > w->mtu) return ANL_EFORMAT;
    r = siv_open(&w->keys, 1 - w->role, (const uint8_t *)data, (size_t)size, (uint8_t *)w->rxbuf);
    if (r < 0) {
        if (r == ANL_EAUTH) w->rx_auth_fail++;
        return r;
    }
    return anl_input_plain(w, w->rxbuf, r);
}

/*=====================================================================
 * 6. send path
 *====================================================================*/

/*--------------------------------------------------------------------
 * FEC encoder (DESIGN 8.2 / 8.3)
 *-------------------------------------------------------------------*/
static void fec_close_block(anl_t *w, anl_stream *st)
{
    uint32_t j;
    if (st->fec_n == 0 || st->groups == NULL) return;
    for (j = 0; j < (uint32_t)st->fec_depth; j++) {
        fec_group *g = &st->groups[j];
        uint8_t *body;
        char *p;
        if (g->k == 0) continue;
        body = (uint8_t *)w->scratch + w->mtu;      /* second half of scratch */
        p = (char *)body;
        p = enc16(p, (uint16_t)(st->fec_base + j));
        p = enc8(p, (uint8_t)(((g->k - 1) << 4) | (uint32_t)(st->fec_depth - 1)));
        memcpy(p, g->buf, g->lmax);
        write_ctrl_seg(w, st->sid, CTRL_PARITY, body, 3 + g->lmax);
        w->flush_budget--;
        g->k = 0;
        g->lmax = 0;
    }
    st->fec_n = 0;
}

static void fec_add(anl_t *w, anl_stream *st, const anl_seg *seg)
{
    fec_group *g;
    uint8_t *canon = (uint8_t *)w->scratch;
    uint32_t clen, i;
    if (st->fec_n > 0 && seg->sn != st->fec_base + st->fec_n) fec_close_block(w, st);
    if (st->fec_n == 0) {
        st->fec_base = seg->sn;
        st->fec_first_ts = w->current;
    }
    g = &st->groups[st->fec_n % (uint32_t)st->fec_depth];
    clen = canon_build(canon, seg->frg, seg->flags, (uint16_t)seg->frame_no, seg->data, seg->len);
    if (g->k == 0) memset(g->buf, 0, st->mss + CANON_HDR_MAX);
    for (i = 0; i < clen; i++) g->buf[i] ^= canon[i];
    if (clen > g->lmax) g->lmax = clen;
    g->k++;
    st->fec_n++;
    if (st->fec_n >= 8u * (uint32_t)st->fec_depth) fec_close_block(w, st);
}

/* transmit a segment (first time or retransmission) */
static void send_seg(anl_t *w, anl_stream *st, anl_seg *seg)
{
    int first = seg->xmit == 0;
    write_data_seg(w, st, seg);
    seg->xmit++;
    seg->ts_sent = w->current;
    if (first) {
        if (st->fec) fec_add(w, st, seg);
    } else {
        st->retrans++;
        w->retrans_total++;
    }
}

/*--------------------------------------------------------------------
 * semi-reliable sender-side dropping (DESIGN 7.3)
 *-------------------------------------------------------------------*/
#define PURGED_ANY  1
#define PURGED_SENT 2   /* some segment already had a sn: FWD needed */

/* remove every segment of frame_no from snd_buf and snd_queue */
static int purge_frame(anl_stream *st, uint32_t frame_no)
{
    anl_node *pos, *next;
    int sent = 0, in_buf = 0, first = 1;
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        next = pos->next;
        if (s->frame_no != frame_no) { if (in_buf) break; else continue; }
        in_buf = sent = 1;
        qdel(&s->node);
        st->nsnd_buf--;
        backlog_sub(st, s->len);
        seg_free(s);
    }
    for (pos = st->snd_queue.next; pos != &st->snd_queue; pos = next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        next = pos->next;
        if (s->frame_no != frame_no) break;
        if (first && !(s->flags & F_HAS_FRAME)) sent = 1;           /* head already sent (maybe acked) */
        first = 0;
        in_buf = 1;
        qdel(&s->node);
        st->nsnd_que--;
        backlog_sub(st, s->len);
        seg_free(s);
    }
    return (in_buf ? PURGED_ANY : 0) | (sent ? PURGED_SENT : 0);
}

/* oldest frame newer than frame_no still waiting in snd_buf or snd_queue */
static anl_seg *next_frame_after(anl_stream *st, uint32_t frame_no)
{
    anl_node *pos;
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        if (tdiff(s->frame_no, frame_no) > 0) return s;
    }
    for (pos = st->snd_queue.next; pos != &st->snd_queue; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        if (tdiff(s->frame_no, frame_no) > 0) return s;
    }
    return NULL;
}

/* Drop a whole frame (DESIGN 7.3). With drop_until_key every later non-key
 * frame is useless too: those still queued AND those already in flight are
 * dropped up to the next key frame (DESIGN 7.6). One FWD then skips to the
 * first surviving frame. */
static void drop_frame(anl_t *w, anl_stream *st, uint32_t frame_no)
{
    int r = purge_frame(st, frame_no), sent = r & PURGED_SENT;
    if (!(r & PURGED_ANY)) return;          /* already dropped together with an older frame */
    st->frames_dropped++;
    if (st->drop_until_key) {
        anl_seg *s;
        uint32_t last = frame_no;
        st->dropping = 1;
        while ((s = next_frame_after(st, last)) != NULL) {
            if (s->fkey) { st->dropping = 0; break; }
            last = s->frame_no;
            sent |= purge_frame(st, last) & PURGED_SENT;
            st->frames_dropped++;
        }
    }
    if (sent) {
        anl_seg *h = qfirst_seg(&st->snd_buf), *q = qfirst_seg(&st->snd_queue);
        uint32_t new_una;
        if (h) new_una = h->first_sn;
        else if (q && !(q->flags & F_HAS_FRAME)) new_una = st->cur_first_sn;   /* current frame survives */
        else new_una = st->snd_nxt;
        if (!st->fwd_pending || tdiff(new_una, st->fwd_una) > 0) st->fwd_una = new_una;
        if (!st->fwd_pending) { st->fwd_ts = w->current; st->fwd_xmit = 0; st->fwd_rto = 0; }
        st->fwd_pending = 1;
        shrink_buf(st);
    }
}

/* abandon frame_no and every older frame still in snd_buf, oldest first, so
 * that abandoned sn always form a prefix (FWD skips everything below new_una) */
static void abandon_through(anl_t *w, anl_stream *st, uint32_t frame_no)
{
    anl_seg *h;
    while ((h = qfirst_seg(&st->snd_buf)) != NULL && tdiff(h->frame_no, frame_no) < 0)
        drop_frame(w, st, h->frame_no);
    drop_frame(w, st, frame_no);
}

static int semi_expired(const anl_t *w, const anl_stream *st, const anl_seg *seg)
{
    return st->mode == ANL_SEMI && st->max_age_ms && tdiff(w->current, seg->ts_enq) > st->max_age_ms;
}

/* DESIGN 7.3: max_bytes drops the oldest frame wherever it is; max_age only
 * drops frames that are not completely sent. A completely sent frame past
 * max_age is abandoned by the flush loop when it would need a retransmission. */
static void semi_drop_check(anl_t *w, anl_stream *st)
{
    if (st->mode != ANL_SEMI) return;
    if (st->max_age_ms == 0 && st->max_bytes == 0) return;
    for (;;) {
        anl_seg *head;
        if (st->max_bytes && st->backlog_bytes > (uint32_t)st->max_bytes) {
            head = qfirst_seg(&st->snd_buf);
            if (head == NULL) head = qfirst_seg(&st->snd_queue);
            if (head == NULL) break;
            drop_frame(w, st, head->frame_no);
            continue;
        }
        head = qfirst_seg(&st->snd_queue);
        if (head == NULL || !semi_expired(w, st, head)) break;
        if (head->flags & F_HAS_FRAME) drop_frame(w, st, head->frame_no);    /* never sent: no FWD */
        else abandon_through(w, st, head->frame_no);                         /* head already sent */
    }
}

/* receiver-side deadline (DESIGN 7.5) */
static void semi_deadline_check(anl_t *w, anl_stream *st)
{
    anl_seg *head;
    if (st->mode != ANL_SEMI || st->rcv_deadline_ms == 0) return;
    head = qfirst_seg(&st->rcv_buf);
    if (head == NULL || tdiff(head->sn, st->rcv_nxt) <= 0) { st->blocked = 0; return; }
    if (!st->blocked) { st->blocked = 1; st->block_since = w->current; return; }
    if (tdiff(w->current, st->block_since) < st->rcv_deadline_ms) return;
    {
        anl_node *pos;
        for (pos = st->rcv_buf.next; pos != &st->rcv_buf; pos = pos->next) {
            anl_seg *s = QENTRY(pos, anl_seg, node);
            if (s->flags & F_HAS_FRAME) {
                skip_to(w, st, s->sn);
                return;
            }
        }
    }
}

/*--------------------------------------------------------------------
 * flush
 *-------------------------------------------------------------------*/
static int has_new_data(const anl_t *w)
{
    anl_node *n, *nx;
    anl_stream *st;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st) && st->nsnd_que > 0 &&
            tdiff(st->snd_nxt, st->snd_una + umin32(st->snd_wnd, st->rmt_wnd)) < 0)
            return 1;
    }
    return 0;
}

/* retransmission interval of CLOSE / FWD: starts at RTO and backs off like a
 * data segment, so that dead_link means the same time span for all of them
 * (a fixed RTO period used up dead_link in ~2 s of outage) */
static uint32_t ctrl_backoff(const anl_t *w, uint32_t rto)
{
    if (rto == 0) return (uint32_t)w->rx_rto;
    if (w->nodelay == 0) rto += umax32(rto, (uint32_t)w->rx_rto);
    else rto += (w->nodelay < 2 ? rto : (uint32_t)w->rx_rto) / 2;
    return umin32(rto, RTO_MAX);
}

/* DESIGN 6.4 steps 1-2 for one stream: ACK, window probe, RST, CLOSE, FWD.
 * May free st (CLOSED and drained) - the caller must not touch it afterwards. */
static void control_stream(anl_t *w, anl_stream *st)
{
    uint32_t current = w->current;
    if (st->cnode.next) qdel(&st->cnode);
    if (st->detached) return;               /* sid gone: late segments get stateless RSTs */

    if (st->rst_pending) {
        write_close_seg(w, st->sid, st->final_sn, 1, NULL);
        st->rst_pending = 0;
        st->close_answer = 0;
    }
    if (st->state == ANL_STREAM_CLOSED) {
        /* answer the peer's CLOSE and acknowledge its last segments, then free
           the stream once the application has read what is left */
        if (st->close_answer) { write_close_seg(w, st->sid, st->final_sn, 0, st); st->close_answer = 0; }
        if (st->ack_pending) write_ack_segs(w, st);
        if (QEMPTY(&st->rcv_queue)) stream_free(w, st);
        return;
    }

    semi_deadline_check(w, st);
    if (st->mode == ANL_SEMI && st->rcv_drop_until_key) (void)frame_peeksize(w, st);

    /* window probing (ikcp) */
    if (st->rmt_wnd == 0 && (st->nsnd_que + st->nsnd_buf) > 0) {
        if (st->probe_wait == 0) {
            st->probe_wait = PROBE_INIT;
            st->ts_probe = current + st->probe_wait;
        } else if (tdiff(current, st->ts_probe) >= 0) {
            if (st->probe_wait < PROBE_INIT) st->probe_wait = PROBE_INIT;
            st->probe_wait += st->probe_wait / 2;
            if (st->probe_wait > PROBE_LIMIT) st->probe_wait = PROBE_LIMIT;
            st->ts_probe = current + st->probe_wait;
            st->probe_ask = 1;
        }
    } else {
        st->probe_wait = 0;
        st->ts_probe = 0;
    }
    if (st->ack_pending || st->probe_ask || st->probe_tell) write_ack_segs(w, st);

    /* OPEN announcement with exponential backoff until anything is heard from
       the peer; not counted towards dead_link (the peer may simply be idle) */
    if (!st->peer_opened && tdiff(current, st->open_ts) >= 0) {
        write_open_seg(w, st);
        st->open_rto = st->open_rto == 0 ? (uint32_t)w->rx_rto : umin32(st->open_rto * 2, OPEN_RTO_MAX);
        st->open_ts = current + st->open_rto;
    }

    /* STREAM_CLOSE: RTO period with backoff, counts towards dead_link. Carries
       the stream parameters while the peer has not been heard, so that a CLOSE
       overtaking the data still creates the stream there (DESIGN 6.1). */
    if (st->state == ANL_STREAM_CLOSING && !st->peer_closed && tdiff(current, st->close_ts) >= 0) {
        write_close_seg(w, st->sid, st->final_sn, 0, st);
        st->close_rto = ctrl_backoff(w, st->close_rto);
        st->close_ts = current + st->close_rto;
        st->close_xmit++;
        if (st->close_xmit >= w->dead_link) w->state = -1;
    } else if (st->state == ANL_STREAM_CLOSING && st->peer_closed && (st->close_xmit == 0 || st->close_answer)) {
        /* peer closed first: answer each of its CLOSEs (paced by the peer's RTO) */
        write_close_seg(w, st->sid, st->final_sn, 0, st);
        st->close_xmit = 1;
        st->close_answer = 0;
    }

    /* FWD */
    if (st->fwd_pending && tdiff(current, st->fwd_ts) >= 0) {
        write_fwd_seg(w, st, st->fwd_una);
        st->fwd_rto = ctrl_backoff(w, st->fwd_rto);
        st->fwd_ts = current + st->fwd_rto;
        st->fwd_xmit++;
        if (st->fwd_xmit > w->dead_link) w->state = -1;
    }
}

static void flush_rstq(anl_t *w)
{
    int i;
    for (i = 0; i < w->nrstq; i++) {
        write_close_seg(w, w->rstq[i], 0, 1, NULL);
        w->rst_bits[w->rstq[i] >> 3] &= (uint8_t)~(1u << (w->rstq[i] & 7));
    }
    w->nrstq = 0;
}

/* steps 1-2 of DESIGN 6.4 over every stream (periodic flush: timers) */
static void flush_control_segs(anl_t *w)
{
    anl_node *n, *nx;
    anl_stream *st;
    FOR_EACH_STREAM(w, st, n, nx) control_stream(w, st);
    flush_rstq(w);
}

/* Immediate control flush (ack_nodelay, close): only the streams that asked
 * for it (ctl_list), so that its cost does not grow with the number of
 * streams. Timers (CLOSE / FWD retransmission, probes) are driven by the
 * periodic full flush. */
static void flush_control(anl_t *w)
{
    if (!w->updated || w->state < 0) return;
    dg_begin(w);
    while (!QEMPTY(&w->ctl_list)) control_stream(w, QENTRY(w->ctl_list.next, anl_stream, cnode));
    flush_rstq(w);
    dg_seal(w);
    w->rx_data_since_ack = 0;
}

static void move_and_send(anl_t *w, anl_stream *st)
{
    anl_seg *seg = qfirst_seg(&st->snd_queue);
    qdel(&seg->node);
    st->nsnd_que--;
    qadd_tail(&seg->node, &st->snd_buf);
    st->nsnd_buf++;
    seg->sn = st->snd_nxt++;
    if (seg->flags & F_HAS_FRAME) st->cur_first_sn = seg->sn;
    seg->first_sn = st->cur_first_sn;
    seg->rto = (uint32_t)w->rx_rto;
    seg->resendts = w->current + seg->rto;
    seg->lost = 0;
    seg->xmit = 0;
    send_seg(w, st, seg);
}

static void anl_flush_internal(anl_t *w)
{
    uint32_t current = w->current;
    uint32_t inflight = 0;
    int lost = 0, change = 0;
    int64_t retrans_limit, retrans_spent = 0;
    int pacing, rtx_capped = 0, prio;
    anl_node *n, *nx;
    anl_stream *st;

    if (!w->updated || w->state < 0) return;
    pace_refill(w);
    pacing = w->pace_rate > 0;
    w->pace_blocked = 0;
    dg_begin(w);

    /* 1 + 2: control */
    flush_control_segs(w);
    w->rx_data_since_ack = 0;

    /* sender-side dropping before computing budgets */
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st)) semi_drop_check(w, st);
    }
    FOR_EACH_STREAM(w, st, n, nx) inflight += st->nsnd_buf;
    w->flush_budget = w->nc ? (int64_t)0x7fffffff : (int64_t)w->cwnd - (int64_t)inflight;

    /* 3: retransmissions, not gated by cwnd, gated by pacing (3/4 if new data waits);
       streams are visited in priority order. The retransmission state (backoff,
       resendts, lost) changes only when the segment is actually sent: a
       retransmission deferred by pacing must not be pushed back by another RTO. */
    retrans_limit = (pacing && has_new_data(w)) ? (w->pace_tokens > 0 ? w->pace_tokens * 3 / 4 : 0)
                                                : (int64_t)0x7fffffffffffLL;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st)) (void)rack_detect(w, st);           /* RACK timer */
    }
    for (prio = -1; prio < ANL_MAX_PRIO && !w->pace_blocked && !rtx_capped; prio++) {
        FOR_EACH_STREAM(w, st, n, nx) {
            anl_node *pos;
            if (w->pace_blocked || rtx_capped) break;
            if ((prio < 0 ? !st->strict : (st->strict || st->prio != prio)) || !stream_sendable(st)) continue;
            for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
                anl_seg *seg = QENTRY(pos, anl_seg, node);
                int why = 0;                            /* 1 first, 2 timeout, 3 RACK */
                if (seg->xmit == 0) why = 1;
                else if (tdiff(current, seg->resendts) >= 0) why = 2;
                else if (seg->lost) why = 3;
                if (!why) continue;
                if (why != 1 && semi_expired(w, st, seg)) {
                    /* past max_age: abandon instead of retransmitting (DESIGN 7.3) */
                    abandon_through(w, st, seg->frame_no);
                    pos = &st->snd_buf;         /* a prefix was removed: restart at the new head */
                    continue;
                }
                if (pacing && !pace_can_send(w)) { w->pace_blocked = 1; break; }
                if (pacing && retrans_spent >= retrans_limit) { rtx_capped = 1; break; }
                if (why == 2) {
                    lost = 1;
                    if (w->nodelay == 0) seg->rto += umax32(seg->rto, (uint32_t)w->rx_rto);
                    else seg->rto += (w->nodelay < 2 ? seg->rto : (uint32_t)w->rx_rto) / 2;
                    seg->resendts = current + seg->rto;
                } else if (why == 3) {
                    change = 1;
                    seg->resendts = current + seg->rto;
                }
                seg->rack_rtx = why == 3;
                seg->lost = 0;
                send_seg(w, st, seg);
                retrans_spent += data_seg_size(st, seg);
                if (st->mode == ANL_RELIABLE && seg->xmit >= w->dead_link) w->state = -1;
            }
        }
    }

    /* 4: new data. The default stream has strict priority, the others share
       by weighted round robin. */
    st = w->dflt;
    while (!w->pace_blocked && w->flush_budget > 0 && st->nsnd_que > 0 && stream_sendable(st) &&
           tdiff(st->snd_nxt, st->snd_una + umin32(st->snd_wnd, st->rmt_wnd)) < 0) {
        if (pacing && !pace_can_send(w)) { w->pace_blocked = 1; break; }
        move_and_send(w, st);
        w->flush_budget--;
    }
    if (!w->pace_blocked) {
        int progress = 1;
        while (progress && w->flush_budget > 0 && !w->pace_blocked) {
            progress = 0;
            for (prio = 0; prio < ANL_MAX_PRIO && !w->pace_blocked; prio++) {
                FOR_EACH_STREAM(w, st, n, nx) {
                    uint32_t quota = prio_weight[prio];
                    if (w->pace_blocked) break;
                    if (st->strict || st->prio != prio || !stream_sendable(st)) continue;
                    while (quota > 0 && w->flush_budget > 0 && st->nsnd_que > 0 &&
                           tdiff(st->snd_nxt, st->snd_una + umin32(st->snd_wnd, st->rmt_wnd)) < 0) {
                        if (pacing && !pace_can_send(w)) { w->pace_blocked = 1; break; }
                        move_and_send(w, st);
                        quota--;
                        w->flush_budget--;
                        progress = 1;
                    }
                }
            }
        }
    }

    /* 5: FEC block timers */
    FOR_EACH_STREAM(w, st, n, nx) {
        if (st->fec && st->fec_n > 0 && tdiff(current, st->fec_first_ts) >= st->fec_flush_ms)
            fec_close_block(w, st);
        if (st->fec && st->pcache) {
            uint32_t j;
            for (j = 0; j < st->pcache_n; j++)
                if (st->pcache[j].valid && tdiff(current, st->pcache[j].ts) > w->rx_rto) st->pcache[j].valid = 0;
        }
    }

    dg_seal(w);

    /* congestion window adjustments (ikcp, with init_cwnd on RTO loss) */
    if (!w->nc) {
        if (change) {
            w->ssthresh = umax32(inflight / 2, 2);
            w->cwnd = w->ssthresh + (uint32_t)w->resend;
            w->incr = w->cwnd * w->mss;
        }
        if (lost) {
            w->ssthresh = umax32(inflight / 2, 2);
            w->cwnd = w->init_cwnd;
            w->incr = w->cwnd * w->mss;
        }
        if (w->cwnd < 1) { w->cwnd = 1; w->incr = w->mss; }
    }

}

/*=====================================================================
 * 7. public API
 *====================================================================*/
void anl_config_default(anl_config *cfg, int role)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->role = role ? ANL_ROLE_SERVER : ANL_ROLE_CLIENT;
    cfg->mtu = 1400;
    cfg->pad_max = 32;
    cfg->interval = 20;
    cfg->ack_nodelay = 1;
    cfg->init_cwnd = 16;
    cfg->dead_link = 20;
    cfg->ts_window_ms = 1000;
    cfg->idle_timeout_ms = cfg->role == ANL_ROLE_SERVER ? 30000 : 0;
    cfg->rcv_limit_bytes = 16 << 20;
    cfg->max_peer_streams = 1024;
    cfg->default_snd_wnd = 1200;
    cfg->default_rcv_wnd = 1200;
}

void anl_stream_opt_default(anl_stream_opt *opt, int mode)
{
    memset(opt, 0, sizeof(*opt));
    opt->mode = mode ? ANL_SEMI : ANL_RELIABLE;
    opt->prio = 2;
    opt->fec_depth = 1;
    if (opt->mode == ANL_SEMI) {
        opt->snd_wnd = 512;
        opt->rcv_wnd = 512;
        opt->flush_on_send = 1;
        opt->max_age_ms = 500;
    } else {
        opt->snd_wnd = 32;
        opt->rcv_wnd = 128;
    }
}

anl_t *anl_create(uint32_t conv, const anl_config *cfg, void *user)
{
    anl_t *w;
    if (conv == 0 || cfg == NULL) return NULL;
    if (cfg->role != ANL_ROLE_CLIENT && cfg->role != ANL_ROLE_SERVER) return NULL;
    if (cfg->mtu < ANL_OVERHEAD + DATA_HDR_MAX + OPEN_BODY + 64 || cfg->mtu > 65535) return NULL;
    if (cfg->pad_max < 0 || cfg->pad_max > ANL_MAX_PAD) return NULL;
    if (cfg->default_snd_wnd < 0 || cfg->default_snd_wnd > ANL_MAX_WND) return NULL;
    if (cfg->default_rcv_wnd < 0 || cfg->default_rcv_wnd > ANL_MAX_WND) return NULL;

    w = (anl_t *)anl_malloc(sizeof(anl_t));
    if (w == NULL) return NULL;
    memset(w, 0, sizeof(*w));
    w->conv = conv;
    w->role = cfg->role;
    w->user = user;
    anl_keys_derive(&w->keys, cfg->psk);
    w->mtu = (uint32_t)cfg->mtu;
    w->mss = w->mtu - ANL_OVERHEAD - DATA_HDR_MAX;
    w->pad_max = cfg->pad_max;
    w->rng = cfg->rng;
    w->nodelay = cfg->nodelay;
    w->interval = cfg->interval > 0 ? ubound32(1, (uint32_t)cfg->interval, 5000) : 20;
    w->resend = cfg->resend > 0 ? cfg->resend : 0;
    w->nc = cfg->nc;
    w->ack_nodelay = cfg->ack_nodelay;
    w->init_cwnd = cfg->init_cwnd > 0 ? (uint32_t)cfg->init_cwnd : 16;
    w->dead_link = cfg->dead_link > 0 ? (uint32_t)cfg->dead_link : 20;
    w->ts_window = cfg->ts_window_ms > 0 ? (uint32_t)cfg->ts_window_ms : 1000;
    w->keepalive_ms = cfg->keepalive_ms > 0 ? (uint32_t)cfg->keepalive_ms : 0;
    w->idle_timeout_ms = cfg->idle_timeout_ms > 0 ? (uint32_t)cfg->idle_timeout_ms : 0;
    w->pace_rate_cfg = cfg->pace_rate;
    w->pace_burst = cfg->pace_burst > 0 ? (uint32_t)cfg->pace_burst : 4 * w->mtu;
    w->rcv_limit = cfg->rcv_limit_bytes > 0 ? (uint32_t)cfg->rcv_limit_bytes : 0;
    w->max_peer_streams = cfg->max_peer_streams > 0 ? umin32((uint32_t)cfg->max_peer_streams, ANL_MAX_STREAMS) : 1024;
    w->next_sid = w->role == ANL_ROLE_CLIENT ? 2 : 1;
    QINIT(&w->slist);
    QINIT(&w->ctl_list);

    w->rx_rto = RTO_DEF;
    w->rx_minrto = w->nodelay ? RTO_NDL : RTO_MIN;
    w->reo_mult = 1;
    w->cwnd = w->init_cwnd;
    w->ssthresh = ANL_MAX_WND;
    w->incr = w->cwnd * w->mss;
    w->pace_tokens = (int64_t)w->pace_burst;

    w->buf = (char *)anl_malloc(w->mtu);
    w->rxbuf = (char *)anl_malloc(w->mtu);
    w->scratch = (char *)anl_malloc(w->mtu * 2);
    if (w->buf == NULL || w->rxbuf == NULL || w->scratch == NULL) {
        anl_free(w->buf); anl_free(w->rxbuf); anl_free(w->scratch); anl_free(w);
        return NULL;
    }
    prng_init(w);
    dg_begin(w);

    /* default stream: reliable byte stream, strict priority, open at once */
    {
        anl_stream_opt o;
        anl_stream_opt_default(&o, ANL_RELIABLE);
        o.stream = 1;
        o.prio = 0;
        o.flush_on_send = 1;
        o.snd_wnd = cfg->default_snd_wnd > 0 ? cfg->default_snd_wnd : 1200;
        o.rcv_wnd = cfg->default_rcv_wnd > 0 ? cfg->default_rcv_wnd : 1200;
        w->dflt = stream_create(w, ANL_SID_DEFAULT, &o);
        if (w->dflt == NULL) { anl_release(w); return NULL; }
        w->dflt->strict = 1;
        sid_mark_used(w, ANL_SID_DEFAULT);
    }
    return w;
}

void anl_release(anl_t *w)
{
    int i;
    if (w == NULL) return;
    while (!QEMPTY(&w->slist)) {
        anl_stream *st = STREAM_OF(w->slist.next);
        st->app_released = 1;
        stream_free(w, st);
    }
    for (i = 0; i < SID_PAGES; i++) anl_free(w->spages[i]);
    anl_free(w->rstq);
    anl_free(w->buf);
    anl_free(w->rxbuf);
    anl_free(w->scratch);
    anl_free(w);
}

void anl_setoutput(anl_t *w, anl_output_fn output)
{
    if (w) w->output = output;
}

void anl_set_accept(anl_t *w, anl_accept_fn accept)
{
    if (w) w->accept_cb = accept;
}

void anl_update(anl_t *w, uint32_t current)
{
    int32_t slap;
    if (w == NULL) return;
    w->current = current;
    if (!w->updated) {
        w->updated = 1;
        w->ts_flush = current;
        w->pace_last = current;
        w->last_rx = current;
        w->last_tx = current;
        prng_mix(w, current);
    }
    if (w->state >= 0 && w->idle_timeout_ms && tdiff(current, w->last_rx) >= (int32_t)w->idle_timeout_ms)
        w->state = -1;

    slap = tdiff(current, w->ts_flush);
    if (slap >= 10000 || slap < -10000) { w->ts_flush = current; slap = 0; }
    if (slap >= 0) {
        w->ts_flush += w->interval;
        if (tdiff(current, w->ts_flush) >= 0) w->ts_flush = current + w->interval;
        anl_flush_internal(w);
    } else if (w->pace_blocked) {
        anl_flush_internal(w);
    }

    if (w->state >= 0 && w->keepalive_ms && tdiff(current, w->last_tx) >= (int32_t)w->keepalive_ms) {
        dg_begin(w);
        dg_output(w, 1);
    }
}

uint32_t anl_check(const anl_t *w, uint32_t current)
{
    uint32_t ts_flush, minimal;
    int32_t tm_flush, tm_min = 0x7fffffff;
    anl_node *n, *nx;
    anl_stream *st;

    if (w == NULL || !w->updated) return current;
    if (w->state < 0) return current + (uint32_t)w->interval;
    ts_flush = w->ts_flush;
    if (tdiff(current, ts_flush) >= 10000 || tdiff(current, ts_flush) < -10000) ts_flush = current;
    if (tdiff(current, ts_flush) >= 0) return current;
    tm_flush = tdiff(ts_flush, current);

    if (w->nrstq > 0 || !QEMPTY(&w->ctl_list)) return current;
    FOR_EACH_STREAM(w, st, n, nx) {
        anl_node *pos;
        if (st->state == ANL_STREAM_CLOSED) continue;
        if (st->ack_pending || st->probe_ask || st->probe_tell || st->rst_pending) return current;
        if (!st->peer_opened) {
            int32_t d = tdiff(st->open_ts, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        if (st->fwd_pending) {
            int32_t d = tdiff(st->fwd_ts, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        if (st->state == ANL_STREAM_CLOSING && !st->peer_closed) {
            int32_t d = tdiff(st->close_ts, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        if (st->fec && st->fec_n > 0) {
            int32_t d = tdiff(st->fec_first_ts + (uint32_t)st->fec_flush_ms, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
            const anl_seg *seg = QENTRY(pos, anl_seg, node);
            int32_t d = tdiff(seg->resendts, current);
            if (d <= 0 || seg->lost) return current;
            if (d < tm_min) tm_min = d;
            if (rack_candidate(w, st, seg)) {
                d = tdiff(seg->ts_sent + w->rack_rtt + reo_wnd(w, st), current);    /* RACK timer */
                if (d <= 0) return current;
                if (d < tm_min) tm_min = d;
            }
        }
    }
    if (w->pace_blocked) {
        uint32_t wait = pace_wait_ms(w);
        int32_t elapsed = tdiff(current, w->pace_last);
        int32_t d = (int32_t)wait - elapsed;
        if (d <= 0) return current;
        if (d < tm_min) tm_min = d;
    }
    minimal = (uint32_t)(tm_min < tm_flush ? tm_min : tm_flush);
    if (minimal >= (uint32_t)w->interval) minimal = (uint32_t)w->interval;
    return current + minimal;
}

void anl_flush(anl_t *w)
{
    if (w) anl_flush_internal(w);
}

int anl_state(const anl_t *w)
{
    return w ? w->state : -1;
}

int anl_get_stats(const anl_t *w, anl_stats *out)
{
    anl_node *n, *nx;
    anl_stream *st;
    if (w == NULL || out == NULL) return ANL_EINVAL;
    memset(out, 0, sizeof(*out));
    out->srtt = (uint32_t)w->rx_srtt;
    out->rttval = (uint32_t)w->rx_rttval;
    out->rto = (uint32_t)w->rx_rto;
    out->cwnd = w->cwnd;
    out->ssthresh = w->ssthresh;
    FOR_EACH_STREAM(w, st, n, nx) out->inflight += st->nsnd_buf;
    out->retrans = w->retrans_total;
    out->pace_rate = w->pace_rate ? w->pace_rate : compute_pace_rate(w);
    out->rcv_bytes = w->rcv_bytes;
    out->tx_datagrams = w->tx_dg;
    out->rx_datagrams = w->rx_dg;
    out->rx_auth_fail = w->rx_auth_fail;
    out->rx_stale = w->rx_stale;
    return ANL_OK;
}

/*--------------------------------------------------------------------
 * streams
 *-------------------------------------------------------------------*/
static int fec_alloc(anl_stream *st)
{
    uint32_t i, bufsz = st->mss + CANON_HDR_MAX;
    st->groups = (fec_group *)anl_malloc(sizeof(fec_group) * (uint32_t)st->fec_depth);
    st->cache_n = 16u * (uint32_t)st->fec_depth;
    st->cache = (fec_centry *)anl_malloc(sizeof(fec_centry) * st->cache_n);
    st->pcache_n = 2u * (uint32_t)st->fec_depth;
    st->pcache = (fec_pentry *)anl_malloc(sizeof(fec_pentry) * st->pcache_n);
    if (!st->groups || !st->cache || !st->pcache) return -1;
    memset(st->groups, 0, sizeof(fec_group) * (uint32_t)st->fec_depth);
    memset(st->cache, 0, sizeof(fec_centry) * st->cache_n);
    memset(st->pcache, 0, sizeof(fec_pentry) * st->pcache_n);
    for (i = 0; i < (uint32_t)st->fec_depth; i++) {
        st->groups[i].buf = (uint8_t *)anl_malloc(bufsz);
        if (!st->groups[i].buf) return -1;
    }
    for (i = 0; i < st->cache_n; i++) {
        st->cache[i].buf = (uint8_t *)anl_malloc(bufsz);
        if (!st->cache[i].buf) return -1;
    }
    for (i = 0; i < st->pcache_n; i++) {
        st->pcache[i].buf = (uint8_t *)anl_malloc(bufsz);
        if (!st->pcache[i].buf) return -1;
    }
    return 0;
}

static int stream_opt_check(const anl_stream_opt *opt)
{
    if (opt->mode != ANL_RELIABLE && opt->mode != ANL_SEMI) return ANL_EINVAL;
    if (opt->prio < 0 || opt->prio >= ANL_MAX_PRIO) return ANL_EINVAL;
    if (opt->snd_wnd < 1 || opt->snd_wnd > ANL_MAX_WND) return ANL_EINVAL;
    if (opt->rcv_wnd < 1 || opt->rcv_wnd > ANL_MAX_WND) return ANL_EINVAL;
    if (opt->fec && (opt->fec_depth < 1 || opt->fec_depth > ANL_MAX_FEC_DEPTH)) return ANL_EINVAL;
    if (opt->tag < 0 || opt->tag > 0xffff) return ANL_EINVAL;
    return 0;
}

/* local options that do not have to match the peer (DESIGN 6.1) */
static int stream_apply_local(anl_t *w, anl_stream *st, const anl_stream_opt *opt)
{
    st->prio = opt->prio;
    st->flush_on_send = opt->flush_on_send;
    st->snd_wnd = (uint32_t)opt->snd_wnd;
    if (st->mode == ANL_SEMI) {
        st->max_age_ms = opt->max_age_ms > 0 ? opt->max_age_ms : 0;
        st->max_bytes = opt->max_bytes > 0 ? opt->max_bytes : 0;
        st->drop_until_key = opt->drop_until_key;
        st->rcv_deadline_ms = opt->rcv_deadline_ms > 0 ? opt->rcv_deadline_ms : 0;
        st->rcv_drop_until_key = opt->rcv_drop_until_key != 0;
    }
    /* FEC changes only before anything was segmented (mss depends on it) */
    if ((opt->fec != 0) != st->fec && st->snd_nxt == 0 && st->nsnd_que == 0) {
        fec_free(st);
        st->fec = 0;
        st->mss = w->mss;
        if (opt->fec) {
            st->fec = 1;
            st->fec_depth = opt->fec_depth;
            st->fec_flush_ms = opt->fec_flush_ms > 0 ? opt->fec_flush_ms : (int)umin32(w->interval, 20);
            st->mss = w->mss - ANL_FEC_OVERHEAD;
            if (fec_alloc(st) < 0) { fec_free(st); st->fec = 0; st->mss = w->mss; return ANL_ENOMEM; }
        }
    }
    return 0;
}

static anl_stream *stream_create(anl_t *w, int sid, const anl_stream_opt *opt)
{
    anl_stream *st = (anl_stream *)anl_malloc(sizeof(anl_stream));
    if (st == NULL) return NULL;
    memset(st, 0, sizeof(*st));
    st->w = w;
    st->sid = sid;
    st->tag = opt->tag;
    st->mode = opt->mode;
    st->stream = opt->mode == ANL_RELIABLE ? (opt->stream != 0) : 0;
    st->state = ANL_STREAM_OPEN;
    st->rcv_wnd = (uint32_t)opt->rcv_wnd;
    st->rmt_wnd = st->rcv_wnd;              /* the same on both ends (DESIGN 6.1) */
    st->mss = w->mss;
    st->open_ts = w->current;
    QINIT(&st->snd_queue); QINIT(&st->snd_buf); QINIT(&st->rcv_buf); QINIT(&st->rcv_queue);
    if (stream_apply_local(w, st, opt) != 0 || sput(w, st) != 0) {
        fec_free(st);
        anl_free(st);
        return NULL;
    }
    return st;
}

anl_stream_t *anl_stream_open(anl_t *w, const anl_stream_opt *opt, int *err)
{
    anl_stream *st;
    int r;
    if (err) *err = ANL_OK;
    if (w == NULL || opt == NULL) { r = ANL_EINVAL; goto fail; }
    if ((r = stream_opt_check(opt)) != 0) goto fail;
    if (w->state < 0) { r = ANL_EDEAD; goto fail; }
    /* client even from 2, server odd; never reused within a connection */
    if (w->next_sid >= ANL_MAX_STREAMS) { r = ANL_EBUSY; goto fail; }
    st = stream_create(w, w->next_sid, opt);
    if (st == NULL) { r = ANL_ENOMEM; goto fail; }
    sid_mark_used(w, w->next_sid);
    w->next_sid += 2;
    ctl_mark(st);
    flush_control(w);                       /* announce it at once */
    return st;
fail:
    if (err) *err = r;
    return NULL;
}

int anl_stream_close(anl_stream_t *st)
{
    anl_t *w;
    if (st == NULL) return ANL_EINVAL;
    w = st->w;
    if (st == w->dflt || st->app_released) return ANL_EINVAL;
    st->app_released = 1;
    st->user = NULL;
    if (st->detached) { stream_free(w, st); return ANL_OK; }    /* over on the wire already */
    discard_rcv_queue(w, st);
    stream_local_close(w, st);
    ctl_mark(st);
    stream_try_release(w, st);              /* may free st */
    flush_control(w);
    return ANL_OK;
}

static int reliable_peeksize(const anl_stream *st)
{
    const anl_seg *seg;
    anl_node *pos;
    uint32_t length = 0;
    if (QEMPTY(&st->rcv_queue)) return -1;
    seg = QENTRY(st->rcv_queue.next, anl_seg, node);
    if (seg->frg == 0) return (int)seg->len;
    if (st->nrcv_que < seg->frg + 1) return -1;
    for (pos = st->rcv_queue.next; pos != &st->rcv_queue; pos = pos->next) {
        seg = QENTRY(pos, anl_seg, node);
        length += seg->len;
        if (seg->frg == 0) break;
    }
    return (int)length;
}

static int frame_peeksize(anl_t *w, anl_stream *st)
{
    anl_seg *head;
    anl_node *pos;
    uint32_t n, i, length = 0;
    for (;;) {
        head = qfirst_seg(&st->rcv_queue);
        if (head == NULL) return -1;
        if (head->flags & F_HAS_FRAME) {
            uint32_t expect = st->delivered_any ? st->last_delivered + 1 : 0;
            if ((head->flags & F_KEY) || !st->rcv_drop_until_key || head->frame_no == expect) break;
            /* DESIGN 7.6: a frame before this one is lost, so this non-key frame
               cannot be decoded; drop it (lost_before counts it) */
            st->frames_discarded++;
        }
        /* discarded frame head, or stray fragment without a frame start */
        qdel(&head->node);
        st->nrcv_que--;
        rcv_bytes_sub(w, head->len);
        seg_free(head);
    }
    n = head->frg + 1;
    if (st->nrcv_que < n) return -1;
    for (pos = st->rcv_queue.next, i = 0; i < n; pos = pos->next, i++) {
        const anl_seg *s = QENTRY(pos, anl_seg, node);
        if (s->sn != head->sn + i || s->frg != head->frg - i || (i > 0 && (s->flags & F_HAS_FRAME))) {
            /* broken frame (its tail was abandoned): discard up to the next frame start */
            anl_seg *h;
            do {
                h = qfirst_seg(&st->rcv_queue);
                qdel(&h->node); st->nrcv_que--; rcv_bytes_sub(w, h->len); seg_free(h);
                h = qfirst_seg(&st->rcv_queue);
            } while (h && !(h->flags & F_HAS_FRAME));
            st->frames_skipped++;
            return frame_peeksize(w, st);
        }
        length += s->len;
    }
    return (int)length;
}

static int stream_peeksize(anl_t *w, anl_stream *st)
{
    return st->mode == ANL_SEMI ? frame_peeksize(w, st) : reliable_peeksize(st);
}

/* no more data will ever arrive and nothing complete is left (DESIGN 6.1) */
static int stream_at_end(const anl_stream *st)
{
    if (st->state == ANL_STREAM_CLOSED) return 1;
    return st->peer_closed && tdiff(st->rcv_nxt, st->peer_final_sn) >= 0 && QEMPTY(&st->rcv_buf);
}

int anl_readable(anl_t *w, anl_stream_t **out, int max)
{
    anl_node *n, *nx;
    anl_stream *st;
    int cnt = 0;
    if (w == NULL || max < 0 || (out == NULL && max > 0)) return ANL_EINVAL;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (st->app_released) continue;
        if (stream_peeksize(w, st) < 0 && !stream_at_end(st)) continue;
        if (cnt < max) out[cnt] = st;
        cnt++;
    }
    return cnt;
}

int anl_stream_peeksize(const anl_stream_t *s)
{
    anl_stream *st = (anl_stream *)s;
    int n;
    if (st == NULL) return ANL_EINVAL;
    n = stream_peeksize(st->w, st);
    if (n >= 0) return n;
    return stream_at_end(st) ? ANL_ECLOSED : ANL_EAGAIN;
}

int anl_stream_waitsnd(const anl_stream_t *st)
{
    if (st == NULL) return ANL_EINVAL;
    return (int)(st->nsnd_buf + st->nsnd_que);
}

int anl_stream_get_stats(const anl_stream_t *st, anl_stream_stats *out)
{
    if (st == NULL || out == NULL) return ANL_EINVAL;
    memset(out, 0, sizeof(*out));
    out->state = st->state == ANL_STREAM_OPEN && !st->peer_opened ? ANL_STREAM_OPENING : st->state;
    out->wait_snd = st->nsnd_buf + st->nsnd_que;
    out->backlog_bytes = st->backlog_bytes;
    out->rmt_wnd = st->rmt_wnd;
    out->retrans = st->retrans;
    out->frames_dropped = st->frames_dropped;
    out->frames_skipped = st->frames_skipped;
    out->fec_recovered = st->fec_recovered;
    out->frames_discarded = st->frames_discarded;
    return ANL_OK;
}

int anl_stream_id(const anl_stream_t *st) { return st ? st->sid : ANL_EINVAL; }
int anl_stream_tag(const anl_stream_t *st) { return st ? st->tag : ANL_EINVAL; }
anl_t *anl_stream_conn(const anl_stream_t *st) { return st ? st->w : NULL; }
void anl_stream_set_user(anl_stream_t *st, void *user) { if (st) st->user = user; }
void *anl_stream_get_user(const anl_stream_t *st) { return st ? st->user : NULL; }

/* default stream (sid 0) */
anl_stream_t *anl_default_stream(anl_t *w) { return w ? w->dflt : NULL; }
int anl_send(anl_t *w, const char *buf, int len) { return w ? anl_stream_send(w->dflt, buf, len) : ANL_EINVAL; }
int anl_recv(anl_t *w, char *buf, int len) { return w ? anl_stream_recv(w->dflt, buf, len) : ANL_EINVAL; }
int anl_peeksize(const anl_t *w) { return w ? anl_stream_peeksize(w->dflt) : ANL_EINVAL; }
int anl_waitsnd(const anl_t *w) { return w ? anl_stream_waitsnd(w->dflt) : ANL_EINVAL; }

/* common checks for send APIs; returns 0 or an error code */
static int send_precheck(const anl_t *w, const anl_stream *st, int mode)
{
    if (w->state < 0) return ANL_EDEAD;
    if (st->mode != mode) return ANL_EMODE;
    if (st->state != ANL_STREAM_OPEN) return ANL_ECLOSED;
    return 0;
}

/* after the application took something out of rcv_queue; may free st */
static void after_recv(anl_t *w, anl_stream *st, int recover)
{
    move_to_queue(st);
    if (st->nrcv_que < st->rcv_wnd && recover) { st->probe_tell = 1; ctl_mark(st); }
    if (st->state == ANL_STREAM_CLOSED && QEMPTY(&st->rcv_queue)) { ctl_mark(st); flush_control(w); }
}

/* payload size of a new segment: segments cut before the peer has been heard
 * may go out with the stream parameters (OPEN_BODY) and are made that much
 * smaller; peer_opened never goes back to 0, so a segment cut later is never
 * sent with them and the connection keeps the full mss (DESIGN 5.2) */
static uint32_t seg_limit(const anl_stream *st)
{
    return st->peer_opened ? st->mss : st->mss - OPEN_BODY;
}

/*--------------------------------------------------------------------
 * reliable stream
 *-------------------------------------------------------------------*/
int anl_stream_send(anl_stream_t *st, const char *buf, int len)
{
    anl_t *w;
    uint32_t count, i, mss;
    int r;
    if (st == NULL || buf == NULL || len <= 0) return ANL_EINVAL;
    w = st->w;
    r = send_precheck(w, st, ANL_RELIABLE);
    if (r) return r;
    mss = seg_limit(st);

    /* byte-stream mode: append to the last queued segment (ikcp) */
    if (st->stream) {
        anl_seg *old = qlast_seg(&st->snd_queue);
        if (old && old->len < mss) {
            uint32_t cap = mss - old->len;
            uint32_t ext = (uint32_t)len < cap ? (uint32_t)len : cap;
            anl_seg *seg = seg_new(old->len + ext);
            if (seg == NULL) return ANL_ENOMEM;
            memcpy(seg->data, old->data, old->len);
            memcpy(seg->data + old->len, buf, ext);
            seg->frg = 0;
            seg->ts_enq = w->current;
            qadd_after(&seg->node, &old->node);
            qdel(&old->node);
            seg_free(old);
            buf += ext;
            len -= (int)ext;
            if (len <= 0) { if (st->flush_on_send) anl_flush_internal(w); return ANL_OK; }
        }
    }

    count = (uint32_t)len <= mss ? 1 : ((uint32_t)len + mss - 1) / mss;
    if (!st->stream && count > st->rcv_wnd) return ANL_ETOOBIG;     /* peer rcv_wnd == ours */
    if (count > VARINT_MAX) return ANL_ETOOBIG;

    for (i = 0; i < count; i++) {
        uint32_t size = (uint32_t)len > mss ? mss : (uint32_t)len;
        anl_seg *seg = seg_new(size);
        if (seg == NULL) return ANL_ENOMEM;
        memcpy(seg->data, buf, size);
        seg->frg = st->stream ? 0 : (count - i - 1);
        seg->ts_enq = w->current;
        qadd_tail(&seg->node, &st->snd_queue);
        st->nsnd_que++;
        st->backlog_bytes += size;
        buf += size;
        len -= (int)size;
    }
    if (st->flush_on_send) anl_flush_internal(w);
    return ANL_OK;
}

int anl_stream_recv(anl_stream_t *st, char *buf, int len)
{
    anl_t *w;
    int peek, recover, total = 0;
    if (st == NULL || buf == NULL || len < 0) return ANL_EINVAL;
    w = st->w;
    if (st->mode != ANL_RELIABLE) return ANL_EMODE;
    peek = reliable_peeksize(st);
    if (peek < 0) return stream_at_end(st) ? ANL_ECLOSED : ANL_EAGAIN;
    if (peek > len) return ANL_EBUFSIZE;
    recover = st->nrcv_que >= st->rcv_wnd;
    while (!QEMPTY(&st->rcv_queue)) {
        anl_seg *seg = qfirst_seg(&st->rcv_queue);
        uint32_t frg = seg->frg;
        memcpy(buf + total, seg->data, seg->len);
        total += (int)seg->len;
        qdel(&seg->node);
        st->nrcv_que--;
        rcv_bytes_sub(w, seg->len);
        seg_free(seg);
        if (frg == 0) break;
    }
    after_recv(w, st, recover);
    return total;
}

/*--------------------------------------------------------------------
 * semi-reliable stream
 *-------------------------------------------------------------------*/
int anl_stream_send_frame(anl_stream_t *st, int flags, const char *buf, int len, uint32_t *frame_no)
{
    anl_t *w;
    uint32_t count, i, fno, mss;
    int r, key = (flags & ANL_FRAME_KEY) != 0;
    if (st == NULL || buf == NULL || len <= 0) return ANL_EINVAL;
    w = st->w;
    r = send_precheck(w, st, ANL_SEMI);
    if (r) return r;
    mss = seg_limit(st);

    count = (uint32_t)len <= mss ? 1 : ((uint32_t)len + mss - 1) / mss;
    if (count > st->rcv_wnd) return ANL_ETOOBIG;                    /* peer rcv_wnd == ours */

    fno = st->frame_next++;
    if (frame_no) *frame_no = fno;
    if (key) {
        st->dropping = 0;
    } else if (st->dropping) {
        st->frames_dropped++;
        return ANL_EDROPPED;
    }

    for (i = 0; i < count; i++) {
        uint32_t size = (uint32_t)len > mss ? mss : (uint32_t)len;
        anl_seg *seg = seg_new(size);
        if (seg == NULL) return ANL_ENOMEM;
        memcpy(seg->data, buf, size);
        seg->frg = count - i - 1;
        seg->frame_no = fno;
        seg->flags = i == 0 ? (uint8_t)(F_HAS_FRAME | (key ? F_KEY : 0)) : 0;
        seg->fkey = (uint8_t)key;
        seg->ts_enq = w->current;
        qadd_tail(&seg->node, &st->snd_queue);
        st->nsnd_que++;
        st->backlog_bytes += size;
        buf += size;
        len -= (int)size;
    }
    semi_drop_check(w, st);
    if (st->flush_on_send) anl_flush_internal(w);
    return ANL_OK;
}

int anl_stream_recv_frame(anl_stream_t *st, char *buf, int len, anl_frame_info *info)
{
    anl_t *w;
    anl_seg *head;
    int peek, recover, total = 0;
    uint32_t fno;
    uint8_t fflags;
    if (st == NULL || buf == NULL || len < 0) return ANL_EINVAL;
    w = st->w;
    if (st->mode != ANL_SEMI) return ANL_EMODE;
    peek = frame_peeksize(w, st);
    if (peek < 0) return stream_at_end(st) ? ANL_ECLOSED : ANL_EAGAIN;
    if (peek > len) return ANL_EBUFSIZE;
    recover = st->nrcv_que >= st->rcv_wnd;
    head = qfirst_seg(&st->rcv_queue);
    fno = head->frame_no;
    fflags = head->flags;
    while (!QEMPTY(&st->rcv_queue)) {
        anl_seg *seg = qfirst_seg(&st->rcv_queue);
        uint32_t frg = seg->frg;
        memcpy(buf + total, seg->data, seg->len);
        total += (int)seg->len;
        qdel(&seg->node);
        st->nrcv_que--;
        rcv_bytes_sub(w, seg->len);
        seg_free(seg);
        if (frg == 0) break;
    }
    if (info) {
        info->frame_no = fno;
        info->flags = (fflags & F_KEY) ? ANL_FRAME_KEY : 0;
        info->lost_before = st->delivered_any ? (fno - st->last_delivered - 1) : fno;
    }
    st->last_delivered = fno;
    st->delivered_any = 1;
    after_recv(w, st, recover);
    return total;
}
