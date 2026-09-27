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
#define CTRL_REPORT     0x04    /* receiver's delay report (DESIGN 6.9) */
#define REPORT_BODY     16      /* jitter qavg qmax favg fmax frames skipped fec_rec, u16 each */
#define REPORT_MIN_MS   100     /* reports every max(srtt, this) while data arrives */
#define DELAY_WIN_MS    5000    /* base transit: min over two such windows */
#define RATE_STEP_MS    200     /* target_rate update period (DESIGN 6.10) */
#define RATE_MARGIN     10      /* % of the estimate left for bitrate spikes */
#define RATE_GROWTH     25      /* %/s: target_rate rises at most this fast */
#define RATE_DECREASE   15      /* % per RATE_STEP_MS while the queue grows */
#define RATE_RTT_WIN    15000   /* minimum RTT for the queue estimate: two such windows */

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

#define RTO_MIN         30
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
#define PARITY_HDR      5       /* base(2) k(1) m(1) j(1), after type|sid sub len */

#define SID_PAGE_SHIFT  7       /* stream table: 64 pages of 128 slots, allocated on demand */
#define SID_PAGE_SIZE   (1u << SID_PAGE_SHIFT)
#define SID_PAGES       (ANL_MAX_STREAMS >> SID_PAGE_SHIFT)
#define CANON_HDR_MAX   7       /* b1 frg_ext(2) frame(2) plen(2) */
#define BBR_UNIT            256
#define BBR_STARTUP_GAIN    739     /* 2.885 = 2 / ln 2 */
#define BBR_DRAIN_GAIN      88      /* 1 / 2.885 */
#define BBR_DOWN_GAIN       230     /* 0.9: PROBE_BW drains the probe's queue (BBRv3) */
#define BBR_UP_GAIN         320     /* 1.25: PROBE_BW probes for bandwidth */
#define BBR_PROBE_WAIT_MS   2000    /* PROBE_BW probes every 2..3 s of wall clock (random) */
#define BBR_CWND_GAIN       512     /* 2 */
#define BBR_BW_ROUNDS       10
#define BBR_PROBE_RTT_MS    200
#define BBR_MIN_RTT_WIN     10000
#define BBR_LOSS_THRESH     2       /* % of a round's data lost: congestion, if a queue shows */
#define BBR_LOSS_BLIND      50      /* % lost in PROBE_BW: congestion even without a queue (policer) */
#define BBR_PATH_ROUNDS     3       /* rounds a queue outlives our cuts before it counts as the path RTT */
#define BBR_BETA            179     /* 0.7: inflight_hi after congestive loss */
#define BBR_MIN_CWND        4
#define SEG_WIRE_OVH        30      /* per-segment share of datagram / segment headers */
#define FEC_K_MAX       64      /* data packets per Reed-Solomon block */
#define FEC_M_MAX       16      /* parities per block */
#define FEC_BLOCK_MS    100     /* a block collects data packets for at most this long */
#define FEC_GAP         5       /* ms between the parities of a block (loss bursts) */
#define FEC_AUTO_START  25      /* fec_ratio 0 (auto, DESIGN 8.5): the ratio it starts from, */
#define FEC_AUTO_MIN    10      /* its floor (small blocks get no parity at all), */
#define FEC_AUTO_MAX    100     /* its ceiling, */
#define FEC_AUTO_MISS   1       /* % of first transmissions lost despite FEC that raises it, */
#define FEC_AUTO_CLEAN  200     /* first transmissions without such a loss that lower it */
#define FEC_CREDIT_FREE 25      /* % of parities not counted as delivered (fec_share) */
#define FEC_LOSS_PKTS   200     /* connection loss estimate: window of FEC first transmissions */
#define FEC_BLOCK_FAIL  1       /* auto: parities so that a block fails with at most this % */

static const uint32_t prio_weight[ANL_MAX_PRIO] = { 8, 4, 2, 1 };

typedef struct anl_seg {
    anl_node node;
    uint32_t sn;
    uint32_t frg;
    uint32_t frame_no;      /* semi: 32-bit frame number (all fragments) */
    uint32_t first_sn;      /* semi: sn of the frame's first fragment */
    uint32_t ts_enq;        /* semi: enqueue time */
    uint32_t ts_sent;       /* time of the last transmission (RACK); receiver: the peer's send time */
    uint32_t fec_ts;        /* its FEC block's last parity goes out (first transmission only) */
    uint16_t fec_share;     /* its share of the block's parity bytes (delivery rate) */
    uint32_t resendts;
    uint32_t rto;
    uint32_t lost;          /* RACK declared it lost: retransmit at the next flush */
    uint32_t xmit;          /* sender: transmissions; receiver (rcv_buf): times reported in a SACK range */
    uint8_t  flags;         /* F_HAS_FRAME | F_KEY (wire: first fragment only) */
    uint8_t  fkey;          /* semi: the frame is a key frame (every fragment) */
    uint8_t  rack_rtx;      /* the last transmission was a retransmission by 1 RACK, 2 RTO (spurious check) */
    uint8_t  rs_app;        /* delivery rate sample (BBR): sent while app-limited */
    uint32_t burst_id;      /* first sent in this app-limited burst (0: none; burst_on_acked) */
    uint64_t rs_delivered;  /* connection's delivered bytes when it was sent */
    uint64_t rs_fec;        /* ... and delivered_fec */
    uint32_t rs_ts;         /* ... and the time of that delivery */
    uint32_t rs_first;      /* send time of the first packet of the sampling interval */
    uint32_t rs_sent, rs_sent_first;    /* sent_wire after this packet / at rs_first */
    uint32_t len;
    char     data[1];
} anl_seg;

typedef struct fec_buf {        /* grows on demand: audio needs 170 bytes, not an mss */
    uint8_t *p;
    uint32_t cap, len;
} fec_buf;

typedef struct fec_centry {     /* receiver: canonical encoding of a received DATA segment */
    int      valid;
    uint32_t sn;
    fec_buf  b;
} fec_centry;

typedef struct fec_pentry {     /* receiver: a parity waiting for its block to become decodable */
    int      valid;
    uint32_t base, k, m, j;
    uint32_t ts;
    fec_buf  b;
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

    /* FEC (DESIGN 8): Reed-Solomon over the stream's first transmissions */
    int fec, fec_ratio;                 /* parities per 100 data packets */
    int fec_auto;                       /* fec_ratio follows the residual loss (DESIGN 8.5) */
    uint32_t fec_deadline;              /* auto: a retransmission arriving within this (ms from
                                           enqueue) is fine, FEC is not needed for it; 0 = none */
    uint32_t fec_sent, fec_miss, fec_adj_ts;    /* auto: first transmissions, lost ones, last raise */

    /* delay measurement and reports (DESIGN 6.9) */
    int report;                         /* receiver: send reports */
    int rp_have, rp_in_frame;
    int32_t rp_prev, rp_min_cur, rp_min_old;    /* transit (local - peer ts): last, window minima */
    uint32_t rp_win_ts, rp_jit16;       /* window start; jitter x 16 */
    uint32_t rp_frm_ts;                 /* peer ts of the earliest fragment of the frame being completed */
    uint32_t rp_qsum, rp_qn, rp_qmax, rp_fsum, rp_fn, rp_fmax;  /* the current interval */
    uint32_t rp_next;                   /* next report */
    anl_delay_report rp_last;           /* the last interval, measured here */
    uint32_t rp_last_ts;
    anl_delay_report peer_rp;           /* the peer's latest report */
    int peer_rp_rec_valid;              /* peer_rp.fec_recovered seen once (fec_loss deltas) */
    uint32_t peer_rp_ts;
    fec_buf *fec_slot;                  /* sender: canonical encodings of the open block (FEC_K_MAX) */
    uint32_t fec_base, fec_first_ts, fec_n;
    fec_buf *fec_out;                   /* sender: parities of the last block (FEC_M_MAX), FEC_GAP apart */
    uint32_t fec_out_base, fec_out_k, fec_out_m, fec_out_i, fec_out_ts;
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
    int interval;
    uint32_t init_cwnd, dead_link, ts_window, keepalive_ms, idle_timeout_ms;
    int pace_rate_cfg;
    uint32_t pace_burst, rcv_limit;

    int32_t rx_rttval, rx_srtt, rx_rto;
    int reo_mult;                       /* RACK reordering window = reo_mult * min_rtt / 16 */
    uint32_t reo_inc_ts;                /* last reo_mult change: at most one per round trip */
    uint32_t reo_spur_ts;               /* last spurious RACK retransmission */
    uint32_t min_rtt, min_rtt_ts;       /* windowed minimum RTT (BBR_MIN_RTT_WIN) */
    uint32_t rack_ts, rack_rtt;         /* RACK: newest datagram the peer is known to have (any stream) */
    int rack_valid;
    uint32_t cwnd;                      /* segments */

    /* BBRv2 (DESIGN 6.8): delivery rate sampling, bandwidth / min_rtt model */
    uint64_t delivered;                 /* data bytes (wire estimate) acknowledged so far */
    uint64_t delivered_fec;             /* parity bytes counted with them (fec_share): rate samples only */
    uint32_t delivered_ts;              /* time of the last acknowledgement */
    uint32_t first_sent_ts;             /* send time of the packet starting the sampling interval */
    uint32_t sent_wire, first_sent_wire; /* wire bytes sent (data, retransmissions, parity; wraps) */
    uint64_t app_limited;               /* != 0: samples are app-limited until delivered passes it */
    uint64_t lost_bytes;                /* data bytes lost: RTO, or RACK once the retransmission is acknowledged and not spurious */
    uint32_t inflight_segs;             /* segments in flight (exact at each flush) */
    uint32_t avg_seg;                   /* average wire size of a data segment, bytes */
    uint64_t next_round_delivered;
    uint32_t round_count;
    uint64_t round_delivered0, round_lost0;
    uint32_t bw_round[BBR_BW_ROUNDS];   /* max delivery rate per round, bytes/s */
    uint32_t btl_bw;                    /* bottleneck bandwidth: max over the last 10 rounds */
    uint32_t net_round;                 /* round of the last network-limited sample (| 1); 0 = none */
    uint32_t net_sample_ts;             /* ... its time (| 1); 0 = none (stats.bw_estimate_age_ms) */
    uint32_t bw_lo;                     /* BBRv2 lower bound after congestive loss, until the next probe; 0 = none */
    uint32_t bw_idx;                    /* filter slot of the current round */
    /* token-bucket policer detection (DESIGN 6.8): intervals of >= 16 rounds and 300 ms */
    int lt_state;                       /* 0 watching, 1 testing at lt_rate, 2 policed at lt_rate */
    int lt_bad;                         /* the interval had app-limited or queued rounds */
    uint32_t lt_ts, lt_rounds, lt_left, lt_hold;
    uint32_t lt_sent0;                  /* sent_wire at the start of the interval */
    uint64_t lt_rd, lt_lost;
    uint32_t lt_rate, lt_prev_rate, lt_prev_loss, lt_ref_loss;  /* bytes/s; loss per mille */
    uint32_t burst_id;                  /* the last app-limited burst (a key frame); its segments carry it */
    uint8_t  burst_open, burst_done;    /* its segments are being sent; its measurement is over */
    uint32_t burst_left;                /* segments of it not sent yet (queued when it opened) */
    uint32_t burst_t0, burst_t1;        /* first / last send of its segments */
    uint32_t burst_sw0, burst_sw1;      /* sent_wire before its first / after its last segment */
    uint32_t disp_ts, disp_bytes;       /* its first ACK (0: none yet); bytes acknowledged since */
    uint32_t burst_rtt0;                /* the RTT at its first ACK (at least bbr_rtt) */
    uint32_t burst_bw;                  /* the rate the last measured burst went through at (ACK dispersion), bytes/s */
    uint32_t burst_cur;                 /* ... the current one so far (0: none), taken over by the next burst */
    uint32_t round_bw;                  /* largest sample of the current round (the slot keeps the
                                           peak of earlier rounds while app-limited rounds do not rotate) */
    int round_net_sample;               /* the current round had a sample that was not app-limited */
    int bw_last_app;                    /* the latest sample was app-limited */
    int bbr_state;                      /* ANL_BBR_STARTUP .. ANL_BBR_PROBE_RTT */
    uint32_t pacing_gain, cwnd_gain;    /* BBR_UNIT = 1.0 */
    uint32_t full_bw, full_bw_cnt;
    int full_bw_reached;
    int probe_phase;                    /* PROBE_BW: BBR_DOWN .. BBR_UP */
    uint32_t phase_ts, phase_round;     /* start of the phase; REFILL: the round it ends */
    uint32_t probe_ts, probe_round;     /* the last probe ended: wall clock (+ 2..3 s), round */
    uint32_t up_bw, up_stall;           /* UP: btl_bw at the last 25% growth; rounds since */
    uint32_t probe_rtt_done_ts, probe_rtt_round;
    uint32_t prior_cwnd;
    uint64_t inflight_hi;               /* BBRv2 loss bound on inflight, bytes; 0 = none */
    uint32_t loss_rate;                 /* smoothed per-round loss fraction, 1/256 */
    uint32_t qfall;                     /* consecutive congestive rounds whose delivery rate fell with our cuts */
    uint32_t round_ts, last_round_rate; /* start of the round; delivery rate of the last round, bytes/s */
    uint32_t clean_rounds;              /* rounds without congestive loss since inflight_hi was set */
    uint32_t rto_round, rto_inflight;   /* after an RTO: packet conservation for a round */
    int32_t last_rtt;                   /* latest RTT sample */
    uint32_t round_min_rtt;             /* smallest RTT sample of the current round (0: none yet) */
    uint32_t prev_round_min_rtt;        /* ... of the last completed round */
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
    anl_rate_fn rate_cb;
    anl_report_fn report_cb;
    uint64_t tx_payload;                /* first-transmission payload bytes (target_rate) */
    uint32_t fl_sent, fl_lost;          /* FEC streams: first transmissions, lost ones (repaired
                                           by the peer's FEC or not) in the current window */
    uint32_t fec_loss;                  /* raw loss of the connection before FEC, 1/65536 (DESIGN 8.5) */
    uint64_t rate_payload0, rate_wire0, rate_deliv0;
    uint32_t rate_ts, rate_share;       /* payload share of the wire bytes, 1/256 */
    uint32_t rate_target, rate_told;    /* target_rate; the value last given to rate_cb */
    uint32_t rate_rtt_min, rate_rtt_old, rate_rtt_ts;  /* min srtt over 15..30 s (two windows) */
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

/* data bytes a segment puts on the wire, as BBR counts them */
static uint32_t seg_wire(const anl_seg *s) { return s->len + SEG_WIRE_OVH; }

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
enum { FEC_SENT, FEC_LOST, FEC_LATE };  /* fec_auto_count */
static void fec_auto_count(anl_t *w, anl_stream *st, int lost);
static void fec_loss_add(anl_t *w, uint32_t sent, uint32_t lost);
static uint32_t fec_parities_for(uint32_t k, uint32_t p);

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
    if (w->dg_has_data) w->pace_tokens -= (int64_t)w->ptr;
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

static void write_report_seg(anl_t *w, anl_stream *st)
{
    const anl_delay_report *r = &st->rp_last;
    uint8_t body[REPORT_BODY];
    char *p = (char *)body;
    p = enc16(p, (uint16_t)umin32(r->jitter_ms, 0xffff));
    p = enc16(p, (uint16_t)umin32(r->qdelay_avg_ms, 0xffff));
    p = enc16(p, (uint16_t)umin32(r->qdelay_max_ms, 0xffff));
    p = enc16(p, (uint16_t)umin32(r->frame_delay_avg_ms, 0xffff));
    p = enc16(p, (uint16_t)umin32(r->frame_delay_max_ms, 0xffff));
    p = enc16(p, (uint16_t)umin32(r->frames, 0xffff));
    p = enc16(p, (uint16_t)r->frames_skipped);
    (void)enc16(p, (uint16_t)r->fec_recovered);
    write_ctrl_seg(w, st->sid, CTRL_REPORT, body, REPORT_BODY);
}

static void handle_report(anl_t *w, anl_stream *st, const char *p)
{
    anl_delay_report *r = &st->peer_rp;
    uint32_t rec0 = r->fec_recovered;
    r->valid = 1;
    r->jitter_ms = dec16(&p);
    r->qdelay_avg_ms = dec16(&p);
    r->qdelay_max_ms = dec16(&p);
    r->frame_delay_avg_ms = dec16(&p);
    r->frame_delay_max_ms = dec16(&p);
    r->frames = dec16(&p);
    r->frames_skipped = dec16(&p);
    r->fec_recovered = dec16(&p);
    r->age_ms = 0;
    st->peer_rp_ts = w->current;
    if (st->fec && st->peer_rp_rec_valid) fec_loss_add(w, 0, (uint16_t)(r->fec_recovered - rec0));
    st->peer_rp_rec_valid = 1;
    if (w->report_cb) w->report_cb(w, st, r, w->user);
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
static uint32_t bbr_bw(const anl_t *w);
static int bbr_queue_signal(const anl_t *w);

/* Burst headroom for an app-limited sender whose bandwidth estimate only
 * shows what the application offered: a key frame goes out at the STARTUP
 * gain and its samples find the path. Not when the path was measured in the
 * last BBR_BW_ROUNDS rounds: then the estimate is the path, and a burst
 * above it would only move the queue from the sender - where a control
 * stream overtakes it - into the network, where nothing can. */
static int bbr_headroom(const anl_t *w)
{
    return w->app_limited != 0 && (w->net_round == 0 || tdiff(w->round_count, w->net_round) > BBR_BW_ROUNDS);
}

/* An app-limited sender whose bursts go through much faster than its
   average rate (the model's bandwidth): pace and window for the burst rate
   (burst_bw). Not when they are about as fast - the application sends
   about what the path takes, and bursts at 1.25x the path's rate only
   queue (priority test: control p99 215 -> 350 ms). Nor while the path
   shows a queue or a policer. */
static int bbr_burst(const anl_t *w)
{
    return (w->app_limited != 0 || w->burst_open) && (uint64_t)w->burst_bw * 2 > (uint64_t)bbr_bw(w) * 3 &&
           w->lt_state == 0 && !bbr_queue_signal(w);
}

static uint32_t compute_pace_rate(const anl_t *w)
{
    /* gain * bottleneck bandwidth; before the first sample the initial window
       per RTT, at the STARTUP gain. Never below BBR_MIN_CWND segments per
       RTT; never above cfg.pace_rate when that is set. */
    /* not below the update interval (bbr_rtt): at 1 ms srtt the floor was
       4 segments per ms, 44 Mbps, over a 28 Mbps policer - 40% of what was
       sent was lost (real network, DESIGN 13.24) */
    uint32_t srtt = umax32(w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF, (uint32_t)w->interval);
    uint64_t rate, floor = (uint64_t)BBR_MIN_CWND * w->mss * 1000u / srtt;
    uint32_t gain = w->pacing_gain;
    /* app-limited (audio, video between key frames): btl_bw only shows
       what the application sent. Its bursts - a key frame - go out at the
       STARTUP gain; if the path takes them, their samples raise btl_bw */
    if (bbr_headroom(w) && gain < BBR_STARTUP_GAIN) gain = BBR_STARTUP_GAIN;
    /* policed (or testing for it): the rate is known, probing above it is
       only loss - 6% of what was sent at 1 ms RTT (BBRv1 does the same) */
    if (w->lt_state != 0 && gain > BBR_UNIT) gain = BBR_UNIT;
    if (w->btl_bw != 0) rate = (uint64_t)bbr_bw(w) * gain / BBR_UNIT;
    else rate = (uint64_t)w->init_cwnd * w->mss * 1000u / srtt * BBR_STARTUP_GAIN / BBR_UNIT;
    if (rate < floor) rate = floor;
    /* app-limited: bursts (key frames) at the rate the last ones went through
       at, x 1.25 to find more (burst_bw, burst_on_acked) - to their end, when
       the ACKs of their first segments ended the app-limited period */
    if (bbr_burst(w) && (uint64_t)w->burst_bw * 5 / 4 > rate) rate = (uint64_t)w->burst_bw * 5 / 4;
    if (w->pace_rate_cfg > 0 && rate > (uint64_t)w->pace_rate_cfg) rate = (uint64_t)w->pace_rate_cfg;
    if (rate > 0xffffffffu) rate = 0xffffffffu;
    return (uint32_t)rate;
}

static void pace_refill(anl_t *w)
{
    int32_t dt;
    w->pace_rate = compute_pace_rate(w);
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

/* tokens left after the datagram being built: checking the bucket alone let
 * a segment that seals the previous datagram (spending its tokens) open the
 * next one regardless - two datagrams over the budget instead of one */
static int pace_can_send(const anl_t *w)
{
    return w->pace_tokens - (w->dg_has_data ? (int64_t)w->ptr : 0) > 0;
}

/* milliseconds until the bucket becomes positive again */
static uint32_t pace_wait_ms(const anl_t *w)
{
    int64_t need;
    if (w->pace_tokens > 0) return 0;
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

static void fbuf_free(fec_buf *b)
{
    anl_free(b->p);
    b->p = NULL;
    b->cap = b->len = 0;
}

/* capacity for n bytes; the content is not kept */
static int fbuf_reserve(fec_buf *b, uint32_t n)
{
    uint8_t *np;
    if (n <= b->cap) return 0;
    np = (uint8_t *)anl_malloc(n);
    if (np == NULL) return -1;
    anl_free(b->p);
    b->p = np;
    b->cap = n;
    return 0;
}

static void fec_free(anl_stream *st)
{
    uint32_t i;
    st->fec_n = 0;                  /* an open block would be closed later on freed buffers */
    st->fec_out_i = st->fec_out_m = 0;
    if (st->fec_slot) {
        for (i = 0; i < FEC_K_MAX; i++) fbuf_free(&st->fec_slot[i]);
        anl_free(st->fec_slot);
        st->fec_slot = NULL;
    }
    if (st->fec_out) {
        for (i = 0; i < FEC_M_MAX; i++) fbuf_free(&st->fec_out[i]);
        anl_free(st->fec_out);
        st->fec_out = NULL;
    }
    if (st->cache) {
        for (i = 0; i < st->cache_n; i++) fbuf_free(&st->cache[i].b);
        anl_free(st->cache);
        st->cache = NULL;
    }
    if (st->pcache) {
        for (i = 0; i < st->pcache_n; i++) fbuf_free(&st->pcache[i].b);
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
 * segments have gone out (control_stream). A reliable stream first delivers
 * everything both ways; a semi-reliable one is aborted - what is still in
 * flight is dropped, frames already queued for the application stay readable. */
static void stream_try_release(anl_t *w, anl_stream *st)
{
    if (st->state != ANL_STREAM_CLOSING || !st->peer_closed) return;
    if (!st->peer_released && st->mode == ANL_RELIABLE) {
        if (st->nsnd_buf > 0 || st->nsnd_que > 0) return;
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

/* Delay measurement (DESIGN 6.9). transit = local time - the peer's send
 * time: unknown clock offset plus the one-way delay; its minimum over
 * 5..10 s is the propagation time, anything above it is queueing,
 * retransmission or reassembly. */
static int32_t rp_base(const anl_stream *st)
{
    return (int32_t)(st->rp_min_old - st->rp_min_cur) < 0 ? st->rp_min_old : st->rp_min_cur;
}

static void rp_packet(anl_t *w, anl_stream *st, uint32_t ts)
{
    int32_t transit = (int32_t)(w->current - ts), d;
    uint32_t q;
    if (!st->rp_have) {
        st->rp_have = 1;
        st->rp_prev = st->rp_min_cur = st->rp_min_old = transit;
        st->rp_win_ts = w->current;
    }
    d = transit - st->rp_prev;
    if (d < 0) d = -d;
    st->rp_jit16 += (uint32_t)d - st->rp_jit16 / 16;    /* J += (|D| - J) / 16 */
    st->rp_prev = transit;
    if (tdiff(w->current, st->rp_win_ts) >= DELAY_WIN_MS) {
        st->rp_min_old = st->rp_min_cur;
        st->rp_min_cur = transit;
        st->rp_win_ts = w->current;
    } else if (transit - st->rp_min_cur < 0) {
        st->rp_min_cur = transit;
    }
    q = (uint32_t)(transit - rp_base(st));          /* >= 0: the base is a minimum */
    st->rp_qsum += q;
    st->rp_qn++;
    st->rp_qmax = umax32(st->rp_qmax, q);
}

/* a segment reached rcv_queue in order: frames (messages) complete here */
static void rp_segment(anl_t *w, anl_stream *st, const anl_seg *s)
{
    uint32_t d;
    if (!st->rp_have) return;
    if (!st->rp_in_frame || tdiff(s->ts_sent, st->rp_frm_ts) < 0) st->rp_frm_ts = s->ts_sent;
    st->rp_in_frame = 1;
    if (s->frg != 0) return;
    st->rp_in_frame = 0;
    d = (uint32_t)((int32_t)(w->current - st->rp_frm_ts) - rp_base(st));
    if ((int32_t)d < 0) d = 0;
    st->rp_fsum += d;
    st->rp_fn++;
    st->rp_fmax = umax32(st->rp_fmax, d);
}

/* close the measurement interval: rp_last is what stats and the report show */
static void rp_close_interval(anl_t *w, anl_stream *st)
{
    anl_delay_report *r = &st->rp_last;
    r->valid = 1;
    r->jitter_ms = st->rp_jit16 / 16;
    r->qdelay_avg_ms = st->rp_qn ? st->rp_qsum / st->rp_qn : 0;
    r->qdelay_max_ms = st->rp_qmax;
    r->frame_delay_avg_ms = st->rp_fn ? st->rp_fsum / st->rp_fn : 0;
    r->frame_delay_max_ms = st->rp_fmax;
    r->frames = st->rp_fn;
    r->frames_skipped = st->frames_skipped;
    r->fec_recovered = st->fec_recovered;
    st->rp_last_ts = w->current;
    st->rp_qsum = st->rp_qn = st->rp_qmax = st->rp_fsum = st->rp_fn = st->rp_fmax = 0;
}

/* move contiguous segments from rcv_buf to rcv_queue (ikcp) */
static void move_to_queue(anl_t *w, anl_stream *st)
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
        rp_segment(w, st, s);
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
    st->rp_in_frame = 0;                    /* the partial frame was dropped */
    move_to_queue(w, st);
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

/* GF(2^8), polynomial 0x11d. The tables are built once (anl_create). */
static uint8_t gf_exp[512], gf_log[256];

static void gf_init(void)
{
    uint32_t i, x = 1;
    if (gf_exp[0] == 1) return;
    for (i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;
    }
    for (i = 255; i < 512; i++) gf_exp[i] = gf_exp[i - 255];
}

static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    return (a && b) ? gf_exp[gf_log[a] + gf_log[b]] : 0;
}

static uint8_t gf_inv(uint8_t a) { return gf_exp[255 - gf_log[a]]; }

/* dst ^= c * src */
static void gf_addmul(uint8_t *dst, const uint8_t *src, uint32_t len, uint8_t c)
{
    uint32_t i, lc;
    if (c == 0) return;
    if (c == 1) { for (i = 0; i < len; i++) dst[i] ^= src[i]; return; }
    lc = gf_log[c];
    for (i = 0; i < len; i++) if (src[i]) dst[i] ^= gf_exp[lc + gf_log[src[i]]];
}

/* Cauchy matrix: parity j of a block is sum_i C(j, i) * data_i with
 * C(j, i) = 1 / (x_j + y_i), x_j = FEC_K_MAX + j, y_i = i. All x and y are
 * distinct, so every square submatrix is invertible: any m of the k + m
 * packets that are lost can be rebuilt (DESIGN 8.3). */
static uint8_t fec_coef(uint32_t j, uint32_t i)
{
    return gf_inv((uint8_t)((FEC_K_MAX + j) ^ i));
}

/* invert the t x t matrix a (row-major) into inv; 0 on success */
static int gf_invert(uint8_t *a, uint8_t *inv, uint32_t t)
{
    uint32_t r, c, k;
    memset(inv, 0, t * t);
    for (r = 0; r < t; r++) inv[r * t + r] = 1;
    for (c = 0; c < t; c++) {
        uint8_t f;
        for (r = c; r < t && a[r * t + c] == 0; r++) ;
        if (r == t) return -1;
        if (r != c) {
            for (k = 0; k < t; k++) {
                uint8_t x = a[r * t + k]; a[r * t + k] = a[c * t + k]; a[c * t + k] = x;
                x = inv[r * t + k]; inv[r * t + k] = inv[c * t + k]; inv[c * t + k] = x;
            }
        }
        f = gf_inv(a[c * t + c]);
        for (k = 0; k < t; k++) { a[c * t + k] = gf_mul(a[c * t + k], f); inv[c * t + k] = gf_mul(inv[c * t + k], f); }
        for (r = 0; r < t; r++) {
            if (r == c || a[r * t + c] == 0) continue;
            f = a[r * t + c];
            for (k = 0; k < t; k++) {
                a[r * t + k] ^= gf_mul(f, a[c * t + k]);
                inv[r * t + k] ^= gf_mul(f, inv[c * t + k]);
            }
        }
    }
    return 0;
}

static void fec_cache_add(anl_stream *st, uint32_t sn, uint32_t frg, uint8_t flags,
                          uint16_t frame16, const char *data, uint32_t len)
{
    fec_centry *e;
    if (st->cache == NULL || len > st->mss) return;
    e = &st->cache[sn % st->cache_n];
    if (fbuf_reserve(&e->b, len + CANON_HDR_MAX) < 0) { e->valid = 0; return; }
    e->valid = 1;
    e->sn = sn;
    e->b.len = canon_build(e->b.p, frg, flags, frame16, data, len);
}

/* deliver a rebuilt canonical encoding as the DATA segment sn */
static void fec_deliver(anl_t *w, anl_stream *st, uint32_t sn, const uint8_t *c, uint32_t clen, uint32_t ts)
{
    const char *p = (const char *)c, *end = p + clen;
    uint32_t frg, plen, b1;
    uint16_t frame16 = 0;
    uint8_t flags;
    if (tdiff(sn, st->rcv_nxt) < 0 || tdiff(sn, st->rcv_nxt + st->rcv_wnd) >= 0 || clen < 3) return;
    b1 = dec8(&p);
    flags = (uint8_t)(b1 & (F_HAS_FRAME | F_KEY));
    frg = b1 & F_FRG_MASK;
    if (frg == 31) {
        uint32_t ext;
        if (dec_varint(&p, end, &ext) < 0) return;
        frg = 31 + ext;
    }
    if (flags & F_HAS_FRAME) {
        if (end - p < 2) return;
        frame16 = dec16(&p);
    }
    if (end - p < 2) return;
    plen = dec16(&p);
    if ((uint32_t)(end - p) < plen) return;
    st->fec_recovered++;
    handle_data(w, st, sn, frg, flags, frame16, p, plen, ts, 1);
}

/* Try to decode the block (base, k) from the cached data packets and the
 * parities waiting in pcache. Returns 0 when done with the block (decoded,
 * nothing missing, or nothing left worth rebuilding), 1 to keep waiting. */
static int fec_block_decode(anl_t *w, anl_stream *st, uint32_t base, uint32_t k, uint32_t ts)
{
    uint32_t miss[FEC_M_MAX], row[FEC_M_MAX], known[FEC_K_MAX];
    uint8_t a[FEC_M_MAX * FEC_M_MAX], inv[FEC_M_MAX * FEC_M_MAX];
    uint32_t i, t = 0, nk = 0, np = 0, useful = 0, lmax = 0, x, y;
    uint8_t *out = (uint8_t *)w->scratch;

    for (i = 0; i < k; i++) {
        uint32_t sn = base + i;
        fec_centry *e = &st->cache[sn % st->cache_n];
        if (e->valid && e->sn == sn) { known[nk++] = i; continue; }
        if (t == FEC_M_MAX) return 1;               /* more missing than any block can repair: wait */
        miss[t++] = i;
        if (tdiff(sn, st->rcv_nxt) >= 0) useful = 1;
    }
    if (t == 0 || !useful) return 0;
    for (i = 0; i < st->pcache_n && np < t; i++) {
        fec_pentry *e = &st->pcache[i];
        if (!e->valid || e->base != base || e->k != k) continue;
        if (np == 0) lmax = e->b.len;
        else if (e->b.len != lmax) continue;
        row[np++] = i;
    }
    if (np < t) return 1;                           /* too few parities so far */
    if (lmax > w->mtu) return 0;

    /* A[x][y] = C(j of parity x, missing y); missing_y = sum_x inv[y][x] * (P_x - known part) */
    for (x = 0; x < t; x++)
        for (y = 0; y < t; y++) a[x * t + y] = fec_coef(st->pcache[row[x]].j, miss[y]);
    if (gf_invert(a, inv, t) < 0) return 0;
    for (y = 0; y < t; y++) {
        uint32_t sn = base + miss[y];
        if (tdiff(sn, st->rcv_nxt) < 0) continue;   /* skipped meanwhile: no use */
        memset(out, 0, lmax);
        for (x = 0; x < t; x++) gf_addmul(out, st->pcache[row[x]].b.p, lmax, inv[y * t + x]);
        for (i = 0; i < nk; i++) {
            fec_centry *e = &st->cache[(base + known[i]) % st->cache_n];
            uint8_t c = 0;
            for (x = 0; x < t; x++) c ^= gf_mul(inv[y * t + x], fec_coef(st->pcache[row[x]].j, known[i]));
            gf_addmul(out, e->b.p, umin32(e->b.len, lmax), c);
        }
        fec_deliver(w, st, sn, out, lmax, ts);
    }
    return 0;
}

static void fec_drop_block(anl_stream *st, uint32_t base, uint32_t k)
{
    uint32_t i;
    for (i = 0; i < st->pcache_n; i++)
        if (st->pcache[i].valid && st->pcache[i].base == base && st->pcache[i].k == k) st->pcache[i].valid = 0;
}

/* a parity waits for at most this long for the rest of its block */
static uint32_t fec_parity_ttl(const anl_t *w)
{
    return umax32(2u * (uint32_t)w->rx_rto, 2u * FEC_BLOCK_MS);
}

/* a DATA segment arrived: blocks that were waiting for it may decode now */
static void fec_retry_pending(anl_t *w, anl_stream *st)
{
    uint32_t i, j;
    if (st->pcache == NULL || st->in_retry) return;
    st->in_retry = 1;
    for (i = 0; i < st->pcache_n; i++) {
        fec_pentry *e = &st->pcache[i];
        int seen = 0;
        if (!e->valid) continue;
        if (tdiff(w->current, e->ts) > (int32_t)fec_parity_ttl(w)) { e->valid = 0; continue; }
        for (j = 0; j < i && !seen; j++)
            seen = st->pcache[j].valid && st->pcache[j].base == e->base && st->pcache[j].k == e->k;
        if (seen) continue;                         /* block already tried */
        if (fec_block_decode(w, st, e->base, e->k, e->ts) == 0) fec_drop_block(st, e->base, e->k);
    }
    st->in_retry = 0;
}

static void handle_parity(anl_t *w, anl_stream *st, const char *body, uint32_t blen, uint32_t ts)
{
    const char *p = body;
    uint32_t base, k, m, jj, lmax, i, slot = 0;
    fec_pentry *e;
    if (!st->fec || st->cache == NULL || blen < PARITY_HDR) return;
    base = extend16(dec16(&p), st->rcv_nxt);
    k = dec8(&p);
    m = dec8(&p);
    jj = dec8(&p);
    lmax = blen - PARITY_HDR;
    if (k < 1 || k > FEC_K_MAX || m < 1 || m > FEC_M_MAX || jj >= m) return;
    if (lmax == 0 || lmax > st->mss + CANON_HDR_MAX) return;
    if (tdiff(base + k, st->rcv_nxt) <= 0) return;  /* the whole block is behind us */
    for (i = 0; i < st->pcache_n; i++) {
        fec_pentry *q = &st->pcache[i];
        if (q->valid && q->base == base && q->k == k && q->j == jj) return;     /* duplicate */
        if (!q->valid) { slot = i; break; }
        if (tdiff(q->ts, st->pcache[slot].ts) < 0) slot = i;
    }
    e = &st->pcache[slot];
    if (fbuf_reserve(&e->b, lmax) < 0) return;
    e->valid = 1;
    e->base = base;
    e->k = k;
    e->m = m;
    e->j = jj;
    e->ts = w->current;
    e->b.len = lmax;
    memcpy(e->b.p, p, lmax);
    if (fec_block_decode(w, st, base, k, ts) == 0) fec_drop_block(st, base, k);
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
    seg->ts_sent = ts;                      /* receiver: the peer's send time (rp_segment) */
    if (!recovered) rp_packet(w, st, ts);
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
    move_to_queue(w, st);
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
/* the time RACK measures from: the last transmission, or - for a first
 * transmission covered by FEC - the parity of its group, which the peer can
 * rebuild it from. Otherwise RACK declares it lost (and a semi-reliable
 * stream may abandon it and send FWD) while the recovery is on its way. */
static uint32_t rack_sent(const anl_seg *seg)
{
    if (seg->xmit == 1 && seg->fec_ts != 0 && tdiff(seg->fec_ts, seg->ts_sent) > 0) return seg->fec_ts;
    return seg->ts_sent;
}

static int rack_candidate(const anl_t *w, const anl_stream *st, const anl_seg *seg)
{
    uint32_t ts = rack_sent(seg);
    if (seg->xmit == 0 || seg->lost) return 0;
    if (w->rack_valid && tdiff(ts, w->rack_ts) < 0) return 1;
    return st->rack_valid && tdiff(ts, st->rack_ts) <= 0 && tdiff(seg->sn, st->rack_hi) < 0;
}

/* RACK loss detection (RFC 8985): a segment sent before the newest delivered
 * datagram is lost once it has been outstanding for that one's RTT plus the
 * reordering window. Runs on every ACK and on every flush (the timer). */
static int rack_detect(anl_t *w, anl_stream *st)
{
    anl_node *pos;
    uint32_t wait;
    int marked = 0;
    if (!w->rack_valid) return 0;
    wait = w->rack_rtt + reo_wnd(w, st);
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        if (rack_candidate(w, st, s) && tdiff(w->current, rack_sent(s) + wait) >= 0) {
            s->lost = 1;
            marked++;
        }
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

/*--------------------------------------------------------------------
 * congestion control: BBRv2, PROBE_BW as in BBRv3 (DESIGN 6.8)
 *
 * Model: the bottleneck bandwidth btl_bw (max delivery rate over the last 10
 * round trips) and the round-trip propagation time min_rtt. Pacing rate =
 * pacing_gain * btl_bw, cwnd = cwnd_gain * BDP, bounded by inflight_hi after
 * congestive loss. btl_bw is also the bandwidth estimate handed to the
 * application (anl_get_stats), for example to set the encoder bitrate.
 *-------------------------------------------------------------------*/

enum { BBR_DOWN, BBR_CRUISE, BBR_REFILL, BBR_UP };    /* PROBE_BW phases (BBRv3) */

typedef struct bbr_sample {             /* the delivery rate sample of one ACK */
    int valid, app_limited;
    uint64_t prior_delivered, prior_fec;
    uint32_t prior_ts, send_ts, first_sent;
    uint32_t sent;                      /* wire bytes sent over the sample's send interval */
} bbr_sample;

/* the model's bandwidth: btl_bw, held down by bw_lo after congestive loss -
   the max filter alone would remember a bandwidth that is gone for 10 rounds */
static uint32_t bbr_bw(const anl_t *w)
{
    uint32_t bw = w->bw_lo != 0 && w->bw_lo < w->btl_bw ? w->bw_lo : w->btl_bw;
    /* policed: the policer's rate itself - without probing (compute_pace_rate)
       the filter only saw its own pace minus the loss and ratcheted down,
       27 -> 18 Mbps over a minute on a 30 Mbps path (DESIGN 13.25); testing:
       at most that rate */
    if (w->lt_state == 2) return w->lt_rate;
    return w->lt_state != 0 && w->lt_rate < bw ? w->lt_rate : bw;
}

/* A token-bucket policer drops what exceeds its rate without queueing it:
 * loss without a queue, which BBR here does not take as congestion (random
 * loss on a radio link looks the same), and the send-rate credit then keeps
 * the sender at up to 1.5x the rate - 40% of the packets lost (a home uplink,
 * real network, DESIGN 13.22). Told apart by the response (BBRv1's long-term
 * sampling plus a test): two intervals (>= 16 rounds and 300 ms) in a row,
 * network-limited, no queue, over 20% lost, delivering the same rate within
 * 1/8 - then an interval paced at that rate. A policer's share of the loss
 * goes (random loss on top of it stays): at least halved is a policer,
 * policed for 48 intervals (then watched again); otherwise 48 intervals
 * without suspicion. Bursty random loss varies a lot between intervals:
 * with 10%, a third and 8 rounds 4 of 20 soak runs took 5% burst loss for a
 * policer. */
static void bbr_policer(anl_t *w, uint64_t rd, uint64_t lost, int app_limited)
{
    uint32_t dur, rate, loss;
    if (w->lt_ts == 0) { w->lt_ts = w->current | 1; w->lt_sent0 = w->sent_wire; }
    w->lt_rd += rd;
    w->lt_lost += lost;
    w->lt_rounds++;
    if (app_limited || bbr_queue_signal(w)) w->lt_bad = 1;
    dur = (uint32_t)tdiff(w->current, w->lt_ts);
    if (w->lt_rounds < 16 || dur < 300) return;
    rate = (uint32_t)umin32((uint32_t)(w->lt_rd * 1000 / dur), 0xffffffffu);
    loss = w->lt_rd + w->lt_lost > 0 ? (uint32_t)(w->lt_lost * 1000 / (w->lt_rd + w->lt_lost)) : 0;
    if (w->lt_state == 1) {                             /* the test interval */
        /* its loss from what it sent and what was delivered: the losses
           counted in it are mostly of what was sent before, found a round
           or more later - at 100 ms RTT they failed every test (sent 1.21
           MB/s, delivered 1.21, "lost" 36%), then held for 48 intervals at
           1.5x the policer's rate, a third lost (DESIGN 13.25) */
        uint32_t sent = w->sent_wire - w->lt_sent0;
        loss = sent > w->lt_rd ? (uint32_t)((sent - w->lt_rd) * 1000 / sent) : 0;
        if (loss * 2 < w->lt_ref_loss) {
            /* what is still lost at the policer's rate is random loss: send
               that much more, or random loss on top would pace below the rate */
            w->lt_rate = (uint32_t)umin32((uint32_t)((uint64_t)w->lt_rate * 1000 / (1000 - umin32(loss, 500))), 0xffffffffu);
            w->lt_state = 2;
            w->lt_left = 48;
        }
        else { w->lt_state = 0; w->lt_hold = 48; }
        w->lt_prev_rate = 0;
    } else if (w->lt_state == 2) {
        if (--w->lt_left == 0) { w->lt_state = 0; w->lt_prev_rate = 0; }
    } else if (w->lt_hold > 0) {
        w->lt_hold--;
    } else if (!w->lt_bad && loss > 100) {
        /* over 10% lost, rates within 1/4: a test costs one interval at the
           delivery rate, and the test itself tells a policer from random
           loss - over 20% and within 1/8 missed a 50 Mbps uplink whose rate
           jitters, and the sender stayed at 1.7x it with a fifth of the
           packets lost for over a minute (real network, DESIGN 13.26) */
        if (w->lt_prev_rate != 0 && rate + w->lt_prev_rate / 4 >= w->lt_prev_rate && rate <= w->lt_prev_rate + w->lt_prev_rate / 4) {
            w->lt_state = 1;
            w->lt_rate = (uint32_t)(((uint64_t)rate + w->lt_prev_rate) / 2);
            w->lt_ref_loss = (loss + w->lt_prev_loss) / 2;
        } else {
            w->lt_prev_rate = rate;
            w->lt_prev_loss = loss;
        }
    } else {
        w->lt_prev_rate = 0;
    }
    w->lt_rd = w->lt_lost = 0;
    w->lt_rounds = 0;
    w->lt_bad = 0;
    w->lt_ts = w->current | 1;
    w->lt_sent0 = w->sent_wire;
}

/* The RTT the model works with: min_rtt, but not below the update interval.
 * RTT samples are taken against the time of the last anl_update, up to an
 * interval old when a datagram arrives in between: on a path of a few ms a
 * sample of 1 ms stood for 10 s in min_rtt, cwnd (2 x bw x min_rtt) fell to 4
 * segments and the delivery rate - and btl_bw - with it (real network, DESIGN
 * 13.22). The sender also acts only every interval: cwnd has to cover that. */
static uint32_t bbr_rtt(const anl_t *w)
{
    return umax32(w->min_rtt, (uint32_t)w->interval);
}

static uint64_t bbr_bdp(const anl_t *w)
{
    return (uint64_t)bbr_bw(w) * bbr_rtt(w) / 1000;
}

static uint64_t bbr_inflight_bytes(const anl_t *w)
{
    return (uint64_t)w->inflight_segs * w->avg_seg;
}

/* A queue has built up: even the smallest RTT sample of the last round is
 * well above min_rtt. Jitter makes single samples high, but some samples of
 * a round stay low; a standing queue raises all of them. Tells congestive
 * loss from random (radio) loss. */
static int bbr_queue_signal(const anl_t *w)
{
    return w->min_rtt > 0 && w->prev_round_min_rtt > bbr_rtt(w) + umax32(bbr_rtt(w) / 4, 5);
}

static void bbr_set_cwnd(anl_t *w)
{
    uint32_t segs;
    if (w->btl_bw == 0 || w->min_rtt == 0) {
        segs = w->init_cwnd;
    } else {
        uint64_t bdp = bbr_bdp(w);
        uint64_t target = bdp * w->cwnd_gain / BBR_UNIT + 3u * w->avg_seg;     /* + send / ACK quanta */
        if (w->inflight_hi != 0 && target > w->inflight_hi) target = w->inflight_hi;
        segs = (uint32_t)umin32((uint32_t)(target / w->avg_seg), ANL_MAX_WND);
        if (w->bbr_state == ANL_BBR_PROBE_RTT)          /* BBRv2: half the BDP, not 4 packets */
            segs = umin32(segs, (uint32_t)(bdp / 2 / w->avg_seg));
    }
    if (bbr_headroom(w)) segs = umax32(segs, w->init_cwnd);     /* room for an app-limited burst */
    /* ... and a window for the rate bursts go out at: on a short path the
       model's BDP (the application's average rate) held a key frame to 13
       segments per RTT, 20 ms instead of 5 (DESIGN 13.23) */
    if (bbr_burst(w) && w->min_rtt != 0) {
        uint64_t target = (uint64_t)w->burst_bw * bbr_rtt(w) / 1000u * 2u + 3u * w->avg_seg;
        if (w->inflight_hi != 0 && target > w->inflight_hi) target = w->inflight_hi;
        segs = umax32(segs, (uint32_t)umin32((uint32_t)(target / w->avg_seg), ANL_MAX_WND));
    }
    if (tdiff(w->round_count, w->rto_round) < 0)        /* after an RTO: packet conservation */
        segs = umin32(segs, umax32(w->rto_inflight, BBR_MIN_CWND));
    w->cwnd = umax32(segs, BBR_MIN_CWND);
}

static void bbr_set_phase(anl_t *w, int phase)
{
    static const uint16_t gain[4] = { BBR_DOWN_GAIN, BBR_UNIT, BBR_UNIT, BBR_UP_GAIN };
    w->probe_phase = phase;
    w->phase_ts = w->current;
    w->pacing_gain = gain[phase];
    if (phase == BBR_DOWN) {                            /* schedule the next probe */
        uint8_t r[2];
        prng_bytes(w, r, 2);
        w->probe_ts = w->current + BBR_PROBE_WAIT_MS + (uint32_t)((r[0] << 8 | r[1]) % 1001);
        w->probe_round = w->round_count;
    } else if (phase == BBR_REFILL) {
        w->bw_lo = 0;                                   /* about to probe: forget the lower bound */
        w->phase_round = w->round_count + 1;
    } else if (phase == BBR_UP) {
        w->up_bw = w->btl_bw;
        w->up_stall = 0;
    }
}

/* BBRv3: probe after 2..3 s, or sooner at a small BDP - after as many
   rounds as the BDP has packets (at most 63), the pace at which Reno would
   grow cwnd by one BDP. Without it bw_lo, cut on every lossy round, would
   outlive the bandwidth filter on long lossy paths and the model would
   shrink to nothing between probes. */
static int bbr_probe_due(const anl_t *w)
{
    uint32_t pkts = umin32(umin32((uint32_t)(bbr_bdp(w) / w->avg_seg), w->cwnd), 63);
    return tdiff(w->current, w->probe_ts) >= 0 || tdiff(w->round_count, w->probe_round) >= (int32_t)pkts;
}

static void bbr_enter_probe_bw(anl_t *w)
{
    w->bbr_state = ANL_BBR_PROBE_BW;
    w->cwnd_gain = BBR_CWND_GAIN;
    bbr_set_phase(w, BBR_DOWN);
}

/* min_rtt over BBR_MIN_RTT_WIN; when it expires, PROBE_RTT drains the queue */
static void bbr_update_min_rtt(anl_t *w, int32_t rtt)
{
    int expired = w->min_rtt != 0 && tdiff(w->current, w->min_rtt_ts) > BBR_MIN_RTT_WIN;
    if (w->min_rtt == 0 || (uint32_t)rtt <= w->min_rtt || expired) {
        w->min_rtt = umax32((uint32_t)rtt, 1);
        w->min_rtt_ts = w->current;
    }
    /* an app-limited sender keeps no queue: its samples are the propagation
       time already, and halving cwnd would only make frames wait */
    if (expired && w->bbr_state != ANL_BBR_PROBE_RTT && w->app_limited == 0) {
        w->bbr_state = ANL_BBR_PROBE_RTT;
        w->pacing_gain = BBR_UNIT;
        w->cwnd_gain = BBR_CWND_GAIN;
        w->prior_cwnd = w->cwnd;
        w->probe_rtt_done_ts = 0;
    }
}

/* a new round trip begins: bandwidth filter slot, loss bounds, STARTUP exit */
static void bbr_round_end(anl_t *w, int app_limited)
{
    uint64_t rd = w->delivered - w->round_delivered0, lost = w->lost_bytes - w->round_lost0;
    uint32_t i;
    w->prev_round_min_rtt = w->round_min_rtt;
    w->round_min_rtt = 0;
    bbr_policer(w, rd, lost, app_limited);
    /* BBRv2: congestive loss bounds inflight - loss while a queue stands.
       Loss without a queue (radio, random) does not: on lossy links it would
       throttle to nothing. Heavy loss without a queue (a policer) counts only
       in PROBE_BW: in STARTUP the first RTOs, before any RTT sample, are
       often spurious (initial RTO below the path RTT). */
    /* The path's RTT went up (route change, new link): every round now looks
       queued against the old min_rtt for up to BBR_MIN_RTT_WIN, and random
       loss looks congestive - each round would cut the model by 0.7 until
       nothing is left. The two differ in the delivery rate while we cut: at
       a bottleneck that got slower it stays at the link rate (the queue stays
       full until we are below it), on a longer path it falls with each cut.
       BBR_PATH_ROUNDS congestive rounds, each delivering 15% less than the
       one before (or app-limited), while the queue signal stays (rounds
       without loss in between do not reset the count, only the queue going
       away does): take the round's RTT as min_rtt and undo the cuts (btl_bw
       still holds the rate). */
    {
        uint32_t dur = (uint32_t)tdiff(w->current, w->round_ts);
        uint32_t rate = dur > 0 ? (uint32_t)umin32((uint32_t)(rd * 1000 / dur), 0xffffffffu) : 0;
        int cong = rd + lost > 0 && lost * 100 > BBR_LOSS_THRESH * (rd + lost) && bbr_queue_signal(w);
        /* an app-limited sender builds no queue at all: counts too */
        if (cong && (app_limited || (w->last_round_rate != 0 && (uint64_t)rate * 100 < (uint64_t)w->last_round_rate * 85))) w->qfall++;
        else if (!bbr_queue_signal(w)) w->qfall = 0;
        w->last_round_rate = rate;
        w->round_ts = w->current;
        if (w->qfall >= BBR_PATH_ROUNDS) {
            w->min_rtt = w->prev_round_min_rtt;
            w->min_rtt_ts = w->current;
            w->bw_lo = 0;
            w->inflight_hi = 0;
            w->qfall = 0;
        }
    }
    if (rd + lost > 0 && ((lost * 100 > BBR_LOSS_THRESH * (rd + lost) && bbr_queue_signal(w)) ||
                          (w->bbr_state == ANL_BBR_PROBE_BW && lost * 100 > BBR_LOSS_BLIND * (rd + lost)))) {
        uint64_t cur = (uint64_t)w->cwnd * w->avg_seg;
        uint64_t hi = cur * BBR_BETA / BBR_UNIT;
        /* the round's delivery rate is what the path has now (not below 0.7x
           per round: one lossy round must not wipe the model out) */
        w->bw_lo = umax32(w->round_bw, (uint32_t)((uint64_t)bbr_bw(w) * BBR_BETA / BBR_UNIT));
        w->inflight_hi = hi > bbr_bdp(w) ? hi : bbr_bdp(w);
        w->clean_rounds = 0;
        if (w->bbr_state == ANL_BBR_STARTUP) w->full_bw_reached = 1;
        if (w->bbr_state == ANL_BBR_PROBE_BW && w->probe_phase >= BBR_REFILL)
            bbr_set_phase(w, BBR_DOWN);                 /* the probe found the limit */
    } else if (w->inflight_hi != 0 && w->bbr_state == ANL_BBR_PROBE_BW && ++w->clean_rounds >= 2) {
        w->inflight_hi += w->inflight_hi / 4;           /* probe the bound upwards again */
        if (w->inflight_hi > 4 * bbr_bdp(w) + 8u * w->avg_seg) w->inflight_hi = 0;
    }
    if (rd + lost > 0) {
        uint32_t frac = (uint32_t)(lost * 256 / (rd + lost));
        w->loss_rate = (uint32_t)((int32_t)w->loss_rate + ((int32_t)frac - (int32_t)w->loss_rate) / 4);
    }
    w->round_delivered0 = w->delivered;
    w->round_lost0 = w->lost_bytes;
    /* STARTUP ends when the bandwidth stops growing by 25% for 3 rounds -
       or when a round lost over 40% of what it sent: a policer's bucket let
       the doubling run far past its rate (20000 of 26000 retransmissions of
       a 75 s stream were STARTUP's, DESIGN 13.26). Only once the model has
       grown to 4x the initial rate: a path that dropped everything in its
       first second otherwise left STARTUP at almost nothing, and PROBE_BW
       took 70 s to reach 60 Mbps (DESIGN 13.25). No inflight bound: the
       loss may be random. */
    if (w->bbr_state == ANL_BBR_STARTUP && !w->full_bw_reached && w->min_rtt != 0 &&
        (uint64_t)w->btl_bw * w->min_rtt >= 4000ull * w->init_cwnd * w->mss &&
        lost > 8u * w->avg_seg && lost * 100 > 40 * (rd + lost))
        w->full_bw_reached = 1;
    if (w->bbr_state == ANL_BBR_STARTUP && !w->full_bw_reached && !app_limited && w->btl_bw != 0) {
        if (w->btl_bw >= w->full_bw + w->full_bw / 4) { w->full_bw = w->btl_bw; w->full_bw_cnt = 0; }
        else if (++w->full_bw_cnt >= 3) w->full_bw_reached = 1;
    }
    /* The filter window advances only over rounds that measured the network:
       a round of app-limited samples (video between key frames) shows what
       the application sent, not that the path got slower - the peak of the
       last key frame is kept for the next one. */
    if (w->round_net_sample) {
        w->bw_idx = (w->bw_idx + 1) % BBR_BW_ROUNDS;
        w->bw_round[w->bw_idx] = 0;
        w->btl_bw = 0;
        for (i = 0; i < BBR_BW_ROUNDS; i++) w->btl_bw = umax32(w->btl_bw, w->bw_round[i]);
    }
    w->round_net_sample = 0;
    w->round_bw = 0;
    if (w->bbr_state == ANL_BBR_PROBE_BW && w->probe_phase == BBR_UP) {
        if (w->btl_bw >= w->up_bw + w->up_bw / 4) { w->up_bw = w->btl_bw; w->up_stall = 0; }
        else w->up_stall++;
    }
}

static void bbr_update_state(anl_t *w)
{
    uint32_t rtt = w->min_rtt ? w->min_rtt : RTO_DEF;
    switch (w->bbr_state) {
    case ANL_BBR_STARTUP:
        if (w->full_bw_reached) {
            w->bbr_state = ANL_BBR_DRAIN;
            w->pacing_gain = BBR_DRAIN_GAIN;
        }
        break;
    case ANL_BBR_DRAIN:
        if (bbr_inflight_bytes(w) <= bbr_bdp(w)) bbr_enter_probe_bw(w);
        break;
    case ANL_BBR_PROBE_BW:
        /* BBRv3: DOWN (0.9) drains the probe's queue down to the BDP,
           CRUISE (1.0) holds until the next probe, 2..3 s later - probing
           every few rounds would put a queue spike into every audio stream
           (sooner at a small BDP, bbr_probe_due); REFILL (1.0) refills the
           pipe for a round, UP (1.25) probes and keeps going while btl_bw
           grows, until the pipe is full (inflight 1.25 BDP), loss
           (bbr_round_end) or two rounds without 25% growth */
        switch (w->probe_phase) {
        case BBR_DOWN:
            if (bbr_probe_due(w)) bbr_set_phase(w, BBR_REFILL);
            else if (bbr_inflight_bytes(w) <= bbr_bdp(w)) bbr_set_phase(w, BBR_CRUISE);
            break;
        case BBR_CRUISE:
            if (bbr_probe_due(w)) bbr_set_phase(w, BBR_REFILL);
            break;
        case BBR_REFILL:
            if (tdiff(w->round_count, w->phase_round) >= 0) bbr_set_phase(w, BBR_UP);
            break;
        case BBR_UP:
            if (tdiff(w->current, w->phase_ts) >= (int32_t)rtt &&
                (bbr_inflight_bytes(w) >= bbr_bdp(w) * BBR_UP_GAIN / BBR_UNIT || w->up_stall >= 2))
                bbr_set_phase(w, BBR_DOWN);
            break;
        }
        break;
    case ANL_BBR_PROBE_RTT:
        if (w->probe_rtt_done_ts == 0) {
            if (w->inflight_segs <= w->cwnd) {
                w->probe_rtt_done_ts = (w->current + BBR_PROBE_RTT_MS) | 1;
                w->probe_rtt_round = w->round_count + 1;
            }
        } else if (tdiff(w->current, w->probe_rtt_done_ts) >= 0 && tdiff(w->round_count, w->probe_rtt_round) >= 0) {
            w->min_rtt_ts = w->current;
            if (w->full_bw_reached) bbr_enter_probe_bw(w);
            else { w->bbr_state = ANL_BBR_STARTUP; w->pacing_gain = BBR_STARTUP_GAIN; }
        }
        break;
    }
}

/* a data segment was sent: remember the delivery state for its rate sample */
static void bbr_on_send(anl_t *w, anl_seg *seg)
{
    uint32_t wire = seg_wire(seg);
    if (w->inflight_segs == 0) {
        w->first_sent_ts = w->delivered_ts = w->current;
        w->first_sent_wire = w->sent_wire;
    }
    seg->burst_id = 0;
    if (w->burst_open && seg->xmit == 1) {
        if (w->burst_t0 == 0) { w->burst_t0 = w->current | 1; w->burst_sw0 = w->sent_wire; }
        seg->burst_id = w->burst_id;
        w->burst_t1 = w->current | 1;
        w->burst_sw1 = w->sent_wire + wire;
        if (--w->burst_left == 0) w->burst_open = 0;    /* sent: later data is not part of it */
    }
    w->sent_wire += wire;
    seg->rs_sent = w->sent_wire;
    seg->rs_sent_first = w->first_sent_wire;
    seg->rs_delivered = w->delivered;
    seg->rs_fec = w->delivered_fec;
    seg->rs_ts = w->delivered_ts;
    seg->rs_first = w->first_sent_ts;
    seg->rs_app = w->app_limited != 0;
    if (seg->xmit == 1) w->inflight_segs++;
    w->avg_seg = (uint32_t)umax32((uint32_t)((int32_t)w->avg_seg + ((int32_t)wire - (int32_t)w->avg_seg) / 8), 32);
}

/* A burst of an app-limited sender (a key frame) on a path whose RTT is
   longer than the burst: every rate sample spans burst plus RTT, a fraction
   of the rate the burst went through at - on a 100 ms path the estimate stays
   at the video's average rate and a 30 KB key frame takes 20 ms to leave
   (real network, DESIGN 13.23). The spacing of its ACKs shows the rate
   (packet-train dispersion): bytes of its segments acknowledged after the
   first one over the time since, capped at the rate it was sent at (ACK
   compression cannot raise it above that). Its own segments, tagged when
   sent: other traffic in flight (audio) does not matter. Not for the model -
   an estimate that full at once filled bottleneck queues in STARTUP and next
   to bulk traffic (s5, priority test) - but burst_bw, the rate an
   app-limited sender paces at (compute_pace_rate): 1.25x of it, so that the
   next burst can find more; less by a fifth when the burst queued. */
static void burst_on_acked(anl_t *w, const anl_seg *s)
{
    uint32_t el;
    uint64_t disp;
    if (s->burst_id == 0 || s->burst_id != w->burst_id || w->burst_done || s->xmit != 1) return;
    /* a queue the burst added beyond what it built itself: over the RTT
       its first segment saw (a home downlink jitters by 10 ms and more
       without any queue of ours: against min_rtt that halved burst_bw
       again and again, DESIGN 13.23); its segments wait behind each other
       at most the time its ACKs have taken so far (a burst sent at the
       bottleneck rate queues too). A queue already there is the model's
       (bbr_queue_signal stops burst pacing). */
    if (w->disp_ts == 0) {
        w->disp_ts = w->current | 1;
        w->disp_bytes = 0;
        w->burst_rtt0 = umax32(w->last_rtt > 0 ? (uint32_t)w->last_rtt : 0, bbr_rtt(w));
        return;
    }
    el = (uint32_t)tdiff(w->current, w->disp_ts);
    if (w->last_rtt > 0 && (uint32_t)w->last_rtt > w->burst_rtt0 + umax32(bbr_rtt(w) / 4, 5) + el) {
        /* what it went through at so far, at most 4/5 of the last; half
           without a measurement (a link that slowed down: soak bw2m) */
        w->burst_bw = w->burst_cur != 0 ? umin32(w->burst_cur, w->burst_bw / 5 * 4) : w->burst_bw / 2;
        w->burst_cur = 0;
        w->burst_done = 1;
        return;
    }
    w->disp_bytes += seg_wire(s) + s->fec_share;
    if (w->disp_bytes < 8u * w->avg_seg || el < 4) return;
    disp = (uint64_t)w->disp_bytes * 1000 / el;
    if (tdiff(w->burst_t1, w->burst_t0) > 0) {
        uint64_t sr = (uint64_t)(w->burst_sw1 - w->burst_sw0) * 1000 / (uint32_t)tdiff(w->burst_t1, w->burst_t0);
        if (disp > sr) disp = sr;
    }
    if (disp > 0xffffffffu) disp = 0xffffffffu;
    w->burst_cur = (uint32_t)disp;
}

/* a data segment was acknowledged */
static void bbr_on_acked(anl_t *w, const anl_seg *s, bbr_sample *rs)
{
    burst_on_acked(w, s);
    w->delivered += seg_wire(s);
    w->delivered_fec += s->fec_share;
    w->delivered_ts = w->current;
    if (w->inflight_segs > 0) w->inflight_segs--;
    if (rs == NULL) return;
    if (!rs->valid || s->rs_delivered > rs->prior_delivered ||
        (s->rs_delivered == rs->prior_delivered && tdiff(s->ts_sent, rs->send_ts) > 0)) {
        rs->valid = 1;
        rs->prior_delivered = s->rs_delivered;
        rs->prior_fec = s->rs_fec;
        rs->prior_ts = s->rs_ts;
        rs->send_ts = s->ts_sent;
        rs->first_sent = s->rs_first;
        rs->app_limited = s->rs_app;
        rs->sent = s->rs_sent - s->rs_sent_first;
        w->first_sent_ts = s->ts_sent;
        w->first_sent_wire = s->rs_sent;
    }
}

/* all segments of an input datagram are processed: one rate sample */
static void bbr_on_ack(anl_t *w, const bbr_sample *rs)
{
    uint64_t delivered;
    int32_t send_el, ack_el;
    uint32_t interval;
    if (w->app_limited != 0 && w->delivered > w->app_limited) w->app_limited = 0;
    if (rs->prior_delivered >= w->next_round_delivered) {
        w->next_round_delivered = w->delivered;
        w->round_count++;
        bbr_round_end(w, rs->app_limited);
    }
    delivered = w->delivered - rs->prior_delivered + (w->delivered_fec - rs->prior_fec);
    send_el = tdiff(rs->send_ts, rs->first_sent);
    ack_el = tdiff(w->delivered_ts, rs->prior_ts);
    interval = (uint32_t)(send_el > ack_el ? send_el : ack_el);
    /* an interval shorter than min_rtt comes from ACK compression: no sample */
    if (interval > 0 && delivered > 0 && (w->min_rtt == 0 || interval >= w->min_rtt)) {
        uint64_t bw = delivered * 1000 / interval;
        uint32_t *slot = &w->bw_round[w->bw_idx];
        /* Without a queue the path carried everything sent - lost bytes,
           parities, abandoned frames too - not only what was acknowledged.
           On a lossy link delivered-only samples fall by the loss rate plus
           the FEC overhead, and the 1.25 probe cannot win that back. The
           send rate counts, at most 1.5x the delivery rate, while the sample
           saw no queue at all: on a full link the probe builds one, so
           overflow loss never counts. (The round's smallest sample would
           let jittery paths qualify too, but it lags a building queue by a
           round: measured worse on shared bottlenecks, DESIGN 13.14.) */
        if (w->min_rtt > 0 && w->lt_state == 0 && send_el > 0 && send_el >= (int32_t)(w->min_rtt / 2) && w->last_rtt > 0 &&
            (uint32_t)w->last_rtt <= bbr_rtt(w) + umax32(bbr_rtt(w) / 16, 3)) {
            uint64_t sr = (uint64_t)rs->sent * 1000 / (uint32_t)send_el;
            if (sr > bw * 3 / 2) sr = bw * 3 / 2;
            if (sr > bw) bw = sr;
        }
        if (bw > 0xffffffffu) bw = 0xffffffffu;
        if (bw > w->round_bw) w->round_bw = (uint32_t)bw;
        w->bw_last_app = rs->app_limited;
        if (!rs->app_limited) { w->round_net_sample = 1; w->net_round = w->round_count | 1; w->net_sample_ts = w->current | 1; }
        if (!rs->app_limited || bw >= w->btl_bw) {
            if (bw > *slot) *slot = (uint32_t)bw;
            if (bw > w->btl_bw) w->btl_bw = (uint32_t)bw;
        }
    }
    bbr_update_state(w);
    bbr_set_cwnd(w);
}

static void update_ack(anl_t *w, int32_t rtt)
{
    int32_t rto;
    w->last_rtt = rtt;
    if (w->round_min_rtt == 0 || (uint32_t)rtt < w->round_min_rtt) w->round_min_rtt = umax32((uint32_t)rtt, 1);
    bbr_update_min_rtt(w, rtt);
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
    /* + srtt / 4 at least: a BBR probe (gain 1.25 for a round trip) queues up
       to a quarter of the RTT at once, faster than rttval follows; losses are
       RACK's job, the RTO is the fallback for tails */
    rto = w->rx_srtt + (int32_t)umax32(umax32((uint32_t)w->interval, 4u * (uint32_t)w->rx_rttval), (uint32_t)w->rx_srtt / 4);
    w->rx_rto = (int32_t)ubound32(RTO_MIN, (uint32_t)rto, RTO_MAX);
}

/* una + SACK ranges (DESIGN 5.3), then RACK loss detection (DESIGN 6.3).
 * rng holds n (gap, len) pairs. Returns the number of segments acknowledged;
 * *lost counts the segments newly declared lost. */
static int handle_ack(anl_t *w, anl_stream *st, uint8_t b1, uint16_t una16, uint16_t wnd,
                      uint32_t ts_echo, const uint32_t *rng, uint32_t n, int *lost, bbr_sample *rs)
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
                int orig = s->xmit > 1 && (b1 & ACK_F_FRESH) && tdiff(ts_echo, s->ts_sent) < 0;
                if (orig && s->rack_rtx == 1) spurious = 1;
                /* a loss counts for congestion control only now, when it is
                   known not to be reordering or a late ACK: under heavy
                   jitter the RACK window and the RTO fire for segments that
                   were never lost */
                else if (!orig && s->rack_rtx) {
                    w->lost_bytes += seg_wire(s);
                    /* FEC did not repair it either - known only from a FRESH ACK;
                       late if it reached the peer (half an RTT before this ACK)
                       after the deadline (DESIGN 8.5) */
                    if (b1 & ACK_F_FRESH) {
                        int32_t at = tdiff(w->current - (uint32_t)(w->rx_srtt > 0 ? w->rx_srtt : RTO_DEF) / 2, s->ts_enq);
                        fec_auto_count(w, st, st->fec_deadline && at <= (int32_t)st->fec_deadline ? FEC_LOST : FEC_LATE);
                    }
                }
                /* the original was acknowledged: the send state recorded for
                   the retransmission would give a false rate sample and end
                   the round early */
                bbr_on_acked(w, s, orig ? NULL : rs);
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
    bbr_sample rs;
    uint32_t max_echo = 0;
    uint32_t *snbuf = (uint32_t *)w->scratch;
    uint32_t snbuf_cap = (w->mtu * 2) / sizeof(uint32_t);

    if (w == NULL || plain == NULL) return ANL_EINVAL;
    if (size < ANL_HDR_SIZE || (uint32_t)size > w->mtu) return ANL_EFORMAT;
    memset(&rs, 0, sizeof(rs));

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
                acked += handle_ack(w, st, b1, una16, wnd, ts_echo, snbuf, n, &lost, &rs);
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
            } else if (sub == CTRL_REPORT && blen >= REPORT_BODY) {
                st = stream_for_input(w, sid, &urgent);
                if (st) handle_report(w, st, p);
            }
            p += blen;                      /* unknown subtypes are skipped */
        }
    }

    if (have_echo && w->updated) {
        int32_t rtt = tdiff(w->current, max_echo);
        if (rtt >= 0 && rtt <= (int32_t)RTO_MAX) update_ack(w, rtt);   /* ignore garbage echoes */
    }
    if (rs.valid && w->updated) bbr_on_ack(w, &rs);

    /* ACK clocking (DESIGN 6.4): the window just opened or RACK found a loss -
       send now instead of at the next interval (still within cwnd and pacing) */
    if (w->updated && w->state >= 0 && (lost > 0 || (acked > 0 && has_new_data(w)))) anl_flush_internal(w);

    if (w->updated) {
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
/* Send the next parity of the last closed block. Each goes in a datagram of
 * its own (never with a member: losing that datagram would take the member and
 * a repair with it) and FEC_GAP after the previous one, so that one loss burst
 * does not take all of them. */
static void fec_send_parity(anl_t *w, anl_stream *st)
{
    uint8_t *body = (uint8_t *)w->scratch + w->mtu;         /* second half of scratch */
    const fec_buf *b = &st->fec_out[st->fec_out_i];
    char *p = (char *)body;
    dg_seal(w);
    p = enc16(p, (uint16_t)st->fec_out_base);
    p = enc8(p, (uint8_t)st->fec_out_k);
    p = enc8(p, (uint8_t)st->fec_out_m);
    p = enc8(p, (uint8_t)st->fec_out_i);
    memcpy(p, b->p, b->len);
    write_ctrl_seg(w, st->sid, CTRL_PARITY, body, PARITY_HDR + b->len);
    dg_seal(w);
    w->sent_wire += PARITY_HDR + b->len + SEG_WIRE_OVH;
    w->flush_budget--;
    st->fec_out_i++;
    st->fec_out_ts = w->current + FEC_GAP;
}

/* the parity that is due, if pacing allows - in the stream's turn of the
 * priority schedule (DESIGN 8.2); all of them with flush_all (a new block
 * closes and needs the buffers) */
static void fec_pump(anl_t *w, anl_stream *st, int flush_all)
{
    while (st->fec_out_i < st->fec_out_m && (flush_all || tdiff(w->current, st->fec_out_ts) >= 0)) {
        if (!flush_all && !pace_can_send(w)) { w->pace_blocked = 1; break; }
        fec_send_parity(w, st);
        if (!flush_all) break;
    }
}

/* Close the open block (DESIGN 8.2): k data packets get m = round(k * ratio)
 * Reed-Solomon parities (1..FEC_M_MAX); any m of the k + m can be lost.
 * Rounded, not ceiled: 6 audio packets at 20% get 1 parity, not 2 (33%). */
static void fec_close_block(anl_t *w, anl_stream *st)
{
    uint32_t k = st->fec_n, m, j, i, lmax = 0, share;
    anl_node *pos;
    if (k == 0 || st->fec_slot == NULL) return;
    st->fec_n = 0;
    fec_pump(w, st, 1);                             /* the previous block's parities first */
    m = (k * (uint32_t)st->fec_ratio + 50) / 100;
    /* at least what the loss needs - unless a retransmission (about 1.5
       RTT) makes the deadline anyway */
    if (st->fec_auto && !(st->fec_deadline && (uint32_t)(w->rx_srtt > 0 ? w->rx_srtt : RTO_DEF) * 3 / 2 <= st->fec_deadline))
        m = umax32(m, fec_parities_for(k, w->fec_loss));
    if (m == 0 && st->fec_auto) return;             /* auto at a low ratio: small blocks go unprotected */
    m = umin32(umax32(m, 1), FEC_M_MAX);
    for (i = 0; i < k; i++) lmax = umax32(lmax, st->fec_slot[i].len);
    for (j = 0; j < m; j++) {
        fec_buf *o = &st->fec_out[j];
        if (fbuf_reserve(o, lmax) < 0) { m = j; break; }
        memset(o->p, 0, lmax);
        o->len = lmax;
        for (i = 0; i < k; i++) gf_addmul(o->p, st->fec_slot[i].p, st->fec_slot[i].len, fec_coef(j, i));
    }
    st->fec_out_base = st->fec_base;
    st->fec_out_k = k;
    st->fec_out_m = m;
    st->fec_out_i = 0;
    st->fec_out_ts = w->current;
    /* the members still unacknowledged are covered from now on: RACK
       (rack_sent) counts from the last parity, a repair may need it -
       otherwise it resends what the peer is rebuilding (not the RTO: when
       FEC fails, that would only delay the retransmission further). Each
       carries a share of the parity bytes into the rate samples (not the
       round's loss fraction): parities are never acknowledged, and at a
       high ratio the rate of the data alone would pace the stream down step
       by step. Only the parities beyond FEC_CREDIT_FREE %: up to that the
       samples of the data alone reach the link already (the max filter picks
       the bursts) - crediting all unused parities, from the measured loss,
       overestimated by 7..14% (DESIGN 13.20). */
    j = (k * FEC_CREDIT_FREE + 50) / 100;
    share = m > j ? (m - j) * (lmax + PARITY_HDR + SEG_WIRE_OVH) / k : 0;
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        uint32_t last = w->current + (m - 1) * FEC_GAP;
        if (tdiff(s->sn, st->fec_base + k) >= 0) break;
        if (tdiff(s->sn, st->fec_base) < 0 || s->xmit != 1) continue;
        s->fec_ts = last ? last : 1;
        s->fec_share = (uint16_t)umin32(share, 0xffff);
    }
    fec_pump(w, st, 0);
}

/* Adaptive redundancy (DESIGN 8.5), from what the sender sees anyway: data
 * that was resent and whose retransmission (not the original, Eifel; only
 * a FRESH ACK tells) was acknowledged, or that was abandoned - FEC did not repair it. A RACK
 * retransmission alone is no evidence: the ACK of an FEC repair often comes
 * after RACK fired, the more parities the later (FEC_GAP apart). Raised by half when more than FEC_AUTO_MISS % of them are lost
 * (at most once per 2 RTT + a block: the effect of a raise shows that late),
 * lowered by a fifth after FEC_AUTO_CLEAN first transmissions without one. */
/* The connection's loss before FEC (DESIGN 8.5): first transmissions of
 * all FEC streams against what the peer's FEC repaired (its delay reports,
 * 6.9) plus what it did not (fec_auto_count). One estimate for all streams:
 * audio alone takes seconds to see a few losses. */
static void fec_loss_add(anl_t *w, uint32_t sent, uint32_t lost)
{
    w->fl_sent += sent;
    w->fl_lost += lost;
    if (w->fl_sent >= FEC_LOSS_PKTS) {
        int32_t x = (int32_t)((uint64_t)umin32(w->fl_lost, w->fl_sent) * 65536 / w->fl_sent);
        w->fec_loss = (uint32_t)((int32_t)w->fec_loss + (x - (int32_t)w->fec_loss) / 4);
        w->fl_sent = w->fl_lost = 0;
    }
}

/* the fewest parities for k data packets at raw loss p (1/65536) so that a
 * block fails - more than m of its k + m packets lost - with at most
 * FEC_BLOCK_FAIL %: binomial tail in 32.32 fixed point; at most k (100%) */
static uint32_t fec_parities_for(uint32_t k, uint32_t p)
{
    const uint64_t one = 1ull << 32;
    uint64_t q = 65536u - umin32(p, 65535);
    uint32_t m;
    if (p == 0) return 0;
    for (m = 0; m < FEC_M_MAX && m < k; m++) {
        uint32_t n = k + m, i;
        uint64_t pmf = one, cdf;
        for (i = 0; i < n; i++) pmf = pmf * q >> 16;            /* (1 - p)^n */
        cdf = pmf;
        for (i = 0; i < m; i++) {                               /* P(X = i + 1) */
            pmf = pmf * (n - i) / (i + 1) * p / q;
            cdf += pmf;
        }
        if (cdf >= one || (one - cdf) * 100 <= one * FEC_BLOCK_FAIL) return m;
    }
    return m;
}

/* FEC_SENT: a first transmission; FEC_LOST: FEC did not repair it but the
 * retransmission made the deadline; FEC_LATE: it did not */
static void fec_auto_count(anl_t *w, anl_stream *st, int lost)
{
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    if (st->fec) fec_loss_add(w, lost == FEC_SENT, lost != FEC_SENT);
    if (!st->fec_auto || lost == FEC_LOST) return;          /* the loss estimate only */
    if (lost == FEC_SENT) {
        if (++st->fec_sent < FEC_AUTO_CLEAN) return;
        if (st->fec_miss == 0) st->fec_ratio = (int)umax32((uint32_t)st->fec_ratio * 4 / 5, FEC_AUTO_MIN);
    } else {
        st->fec_miss++;
        if (st->fec_miss < 2 || st->fec_miss * 100 <= st->fec_sent * FEC_AUTO_MISS ||
            tdiff(w->current, st->fec_adj_ts) < (int32_t)(2 * srtt + FEC_BLOCK_MS)) return;
        st->fec_ratio = (int)umin32((uint32_t)st->fec_ratio * 3 / 2 + 5, FEC_AUTO_MAX);
        st->fec_adj_ts = w->current;
    }
    st->fec_sent = st->fec_miss = 0;
}

static void fec_add(anl_t *w, anl_stream *st, const anl_seg *seg)
{
    fec_buf *b;
    if (st->fec_n > 0 && seg->sn != st->fec_base + st->fec_n) fec_close_block(w, st);
    if (st->fec_n == 0) {
        st->fec_base = seg->sn;
        st->fec_first_ts = w->current;
    }
    b = &st->fec_slot[st->fec_n];
    if (fbuf_reserve(b, seg->len + CANON_HDR_MAX) < 0) { fec_close_block(w, st); return; }
    b->len = canon_build(b->p, seg->frg, seg->flags, (uint16_t)seg->frame_no, seg->data, seg->len);
    st->fec_n++;
    if (st->fec_n >= FEC_K_MAX) fec_close_block(w, st);
}

/* transmit a segment (first time or retransmission) */
static void send_seg(anl_t *w, anl_stream *st, anl_seg *seg)
{
    int first = seg->xmit == 0;
    write_data_seg(w, st, seg);
    seg->xmit++;
    seg->ts_sent = w->current;
    bbr_on_send(w, seg);
    if (first) {
        w->tx_payload += seg->len;
        if (st->fec) fec_add(w, st, seg);
        fec_auto_count(w, st, FEC_SENT);
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

/* remove every segment of frame_no from snd_buf and snd_queue; *end is
 * raised past the highest sn removed (the FWD must not skip further) */
static int purge_frame(anl_stream *st, uint32_t frame_no, uint32_t *end)
{
    anl_node *pos, *next;
    int sent = 0, in_buf = 0, first = 1;
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        next = pos->next;
        if (s->frame_no != frame_no) { if (in_buf) break; else continue; }
        in_buf = sent = 1;
        if (tdiff(s->sn + 1, *end) > 0) *end = s->sn + 1;
        qdel(&s->node);
        st->nsnd_buf--;
        backlog_sub(st, s->len);
        seg_free(s);
    }
    for (pos = st->snd_queue.next; pos != &st->snd_queue; pos = next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        next = pos->next;
        if (s->frame_no != frame_no) break;
        if (first && !(s->flags & F_HAS_FRAME)) {
            sent = 1;                       /* head already sent (maybe acked) */
            *end = st->snd_nxt;             /* its sent part ends where sending stopped */
        }
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
 * dropped up to the next key frame (DESIGN 7.6). One FWD then skips exactly
 * the dropped segments: up to the highest sn dropped. Not to the first frame
 * still in the send buffers - frames the peer acknowledged by SACK are gone
 * from them, and the peer would throw such a received frame away. */
static void drop_frame(anl_t *w, anl_stream *st, uint32_t frame_no)
{
    uint32_t end = st->snd_una;
    int r = purge_frame(st, frame_no, &end), sent = r & PURGED_SENT;
    if (!(r & PURGED_ANY)) return;          /* already dropped together with an older frame */
    st->frames_dropped++;
    if (st->drop_until_key) {
        anl_seg *s;
        uint32_t last = frame_no;
        st->dropping = 1;
        while ((s = next_frame_after(st, last)) != NULL) {
            if (s->fkey) { st->dropping = 0; break; }
            last = s->frame_no;
            sent |= purge_frame(st, last, &end) & PURGED_SENT;
            st->frames_dropped++;
        }
    }
    if (sent) {
        uint32_t new_una = end;
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
/* data waiting in a send queue, window or not */
static int has_queued_data(const anl_t *w)
{
    anl_node *n, *nx;
    anl_stream *st;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st) && st->nsnd_que > 0) return 1;
    }
    return 0;
}

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
    return umin32(rto + rto / 2, RTO_MAX);
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
           the stream once the application has read what is left - or has
           closed it: segments in flight at its close may still have arrived */
        if (st->close_answer) { write_close_seg(w, st->sid, st->final_sn, 0, st); st->close_answer = 0; }
        if (st->ack_pending) write_ack_segs(w, st);
        if (st->app_released || QEMPTY(&st->rcv_queue)) stream_free(w, st);
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

    /* delay measurement interval; the report to the peer (DESIGN 6.9) */
    if ((st->rp_qn > 0 || st->rp_fn > 0) && tdiff(current, st->rp_next) >= 0) {
        uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
        rp_close_interval(w, st);
        if (st->report) write_report_seg(w, st);
        st->rp_next = current + umax32(srtt, REPORT_MIN_MS);
    }

    /* OPEN announcement with exponential backoff until anything is heard from
       the peer; not counted towards dead_link (the peer may simply be idle) */
    if (!st->peer_opened && tdiff(current, st->open_ts) >= 0) {
        write_open_seg(w, st);
        /* before the first RTT sample from RTO_DEF, not the initial RTO: that
           is long to spare the first flight of data spurious resends, an
           OPEN is a few bytes (6.3) */
        st->open_rto = st->open_rto == 0 ? (w->rx_srtt > 0 ? (uint32_t)w->rx_rto : RTO_DEF)
                                         : umin32(st->open_rto * 2, OPEN_RTO_MAX);
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

/* Immediate control flush (ACK after 2 data datagrams, close): only the streams that asked
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

/* target_rate (DESIGN 6.10): the payload rate the application may send.
 * The estimate is in wire bytes; the payload share of what was sent lately
 * takes out headers, FEC parities and retransmissions, RATE_MARGIN leaves
 * room for bitrate spikes. Two cases the estimate alone gets wrong:
 * - app-limited, it only shows what the application sent: without a queue
 *   the target grows RATE_GROWTH %/s (at most 1.25 x what is actually sent),
 *   so an encoder that follows it probes upwards until the network pushes
 *   back; it never rises faster than that, whatever the estimate does;
 * - an application above the link: a semi-reliable stream abandons what
 *   waits longer than max_age, and once the bottleneck queue is longer than
 *   that nothing is acknowledged - no rate samples, no rounds, BBR keeps the
 *   old estimate for a while. The RTT still shows the queue (ACKs keep
 *   coming): while it is well above the minimum of the last 15..30 s the
 *   target is what the path delivers now, or RATE_DECREASE % less per step
 *   when nothing is delivered in time. */
static void rate_update(anl_t *w)
{
    int32_t dt = tdiff(w->current, w->rate_ts);
    uint64_t dp, dwire, dd, base, pay_rate;
    uint32_t rmin, queue;
    if (w->rate_ts != 0 && dt < RATE_STEP_MS) return;
    dp = w->tx_payload - w->rate_payload0;
    dwire = w->sent_wire - w->rate_wire0;
    dd = w->delivered - w->rate_deliv0;
    w->rate_payload0 = w->tx_payload;
    w->rate_wire0 = w->sent_wire;
    w->rate_deliv0 = w->delivered;
    w->rate_ts = w->current ? w->current : 1;
    if (w->rate_share == 0) w->rate_share = 230;                /* 0.9 until measured */
    if (dt <= 0 || dt > 10 * RATE_STEP_MS) return;              /* first call, or after idling */
    if (dp >= 2u * w->mss && dwire >= 4u * w->mss) {            /* not from retransmissions alone */
        uint32_t sh = ubound32(128, (uint32_t)umin32((uint32_t)(dp * 256 / dwire), 256), 256);
        w->rate_share = (uint32_t)((int32_t)w->rate_share + ((int32_t)sh - (int32_t)w->rate_share) / 4);
    }
    if (w->btl_bw == 0 || w->rx_srtt <= 0) return;
    if (w->rate_rtt_ts == 0 || tdiff(w->current, w->rate_rtt_ts) >= RATE_RTT_WIN) {
        w->rate_rtt_old = w->rate_rtt_ts ? w->rate_rtt_min : (uint32_t)w->rx_srtt;
        w->rate_rtt_min = (uint32_t)w->rx_srtt;
        w->rate_rtt_ts = w->current ? w->current : 1;
    }
    w->rate_rtt_min = umin32(w->rate_rtt_min, (uint32_t)w->rx_srtt);
    rmin = umin32(w->rate_rtt_min, w->rate_rtt_old);
    queue = (uint32_t)w->rx_srtt - rmin;
    base = (uint64_t)bbr_bw(w) * w->rate_share / 256 * (100 - RATE_MARGIN) / 100;
    pay_rate = dp * 1000 / (uint32_t)dt;
    if (queue > umax32(rmin / 2, 30)) {
        /* what the path delivers now, or - when nothing gets through in
           time - RATE_DECREASE % less per step; not below what BBR keeps
           going at its smallest window */
        uint64_t floor = (uint64_t)BBR_MIN_CWND * w->mss * 1000 / (uint32_t)w->rx_srtt * w->rate_share / 256;
        uint64_t cut = dd * 1000 / (uint32_t)dt * w->rate_share / 256 * (100 - RATE_MARGIN) / 100;
        if (cut < floor) cut = (uint64_t)w->rate_target * (100 - RATE_DECREASE) / 100;
        if (cut < floor) cut = floor;
        if (cut < base) base = cut;
    } else {
        /* up at most RATE_GROWTH %/s: after a bandwidth drop the estimate may
           return to the old peak (app-limited rounds do not age it out, bw_lo
           goes at the next probe) - climbing, the queue shows first. While
           app-limited without a queue, up by as much (at most 1.25 x what is
           sent): the estimate only shows what the application sent. */
        uint64_t prev = w->rate_target ? w->rate_target : base;
        uint64_t grow = prev + prev * RATE_GROWTH * (uint32_t)dt / 100000;
        /* 25 ms: at a low rate srtt sits 10..20 ms above its minimum anyway
           (ACKs wait for the flush interval, key frames come in bursts) */
        if ((w->app_limited != 0 || w->bw_last_app) && queue < umax32(rmin / 4, 25)) {
            uint64_t cap = pay_rate * 5 / 4;
            if (base < cap) base = grow < cap ? grow : cap;
        }
        if (base > grow) base = grow;
    }
    w->rate_target = base > 0xffffffffu ? 0xffffffffu : (uint32_t)base;
    if (w->rate_cb && (w->rate_told == 0 || w->rate_target * 20ull >= w->rate_told * 21ull || w->rate_target * 20ull <= w->rate_told * 19ull)) {
        w->rate_told = w->rate_target;
        w->rate_cb(w, w->rate_target, w->user);
    }
}

static void anl_flush_internal(anl_t *w)
{
    uint32_t current = w->current;
    uint32_t inflight = 0;
    int lost = 0;
    int64_t retrans_limit, retrans_spent = 0;
    int rtx_capped = 0, prio;
    anl_node *n, *nx;
    anl_stream *st;

    if (!w->updated || w->state < 0) return;
    pace_refill(w);
    w->pace_blocked = 0;
    dg_begin(w);

    /* 1 + 2: control */
    flush_control_segs(w);
    w->rx_data_since_ack = 0;

    /* sender-side dropping before computing budgets */
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st)) semi_drop_check(w, st);
    }
    /* in flight: sent and not acknowledged, minus what RACK declared lost
       and is not resent yet (BBR's pipe). With the lost segments counted, a
       policer that dropped half of a STARTUP overshoot kept DRAIN from ever
       ending: inflight stayed far above the BDP, the drain gain slowed the
       retransmissions, their samples lowered btl_bw and so the pace - down
       to 0.4 Mbps on a 10 Mbps path for 20 s (DESIGN 13.25) */
    FOR_EACH_STREAM(w, st, n, nx) {
        anl_node *pos;
        inflight += st->nsnd_buf;
        for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next)
            if (QENTRY(pos, anl_seg, node)->lost && inflight > 0) inflight--;
    }
    w->inflight_segs = inflight;
    w->flush_budget = (int64_t)w->cwnd - (int64_t)inflight;

    /* 3: retransmissions, not gated by cwnd, gated by pacing (3/4 if new data waits);
       streams are visited in priority order. The retransmission state (backoff,
       resendts, lost) changes only when the segment is actually sent: a
       retransmission deferred by pacing must not be pushed back by another RTO. */
    retrans_limit = has_new_data(w) ? (w->pace_tokens > 0 ? w->pace_tokens * 3 / 4 : 0)
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
                    if (seg->xmit == 1) fec_auto_count(w, st, FEC_LATE);
                    abandon_through(w, st, seg->frame_no);
                    pos = &st->snd_buf;         /* a prefix was removed: restart at the new head */
                    continue;
                }
                if (!pace_can_send(w)) { w->pace_blocked = 1; break; }
                if (retrans_spent >= retrans_limit) { rtx_capped = 1; break; }
                if (why == 2) {
                    lost = 1;
                    seg->rto = umin32(seg->rto + seg->rto / 2, RTO_MAX);  /* back off x1.5 */
                    seg->resendts = current + seg->rto;
                } else if (why == 3) {
                    seg->resendts = current + seg->rto;
                }
                seg->rack_rtx = why == 3 ? 1 : why == 2 ? 2 : 0;
                seg->lost = 0;
                send_seg(w, st, seg);
                retrans_spent += data_seg_size(st, seg);
                if (st->mode == ANL_RELIABLE && seg->xmit >= w->dead_link) w->state = -1;
            }
        }
    }

    /* 4: parities and new data. The default stream has strict priority, the
       others share by weighted round robin; a stream's due parity goes first
       in its turn: it repairs data already sent. */
    if (w->app_limited != 0 && !w->burst_open) {    /* a burst after app-limited sending (burst_on_acked) */
        uint32_t q = 0;
        FOR_EACH_STREAM(w, st, n, nx) {
            if (stream_sendable(st)) q += st->nsnd_que;
        }
        if (q >= 8) {
            if (++w->burst_id == 0) w->burst_id = 1;
            if (w->burst_cur > w->burst_bw) w->burst_bw = w->burst_cur;
            w->burst_cur = 0;
            w->burst_open = 1;
            w->burst_left = q;
            w->burst_done = 0;
            w->burst_t0 = w->disp_ts = 0;
        }
    }
    st = w->dflt;
    if (st->fec && !w->pace_blocked) fec_pump(w, st, 0);
    while (!w->pace_blocked && w->flush_budget > 0 && st->nsnd_que > 0 && stream_sendable(st) &&
           tdiff(st->snd_nxt, st->snd_una + umin32(st->snd_wnd, st->rmt_wnd)) < 0) {
        if (!pace_can_send(w)) { w->pace_blocked = 1; break; }
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
                    if (st->fec) fec_pump(w, st, 0);
                    while (quota > 0 && w->flush_budget > 0 && st->nsnd_que > 0 &&
                           tdiff(st->snd_nxt, st->snd_una + umin32(st->snd_wnd, st->rmt_wnd)) < 0) {
                        if (!pace_can_send(w)) { w->pace_blocked = 1; break; }
                        move_and_send(w, st);
                        quota--;
                        w->flush_budget--;
                        progress = 1;
                    }
                }
            }
        }
    }

    /* the budget is not used up and nothing waits: the application is the
       limit, not the network - rate samples until the data now in flight is
       delivered do not show the path's bandwidth (BBR app-limited). Data
       held back by a stream window is not: that is the receiver's limit, and
       an app-limited sender gets burst headroom a window-limited one must not
       have (it would pace at the STARTUP gain for good) */
    if (!w->pace_blocked && w->flush_budget > 0 && !has_queued_data(w)) {
        w->app_limited = (w->delivered + bbr_inflight_bytes(w)) | 1;
        w->burst_open = 0;
    }

    /* 5: FEC: blocks that collected FEC_BLOCK_MS, parities still due (streams
       without new data), in priority order; stale parities */
    for (prio = -1; prio < ANL_MAX_PRIO; prio++) {
        FOR_EACH_STREAM(w, st, n, nx) {
            if (!st->fec || (prio < 0 ? !st->strict : (st->strict || st->prio != prio))) continue;
            if (st->fec_n > 0 && tdiff(current, st->fec_first_ts) >= FEC_BLOCK_MS) fec_close_block(w, st);
            if (!w->pace_blocked) fec_pump(w, st, 0);
        }
    }
    FOR_EACH_STREAM(w, st, n, nx) {
        if (!st->fec) continue;
        if (st->pcache) {
            uint32_t j;
            for (j = 0; j < st->pcache_n; j++)
                if (st->pcache[j].valid && tdiff(current, st->pcache[j].ts) > (int32_t)fec_parity_ttl(w))
                    st->pcache[j].valid = 0;
        }
    }

    dg_seal(w);

    /* BBR: an RTO means the model may be stale - the bandwidth dropped: keep
       inflight where it is for a round (packet conservation) instead of
       collapsing to one packet. Only while a queue shows (a bandwidth drop
       fills the bottleneck queue first) or with a policer's heavy loss:
       without a queue the RTOs are tail losses of a burst or reordering on
       a jittery link, and each would stall a round (DESIGN 13.16). */
    if (lost && (bbr_queue_signal(w) || w->loss_rate * 100 > BBR_LOSS_BLIND * 256u)) {
        w->rto_round = w->round_count + 1;
        w->rto_inflight = inflight;
        bbr_set_cwnd(w);
    }
    rate_update(w);
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
    opt->fec_ratio = 25;
    if (opt->mode == ANL_SEMI) {
        opt->snd_wnd = 512;
        opt->rcv_wnd = 512;
        opt->flush_on_send = 1;
        opt->max_age_ms = 500;
        opt->report = 1;
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
    gf_init();                          /* FEC tables (idempotent) */

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
    w->interval = cfg->interval > 0 ? ubound32(1, (uint32_t)cfg->interval, 5000) : 20;
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

    /* before the first sample: the RTO a first sample of RTO_DEF gives
       (srtt + 4 x srtt / 2). RTO_DEF alone is the RTT of many mobile paths:
       the whole first flight - the first key frame - was resent spuriously */
    w->rx_rto = 3 * RTO_DEF;
    w->reo_mult = 1;
    w->cwnd = w->init_cwnd;
    w->avg_seg = w->mss + SEG_WIRE_OVH;
    w->bbr_state = ANL_BBR_STARTUP;
    w->pacing_gain = BBR_STARTUP_GAIN;
    w->cwnd_gain = BBR_CWND_GAIN;
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

void anl_set_rate_callback(anl_t *w, anl_rate_fn fn) { if (w) { w->rate_cb = fn; w->rate_told = 0; } }
void anl_set_report_callback(anl_t *w, anl_report_fn fn) { if (w) w->report_cb = fn; }

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
            int32_t d = tdiff(st->fec_first_ts + FEC_BLOCK_MS, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        if (st->fec && st->fec_out_i < st->fec_out_m) {
            int32_t d = tdiff(st->fec_out_ts, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
        for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
            const anl_seg *seg = QENTRY(pos, anl_seg, node);
            int32_t d = tdiff(seg->resendts, current);
            if (d <= 0 || seg->lost) return current;
            if (d < tm_min) tm_min = d;
            if (rack_candidate(w, st, seg)) {
                d = tdiff(rack_sent(seg) + w->rack_rtt + reo_wnd(w, st), current);  /* RACK timer */
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
    out->bw_estimate = bbr_bw(w);
    out->bw_app_limited = w->bw_last_app;
    out->min_rtt = w->min_rtt;
    out->cc_state = w->bbr_state;
    FOR_EACH_STREAM(w, st, n, nx) out->inflight += st->nsnd_buf;
    out->retrans = w->retrans_total;
    out->pace_rate = w->pace_rate ? w->pace_rate : compute_pace_rate(w);
    out->target_rate = w->rate_target;
    out->bw_estimate_age_ms = w->net_sample_ts ? (uint32_t)tdiff(w->current, w->net_sample_ts) : 0xffffffffu;
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
    /* the buffers themselves grow on first use (fbuf_reserve) */
    st->fec_slot = (fec_buf *)anl_malloc(sizeof(fec_buf) * FEC_K_MAX);
    st->fec_out = (fec_buf *)anl_malloc(sizeof(fec_buf) * FEC_M_MAX);
    st->cache_n = 2u * FEC_K_MAX;                   /* two blocks of received data */
    st->cache = (fec_centry *)anl_malloc(sizeof(fec_centry) * st->cache_n);
    st->pcache_n = 2u * FEC_M_MAX;                  /* two blocks of parities */
    st->pcache = (fec_pentry *)anl_malloc(sizeof(fec_pentry) * st->pcache_n);
    if (st->fec_slot) memset(st->fec_slot, 0, sizeof(fec_buf) * FEC_K_MAX);
    if (st->fec_out) memset(st->fec_out, 0, sizeof(fec_buf) * FEC_M_MAX);
    if (st->cache) memset(st->cache, 0, sizeof(fec_centry) * st->cache_n);
    if (st->pcache) memset(st->pcache, 0, sizeof(fec_pentry) * st->pcache_n);
    if (!st->fec_slot || !st->fec_out || !st->cache || !st->pcache) return -1;
    return 0;
}

static int stream_opt_check(const anl_stream_opt *opt)
{
    if (opt->mode != ANL_RELIABLE && opt->mode != ANL_SEMI) return ANL_EINVAL;
    if (opt->prio < 0 || opt->prio >= ANL_MAX_PRIO) return ANL_EINVAL;
    if (opt->snd_wnd < 1 || opt->snd_wnd > ANL_MAX_WND) return ANL_EINVAL;
    if (opt->rcv_wnd < 1 || opt->rcv_wnd > ANL_MAX_WND) return ANL_EINVAL;
    if (opt->fec && (opt->fec_ratio < 0 || opt->fec_ratio > 100)) return ANL_EINVAL;
    if (opt->tag < 0 || opt->tag > 0xffff) return ANL_EINVAL;
    return 0;
}

/* local options that do not have to match the peer (DESIGN 6.1) */
static int stream_apply_local(anl_t *w, anl_stream *st, const anl_stream_opt *opt)
{
    st->prio = opt->prio;
    st->flush_on_send = opt->flush_on_send;
    st->report = opt->report != 0;
    st->fec_deadline = opt->fec_deadline_ms > 0 ? (uint32_t)opt->fec_deadline_ms
                     : st->mode == ANL_SEMI && opt->max_age_ms > 0 ? (uint32_t)opt->max_age_ms / 2 : 0;
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
            st->mss = w->mss - ANL_FEC_OVERHEAD;
            if (fec_alloc(st) < 0) { fec_free(st); st->fec = 0; st->mss = w->mss; return ANL_ENOMEM; }
        }
    }
    if (st->fec && (opt->fec_ratio == 0) != st->fec_auto) {
        st->fec_auto = opt->fec_ratio == 0;
        st->fec_sent = st->fec_miss = 0;
        if (st->fec_auto) st->fec_ratio = FEC_AUTO_START;
    }
    if (st->fec && !st->fec_auto) st->fec_ratio = opt->fec_ratio;
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
    out->fec_ratio = st->fec ? (uint32_t)st->fec_ratio : 0;
    out->rx = st->rp_last;
    if (out->rx.valid) out->rx.age_ms = (uint32_t)tdiff(st->w->current, st->rp_last_ts);
    out->peer = st->peer_rp;
    if (out->peer.valid) out->peer.age_ms = (uint32_t)tdiff(st->w->current, st->peer_rp_ts);
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
    move_to_queue(w, st);
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
