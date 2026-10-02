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
static uint32_t sat32(uint64_t v) { return v > 0xffffffffu ? 0xffffffffu : (uint32_t)v; }
static uint32_t ubound32(uint32_t lo, uint32_t v, uint32_t hi)
{
    return umin32(umax32(lo, v), hi);
}

/* 16-bit wire value -> 32-bit, relative to ref (frame numbers, DESIGN 7.1) */
static uint32_t extend16(uint16_t v, uint32_t ref)
{
    int16_t d = (int16_t)(uint16_t)(v - (uint16_t)ref);
    return ref + (uint32_t)(int32_t)d;
}

/* 24-bit wire sn / una -> 32-bit, relative to ref (DESIGN 5.1) */
#define SN_MASK 0xffffffu
static uint32_t extend24(uint32_t v, uint32_t ref)
{
    int32_t d = (int32_t)(((v - ref) & SN_MASK) << 8) >> 8;
    return ref + (uint32_t)d;
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
static char *enc24(char *p, uint32_t v)
{
    p = enc16(p, (uint16_t)(v & 0xffff));
    return enc8(p, (uint8_t)(v >> 16));
}
static uint32_t dec24(const char **p)
{
    uint32_t lo = dec16(p);
    uint32_t hi = dec8(p);
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
#define CTRL_RCV_SKIP   0x05    /* receiver retired a prefix; not delivery credit */
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

#define CLOSE_BODY      7       /* final_sn(3) flags(1) una(3) */
#define CLOSE_F_RST     0x01
#define CLOSE_F_OPEN    0x02    /* CLOSE carries the stream parameters */
#define CLOSE_F_HALF    0x04    /* the FIN is a half-close: the sender still reads (DESIGN 6.1) */
#define CLOSE_F_ACKFIN  0x08    /* the sender has the receiver's FIN */
#define CLOSE_F_NOFIN   0x10    /* no FIN: only ACKFIN (the sender still sends); final_sn is 0 */

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
#define PROBE_LIMIT     60000
#define OPEN_RTO_MAX    5000
#define KEEPALIVE_PAD   16

#define SID_LO_BITS     13      /* type(2) | X(1) | sid[12:0](13) [sid[28:13](16) if X], DESIGN 5 */
#define SID_X           0x20    /* b0: the 2-byte sid extension follows */
#define SID_HI_MASK     0x1f
#define DATA_HDR_MAX    13      /* type|sid(2) b1 frg_ext(3) sn(3) frame(2) len(2); + OPEN_BODY until the peer is
                                   heard; a sid >= 2^13 takes 2 more bytes off its stream's mss (stream_mss) */
#define ACK_FIX         10      /* after type|sid: b1 una(3) wnd(2) ts_echo(4) */
#define SKIP_BODY       4       /* CTRL_RCV_SKIP body: the retired una, 32 bits */
#define ACK_F_WASK      0x80    /* window probe: please answer with an ACK */
#define ACK_F_FRESH     0x40    /* data arrived since the last ACK: ts_echo is an RTT sample */
#define SACK_REPEAT     3       /* every received segment is reported in at least 3 ACKs */
#define RCV_HELD_MAX    64      /* over rcv_limit: unread segments above which a stream's window closes */
#define REO_DIV         16      /* RACK reordering window starts at min_rtt / 16 */
#define REO_MULT_MAX    16      /* and grows up to min_rtt */
#define REO_DECAY       16      /* round trips without a spurious retransmission before it shrinks */
#define PARITY_HDR      6       /* base(3) k(1) m(1) j(1), after type|sid sub len */

#define SID_WIN         8192    /* peer sids opened but not seen yet that are tracked (DESIGN 6.1) */
#define CANON_HDR_MAX   10      /* b1 frg_ext(varint, up to 5) frame(2) plen(2); the parser bounds
                                   frg below ANL_MAX_WND (a 2-byte extension), the size is defensive */
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
#define BBR_APP_LOSS_MAX    32      /* 1/8 (of 256): smoothed loss above which an app-limited round's loss is overload, not the path's random loss */
#define BBR_MIN_CWND        4
#define BBR_DW_SLOTS        16      /* delivered-bytes checkpoints spanning at least the sampling window */
#define BBR_DW_MIN_MS       10      /* smooth millisecond clock quantization even with 1 ms updates */
#define BBR_LT_SPAN         8       /* policed intervals before the first probe above the rate; doubles up to BBR_LT_SPAN_MAX */
#define BBR_LT_SPAN_MAX     64
#define BBR_LT_PROBE_MAX    16      /* probe steps of 1/4 lt_rate without finding the ceiling: the policer is gone */
#define BBR_LT_ROUNDS       4       /* rounds per policer-detection interval (and >= BBR_LT_MS) */
#define BBR_LT_MS           300
#define LT_GAP_MS           5000    /* after an input gap: its losses and backlog are no policer evidence */
#define SEG_WIRE_OVH        30      /* per-segment share of datagram / segment headers */
#define START_WND_MS    300     /* cfg.start_rate: initial window of this long at that rate */
#define START_BURST_MTU 1       /* ... and pace_burst (unless set) in datagrams */
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
#define FEC_LOSS_FIRST  50      /* ... its first window: the RTT gate waits for it (1 s of audio) */
#define FEC_LOSS_WARM   3       /* ... windows over which a higher measurement replaces the estimate */
#define FEC_BLOCK_FAIL  10      /* auto: parities so that a block fails with at most this per mille */
#define FEC_SMALL_FAIL  1       /* ... a small block (audio, cheap to protect) or any block of a
                                   drop_until_key stream (a failure a retransmission cannot repair in
                                   time costs the rest of the GOP: 15 frames): per mille */
#define FEC_GATE_LOSS_ON  655   /* RTT auto (DESIGN 8.6): opens at this raw loss (1%, 1/65536), */
#define FEC_GATE_LOSS_OFF 164   /* closes below this (0.25%) */
#define FEC_GATE_HOLD_MS  2000  /* ... and switches at most this often (and stays closed this long after a
                                   capacity shortage ended, DESIGN 8.6) */
#define FEC_LOSS_RECENT_MS 30000 /* ... and only while the path lost a packet within this long (DESIGN 8.6):
                                   before the first loss and after the last one no parity at all */
#define FEC_AUDIO_START_MAX_MS 1000 /* one bounded audio startup allowance; never renewed */
#define FEC_REC_RING      16    /* receiver: recently rebuilt sn, to tell a rebuild whose original arrives after all */
#define FEC_REC_GRACE_MS  200   /* ... a rebuild younger than this is not reported yet (the original may still come) */
#define FEC_START_RATIO   25    /* RTT auto: key frames while the loss is unknown (the first one) */
#define FEC_BUDGET_MS     500   /* parity budget: the bucket holds this long at the budget rate */
#define FEC_FLOOR_CAP     30    /* adaptive: parities of a large non-key block, at most this % of k; the
                                   auto ratio's ceiling while the budget's bucket is short
                                   (50 / 35 / 25 simulated: 25 already held long-RTT video at 99.5%,
                                   real cross-border video 97.5..98.6% at 20%, progress 40) */
#define FEC_SMALL_BLOCK   2048  /* data bytes up to which a block counts as small (audio) */
#define FEC_SMALL_RATIO   100   /* adaptive, a retransmission too late: parities of a small block, % */

static const uint32_t prio_weight[ANL_MAX_PRIO] = { 8, 4, 2, 1 };

typedef struct anl_seg {
    anl_node node;
    anl_node tnode;         /* sender: st->snd_time, in the order of the last transmission */
    uint32_t sn;
    uint32_t frg;
    uint32_t frame_no;      /* semi: 32-bit frame number (all fragments) */
    uint32_t ts_enq;        /* semi: enqueue time */
    uint32_t ts_sent;       /* time of the last transmission (RACK); receiver: the peer's send time */
    uint32_t fec_ts;        /* its FEC block's last parity goes out (first transmission only) */
    uint16_t fec_share;     /* its share of the block's parity bytes (delivery rate) */
    uint8_t  lost_cnt;      /* counted in lost_bytes (RACK marked it; undone if the original arrives) */
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
    uint32_t rs_par, rs_par_first;      /* ... and sent_par (the parity part of sent_wire) */
    uint32_t len;
    char     data[1];
} anl_seg;

/* receiver: a run of consecutive sn in rcv_buf (DESIGN 5.3) - what an ACK
 * reports as one SACK range; the runs are what holes leave, not the window */
typedef struct rcv_run {
    anl_node node;
    uint32_t start, end;        /* [start, end) */
    uint32_t rep;               /* ACKs it went out in since it last changed */
    anl_seg *first, *last;      /* its segments in rcv_buf */
} rcv_run;

#define RUN_OF(n) QENTRY(n, rcv_run, node)

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
    uint32_t base, k, j;
    uint32_t ts;
    fec_buf  b;
} fec_pentry;

typedef struct anl_stream {
    anl_node lnode;         /* w->slist */
    struct anl_stream *hnext;   /* sid hash chain */
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
    /* the cost of a large window (DESIGN 5.1): what the per-ACK and per-flush
       work needs without walking the whole of snd_buf */
    anl_node snd_time;      /* snd_buf by last transmission: RACK stops at the newest delivered */
    anl_node rcv_runs;      /* rcv_buf as runs of consecutive sn: SACK ranges, insertion */
    uint32_t nlost;         /* segments in snd_buf RACK marked lost, not resent yet */
    uint32_t rto_next;      /* no RTO is due before this (a lower bound; exact after a full walk) */

    int ack_pending;        /* an ACK is due */
    int ack_fresh;          /* data arrived since the last ACK: ts_echo is an RTT sample */
    uint32_t ack_ts;
    uint32_t ack_rep_ts;    /* receiver: repeat the last ACK then unless another goes out first (| 1; 0: none) */
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
    int half;               /* our FIN is a half-close (anl_stream_shutdown): we still read */
    int fin_acked;          /* the peer has our FIN (CLOSE_F_ACKFIN) */
    int peer_half;          /* the peer's FIN is a half-close: our direction stays open */
    uint32_t final_sn, peer_final_sn;
    uint32_t close_ts, close_xmit, close_rto;

    /* semi-reliable */
    int max_age_ms, max_bytes, drop_until_key, rcv_deadline_ms, dropping;
    uint32_t frame_next, backlog_bytes;
    int fwd_pending;
    uint32_t fwd_una, fwd_ts, fwd_xmit, fwd_peer_una, fwd_rto;
    int frame_seen, delivered_any;
    uint32_t frame_max, last_delivered;
    /* key frames (DESIGN 7.6) */
    int rcv_drop_until_key;
    uint32_t block_since;
    int blocked;
    int rcv_skip_valid;
    uint32_t rcv_skip_una;        /* latest local deadline skip, repeated with ACKs */

    /* FEC (DESIGN 8): Reed-Solomon over the stream's first transmissions */
    int fec, fec_ratio;                 /* parities per 100 data packets */
    int fec_auto;                       /* fec_ratio follows the residual loss (DESIGN 8.5) */
    int fec_rtt_auto;                   /* reserve FEC from open, gate new parity blocks by RTT */
    uint32_t fec_deadline;              /* auto: a retransmission arriving within this (ms from
                                           enqueue) is fine, FEC is not needed for it; 0 = none */
    uint32_t fec_sent, fec_miss, fec_adj_ts;    /* auto: first transmissions, lost ones, last raise */
    int fec_gate;                       /* RTT auto: parity for the stream's blocks (DESIGN 8.6) */
    int fec_gate_was;                   /* ... ever opened on hard loss (the first opening skips the hold) */
    uint32_t fec_start_ts;              /* first transmission, not the latest frame/block */
    int fec_start_state;                /* 0: not sent, 1: startup allowance, 2: permanently spent */
    uint32_t fec_gate_ts;               /* its last switch (0: never) */
    uint32_t fec_frame_avg, fec_key_bytes;  /* average non-key frame, last key frame (bytes) */
    uint32_t fec_carry;                 /* ratio rounding carried to the next block, 1/100 parity */
    uint8_t  fec_blk_key;               /* the open block has key-frame fragments */

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
    uint32_t peer_rp_wire_ts;           /* newest report's peer clock; reject reordered / replayed reports */
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

    uint32_t fec_rec_ring[FEC_REC_RING];/* receiver: the last rebuilt sn (spurious when the original follows) */
    uint32_t fec_rec_ts[FEC_REC_RING];  /* ... and when (| 1; 0: spurious): a report counts a rebuild only once it is FEC_REC_GRACE_MS old */
    uint32_t fec_rec_pts[FEC_REC_RING]; /* ... the parity's send time: an original sent no later than it was reordered (the block's
                                           last packet may share the parity's flush), one sent after it is a retransmission */
    uint32_t fec_rec_i;
    uint32_t fec_spurious;              /* receiver: rebuilds whose original arrived after all (reordering) */

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
    uint32_t start_cap;                 /* cfg.start_rate: pacing ceiling, raised by delivery (DESIGN 6.8); 0 = none */
    uint32_t pace_burst, rcv_limit;

    int32_t rx_rttval, rx_srtt, rx_rto;
    int rtt_resume;                  /* resumed after an RTO without input: drain old ACK echoes */
    uint32_t lt_gap_ts;              /* ... when input resumed after such a gap (| 1): no policer evidence for LT_GAP_MS */
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
    uint32_t vq_bytes, vq_ts;           /* our own backlog at the bottleneck if it drains at the estimate (vq_ms) */
    uint32_t sent_par, first_sent_par;  /* ... of which parity (wraps) */
    uint64_t app_limited;               /* != 0: samples are app-limited until delivered passes it */
    uint64_t lost_bytes;                /* RACK-marked bytes (spurious marks undone); RTO losses counted at ACK */
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
    /* token-bucket policer detection (DESIGN 6.8): intervals of >= BBR_LT_ROUNDS rounds and 300 ms */
    int lt_state;                       /* 0 watching, 1 testing at lt_rate, 2 policed at lt_rate, 3 probing above it */
    int lt_bad;                         /* the interval had app-limited (1) or queued (2) rounds */
    uint32_t lt_ts, lt_rounds, lt_left, lt_hold; /* hold: watch delay or failed capacity-retest cooldown */
    uint32_t lt_sent0;                  /* sent_wire at the start of the interval */
    uint8_t  post_startup;              /* rounds after STARTUP in which heavy loss can trim stale bandwidth peaks */
    uint8_t  lt_k;                      /* probing: the step above lt_rate, pace = lt_rate * (4 + k) / 4 */
    uint8_t  lt_from;                   /* 1 initial confirmation; 2 capacity retest/probe; 3 residual-loss check */
    uint8_t  lt_queue;                  /* a confirmed ceiling's previous probe interval had a queue signal */
    uint32_t lt_span;                   /* policed intervals before the next probe (doubles while confirmed) */
    uint8_t  lt_tail;                   /* probe tail, or first clean residual-loss check interval */
    uint8_t  lt_skip;                   /* the pace just changed: the next round is the transition, not measured */
    uint8_t  lt_res_checked;            /* the current residual has already had a low-rate check */
    uint8_t  lt_res_low;                /* consecutive steady intervals below 7/8 of the residual */
    uint32_t lt_res;                    /* residual (random) loss at lt_rate, per mille, from the test */
    uint64_t lt_infl0;                  /* inflight bytes at the start of the interval */
    uint64_t lt_rd, lt_lost;
    uint32_t lt_rate, lt_prev_rate, lt_prev_loss, lt_ref_loss;  /* prev_rate: prior watch/probe/drop sample; loss per mille */
    uint32_t lt_save_btl;               /* initial test: btl_bw; retest: confirmed lt_rate, restored on failure */
    uint32_t lt_recover_rate;           /* ceiling before a verified fall; faster probes until recovered */
    /* delivered-byte checkpoints spanning max(update interval, 10 ms)
       for bbr_window_bw, even when updates arrive every millisecond */
    uint32_t dw_ts[BBR_DW_SLOTS];
    uint64_t dw_bytes[BBR_DW_SLOTS];
    uint32_t dw_idx, dw_n;              /* newest slot; slots filled */
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
    uint32_t up_bw, up_stall;           /* UP: btl_bw at the last 12.5% growth; rounds since */
    uint32_t probe_rtt_done_ts, probe_rtt_round;
    uint64_t inflight_hi;               /* BBRv2 loss bound on inflight, bytes; 0 = none */
    uint32_t loss_rate;                 /* smoothed per-round loss fraction, 1/256 */
    uint32_t qfall;                     /* consecutive congestive rounds whose delivery rate fell with our cuts */
    uint32_t qflat, qflat_rtt;          /* consecutive loss-free rounds at gain <= 1 whose RTT stayed above min_rtt, and that RTT */
    uint8_t  qflat_probe;               /* the current PROBE_RTT was asked for by qflat: its RTT becomes min_rtt */
    uint8_t  min_rtt_probed;            /* a PROBE_RTT has run since min_rtt last took a lower value */
    uint32_t qfall_rtt, qfall_rate;     /* ... the round min RTT and delivery rate of the last one counted */
    uint32_t round_ts, last_round_rate; /* start of the round; delivery rate of the last round, bytes/s */
    uint32_t round_sent0;               /* sent_wire at the start of the round (its send rate: what the sender needed) */
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

    anl_stream **stab;                  /* sid -> stream: hash chains (hnext) */
    uint32_t stab_mask, stab_n;
    anl_node slist;                     /* every stream struct */
    anl_node ctl_list;                  /* streams with control output pending (flush_control) */
    uint32_t npeer_streams, max_peer_streams;
    uint32_t next_sid;                  /* sids are never reused: client 2,4,6.. server 1,3,5.. */
    /* sids in use order (index = (sid - first) / 2 of each side's sequence, DESIGN 6.1):
       every index below the floor is done, the bitmaps cover the SID_WIN above it */
    uint32_t peer_floor;                /* the peer's sids: seen here (a late first segment gets RST) */
    uint8_t peer_seen[SID_WIN / 8];
    uint32_t own_floor;                 /* our sids: the peer is known to have seen them */
    uint8_t own_heard[SID_WIN / 8];
    anl_accept_fn accept_cb;
    anl_rate_fn rate_cb;
    anl_report_fn report_cb;
    uint64_t tx_payload;                /* first-transmission payload bytes (target_rate) */
    uint32_t fl_sent, fl_lost;          /* FEC streams: first transmissions, lost ones (repaired
                                           by the peer's FEC or not) in the current window */
    uint32_t fec_loss;                  /* raw loss of the connection before FEC, 1/65536 (DESIGN 8.5) */
    int fec_loss_valid;                 /* windows fec_loss has had, up to FEC_LOSS_WARM (0: none yet) */
    uint32_t fec_loss_ts;               /* the last loss with hard evidence (| 1; 0: none yet): a confirmed retry,
                                           RTO, expiry or reported rebuild - not "acknowledged after a higher sn",
                                           which reordering does too (DESIGN 8.6) */
    int64_t par_tokens;                 /* parity budget (DESIGN 8.6), bytes */
    uint32_t par_rate, par_ts;          /* its rate (0xffffffff: no estimate yet), last refill */
    uint32_t par_queue_ts;              /* recent queue evidence: limit RTT-auto parity bursts */
    int capacity_short;                 /* the bottleneck is slower than the media: the path delivers well
                                           under what is sent, or frames expire unsent (DESIGN 8.6) - no
                                           adaptive parity, not app-limited */
    uint32_t pay_avg, dlv_avg;          /* ... payload sent / delivered, bytes/s, smoothed over rate steps */
    uint32_t off_avg, unsent_avg;       /* ... semi-reliable payload offered / of it expired unsent, bytes/s */
    uint32_t rate_steps;                /* rate_update steps so far (the averages need a few) */
    uint32_t cs_retry;                 /* steps without queueing before a recovery probe */
    uint32_t cs_recover;               /* successful probe: observation deadline (| 1), 0 otherwise */
    uint32_t cs_test_ts, cs_test_dlv;   /* bounded probe: start time and prior delivered payload rate */
    uint32_t cs_cnt, cs_clear, cs_ts;   /* consecutive steps that read short / clear; last change or failed recovery probe (| 1) */
    int cs_by_unsent;                   /* entered on expiring frames alone (the path delivered what was sent) */
    int cs_net;                         /* the network shows the shortage: payload lost (a sixteenth) or a queue */
    int cs_loss;                        /* ... the loss part alone: app-limited marking is suppressed only then */
    uint32_t cs_calm;                   /* consecutive steps it did not: 5 of them end a state entered on expiry alone */
    int cs_probe;                       /* such a state (or within 5 s of leaving it) with 3 calm steps: bw_lo released,
                                           PROBE_BW probes at once and UP goes on while the estimate grows */
    uint32_t exp_last, exp_prev;        /* the last two expiry events (steps with unsent frames expired, >= 1 s apart; | 1) */
    uint64_t tx_unsent, rate_unsent0;   /* semi-reliable payload dropped before its first send (max_age) */
    uint64_t delivered_pay, rate_dpay0; /* payload bytes acknowledged (repaired ones included) */
    uint64_t purged_unsent;             /* purge_frame: payload bytes taken out of snd_queue, ever */
    uint32_t rate_par0;                 /* sent_par at the last rate_update */
    uint64_t rate_payload0, rate_wire0, rate_deliv0;
    uint32_t rate_ts, rate_share;       /* payload share of the wire bytes, 1/256 */
    uint32_t rate_target, rate_told;    /* target_rate; the value last given to rate_cb */
    uint32_t rate_rtt_min, rate_rtt_old, rate_rtt_ts;  /* min srtt over 15..30 s (two windows) */
    uint32_t pay_avg_prev;              /* pay_avg a step ago: delivery trails sending by a round trip, about a step */
    anl_stream *dflt;                   /* default stream, sid 0 */
    uint32_t *rstq;                     /* pending RSTs for sids without any state */
    int nrstq, rstq_cap;
    uint32_t *rst_set;                  /* dedupe for rstq: open addressing, 2 x rstq_cap slots, 0 = free */

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

/* stream table: hash chains, grown (x2) when there are more streams than chains */
static uint32_t sid_hash(uint32_t sid) { return (sid * 0x9E3779B1u) ^ (sid >> 15); }

static anl_stream *sget(const anl_t *w, int sid)
{
    anl_stream *st;
    if (sid < 0 || (uint32_t)sid > ANL_MAX_SID || w->stab == NULL) return NULL;
    for (st = w->stab[sid_hash((uint32_t)sid) & w->stab_mask]; st != NULL; st = st->hnext)
        if (st->sid == sid) return st;
    return NULL;
}

static int stab_grow(anl_t *w)
{
    uint32_t n = w->stab ? (w->stab_mask + 1) * 2 : 16, i;
    anl_stream **t = (anl_stream **)anl_malloc(sizeof(anl_stream *) * n);
    if (t == NULL) return ANL_ENOMEM;
    memset(t, 0, sizeof(anl_stream *) * n);
    for (i = 0; w->stab && i <= w->stab_mask; i++) {
        anl_stream *st = w->stab[i], *nx;
        for (; st != NULL; st = nx) {
            nx = st->hnext;
            st->hnext = t[sid_hash((uint32_t)st->sid) & (n - 1)];
            t[sid_hash((uint32_t)st->sid) & (n - 1)] = st;
        }
    }
    anl_free(w->stab);
    w->stab = t;
    w->stab_mask = n - 1;
    return 0;
}

static int sput(anl_t *w, anl_stream *st)
{
    anl_stream **head;
    if ((w->stab == NULL || w->stab_n >= w->stab_mask + 1) && stab_grow(w) != 0 && w->stab == NULL)
        return ANL_ENOMEM;                  /* a failed growth only lengthens the chains */
    head = &w->stab[sid_hash((uint32_t)st->sid) & w->stab_mask];
    st->hnext = *head;
    *head = st;
    w->stab_n++;
    qadd_tail(&st->lnode, &w->slist);
    return 0;
}

/* take the stream out of the sid table; it stays in slist */
static void sdetach(anl_t *w, anl_stream *st)
{
    if (!st->detached && w->stab) {
        anl_stream **pp = &w->stab[sid_hash((uint32_t)st->sid) & w->stab_mask];
        for (; *pp != NULL; pp = &(*pp)->hnext)
            if (*pp == st) { *pp = st->hnext; w->stab_n--; break; }
    }
    st->hnext = NULL;
    st->detached = 1;
}

/* sids in use order (DESIGN 6.1): each side opens its own parity in ascending
 * order, so "used" is a floor plus a window of SID_WIN indices above it */
static uint32_t sid_first(int role) { return role == ANL_ROLE_CLIENT ? 2u : 1u; }

static int win_test(const uint8_t *bits, uint32_t floor, uint32_t i)
{
    return i < floor || (i - floor < SID_WIN && ((bits[(i % SID_WIN) >> 3] >> (i & 7)) & 1));
}

/* mark index i (floor <= i < floor + SID_WIN) and move the floor over the done prefix */
static void win_mark(uint8_t *bits, uint32_t *floor, uint32_t i)
{
    if (i < *floor || i - *floor >= SID_WIN) return;
    bits[(i % SID_WIN) >> 3] |= (uint8_t)(1u << (i & 7));
    while (bits[(*floor % SID_WIN) >> 3] & (1u << (*floor & 7))) {
        bits[(*floor % SID_WIN) >> 3] &= (uint8_t)~(1u << (*floor & 7));
        (*floor)++;
    }
}

/* the peer has heard of one of our sids (any segment or RST from it): opening
 * new sids may run up to SID_WIN past the oldest one it has not (anl_stream_open) */
static void own_heard_mark(anl_t *w, int sid)
{
    uint32_t first = sid_first(w->role);
    if (sid <= 0 || ((uint32_t)sid & 1) != (first & 1) || (uint32_t)sid < first) return;
    win_mark(w->own_heard, &w->own_floor, ((uint32_t)sid - first) / 2);
}

static void peer_heard(anl_t *w, anl_stream *st)
{
    if (!st->peer_opened) own_heard_mark(w, st->sid);
    st->peer_opened = 1;
}

static uint32_t sid_bytes(int sid) { return (uint32_t)sid >> SID_LO_BITS ? 4u : 2u; }

/* a stream's payload per segment: the connection's, less the sid extension */
static uint32_t stream_mss(const anl_t *w, int sid) { return w->mss + 2 - sid_bytes(sid); }

/* schedule control output (ACK / RST / CLOSE / probe) for the next flush_control */
static void ctl_mark(anl_stream *st)
{
    if (st->cnode.next == NULL) qadd_tail(&st->cnode, &st->w->ctl_list);
}

static char *enc_sid(char *p, int type, int sid)
{
    uint32_t hi = (uint32_t)sid >> SID_LO_BITS;
    p = enc8(p, (uint8_t)((type << 6) | (hi ? SID_X : 0) | ((sid >> 8) & SID_HI_MASK)));
    p = enc8(p, (uint8_t)(sid & 0xff));
    return hi ? enc16(p, (uint16_t)hi) : p;
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
    uint32_t n = sid_bytes(st->sid) + 1 + 3 + (uint32_t)varint_size(seg->len) + seg->len;
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

/* Optional diagnostic hook for the first transition to a dead connection.
 * Timestamps for control-only failures are zero; enqueued is not first sent. */
static void mark_dead(anl_t *w, const char *reason, int sid, uint32_t sn,
                      uint32_t xmit, uint32_t enqueued, uint32_t last_sent)
{
#ifdef ANL_DEAD_TRACE
    if (w->state >= 0) ANL_DEAD_TRACE(w, reason, sid, sn, xmit, enqueued, last_sent);
#else
    (void)reason; (void)sid; (void)sn; (void)xmit; (void)enqueued; (void)last_sent;
#endif
    w->state = -1;
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
enum { FEC_SENT, FEC_LOST, FEC_LATE, FEC_SLOW };  /* fec_auto_count; SLOW: late, already in the loss estimate */
static void fec_auto_count(anl_t *w, anl_stream *st, int lost);
static void fec_loss_add(anl_t *w, uint32_t sent, uint32_t lost, int hard);
static uint32_t fec_parities_for(uint32_t k, uint32_t p, uint32_t fail);
static uint32_t fec_repair_ms(const anl_t *w, const anl_stream *st, uint32_t bytes);
static int fec_active(const anl_t *w, const anl_stream *st);

static void dg_begin(anl_t *w)
{
    w->ptr = ANL_OVERHEAD;
    w->dg_has_data = 0;
}

static uint32_t dg_room(const anl_t *w) { return w->mtu - w->ptr; }

static void dg_output(anl_t *w, int force_pad)
{
    uint8_t flg = (uint8_t)(ANL_VERSION << 6);
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
#ifdef ANL_TX_OUTPUT_TRACE
    ANL_TX_OUTPUT_TRACE(w, w->ptr, w->dg_has_data);
#endif
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
#ifdef ANL_SEG_COMMIT_TRACE
    ANL_SEG_COMMIT_TRACE(w, size, is_data);
#endif
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
    p = enc24(p, seg->sn & SN_MASK);
    if (seg->flags & F_HAS_FRAME) p = enc16(p, (uint16_t)seg->frame_no);
    if (!st->peer_opened) p = enc_open_body(p, st);
    p = enc_varint(p, seg->len);
    memcpy(p, seg->data, seg->len);
    dg_commit(w, size, 1);
#ifdef ANL_DATA_SEG_TRACE
    ANL_DATA_SEG_TRACE(w, st, size, seg->xmit == 0);
#endif
}

static void write_fwd_seg(anl_t *w, const anl_stream *st, uint32_t new_una)
{
    uint32_t size = sid_bytes(st->sid) + 3;
    char *p;
    dg_need(w, size);
    p = dg_ptr(w);
    p = enc_sid(p, SEG_FWD, st->sid);
    (void)enc24(p, new_una & SN_MASK);
    dg_commit(w, size, 0);
}

static void write_ctrl_seg(anl_t *w, int sid, uint8_t subtype, const uint8_t *body, uint32_t blen)
{
    uint32_t size = sid_bytes(sid) + 1 + (uint32_t)varint_size(blen) + blen;
    char *p;
    dg_need(w, size);
    p = dg_ptr(w);
    p = enc_sid(p, SEG_CTRL, sid);
    p = enc8(p, subtype);
    p = enc_varint(p, blen);
    if (blen) memcpy(p, body, blen);
    dg_commit(w, size, subtype == CTRL_PARITY);
#ifdef ANL_PARITY_SEG_TRACE
    if (subtype == CTRL_PARITY) ANL_PARITY_SEG_TRACE(w, sid, size);
#endif
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
    /* rebuilds net of the ones whose original arrived after all (those
       were reordering, not loss - a lossless real path: 461 "repairs" in 5
       minutes, and audio duplicated for all of it) and of the ones too
       young for the original to have come yet */
    uint32_t i, young = 0;
    for (i = 0; i < FEC_REC_RING && i < st->fec_rec_i; i++)
        if (st->fec_rec_ts[i] != 0 && tdiff(w->current, st->fec_rec_ts[i]) < FEC_REC_GRACE_MS) young++;
    (void)enc16(p, (uint16_t)(r->fec_recovered - st->fec_spurious - young));
    write_ctrl_seg(w, st->sid, CTRL_REPORT, body, REPORT_BODY);
}

static void handle_report(anl_t *w, anl_stream *st, const char *p, uint32_t ts)
{
    anl_delay_report *r = &st->peer_rp;
    uint32_t rec0 = r->fec_recovered, skip0 = r->frames_skipped;
    int had_report = r->valid;
    /* Reports contain cumulative 16-bit counters. A delayed older report
       would look like a wrap and invent up to 65535 recovered losses. */
    if (had_report && tdiff(ts, st->peer_rp_wire_ts) <= 0) return;
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
    st->peer_rp_wire_ts = ts;
    if (st->fec && had_report) {
        /* the repairs it reports are losses FEC hid from RACK (the rebuilt
           packet's ACK usually beats the mark; a mark that lost the race is
           undone at that ACK); each skip is a frame FEC and retransmission
           did not bring in time (DESIGN 8.5); both bounded against garbage */
        uint32_t skips = umin32((uint16_t)(r->frames_skipped - skip0), 64), i;
        uint32_t rec = (uint16_t)(r->fec_recovered - rec0);
        if (rec > 0x8000) rec = 0;          /* the count went down: rebuilds turned out spurious */
        fec_loss_add(w, 0, umin32(rec, 256), 1);
        for (i = 0; i < skips; i++) fec_auto_count(w, st, FEC_LATE);
        /* a frame took 3/4 of a round trip beyond its packets' queueing: a
           retransmission (at least a round trip) completed it - late where
           one cannot make the deadline. (Half a round trip also caught key
           frames paced over that long.) Its loss is counted already. A
           rebuild waits for its block's parity, up to FEC_BLOCK_MS after
           the frame: beyond that as well (counted from the queueing alone,
           every repair read as a retransmission - at 100 ms RTT and 5% loss
           the ratio ran to its ceiling on FEC's own successes) */
        if (r->frames > 0 && w->rx_srtt > 0 &&
            r->frame_delay_max_ms > r->qdelay_max_ms + (uint32_t)w->rx_srtt * 3 / 4 +
                                    (fec_active(w, st) ? FEC_BLOCK_MS : 0) &&
            fec_repair_ms(w, st, st->fec_frame_avg) > st->fec_deadline)
            fec_auto_count(w, st, FEC_SLOW);
    }
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
    uint8_t body[CLOSE_BODY + OPEN_BODY];
    int open = st != NULL && !st->peer_opened && !rst;
    uint8_t flags = (uint8_t)((rst ? CLOSE_F_RST : 0) | (open ? CLOSE_F_OPEN : 0));
    char *p = (char *)body;
    if (!rst && st != NULL) {
        /* our FIN once our direction is closed, an acknowledgement of the
           peer's once we have it (DESIGN 6.1) */
        if (st->state == ANL_STREAM_OPEN) { flags |= CLOSE_F_NOFIN; final_sn = 0; }
        else if (st->half) flags |= CLOSE_F_HALF;
        if (st->peer_closed) flags |= CLOSE_F_ACKFIN;
    }
    p = enc24(p, final_sn & SN_MASK);
    p = enc8(p, flags);
    p = enc24(p, (st != NULL ? st->rcv_nxt : 0) & SN_MASK);
    if (open) p = enc_open_body(p, st);
    write_ctrl_seg(w, sid, CTRL_CLOSE, body, (uint32_t)(p - (char *)body));
}

/* Over the connection's receive cap only the streams whose application
 * leaves data unread lose their window; a stream that is read keeps it -
 * otherwise a few unread streams with large windows stop every other stream
 * of the connection (DESIGN 6.1) */
static uint32_t wnd_unused(const anl_t *w, const anl_stream *st)
{
    if (st->nrcv_que >= st->rcv_wnd) return 0;
    if (w->rcv_limited && st->nrcv_que >= RCV_HELD_MAX) return 0;
    return st->rcv_wnd - st->nrcv_que;
}

/* ACK: una + SACK ranges of rcv_buf (DESIGN 5.3). A range (a run) is reported
 * until it has gone out in SACK_REPEAT ACKs since it last changed, so a lost
 * ACK costs nothing as long as one of the next ones gets through. The first
 * range starts at una (gap 0) when the queue is full and rcv_nxt is held. */
static void write_ack_segs(anl_t *w, anl_stream *st)
{
    uint32_t maxroom = w->mtu - ANL_OVERHEAD;
    uint8_t b1 = (uint8_t)((st->probe_ask ? ACK_F_WASK : 0) | (st->ack_fresh ? ACK_F_FRESH : 0));
    anl_node *pos = st->rcv_runs.next;
    char *rb = w->scratch + w->mtu;         /* range bytes; segment assembled in scratch */
    int skip;
    /* Progress by a full sending window proves the peer retired this prefix,
       even if the first ACK carrying it was lost. Use the full 32-bit value. */
    if (st->rcv_skip_valid && tdiff(st->rcv_nxt, st->rcv_skip_una) >= ANL_MAX_WND)
        st->rcv_skip_valid = 0;
    skip = st->rcv_skip_valid;
    if (skip) maxroom -= sid_bytes(st->sid) + 1 + 1 + SKIP_BODY;

    do {
        char *p = w->scratch;
        uint32_t cnt = 0, prev = st->rcv_nxt, rlen = 0, seglen;
        while (pos != &st->rcv_runs) {
            rcv_run *r = RUN_OF(pos);
            if (r->rep < SACK_REPEAT) {
                uint32_t bytes = (uint32_t)varint_size(r->start - prev) + (uint32_t)varint_size(r->end - r->start);
                if (sid_bytes(st->sid) + ACK_FIX + (uint32_t)varint_size(cnt + 1) + rlen + bytes > maxroom) break;  /* next ACK segment */
                (void)enc_varint(enc_varint(rb + rlen, r->start - prev), r->end - r->start);
                rlen += bytes;
                cnt++;
                prev = r->end;
                r->rep++;
            }
            pos = pos->next;
        }
        p = enc_sid(p, SEG_ACK, st->sid);
        p = enc8(p, b1);
        p = enc24(p, st->rcv_nxt & SN_MASK);
        p = enc16(p, (uint16_t)wnd_unused(w, st));
        p = enc32(p, st->ack_ts);
        p = enc_varint(p, cnt);
        memcpy(p, rb, rlen);
        p += rlen;
        seglen = (uint32_t)(p - w->scratch);
        /* Keep the retirement marker and its ACK in the same datagram:
           losing the marker alone would turn a skipped prefix into credit. */
        dg_need(w, seglen + (skip ? sid_bytes(st->sid) + 1 + 1 + SKIP_BODY : 0));
        if (skip) {
            uint8_t body[SKIP_BODY];
            (void)enc32((char *)body, st->rcv_skip_una);
            write_ctrl_seg(w, st->sid, CTRL_RCV_SKIP, body, sizeof(body));
        }
        memcpy(dg_ptr(w), w->scratch, seglen);
        dg_commit(w, seglen, 0);
    } while (pos != &st->rcv_runs);

    /* An ACK that carried news is sent once more an update interval later
       unless another one goes out first: the receiver of a frame-paced
       stream sends nothing between frames, so losing a frame's last ACK left
       its segments to the sender's RTO before the next frame's ACK came. The
       repeat is not FRESH: no RTT sample, no RACK time. */
    st->ack_rep_ts = st->ack_fresh ? (w->current + (uint32_t)w->interval) | 1 : 0;
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
static uint32_t bbr_rtt(const anl_t *w);
static void vq_add(anl_t *w, uint32_t wire);
static uint32_t bbr_lt_probe_rate(const anl_t *w);
static int bbr_queue_signal(const anl_t *w);
static uint64_t bbr_inflight_bytes(const anl_t *w);

/* Burst headroom for an app-limited sender whose bandwidth estimate only
 * shows what the application offered: a key frame goes out at the STARTUP
 * gain and its samples find the path. Not when the path was measured in the
 * last BBR_BW_ROUNDS rounds: then the estimate is the path, and a burst
 * above it would only move the queue from the sender - where a control
 * stream overtakes it - into the network, where nothing can. A bounded
 * capacity-recovery probe also gets headroom: its old model is precisely
 * what it is testing (rate_update); adaptive parity stays off meanwhile. */
static int bbr_headroom(const anl_t *w)
{
    return w->cs_test_ts != 0 || (w->app_limited != 0 &&
           (w->net_round == 0 || tdiff(w->round_count, w->net_round) > BBR_BW_ROUNDS));
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
       per RTT, at the STARTUP gain. The normal floor is BBR_MIN_CWND segments
       per RTT, bounded by a policer test/confirmed/probe target when active;
       never above cfg.pace_rate when that is set. */
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
    /* A lower-rate trial must be executable. At 1 ms RTT / 10 ms interval,
       the ordinary floor is 4.38 Mbps: it defeated a 2.87 Mbps trial on a
       3 Mbps policer, so the remaining loss falsely rejected the trial.
       Retain the floor outside policer control and allow explicit up-probes. */
    if (w->lt_state != 0 && w->lt_rate != 0) {
        uint32_t target = w->lt_state == 3 ? bbr_lt_probe_rate(w) : w->lt_rate;
        if (floor > target) floor = target;
    }
    if (rate < floor) rate = floor;
    /* app-limited: bursts (key frames) at the rate the last ones went through
       at, x 1.25 to find more (burst_bw, burst_on_acked) - to their end, when
       the ACKs of their first segments ended the app-limited period */
    if (bbr_burst(w) && (uint64_t)w->burst_bw * 5 / 4 > rate) rate = (uint64_t)w->burst_bw * 5 / 4;
    if (w->start_cap != 0 && rate > w->start_cap) rate = w->start_cap;
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
#ifdef ANL_PACE_REFILL_TRACE
        ANL_PACE_REFILL_TRACE(w, (uint32_t)dt, (uint64_t)earned,
                              w->pace_tokens > cap ? (uint64_t)(w->pace_tokens - cap) : 0);
#endif
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

/* take a segment out of snd_buf (acknowledged or abandoned); the caller frees it */
static void snd_unlink(anl_stream *st, anl_seg *s)
{
    qdel(&s->node);
    if (s->tnode.next) qdel(&s->tnode);
    st->nsnd_buf--;
    if (s->lost) st->nlost--;
    backlog_sub(st, s->len);
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
    QINIT(&st->snd_time);
    st->nsnd_que = st->nsnd_buf = st->nlost = 0;
    st->backlog_bytes = 0;
    st->fwd_pending = 0;
    st->snd_una = st->snd_nxt;
}

/* the last run starting at or below sn, NULL if none: a walk over the runs from
 * the newest - arrivals are mostly at the top */
static rcv_run *run_find(const anl_stream *st, uint32_t sn)
{
    anl_node *pos;
    for (pos = st->rcv_runs.prev; pos != &st->rcv_runs; pos = pos->prev)
        if (tdiff(sn, RUN_OF(pos)->start) >= 0) return RUN_OF(pos);
    return NULL;
}

/* link a new segment (not in any run, r = run_find) into rcv_buf and the runs;
 * 0 if there was no memory for a new run (the caller frees seg) */
static int rcv_link(anl_stream *st, anl_seg *seg, rcv_run *r)
{
    anl_node *np = r ? r->node.next : st->rcv_runs.next;
    rcv_run *next = np != &st->rcv_runs ? RUN_OF(np) : NULL;
    uint32_t sn = seg->sn;
    if (r && r->end == sn) {
        qadd_after(&seg->node, &r->last->node);
        r->last = seg;
        r->end++;
        r->rep = 0;
        if (next && next->start == r->end) {        /* the hole between them is filled */
            r->end = next->end;
            r->last = next->last;
            qdel(&next->node);
            anl_free(next);
        }
    } else if (next && next->start == sn + 1) {
        qadd_after(&seg->node, next->first->node.prev);
        next->first = seg;
        next->start = sn;
        next->rep = 0;
    } else {
        rcv_run *nr = (rcv_run *)anl_malloc(sizeof(rcv_run));
        if (nr == NULL) return 0;
        nr->start = sn;
        nr->end = sn + 1;
        nr->rep = 0;
        nr->first = nr->last = seg;
        qadd_after(&seg->node, r ? &r->last->node : &st->rcv_buf);
        qadd_after(&nr->node, r ? &r->node : &st->rcv_runs);
    }
    st->nrcv_buf++;
    return 1;
}

/* unlink the lowest segment of rcv_buf (the caller queues or frees it) */
static anl_seg *rcv_pop_first(anl_stream *st)
{
    rcv_run *r = RUN_OF(st->rcv_runs.next);
    anl_seg *s = r->first;
    if (s == r->last) {
        qdel(&r->node);
        anl_free(r);
    } else {
        r->first = QENTRY(s->node.next, anl_seg, node);
        r->start++;
    }
    qdel(&s->node);
    st->nrcv_buf--;
    return s;
}

static void free_runs(anl_stream *st)
{
    while (!QEMPTY(&st->rcv_runs)) {
        rcv_run *r = RUN_OF(st->rcv_runs.next);
        qdel(&r->node);
        anl_free(r);
    }
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
static uint32_t *rst_slot(const anl_t *w, uint32_t sid)
{
    uint32_t mask = 2u * (uint32_t)w->rstq_cap - 1, i = sid_hash(sid) & mask;
    while (w->rst_set[i] != 0 && w->rst_set[i] != sid) i = (i + 1) & mask;
    return &w->rst_set[i];
}

static void rstq_push(anl_t *w, int sid)
{
    int i;
    if (sid <= 0) return;                   /* the default stream always has state */
    if (w->rstq_cap && *rst_slot(w, (uint32_t)sid) == (uint32_t)sid) return;
    if (w->nrstq == w->rstq_cap) {
        /* grow: many streams may be closed at once and must all get their RST */
        int cap = w->rstq_cap ? w->rstq_cap * 2 : 32;
        uint32_t *q = (uint32_t *)anl_malloc(sizeof(uint32_t) * (size_t)cap);
        uint32_t *set = (uint32_t *)anl_malloc(sizeof(uint32_t) * 2 * (size_t)cap);
        if (q == NULL || set == NULL) { anl_free(q); anl_free(set); return; }
        if (w->nrstq) memcpy(q, w->rstq, sizeof(uint32_t) * (size_t)w->nrstq);
        memset(set, 0, sizeof(uint32_t) * 2 * (size_t)cap);
        anl_free(w->rstq);
        anl_free(w->rst_set);
        w->rstq = q;
        w->rst_set = set;
        w->rstq_cap = cap;
        for (i = 0; i < w->nrstq; i++) *rst_slot(w, w->rstq[i]) = w->rstq[i];
    }
    w->rstq[w->nrstq++] = (uint32_t)sid;
    *rst_slot(w, (uint32_t)sid) = (uint32_t)sid;
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
    free_runs(st);
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
        /* after a half-close the peer still reads: it must have our FIN (or
           it never sees the end of stream). After a full close nobody reads
           there - a lost answer is settled by the RST to its next FIN, as in
           version 0 */
        if (!st->fin_acked && st->peer_half) return;
        if (st->nsnd_buf > 0 || st->nsnd_que > 0) return;
        if (tdiff(st->rcv_nxt, st->peer_final_sn) < 0) return;
    }
    st->state = ANL_STREAM_CLOSED;
    stream_free_send_side(st);
    fec_free(st);
    free_runs(st);
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
    st->close_rto = 0;
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
        /* the first interval starts now: from 0 it "started" 24.8 days
           ago or, on a host whose millisecond clock has passed 2^31, in the
           future - no interval ever closed, the peer never got a report
           (real network, every batch on that host) */
        st->rp_next = w->current;
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
    while (!QEMPTY(&st->rcv_runs)) {
        anl_seg *s;
        if (RUN_OF(st->rcv_runs.next)->start != st->rcv_nxt || st->nrcv_que >= st->rcv_wnd) break;
        s = rcv_pop_first(st);
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
    while (!QEMPTY(&st->rcv_runs) && tdiff(RUN_OF(st->rcv_runs.next)->start, new_una) < 0) {
        anl_seg *s = rcv_pop_first(st);
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
    peer_heard(w, st);
    return st;
}

/* a peer-opened sid without a stream here: 1 used before (RST), 0 new, -1 to be
 * ignored - not the peer's parity, or further ahead of the oldest one not seen
 * yet than SID_WIN (the peer keeps announcing it; anl_stream_open) */
static int peer_sid_state(const anl_t *w, int sid)
{
    uint32_t first = sid_first(1 - w->role), i;
    if (sid <= 0 || ((uint32_t)sid & 1) != (first & 1)) return -1;
    i = ((uint32_t)sid - first) / 2;
    if (win_test(w->peer_seen, w->peer_floor, i)) return 1;
    return i - w->peer_floor < SID_WIN ? 0 : -1;
}

static void peer_sid_mark(anl_t *w, int sid)
{
    win_mark(w->peer_seen, &w->peer_floor, ((uint32_t)sid - sid_first(1 - w->role)) / 2);
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
    st->fec_rec_ts[st->fec_rec_i % FEC_REC_RING] = w->current | 1;
    st->fec_rec_pts[st->fec_rec_i % FEC_REC_RING] = ts;
    st->fec_rec_ring[st->fec_rec_i++ % FEC_REC_RING] = sn;
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
    base = extend24(dec24(&p), st->rcv_nxt);
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
    anl_seg *seg;
    rcv_run *r;

    if (st->mode == ANL_RELIABLE && (flags & F_HAS_FRAME)) { stream_reset(w, st); return; }

    if (!recovered) {
        uint32_t i;
        st->ack_ts = ts; st->ack_fresh = 1;
        /* the original of a packet FEC rebuilt, sent before the parity it
           was rebuilt from: it was reordered, not lost - the rebuild is
           taken out of the loss evidence (report). Sent after the parity
           it is a retransmission of a real loss (RACK fired before the
           rebuild's ACK arrived) */
        for (i = 0; i < FEC_REC_RING && st->fec_rec_i != 0; i++)
            if (st->fec_rec_ring[i] == sn && st->fec_rec_ts[i] != 0 && tdiff(ts, st->fec_rec_pts[i]) <= 0) {
                st->fec_rec_ts[i] = 0; st->fec_spurious++; break;
            }
    }
    if (tdiff(sn, st->rcv_nxt + st->rcv_wnd) >= 0) {
        /* beyond the window. On a semi-reliable stream the sender has moved
           on: it abandoned everything below sn - rcv_wnd while we heard no
           FWD (the peer was unreachable for longer than a window of frames:
           a receiver started 25 s after the sender, or an outage). Nothing
           can be stored, but the ACK tells the sender we are alive and where
           we stand, so that it repeats the FWD now instead of at the end of
           its backoff (handle_ack; 20 s of silence on a live path before). */
        if (st->mode == ANL_SEMI) ack_schedule(st);
        return;
    }
    ack_schedule(st);
#ifdef ANL_DUP_TRACE
    if (!recovered && (tdiff(sn, st->rcv_nxt) < 0 || ((r = run_find(st, sn)) && tdiff(sn, r->end) < 0)))
        ANL_DUP_TRACE(w, st, sn);
#endif
    if (tdiff(sn, st->rcv_nxt) < 0) return;

    r = run_find(st, sn);
    if (r && tdiff(sn, r->end) < 0) {
        /* the sender retransmitted it: it may not have heard of it, report again */
        r->rep = 0;
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
    if (!rcv_link(st, seg, r)) { seg_free(seg); return; }
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
        snd_unlink(st, s);
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
    /* A repeated reliable retransmission must not stay phase-locked to the
       empty part of a policer's token cycle. With a 1 ms RTT, a later packet
       was delivered while the same missing packet lost 20 transmissions in
       64 ms. Space repeated fast retries by 4, 8, 16 ... ms, capped by its
       existing RTO (and 256 ms). The first fast retry and semi deadlines keep
       their original timing; RTO backoff and dead_link remain unchanged. */
    if (st->mode == ANL_RELIABLE && seg->xmit > 1) {
        uint32_t shift = seg->xmit > 8 ? 8 : seg->xmit;
        uint32_t pause = umin32(seg->rto, 1u << shift);
        if (tdiff(w->current, seg->ts_sent) < (int32_t)pause) return 0;
    }
    if (w->rack_valid && tdiff(ts, w->rack_ts) < 0) return 1;
    return st->rack_valid && tdiff(ts, st->rack_ts) <= 0 && tdiff(seg->sn, st->rack_hi) < 0;
}

/* RACK loss detection (RFC 8985): a segment sent before the newest delivered
 * datagram is lost once it has been outstanding for that one's RTT plus the
 * reordering window. Runs on every ACK and on every flush (the timer). The
 * walk is in the order of transmission (snd_time) and stops at the first
 * segment sent after the newest delivered one - everything later was sent
 * later still (rack_sent is never before ts_sent) - so that it costs the
 * suspects, not the window (DESIGN 5.1). */
static int rack_detect(anl_t *w, anl_stream *st)
{
    anl_node *pos;
    uint32_t wait, newest;
    int marked = 0;
    if (!w->rack_valid) return 0;
    wait = w->rack_rtt + reo_wnd(w, st);
    newest = st->rack_valid && tdiff(st->rack_ts, w->rack_ts) > 0 ? st->rack_ts : w->rack_ts;
    for (pos = st->snd_time.next; pos != &st->snd_time; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, tnode);
        if (tdiff(s->ts_sent, newest) > 0 || tdiff(w->current, s->ts_sent + wait) < 0) break;
        if (rack_candidate(w, st, s) && tdiff(w->current, rack_sent(s) + wait) >= 0) {
            s->lost = 1;
            st->nlost++;
            marked++;
            /* counted for congestion control now (Linux BBR does the same):
               waiting for the retransmission's ACK put the loss 1-2 RTTs
               late, after a policer's bucket had let STARTUP overshoot -
               the rounds that should have stopped it saw none (DESIGN 13.28).
               Undone if the original turns up (handle_ack, Eifel). Not for a
               segment the RTO already retransmitted: after an outage the
               first ACK marks everything sent during it at once - 86% of the
               round, which reads as a policer (BBR_LOSS_BLIND) and held bw_lo
               and inflight_hi down for 800 ms after the link came back (soak
               outage, inter p99 +8%). Those count when their recovery is
               acknowledged (handle_ack), spread over the rounds it takes. */
            if (!s->lost_cnt && s->rack_rtx != 2) {
                s->lost_cnt = 1;
                w->lost_bytes += seg_wire(s);
                /* the FEC loss estimate (DESIGN 8.5): a loss FEC did not
                   hide (or has not yet: undone if the original's ACK comes,
                   handle_ack) - whether or not the peer reports */
                if (s->xmit == 1 && st->fec) fec_loss_add(w, 0, 1, 0);   /* hard only once the retransmission is confirmed (handle_ack) */
            }
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
    uint32_t par;                       /* ... of which parity */
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
    /* probing above it: one step of a quarter per interval (bbr_policer) */
    if (w->lt_state == 3) return bbr_lt_probe_rate(w);
    return w->lt_state != 0 && w->lt_rate < bw ? w->lt_rate : bw;
}

/* A token-bucket policer drops what exceeds its rate without queueing it:
 * loss without a queue, which BBR here does not take as congestion (random
 * loss on a radio link looks the same), and the send-rate credit then keeps
 * the sender at up to 1.5x the rate - 40% of the packets lost (a home uplink,
 * real network, DESIGN 13.22). Told apart by the response (BBRv1's long-term
 * sampling plus a test): two intervals (>= BBR_LT_ROUNDS rounds and 300 ms)
 * in a row, network-limited, no queue, over 10% lost, delivering the same
 * rate within 1/4 - then an interval paced at that rate. Halving the loss
 * starts a probe for the ceiling; a failed test holds off for 48 intervals.
 *
 * The test alone passes on any path whose capacity is above the rate (a
 * jittery 50 Mbps uplink was locked at 33 for two minutes, DESIGN 13.27): a
 * policer is a ceiling, so the test is followed by intervals paced a
 * quarter above the rate, then another quarter, and so on (lt_state 3,
 * lt_k). Delivery stays at the rate and the excess is lost: the ceiling,
 * and the policed state starts there. Delivery follows the pace: the
 * ceiling, if there is one, is higher - the next step looks for it. Not
 * "no policer": a 48 Mbps shaper with a burst allowance passed the first
 * step for a whole interval (real network, DESIGN 13.29), and rejected, the
 * sender went back to 1.5x the rate with a fifth lost for a minute. After
 * BBR_LT_PROBE_MAX steps (5x the rate) exhaust the probe budget; a larger
 * bucket or higher ceiling can still escape detection.
 *
 * Intervals are >= BBR_LT_ROUNDS rounds and 300 ms: at 280 ms RTT the
 * 16-round intervals of DESIGN 13.22 took 9 s to enter the test and 18 s
 * to a verdict, at 1.5x the policer's rate with a quarter lost.
 *
 * The policed state does not simply expire either: on a sub-millisecond
 * path the token bucket the policer refilled while we paced below its rate
 * passed everything, the samples ran off to the line rate within tens of
 * milliseconds and 2400 segments were in flight before the bucket was empty
 * (10000 retransmissions every 15 s, DESIGN 13.28). Instead the same probe
 * runs after lt_span intervals: pace a quarter above the rate, then another
 * quarter, and so on. The ceiling shows again - lt_rate becomes what was
 * delivered (the policer's rate may have changed) and the policed state
 * resumes for twice as many intervals (up to BBR_LT_SPAN_MAX); after
 * BBR_LT_PROBE_MAX steps without a ceiling the policer is gone, and the
 * bandwidth filter restarts from what the last step delivered. A bucket can
 * pass multiple steps; once it empties, the excess is bounded by the probe
 * rate instead of a window that grew to the line rate. A
 * persistent queue during a probe yields to ordinary congestion control. */
static uint32_t bbr_lt_probe_rate(const anl_t *w)
{
    return sat32((uint64_t)w->lt_rate * (4u + w->lt_k) / 4u);
}

/* the bandwidth filter restarts from a rate (the probe's delivery) */
static void bbr_reset_filter(anl_t *w, uint32_t rate)
{
    uint32_t k;
    for (k = 0; k < BBR_BW_ROUNDS; k++) w->bw_round[k] = rate;
    w->btl_bw = rate;
    w->bw_lo = 0;
}

static void bbr_policer(anl_t *w, uint64_t rd, uint64_t lost, int app_limited)
{
    uint32_t dur, rate, loss, counted;
    if (w->lt_ts == 0) {
        w->lt_ts = w->current | 1; w->lt_sent0 = w->sent_wire; w->lt_infl0 = bbr_inflight_bytes(w);
#ifdef ANL_POLICER_BEGIN_TRACE
        ANL_POLICER_BEGIN_TRACE(w);
#endif
    }
    /* Just after STARTUP a round over 25% lost, delivering less than half
       the estimate, clears what the filter kept
       of STARTUP: a policer with a large bucket let STARTUP measure 4x its
       rate, and the filter took 10 s to come down through its rounds at
       277 ms RTT - retransmissions sent at 2-4x the rate were lost again and
       again, delivery stalled and resumed second by second (29000
       retransmissions in 13 s, DESIGN 13.27). The round's delivery rate is
       where the model restarts; probing finds any more. (Starting the
       policer test there instead locked a 45 Mbps path at 33 for two
       minutes: the test passes whenever the rate is below the capacity.) */
    if (w->post_startup > 0) {
        w->post_startup--;
        /* a round of at least half the window: losses are counted when RACK
           marks them (rack_detect), and a short round of a 20% random-loss
           path (a few segments delivered between two marks) showed 27%
           and pulled the filter down to a quarter (s1 20%/200 ms) */
        if (!app_limited && rd > 0 && lost * 4 > rd + lost && rd + lost >= (uint64_t)w->cwnd * w->avg_seg / 2) {     /* over 25%: a burst or jitter makes 10% */
            uint32_t dur0 = (uint32_t)tdiff(w->current, w->round_ts);
            uint32_t r = dur0 > 0 ? (uint32_t)umin32((uint32_t)(rd * 1000 / dur0), 0xffffffffu) : 0;
            if (r != 0 && (uint64_t)r * 2 < w->btl_bw) {       /* random loss still delivers most of it */
                uint32_t k;
                for (k = 0; k < BBR_BW_ROUNDS; k++) w->bw_round[k] = umin32(w->bw_round[k], r);
                w->btl_bw = r;
                w->bw_lo = 0;
            }
            w->post_startup = 0;
        }
    }
    /* the first round at a new pace is the transition: what was in flight
       at the old pace is still being dropped (a third of it after 1.5x the
       rate) and would be the new interval's loss - 14% in a test paced at
       the rate, which failed (30 Mbps policer, 100 ms); it is left out */
    if (w->lt_skip) {
        w->lt_skip = 0;
        w->lt_rd = w->lt_lost = 0;
        w->lt_rounds = 0;
        w->lt_bad = 0;
        w->lt_ts = w->current | 1;
        w->lt_sent0 = w->sent_wire;
        w->lt_infl0 = bbr_inflight_bytes(w);
#ifdef ANL_POLICER_BEGIN_TRACE
        ANL_POLICER_BEGIN_TRACE(w);
#endif
        return;
    }
    w->lt_rd += rd;
    w->lt_lost += lost;
    w->lt_rounds++;
    if (app_limited) w->lt_bad |= 1;
    if (bbr_queue_signal(w)) w->lt_bad |= 2;
    dur = (uint32_t)tdiff(w->current, w->lt_ts);
    if (w->lt_rounds < BBR_LT_ROUNDS || dur < BBR_LT_MS) return;
    /* Intervals ending within LT_GAP_MS of a resumed input gap are dropped:
       the outage's losses, abandoned frames and backlog retransmissions
       read 40..60% lost, and the test interval after them only the path's
       random 20% - "halved", a policer - which locked a 5 Mbit path at
       0.6..0.8 Mbit for the remaining 60 s (simulation, 20 s outage, 180 ms,
       3 of 400 runs). A real policer is found that much later. */
    if (w->lt_gap_ts != 0 && tdiff(w->current, w->lt_gap_ts) < LT_GAP_MS) {
        w->lt_rd = w->lt_lost = 0;
        w->lt_rounds = 0;
        w->lt_bad = 0;
        w->lt_prev_rate = 0;
        w->lt_ts = w->current | 1;
        w->lt_sent0 = w->sent_wire;
        w->lt_infl0 = bbr_inflight_bytes(w);
        return;
    }
    rate = sat32(w->lt_rd * 1000 / dur);
    counted = w->lt_rd + w->lt_lost > 0 ? (uint32_t)(w->lt_lost * 1000 / (w->lt_rd + w->lt_lost)) : 0;
    /* The interval's loss from what it sent and what was delivered - what
       is still in flight at its end was sent but could not be delivered yet,
       what was in flight at its start is delivered in it but was sent
       before: both are taken out, or a 4-round interval is a quarter off.
       The losses counted (RACK) are mostly of what was sent before, found a
       round or more later - at 100 ms RTT they failed every test (sent 1.21
       MB/s, delivered 1.21, "lost" 36%), then held for 48 intervals at 1.5x
       the policer's rate, a third lost (DESIGN 13.25). */
    {
        uint64_t sent = (uint64_t)(w->sent_wire - w->lt_sent0) + w->lt_infl0;
        uint64_t infl = bbr_inflight_bytes(w);
        sent = sent > infl ? sent - infl : 0;
        loss = sent > w->lt_rd ? (uint32_t)((sent - w->lt_rd) * 1000 / sent) : 0;
    }
#ifdef ANL_POLICER_TRACE
    /* Optional internal diagnostics: observe the completed interval before
       the decision, and afterwards while its counters are still intact. */
    ANL_POLICER_TRACE(w, dur, rate, loss, counted, 0);
#endif
    if (w->lt_state != 3) w->lt_queue = 0;
    if (w->lt_state != 2) w->lt_res_low = 0;
    if (w->lt_state == 1 && w->lt_from == 3) {
        /* Recheck a material residual below the previously delivered rate.
           At the compensated ceiling, congestion loss and random loss are
           indistinguishable. Two well-fed, queue-free low-rate intervals
           must both halve it; a quiet interval alone must not erase real
           random loss. An inconclusive check keeps the previous estimate. */
        uint32_t residual = umin32(loss, counted);
        int valid = !w->lt_bad &&
                    (uint64_t)(w->sent_wire - w->lt_sent0) * 8000 / 7 >= (uint64_t)w->lt_rate * dur;
        int clean = valid && loss * 2 < w->lt_res && counted * 2 < w->lt_res;
        if (clean && !w->lt_tail) {
            w->lt_prev_loss = residual;
            w->lt_tail = 1;
        } else {
            w->lt_res_checked = (uint8_t)valid;
            w->lt_rate = w->lt_save_btl;
            if (clean) {
                residual = umax32(residual, w->lt_prev_loss);
                w->lt_rate = sat32((uint64_t)w->lt_rate * (1000 - w->lt_res) / (1000 - residual));
                w->lt_res = residual;
            }
            w->lt_state = 3;
            w->lt_from = 2;
            w->lt_k = 1;
            w->lt_tail = 0;
            w->lt_skip = 1;
        }
        w->lt_prev_rate = 0;
    } else if (w->lt_state == 1) {                      /* the capacity test interval */
        /* A capacity retest must actually offer >=7/8 of its requested rate,
           with no queue signal. Dividing the byte budget first avoids an
           overflow for long intervals. Initial detection keeps its policy. */
        if (loss * 2 < w->lt_ref_loss && !(w->lt_bad & 1) &&
            (w->lt_from != 2 || (!(w->lt_bad & 2) &&
             (uint64_t)(w->sent_wire - w->lt_sent0) * 8000 / 7 >= (uint64_t)w->lt_rate * dur))) {
            /* what is still lost at the policer's rate is random loss: send
               that much more, or random loss on top would pace below the rate.
               The smaller of the two measures: what was sent includes the
               retransmissions of the intervals before (10% on a clean 30
               Mbps policer, paced 6% above it for good), what was counted
               includes their tail (RACK, a round late) */
            w->lt_res = umin32(umin32(loss, counted), 500);
            w->lt_res_checked = 0;
            w->lt_rate = sat32((uint64_t)w->lt_rate * 1000 / (1000 - w->lt_res));
            w->lt_state = 3;                            /* look for the ceiling: a quarter above it */
            w->lt_k = 1;
            if (w->lt_from == 2) {
                w->lt_span = BBR_LT_SPAN;
                w->lt_recover_rate = umax32(w->lt_recover_rate, w->lt_save_btl);
            } else w->lt_from = 1;
            w->lt_hold = 0;
            w->lt_tail = 0;
            w->lt_skip = 1;
            if (w->lt_span == 0) w->lt_span = BBR_LT_SPAN;
        }
        else if (w->lt_from == 2) {
            /* No valid evidence that slowing removed the excess loss.
               Restore the confirmed ceiling and keep the existing probe
               schedule; repeated failed trials also depress random-loss
               throughput even when each one restores the rate afterwards. */
            w->lt_rate = w->lt_save_btl;
            w->lt_state = 2;
            w->lt_hold = w->lt_left;
            w->lt_skip = 1;
        }
        else {
            w->lt_state = 0;
            w->lt_hold = 48;
            /* the loss is random: the estimate from before the test stands
               for another filter window (the test's samples, paced at the
               rate, had taken the filter down to it - heavy20 video on time
               99 -> 96%, DESIGN 13.26) */
            w->bw_round[w->bw_idx] = umax32(w->bw_round[w->bw_idx], w->lt_save_btl);
            w->btl_bw = umax32(w->btl_bw, w->lt_save_btl);
        }
        w->lt_prev_rate = 0;
    } else if (w->lt_state == 3) {                      /* probing above the rate, step lt_k */
        /* Paced lt_rate * (4 + k) / 4, a share k / (4 + k) of what is sent
           is above the rate. A ceiling drops it: the loss rises by that
           much over the residual (lt_res). Random loss does not depend on
           the pace: at 20% it read "an eighth more sent than delivered" and
           locked a 20 Mbps path at 0.8 (s1 20%/50 ms) - it is the rise that
           tells. Half the share: a jittery ceiling drops less. */
        uint32_t excess = 1000u * w->lt_k / (4u + w->lt_k);
        uint32_t sent_rate = sat32((uint64_t)(w->sent_wire - w->lt_sent0) * 1000 / dur);
        /* A window stall can leave a tail below the offered probe rate with
           little loss: its low delivery does not measure the ceiling. Keep
           the old rate without lengthening the retry interval. Still use a
           lossy tail when capacity really fell, even if sending slowed.
           Use the first step's loss margin at every k: a larger nominal
           probe must not make a 15% lossy, underfed tail look loss-free. */
        int tail_limited = w->lt_tail && loss < w->lt_res + 100 &&
            (uint64_t)sent_rate * 8 < (uint64_t)bbr_lt_probe_rate(w) * 7;
        /* At a newly higher ceiling delivery may flatten without a >1/32
           fall in any single step. Each nominal step grows by at least 1/20
           within the probe budget; <=1/32 delivery growth with rising excess
           loss is also a ceiling signal, but only with sufficient offered
           load. Otherwise a pacing/window stall could mimic the plateau. */
        int plateau = (uint64_t)rate <= (uint64_t)w->lt_prev_rate + w->lt_prev_rate / 32 &&
            (uint64_t)sent_rate * 8 >= (uint64_t)bbr_lt_probe_rate(w) * 7;
        if (w->lt_bad & 2) {
            /* A single queued round can taint a whole short-RTT interval.
               When the 300 ms floor dominates its duration, repeat this
               bounded step before discarding an established ceiling. Initial
               detection and RTT-paced intervals retain their queue response. */
            if (w->lt_from == 1 || bbr_rtt(w) >= BBR_LT_MS / BBR_LT_ROUNDS || w->lt_queue) {
                w->lt_state = 0;
                w->lt_hold = 48;
                w->lt_span = 0;
                w->lt_tail = 0;
            }
            w->lt_queue = 1;
            w->lt_prev_rate = 0;
        } else if ((w->lt_bad & 1) || tail_limited) {  /* insufficient offered load: no verdict */
            if (w->lt_from == 1) { w->lt_state = 0; w->lt_hold = BBR_LT_SPAN; w->lt_span = 0; }
            else { w->lt_state = 2; w->lt_left = w->lt_span; }
            w->lt_tail = 0;
        } else if (w->lt_tail) {
            /* the tail: the same pace for an interval with the bucket empty
               (the interval that showed the ceiling delivered the bucket the
               policed state had refilled on top of the rate: 6% over on a
               30 Mbps policer, then 6% lost for good). Its delivery, plus
               the residual, is the policer's rate; not below 7/8 of the
               estimate - one tail can be unlucky, the next probe measures
               again (50 ms tails read 1.35, 1.18, 1.03 MB/s for 1.25 on a
               10 Mbps policer that passes its rate in slices: an interval
               at least, DESIGN 13.29) */
            uint32_t r = sat32((uint64_t)rate * 1000 / (1000 - w->lt_res));
            w->lt_rate = umax32(umin32(r, bbr_lt_probe_rate(w)), w->lt_rate / 8 * 7);
            w->lt_state = 2;
            /* A recently lower ceiling needs timely recovery probes. Once
               it is back within 1/8 of the former value, normal backoff resumes. */
            if (w->lt_recover_rate && (uint64_t)w->lt_rate * 8 >= (uint64_t)w->lt_recover_rate * 7)
                w->lt_recover_rate = 0;
            w->lt_left = w->lt_span;
            w->lt_span = umin32(w->lt_span * 2, w->lt_recover_rate ? BBR_LT_SPAN : BBR_LT_SPAN_MAX);
            w->lt_tail = 0;
        } else if (loss >= w->lt_res + excess / 2 ||
                   (w->lt_prev_rate != 0 && sent_rate >= w->lt_prev_rate &&
                    (rate < w->lt_prev_rate - w->lt_prev_rate / 32 || plateau) &&
                    loss >= w->lt_res + 100)) {
            /* A bucket can empty well above the old estimate: the larger
               k's loss threshold would keep rising while delivery falls.
               Stop also when offered load still covers the previous step's
               delivery, delivery falls >1/32 (or plateaus at sufficient
               load) and loss rises >=100 per mille above the residual
               (the first step's half-excess threshold).
               Neither a delivery dip nor residual random loss alone counts. */
            w->lt_tail = 1;                             /* the ceiling: measure it */
        } else if (++w->lt_k <= BBR_LT_PROBE_MAX) {
            w->lt_prev_rate = rate;
            w->lt_skip = 1;                             /* delivered: the ceiling, if any, is higher - the next step */
        } else {
            /* BBR_LT_PROBE_MAX steps (5x the rate) without a measured ceiling
               (confirming a test: none at the rate it passed at, 48
               intervals without suspicion; the policed state's: it is
               gone, the filter restarts from what the last step delivered) */
            w->lt_state = 0;
            w->lt_hold = w->lt_from == 1 ? 48 : 0;
            w->lt_span = 0;
            bbr_reset_filter(w, rate);
        }
        if (!(w->lt_bad & 2) || w->lt_state != 3) w->lt_queue = 0;
        if (w->lt_state != 3 || w->lt_tail) w->lt_prev_rate = 0;
    } else if (w->lt_state == 2) {
        uint32_t compensated = sat32((uint64_t)rate * 1000 / (1000 - w->lt_res));
        int lower_residual = !w->lt_bad && loss * 8 <= w->lt_res * 7 && counted * 8 <= w->lt_res * 7 &&
                             (uint64_t)(w->sent_wire - w->lt_sent0) * 8000 / 7 >= (uint64_t)w->lt_rate * dur;
        /* Two agreeing, network-limited intervals must show a substantial
           delivery fall and excess loss by both accounting methods. A mixed
           transition interval is not paired with the new steady rate. */
        int reduced = !w->lt_hold && !w->lt_bad &&
                      loss >= w->lt_res + 100 && counted >= w->lt_res + 100 &&
                      compensated > 0 && (uint64_t)compensated * 4 < (uint64_t)w->lt_rate * 3;
        w->lt_res_low = lower_residual ? (uint8_t)umin32(w->lt_res_low + 1u, 2) : 0;
        if (w->lt_hold) w->lt_hold--;
        if (reduced && w->lt_prev_rate != 0 &&
            (uint64_t)umin32(compensated, w->lt_prev_rate) * 8 >=
            (uint64_t)umax32(compensated, w->lt_prev_rate) * 7) {
            /* Verify a capacity fall by its response to a lower sending rate,
               reusing the existing one-interval loss-halving test. Here the
               saved value is the confirmed rate, rather than the bw filter. */
            w->lt_save_btl = w->lt_rate;
            w->lt_rate = umax32(compensated, w->lt_prev_rate);
            w->lt_ref_loss = umin32(loss, counted);
            w->lt_state = 1;
            w->lt_from = 2;
            w->lt_prev_rate = 0;
            w->lt_skip = 1;
        } else {
            w->lt_prev_rate = reduced ? compensated : 0;
            if (--w->lt_left == 0) {
                if (w->lt_res >= 20 && (!w->lt_res_checked || w->lt_res_low >= 2)) {
                    /* Below the old delivered rate, rather than its loss-
                       compensated rate. Reuse the periodic probe schedule:
                       check each new estimate once, and repeat only with
                       persistent evidence of lower loss. */
                    w->lt_save_btl = w->lt_rate;
                    w->lt_rate = umax32(1, sat32((uint64_t)w->lt_rate * (1000 - w->lt_res) * 7 / 8000));
                    w->lt_state = 1;
                    w->lt_from = 3;
                } else {
                    w->lt_state = 3; w->lt_k = 1; w->lt_from = 2;
                }
                w->lt_tail = 0; w->lt_skip = 1;
                w->lt_prev_rate = 0;
            }
        }
    } else if (w->lt_hold > 0) {
        w->lt_hold--;
    } else if (!w->lt_bad && counted > 100) {
        /* over 10% lost, rates within 1/4: a test costs one interval at the
           delivery rate, and the test itself tells a policer from random
           loss - over 20% and within 1/8 missed a 50 Mbps uplink whose rate
           jitters, and the sender stayed at 1.7x it with a fifth of the
           packets lost for over a minute (real network, DESIGN 13.26) */
        if (w->lt_prev_rate != 0 && rate + w->lt_prev_rate / 4 >= w->lt_prev_rate && rate <= w->lt_prev_rate + w->lt_prev_rate / 4) {
            w->lt_state = 1;
            w->lt_from = 1;
            w->lt_skip = 1;
            w->lt_rate = (uint32_t)(((uint64_t)rate + w->lt_prev_rate) / 2);
            w->lt_ref_loss = (counted + w->lt_prev_loss) / 2;
            w->lt_save_btl = w->btl_bw;
        } else {
            w->lt_prev_rate = rate;
            w->lt_prev_loss = counted;
        }
    } else {
        w->lt_prev_rate = 0;
    }
#ifdef ANL_POLICER_TRACE
    ANL_POLICER_TRACE(w, dur, rate, loss, counted, 1);
#endif
    w->lt_rd = w->lt_lost = 0;
    w->lt_rounds = 0;
    w->lt_bad = 0;
    w->lt_ts = w->current | 1;
    w->lt_sent0 = w->sent_wire;
    w->lt_infl0 = bbr_inflight_bytes(w);
#ifdef ANL_POLICER_BEGIN_TRACE
    ANL_POLICER_BEGIN_TRACE(w);
#endif
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
    return w->cs_probe || tdiff(w->current, w->probe_ts) >= 0 || tdiff(w->round_count, w->probe_round) >= (int32_t)pkts;
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
        if (w->min_rtt == 0 || (uint32_t)rtt < w->min_rtt) w->min_rtt_probed = 0;   /* a new value: no PROBE_RTT has seen it yet */
        w->min_rtt = umax32((uint32_t)rtt, 1);
        w->min_rtt_ts = w->current;
    }
    /* an app-limited sender keeps no queue: its samples are the propagation
       time already, and halving cwnd would only make frames wait */
    if (expired && w->bbr_state != ANL_BBR_PROBE_RTT && w->app_limited == 0) {
        w->bbr_state = ANL_BBR_PROBE_RTT;
        w->pacing_gain = BBR_UNIT;
        w->cwnd_gain = BBR_CWND_GAIN;
        w->probe_rtt_done_ts = 0;
    }
}

/* a new round trip begins: bandwidth filter slot, loss bounds, STARTUP exit */
static void bbr_round_end(anl_t *w, int app_limited)
{
    uint64_t rd = w->delivered - w->round_delivered0;
    uint64_t lost = w->lost_bytes > w->round_lost0 ? w->lost_bytes - w->round_lost0 : 0;   /* undone losses (handle_ack) */
    uint32_t i;
    uint32_t rdur = (uint32_t)tdiff(w->current, w->round_ts);   /* the round's duration and delivery rate */
    uint32_t rrate = rdur > 0 ? sat32(rd * 1000 / rdur) : 0;
    uint32_t rsent = w->sent_wire - w->round_sent0;             /* wire bytes sent in the round (wraps) */
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
       still holds the rate). The rounds counted must also agree on the RTT
       (within a quarter): a longer path's RTT stays put while we cut, a
       queue's moves with the cuts - a 100 ms buffer at a bottleneck that
       dropped 8 -> 2 Mbps showed 86 / 114 / 126 ms over the three rounds
       and passed for a longer path once losses were counted a round
       earlier (bwstep, RACK-marked losses): cwnd 32 -> 155, 72% lost. And
       each counted round must deliver less than the last one counted. */
    {
        uint32_t rate = rrate;
        int cong = rd + lost > 0 && lost * 100 > BBR_LOSS_THRESH * (rd + lost) && bbr_queue_signal(w);
        /* an app-limited sender builds no queue at all: counts too */
        if (cong && (app_limited || (w->last_round_rate != 0 && (uint64_t)rate * 100 < (uint64_t)w->last_round_rate * 85))) {
            /* "less than the one before" is the last round counted, not the
               last round: between them a bursty sender's rate goes up and
               down (video), and a slower bottleneck's would pass on the way
               down (5000 -> 1000 kbps: 75, 62, 70 KB/s counted 3) */
            uint32_t r = w->prev_round_min_rtt;
            int same_path = r + r / 4 >= w->qfall_rtt && w->qfall_rtt + w->qfall_rtt / 4 >= r;
            int falling = app_limited || (uint64_t)rate * 100 < (uint64_t)w->qfall_rate * 85;
            if (w->qfall == 0 || (same_path && falling)) w->qfall++;
            else w->qfall = 1;
            w->qfall_rtt = r;
            w->qfall_rate = rate;
        }
        else if (!bbr_queue_signal(w)) w->qfall = 0;
        w->last_round_rate = rate;
        w->round_ts = w->current;
        w->round_sent0 = w->sent_wire;
        if (w->qfall >= BBR_PATH_ROUNDS) {
            w->min_rtt = w->prev_round_min_rtt;
            w->min_rtt_ts = w->current;
            w->bw_lo = 0;
            w->inflight_hi = 0;
            w->qfall = 0;
        }
        /* The same without loss: the round RTT sits above 1.25x min_rtt while
           we pace at or below the estimate (DOWN, CRUISE) and does not move
           from one round to the next. Either a standing queue or the path -
           passively the two look alike (taking the RTT as the path's ratcheted
           a standing queue up: bwstep audio p95 115 -> 219 ms), so ask the
           network: PROBE_RTT now instead of at the 10 s expiry, and take the
           drained RTT as min_rtt (bbr_update_state). A queue drains and the
           old min_rtt comes back; the path does not. Until then the smaller
           BDP ended every probe after one round with "the pipe is full" and
           DOWN never reached CRUISE: min_rtt 104 ms on a 185 ms path held
           24 Mbps of a 50 Mbps uplink for 10 s (s_hz, DESIGN 13.29). Once
           per min_rtt value (min_rtt_probed): a sender whose bursts keep a
           standing queue at the bottleneck would otherwise drain it every
           few seconds, and each drain holds the control stream behind the
           minimum cwnd (priority test: p99 193 -> 234 ms at once per 3 s). */
        if (!cong && bbr_queue_signal(w) && w->bbr_state == ANL_BBR_PROBE_BW && w->probe_phase <= BBR_CRUISE) {
            uint32_t r = w->prev_round_min_rtt;
            int flat = r + r / 16 >= w->qflat_rtt && w->qflat_rtt + w->qflat_rtt / 16 >= r;
            if (w->qflat == 0 || flat) w->qflat++;
            else w->qflat = 1;
            w->qflat_rtt = r;
            if (w->qflat > BBR_PATH_ROUNDS && !app_limited && !w->min_rtt_probed &&
                tdiff(w->current, w->min_rtt_ts) >= 1000) {
                w->qflat = 0;
                w->qflat_probe = 1;
                w->bbr_state = ANL_BBR_PROBE_RTT;
                w->pacing_gain = BBR_UNIT;
                w->cwnd_gain = BBR_CWND_GAIN;
                w->probe_rtt_done_ts = 0;
            }
        } else w->qflat = 0;
    }
    if (rd + lost > 0 && ((lost * 100 > BBR_LOSS_THRESH * (rd + lost) && bbr_queue_signal(w)) ||
                          (w->bbr_state == ANL_BBR_PROBE_BW && lost * 100 > BBR_LOSS_BLIND * (rd + lost)))) {
        uint64_t cur = (uint64_t)w->cwnd * w->avg_seg;
        uint64_t hi = cur * BBR_BETA / BBR_UNIT;
        /* the round's delivery rate is what the path has now (not below 0.7x
           per round: one lossy round must not wipe the model out) */
        uint32_t lo = umax32(w->round_bw, (uint32_t)((uint64_t)bbr_bw(w) * BBR_BETA / BBR_UNIT));
        /* An app-limited round delivered what the application sent, not
           what the path carries: its delivery rate is the application's own
           rate. Cutting the model to it leaves nothing for retransmissions,
           parities and key frames - they queue at the sender, where frames
           expire whole. On a 1.2 Mbps media stream over a path whose RTT
           moves between 60 and 110 ms (a queue signal against min_rtt most
           of the time) with 1-4% random loss, each lossy round cut bw_lo to
           the P-frame rate and inflight_hi to 0.7x a window that was already
           2 BDP of that; window-limited, the rounds turned network-limited,
           the filter followed cwnd / srtt and the model fell to 105 kB/s for
           a 150 kB/s stream (real network s_rb -> s_ali_ecu, 3 of 8 rounds:
           150-307 frames dropped, video on time 100 -> 94-96%). The round's
           send rate - retransmissions and parities included - is what the
           sender needed, and the path carried it: bw_lo does not go below
           it. Not when the smoothed loss (this round included) exceeds 1/8:
           an app-limited sender offering more than a slower bottleneck loses
           the excess every round (bwstep --abr 8 -> 2 Mbps: 70% at once),
           the path's random loss averages a few percent even though a single
           round of 11 segments shows 9% for one segment. inflight_hi is not
           bounded by an app-limited round at all (BBRv2: an app-limited
           sample does not probe the volume the path takes): the window is
           what keeps the sender app-limited. */
        if (app_limited && rdur > 0) {
            uint32_t frac = (uint32_t)(lost * 256 / (rd + lost));
            uint32_t smoothed = (uint32_t)((int32_t)w->loss_rate + ((int32_t)frac - (int32_t)w->loss_rate) / 4);
            if (smoothed < BBR_APP_LOSS_MAX)
                lo = umax32(lo, sat32((uint64_t)rsent * 1000 / rdur));
        }
        w->bw_lo = lo;                                  /* before the BDP below: it is of the cut model */
        if (!app_limited) w->inflight_hi = hi > bbr_bdp(w) ? hi : bbr_bdp(w);
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
        lost > 8u * w->avg_seg && lost * 100 > 40 * (rd + lost)) {
        w->full_bw_reached = 1;
        /* ... and the round's delivery rate, well below the estimate, is
           where the model restarts (as bbr_policer does after STARTUP):
           RACK's marks put the bucket's whole overshoot into this round,
           the rounds after it saw little and kept the peak for a filter
           window (30 Mbps policer, 280 ms: 21000 -> 30000 retransmissions) */
        if (rrate != 0 && (uint64_t)rrate * 2 < w->btl_bw) {
            for (i = 0; i < BBR_BW_ROUNDS; i++) w->bw_round[i] = umin32(w->bw_round[i], rrate);
            w->btl_bw = rrate;
            w->bw_lo = 0;
        }
    }
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
        /* growing by an eighth per round keeps the probe going: the pace is
           1.25x, so a quarter - the most a round can show - failed on any
           noise and every probe ended after two rounds. After min_rtt had
           been taken from a 104 ms dip on a 185 ms path, the queue signal
           made a loss round cut the model to a quarter, and at one probe
           per 2-3 s it took 25 s to climb back (s_hz uplink, 4 times,
           DESIGN 13.29) */
        if (w->btl_bw >= w->up_bw + w->up_bw / 8) { w->up_bw = w->btl_bw; w->up_stall = 0; }
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
            w->post_startup = 8;
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
           (bbr_round_end) or two rounds without growth by an eighth */
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
            /* after a shortage the network no longer shows (cs_probe): the
               full pipe is the stale estimate's, keep going while it grows */
            if (tdiff(w->current, w->phase_ts) >= (int32_t)rtt &&
                ((bbr_inflight_bytes(w) >= bbr_bdp(w) * BBR_UP_GAIN / BBR_UNIT && !(w->cs_probe && w->up_stall == 0)) ||
                 w->up_stall >= 2))
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
            /* a probe the flat queue signal asked for: the RTT of the drained
               pipe is the path's, above the old min_rtt or not (bbr_round_end) */
            if (w->qflat_probe) {
                uint32_t m = w->round_min_rtt ? w->round_min_rtt : w->prev_round_min_rtt;
                if (m != 0) w->min_rtt = m;
                w->qflat_probe = 0;
            }
            w->min_rtt_probed = 1;
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
        w->first_sent_par = w->sent_par;
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
    vq_add(w, wire);
    seg->rs_sent = w->sent_wire;
    seg->rs_sent_first = w->first_sent_wire;
    seg->rs_par = w->sent_par;
    seg->rs_par_first = w->first_sent_par;
    seg->rs_delivered = w->delivered;
    seg->rs_fec = w->delivered_fec;
    seg->rs_ts = w->delivered_ts;
    seg->rs_first = w->first_sent_ts;
    /* held down by cfg.start_rate: the sample shows the ceiling, not the
       path - like an app-limited one it must not end STARTUP or become the
       model's full bandwidth (the model then paced at the ceiling for good) */
    seg->rs_app = w->app_limited != 0 || (w->start_cap != 0 && w->pace_rate >= w->start_cap);
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
    w->delivered_pay += s->len;
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
        rs->par = s->rs_par - s->rs_par_first;
        w->first_sent_ts = s->ts_sent;
        w->first_sent_wire = s->rs_sent;
        w->first_sent_par = s->rs_par;
    }
}

static uint32_t bbr_window_ms(const anl_t *w)
{
    return umax32((uint32_t)w->interval, BBR_DW_MIN_MS);
}

/* Delivered bytes sampled from ACKs and updates (a ring of BBR_DW_SLOTS),
 * for the delivery rate over a window of
 * at least span ms: bbr_window_bw. A rate sample spans about one RTT; when
 * that is below the clock's resolution (a 0.5 ms path, a 1 ms clock) the
 * sample's interval is 1 ms for anything up to 2 ms - up to twice the rate,
 * and the pace set from it doubled the next sample too: through a policer's
 * refilled token bucket the estimate ran from 3.5 to 128 MB/s in 50 ms
 * (real network, DESIGN 13.28). Over 10 ms the truncation is 10% at most.
 * Returns 0 without enough history. */
static void bbr_dw_checkpoint(anl_t *w)
{
    /* One entry per ms retained only 15 ms: with the default 20 ms update
       interval the requested window never existed. Space checkpoints so
       even a full ring always retains at least one complete window. */
    uint32_t step = (bbr_window_ms(w) + BBR_DW_SLOTS - 2) / (BBR_DW_SLOTS - 1);
    if (w->dw_n != 0 && tdiff(w->current, w->dw_ts[w->dw_idx]) < (int32_t)step) return;
    w->dw_idx = w->dw_n == 0 ? 0 : (w->dw_idx + 1) % BBR_DW_SLOTS;
    w->dw_ts[w->dw_idx] = w->current;
    w->dw_bytes[w->dw_idx] = w->delivered + w->delivered_fec;
    if (w->dw_n < BBR_DW_SLOTS) w->dw_n++;
}

static uint32_t bbr_window_bw(const anl_t *w, uint32_t span)
{
    uint32_t i;
    for (i = 0; i < w->dw_n; i++) {                     /* newest to oldest */
        uint32_t k = (w->dw_idx + BBR_DW_SLOTS - i) % BBR_DW_SLOTS;
        int32_t el = tdiff(w->current, w->dw_ts[k]);
        if (el >= (int32_t)span) {
            uint64_t d = w->delivered + w->delivered_fec - w->dw_bytes[k];
            return sat32(d * 1000 / (uint32_t)el);
        }
    }
    return 0;
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
        /* cfg.start_rate: the ceiling follows what was delivered, 9/8 above
           the fastest delivery so far - a burst through a slower bottleneck
           comes back at the bottleneck's rate and holds it there */
        if (w->start_cap != 0 && bw * 9 / 8 > w->start_cap)
            w->start_cap = bw * 9 / 8 > 0xffffffffu ? 0xffffffffu : (uint32_t)(bw * 9 / 8);
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
            /* data against data: the parities are in the send rate in full
               but in the delivery rate only as their fec_share credit - at a
               high ratio the difference alone passed for loss, and on a
               shallow queue (overflow shows no queue) the estimate rose
               above the link, 323..362 KB/s on 250 (real network) */
            uint64_t dd = w->delivered - rs->prior_delivered;
            uint64_t sr = (uint64_t)(rs->sent - umin32(rs->par, rs->sent)) * 1000 / (uint32_t)send_el;
            uint64_t dr = dd * 1000 / interval;
            if (dr > 0 && sr > dr) {
                uint64_t credit = bw * sr / dr;
                if (credit > bw * 3 / 2) credit = bw * 3 / 2;
                bw = credit;
            }
        }
        /* an RTT below the smoothing window: the sample's interval is a
           few clock ticks and its truncation up to 2x - at most 9/8 of the
           delivery rate over max(update interval, 10 ms). Network-
           limited samples only: an app-limited burst is meant to stand out
           of its window. */
        if (!rs->app_limited && w->min_rtt != 0 && w->min_rtt < bbr_window_ms(w)) {
            uint64_t win = bbr_window_bw(w, bbr_window_ms(w));
            if (win != 0 && bw > win * 9 / 8) bw = win * 9 / 8;
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
       RACK's job, the RTO is the fallback for tails. Two update intervals
       at least: the peer's ACK waits up to one for its flush, and a lost
       ACK's repeat comes one later (write_ack_segs) - with one, the RTO
       raced both (20 ms RTT: audio retransmitted once a second without loss,
       a third of the RTOs at 5..15% loss reached a peer that had the data) */
    rto = w->rx_srtt + (int32_t)umax32(umax32(2u * (uint32_t)w->interval, 4u * (uint32_t)w->rx_rttval), (uint32_t)w->rx_srtt / 4);
    w->rx_rto = (int32_t)ubound32(RTO_MIN, (uint32_t)rto, RTO_MAX);
}

/* una + SACK ranges (DESIGN 5.3), then RACK loss detection (DESIGN 6.3).
 * rng holds n (gap, len) pairs. Returns the number of segments acknowledged;
 * *lost counts the segments newly declared lost. */
static int handle_ack(anl_t *w, anl_stream *st, uint8_t b1, uint32_t una24, uint16_t wnd,
                      uint32_t ts_echo, const uint32_t *rng, uint32_t n, int *lost, bbr_sample *rs)
{
    uint32_t una, i, hi;
    anl_node *pos;
    int acked = 0, spurious = 0;
    st->rmt_wnd = wnd;
    if (w->updated) bbr_dw_checkpoint(w);               /* delivered before this tick's ACKs */
    if (b1 & ACK_F_WASK) { st->probe_tell = 1; ack_schedule(st); }
    una = extend24(una24, st->snd_una);
    if (tdiff(una, st->snd_nxt) > 0) una = st->snd_una;         /* garbage: ignore */

    /* una, then the ranges (ascending): one walk over snd_buf */
    hi = una;
    pos = st->snd_buf.next;
    for (i = 0; i <= n; i++) {
        uint32_t start, end;
        if (i == 0) { start = st->snd_una - (SN_MASK >> 1); end = una; }   /* everything below una */
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
                if (orig || s->xmit <= 1) {
                    /* never lost (reordering, a late ACK under heavy jitter;
                       or RACK marked it and it arrived before the flush
                       resent it): take it out of the loss count */
                    if (s->lost_cnt) {
                        uint32_t wire = seg_wire(s);
                        w->lost_bytes -= (uint64_t)wire < w->lost_bytes ? wire : w->lost_bytes;
                        /* out of the FEC loss estimate too when the peer
                           reports: its report counts the repair (a peer
                           that does not report leaves the mark as the
                           only evidence of a repaired loss) */
                        if (st->fec && st->peer_rp.valid && w->fl_lost) w->fl_lost--;
                    }
                    /* acknowledged after a higher sn was (the last ACK's high
                       mark): lost and rebuilt from parity - or reordered. The
                       estimate's only view of repaired losses from a peer
                       that does not report (the rebuilt packet's ACK beats
                       RACK's mark) */
                    else if (s->xmit == 1 && st->fec && !st->peer_rp.valid && st->rack_valid &&
                             tdiff(s->sn, st->rack_hi) < 0)
                        fec_loss_add(w, 0, 1, 0);
                }
                /* an RTO retransmission's loss counts only now, when it is
                   known not to be a late ACK (RACK's is counted when it is
                   marked, rack_detect) */
                else if (s->rack_rtx) {
                    if (!s->lost_cnt) {
                        w->lost_bytes += seg_wire(s);
                        if (st->fec) fec_loss_add(w, 0, 1, 1);  /* an RTO loss: not marked */
                    }
                    /* the retransmission, not the original, was acknowledged:
                       the loss is confirmed (a RACK mark alone can be
                       reordering, undone above) - the gate's hard evidence */
                    else if (st->fec) w->fec_loss_ts = w->current | 1;
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
                snd_unlink(st, s);
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
        else if (tdiff(una, st->fwd_peer_una) > 0) {
            /* Progress clears backoff, including its scheduled deadline.
               Keeping that old deadline after zeroing fwd_rto made the next
               liveness check treat a future retry as the last send time. */
            uint32_t retry = w->current + (uint32_t)w->rx_rto;
            st->fwd_xmit = 0; st->fwd_rto = 0;
            if (tdiff(st->fwd_ts, retry) > 0) st->fwd_ts = retry;
        }
        else if (tdiff(w->current, st->fwd_ts - st->fwd_rto + (uint32_t)w->rx_rto) >= 0 &&
                 tdiff(st->fwd_ts, w->current) > 0) {
            /* The peer answers but stays behind our new_una: the FWD was lost
               (or the peer never heard from us for longer than a window of
               frames and now drops everything as beyond its window - it ACKs
               that, handle_data). The backoff is for dead-link detection while
               nothing comes back; a live peer gets the FWD again one RTO after
               the last one, at once, without the backoff (a 25 s absent
               receiver waited 6..20 s more before the first frame). */
            st->fwd_ts = w->current;
            st->fwd_rto = 0;
        }
    }
    st->fwd_peer_una = una;
    return acked;
}

/*--------------------------------------------------------------------
 * FWD / CTRL
 *-------------------------------------------------------------------*/
static void handle_fwd(anl_t *w, anl_stream *st, uint32_t una24)
{
    uint32_t new_una;
    if (st->mode != ANL_SEMI) { stream_reset(w, st); return; }
    new_una = extend24(una24, st->rcv_nxt);
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
 * a stream that is already gone gets RST instead of a new stream. A sid of our
 * own parity that we do not have is one of ours that is gone (or garbage). */
static anl_stream *stream_for_open(anl_t *w, int sid, const open_info *oi, int *urgent)
{
    anl_stream *st = sget(w, sid);
    if (st == NULL) {
        int used = peer_sid_state(w, sid);
        if (used < 0 && ((uint32_t)sid & 1) == (sid_first(1 - w->role) & 1)) return NULL;  /* too far ahead: ignored */
        if (w->state < 0 || used != 0) { queue_rst(w, sid); *urgent = 1; return NULL; }
        peer_sid_mark(w, sid);
        if ((st = accept_stream(w, sid, oi)) == NULL) { queue_rst(w, sid); *urgent = 1; return NULL; }
        return st;
    }
    if (st->state == ANL_STREAM_CLOSED) { queue_rst(w, sid); *urgent = 1; return NULL; }
    peer_heard(w, st);
    if (oi->mode != st->mode || (oi->mode == ANL_RELIABLE && oi->stream != st->stream)) {
        stream_reset(w, st);
        return NULL;
    }
    return st;
}

static void handle_close(anl_t *w, int sid, const char *body, uint32_t blen, int *urgent)
{
    const char *p = body;
    uint32_t final24, una24;
    uint8_t flags;
    int rst, has_open;
    open_info oi;
    anl_stream *st;
    if (blen < CLOSE_BODY) return;
    final24 = dec24(&p);
    flags = dec8(&p);
    una24 = dec24(&p);
    rst = (flags & CLOSE_F_RST) != 0;
    has_open = (flags & CLOSE_F_OPEN) != 0;
    if (has_open) {
        if (blen < CLOSE_BODY + OPEN_BODY) return;
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
        if (!rst) peer_heard(w, st);
        else own_heard_mark(w, sid);        /* a refusal: the peer has seen it all the same */
    }
    if (st == NULL) return;
    if (!rst) {
        /* the peer's una: acknowledges our data like an ACK */
        uint32_t una = extend24(una24, st->snd_una);
        if (tdiff(una, st->snd_una) > 0 && tdiff(una, st->snd_nxt) <= 0) {
            parse_una(st, una);
            shrink_buf(st);
            if (st->fwd_pending && tdiff(una, st->fwd_una) >= 0) st->fwd_pending = 0;
        }
    }
    if (rst) {
        if (!st->peer_closed) { st->peer_closed = 1; st->peer_final_sn = extend24(final24, st->rcv_nxt); }
        st->peer_released = 1;
        stream_local_close(w, st);
    } else {
        if ((flags & CLOSE_F_ACKFIN) && st->state != ANL_STREAM_OPEN) st->fin_acked = 1;
        if (!(flags & CLOSE_F_NOFIN)) {
            int half = (flags & CLOSE_F_HALF) && st->mode == ANL_RELIABLE;
            if (!st->peer_closed) {
                st->peer_closed = 1;
                st->peer_final_sn = extend24(final24, st->rcv_nxt);
                st->peer_half = half;
            } else if (!half) {
                st->peer_half = 0;              /* the peer closed the handle after a shutdown */
            }
            st->close_answer = 1;               /* answer every FIN: our answer may have been lost */
            /* a full close ends our direction too (the peer no longer reads);
               after a half-close we may go on sending (DESIGN 6.1) */
            if (!st->peer_half) stream_local_close(w, st);
        }
    }
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
    /* A delivery gap can release buffered ACKs together on resumption.
       Ordinary, continuously arriving ACKs must still measure queue delay. */
    if (w->rx_srtt > 0 && tdiff(w->current, w->last_rx) > w->rx_rto) { w->rtt_resume = 1; w->lt_gap_ts = w->current | 1; }
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
        if (end - p < 2) return ANL_EFORMAT;
        b0 = dec8(&p);
        type = b0 >> 6;
        sid = ((b0 & SID_HI_MASK) << 8) | dec8(&p);
        if (b0 & SID_X) {
            uint32_t hi;
            if (end - p < 2) return ANL_EFORMAT;
            hi = dec16(&p);
            if (hi == 0) return ANL_EFORMAT;    /* one encoding per sid */
            sid |= (int)(hi << SID_LO_BITS);
        }

        if (type == SEG_DATA) {
            uint8_t b1, flags;
            uint32_t frg, len;
            uint32_t sn24;
            uint16_t frame16 = 0;
            open_info oi;
            if (end - p < 4) return ANL_EFORMAT;
            b1 = dec8(&p);
            flags = (uint8_t)(b1 & (F_HAS_FRAME | F_KEY));
            frg = b1 & F_FRG_MASK;
            if (frg == 31) {
                uint32_t ext;
                if (dec_varint(&p, end, &ext) < 0) return ANL_EFORMAT;
                frg = 31 + ext;
                /* a frame has at most a window of fragments (ANL_ETOOBIG at
                   the sender); a larger index is garbage - and its canonical
                   encoding for FEC (a 3..5 byte extension) overran the
                   receive cache slot by up to 3 bytes (fuzz, ASan) */
                if (frg >= ANL_MAX_WND) return ANL_EFORMAT;
            }
            if (end - p < 3) return ANL_EFORMAT;
            sn24 = dec24(&p);
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
                handle_data(w, st, extend24(sn24, st->rcv_nxt), frg, flags, frame16, p, len, ts, 0);
                stream_try_release(w, st);
            }
            p += len;
        } else if (type == SEG_ACK) {
            uint8_t b1;
            uint16_t wnd;
            uint32_t una24, ts_echo, n, i, span = 0;
            if (end - p < ACK_FIX) return ANL_EFORMAT;
            b1 = dec8(&p);
            una24 = dec24(&p);
            wnd = dec16(&p);
            ts_echo = dec32(&p);
            if (dec_varint(&p, end, &n) < 0) return ANL_EFORMAT;
            if (2 * n > snbuf_cap) return ANL_EFORMAT;
            for (i = 0; i < n; i++) {
                uint32_t gap, len;
                if (dec_varint(&p, end, &gap) < 0 || dec_varint(&p, end, &len) < 0) return ANL_EFORMAT;
                span += gap + len;
                if ((gap == 0 && i > 0) || len == 0 || span > ANL_MAX_WND) return ANL_EFORMAT;
                snbuf[2 * i] = gap;
                snbuf[2 * i + 1] = len;
            }
            if (b1 & ACK_F_WASK) urgent = 1;
            st = stream_for_input(w, sid, &urgent);
            if (st) {
                int fresh_acked = handle_ack(w, st, b1, una24, wnd, ts_echo, snbuf, n, &lost, &rs);
                acked += fresh_acked;
                /* After an input gap, an old buffered ACK with no new
                   confirmation cannot restart RTT from a retired flight.
                   Keep ordinary and in-window media echoes: retirement
                   alone does not make queue delay stale. A new confirmation
                   still learns a genuine RTT increase without a fixed cap. */
                if ((fresh_acked > 0 || !w->rtt_resume || tdiff(w->current, ts_echo) <= w->rx_rto) && (b1 & ACK_F_FRESH) && (!have_echo || tdiff(ts_echo, max_echo) > 0)) { max_echo = ts_echo; have_echo = 1; }
                stream_try_release(w, st);
            }
        } else if (type == SEG_FWD) {
            uint32_t una24;
            if (end - p < 3) return ANL_EFORMAT;
            una24 = dec24(&p);
            urgent = 1;
            st = stream_for_input(w, sid, &urgent);
            if (st) handle_fwd(w, st, una24);
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
            } else if (sub == CTRL_RCV_SKIP && blen >= SKIP_BODY) {
                const char *q = p;
                uint32_t retired = dec32(&q);
                st = stream_for_input(w, sid, &urgent);
                if (st && st->mode == ANL_SEMI && tdiff(retired, st->snd_una) > 0 &&
                    tdiff(retired, st->snd_nxt) <= 0) {
                    int freed = parse_una(st, retired);
                    shrink_buf(st);
                    w->inflight_segs -= umin32(w->inflight_segs, (uint32_t)freed);
                    acked += freed; /* opens the window, without a delivery sample */
                }
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
                if (st) handle_report(w, st, p, ts);
            }
            p += blen;                      /* unknown subtypes are skipped */
        }
    }

    if (have_echo && w->updated) {
        int32_t rtt = tdiff(w->current, max_echo);
        if (rtt >= 0 && rtt <= w->rx_rto) w->rtt_resume = 0;
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
    p = enc24(p, st->fec_out_base & SN_MASK);
    p = enc8(p, (uint8_t)st->fec_out_k);
    p = enc8(p, (uint8_t)st->fec_out_m);
    p = enc8(p, (uint8_t)st->fec_out_i);
    memcpy(p, b->p, b->len);
    write_ctrl_seg(w, st->sid, CTRL_PARITY, body, PARITY_HDR + b->len);
    dg_seal(w);
    w->sent_wire += PARITY_HDR + b->len + SEG_WIRE_OVH;
    vq_add(w, PARITY_HDR + b->len + SEG_WIRE_OVH);
    w->sent_par += PARITY_HDR + b->len + SEG_WIRE_OVH;
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

static int fec_active(const anl_t *w, const anl_stream *st)
{
    (void)w;
    return st->fec && (!st->fec_rtt_auto || st->fec_gate);
}

/* Time from enqueue until a lost packet of a frame of `bytes` is back by one
 * retransmission (DESIGN 8.6): the frame leaves at the current pace, the loss
 * shows a round trip after it plus RACK's reordering window and the peer's
 * ACK delay (an update interval), the retransmission takes half a round trip.
 * RTT-auto large frames also reserve a second retry when measured random
 * loss makes failure of the first retry exceed the parity failure target. */
static uint32_t fec_repair_ms(const anl_t *w, const anl_stream *st, uint32_t bytes)
{
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    uint32_t pace = w->pace_rate ? w->pace_rate : compute_pace_rate(w);
    uint32_t ser = pace ? (uint32_t)umin32((uint32_t)((uint64_t)bytes * 1000 / pace), 10000) : 0;
    uint32_t detect = reo_wnd(w, st) + (uint32_t)w->interval;
    uint32_t need = ser + srtt * 3 / 2 + detect;
    /* A large frame needs every fragment. Even when one retry fits, losing
     * that retry can leave the frame (and a key frame's GOP) unrecoverable.
     * n*p*p bounds the chance that some fragment loses both its original
     * and first retry. If it exceeds the parity floor's failure target,
     * reserve one more detection/round trip instead of assuming that retry
     * surely works. This covers the first repeated-loss blind spot, not an
     * arbitrary tail guarantee. Small audio keeps its bounded startup and
     * one-repair policy; explicit FEC modes keep their existing estimate. */
    if (st->fec_rtt_auto && bytes > FEC_SMALL_BLOCK / 8 &&
        w->fec_loss_valid && w->fec_loss) {
        uint32_t n = bytes / st->mss + (bytes % st->mss != 0);
        uint32_t target = st->drop_until_key ? FEC_SMALL_FAIL : FEC_BLOCK_FAIL;
        uint64_t risk = (uint64_t)n * w->fec_loss * w->fec_loss / 65536;
        if (risk * 1000 > (uint64_t)target * 65536)
            need += srtt + detect;
    }
    return need;
}

/* RTT auto (ANL_FEC_RTT_AUTO, DESIGN 8.6): parity for the stream while the
 * estimated recovery of a typical frame cannot make fec_deadline and the path
 * loses packets. Large frames: opens at repair > deadline and loss >= 1%,
 * closes at repair < 3/4 deadline or loss < 0.25%. Small frames (audio):
 * opens at repair > deadline during bounded startup or recent hard loss. Both
 * kinds close after 30 s without hard loss evidence. Changes are held
 * for 2 s, except the first opening on loss and expiry of the allowance. */
/* A long-RTT audio loss expires before its first hard evidence comes
 * back. Protect that first flight once, for at most two RTTs and 1 s.
 * Spending the allowance is permanent, including across clock wrap. */
static int fec_audio_startup(anl_t *w, anl_stream *st)
{
    int32_t age;
    if (st->fec_start_state != 1) return 0;
    age = tdiff(w->current, st->fec_start_ts);
    if (age >= FEC_AUDIO_START_MAX_MS ||
        (w->rx_srtt > 0 && age >= (int64_t)w->rx_srtt * 2)) {
        st->fec_start_state = 2;
        return 0;
    }
    return w->rx_srtt > 0 && st->fec_frame_avg != 0 &&
           st->fec_frame_avg * 8 <= FEC_SMALL_BLOCK;
}

static void fec_gate_update(anl_t *w, anl_stream *st)
{
    int on = 0;
    int recent = w->fec_loss_ts != 0 && tdiff(w->current, w->fec_loss_ts) < FEC_LOSS_RECENT_MS;
    int startup = fec_audio_startup(w, st);
    uint32_t d = st->fec_deadline;
    if (w->rx_srtt > 0 && d != 0) {
        uint32_t need = fec_repair_ms(w, st, st->fec_frame_avg);
        int small = st->fec_frame_avg != 0 && st->fec_frame_avg * 8 <= FEC_SMALL_BLOCK;
        /* Beyond bounded audio startup, only while the path has lost a
           packet, with hard evidence, in the last FEC_LOSS_RECENT_MS.
           Otherwise parity was 7..28% of the
           media on lossless real paths (audio duplicated for 5..10 minutes
           on one early rebuild - reordering, as it turned out). Small
           frames (audio) then on the repair time alone (the estimate dips
           between windows, and every dip cost seconds of unprotected audio
           on a lossy long path); large frames need 1% as well. */
        if (st->fec_gate)
            on = (recent || startup) && !(need * 4 < d * 3 ||
                             (!small && w->fec_loss_valid >= 2 && w->fec_loss < FEC_GATE_LOSS_OFF));
        else if (small)
            on = need > d && (recent || startup);
        else
            on = need > d && recent && w->fec_loss_valid && w->fec_loss >= FEC_GATE_LOSS_ON;
    }
    /* A startup allowance never overrides known capacity shortage or
       its reopening hold; failed delivery probes keep all adaptive FEC off. */
    if (w->capacity_short || (w->cs_ts != 0 && tdiff(w->current, w->cs_ts) < FEC_GATE_HOLD_MS)) on = 0;
    /* Opening on the first loss is not held back; subsequent changes
       retain the hold to avoid toggling around the thresholds. */
    if (on != st->fec_gate && (st->fec_gate_ts == 0 || (!on && (w->capacity_short || (!recent && !startup))) ||
                               (on && !st->fec_gate_was) ||
                               tdiff(w->current, st->fec_gate_ts) >= FEC_GATE_HOLD_MS)) {
        st->fec_gate = on;
        st->fec_gate_ts = w->current | 1;
        if (on) st->fec_sent = st->fec_miss = 0;
    }
    if (on && recent) st->fec_gate_was = 1;
}

/* RTT auto with drop_until_key: a lost key frame takes its whole GOP with
 * it, so key-frame blocks are judged by themselves - by the key frame's own
 * send time - and protected while the loss is not known yet (the first key
 * frame) unless a retransmission surely makes the deadline. */
static int fec_key_gate(anl_t *w, anl_stream *st)
{
    if (!st->drop_until_key || st->fec_deadline == 0) return 0;
    if (w->rx_srtt > 0 && fec_repair_ms(w, st, st->fec_key_bytes) <= st->fec_deadline) return 0;
    /* before anything is known (the first key frame), or a recent loss and 1% */
    if (!w->fec_loss_valid && w->fec_loss_ts == 0) return 1;
    return w->fec_loss_ts != 0 && tdiff(w->current, w->fec_loss_ts) < FEC_LOSS_RECENT_MS && w->fec_loss >= FEC_GATE_LOSS_ON;
}

/* the parity budget (DESIGN 8.6): what the bandwidth estimate leaves beside
 * everything else sent (rate_update); refilled here into a bucket of
 * FEC_BUDGET_MS at that rate */
static int64_t par_bucket(const anl_t *w)
{
    return (int64_t)umax32((uint32_t)((uint64_t)w->par_rate * FEC_BUDGET_MS / 1000), 8u * w->mss);
}

static void fec_budget_refill(anl_t *w)
{
    int32_t dt = w->par_ts ? tdiff(w->current, w->par_ts) : 0;
    int64_t cap;
    w->par_ts = w->current | 1;
    if (w->par_rate == 0xffffffffu) return;
    cap = par_bucket(w);
    if (dt > 0) w->par_tokens += (int64_t)w->par_rate * umin32((uint32_t)dt, FEC_BUDGET_MS) / 1000;
    if (w->par_tokens > cap) w->par_tokens = cap;
    if (w->par_tokens < -cap) w->par_tokens = -cap;
}

/* one retransmission of a typical frame's loss makes fec_deadline
   (fec_repair_ms without the second retry it may reserve) */
static int fec_one_retry(const anl_t *w, const anl_stream *st)
{
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    uint32_t pace = w->pace_rate ? w->pace_rate : compute_pace_rate(w);
    uint32_t ser = pace ? (uint32_t)umin32((uint32_t)((uint64_t)st->fec_frame_avg * 1000 / pace), 10000) : 0;
    return st->fec_deadline != 0 && w->rx_srtt > 0 &&
           ser + srtt * 3 / 2 + reo_wnd(w, st) + (uint32_t)w->interval <= st->fec_deadline;
}

/* Close the open block (DESIGN 8.2): k data packets get m Reed-Solomon
 * parities (up to FEC_M_MAX); any m of the k + m can be lost. m follows the
 * ratio exactly over blocks, not per block: the fraction left over is
 * carried to the next one (5 audio packets at 10% get 1 parity every other
 * block - rounded per block, 10% and 20% were the same). */
static void fec_close_block(anl_t *w, anl_stream *st)
{
    uint32_t k = st->fec_n, m, j, i, lmax = 0, share, x, reach;
    int key = st->fec_blk_key;
    anl_node *pos;
    if (k == 0 || st->fec_slot == NULL) return;
    st->fec_n = 0;
    st->fec_blk_key = 0;
    fec_pump(w, st, 1);                             /* the previous block's parities first */
    if (st->fec_rtt_auto) {
        fec_gate_update(w, st);
        if (!st->fec_gate && !(key && fec_key_gate(w, st))) return;
    }
    /* adaptive parity while capacity is short (rate_update, DESIGN 8.6):
       none, key frames included - a key frame's 16 parities are the burst
       that overflows the queue; a fixed ratio stays as configured */
    if (st->fec_auto && w->capacity_short) return;
    for (i = 0; i < k; i++) lmax = umax32(lmax, st->fec_slot[i].len);
    x = k * (uint32_t)st->fec_ratio + st->fec_carry;
    m = x / 100;
    st->fec_carry = x % 100;
    if (st->fec_auto) {
        uint32_t need = fec_repair_ms(w, st, key ? st->fec_key_bytes : st->fec_frame_avg);
        if (st->fec_rtt_auto && key && !w->fec_loss_valid) {
            m = umax32(m, umax32((k * FEC_START_RATIO + 50) / 100, 1));
        } else if (!(st->fec_deadline && need <= st->fec_deadline)) {
            /* at least what the loss needs - unless a retransmission makes
               the deadline anyway */
            /* a non-key block of a drop_until_key stream fails at the
               looser target while one retransmission still makes the
               deadline: the early RTO repairs what FEC does not */
            m = umax32(m, fec_parities_for(k, w->fec_loss,
                                          k * lmax > FEC_SMALL_BLOCK && !key &&
                                          (!st->drop_until_key || fec_one_retry(w, st)) ? FEC_BLOCK_FAIL : FEC_SMALL_FAIL));
            /* a small block (audio) as many parities as packets while the
               loss estimate settles: its bytes are few, and nothing else kept
               long-RTT audio on time (real cross-border paths: 99.9..100% at
               100%, 38..62% at fixed 20..40%). Once it has, the binomial floor
               above: at 1..3% random loss 33% instead of 100%, audio on time
               within 0.1 point (simulation, 100..300 ms RTT) */
            if (k * lmax <= FEC_SMALL_BLOCK && (w->fec_loss >= FEC_GATE_LOSS_ON ||
                st->fec_rtt_auto) && w->fec_loss_valid < FEC_LOSS_WARM) m = umax32(m, k * FEC_SMALL_RATIO / 100);
        }
        /* the parity budget (DESIGN 8.6): small blocks (audio) outside it;
           a large block gets, beyond the FEC_AUTO_MIN share, what the budget
           holds - a key frame's may borrow up to the bucket size, a non-key
           block's at most FEC_FLOOR_CAP % */
        if (k * lmax > FEC_SMALL_BLOCK) {
            uint32_t base = (k * FEC_AUTO_MIN + 50) / 100;
            fec_budget_refill(w);
            if (!key) {
                m = umin32(m, umax32((k * FEC_FLOOR_CAP + 99) / 100, base));
            }
            if (w->par_rate != 0xffffffffu && m > base) {
                /* a key frame may borrow up to the bucket's size */
                int64_t per = lmax + PARITY_HDR + SEG_WIRE_OVH;
                int64_t tok = w->par_tokens + (key ? (int64_t)par_bucket(w) : 0);
                uint32_t room = tok > 0 ? (uint32_t)umin32((uint32_t)(tok / per), FEC_M_MAX) : 0;
                /* After queueing, RTT-auto may use retries as well as
                 * parity. Do not turn
                 * half a second of saved (or borrowed) budget into one
                 * block's burst: after that burst enters the link queue,
                 * higher-priority audio cannot overtake it. Bound each
                 * block by one collection interval of the budget rate,
                 * retaining the evidence for one RTT-estimation window so
                 * gaps between key frames do not restore the burst. A
                 * larger recovered budget naturally releases this cap.
                 * The small mandatory floor remains available. */
                if (st->fec_rtt_auto && w->par_queue_ts &&
                    tdiff(w->current, w->par_queue_ts) < RATE_RTT_WIN) {
                    uint32_t burst = (uint32_t)((uint64_t)w->par_rate * FEC_BLOCK_MS / 1000 / per);
                    room = umin32(room, burst);
                }
                m = umin32(m, umax32(base, room));
            }
        }
    }
    if (m == 0) return;                             /* this block's share of the ratio was below one */
    m = umin32(m, FEC_M_MAX);
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
    fec_budget_refill(w);
    w->par_tokens -= (int64_t)m * (lmax + PARITY_HDR + SEG_WIRE_OVH);
#ifdef ANL_FEC_BLOCK_TRACE
    ANL_FEC_BLOCK_TRACE(w, st, k, m);
#endif
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
    /* parities are lost like data: credit what is expected to arrive, not
       all that was sent (with the loss the credit exceeded the link) */
    share = (uint32_t)((uint64_t)share * (65536u - umin32(w->fec_loss, 65536u)) >> 16);
    /* from a retransmission until its ACK shows it made fec_deadline: half
       a round trip, the peer's ACK delay and our flush (an update interval
       each) and the jitter */
    reach = (w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF) / 2 + 2u * (uint32_t)w->interval +
            4u * (uint32_t)w->rx_rttval;
    for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
        anl_seg *s = QENTRY(pos, anl_seg, node);
        uint32_t last = w->current + (m - 1) * FEC_GAP;
        if (tdiff(s->sn, st->fec_base + k) >= 0) break;
        if (tdiff(s->sn, st->fec_base) < 0 || s->xmit != 1) continue;
        s->fec_ts = last ? last : 1;
        s->fec_share = (uint16_t)umin32(share, 0xffff);
        /* the RTO counts from the last parity too, as far as a
           retransmission then still makes fec_deadline (reach): a block
           collects up to FEC_BLOCK_MS, and timed from the send the RTO beat
           the rebuild's ACK (100 ms RTT: 80% of the retransmissions reached
           a peer that had rebuilt them). Not beyond: where FEC fails, that
           early retransmission is what keeps the frame on time (deferred all
           the way, video at 180 ms RTT and 15% loss went from 98.9 to 97.3%
           on time), and one that only just arrives counts as late - the
           ratio ran to its ceiling where retransmissions are in time */
        if (st->fec_deadline > reach) {
            uint32_t defer = last + s->rto, latest = s->ts_enq + st->fec_deadline - reach;
            if (tdiff(defer, latest) > 0) defer = latest;
            if (tdiff(defer, s->resendts) > 0) s->resendts = defer;
        }
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
static void fec_loss_add(anl_t *w, uint32_t sent, uint32_t lost, int hard)
{
#ifdef ANL_FEC_LOSS_TRACE
    ANL_FEC_LOSS_TRACE(w, sent, lost);
#endif
    w->fl_sent += sent;
    w->fl_lost += lost;
    if (lost && hard) w->fec_loss_ts = w->current | 1;
    if (w->fl_sent >= (w->fec_loss_valid ? FEC_LOSS_PKTS : FEC_LOSS_FIRST)) {
        int32_t x = (int32_t)((uint64_t)umin32(w->fl_lost, w->fl_sent) * 65536 / w->fl_sent);
        /* the first windows take a higher measurement as it is: the first
           one closes before most of its losses are detected, and smoothed
           from that near-zero start the estimate sat below the gate's
           thresholds for seconds (real network: audio unprotected 2.5..5 s) */
        if (w->fec_loss_valid < FEC_LOSS_WARM && x > (int32_t)w->fec_loss) w->fec_loss = (uint32_t)x;
        else w->fec_loss = (uint32_t)((int32_t)w->fec_loss + (x - (int32_t)w->fec_loss) / 4);
        if (w->fec_loss_valid < FEC_LOSS_WARM) w->fec_loss_valid++;
        w->fl_sent = w->fl_lost = 0;
    }
}

/* the fewest parities for k data packets at raw loss p (1/65536) so that a
 * block fails - more than m of its k + m packets lost - with at most
 * `fail` per mille: binomial tail in 32.32 fixed point; at most k (100%) */
static uint32_t fec_parities_for(uint32_t k, uint32_t p, uint32_t fail)
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
        if (cdf >= one || (one - cdf) * 1000 <= one * fail) return m;
    }
    return m;
}

/* FEC_SENT: a first transmission; FEC_LOST: FEC did not repair it but the
 * retransmission made the deadline; FEC_LATE: it did not */
static void fec_auto_count(anl_t *w, anl_stream *st, int lost)
{
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
#ifdef ANL_FEC_COUNT_TRACE
    ANL_FEC_COUNT_TRACE(w, st, lost);
#endif
    if (st->fec && lost == FEC_SENT) fec_loss_add(w, 1, 0, 0); /* losses: RACK marks, RTO ACKs */
    if (!st->fec_auto || !fec_active(w, st) || lost == FEC_LOST) return; /* the loss estimate only */
    if (lost == FEC_SENT) {
        if (++st->fec_sent < FEC_AUTO_CLEAN) return;
        if (st->fec_miss == 0) st->fec_ratio = (int)umax32((uint32_t)st->fec_ratio * 4 / 5, FEC_AUTO_MIN);
    } else {
        st->fec_miss++;
        if (st->fec_miss < 2 || st->fec_miss * 100 <= st->fec_sent * FEC_AUTO_MISS ||
            (st->fec_adj_ts != 0 && tdiff(w->current, st->fec_adj_ts) < (int32_t)(2 * srtt + FEC_BLOCK_MS))) return;
        /* not while large frames are short of parity budget (the bucket
           below half): those losses are likely our own congestion, more
           parity would add to it - the ratio ran to 100% on a 2 Mbps path
           and its key frames overflowed the queue (simulation). Only while
           network-limited or queueing: app-limited, the budget follows an
           estimate that shows only what was sent, and the losses are not
           ours - with fewer spurious retransmissions to inflate it, 20%
           random loss left the ratio at its floor (test.c, 5 of 140 seeds) */
        if (w->capacity_short || (st->fec_frame_avg * 8 > FEC_SMALL_BLOCK && w->par_rate != 0xffffffffu &&
                                  w->par_tokens * 2 < (int64_t)par_bucket(w) &&
                                  (w->app_limited == 0 || bbr_queue_signal(w)))) {
            if (st->fec_ratio > FEC_FLOOR_CAP) st->fec_ratio = FEC_FLOOR_CAP;
            st->fec_adj_ts = w->current | 1;
            st->fec_sent = st->fec_miss = 0;
            return;
        }
        st->fec_ratio = (int)umin32((uint32_t)st->fec_ratio * 3 / 2 + 5, FEC_AUTO_MAX);
        st->fec_adj_ts = w->current | 1;
    }
    st->fec_sent = st->fec_miss = 0;
}

static void fec_add(anl_t *w, anl_stream *st, const anl_seg *seg)
{
    fec_buf *b;
    if (st->fec_rtt_auto && st->fec_start_state == 0) {
        st->fec_start_ts = w->current;
        st->fec_start_state = 1;
    }
    if (st->fec_n > 0 && seg->sn != st->fec_base + st->fec_n) fec_close_block(w, st);
    if (st->fec_n == 0) {
        st->fec_base = seg->sn;
        st->fec_first_ts = w->current;
    }
    b = &st->fec_slot[st->fec_n];
    if (fbuf_reserve(b, seg->len + CANON_HDR_MAX) < 0) { fec_close_block(w, st); return; }
    b->len = canon_build(b->p, seg->frg, seg->flags, (uint16_t)seg->frame_no, seg->data, seg->len);
    st->fec_n++;
    if (seg->fkey) st->fec_blk_key = 1;
    /* not closed at the end of a key frame: its parities right behind it
       made one larger burst - on a 2 Mbps / 280 ms path with a shallow
       queue video on time fell from 94 to 77% (simulation) */
    if (st->fec_n >= FEC_K_MAX) fec_close_block(w, st);
}

/* transmit a segment (first time or retransmission) */
static void send_seg(anl_t *w, anl_stream *st, anl_seg *seg)
{
    int first = seg->xmit == 0;
    write_data_seg(w, st, seg);
    seg->xmit++;
    seg->ts_sent = w->current;
    if (seg->tnode.next) qdel(&seg->tnode);
    qadd_tail(&seg->tnode, &st->snd_time);
    if (st->nsnd_buf == 1 || tdiff(seg->resendts, st->rto_next) < 0) st->rto_next = seg->resendts;
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
        snd_unlink(st, s);
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
        st->w->purged_unsent += s->len;
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
    /* what these drops take out of snd_queue was never sent: the sender
       could not send the media within max_age (or max_bytes) - the path is
       short of capacity for it (rate_update). A frame lost in flight is
       abandoned by the retransmission path instead, and what its GOP takes
       with it is the loss's doing, not counted here */
    uint64_t unsent0 = w->purged_unsent;
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
    w->tx_unsent += w->purged_unsent - unsent0;
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
                st->rcv_skip_una = s->sn;
                st->rcv_skip_valid = 1;
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

    /* Zero-window persistence follows the connection RTO (DESIGN 5.3). */
    if (st->rmt_wnd == 0 && (st->nsnd_que + st->nsnd_buf) > 0) {
        if (st->probe_wait == 0) {
            /* Losing a reopened-window ACK must not strand a live stream
               for seconds. Probe on the same RTT-aware clock as data loss. */
            st->probe_wait = (uint32_t)w->rx_rto;
            st->ts_probe = current + st->probe_wait;
        } else if (tdiff(current, st->ts_probe) >= 0) {
            if (st->probe_wait < (uint32_t)w->rx_rto) st->probe_wait = (uint32_t)w->rx_rto;
            st->probe_wait += st->probe_wait / 2;
            if (st->probe_wait > PROBE_LIMIT) st->probe_wait = PROBE_LIMIT;
            st->ts_probe = current + st->probe_wait;
            st->probe_ask = 1;
        }
    } else {
        st->probe_wait = 0;
        st->ts_probe = 0;
    }
    if (st->ack_rep_ts != 0 && tdiff(current, st->ack_rep_ts) >= 0) st->ack_pending = 1;
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
    if (st->state == ANL_STREAM_CLOSING && !st->fin_acked && tdiff(current, st->close_ts) >= 0) {
        write_close_seg(w, st->sid, st->final_sn, 0, st);
        st->close_rto = ctrl_backoff(w, st->close_rto);
        st->close_ts = current + st->close_rto;
        st->close_xmit++;
        st->close_answer = 0;
        if (st->close_xmit >= w->dead_link)
            mark_dead(w, "close", st->sid, st->final_sn, st->close_xmit, 0, current);
    } else if (st->close_answer) {
        /* answer each FIN of the peer (paced by the peer's RTO): ACKFIN, with
           our FIN if our direction is closed too */
        write_close_seg(w, st->sid, st->final_sn, 0, st);
        st->close_answer = 0;
    }

    /* FWD */
    if (st->fwd_pending && tdiff(current, st->fwd_ts) >= 0) {
        write_fwd_seg(w, st, st->fwd_una);
        st->fwd_rto = ctrl_backoff(w, st->fwd_rto);
        st->fwd_ts = current + st->fwd_rto;
        st->fwd_xmit++;
        if (st->fwd_xmit > w->dead_link)
            mark_dead(w, "fwd", st->sid, st->fwd_una, st->fwd_xmit, 0, current);
    }
}

static void flush_rstq(anl_t *w)
{
    int i;
    for (i = 0; i < w->nrstq; i++) {
        write_close_seg(w, w->rstq[i], 0, 1, NULL);
    }
    if (w->nrstq) memset(w->rst_set, 0, sizeof(uint32_t) * 2 * (size_t)w->rstq_cap);
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

/* Our own backlog at the bottleneck: every wire byte sent, drained at the
 * bandwidth estimate or the rate the last burst went through (vq_ms) */
static uint32_t vq_left(const anl_t *w)
{
    uint32_t rate = umax32(bbr_bw(w), w->burst_bw);
    int32_t dt = tdiff(w->current, w->vq_ts);
    uint64_t drained = dt > 0 ? (uint64_t)rate * (uint32_t)dt / 1000 : 0;
    return drained >= w->vq_bytes ? 0 : w->vq_bytes - (uint32_t)drained;
}

static void vq_add(anl_t *w, uint32_t wire)
{
    uint64_t left = (uint64_t)vq_left(w) + wire;
    w->vq_bytes = left > 0xffffffffu ? 0xffffffffu : (uint32_t)left;
    w->vq_ts = w->current;
}

/* The time a segment just sent waits behind that backlog: its RTO waits as
 * much longer. A key frame's burst, paced above the bottleneck, delays its
 * last segments and the frames after it: at 5 Mbit, 100 ms, 20% loss their
 * RTT reached 140..210 ms against an RTO of 130 from the smoothed RTT, and
 * 57% of the video retransmissions were of segments the peer already had.
 * Drained at the faster of the estimate and the rate bursts went through, at
 * most one srtt, and not while capacity is short: an app-limited or collapsed
 * estimate read a backlog the link did not have, the late RTOs sent less, the
 * estimate fell further - parity stayed at its floor under 20% loss, and a
 * 4 Mbit path stayed capacity-short for 30 s after an 800 kbit stretch. */
static uint32_t vq_ms(const anl_t *w)
{
    uint32_t rate = umax32(bbr_bw(w), w->burst_bw);
    uint32_t srtt = w->rx_srtt > 0 ? (uint32_t)w->rx_srtt : RTO_DEF;
    if (w->capacity_short || rate == 0) return 0;
    return (uint32_t)umin32((uint64_t)vq_left(w) * 1000 / rate, srtt);
}

static void move_and_send(anl_t *w, anl_stream *st)
{
    anl_seg *seg = qfirst_seg(&st->snd_queue);
    qdel(&seg->node);
    st->nsnd_que--;
    qadd_tail(&seg->node, &st->snd_buf);
    st->nsnd_buf++;
    seg->sn = st->snd_nxt++;
    seg->rto = (uint32_t)w->rx_rto;
    seg->resendts = w->current + seg->rto;
    seg->lost = 0;
    seg->xmit = 0;
    send_seg(w, st, seg);
    seg->resendts += vq_ms(w);
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
    uint64_t dp, dwire, dd, dpar, base, pay_rate;
    uint32_t rmin, queue;
    int delivery_limited;
    if (w->rate_ts != 0 && dt < RATE_STEP_MS) return;
    dp = w->tx_payload - w->rate_payload0;
    dwire = (uint32_t)(w->sent_wire - (uint32_t)w->rate_wire0); /* sent_wire wraps at 32 bits */
    dd = w->delivered - w->rate_deliv0;
    dpar = (uint32_t)(w->sent_par - w->rate_par0);
    w->rate_par0 = w->sent_par;
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
    /* A small packet acknowledged before the first media flight finishes
       measures its bytes over the whole RTT, not the path's capacity. Do
       not initialize encoder feedback or the send/delivery averages from
       that sample: the 25%/s growth limit would hold the source near zero,
       while the initial key burst makes delivery look capacity-limited
       and turns off audio repair. Wait once for the payload of a normal
       two-datagram ACK batch; BBR and pacing keep operating meanwhile. */
    if (w->btl_bw == 0 || w->rx_srtt <= 0) return;
    if (w->rate_target == 0 && w->delivered_pay < 2u * w->mss) {
        w->rate_dpay0 = w->delivered_pay;
        w->rate_unsent0 = w->tx_unsent;
        return;
    }
    /* parity budget (DESIGN 8.6): 90% of the estimate less all else sent,
       smoothed over about 8 steps (1.6 s): a key frame fills a 200 ms
       step by itself, and a budget that read 0 for that step shrank the
       bucket and threw its tokens away */
    if (w->rate_rtt_ts == 0 || tdiff(w->current, w->rate_rtt_ts) >= RATE_RTT_WIN) {
        w->rate_rtt_old = w->rate_rtt_ts ? w->rate_rtt_min : (uint32_t)w->rx_srtt;
        w->rate_rtt_min = (uint32_t)w->rx_srtt;
        w->rate_rtt_ts = w->current ? w->current : 1;
    }
    w->rate_rtt_min = umin32(w->rate_rtt_min, (uint32_t)w->rx_srtt);
    rmin = umin32(w->rate_rtt_min, w->rate_rtt_old);
    queue = (uint32_t)w->rx_srtt - rmin;
    if (queue > umax32(rmin / 4, 25)) w->par_queue_ts = w->current | 1;
    base = (uint64_t)bbr_bw(w) * w->rate_share / 256 * (100 - RATE_MARGIN) / 100;
    pay_rate = dp * 1000 / (uint32_t)dt;
    delivery_limited = w->rate_steps >= 5 && w->dlv_avg != 0 &&
        (w->capacity_short || (uint64_t)w->dlv_avg * 4 < (uint64_t)w->pay_avg_prev * 3);
    if (queue > umax32(rmin / 2, 30)) {
        /* what the path delivers now, or - when nothing gets through in
           time - RATE_DECREASE % less per step; not below what BBR keeps
           going at its smallest window. While the path delivers all it is
           sent (no loss beyond a sixteenth, cs_loss of the last step) the
           queue is our own burst draining: not below the payload delivered
           over the last few steps (dlv_avg). A key frame's burst into a slow
           shaper queues for a step (30 KB is 300 ms of an 800 kbit link)
           and its few acknowledgements in that step read as 8..24 kB/s: the
           target fell to that on every key frame and climbed back at 25%/s
           for 9 s, the encoder at 23..55% of the link (real network, closed
           loop). A bottleneck that got slower loses what is sent and gets
           this step's rate (bwstep 8 -> 2 Mbps within a step, as before). */
        uint64_t floor = (uint64_t)BBR_MIN_CWND * w->mss * 1000 / (uint32_t)w->rx_srtt * w->rate_share / 256;
        uint64_t now_pay = dd * 1000 / (uint32_t)dt * w->rate_share / 256, cut;
        if (!w->cs_loss && now_pay < w->dlv_avg) now_pay = w->dlv_avg;
        cut = now_pay * (100 - RATE_MARGIN) / 100;
        if (cut < floor) cut = (uint64_t)w->rate_target * (100 - RATE_DECREASE) / 100;
        if (cut < floor) cut = floor;
        if (cut < base) base = cut;
        /* A burst draining into ACKs is not new capacity: apply the same
           upward limit as without a queue. A sustained delivery ceiling
           already bounds the target below actual delivery (below); let
           ACKs recover from a sparse step within that ceiling instead of
           making one low sample the starting point of a long ramp. */
        if (w->rate_target != 0 && !delivery_limited) {
            uint64_t grow = w->rate_target + (uint64_t)w->rate_target * RATE_GROWTH * (uint32_t)dt / 100000;
            if (base > grow) base = grow;
        }
    } else {
        /* up at most RATE_GROWTH %/s: after a bandwidth drop the estimate may
           return to the old peak (app-limited rounds do not age it out, bw_lo
           goes at the next probe) - climbing, the queue shows first. While
           app-limited without a queue, up by as much (at most 1.25 x what is
           sent): the estimate only shows what the application sent. */
        uint64_t prev = w->rate_target ? w->rate_target : base;
        /* The bounded recovery test has to feed the path to test growth.
           The application may already send above a depressed target (its
           minimum media rate); start from that measured load, not below it. */
        if (w->cs_test_ts && prev < w->pay_avg) prev = w->pay_avg;
        uint64_t grow = prev + prev * RATE_GROWTH * (uint32_t)dt / 100000;
        /* 25 ms: at a low rate srtt sits 10..20 ms above its minimum anyway
           (ACKs wait for the flush interval, key frames come in bursts) */
        if ((w->app_limited != 0 || w->bw_last_app) && queue < umax32(rmin / 4, 25)) {
            uint64_t cap = pay_rate * 5 / 4;
            if (base < cap) base = grow < cap ? grow : cap;
        }
        if (base > grow) base = grow;
    }
    /* A policer keeps no queue: the estimate (a token bucket's burst) and
       the target sat above it while a quarter of the payload was dropped
       (1200 kbit policer: target 150..222 kB/s, the line at 1.6x). Losing
       over a quarter of the payload - no random loss does that - or short
       of capacity (8.6): not above what the path delivers, less the
       margin; parities are not payload, so they are out already. The
       delivered payload is compared with what was sent a step earlier: at
       170 ms a key frame's step sends 2x the average and its delivery
       shows a step later (against the same step the cap read 0.6 and held
       an 8 Mbps link's encoder at 0.8 Mbps) */
    /* During the existing 1.5 s capacity test, allow the ordinary bounded
       upward ramp to produce the load whose delivery the test measures.
       Capping it at old delivery otherwise defeats the requested probe. */
    if (delivery_limited && !w->cs_test_ts) {
        uint64_t cap = (uint64_t)w->dlv_avg * (100 - RATE_MARGIN) / 100;
        uint64_t floor = (uint64_t)BBR_MIN_CWND * w->mss * 1000 / (uint32_t)w->rx_srtt * w->rate_share / 256;
        if (cap < floor) cap = floor;
        if (base > cap) base = cap;
    }
    w->rate_target = base > 0xffffffffu ? 0xffffffffu : (uint32_t)base;
    if (w->rate_cb && (w->rate_told == 0 || w->rate_target * 20ull >= w->rate_told * 21ull || w->rate_target * 20ull <= w->rate_told * 19ull)) {
        w->rate_told = w->rate_target;
        w->rate_cb(w, w->rate_target, w->user);
    }
    /* Capacity short (DESIGN 8.6): the bottleneck is slower than the media.
       Two signs, each smoothed over about 4 steps (a key frame's step sends
       2x the average, its delivery shows a step later), each with its own
       hysteresis so that the state does not flap once the parity is gone
       and the ratio recovers a little:
       - the path delivers under half of the payload sent: strong initial
         evidence of overflow (recovery is retested below; retransmissions
         and abandoned frames can also depress this ratio). The queue is
         no criterion: a shaper caps it (tc tbf
         at 100 ms: srtt 230 on a 170 ms path while it dropped 70%) - leaves
         above three quarters;
       - a sixteenth or more of the semi-reliable payload expires at the
         sender before its first send (semi_drop_check): whatever the
         estimate says, the sender could not send the media in max_age.
         Losses on a good path never do this (a frame lost in flight is
         abandoned by the retransmission path, not here) - leaves below a
         sixty-fourth. Only once it has happened twice, at least 1 s apart,
         within 6 s: a bottleneck that is too slow expires frames every
         second or two for as long as it lasts, a one-off dip of the model
         (a route change, a burst of loss) flushes a backlog once, and one
         GOP is two seconds of the media - enough to read as a sixteenth
         for the next 3 s.
       Additional parity could deepen the apparent overflow: no adaptive
       parity (fec_close_block), gates closed (fec_gate_update), no budget. The estimate cannot tell: a token bucket's burst or a key
       frame measured it (1.2..1.9 Mbps on an 800 kbit shaper, real network).
       Nor is the sender app-limited then (anl_flush_internal): its queue is
       empty because it discarded the application's data, not because the
       application had nothing to send - marked app-limited, every sample
       was ignored, the filter never aged the burst's peak out, and the
       burst headroom kept pacing at 2.885x an estimate already 1.6x the
       link (simulation, tbf 800 kbit: 70% lost for a minute). */
    {
        uint64_t dlv_pay = (w->delivered_pay - w->rate_dpay0) * 1000 / (uint32_t)dt;
        uint64_t dun = w->tx_unsent - w->rate_unsent0, un_rate = dun * 1000 / (uint32_t)dt, off_rate = pay_rate + un_rate;
        int enter, leave, repeated, retry_ok, grew;
        w->rate_unsent0 = w->tx_unsent;
        w->rate_dpay0 = w->delivered_pay;
        if (dun > 0 && (w->exp_last == 0 || tdiff(w->current, w->exp_last) >= 1000)) {
            w->exp_prev = w->exp_last;
            w->exp_last = w->current | 1;
        }
        repeated = w->exp_prev != 0 && tdiff(w->current, w->exp_prev) <= 6000;
#define RATE_AVG(f, x) (w->f = w->f == 0 ? sat32(x) : (uint32_t)((int64_t)w->f + ((int64_t)sat32(x) - (int64_t)w->f) / 4))
        w->pay_avg_prev = w->pay_avg;
        RATE_AVG(pay_avg, pay_rate);
        RATE_AVG(dlv_avg, dlv_pay);
        RATE_AVG(off_avg, off_rate);
        RATE_AVG(unsent_avg, un_rate);
#undef RATE_AVG
        /* Not in the first second: delivery trails sending by a round trip,
           and the first steps' averages would read "half delivered" on any
           path (the first key frame went unprotected). Three steps in a
           row: a key frame's burst into a shallow queue reads the same for
           a step or two (start_rate's 4-datagram queue, every key frame),
           a slow bottleneck for as long as it lasts. Out after ten steps
           in a row that read clear and at least 3 s: frames expire in
           bunches (a GOP at a time, every second or two) and the sender
           backs off in between; leaving at each lull let the gate reopen
           and the parity return for a few seconds at a time. */
        if (w->rate_steps < 0xffffffffu) w->rate_steps++;
        retry_ok = w->lt_state == 0 && queue < umax32(rmin / 4, 25);
        /* A failed retry is still the known shortage, not a new suspicion:
           restore suppression now instead of waiting three more steps. */
        if (w->cs_recover && !retry_ok) {
            w->cs_recover = 0;
            w->capacity_short = 1; w->cs_ts = w->current | 1;
            w->cs_by_unsent = 0;
        }
        if (w->cs_recover && tdiff(w->current, w->cs_recover) >= 0) w->cs_recover = 0;
        if (w->cs_test_ts && !retry_ok) {
            w->cs_test_ts = 0;
            w->cs_ts = w->current | 1;
        }
        enter = w->rate_steps >= 5 && !w->cs_recover && w->dlv_avg != 0 &&
                ((uint64_t)w->dlv_avg * 2 < w->pay_avg || (repeated && (uint64_t)w->unsent_avg * 16 > w->off_avg));
        leave = (uint64_t)w->dlv_avg * 4 > (uint64_t)w->pay_avg * 3 && (uint64_t)w->unsent_avg * 64 < w->off_avg;
        /* Random loss can keep delivery below the 75% exit threshold even
           after capacity returns: retransmitted payload is counted in what
           we send, and abandoned frames never acknowledge their tail. With
           parity off and app-limited marking suppressed the model then
           follows its own low pace. After 5 s, a second without queueing
           that delivers the majority of payload permits a bounded test.
           Residual loss is required at its start: an already clean path
           uses the ordinary exit (rushing it reopened parity on a policer).
           Keep short/parity-off while testing, but release bw_lo and allow
           burst headroom/app-limited samples for at most 1.5 s. The absence
           of a queue alone is not proof of capacity: delivery must grow by
           a quarter after at least 1 s, or the test waits another 5 s.
           A successful test gets 4 s to flush old expiries and observe FEC
           after its usual 2 s gate hold. Queueing/policer feedback cancels
           that grace immediately; a low single-step delivery ratio does
           not, since a key-frame/ACK burst also causes it on a lossy path. */
        if (w->capacity_short && tdiff(w->current, w->cs_ts) >= 5000 &&
            retry_ok && (uint64_t)w->dlv_avg * 2 > w->pay_avg)
            w->cs_retry++;
        else w->cs_retry = 0;
        if (w->capacity_short && w->cs_retry >= 5 && !w->cs_test_ts &&
            (uint64_t)w->dlv_avg * 16 < (uint64_t)w->pay_avg * 15) {
            w->cs_test_ts = w->current | 1;
            w->cs_test_dlv = w->dlv_avg;
            w->bw_lo = 0;
        }
        /* The network's own signs of the shortage: payload lost (over a
           sixteenth) or a queue. A state entered on expiring frames alone
           ends after five steps (1 s) without either, whatever the expiries
           say: when the bottleneck recovers (tbf 800 kbit -> 3 Mbit) the
           estimate is still the slow link's, the backlog keeps expiring
           frames, and held short and network-limited the model could only
           grow by PROBE_BW's quarter per 2..3 s cycle (real network: short
           for 4..9 s after the switch, the first 10 s at 3 Mbit 63..97% on
           time against 100%). Not a state entered on loss (an outage, a
           policer): ending that one on calm alone let soak's outage phase
           leave 2 s earlier and the RTT jump that follows collapse the
           model in 3 of 6 seeds (hirtt 97 -> 72..76%). */
        w->cs_loss = (uint64_t)w->dlv_avg * 16 < (uint64_t)w->pay_avg * 15;
        w->cs_net = w->cs_loss || queue > umax32(rmin / 4, 25);
        w->cs_calm = w->cs_net ? 0 : w->cs_calm + 1;
        /* ... and meanwhile the model grows a quarter per round instead of
           per probe cycle: bw_lo (cut on the lossy rounds of the shortage)
           released, PROBE_BW due now, UP not ended by "the pipe is full" -
           the pipe is the stale estimate's - but by a round without growth
           (bbr_probe_due, bbr_update_state) */
        {
            int probe = w->cs_test_ts != 0 || (w->cs_by_unsent && w->cs_calm >= 3 &&
                        (w->capacity_short || (w->cs_ts != 0 && tdiff(w->current, w->cs_ts) < 5000)));
            if (probe && !w->cs_probe) w->bw_lo = 0;
            w->cs_probe = probe;
        }
        grew = w->cs_test_ts && tdiff(w->current, w->cs_test_ts) >= 1000 &&
               (uint64_t)w->dlv_avg * 4 > (uint64_t)w->cs_test_dlv * 5;
        w->cs_cnt = enter ? w->cs_cnt + 1 : 0;
        w->cs_clear = leave ? w->cs_clear + 1 : 0;
        if (!w->capacity_short && w->cs_cnt >= 3) {
            w->capacity_short = 1; w->cs_ts = w->current | 1;
            w->cs_by_unsent = !((uint64_t)w->dlv_avg * 2 < w->pay_avg);
        } else if (w->capacity_short && (w->cs_clear >= 10 || grew || (w->cs_by_unsent && w->cs_calm >= 5)) &&
                   tdiff(w->current, w->cs_ts) >= 3000) {
            if (w->cs_test_ts) w->cs_recover = (w->current + 4000) | 1;
            w->capacity_short = 0; w->cs_ts = w->current | 1;
            w->cs_cnt = 0;
        }
        if (w->cs_test_ts && (!w->capacity_short || w->lt_state != 0 ||
            queue > umax32(rmin / 4, 25) || tdiff(w->current, w->cs_test_ts) >= 1500)) {
            w->cs_test_ts = 0;
            w->cs_retry = 0;
            if (w->capacity_short) w->cs_ts = w->current | 1;
        }
#ifdef ANL_CAPACITY_TRACE
        ANL_CAPACITY_TRACE(w, enter, leave);
#endif
    }
    /* parity budget (DESIGN 8.6): 90% of the estimate less all else sent,
       smoothed over about 8 steps (1.6 s): a key frame fills a 200 ms
       step by itself, and a budget that read 0 for that step shrank the
       bucket and threw its tokens away. Nothing while capacity is short:
       the estimate itself is what a token bucket's burst or a key frame
       measured, not what the path sustains (real network: 1.2..1.9 Mbps on
       an 800 kbit shaper) */
    if (w->capacity_short) {
        w->par_rate = 0;
        if (w->par_tokens > 0) w->par_tokens = 0;
    } else {
        uint64_t other = (dwire > dpar ? dwire - dpar : 0) * 1000 / (uint32_t)dt;
        uint64_t avail = (uint64_t)bbr_bw(w) * 9 / 10;
        uint32_t now = avail > other ? (uint32_t)(avail - other) : 0;    /* < 0xffffffff: bw is 32-bit */
        w->par_rate = w->par_rate == 0xffffffffu ? now
                    : (uint32_t)((int64_t)w->par_rate + ((int64_t)now - (int64_t)w->par_rate) / 8);
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
        inflight += st->nsnd_buf - umin32(st->nlost, st->nsnd_buf);
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
            uint32_t next_rto = current + RTO_MAX, want, found = 0;
            int rto_due;
            if (w->pace_blocked || rtx_capped) break;
            if ((prio < 0 ? !st->strict : (st->strict || st->prio != prio)) || !stream_sendable(st)) continue;
            /* The walk costs the window (DESIGN 5.1): only while something is
               lost or an RTO may be due (every segment in snd_buf has been sent
               - move_and_send - so there is no first transmission), and with no
               RTO due only as far as the last segment RACK marked: those are the
               old ones, below what is in flight */
            rto_due = tdiff(current, st->rto_next) >= 0;
            want = st->nlost;
            if (want == 0 && !rto_due) continue;
            for (pos = st->snd_buf.next; pos != &st->snd_buf; pos = pos->next) {
                anl_seg *seg = QENTRY(pos, anl_seg, node);
                int why = 0;                            /* 1 first, 2 timeout, 3 RACK */
                if (!rto_due && found == want) break;
                if (seg->lost) found++;
                if (seg->xmit == 0) why = 1;
                else if (tdiff(current, seg->resendts) >= 0) why = 2;
                else if (seg->lost) why = 3;
                if (!why) {
                    if (tdiff(seg->resendts, next_rto) < 0) next_rto = seg->resendts;
                    continue;
                }
                if (why != 1 && semi_expired(w, st, seg)) {
                    /* past max_age: abandon instead of retransmitting (DESIGN 7.3).
                       Not an FEC failure: the peer may well have it (repaired,
                       its ACK still on the way) - only the peer's skips tell
                       (handle_report, DESIGN 8.5). But a loss with hard evidence
                       for the gate: unacknowledged for max_age while higher sn
                       were - no reordering lasts that long (audio at 280 ms RTT
                       never gets its retransmissions confirmed) */
                    if (st->fec && st->rack_valid && tdiff(seg->sn, st->rack_hi) < 0) w->fec_loss_ts = w->current | 1;
                    abandon_through(w, st, seg->frame_no);
                    pos = &st->snd_buf;         /* a prefix was removed: restart at the new head */
                    want = st->nlost;
                    found = 0;
                    continue;
                }
                if (!pace_can_send(w)) { w->pace_blocked = 1; next_rto = current; break; }
                if (retrans_spent >= retrans_limit) { rtx_capped = 1; next_rto = current; break; }
                if (why == 2) {
                    lost = 1;
                    seg->rto = umin32(seg->rto + seg->rto / 2, RTO_MAX);  /* back off x1.5 */
                    seg->resendts = current + seg->rto;
                } else if (why == 3) {
                    seg->resendts = current + seg->rto;
                }
#ifdef ANL_RTX_TRACE
                ANL_RTX_TRACE(w, st, seg, why);
#endif
                seg->rack_rtx = why == 3 ? 1 : why == 2 ? 2 : 0;
                if (seg->lost) st->nlost--;
                seg->lost = 0;
                send_seg(w, st, seg);
                seg->resendts += vq_ms(w);
                if (tdiff(seg->resendts, next_rto) < 0) next_rto = seg->resendts;
                retrans_spent += data_seg_size(st, seg);
                if (st->mode == ANL_RELIABLE && seg->xmit >= w->dead_link)
                    mark_dead(w, why == 3 ? "reliable_rack" : why == 2 ? "reliable_rto" : "reliable_first",
                              st->sid, seg->sn, seg->xmit, seg->ts_enq, seg->ts_sent);
            }
            /* exact after a whole walk; now if it stopped for pacing; kept (a
               lower bound, send_seg lowers it) if it stopped at the last loss */
            if (pos == &st->snd_buf || w->pace_blocked || rtx_capped) st->rto_next = next_rto;
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
    /* Not while capacity is short and the path is losing what is sent
       (rate_update): the queues are empty because frames were discarded
       for age, not because the application had nothing to send - the
       network is the limit. With the path delivering everything (a model
       that collapsed after an RTT jump, soak hirtt: frames expire behind
       a window of 33 segments at 390 ms) the app-limited samples are what
       lets the model climb back; held network-limited it fell further
       (bw 408 -> 117 kB/s, video 67%). */
    if (!w->pace_blocked && w->flush_budget > 0 && !has_queued_data(w) && !(w->capacity_short && w->cs_loss && !w->cs_test_ts)) {
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
#ifdef ANL_FLUSH_TRACE
    ANL_FLUSH_TRACE(w, (int64_t)w->cwnd - (int64_t)inflight, retrans_spent, rtx_capped);
#endif

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
    cfg->max_peer_streams = 4096;
    cfg->default_snd_wnd = 4096;
    cfg->default_rcv_wnd = 4096;
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
        opt->rcv_deadline_ms = -1;
        opt->fec = ANL_FEC_RTT_AUTO;
        opt->report = 1;
    } else {
        /* 10 MB/s at up to 500 ms (DESIGN 6.1); memory is taken as data arrives */
        opt->snd_wnd = 4096;
        opt->rcv_wnd = 4096;
    }
}

anl_t *anl_create(uint32_t conv, const anl_config *cfg, void *user)
{
    anl_t *w;
    if (conv == 0 || cfg == NULL) return NULL;
    if (cfg->role != ANL_ROLE_CLIENT && cfg->role != ANL_ROLE_SERVER) return NULL;
    if (cfg->mtu < ANL_OVERHEAD + DATA_HDR_MAX + 2 + OPEN_BODY + 64 || cfg->mtu > 65535) return NULL;
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
    if (cfg->start_rate > 0) {
        /* paced from the start, a window for START_WND_MS at that rate (a
           first key frame in one flight), smaller bursts (DESIGN 6.8) */
        uint32_t segs = (uint32_t)((uint64_t)cfg->start_rate * START_WND_MS / 1000 / (w->mtu - ANL_OVERHEAD));
        w->start_cap = (uint32_t)cfg->start_rate;
        w->init_cwnd = ubound32(w->init_cwnd, segs, ANL_MAX_WND);
        if (cfg->pace_burst <= 0) w->pace_burst = START_BURST_MTU * w->mtu;
    }
    w->rcv_limit = cfg->rcv_limit_bytes > 0 ? (uint32_t)cfg->rcv_limit_bytes : 0;
    w->max_peer_streams = cfg->max_peer_streams > 0 ? umin32((uint32_t)cfg->max_peer_streams, ANL_MAX_STREAMS) : 4096;
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
    w->par_rate = 0xffffffffu;

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
        o.snd_wnd = cfg->default_snd_wnd > 0 ? cfg->default_snd_wnd : 4096;
        o.rcv_wnd = cfg->default_rcv_wnd > 0 ? cfg->default_rcv_wnd : 4096;
        w->dflt = stream_create(w, ANL_SID_DEFAULT, &o);
        if (w->dflt == NULL) { anl_release(w); return NULL; }
        w->dflt->strict = 1;
    }
    return w;
}

void anl_release(anl_t *w)
{
    if (w == NULL) return;
    while (!QEMPTY(&w->slist)) {
        anl_stream *st = STREAM_OF(w->slist.next);
        st->app_released = 1;
        stream_free(w, st);
    }
    anl_free(w->stab);
    anl_free(w->rstq);
    anl_free(w->rst_set);
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
        mark_dead(w, "idle", -1, 0, 0, 0, w->last_tx);
    bbr_dw_checkpoint(w);

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
        if (st->ack_pending || st->probe_ask || st->probe_tell || st->rst_pending || st->close_answer) return current;
        if (st->ack_rep_ts != 0) {
            int32_t d = tdiff(st->ack_rep_ts, current);
            if (d <= 0) return current;
            if (d < tm_min) tm_min = d;
        }
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
        if (st->state == ANL_STREAM_CLOSING && !st->fin_acked) {
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
    out->capacity_short = w->capacity_short;
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
    if (opt->fec < ANL_FEC_RTT_AUTO ||
        (opt->fec == ANL_FEC_RTT_AUTO && opt->mode != ANL_SEMI)) return ANL_EINVAL;
    if (opt->rcv_deadline_ms < -1) return ANL_EINVAL;
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
        st->rcv_deadline_ms = opt->rcv_deadline_ms == -1 ? st->max_age_ms : opt->rcv_deadline_ms;
        st->rcv_drop_until_key = opt->rcv_drop_until_key != 0;
    }
    /* FEC changes only before anything was segmented (mss depends on it) */
    if ((opt->fec != 0) != st->fec && st->snd_nxt == 0 && st->nsnd_que == 0) {
        fec_free(st);
        st->fec = 0;
        st->mss = stream_mss(w, st->sid);
        if (opt->fec) {
            st->fec = 1;
            st->mss = stream_mss(w, st->sid) - ANL_FEC_OVERHEAD;
            if (fec_alloc(st) < 0) { fec_free(st); st->fec = 0; st->mss = stream_mss(w, st->sid); return ANL_ENOMEM; }
        }
    }
    st->fec_rtt_auto = st->fec && opt->fec == ANL_FEC_RTT_AUTO;
    if (st->fec && (opt->fec_ratio == 0 || st->fec_rtt_auto) != st->fec_auto) {
        st->fec_auto = opt->fec_ratio == 0 || st->fec_rtt_auto;
        st->fec_sent = st->fec_miss = 0;
        if (st->fec_auto) st->fec_ratio = FEC_AUTO_START;
    }
    if (st->fec && st->fec_carry == 0) st->fec_carry = 50;     /* the first block rounds */
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
    st->mss = stream_mss(w, sid);
    st->open_ts = w->current;
    QINIT(&st->snd_queue); QINIT(&st->snd_buf); QINIT(&st->rcv_buf); QINIT(&st->rcv_queue);
    QINIT(&st->snd_time);
    QINIT(&st->rcv_runs);
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
    /* client even from 2, server odd; never reused within a connection. The
       peer tracks at most SID_WIN of our sids past the oldest one it has not
       seen yet (DESIGN 6.1): beyond that wait until it has heard of them */
    if (w->next_sid > ANL_MAX_SID ||
        (w->next_sid - sid_first(w->role)) / 2 - w->own_floor >= SID_WIN) { r = ANL_EBUSY; goto fail; }
    st = stream_create(w, (int)w->next_sid, opt);
    if (st == NULL) { r = ANL_ENOMEM; goto fail; }
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
    if (st->state == ANL_STREAM_CLOSING && st->half) {
        /* shut down before, now no longer reading either: the FIN again,
           as a full close, so that the peer stops sending (DESIGN 6.1) */
        st->half = 0;
        if (!st->peer_closed) {
            st->fin_acked = 0;
            st->close_ts = w->current;
            st->close_xmit = 0;
            st->close_rto = 0;
        }
    }
    stream_local_close(w, st);
    ctl_mark(st);
    stream_try_release(w, st);              /* may free st */
    flush_control(w);
    return ANL_OK;
}

int anl_stream_shutdown(anl_stream_t *st)
{
    anl_t *w;
    if (st == NULL) return ANL_EINVAL;
    w = st->w;
    if (st == w->dflt || st->app_released) return ANL_EINVAL;
    if (st->mode != ANL_RELIABLE) return ANL_EMODE;
    if (st->state != ANL_STREAM_OPEN) return ANL_OK;            /* closed already (either side) */
    st->half = 1;
    stream_local_close(w, st);
    stream_try_release(w, st);
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
    out->fec_ratio = fec_active(st->w, st) ? (uint32_t)st->fec_ratio : 0;
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
    if (recover && wnd_unused(w, st) > 0) { st->probe_tell = 1; ctl_mark(st); }
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
    recover = wnd_unused(w, st) == 0;
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
    /* frame sizes for the FEC gate (DESIGN 8.6) */
    if (key) st->fec_key_bytes = (uint32_t)len;
    else st->fec_frame_avg = st->fec_frame_avg == 0 ? (uint32_t)len
                           : (uint32_t)((int32_t)st->fec_frame_avg + ((int32_t)len - (int32_t)st->fec_frame_avg) / 8);

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
    recover = wnd_unused(w, st) == 0;
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
