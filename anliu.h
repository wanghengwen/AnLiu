/*
 * anliu.h - AnLiu（暗流）: an encrypted, multi-stream, semi-reliable ARQ
 * protocol over UDP, modelled after ikcp.
 *
 * See DESIGN.md for the wire format and protocol rules.
 *
 * Threading: like ikcp, all calls on one anl_t must be serialised by the
 * caller. Different anl_t instances share no state (except anl_allocator).
 *
 * Re-entrancy: anl_flush, anl_send_frame (flush_on_send) and anl_input
 * (ack_nodelay) may invoke the output callback synchronously. The output
 * callback must not call any anl_* function.
 */
#ifndef ANLIU_H
#define ANLIU_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------
 * version / limits
 *---------------------------------------------------------------------*/
#define ANL_VERSION         0       /* wire version, flg bit7-6 */

#define ANL_MAX_STREAMS     8192    /* sid 0..8191, 13 bits on the wire (+1 reserved bit) */
#define ANL_SID_DEFAULT     0       /* the default stream, created with the connection */
#define ANL_MAX_WND         8192    /* 16-bit sn requires wnd << 32768 */
#define ANL_MAX_PRIO        4       /* prio 0 (highest) .. 3 */
#define ANL_MAX_FEC_DEPTH   16
#define ANL_FEC_GROUP       8       /* 8 data + 1 parity */
#define ANL_PSK_SIZE        32
#define ANL_MAX_PAD         255     /* pad length is stored in one byte */

#define ANL_TAG_SIZE        12      /* SipHash-2-4-128 truncated, doubles as nonce */
#define ANL_HDR_SIZE        9       /* conv(4) + flg(1) + ts(4) */
#define ANL_OVERHEAD        (ANL_TAG_SIZE + ANL_HDR_SIZE)   /* 21 */
#define ANL_FEC_OVERHEAD    12      /* mss reduction for FEC streams */

/*---------------------------------------------------------------------
 * return codes
 *---------------------------------------------------------------------*/
#define ANL_OK              0
#define ANL_EINVAL         -1       /* invalid argument */
#define ANL_EMODE          -3       /* API does not match stream mode */
#define ANL_EAGAIN         -4       /* nothing to read */
#define ANL_EBUFSIZE       -5       /* receive buffer too small */
#define ANL_ETOOBIG        -6       /* too many fragments (> peer rcv_wnd) */
#define ANL_EDROPPED       -7       /* frame dropped (drop_until_key) */
#define ANL_EAUTH          -8       /* auth failed: drop SILENTLY, never reply */
#define ANL_ECONV          -9       /* conv mismatch */
#define ANL_EFORMAT       -10       /* malformed packet */
#define ANL_ENOMEM        -11       /* allocation failed */
#define ANL_ECLOSED       -13       /* stream closed (by either side) or reset by the peer */
#define ANL_ESTALE        -14       /* datagram ts outside time window, dropped */
#define ANL_EDEAD         -15       /* connection is dead (dead_link / idle timeout) */
#define ANL_EBUSY         -16       /* no free sid */

/*---------------------------------------------------------------------
 * roles / modes / flags
 *---------------------------------------------------------------------*/
#define ANL_ROLE_CLIENT     0       /* the two ends MUST use different roles */
#define ANL_ROLE_SERVER     1

#define ANL_RELIABLE        0       /* ikcp-like reliable stream */
#define ANL_SEMI            1       /* semi-reliable frame stream */

#define ANL_FRAME_KEY       1       /* key frame */

/* stream states as reported by anl_stream_get_stats */
#define ANL_STREAM_OPENING  0       /* opened here, nothing heard from the peer yet (data is sent anyway) */
#define ANL_STREAM_OPEN     1
#define ANL_STREAM_CLOSING  2       /* close requested; draining snd_buf / waiting peer CLOSE */
#define ANL_STREAM_CLOSED   3       /* incl. streams reset by the peer */

/*---------------------------------------------------------------------
 * configuration
 *---------------------------------------------------------------------*/
typedef void (*anl_rng_fn)(void *user, uint8_t *buf, size_t n);

typedef struct anl_config {
    uint8_t psk[ANL_PSK_SIZE];  /* pre-shared key */
    int role;                   /* ANL_ROLE_CLIENT / ANL_ROLE_SERVER */
    int mtu;                    /* 1400 */
    int pad_max;                /* 32; 0 = no padding; <= ANL_MAX_PAD */
    anl_rng_fn rng;             /* NULL = built-in ChaCha20 PRNG */
    int nodelay;                /* 0, same as ikcp_nodelay */
    int interval;               /* 20 ms (ikcp default is 100) */
    int resend;                 /* 0 = no fast resend */
    int nc;                     /* 0 = congestion control on (pacing still applies) */
    int ack_nodelay;            /* 1 = ACK after every 2 data datagrams; 0 = ikcp behaviour */
    int init_cwnd;              /* 16 segments (ikcp: 1) */
    int dead_link;              /* 20 retransmissions (data / FWD / CLOSE, not OPEN) */
    int ts_window_ms;           /* 1000, fixed; not tied to RTO */
    int keepalive_ms;           /* 0 = off; keepalive datagrams are always padded */
    int idle_timeout_ms;        /* SERVER default 30000, CLIENT default 0 */
    int pace_rate;              /* bytes/s; 0 = auto (1.25*W*mss/srtt), -1 = no pacing */
    int pace_burst;             /* token bucket size in bytes; 0 = 4 * mtu */
    int rcv_limit_bytes;        /* connection-wide receive buffer cap; 16 MB, 0 = unlimited */
    int max_peer_streams;       /* streams the peer may have open at once; 1024, <= ANL_MAX_STREAMS */
    int default_snd_wnd;        /* default stream (sid 0) send window, 1200 */
    int default_rcv_wnd;        /* default stream (sid 0) receive window, 1200 */
} anl_config;

typedef struct anl_stream_opt {
    /* mode, tag, rcv_wnd and stream are chosen by the opening side and carried
     * to the peer with the first segments; the accepting side adopts them */
    int mode;                   /* ANL_RELIABLE / ANL_SEMI */
    int tag;                    /* application-defined 0..65535 */
    int prio;                   /* 0..3, 0 highest, default 2; weights 8/4/2/1 */
    int snd_wnd;                /* reliable 32, semi 512 */
    int rcv_wnd;                /* reliable 128, semi 512, max ANL_MAX_WND; same on both ends */
    int stream;                 /* reliable only: byte-stream mode */
    int flush_on_send;          /* semi default 1, reliable default 0 */
    int fec;                    /* 0 = off */
    int fec_depth;              /* interleave depth 1..16, default 1 */
    int fec_flush_ms;           /* 0 = min(interval, 20) */
    int max_age_ms;             /* semi only: 500, 0 = unlimited */
    int max_bytes;              /* semi only: 0 = unlimited */
    int drop_until_key;         /* semi only: 0 */
    int rcv_deadline_ms;        /* semi only: 0 = off */
    int rcv_drop_until_key;     /* semi only: after a lost frame discard non-key frames until the
                                   next key frame (they cannot be decoded); 0 = off */
} anl_stream_opt;

typedef struct anl_frame_info {
    uint32_t frame_no;          /* protocol-assigned, from 0 */
    int      flags;             /* ANL_FRAME_KEY */
    uint32_t lost_before;       /* frames lost since last delivered one */
} anl_frame_info;

/*---------------------------------------------------------------------
 * statistics
 *---------------------------------------------------------------------*/
typedef struct anl_stats {
    uint32_t srtt, rttval, rto;         /* ms */
    uint32_t cwnd, ssthresh, inflight;  /* segments */
    uint32_t retrans;                   /* total retransmitted segments */
    uint32_t pace_rate;                 /* effective pacing rate, bytes/s */
    uint32_t rcv_bytes;                 /* bytes held in all receive buffers */
    uint64_t tx_datagrams, rx_datagrams;
    uint64_t rx_auth_fail, rx_stale;    /* ANL_EAUTH / ANL_ESTALE drops */
} anl_stats;

typedef struct anl_stream_stats {
    int      state;             /* ANL_STREAM_OPENING .. ANL_STREAM_CLOSED */
    uint32_t wait_snd;          /* segments in snd_queue + snd_buf */
    uint32_t backlog_bytes;     /* unacknowledged bytes */
    uint32_t rmt_wnd;
    uint32_t retrans;
    uint32_t frames_dropped;    /* dropped by sender (age / bytes) */
    uint32_t frames_skipped;    /* skipped by receiver (FWD / deadline) */
    uint32_t fec_recovered;
    uint32_t frames_discarded;  /* receiver: undecodable frames discarded (rcv_drop_until_key) */
} anl_stream_stats;

typedef struct anl_s anl_t;
typedef struct anl_stream anl_stream_t;

typedef int (*anl_output_fn)(const char *buf, int len, anl_t *w, void *user);

/* Called from anl_input when the peer opens a new stream. s is the new
 * stream (anl_stream_tag / anl_stream_id tell what it is); opt is pre-filled
 * with anl_stream_opt_default(peer mode) plus the peer's mode / stream / tag /
 * rcv_wnd, and the callback may change any local option except those four.
 * Return 0 to accept (the application then owns s and must anl_stream_close
 * it), < 0 to refuse (s is freed, the peer gets an RST). Like the output
 * callback it must not call any anl_* function, except anl_stream_set_user. */
typedef int (*anl_accept_fn)(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user);

void anl_config_default(anl_config *cfg, int role);
void anl_stream_opt_default(anl_stream_opt *opt, int mode);

/*---------------------------------------------------------------------
 * keys / server demux
 *---------------------------------------------------------------------*/
/* per-direction keys derived from the PSK; index = sender role */
typedef struct anl_keys {
    uint8_t enc[2][32];         /* ChaCha20 key */
    uint8_t mac[2][16];         /* SipHash key */
    uint8_t rng[2][16];         /* built-in PRNG seed key */
} anl_keys;

void anl_keys_derive(anl_keys *keys, const uint8_t psk[ANL_PSK_SIZE]);

/* Verify and decrypt one datagram with the peer-direction keys of `role`.
 * On success returns the plaintext length, writes the plaintext into
 * `plain` (capacity >= size - ANL_TAG_SIZE) and outputs conv.
 * Returns ANL_EAUTH / ANL_EFORMAT on failure; never reply on ANL_EAUTH. */
int anl_peek_conv(const anl_keys *keys, int role, const char *data, long size,
                  uint32_t *conv, char *plain);

/*---------------------------------------------------------------------
 * connection
 *---------------------------------------------------------------------*/
/* create a connection; conv must be equal on both sides and non-zero */
anl_t   *anl_create(uint32_t conv, const anl_config *cfg, void *user);
void     anl_release(anl_t *w);
void     anl_setoutput(anl_t *w, anl_output_fn output);
/* NULL (default) accepts every peer-opened stream with default options */
void     anl_set_accept(anl_t *w, anl_accept_fn accept);

/* Feed a raw UDP datagram; on ANL_EAUTH the caller must not respond.
 * With ack_nodelay the output callback may be invoked synchronously. */
int      anl_input(anl_t *w, const char *data, long size);
/* feed plaintext already verified by anl_peek_conv (skips crypto) */
int      anl_input_plain(anl_t *w, const char *plain, long size);

/* Drive timers; current is a monotonic millisecond clock. anl_check also
 * accounts for pacing: drive a timer from its return value (1..5 ms
 * resolution recommended for real-time streams) to get smooth output. */
void     anl_update(anl_t *w, uint32_t current);
uint32_t anl_check(const anl_t *w, uint32_t current);
void     anl_flush(anl_t *w);

/* 0 = alive, -1 = dead (dead_link or idle timeout) */
int      anl_state(const anl_t *w);
int      anl_get_stats(const anl_t *w, anl_stats *out);

void     anl_allocator(void *(*new_malloc)(size_t), void (*new_free)(void *));

/*---------------------------------------------------------------------
 * default stream (sid 0): created with the connection on both sides, usable
 * at once, reliable byte stream (ikcp semantics), strict priority over every
 * other stream, cannot be closed. Windows: cfg.default_snd_wnd / rcv_wnd.
 *---------------------------------------------------------------------*/
int      anl_send(anl_t *w, const char *buf, int len);
int      anl_recv(anl_t *w, char *buf, int len);
int      anl_peeksize(const anl_t *w);
int      anl_waitsnd(const anl_t *w);
anl_stream_t *anl_default_stream(anl_t *w);

/*---------------------------------------------------------------------
 * streams (handles)
 *
 * Lifetime follows sockets: a handle is valid from anl_stream_open (or the
 * accept callback) until the application calls anl_stream_close on it (or
 * anl_release). A stream closed or reset by the peer keeps its handle; calls
 * then return ANL_ECLOSED and the application still has to close it.
 *---------------------------------------------------------------------*/
/* Opens a stream with an automatically allocated sid (client even from 2,
 * server odd). There is no handshake: the first segments carry the stream
 * parameters and the peer creates the stream on arrival.
 * Returns NULL on failure with the reason in *err (optional):
 * ANL_EINVAL / ANL_EDEAD / ANL_EBUSY (no free sid) / ANL_ENOMEM. */
anl_stream_t *anl_stream_open(anl_t *w, const anl_stream_opt *opt, int *err);

/* Orderly close and release of the handle. Unsent data is still delivered
 * (reliable), unread received data is discarded. Afterwards the handle must
 * not be used. The default stream cannot be closed (ANL_EINVAL). */
int      anl_stream_close(anl_stream_t *s);

/* reliable stream: ikcp semantics. recv returns ANL_ECLOSED once the peer has
 * closed the stream and everything has been read (end of stream). */
int      anl_stream_send(anl_stream_t *s, const char *buf, int len);
int      anl_stream_recv(anl_stream_t *s, char *buf, int len);

/* semi-reliable stream: frames. frame_no (optional) receives the assigned
 * number, even on ANL_EDROPPED. */
int      anl_stream_send_frame(anl_stream_t *s, int flags, const char *buf, int len,
                               uint32_t *frame_no);
int      anl_stream_recv_frame(anl_stream_t *s, char *buf, int len, anl_frame_info *info);

/* size of the next message / frame; ANL_EAGAIN if none, ANL_ECLOSED at end */
int      anl_stream_peeksize(const anl_stream_t *s);
/* segments waiting to be sent or acknowledged */
int      anl_stream_waitsnd(const anl_stream_t *s);
int      anl_stream_get_stats(const anl_stream_t *s, anl_stream_stats *out);

int      anl_stream_id(const anl_stream_t *s);          /* sid on the wire, same on both sides */
int      anl_stream_tag(const anl_stream_t *s);         /* tag given by the opening side */
anl_t   *anl_stream_conn(const anl_stream_t *s);
void     anl_stream_set_user(anl_stream_t *s, void *user);
void    *anl_stream_get_user(const anl_stream_t *s);

/* Streams owned by the application that can be read now (data, end of
 * stream or error). Writes up to max handles, returns the total count. */
int      anl_readable(anl_t *w, anl_stream_t **out, int max);

#ifdef __cplusplus
}
#endif

#endif /* ANLIU_H */
