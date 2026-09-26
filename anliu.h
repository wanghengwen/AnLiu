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
 * (immediate ACKs) may invoke the output callback synchronously. The output
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
/* BBR states (anl_stats.cc_state); congestion control is always BBR (DESIGN 6.8) */
#define ANL_BBR_STARTUP     0
#define ANL_BBR_DRAIN       1
#define ANL_BBR_PROBE_BW    2
#define ANL_BBR_PROBE_RTT   3
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
    int interval;               /* 20 ms (ikcp default is 100) */
    int init_cwnd;              /* 16 segments: cwnd until the first bandwidth sample */
    int dead_link;              /* 20 retransmissions (data / FWD / CLOSE, not OPEN) */
    int ts_window_ms;           /* 1000, fixed; not tied to RTO */
    int keepalive_ms;           /* 0 = off; keepalive datagrams are always padded */
    int idle_timeout_ms;        /* SERVER default 30000, CLIENT default 0 */
    int pace_rate;              /* bytes/s; 0 = BBR alone (gain * bandwidth estimate), > 0 = upper
                                   bound on the BBR rate (e.g. an uplink quota) */
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
    int fec_ratio;              /* FEC redundancy, parities per 100 data packets 1..100, default 25:
                                   Reed-Solomon over blocks of up to 100 ms (DESIGN 8);
                                   0 = adaptive 10..100, from the losses FEC did not repair (8.5) */
    int fec_deadline_ms;        /* adaptive FEC: a loss whose retransmission arrives within this
                                   (from enqueue) needs no FEC; 0 = semi max_age_ms / 2, reliable none */
    int max_age_ms;             /* semi only: 500, 0 = unlimited */
    int max_bytes;              /* semi only: 0 = unlimited */
    int drop_until_key;         /* semi only: 0 */
    int rcv_deadline_ms;        /* semi only: 0 = off */
    int rcv_drop_until_key;     /* semi only: after a lost frame discard non-key frames until the
                                   next key frame (they cannot be decoded); 0 = off */
    int report;                 /* receiver: send delay reports to the peer (DESIGN 6.9);
                                   semi 1, reliable 0 */
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
    uint32_t cwnd, inflight;            /* segments */
    uint32_t bw_estimate;               /* bytes/s, BBR bottleneck bandwidth (0 until the first sample) */
    int bw_app_limited;                 /* 1: the sender used less than bw_estimate, the real
                                           bandwidth may be higher (the estimate is a lower bound) */
    uint32_t bw_estimate_age_ms;        /* since the last sample that measured the path (not
                                           app-limited); 0xffffffff = none yet. While the application
                                           sends less, bw_estimate keeps that old peak - for an
                                           encoder use target_rate (DESIGN 6.8, 6.10) */
    uint32_t min_rtt;                   /* ms */
    int cc_state;                       /* ANL_BBR_STARTUP .. ANL_BBR_PROBE_RTT */
    uint32_t retrans;                   /* total retransmitted segments */
    uint32_t pace_rate;                 /* effective pacing rate, bytes/s */
    uint32_t target_rate;               /* payload bytes/s the application may send over all streams:
                                           bw_estimate less headers, FEC parities, retransmissions and
                                           a 10% margin; grows 10%/s while app-limited (DESIGN 6.10) */
    uint32_t rcv_bytes;                 /* bytes held in all receive buffers */
    uint64_t tx_datagrams, rx_datagrams;
    uint64_t rx_auth_fail, rx_stale;    /* ANL_EAUTH / ANL_ESTALE drops */
} anl_stats;

/* delay seen by a stream's receiver (DESIGN 6.9). Delays are relative to the
 * smallest one-way transit of the last 10 s: queueing, retransmission and
 * reassembly on top of the path's propagation time. */
typedef struct anl_delay_report {
    int      valid;             /* 0 until the first measurement / report */
    uint32_t age_ms;            /* since it was measured / arrived */
    uint32_t jitter_ms;         /* interarrival jitter (RFC 3550) */
    uint32_t qdelay_avg_ms, qdelay_max_ms;          /* per packet, over the last interval */
    uint32_t frame_delay_avg_ms, frame_delay_max_ms;/* from the earliest fragment's send time to
                                                       the frame being complete */
    uint32_t frames;            /* frames (messages) completed in the last interval */
    uint32_t frames_skipped;    /* receiver's total (mod 65536 in reports) */
    uint32_t fec_recovered;     /* receiver's total (mod 65536 in reports) */
} anl_delay_report;

typedef struct anl_stream_stats {
    int      state;             /* ANL_STREAM_OPENING .. ANL_STREAM_CLOSED */
    uint32_t wait_snd;          /* segments in snd_queue + snd_buf */
    uint32_t backlog_bytes;     /* unacknowledged bytes */
    uint32_t rmt_wnd;
    uint32_t retrans;
    uint32_t frames_dropped;    /* dropped by sender (age / bytes) */
    uint32_t frames_skipped;    /* skipped by receiver (FWD / deadline) */
    uint32_t fec_recovered;
    uint32_t fec_ratio;         /* sender: current FEC redundancy (follows the loss with fec_ratio 0) */
    uint32_t frames_discarded;  /* receiver: undecodable frames discarded (rcv_drop_until_key) */
    anl_delay_report rx;        /* receiver: measured here, on what the peer sends */
    anl_delay_report peer;      /* sender: the peer's latest report on what we send */
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

/* Called from anl_update / anl_input / anl_flush when stats.target_rate
 * changed by 5% or more (DESIGN 6.10), e.g. to set the encoder bitrate.
 * Like the accept callback it must not call anl_* functions, except the
 * read-only anl_get_stats / anl_stream_get_stats. */
typedef void (*anl_rate_fn)(anl_t *w, uint32_t target_rate, void *user);

/* Called from anl_input when the peer's delay report for stream s arrives
 * (DESIGN 6.9). Same restrictions as the rate callback. */
typedef void (*anl_report_fn)(anl_t *w, anl_stream_t *s, const anl_delay_report *r, void *user);

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
void     anl_set_rate_callback(anl_t *w, anl_rate_fn fn);
void     anl_set_report_callback(anl_t *w, anl_report_fn fn);

/* Feed a raw UDP datagram; on ANL_EAUTH the caller must not respond.
 * It may send an ACK at once: the output callback may be invoked synchronously. */
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

/* Close and release the handle. Reliable: orderly, unsent data is still
 * delivered. Semi-reliable: abort, frames in flight are dropped on both
 * sides. Unread received data is discarded. Afterwards the handle must not
 * be used. The default stream cannot be closed (ANL_EINVAL). */
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
