/*
 * churn: AnLiu streams opened and closed without pause over a real UDP path -
 * the close handshake (CLOSE until the peer's RST, DESIGN 6.1), the places it
 * holds meanwhile, and what the peer reads of a stream closed under it.
 *
 *   server:  ./churn server [--port P] <options>
 *   client:  ./churn client --host H [--port P] <options>
 *
 * Both ends get the same options:
 *   --dur S    seconds of churn (default 600); then 30 s to drain, the check,
 *              and 15 s more answering the peer
 *   --conc N   streams of its own each side keeps open at once (default 31,
 *              at most 31: both sides' 62 and the default stream fit in 64)
 *   --seed N
 *
 * Each side opens its own streams, up to --conc at once, and closes them in
 * one of six ways (the plan travels in every message, so the peer checks it):
 *   graceful   reliable, M messages, closed once all are acknowledged: the
 *              peer must read all M, then ANL_ECLOSED
 *   semi       semi-reliable frames (20 fps), closed after a random time
 *   abrupt     reliable messages, closed after a random time with data in
 *              flight: the peer reads an in-order prefix, then ANL_ECLOSED
 *   peer       the acceptor closes after K messages / frames; the opener's
 *              sends then fail and it closes a stream that is over (no CLOSE)
 *   both       the opener closes once its K messages are acknowledged, the
 *              acceptor when it reads the last one: the two CLOSEs often cross
 *   instant    open, one message, close at once: the peer often never hears
 *              of the stream, or hears of the CLOSE first
 * The budget of its own streams counts the ones closed here and not confirmed
 * yet (closing records of our own sids): with both sides' budgets at most 63,
 * no open can reach a full peer, so a refused open (RST to a new stream) is a
 * failure. ANL_EBUSY from anl_stream_open is the library's own check, retried.
 *
 * Output: CHURN_OPEN / CHURN_CLOSE / CHURN_READ / CHURN_FINAL lines, then
 * HEALTH (errors=0 and the final check passed: ok=1).
 *
 * Build:  gcc -std=gnu99 -O2 -I.. churn.c -lm -o churn
 * (includes ../anliu.c: reads the closing records of the connection)
 */
#include <stdint.h>
#include <stdio.h>
struct anl_s;
/* why the connection was declared dead (DEAD line) */
static void trace_dead(const struct anl_s *w, const char *reason, int sid, uint32_t sn,
                       uint32_t xmit, uint32_t enqueued, uint32_t last_sent);
#define ANL_DEAD_TRACE trace_dead
#include "../anliu.c"
#undef ANL_DEAD_TRACE
static void trace_dead(const struct anl_s *w, const char *reason, int sid, uint32_t sn,
                       uint32_t xmit, uint32_t enqueued, uint32_t last_sent)
{
    printf("DEAD_REASON now=%u reason=%s sid=%d sn=%u xmit=%u enqueued=%u last_sent=%u last_rx=%u srtt=%d rto=%d\n",
           w->current, reason, sid, sn, xmit, enqueued, last_sent, w->last_rx, w->rx_srtt, w->rx_rto);
    fflush(stdout);
}

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MTU         1400
#define DRAIN_S     30
#define LINGER_S    15
#define SEND_MS     50          /* a message / frame every 50 ms on each stream */
#define MSG_LEN     600
#define FRAME_LEN   400
#define MAX_LAT     400000
#define HDR         16          /* 'C' | plan | uid(2) | idx(4) | total(4) | sid(4) */

enum { P_GRACEFUL, P_SEMI, P_ABRUPT, P_PEER, P_BOTH, P_INSTANT, NPLAN };
static const char *plan_name[NPLAN] = { "graceful", "semi", "abrupt", "peer", "both", "instant" };
static const int plan_weight[NPLAN] = { 25, 25, 15, 15, 10, 10 };

typedef struct lst {
    anl_stream_t *s;
    int own, plan, semi, sid;
    uint32_t uid;                   /* the opener's count of its opens (low 16 bits): sids are reused, this
                                       tells the stream on a sid from an earlier one on the same sid */
    uint32_t t_open, t_next, t_end;
    uint32_t sent, total;           /* own: sent, the M or K of the plan */
    uint32_t got;                   /* accepted: messages / frames read */
    int plan_known;
} lst;

typedef struct pend { int sid; uint32_t t; int by_acceptor; } pend;

static int g_fd, g_server, g_connected;
static struct sockaddr_storage g_peer;
static socklen_t g_peerlen;
static anl_t *g_w;
static uint32_t g_t0, g_dur = 600, g_conc = 31, g_seed = 1;
static uint64_t g_rng;

static lst *g_own[64], *g_acc[128];
static int g_nown, g_nacc;
static pend g_pend[4 * CLOSE_MAX];
static int g_npend;
static uint32_t *g_lat[2];          /* confirmation times: [0] closed by the opener, [1] by the acceptor */
static int g_nlat[2];

/* counters */
static uint64_t c_open, c_open_plan[NPLAN], c_ebusy, c_refused, c_open_fail;
static uint64_t c_close_rec, c_close_norec, c_close_rec_bad, c_lost_pend, c_over_closed;
static uint64_t c_acc, c_acc_over, c_acc_over_plan[NPLAN], c_acc_close, c_items, c_bytes;
static uint64_t c_graceful_ok, c_graceful_short, c_order_err, c_pattern_err, c_gen_err, c_peer_never;
static uint32_t c_max_sid;
static uint64_t c_input_err, c_output_err, c_tx, c_rx, c_replay;
static uint32_t c_max_clos, c_max_stab;

static uint32_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}

static uint32_t rnd_in(uint32_t lo, uint32_t hi) { return lo + rnd() % (hi - lo + 1); }

static void put32(char *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get32(const char *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* the payload after the header follows from sid, uid and idx: a corrupted or
   misdelivered message is caught */
static void fill(char *b, int len, int plan, uint32_t idx, uint32_t total, int sid, uint32_t uid)
{
    int i;
    b[0] = 'C'; b[1] = (char)plan; b[2] = (char)(uid & 0xff); b[3] = (char)((uid >> 8) & 0xff);
    put32(b + 4, idx); put32(b + 8, total); put32(b + 12, (uint32_t)sid);
    for (i = HDR; i < len; i++) b[i] = (char)((uint32_t)sid * 31u + idx * 7u + uid * 13u + (uint32_t)i);
}

static uint32_t msg_uid(const char *b) { return (uint32_t)(uint8_t)b[2] | (uint32_t)(uint8_t)b[3] << 8; }

static int check(const char *b, int len, int sid)
{
    int i;
    uint32_t idx, uid;
    if (len < HDR || b[0] != 'C' || (int)get32(b + 12) != sid) return -1;
    idx = get32(b + 4);
    uid = msg_uid(b);
    for (i = HDR; i < len; i++) if (b[i] != (char)((uint32_t)sid * 31u + idx * 7u + uid * 13u + (uint32_t)i)) return -1;
    return 0;
}

static void udp_out(char tag, const char *buf, int len)
{
    char out[2048];
    if (!g_peerlen || len + 1 > (int)sizeof(out)) return;
    out[0] = tag;
    memcpy(out + 1, buf, (size_t)len);
    if (sendto(g_fd, out, (size_t)len + 1, 0, (struct sockaddr *)&g_peer, g_peerlen) > 0) c_tx++;
    else c_output_err++;
}

static int anl_out(char *buf, int len, anl_t *w, void *user) { (void)w; (void)user; udp_out('A', buf, len); return 0; }

static int accept_cb(anl_t *w, anl_stream_t *s, anl_stream_opt *opt, void *user)
{
    lst *l;
    (void)w; (void)user; (void)opt;
    if (g_nacc == (int)(sizeof(g_acc) / sizeof(g_acc[0])) || (l = calloc(1, sizeof(*l))) == NULL) return -1;
    l->s = s;
    l->sid = anl_stream_id(s);
    l->semi = opt->mode == ANL_SEMI;
    l->plan = -1;
    anl_stream_set_user(s, l);
    g_acc[g_nacc++] = l;
    c_acc++;
    return 0;
}

/* own sids closed here, not confirmed: they still count against our budget */
static uint32_t own_closing(void)
{
    uint32_t i, n = 0;
    for (i = 0; i < g_w->nclos; i++)
        if ((g_w->clos[i].sid & 1) == (g_server ? 1u : 0u)) n++;
    return n;
}

static void track_close(anl_stream_t *s, int by_acceptor, uint32_t now)
{
    int sid = anl_stream_id(s), was_over = s->state == ANL_STREAM_CLOSED;
    anl_stream_close(s);
    if (was_over) {                     /* over already: nothing to tell */
        if (clos_find(g_w, sid) >= 0) c_close_rec_bad++;
        c_close_norec++;
        return;
    }
    if (clos_find(g_w, sid) < 0) {      /* a close that tells the peer keeps a record */
        if (anl_state(g_w) >= 0) c_close_rec_bad++;
        return;
    }
    c_close_rec++;
    if (g_npend < (int)(sizeof(g_pend) / sizeof(g_pend[0]))) {
        g_pend[g_npend].sid = sid; g_pend[g_npend].t = now; g_pend[g_npend].by_acceptor = by_acceptor;
        g_npend++;
    } else c_lost_pend++;
}

static void poll_confirm(uint32_t now)
{
    int i;
    for (i = 0; i < g_npend; ) {
        if (clos_find(g_w, g_pend[i].sid) >= 0) { i++; continue; }
        if (g_nlat[g_pend[i].by_acceptor] < MAX_LAT) g_lat[g_pend[i].by_acceptor][g_nlat[g_pend[i].by_acceptor]++] = now - g_pend[i].t;
        g_pend[i] = g_pend[--g_npend];
    }
    if (g_w->nclos > c_max_clos) c_max_clos = g_w->nclos;
    if (g_w->nstab > c_max_stab) c_max_stab = g_w->nstab;
}

static void own_remove(int i) { free(g_own[i]); g_own[i] = g_own[--g_nown]; }

static void open_one(uint32_t now)
{
    anl_stream_opt o;
    int err = 0, plan, r = (int)rnd_in(0, 99), acc = 0;
    lst *l;
    for (plan = 0; plan < NPLAN; plan++) { acc += plan_weight[plan]; if (r < acc) break; }
    l = calloc(1, sizeof(*l));
    if (!l) return;
    l->own = 1;
    l->plan = plan;
    l->semi = plan == P_SEMI || (plan == P_PEER && (rnd() & 1));
    anl_stream_opt_default(&o, l->semi ? ANL_SEMI : ANL_RELIABLE);
    o.fec = 0;
    o.tag = plan;
    l->s = anl_stream_open(g_w, &o, &err);
    if (!l->s) {
        if (err == ANL_EBUSY) c_ebusy++; else c_open_fail++;
        free(l);
        return;
    }
    l->sid = anl_stream_id(l->s);
    l->uid = (uint32_t)c_open & 0xffff;
    if ((uint32_t)l->sid > c_max_sid) c_max_sid = (uint32_t)l->sid;
    l->t_open = now;
    l->t_next = now;
    switch (plan) {
    case P_GRACEFUL: l->total = rnd_in(5, 60); break;
    case P_SEMI: case P_ABRUPT: l->t_end = now + rnd_in(200, 4000); break;
    case P_PEER: case P_BOTH: l->total = rnd_in(5, 60); break;
    default: l->total = 1; break;
    }
    g_own[g_nown++] = l;
    c_open++; c_open_plan[plan]++;
}

/* one message / frame of an own stream; < 0: the stream is over (closed by the peer) */
static int own_send(lst *l)
{
    char b[MSG_LEN];
    int len = l->semi ? FRAME_LEN : MSG_LEN, r;
    fill(b, len, l->plan, l->sent, l->total, l->sid, l->uid);
    if (l->semi) r = anl_stream_send_frame(l->s, l->sent % 20 == 0 ? ANL_FRAME_KEY : 0, b, len, NULL);
    else r = anl_stream_send(l->s, b, len);
    if (r == ANL_ECLOSED) return -1;
    l->sent++;
    return 0;
}

static void own_step(uint32_t now, int draining)
{
    int i;
    for (i = 0; i < g_nown; ) {
        lst *l = g_own[i];
        int over = l->s->state == ANL_STREAM_CLOSED, done = 0;
        if (over && l->plan != P_PEER && l->plan != P_BOTH && l->plan != P_INSTANT) {
            /* reset with no close of the acceptor in the plan: a refused open */
            c_refused++;
            fprintf(stderr, "refused: sid %d plan %s after %u ms\n", l->sid, plan_name[l->plan], now - l->t_open);
            track_close(l->s, 0, now);
            own_remove(i);
            continue;
        }
        switch (l->plan) {
        case P_GRACEFUL:
            if (l->sent < l->total && tdiff(now, l->t_next) >= 0) { own_send(l); l->t_next += SEND_MS; }
            if (l->sent == l->total && anl_stream_waitsnd(l->s) == 0) done = 1;
            break;
        case P_SEMI: case P_ABRUPT:
            if (tdiff(now, l->t_next) >= 0) { own_send(l); l->t_next += SEND_MS; }
            if (tdiff(now, l->t_end) >= 0 || draining) done = 1;
            break;
        case P_PEER:
            if (over) { c_over_closed++; done = 1; break; }
            if (tdiff(now, l->t_next) >= 0) {
                if (own_send(l) < 0) { c_over_closed++; done = 1; break; }
                l->t_next += SEND_MS;
            }
            if (now - l->t_open > 60000) { c_peer_never++; done = 1; }
            else if (draining && now - l->t_open > 20000) done = 1;
            break;
        case P_BOTH:
            if (over) { c_over_closed++; done = 1; break; }
            if (l->sent < l->total && tdiff(now, l->t_next) >= 0) { own_send(l); l->t_next += SEND_MS; }
            if (l->sent == l->total && anl_stream_waitsnd(l->s) == 0) done = 1;
            break;
        default:
            own_send(l);
            done = 1;
            break;
        }
        if (done) { track_close(l->s, 0, now); own_remove(i); continue; }
        i++;
    }
}

static void acc_remove(lst *l)
{
    int i;
    for (i = 0; i < g_nacc; i++) if (g_acc[i] == l) { g_acc[i] = g_acc[--g_nacc]; break; }
    free(l);
}

/* read an accepted stream; the plan's close of the acceptor, or the end of a
   stream the opener closed */
static void acc_read(lst *l, uint32_t now)
{
    static char b[65536];
    anl_frame_info fi;
    int r;
    for (;;) {
        uint32_t idx;
        r = l->semi ? anl_stream_recv_frame(l->s, b, sizeof(b), &fi) : anl_stream_recv(l->s, b, sizeof(b));
        if (r <= 0) break;
        c_items++; c_bytes += (uint64_t)r;
        if (check(b, r, l->sid) < 0) { c_pattern_err++; continue; }
        idx = get32(b + 4);
        if (!l->plan_known) { l->plan = b[1]; l->total = get32(b + 8); l->uid = msg_uid(b); l->plan_known = 1; }
        else if (msg_uid(b) != l->uid) { c_gen_err++; continue; }   /* an earlier stream's message on this sid */
        if (l->semi ? idx < l->got : idx != l->got) c_order_err++;
        l->got = idx + 1;
        if ((l->plan == P_PEER && l->got >= l->total) || (l->plan == P_BOTH && idx + 1 == l->total)) {
            c_acc_close++;
            track_close(l->s, 1, now);
            acc_remove(l);
            return;
        }
    }
    if (r == ANL_ECLOSED) {
        int p = l->plan_known ? l->plan : P_INSTANT;
        c_acc_over++;
        if (p >= 0 && p < NPLAN) c_acc_over_plan[p]++;
        if (p == P_GRACEFUL) { if (l->got == l->total) c_graceful_ok++; else c_graceful_short++; }
        track_close(l->s, 1, now);
        acc_remove(l);
    }
}

static void acc_step(uint32_t now)
{
    anl_stream_t *list[128];
    int n = anl_readable(g_w, list, 128), i;
    for (i = 0; i < n && i < 128; i++) {
        lst *l = anl_stream_get_user(list[i]);
        if (list[i] == anl_default_stream(g_w) || l == NULL || l->own) continue;
        acc_read(l, now);
    }
}

static int cmp32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static void report_lat(const char *who, uint32_t *v, int n)
{
    if (n == 0) { printf("CHURN_CONFIRM by=%s n=0\n", who); return; }
    qsort(v, (size_t)n, sizeof(uint32_t), cmp32);
    printf("CHURN_CONFIRM by=%s n=%d p50_ms=%u p90_ms=%u p99_ms=%u p999_ms=%u max_ms=%u\n", who, n, v[n / 2],
           v[(n - 1) * 90 / 100], v[(n - 1) * 99 / 100], v[(int)((n - 1) * 999LL / 1000)], v[n - 1]);
}

/* the connection starts at the hello: created earlier, the server's idle
   timeout ran while the launcher was still starting the client */
static void conn_create(uint32_t now)
{
    anl_config cfg;
    anl_config_default(&cfg, g_server ? ANL_ROLE_SERVER : ANL_ROLE_CLIENT);
    memset(cfg.psk, 0x5c, sizeof(cfg.psk));
    cfg.mtu = MTU;
    cfg.keepalive_ms = 1000;                /* the server's idle timeout outlasts the quiet end */
    g_w = anl_create(0x5c5c0001, &cfg, NULL);
    anl_setoutput(g_w, anl_out);
    anl_set_accept(g_w, accept_cb);
    anl_update(g_w, now);
}

static int run(void)
{
    uint32_t last = 0, t_hello = 0, now, t_check = 0;
    int checked = 0, ok = 0, own_left = 0;
    for (;;) {
        struct pollfd pfd = { g_fd, POLLIN, 0 };
        char buf[2048];
        poll(&pfd, 1, 1);
        now = now_ms();
        for (;;) {
            struct sockaddr_storage from;
            socklen_t fl = sizeof(from);
            ssize_t r = recvfrom(g_fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
            if (r <= 0) break;
            if (buf[0] == 'H') {
                if (g_server) {
                    memcpy(&g_peer, &from, fl); g_peerlen = fl;
                    udp_out('H', "", 0);
                }
                if (!g_connected) { conn_create(now); g_connected = 1; g_t0 = now; printf("CONNECTED t=%u\n", now); fflush(stdout); }
            } else if (buf[0] == 'A' && g_connected) {
                int ir;
                c_rx++;
                /* a datagram the path duplicated is taken once: ANL_EREPLAY is no error */
                if ((ir = anl_input(g_w, buf + 1, (long)r - 1)) == ANL_EREPLAY) c_replay++;
                else if (ir < 0) c_input_err++;
            }
        }
        if (!g_connected) {
            if (!g_server && now - t_hello >= 200) { udp_out('H', "", 0); t_hello = now; }
            continue;
        }
        if (now != last) { anl_update(g_w, now); last = now; }
        if (anl_state(g_w) < 0) { printf("DEAD at %u ms\n", now - g_t0); break; }
        {
            uint32_t el = now - g_t0;
            int churn = el < g_dur * 1000, draining = !churn;
            acc_step(now);
            if (churn)
                while ((uint32_t)g_nown + own_closing() < g_conc) {
                    uint64_t before = c_ebusy + c_open_fail;
                    open_one(now);
                    if (c_ebusy + c_open_fail != before) break;
                }
            own_step(now, draining);
            poll_confirm(now);
            if (!checked && el >= (g_dur + DRAIN_S) * 1000) {
                anl_stats st;
                anl_get_stats(g_w, &st);
                checked = 1; t_check = now;
                own_left = g_nown;
                ok = g_nown == 0 && g_nacc == 0 && st.streams == 1 && st.streams_closing == 0 && g_npend == 0;
                printf("CHURN_FINAL own_open=%d acc_open=%d streams=%u closing=%u pending=%d srtt=%u rto=%u ok=%d\n",
                       g_nown, g_nacc, st.streams, st.streams_closing, g_npend, st.srtt, st.rto, ok);
                fflush(stdout);
            }
            if (checked && now - t_check >= LINGER_S * 1000) break;
        }
    }
    (void)own_left;
    return ok;
}

int main(int argc, char **argv)
{
    const char *host = NULL;
    int port = 9850, i, ok, errors;
    struct sockaddr_in6 a6;
    if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        fprintf(stderr, "usage: churn server|client [--host H] [--port P] [--dur S] [--conc N] [--seed N]\n");
        return 2;
    }
    g_server = !strcmp(argv[1], "server");
    for (i = 2; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--host")) host = argv[i + 1];
        else if (!strcmp(argv[i], "--port")) port = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--dur")) g_dur = (uint32_t)atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--conc")) g_conc = (uint32_t)atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--seed")) g_seed = (uint32_t)atoi(argv[i + 1]);
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
    }
    if (g_conc < 1 || g_conc > 31 || g_dur < 1 || (!g_server && !host)) { fprintf(stderr, "bad options\n"); return 2; }
    g_rng = 0x9E3779B97F4A7C15ULL * (g_seed * 2u + (unsigned)g_server + 1);
    g_lat[0] = malloc(MAX_LAT * sizeof(uint32_t));
    g_lat[1] = malloc(MAX_LAT * sizeof(uint32_t));

    g_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    { int off = 0; setsockopt(g_fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)); }
    { int sz = 4 << 20; setsockopt(g_fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz)); setsockopt(g_fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz)); }
    memset(&a6, 0, sizeof(a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons((uint16_t)(g_server ? port : 0));
    a6.sin6_addr = in6addr_any;
    if (bind(g_fd, (struct sockaddr *)&a6, sizeof(a6)) < 0) { perror("bind"); return 1; }
    if (!g_server) {
        struct addrinfo hints, *res;
        char ps[16];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6; hints.ai_socktype = SOCK_DGRAM; hints.ai_flags = AI_V4MAPPED | AI_ALL;
        snprintf(ps, sizeof(ps), "%d", port);
        if (getaddrinfo(host, ps, &hints, &res) != 0) { fprintf(stderr, "cannot resolve %s\n", host); return 1; }
        memcpy(&g_peer, res->ai_addr, res->ai_addrlen); g_peerlen = res->ai_addrlen;
        freeaddrinfo(res);
    }

    printf("CHURN_CONFIG role=%s dur=%u conc=%u seed=%u\n", g_server ? "server" : "client", g_dur, g_conc, g_seed);
    printf("WORKLOAD_READY\n");
    fflush(stdout);

    ok = run();
    if (g_w == NULL) { printf("HEALTH state=-1 errors=1 ok=0\n"); return 1; }

    {
        anl_stats st;
        anl_get_stats(g_w, &st);
        printf("CHURN_OPEN opened=%llu ebusy=%llu open_fail=%llu refused=%llu max_streams=%u max_closing=%u max_sid=%u",
               (unsigned long long)c_open, (unsigned long long)c_ebusy, (unsigned long long)c_open_fail,
               (unsigned long long)c_refused, c_max_stab, c_max_clos, c_max_sid);
        for (i = 0; i < NPLAN; i++) printf(" %s=%llu", plan_name[i], (unsigned long long)c_open_plan[i]);
        printf("\nCHURN_CLOSE told=%llu not_told=%llu record_errors=%llu untracked=%llu peer_closed_seen_by_opener=%llu peer_never_closed=%llu\n",
               (unsigned long long)c_close_rec, (unsigned long long)c_close_norec, (unsigned long long)c_close_rec_bad,
               (unsigned long long)c_lost_pend, (unsigned long long)c_over_closed, (unsigned long long)c_peer_never);
        report_lat("opener", g_lat[0], g_nlat[0]);
        report_lat("acceptor", g_lat[1], g_nlat[1]);
        printf("CHURN_READ accepted=%llu over=%llu closed_by_acceptor=%llu items=%llu bytes=%llu graceful_ok=%llu graceful_short=%llu order_errors=%llu pattern_errors=%llu gen_errors=%llu",
               (unsigned long long)c_acc, (unsigned long long)c_acc_over, (unsigned long long)c_acc_close,
               (unsigned long long)c_items, (unsigned long long)c_bytes, (unsigned long long)c_graceful_ok,
               (unsigned long long)c_graceful_short, (unsigned long long)c_order_err, (unsigned long long)c_pattern_err,
               (unsigned long long)c_gen_err);
        for (i = 0; i < NPLAN; i++) printf(" over_%s=%llu", plan_name[i], (unsigned long long)c_acc_over_plan[i]);
        printf("\nCHURN_NET tx=%llu rx=%llu replays=%llu input_errors=%llu output_errors=%llu srtt=%u rto=%u retrans=%u state=%d\n",
               (unsigned long long)c_tx, (unsigned long long)c_rx, (unsigned long long)c_replay, (unsigned long long)c_input_err,
               (unsigned long long)c_output_err, st.srtt, st.rto, st.retrans, anl_state(g_w));
        errors = (int)(c_refused + c_open_fail + c_close_rec_bad + c_lost_pend + c_peer_never + c_graceful_short +
                       c_order_err + c_pattern_err + c_gen_err + c_input_err + c_output_err) + (anl_state(g_w) < 0);
        printf("HEALTH state=%d errors=%d ok=%d\n", anl_state(g_w), errors, ok);
    }
    return errors == 0 && ok ? 0 : 1;
}
