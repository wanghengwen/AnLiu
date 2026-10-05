/* srtnet: the realnet media workload (frame_v1) over SRT live mode, for a
 * side-by-side comparison with AnLiu on the same path at the same time.
 *
 *   srtnet server --port P --dur S --seed N            (sender: listens)
 *   srtnet client --host H --port P --lat-audio MS --lat-video MS [--fec CFG]
 *
 * Audio (flow 1: 160 B every 20 ms) and video (flow 2: 30 fps, GOP 30, key
 * frames 25..35 KB, others 2.5..3.5 KB; sizes from the same seed hash as
 * realnet, scale 1000) go over two SRT connections on the sender's one UDP
 * port, so one tc band shapes both. The receiver sets the latency of each
 * connection (SRTO_LATENCY: the larger of both sides wins; the sender asks
 * for 20 ms) and the packet filter (FEC) if any. Everything else is the
 * library default (live mode, TLPKTDROP on, MAXBW -1, payload 1316).
 *
 * A frame goes out as messages of at most 1316 bytes, each with a 24-byte
 * header (flow, key, chunk, chunks, seq, frame length, send time); the
 * receiver counts a frame complete when all its chunks arrived and logs
 *   SRTR flow seq key len send_wall_us done_wall_us
 * (CLOCK_REALTIME on both hosts). The sender logs
 *   SRTS flow seq key len send_wall_us rc
 * and both log SRTSTAT lines (srt_bstats) per connection at the end.
 */
#include <srt/srt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define CHUNK   1316
#define CHDR    24
#define MAXSEQ  40000

static uint64_t wall_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}
static uint64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000;
}

/* realnet media_frame_size_raw: a stable size for each (seed, flow, sequence) */
static uint64_t g_seed;
static int frame_size(int id, uint32_t seq, int key)
{
    int a, b;
    uint64_t x;
    if (id == 1) return 160;
    a = key ? 25000 : 2500; b = key ? 35000 : 3500;
    x = g_seed + ((uint64_t)seq + 1) * 0x9e3779b97f4a7c15ull + (uint64_t)id * 0xd1b54a32d192ed03ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    x ^= x >> 31;
    return a + (int)(x % (uint32_t)(b - a + 1));
}

static void die(const char *what)
{
    fprintf(stderr, "ERROR %s: %s\n", what, srt_getlasterror_str());
    printf("HEALTH state=1 %s\n", what);
    exit(1);
}

/* the last statistics of each connection: the receiver's sockets are gone
   once the sender closes, so they are snapshotted while connected */
static SRT_TRACEBSTATS g_st[3];
static int g_st_ok[3], g_lat[3];
static char g_pf[3][512];
static void snap(int i, SRTSOCKET s)
{
    SRT_TRACEBSTATS st;
    int len = sizeof(g_lat[i]), pfl = sizeof(g_pf[i]);
    if (srt_getsockstate(s) != SRTS_CONNECTED || srt_bstats(s, &st, 0) != 0) return;
    g_st[i] = st; g_st_ok[i] = 1;
    srt_getsockflag(s, SRTO_LATENCY, &g_lat[i], &len);
    srt_getsockflag(s, SRTO_PACKETFILTER, g_pf[i], &pfl);
}
static void stats(const char *role, const char *name, int i)
{
    SRT_TRACEBSTATS st = g_st[i];
    int lat = g_lat[i];
    const char *pf = g_pf[i];
    if (!g_st_ok[i]) { printf("SRTSTAT %s %s unavailable\n", role, name); return; }
    printf("SRTSTAT %s %s latency_ms=%d filter=%s rtt_ms=%.1f pkt_sent=%lld pkt_sent_unique=%lld pkt_retrans=%d"
           " pkt_snd_drop=%d byte_sent=%llu byte_sent_unique=%llu byte_retrans=%llu pkt_snd_filter_extra=%d"
           " pkt_recv=%lld pkt_recv_unique=%lld pkt_rcv_loss=%d pkt_rcv_drop=%d pkt_rcv_belated=%lld"
           " pkt_rcv_filter_extra=%d pkt_rcv_filter_supply=%d pkt_rcv_filter_loss=%d byte_recv=%llu\n",
           role, name, lat, pf[0] ? pf : "none", st.msRTT, (long long)st.pktSentTotal, (long long)st.pktSentUniqueTotal,
           st.pktRetransTotal, st.pktSndDropTotal, (unsigned long long)st.byteSentTotal,
           (unsigned long long)st.byteSentUniqueTotal, (unsigned long long)st.byteRetransTotal, st.pktSndFilterExtraTotal,
           (long long)st.pktRecvTotal, (long long)st.pktRecvUniqueTotal, st.pktRcvLossTotal, st.pktRcvDropTotal,
           (long long)st.pktRcvBelated, st.pktRcvFilterExtraTotal, st.pktRcvFilterSupplyTotal,
           st.pktRcvFilterLossTotal, (unsigned long long)st.byteRecvTotal);
}

static int send_frame(SRTSOCKET s, int id, int key, uint32_t seq, int len, uint64_t t)
{
    static char buf[CHUNK];
    int n = (len + (CHUNK - CHDR) - 1) / (CHUNK - CHDR), i, off = 0, rc = 0;
    for (i = 0; i < n; i++) {
        int pl = len - off < CHUNK - CHDR ? len - off : CHUNK - CHDR;
        uint16_t c = (uint16_t)i, cn = (uint16_t)n;
        uint32_t fl = (uint32_t)len;
        buf[0] = (char)id; buf[1] = (char)key;
        memcpy(buf + 2, &c, 2); memcpy(buf + 4, &cn, 2); buf[6] = buf[7] = 0;
        memcpy(buf + 8, &seq, 4); memcpy(buf + 12, &fl, 4); memcpy(buf + 16, &t, 8);
        memset(buf + CHDR, (int)(seq & 0xff), (size_t)pl);
        if (srt_sendmsg(s, buf, CHDR + pl, -1, 0) == SRT_ERROR) rc = -1;
        off += pl;
    }
    return rc;
}

static int server(int port, int dur)
{
    SRTSOCKET l = srt_create_socket(), s[3] = { SRT_INVALID_SOCK, SRT_INVALID_SOCK, SRT_INVALID_SOCK };
    struct sockaddr_in sa;
    int lat = 20, yes = 1, i, got = 0;
    uint64_t t0, end, next[3];
    uint32_t seq[3] = { 0, 0, 0 };
    if (l == SRT_INVALID_SOCK) die("socket");
    srt_setsockflag(l, SRTO_LATENCY, &lat, sizeof(lat));
    srt_setsockflag(l, SRTO_REUSEADDR, &yes, sizeof(yes));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = INADDR_ANY;
    if (srt_bind(l, (struct sockaddr *)&sa, sizeof(sa)) == SRT_ERROR) die("bind");
    if (srt_listen(l, 4) == SRT_ERROR) die("listen");
    printf("WORKLOAD_READY proto=srt port=%d\n", port);
    fflush(stdout);
    while (got < 2) {
        struct sockaddr_storage peer; int pl = sizeof(peer);
        char sid[64] = ""; int sl = sizeof(sid);
        SRTSOCKET a = srt_accept(l, (struct sockaddr *)&peer, &pl);
        if (a == SRT_INVALID_SOCK) die("accept");
        srt_getsockflag(a, SRTO_STREAMID, sid, &sl);
        i = !strcmp(sid, "audio") ? 1 : !strcmp(sid, "video") ? 2 : 0;
        if (i == 0 || s[i] != SRT_INVALID_SOCK) { srt_close(a); continue; }
        s[i] = a; got++;
    }
    t0 = mono_us(); end = t0 + (uint64_t)dur * 1000000u;
    printf("TIMEBASE event=traffic_start wall_us=%llu\n", (unsigned long long)wall_us());
    next[1] = next[2] = t0;
    for (;;) {
        uint64_t t = mono_us();
        int any = 0;
        for (i = 1; i <= 2; i++) {
            while (t >= next[i] && next[i] < end) {
                int key = i == 2 && seq[i] % 30 == 0, len = frame_size(i, seq[i], key), rc;
                uint64_t w = wall_us();
                rc = send_frame(s[i], i, key, seq[i], len, w);
                printf("SRTS %d %u %d %d %llu %d\n", i, seq[i], key, len, (unsigned long long)w, rc);
                seq[i]++;
                next[i] = i == 1 ? t0 + (uint64_t)seq[i] * 20000u : t0 + (uint64_t)seq[i] * 1000000u / 30u;
            }
            any |= next[i] < end;
        }
        if (!any) break;
        usleep(1000);
    }
    sleep(3);                       /* the last frames, retransmissions */
    snap(1, s[1]); snap(2, s[2]);
    stats("snd", "audio", 1); stats("snd", "video", 2);
    printf("HEALTH state=0 sent_audio=%u sent_video=%u\n", seq[1], seq[2]);
    fflush(stdout);
    srt_close(s[1]); srt_close(s[2]); srt_close(l);
    return 0;
}

static unsigned char got_chunks[3][MAXSEQ];
static int client(const char *host, int port, int lat_a, int lat_v, const char *fec, int dur)
{
    SRTSOCKET s[3];
    int eid = srt_epoll_create(), i, lats[3] = { 0, lat_a, lat_v };
    struct sockaddr_in sa;
    static char buf[CHUNK + 64];
    uint64_t stop;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) die("host");
    for (i = 1; i <= 2; i++) {
        const char *sid = i == 1 ? "audio" : "video";
        int ev = SRT_EPOLL_IN | SRT_EPOLL_ERR, no = 0;
        s[i] = srt_create_socket();
        srt_setsockflag(s[i], SRTO_LATENCY, &lats[i], sizeof(lats[i]));
        srt_setsockflag(s[i], SRTO_STREAMID, sid, (int)strlen(sid));
        if (fec && *fec && srt_setsockflag(s[i], SRTO_PACKETFILTER, fec, (int)strlen(fec)) == SRT_ERROR) die("packetfilter");
        if (srt_connect(s[i], (struct sockaddr *)&sa, sizeof(sa)) == SRT_ERROR) die("connect");
        srt_setsockflag(s[i], SRTO_RCVSYN, &no, sizeof(no));
        srt_epoll_add_usock(eid, s[i], &ev);
    }
    printf("CONNECTED lat_audio=%d lat_video=%d fec=%s\n", lat_a, lat_v, fec && *fec ? fec : "none");
    fflush(stdout);
    stop = mono_us() + (uint64_t)(dur + 20) * 1000000u;
    {
    uint64_t next_snap = 0;
    while (mono_us() < stop) {
        if (mono_us() >= next_snap) { snap(1, s[1]); snap(2, s[2]); next_snap = mono_us() + 500000u; }
        SRTSOCKET rd[2]; int rn = 2, k;
        int n = srt_epoll_wait(eid, rd, &rn, NULL, NULL, 500, NULL, NULL, NULL, NULL);
        if (n < 0) {
            if (srt_getlasterror(NULL) == SRT_ETIMEOUT) continue;
            break;
        }
        for (k = 0; k < rn; k++) {
            int r;
            if (srt_getsockstate(rd[k]) > SRTS_CONNECTED) { stop = 0; break; }
            while ((r = srt_recvmsg(rd[k], buf, sizeof(buf))) > 0) {
                uint16_t c, cn; uint32_t seq, fl; uint64_t t; int id = buf[0], key = buf[1];
                if (r < CHDR || id < 1 || id > 2) continue;
                memcpy(&c, buf + 2, 2); memcpy(&cn, buf + 4, 2);
                memcpy(&seq, buf + 8, 4); memcpy(&fl, buf + 12, 4); memcpy(&t, buf + 16, 8);
                (void)c;
                if (seq >= MAXSEQ) continue;
                if (++got_chunks[id][seq] == cn)
                    printf("SRTR %d %u %d %u %llu %llu\n", id, seq, key, fl, (unsigned long long)t, (unsigned long long)wall_us());
            }
        }
    }
    }
    stats("rcv", "audio", 1); stats("rcv", "video", 2);
    printf("HEALTH state=0\n");
    fflush(stdout);
    srt_close(s[1]); srt_close(s[2]);
    return 0;
}

int main(int argc, char **argv)
{
    const char *role = argc > 1 ? argv[1] : "", *host = "127.0.0.1", *fec = "";
    int port = 9950, dur = 600, lat_a = 150, lat_v = 300, i, rc;
    for (i = 2; i + 1 < argc; i += 2) {
        if (!strcmp(argv[i], "--port")) port = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--host")) host = argv[i + 1];
        else if (!strcmp(argv[i], "--dur")) dur = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--seed")) g_seed = (uint64_t)atoll(argv[i + 1]);
        else if (!strcmp(argv[i], "--lat-audio")) lat_a = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--lat-video")) lat_v = atoi(argv[i + 1]);
        else if (!strcmp(argv[i], "--fec")) fec = argv[i + 1];
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
    }
    setvbuf(stdout, NULL, _IOFBF, 1 << 20);
    srt_startup();
    printf("SRTNET role=%s port=%d dur=%d seed=%llu srt=%s\n", role, port, dur, (unsigned long long)g_seed, SRT_VERSION_STRING);
    if (!strcmp(role, "server")) rc = server(port, dur);
    else if (!strcmp(role, "client")) rc = client(host, port, lat_a, lat_v, fec, dur);
    else { fprintf(stderr, "usage: srtnet server|client ...\n"); rc = 2; }
    srt_cleanup();
    return rc;
}
