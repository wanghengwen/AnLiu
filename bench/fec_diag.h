/* Optional realnet byte accounting. Segment sizes are the actual encoded sizes;
 * datagram headers, authentication and padding are the remaining output bytes.
 * Counts are BEFORE the application's emulated loss/sendto, not NIC counters.
 * The four slots are realnet tags 1/2/3 and slot 0 for any other tag. */
typedef struct { uint64_t first, retry, parity; } fec_diag_bytes;
typedef struct {
    int enabled;
    const anl_t *owner;
    fec_diag_bytes pending[4], sent[4];
    uint64_t pending_control, control, overhead, output, datagrams;
    uint64_t blocks[4], data[4], parities[4], floor_blocks[4];
    uint64_t parity_output[4], parity_datagrams[4]; /* whole PARITY-only datagrams, including headers */
    uint64_t accounting_errors;
} fec_diag;
static fec_diag g_fec_diag;

static int fec_diag_active(const anl_t *w)
{
    return g_fec_diag.enabled && (!g_fec_diag.owner || g_fec_diag.owner == w);
}

static unsigned fec_diag_tag(const anl_stream *st)
{
    return st && st->tag >= 1 && st->tag <= 3 ? (unsigned)st->tag : 0;
}

static void trace_seg_commit(const anl_t *w, uint32_t bytes, int data)
{
    if (fec_diag_active(w) && !data) g_fec_diag.pending_control += bytes;
}

static void trace_data_seg(const anl_t *w, const anl_stream_t *st, uint32_t bytes, int first)
{
    fec_diag_bytes *p;
    if (!fec_diag_active(w)) return;
    p = &g_fec_diag.pending[fec_diag_tag(st)];
    if (first) p->first += bytes; else p->retry += bytes;
}

static void trace_parity_seg(const anl_t *w, int sid, uint32_t bytes)
{
    if (fec_diag_active(w)) g_fec_diag.pending[fec_diag_tag(sget(w, sid))].parity += bytes;
}

static void trace_fec_block(const anl_t *w, const anl_stream_t *st, uint32_t k, uint32_t m)
{
    unsigned tag;
    if (!fec_diag_active(w)) return;
    tag = fec_diag_tag(st);
    g_fec_diag.blocks[tag]++;
    g_fec_diag.data[tag] += k; g_fec_diag.parities[tag] += m;
    g_fec_diag.floor_blocks[tag] += st->fec_auto && m > (k * (uint32_t)st->fec_ratio + 50) / 100;
}

static void fec_diag_output(const anl_t *w, uint32_t bytes)
{
    fec_diag *d = &g_fec_diag;
    uint64_t segments;
    uint64_t parity = 0;
    int parity_tag = -1;
    unsigned i;
    if (!fec_diag_active(w)) return;
    segments = d->pending_control;
    d->control += d->pending_control; d->pending_control = 0;
    for (i = 0; i < 4; i++) {
        fec_diag_bytes *p = &d->pending[i], *s = &d->sent[i];
        segments += p->first + p->retry + p->parity;
        if (p->parity) { parity += p->parity; parity_tag = parity_tag == -1 ? (int)i : -2; }
        s->first += p->first; s->retry += p->retry; s->parity += p->parity;
        memset(p, 0, sizeof(*p));
    }
    d->output += bytes; d->datagrams++;
    /* fec_send_parity seals a datagram before and after each PARITY. Keep the
       condition explicit so a future mixed datagram is never charged twice. */
    if (parity && parity == segments && parity_tag >= 0) {
        d->parity_output[parity_tag] += bytes; d->parity_datagrams[parity_tag]++;
    }
    if (segments <= bytes) d->overhead += bytes - segments;
    else d->accounting_errors++;
}

static void fec_diag_print(const anl_t *w)
{
    const fec_diag *d = &g_fec_diag;
    uint64_t first = 0, retry = 0, parity = 0, pending = d->pending_control;
    uint64_t parity_output = 0, parity_datagrams = 0;
    unsigned i;
    if (!fec_diag_active(w)) return;
    for (i = 0; i < 4; i++) {
        const fec_diag_bytes *s = &d->sent[i], *p = &d->pending[i];
        first += s->first; retry += s->retry; parity += s->parity;
        parity_output += d->parity_output[i]; parity_datagrams += d->parity_datagrams[i];
        pending += p->first + p->retry + p->parity;
        if (!s->first && !s->retry && !s->parity && !d->blocks[i]) continue;
        printf("FECCOST tag=%u first_seg_bytes=%llu retrans_seg_bytes=%llu parity_seg_bytes=%llu"
               " parity_proto_bytes=%llu parity_datagrams=%llu blocks=%llu block_data=%llu block_parities=%llu floor_blocks=%llu\n", i,
               (unsigned long long)s->first, (unsigned long long)s->retry, (unsigned long long)s->parity,
               (unsigned long long)d->parity_output[i], (unsigned long long)d->parity_datagrams[i],
               (unsigned long long)d->blocks[i], (unsigned long long)d->data[i],
               (unsigned long long)d->parities[i], (unsigned long long)d->floor_blocks[i]);
    }
    printf("FECCOST total proto_bytes=%llu datagrams=%llu first_seg_bytes=%llu retrans_seg_bytes=%llu"
           " parity_seg_bytes=%llu control_seg_bytes=%llu overhead_bytes=%llu pending_seg_bytes=%llu errors=%llu"
           " parity_proto_bytes=%llu parity_datagrams=%llu\n",
           (unsigned long long)d->output, (unsigned long long)d->datagrams,
           (unsigned long long)first, (unsigned long long)retry, (unsigned long long)parity,
           (unsigned long long)d->control, (unsigned long long)d->overhead,
           (unsigned long long)pending, (unsigned long long)d->accounting_errors,
           (unsigned long long)parity_output, (unsigned long long)parity_datagrams);
}
