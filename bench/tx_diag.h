/* Optional realnet sender diagnostics; include after anliu.c. No protocol state
 * is changed. Times are sample-held protocol-clock durations, not CPU time.
 * Reasons overlap: a queued stream can lack both a window and pacing credit.
 * The host calls observe after update/input/send; flushes also refresh it. */
typedef struct {
    int enabled, seen;
    const anl_t *owner; /* NULL: the single realnet connection; set for simulation */
    uint32_t last, mask;
    uint64_t elapsed, empty_ms, window_ms, cwnd_ms, pace_ms, ready_ms;
    uint64_t earned, clipped, spent, control, refill_ms, refill_n, flush_n, capped_n;
    uint64_t retrans_seg_bytes;
    int64_t min_budget, max_budget;
} tx_diag;
static tx_diag g_tx_diag;

/* a stream holds unsent data (the library's flush no longer needs this walk) */
static int has_queued_data(const anl_t *w)
{
    anl_node *n, *nx;
    anl_stream *st;
    FOR_EACH_STREAM(w, st, n, nx) {
        if (stream_sendable(st) && st->nsnd_que > 0) return 1;
    }
    return 0;
}

enum { TX_EMPTY = 1, TX_WINDOW = 2, TX_CWND = 4, TX_PACE = 8, TX_READY = 16 };

static void tx_diag_observe(tx_diag *d, const anl_t *w)
{
    uint32_t mask = 0;
    int queued, sendable;
    if (!d->enabled || !w || !w->updated || (d->owner && d->owner != w)) return;
    if (d->seen) {
        int32_t dt = tdiff(w->current, d->last);
        if (dt > 0) {
            d->elapsed += (uint32_t)dt;
            if (d->mask & TX_EMPTY) d->empty_ms += (uint32_t)dt;
            if (d->mask & TX_WINDOW) d->window_ms += (uint32_t)dt;
            if (d->mask & TX_CWND) d->cwnd_ms += (uint32_t)dt;
            if (d->mask & TX_PACE) d->pace_ms += (uint32_t)dt;
            if (d->mask & TX_READY) d->ready_ms += (uint32_t)dt;
        }
    }
    d->last = w->current; d->seen = 1;
    queued = has_queued_data(w); sendable = has_new_data(w);
    if (!queued) mask |= TX_EMPTY;
    if (queued && !sendable) mask |= TX_WINDOW;
    if (sendable && w->inflight_segs >= w->cwnd) mask |= TX_CWND;
    if (queued && !pace_can_send(w)) mask |= TX_PACE;
    if (sendable && w->inflight_segs < w->cwnd && pace_can_send(w)) mask |= TX_READY;
    d->mask = mask;
}

static void trace_pace_refill(const anl_t *w, uint32_t dt, uint64_t earned, uint64_t clipped)
{
    tx_diag *d = &g_tx_diag;
    if (!d->enabled || (d->owner && d->owner != w)) return;
    (void)w;
    d->earned += earned; d->clipped += clipped;
    d->refill_ms += dt; d->refill_n++;
}

static void trace_tx_output(const anl_t *w, uint32_t bytes, int paced)
{
    (void)w;
    if (!g_tx_diag.enabled || (g_tx_diag.owner && g_tx_diag.owner != w)) return;
    if (paced) g_tx_diag.spent += bytes;
    else g_tx_diag.control += bytes;
}

static void trace_flush(const anl_t *w, int64_t budget, int64_t retrans_bytes, int capped)
{
    tx_diag *d = &g_tx_diag;
    if (!d->enabled || (d->owner && d->owner != w)) return;
    if (!d->flush_n || budget < d->min_budget) d->min_budget = budget;
    if (!d->flush_n || budget > d->max_budget) d->max_budget = budget;
    d->flush_n++; d->capped_n += capped != 0;
    d->retrans_seg_bytes += (uint64_t)retrans_bytes;
    tx_diag_observe(d, w);
}

/* Cumulative counters at exact detector boundaries. Difference consecutive
 * lt_begin / lt_end records; a new begin without an end discards a transition.
 * lt_ts uses current|1 in the protocol, so prefer now for elapsed accounting. */
static void tx_diag_print(const anl_t *w, const char *stage)
{
    tx_diag *d = &g_tx_diag;
    if (!d->enabled || (d->owner && d->owner != w)) return;
    tx_diag_observe(d, w);
    fprintf(stderr, "TXDIAG now=%u stage=%s lt_ts=%u lt=%d k=%u elapsed_ms=%llu"
            " newq_empty_ms=%llu all_window_ms=%llu cwnd_ms=%llu pace_ms=%llu ready_ms=%llu"
            " earned=%llu clipped=%llu spent=%llu control=%llu tokens=%lld refill_ms=%llu refill_n=%llu"
            " flush_n=%llu rtx_cap_n=%llu retrans_seg_bytes=%llu budget_min=%lld budget_max=%lld\n",
            w->current, stage, w->lt_ts, w->lt_state, w->lt_k,
            (unsigned long long)d->elapsed, (unsigned long long)d->empty_ms,
            (unsigned long long)d->window_ms, (unsigned long long)d->cwnd_ms,
            (unsigned long long)d->pace_ms, (unsigned long long)d->ready_ms,
            (unsigned long long)d->earned, (unsigned long long)d->clipped,
            (unsigned long long)d->spent, (unsigned long long)d->control,
            (long long)w->pace_tokens, (unsigned long long)d->refill_ms,
            (unsigned long long)d->refill_n, (unsigned long long)d->flush_n,
            (unsigned long long)d->capped_n, (unsigned long long)d->retrans_seg_bytes,
            (long long)d->min_budget, (long long)d->max_budget);
}

static void trace_lt_begin(const anl_t *w) { tx_diag_print(w, "lt_begin"); }
