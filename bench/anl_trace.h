/* anl_trace.h - the library's internal trace points, for the bench tools.
 *
 * anliu.c calls ANL_TRACE(kind, args...) at the points below and defines it
 * as nothing unless the file including it defined it first. A tool defines
 * ANL_TRACE_<kind> for the kinds it wants, includes this header (which makes
 * the other kinds no-ops and routes ANL_TRACE to them), then ../anliu.c.
 *
 *   dead(w, reason, sid, sn, xmit, enqueued, last_sent)  the connection is declared dead
 *   tx_output(w, bytes, has_data)                         a datagram went out
 *   seg_commit(w, bytes, is_data)                         a segment was packed
 *   data_seg(w, st, seg, bytes, first)                    ... a DATA segment (first: its first transmission)
 *   parity_seg(w, sid, bytes)                             ... a PARITY segment
 *   pace_refill(w, dt, earned, clipped)                   pacing tokens earned over dt, clipped by the bucket
 *   dup(w, st, sn, recovered)                             a DATA segment arrived (recovered: rebuilt by FEC)
 *   policer_begin(w)                                      a policer-detection interval starts
 *   policer(w, dur, rate, loss, counted, after)           ... one ended: before / after the decision
 *   fec_block(w, st, k, m, lmax, key)                     a block of k closed with m parities
 *   fec_loss(w, sent, lost)                               first transmissions and losses counted
 *   fec_count(w, st, lost)                                adaptive ratio evidence (FEC_SENT / FEC_LOST / FEC_LATE)
 *   capacity(w, enter, leave)                             capacity_short entered / left
 *   rtx(w, st, seg, why)                                  a retransmission (why: 2 RTO, 3 RACK)
 *   flush(w, budget, retrans_bytes, capped)               a flush ended
 */
#ifndef ANL_TRACE_H
#define ANL_TRACE_H

#define ANL_TRACE(kind, ...) ANL_TRACE_##kind(__VA_ARGS__)

#ifndef ANL_TRACE_dead
#define ANL_TRACE_dead(...) ((void)0)
#endif
#ifndef ANL_TRACE_tx_output
#define ANL_TRACE_tx_output(...) ((void)0)
#endif
#ifndef ANL_TRACE_seg_commit
#define ANL_TRACE_seg_commit(...) ((void)0)
#endif
#ifndef ANL_TRACE_seg_trim
#define ANL_TRACE_seg_trim(...) ((void)0)
#endif
#ifndef ANL_TRACE_data_seg
#define ANL_TRACE_data_seg(...) ((void)0)
#endif
#ifndef ANL_TRACE_parity_seg
#define ANL_TRACE_parity_seg(...) ((void)0)
#endif
#ifndef ANL_TRACE_pace_refill
#define ANL_TRACE_pace_refill(...) ((void)0)
#endif
#ifndef ANL_TRACE_dup
#define ANL_TRACE_dup(...) ((void)0)
#endif
#ifndef ANL_TRACE_policer_begin
#define ANL_TRACE_policer_begin(...) ((void)0)
#endif
#ifndef ANL_TRACE_policer
#define ANL_TRACE_policer(...) ((void)0)
#endif
#ifndef ANL_TRACE_fec_block
#define ANL_TRACE_fec_block(...) ((void)0)
#endif
#ifndef ANL_TRACE_fec_loss
#define ANL_TRACE_fec_loss(...) ((void)0)
#endif
#ifndef ANL_TRACE_fec_count
#define ANL_TRACE_fec_count(...) ((void)0)
#endif
#ifndef ANL_TRACE_capacity
#define ANL_TRACE_capacity(...) ((void)0)
#endif
#ifndef ANL_TRACE_rtx
#define ANL_TRACE_rtx(...) ((void)0)
#endif
#ifndef ANL_TRACE_flush
#define ANL_TRACE_flush(...) ((void)0)
#endif

#endif /* ANL_TRACE_H */
