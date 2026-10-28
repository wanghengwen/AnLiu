/*
 * main.c - AnLiu test suite entry (DESIGN.md M6). The parts are included into this one
 * translation unit so that they share the harness and the library internals.
 *
 * Build:  gcc -std=c99 -Wall -Wextra -O1 -g -fsanitize=address,undefined testcases/main.c -o anl_test
 * Run:    ./anl_test
 */
#include "harness.h"
#include "kat_stream.c"
#include "protocol.c"
#include "lifecycle.c"
#include "priority_key.c"
#include "fec_report.c"
#include "bbr_policer.c"
#include "fec_capacity.c"
#include "rate_misc.c"

static int test_selected(const char *name, const char *only)
{
    const char *p = only;
    for (;;) {
        const char *q = strchr(p, '|');
        size_t n = q ? (size_t)(q - p) : strlen(p);
        if (n > 0 && n < 128) {
            char pat[128];
            memcpy(pat, p, n); pat[n] = 0;
            if (strstr(name, pat)) return 1;
        }
        if (!q) return 0;
        p = q + 1;
    }
}

int main(void)
{
    const char *seed = getenv("ANL_TEST_SEED");    /* runs are deterministic for a given seed */
    const char *only = getenv("ANL_TEST_ONLY");     /* substring of a test name: run only those */
    const char *rnd_state = getenv("ANL_TEST_RND");  /* the generator's state (hex), as ANL_TEST_TRACE prints it before a test */
    const char *trace = getenv("ANL_TEST_TRACE");
#define RUN(call) do { if (!only || test_selected(#call, only)) { if (trace) printf("rnd %llx before %s\n", (unsigned long long)g_seed, #call); call; } } while (0)
    setvbuf(stdout, NULL, _IONBF, 0);
    if (seed) g_seed = 0x9E3779B97F4A7C15ULL * (strtoull(seed, NULL, 10) + 1);
    if (rnd_state) g_seed = strtoull(rnd_state, NULL, 16);
    g_seed0 = g_seed;
    printf("seed %s\n", seed ? seed : "default");
    RUN(test_sid_churn(10, 4000));
    RUN(test_kat());
    RUN(test_demux());
    RUN(test_output_rewrite());
    RUN(test_default_stream());
    RUN(test_allocator());
    RUN(test_reliable(0, 0));
    RUN(test_reliable(10, 0));
    RUN(test_reliable(10, 1));
    RUN(test_semi(0, 0, 0));
    RUN(test_semi(5, 0, 0));
    RUN(test_semi(5, 1, 0));
    RUN(test_semi(2, 0, 1000));
    RUN(test_reflect());
    RUN(test_replay());
    RUN(test_violation());
    RUN(test_default_violation());
    RUN(test_seg_size());
    RUN(test_close_notify(0));
    RUN(test_close_notify(15));
    RUN(test_close_confirm(0));
    RUN(test_close_confirm(10));
    RUN(test_semi_close(0, 0));
    RUN(test_semi_close(10, 0));
    RUN(test_semi_close(10, 1));
    RUN(test_pacing());
    RUN(test_stream_lifecycle(0));
    RUN(test_stream_lifecycle(10));
    RUN(test_sid_lifecycle());
    RUN(test_sid_hold());
    RUN(test_rack_repeat_backoff());
    RUN(test_set_option_mtu());
    RUN(test_set_option_loss());
    RUN(test_fec_pause());
    RUN(test_carrier_switch());
    RUN(test_handle_lifetime());
    RUN(test_wire_v1_wrap(0));
    RUN(test_wire_v1_wrap(1));
    RUN(test_accept_limits());
    RUN(test_max_streams());
    RUN(test_sid_churn(0, 9000));
    RUN(test_sid_churn(10, 9000));
    RUN(test_priority());
    RUN(test_key_sender_purge());
    RUN(test_key_receiver_discard());
    RUN(test_window_reopen_loss());
    RUN(test_receiver_deadline_default());
    RUN(test_receiver_skip_ack_fragments());
    RUN(test_rcv_skip_clears_fwd());
    RUN(test_rcv_hole_echo());
    RUN(test_fec_rtt_default());
    RUN(test_latency_rtt());
    RUN(test_fec_first_key());
    RUN(test_report_late_clock());
    RUN(test_fec_repair());
    RUN(test_fec_report_order());
    RUN(test_report_rx_bytes());
    RUN(test_report_rx_count(0));
    RUN(test_report_rx_count(5));
    RUN(test_fec_auto());
    RUN(test_fec_auto_shared());
    RUN(test_fec_expiry());
    RUN(test_fec_dither());
#ifdef FEC_GATE_HOLD_MS
    RUN(test_fec_budget());
#endif
    RUN(test_fec_bw_estimate());
    RUN(test_fec_capacity_short());
    RUN(test_fec_loss_onset());
    RUN(test_fec_audio_start_bound());
    RUN(test_fec_capacity_gate_priority());
    RUN(test_fec_spurious_repair());
#ifdef START_WND_MS
    RUN(test_start_rate());
#endif
    RUN(test_bbr_delivery_window());
    RUN(test_bbr_app_limited_loss());
    RUN(test_bbr_policer_probes());
    RUN(test_bbr_policer_reports());
    RUN(test_bbr_report_intervals());
    RUN(test_report_epoch_wrap());
    RUN(test_bbr_policer_plateau());
    RUN(test_bbr_policer_pacing());
    RUN(test_bbr_policer_capacity_change());
    RUN(test_bbr_policer_residual_refresh());
    RUN(test_bbr_policer_queue_recheck());
    RUN(test_tiny_rtt());
    RUN(test_target_rate_wrap());
    RUN(test_target_rate_queued_ack_burst());
    RUN(test_target_rate_reports());
    RUN(test_target_rate());
    RUN(test_target_rate_drop_replay());
    RUN(test_delay_report());
    RUN(test_outage());
    RUN(test_rtt_stale_ack());
    RUN(test_start_absent(2000, 10));
    RUN(test_start_absent(17000, 10));
    RUN(test_start_absent(25000, 10));
    RUN(test_start_absent(40000, 10));
    RUN(test_start_absent(25000, 0));
    RUN(test_fuzz());
    RUN(test_fec_capacity_recovery(0));
    RUN(test_fec_capacity_recovery(5));
    RUN(test_fec_capacity_recovery(10));
    RUN(test_fec_capacity_recovery(15));     /* loss at most 15% (the test range) */
    RUN(test_report_capacity_recovery());
    RUN(test_review_scheduler(3));
    RUN(test_review_scheduler(0));
    RUN(test_review_timers());
    RUN(test_check_quiet());
    RUN(test_stream_append());
    RUN(test_byte_stream_read());
    RUN(test_review_backlog());
    RUN(test_review_gf_tables());
    RUN(test_fec_buffers_release());      /* last: new tests leave the others' random sequences alone */
    RUN(test_echo_clock_rate());
    RUN(test_capacity_clear_window());
    RUN(test_capacity_recovery_replay());
    RUN(test_close_confirm_lost_replies());
    RUN(test_fec_gate_finite_flight());
    RUN(test_fec_rebuild_reset());
    if (g_fail) { printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    printf("\nall tests passed\n");
    return 0;
}
