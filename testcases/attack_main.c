/* attack_main.c - entry of the adversarial harness; see attack_harness.h for the threat model. */
#include "attack_harness.h"
#include "attack_wire.c"
#include "attack_session.c"
#include "attack_preauth.c"

int main(void)
{
    printf("AnLiu adversarial harness - on-path attacker without the PSK\n");
    printf("============================================================\n");
    attack_replay_verbatim();
    attack_reflection();
    attack_byteflip();
    attack_length();
    attack_malleability();
    attack_blind_forgery();
    attack_zombie_connect();
    attack_ts_stall();
    attack_cross_conv();
    attack_preauth_fuzz();
    printf("============================================================\n");
    if (g_fail == 0) printf("RESULT: all attacks behaved as the security model predicts.\n");
    else             printf("RESULT: %d unexpected outcome(s) - investigate.\n", g_fail);
    return g_fail ? 1 : 0;
}
