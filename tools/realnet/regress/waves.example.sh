#!/bin/bash
# The layout of reg-20261024 (docs/testcases/03-realnet.md, "完整回归的执行流程"): three waves, each sender
# carries one chain at a time. Copy into the batch directory, adjust host names and ports, then run
#   nohup bash waves.sh > waves.log 2>&1 &
# Each chain writes its own log; WAVE*_DONE marks the end of a wave.
export ANL_REALNET_HOSTS=${ANL_REALNET_HOSTS:-$PWD/hosts-batch.json} ANL_REALNET_WORK=${ANL_REALNET_WORK:-$PWD}
. "$HOME/workspace/AnLiu_github/tools/realnet/regress/lib.sh"

# wave A, about 80 min: RN-02 on two same-site pairs with tc delay, RN-03 on two WAN paths
A=anl-nf,anl-nf@cand; B=anl-nf@cand,anl-nf
pairchain rn02-d100 g5 lsj 9960 100 $A $B > chain-rn02-d100.log 2>&1 &
sleep 45; pairchain rn02-d200 lsj g5 9970 200 $A $B > chain-rn02-d200.log 2>&1 &
sleep 45; rn03 rn03-sld s_ld t1 9980 > chain-rn03-sld.log 2>&1 &
sleep 45; rn03 rn03-hz t1 hz 9990 > chain-rn03-hz.log 2>&1 &
wait; echo "$(date '+%F %T') WAVEA_DONE"

# wave B, about 80 min: RN-06 (auto FEC) on the same paths
A=anl,anl@cand; B=anl@cand,anl
pairchain rn06-d100 g5 lsj 9960 100 $A $B > chain-rn06-d100.log 2>&1 &
sleep 45; pairchain rn06-d200 lsj g5 9970 200 $A $B > chain-rn06-d200.log 2>&1 &
sleep 45; pairchain rn06-sld s_ld t1 9980 0 $A $B > chain-rn06-sld.log 2>&1 &
sleep 45; pairchain rn06-hz t1 hz 9990 0 $A $B > chain-rn06-hz.log 2>&1 &
wait; echo "$(date '+%F %T') WAVEB_DONE"

# wave C, about 90 min: RN-05 (rn05.jsonl: 16 tasks t1>lsj, +20/+100 ms, 0/3%, seeds 1/2, video_max 8000,
# burst 3200, tc_loss, fec_off) and RN-04 on two client-only hosts (n1/n2 take no unsolicited UDP)
python3 "$R/multi_sched_pair.py" rn05.jsonl sched-rn05 > rn05.out 2>&1 &
sleep 60; rn04 g5 n2 9940 7 > rn04-g5n2.log 2>&1 &
sleep 30; rn04 lsj n1 9940 6 > rn04-lsjn1.log 2>&1 &
wait; echo "$(date '+%F %T') WAVEC_DONE"
