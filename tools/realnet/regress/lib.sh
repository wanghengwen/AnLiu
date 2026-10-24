# Shared functions for a version-regression batch (docs/testcases/03-realnet.md, "完整回归的执行流程").
# A batch's wave scripts source this file after exporting ANL_REALNET_HOSTS and ANL_REALNET_WORK:
#
#   export ANL_REALNET_HOSTS=<batch>/hosts-batch.json ANL_REALNET_WORK=<batch>
#   . ~/workspace/AnLiu_github/tools/realnet/regress/lib.sh
#
# Host names only (the host table maps them to addresses, outside the repository).
# Rules the functions follow:
# - one chain (a serial run of rounds) per sender at a time; chains of different senders run in parallel;
# - the two versions of a pair run at the same time on the same path, their order swapped on odd/even seeds;
# - a round runs on the hosts once started (its deadman counts and clears the tc band when the sender exits)
#   and the tools wait out a lost connection on our side for up to an hour; between attempts, waitnet waits
#   here for both hosts, so an outage on our side does not use up the attempts.

: "${ANL_REALNET_HOSTS:?export ANL_REALNET_HOSTS}" "${ANL_REALNET_WORK:?export ANL_REALNET_WORK}"
R=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ANL_REALNET_WORK" || exit 1

addr() { python3 -c "import json,sys;d=json.load(open('$ANL_REALNET_HOSTS'));print(d.get('hosts',d)[sys.argv[1]]['ssh'])" "$1"; }

waitnet() {  # HOST...: until each host answers ssh
  for n in "$@"; do
    a=$(addr "$n")
    until timeout 40 ssh -x -o BatchMode=yes -o ConnectTimeout=15 "$a" true </dev/null 2>/dev/null; do
      echo "$(date '+%F %T') waiting for $n"; sleep 60
    done
  done
}

one() {   # CHAIN SND RCV PORTBASE DELAY LOSS SEED PROTOS: one cmp_round.py round, up to three attempts
  for attempt in 1 2 3; do
    waitnet "$2" "$3"
    out=$(timeout 5400 python3 "$R/srt/cmp_round.py" "$2" "$3" 2000 "$6" "$7" "$4" --anl base --protos "$8" \
          $([ "$5" != 0 ] && echo "--delay $5") --drive-check 2>&1 </dev/null | tail -2)
    echo "$(date '+%F %T') [$1] $2>$3 delay $5 loss $6 seed $7 $out" | tr '\n' ' '; echo
    echo "$out" | grep -q "True$" && return
    sleep 30
  done
}

pairchain() {  # NAME SND RCV PORT DELAY A B: RN-02 / RN-06 chain (3 and 5% with seeds 501/502, 7/10/15% with 501)
  for s in 501 502; do for l in 3 5; do one "$1" "$2" "$3" "$4" "$5" $l $s "$([ $s = 501 ] && echo "$6" || echo "$7")"; done; done
  for l in 7 10 15; do one "$1" "$2" "$3" "$4" "$5" $l 501 "$6"; done
  echo "$(date '+%F %T') [$1] CHAIN_DONE"
}

A3=anl-nf,anl-nf@cand,srt-b; B3=srt-b,anl-nf@cand,anl-nf
rn03() {  # NAME SND RCV PORT: RN-03 chain (0%, 3/5% with two seeds, 7/10%), SRT as the reference lane
  one "$1" "$2" "$3" "$4" 0 0 501 $A3
  for l in 3 5; do one "$1" "$2" "$3" "$4" 0 $l 501 $A3; one "$1" "$2" "$3" "$4" 0 $l 502 $B3; done
  for l in 7 10; do one "$1" "$2" "$3" "$4" 0 $l 501 $A3; done
  echo "$(date '+%F %T') [$1] CHAIN_DONE"
}

churn() {   # VARIANT SERVER CLIENT PORT SEED LOSS [EXTRA]: one churn_round.py round, up to two attempts
  for attempt in 1 2; do
    waitnet "$2" "$3"
    out=$(timeout 5400 python3 "$R/churn_round.py" run "$2" "$3" "$1" "$5" "$4" --loss "$6" --rate 4000 $7 2>&1 </dev/null | tail -1)
    echo "$(date '+%F %T') [$1 $2>$3 loss $6 $7] $out"
    echo "$out" | grep -q 'True' && return
    sleep 30
  done
}

rn04() {  # SERVER CLIENT PORT SEED: RN-04 chain, cbase and ccand at the same time (ports PORT and PORT+4)
  k=0
  for l in 3 5 10 "10 --delay 100"; do
    set -- "$1" "$2" "$3" "$4" $l; L=$5; X="${*:6}"; k=$((k + 1))
    if [ $((k % 2)) = 1 ]; then a=cbase; b=ccand; else a=ccand; b=cbase; fi
    churn $a "$1" "$2" "$3" "$4" "$L" "$X" & sleep 5
    churn $b "$1" "$2" $(($3 + 4)) "$4" "$L" "$X" & wait
  done
  echo "$(date '+%F %T') RN04_$1_$2_DONE"
}
