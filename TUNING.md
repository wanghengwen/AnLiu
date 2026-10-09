# AnLiu 调参记录

anliu.c 里各条规则的实验依据：真实网络和仿真中观察到的现象、试过的做法、数字。代码里只留结论和本文件的条目号（`TUNING.md n`）；条目按代码顺序排列，函数名以外迁时的代码为准。设计规则见 [DESIGN.md](DESIGN.md)，性能数据见 [performance.md](performance.md)，开发记录见 [progress.md](progress.md)。

条目是从代码注释原样搬出来的英文；"real network" 指真实路径上的成对测试，"simulation" 指 test.c / bench 的仿真；s_rb、s_hz 等是测试主机的代号。

## 1. rcv_deadline_ms default: 3/5 of max_age

`anliu.c`: RCV_WAIT_PCT

rcv_deadline_ms -1: a gap is waited for this % of the local max_age (DESIGN 7.5); all of it held the frames behind an unfillable gap past any playout budget shorter than max_age (FEC off, 2 Mbit, 60..300 ms, 3..15%: video on time +2.6, audio +0.55 points on average)

## 2. FEC_FLOOR_CAP

`anliu.c`: FEC_FLOOR_CAP

adaptive: parities of a large non-key block, at most this % of k; the auto ratio's ceiling while the budget's bucket is short (50 / 35 / 25 simulated: 25 already held long-RTT video at 99.5%, real cross-border video 97.5..98.6% at 20%)

## 3. start_rate pacing counts the IP/UDP header

`anliu.c`: dg_output

paced at a start_rate hint, the hint is the path's rate: the IP/UDP header counts too - at 240 kB/s over 2 Mbit/s, datagrams without the padding they used to carry overran the bottleneck (test_start_rate: first key frame lost, 7 of 10 key frames)

## 4. reports: rebuilds net of reordering

`anliu.c`: write_report_seg

rebuilds net of the ones whose original arrived after all (those were reordering, not loss - a lossless real path: 461 "repairs" in 5 minutes, and audio duplicated for all of it) and of the ones too young for the original to have come yet

## 5. FEC_SLOW: a frame completed late

`anliu.c`: handle_report

a frame took 3/4 of a round trip beyond its packets' queueing: a retransmission (at least a round trip) completed it - late where one cannot make the deadline. (Half a round trip also caught key frames paced over that long.) Its loss is counted already. A rebuild waits for its block's parity, up to fec_blk_ms after the frame: beyond that as well (counted from the queueing alone, every repair read as a retransmission - at 100 ms RTT and 5% loss the ratio ran to its ceiling on FEC's own successes)

## 6. pace floor and policer trials

`anliu.c`: compute_pace_rate

A lower-rate trial must be executable. At 1 ms RTT / 10 ms interval, the ordinary floor is 4.38 Mbps: it defeated a 2.87 Mbps trial on a 3 Mbps policer, so the remaining loss falsely rejected the trial. Retain the floor outside policer control and allow explicit up-probes.

## 7. repeated fast retries are spaced

`anliu.c`: rack_candidate

A repeated reliable retransmission must not stay phase-locked to the empty part of a policer's token cycle. With a 1 ms RTT, a later packet was delivered while the same missing packet lost 20 transmissions in 64 ms. Space repeated fast retries by 4, 8, 16 ... ms, capped by its RTO - which a lost retransmission backs off (flush, as for a timeout): held at the RTO (137 ms on a 100 ms path) the cap let a segment the path kept losing use up dead_link in 2.7 s while the peer acknowledged everything else, and the connection died. The first fast retry and semi deadlines keep their original timing.

## 8. RACK marks count as loss at once

`anliu.c`: rack_detect

counted for congestion control now (Linux BBR does the same): waiting for the retransmission's ACK put the loss 1-2 RTTs late, after a policer's bucket had let STARTUP overshoot - the rounds that should have stopped it saw none. Undone if the original turns up (handle_ack, Eifel). Not for a segment the RTO already retransmitted: after an outage the first ACK marks everything sent during it at once - 86% of the round, which reads as a policer (BBR_LOSS_BLIND) and held bw_lo and inflight_hi down for 800 ms after the link came back (soak outage, inter p99 +8%). Those count when their recovery is acknowledged (handle_ack), spread over the rounds it takes.

## 9. policed pace

`anliu.c`: bbr_bw

policed: the policer's rate itself - without probing (compute_pace_rate) the filter only saw its own pace minus the loss and ratcheted down, 27 -> 18 Mbps over a minute on a 30 Mbps path; testing: at most that rate

## 10. policer detection

`anliu.c`: bbr_policer (the comment before bbr_lt_probe_rate)

A token-bucket policer drops what exceeds its rate without queueing it: loss without a queue, which BBR here does not take as congestion (random loss on a radio link looks the same), and the send-rate credit then keeps the sender at up to 1.5x the rate - 40% of the packets lost (a home uplink, real network). Told apart by the response (BBRv1's long-term sampling plus a test): two intervals (>= BBR_LT_ROUNDS rounds and 300 ms) in a row, network-limited, no queue, over 10% lost, delivering the same rate within 1/4 - then an interval paced at that rate. Halving the loss starts a probe for the ceiling; a failed test holds off for 48 intervals.
The test alone passes on any path whose capacity is above the rate (a jittery 50 Mbps uplink was locked at 33 for two minutes): a policer is a ceiling, so the test is followed by intervals paced a quarter above the rate, then another quarter, and so on (lt_state 3, lt_k). Delivery stays at the rate and the excess is lost: the ceiling, and the policed state starts there. Delivery follows the pace: the ceiling, if there is one, is higher - the next step looks for it. Not "no policer": a 48 Mbps shaper with a burst allowance passed the first step for a whole interval (real network), and rejected, the sender went back to 1.5x the rate with a fifth lost for a minute. After BBR_LT_PROBE_MAX steps (5x the rate) exhaust the probe budget; a larger bucket or higher ceiling can still escape detection.
Intervals are >= BBR_LT_ROUNDS rounds and 300 ms: at 280 ms RTT the earlier 16-round intervals took 9 s to enter the test and 18 s to a verdict, at 1.5x the policer's rate with a quarter lost.
The policed state does not simply expire either: on a sub-millisecond path the token bucket the policer refilled while we paced below its rate passed everything, the samples ran off to the line rate within tens of milliseconds and 2400 segments were in flight before the bucket was empty (10000 retransmissions every 15 s). Instead the same probe runs after lt_span intervals: pace a quarter above the rate, then another quarter, and so on. The ceiling shows again - lt_rate becomes what was delivered (the policer's rate may have changed) and the policed state resumes for twice as many intervals (up to BBR_LT_SPAN_MAX); after BBR_LT_PROBE_MAX steps without a ceiling the policer is gone, and the bandwidth filter restarts from what the last step delivered. A bucket can pass multiple steps; once it empties, the excess is bounded by the probe rate instead of a window that grew to the line rate. A persistent queue during a probe yields to ordinary congestion control.

## 11. heavy loss after STARTUP clears the filter

`anliu.c`: bbr_policer

Just after STARTUP a round over 25% lost, delivering less than half the estimate, clears what the filter kept of STARTUP: a policer with a large bucket let STARTUP measure 4x its rate, and the filter took 10 s to come down through its rounds at 277 ms RTT - retransmissions sent at 2-4x the rate were lost again and again, delivery stalled and resumed second by second (29000 retransmissions in 13 s). The round's delivery rate is where the model restarts; probing finds any more. (Starting the policer test there instead locked a 45 Mbps path at 33 for two minutes: the test passes whenever the rate is below the capacity.)

## 12. a round of at least half the window

`anliu.c`: bbr_policer

a round of at least half the window: losses are counted when RACK marks them (rack_detect), and a short round of a 20% random-loss path (a few segments delivered between two marks) showed 27% and pulled the filter down to a quarter (s1 20%/200 ms)

## 13. the transition round

`anliu.c`: bbr_policer

the first round at a new pace is the transition: what was in flight at the old pace is still being dropped (a third of it after 1.5x the rate) and would be the new interval's loss - 14% in a test paced at the rate, which failed (30 Mbps policer, 100 ms); it is left out

## 14. intervals after an input gap

`anliu.c`: bbr_policer

Intervals ending within LT_GAP_MS of a resumed input gap are dropped: the outage's losses, abandoned frames and backlog retransmissions read 40..60% lost, and the test interval after them only the path's random 20% - "halved", a policer - which locked a 5 Mbit path at 0.6..0.8 Mbit for the remaining 60 s (simulation, 20 s outage, 180 ms, 3 of 400 runs). A real policer is found that much later.

## 15. the interval's loss

`anliu.c`: bbr_policer

The interval's loss from what it sent and what was delivered - what is still in flight at its end was sent but could not be delivered yet, what was in flight at its start is delivered in it but was sent before: both are taken out, or a 4-round interval is a quarter off. The losses counted (RACK) are mostly of what was sent before, found a round or more later - at 100 ms RTT they failed every test (sent 1.21 MB/s, delivered 1.21, "lost" 36%), then held for 48 intervals at 1.5x the policer's rate, a third lost.

## 16. residual loss at the policer's rate

`anliu.c`: bbr_policer

what is still lost at the policer's rate is random loss: send that much more, or random loss on top would pace below the rate. The smaller of the two measures: what was sent includes the retransmissions of the intervals before (10% on a clean 30 Mbps policer, paced 6% above it for good), what was counted includes their tail (RACK, a round late)

## 17. probe step: the rise tells

`anliu.c`: bbr_policer

Paced lt.rate * (4 + k) / 4, a share k / (4 + k) of what is sent is above the rate. A ceiling drops it: the loss rises by that much over the residual (lt.res). Random loss does not depend on the pace: at 20% it read "an eighth more sent than delivered" and locked a 20 Mbps path at 0.8 (s1 20%/50 ms) - it is the rise that tells. Half the share: a jittery ceiling drops less.

## 18. the probe's tail interval

`anliu.c`: bbr_policer

the tail: the same pace for an interval with the bucket empty (the interval that showed the ceiling delivered the bucket the policed state had refilled on top of the rate: 6% over on a 30 Mbps policer, then 6% lost for good). Its delivery, plus the residual, is the policer's rate; not below 7/8 of the estimate - one tail can be unlucky, the next probe measures again (50 ms tails read 1.35, 1.18, 1.03 MB/s for 1.25 on a 10 Mbps policer that passes its rate in slices: an interval at least)

## 19. test thresholds: 10% and 1/4

`anliu.c`: bbr_policer

over 10% lost, rates within 1/4: a test costs one interval at the delivery rate, and the test itself tells a policer from random loss - over 20% and within 1/8 missed a 50 Mbps uplink whose rate jitters, and the sender stayed at 1.7x it with a fifth of the packets lost for over a minute (real network)

## 20. bbr_rtt: not below the update interval

`anliu.c`: bbr_rtt

The RTT the model works with: min_rtt, but not below the update interval. RTT samples are taken against the time of the last anl_update, up to an interval old when a datagram arrives in between: on a path of a few ms a sample of 1 ms stood for 10 s in min_rtt, cwnd (2 x bw x min_rtt) fell to 4 segments and the delivery rate - and btl_bw - with it (real network, DESIGN 6.8). The model also allows for the periodic flush interval.

## 21. PROBE_RTT re-arming

`anliu.c`: bbr_update_min_rtt

a new value no PROBE_RTT has seen yet - below what the last one saw. Not merely below the current min_rtt: a flat-queue probe sets min_rtt to the drained round's RTT, a few ms above the path when the pipe does not fully drain, and the 10 s expiry takes any sample; the path's own RTT then read as new every few seconds and re-armed the probe against the same standing queue (2 Mbit, 20 ms, encoder following target_rate: 3..6 PROBE_RTT a minute, key frames on time 81%)

## 22. a longer path, not a queue

`anliu.c`: bbr_round_end

The path's RTT went up (route change, new link): every round now looks queued against the old min_rtt for up to BBR_MIN_RTT_WIN, and random loss looks congestive - each round would cut the model by 0.7 until nothing is left. The two differ in the delivery rate while we cut: at a bottleneck that got slower it stays at the link rate (the queue stays full until we are below it), on a longer path it falls with each cut. BBR_PATH_ROUNDS congestive rounds, each delivering 15% less than the one before (or app-limited), while the queue signal stays (rounds without loss in between do not reset the count, only the queue going away does): take the round's RTT as min_rtt and undo the cuts (btl_bw still holds the rate). The rounds counted must also agree on the RTT (within a quarter): a longer path's RTT stays put while we cut, a queue's moves with the cuts - a 100 ms buffer at a bottleneck that dropped 8 -> 2 Mbps showed 86 / 114 / 126 ms over the three rounds and passed for a longer path once losses were counted a round earlier (bwstep, RACK-marked losses): cwnd 32 -> 155, 72% lost. And each counted round must deliver less than the last one counted.

## 23. a flat queue: PROBE_RTT now

`anliu.c`: bbr_round_end

The same without loss: the round RTT sits above 1.25x min_rtt while we pace at or below the estimate (DOWN, CRUISE) and does not move from one round to the next. Either a standing queue or the path - passively the two look alike (taking the RTT as the path's ratcheted a standing queue up: bwstep audio p95 115 -> 219 ms), so ask the network: PROBE_RTT now instead of at the 10 s expiry, and take the drained RTT as min_rtt (bbr_update_state). A queue drains and the old min_rtt comes back; the path does not. Until then the smaller BDP ended every probe after one round with "the pipe is full" and DOWN never reached CRUISE: min_rtt 104 ms on a 185 ms path held 24 Mbps of a 50 Mbps uplink for 10 s (s_hz). Once per min_rtt value (min_rtt_probed): a sender whose bursts keep a standing queue at the bottleneck would otherwise drain it every few seconds, and each drain holds the control stream behind the minimum cwnd (priority test: p99 193 -> 234 ms at once per 3 s).

## 24. an app-limited round's loss

`anliu.c`: bbr_round_end

An app-limited round delivered what the application sent, not what the path carries: its delivery rate is the application's own rate. Cutting the model to it leaves nothing for retransmissions, parities and key frames - they queue at the sender, where frames expire whole. On a 1.2 Mbps media stream over a path whose RTT moves between 60 and 110 ms (a queue signal against min_rtt most of the time) with 1-4% random loss, each lossy round cut bw_lo to the P-frame rate and inflight_hi to 0.7x a window that was already 2 BDP of that; window-limited, the rounds turned network-limited, the filter followed cwnd / srtt and the model fell to 105 kB/s for a 150 kB/s stream (real network s_rb -> s_ali_ecu, 3 of 8 rounds: 150-307 frames dropped, video on time 100 -> 94-96%). The round's send rate - retransmissions and parities included - is what the sender needed, and the path carried it: bw_lo does not go below it. Not when the smoothed loss (this round included) exceeds 1/8: an app-limited sender offering more than a slower bottleneck loses the excess every round (bwstep --abr 8 -> 2 Mbps: 70% at once), the path's random loss averages a few percent even though a single round of 11 segments shows 9% for one segment. inflight_hi is not bounded by an app-limited round at all (BBRv2: an app-limited sample does not probe the volume the path takes): the window is what keeps the sender app-limited.

## 25. STARTUP exit on heavy loss

`anliu.c`: bbr_round_end

STARTUP ends when the bandwidth stops growing by 25% for 3 rounds - or when a round lost over 40% of what it sent: a policer's bucket let the doubling run far past its rate (20000 of 26000 retransmissions of a 75 s stream were STARTUP's). Only once the model has grown to 4x the initial rate: a path that dropped everything in its first second otherwise left STARTUP at almost nothing, and PROBE_BW took 70 s to reach 60 Mbps. No inflight bound: the loss may be random.

## 26. the model restarts at the round's rate

`anliu.c`: bbr_round_end

... and the round's delivery rate, well below the estimate, is where the model restarts (as bbr_policer does after STARTUP): RACK's marks put the bucket's whole overshoot into this round, the rounds after it saw little and kept the peak for a filter window (30 Mbps policer, 280 ms: 21000 -> 30000 retransmissions)

## 27. UP continues on an eighth per round

`anliu.c`: bbr_round_end

growing by an eighth per round keeps the probe going: the pace is 1.25x, so a quarter - the most a round can show - failed on any noise and every probe ended after two rounds. After min_rtt had been taken from a 104 ms dip on a 185 ms path, the queue signal made a loss round cut the model to a quarter, and at one probe per 2-3 s it took 25 s to climb back (s_hz uplink, 4 times)

## 28. burst_bw: ACK dispersion of a key frame

`anliu.c`: burst_on_acked

A burst of an app-limited sender (a key frame) on a path whose RTT is longer than the burst: every rate sample spans burst plus RTT, a fraction of the rate the burst went through at - on a 100 ms path the estimate stays at the video's average rate and a 30 KB key frame takes 20 ms to leave (real network). The spacing of its ACKs shows the rate (packet-train dispersion): bytes of its segments acknowledged after the first one over the time since, capped at the rate it was sent at (ACK compression cannot raise it above that). Its own segments, tagged when sent: other traffic in flight (audio) does not matter. Not for the model - an estimate that full at once filled bottleneck queues in STARTUP and next to bulk traffic (s5, priority test) - but burst_bw, the rate an app-limited sender paces at (compute_pace_rate): 1.25x of it, so that the next burst can find more; less by a fifth when the burst queued.

## 29. bbr_window_bw: delivered-byte checkpoints

`anliu.c`: bbr_dw_checkpoint

Delivered bytes sampled from ACKs and updates (a ring of BBR_DW_SLOTS), for the delivery rate over a window of at least span ms: bbr_window_bw. A rate sample spans about one RTT; when that is below the clock's resolution (a 0.5 ms path, a 1 ms clock) the sample's interval is 1 ms for anything up to 2 ms - up to twice the rate, and the pace set from it doubled the next sample too: through a policer's refilled token bucket the estimate ran from 3.5 to 128 MB/s in 50 ms (real network). Over 10 ms the truncation is 10% at most. Returns 0 without enough history.

## 30. a queued burst fills the path

`anliu.c`: bbr_on_ack

An app-limited burst that came back queued (RTT as bbr_queue_signal) filled the path: the estimate is the path, as after a network-limited sample - no STARTUP-gain headroom for BBR_BW_ROUNDS (bbr_headroom). Without it a sender held app-limited by its encoder (target below the estimate) at 190 ms sent every key frame at 2.9x into a 100 ms queue: key frames on time 27%, 8.6 queue drops/s at 2 Mbit/s (media_loss, encoder following the target, no random loss).

## 31. RTO margin: srtt / 4 and two intervals

`anliu.c`: update_ack

+ srtt / 4 at least: a BBR probe (gain 1.25 for a round trip) queues up to a quarter of the RTT at once, faster than rttval follows; losses are RACK's job, the RTO is the fallback for tails. Two update intervals at least: the peer's ACK waits up to one for its flush, and a lost ACK's repeat comes one later (write_ack_segs) - with one, the RTO raced both (20 ms RTT: audio retransmitted once a second without loss, a third of the RTOs at 5..15% loss reached a peer that had the data)

## 32. an RTO loss under a report

`anliu.c`: handle_ack

an RTO loss: not marked. Not into the estimate for a segment its block covered while the peer reports: its rebuild is in that report, and the RTO usually fires before the rebuild's ACK (counted twice, the estimate read 3.9% at 3% loss and 19.7% at 15%, simulation); still the gate's hard evidence

## 33. fec_ride: small-block parities ride with data

`anliu.c`: fec_ride

A small block's parities ride with the stream's following first transmissions, one each, instead of datagrams of their own: a datagram header and tag (about 65 bytes with IP/UDP) on a 176-byte audio parity. Judged by the block's size alone - audio, or video at a low rate. Audio alone at 3..7% loss: 6..13% fewer bytes, a third fewer datagrams, on time the same (simulation, 100..300 ms RTT; low-rate video 4..9%). Not while a queue shows: the 20 ms a parity then waits adds to the queue's and cost audio 1..2 points at 800 kbit. Not from FEC_RIDE_LOSS on either: a block that needs several waited 20 ms for each (15%: audio -1..-2), and even the first one's wait put 20% loss at 100 ms RTT below 99.5% audio.

## 34. fec_repair_ms: a second retry for large frames

`anliu.c`: fec_repair_ms

A large frame needs every fragment. Even when one retry fits, losing that retry can leave the frame (and a key frame's GOP) unrecoverable. n*p*p bounds the chance that some fragment loses both its original and first retry. If it exceeds the parity floor's failure target, reserve one more detection/round trip instead of assuming that retry surely works. This covers the first repeated-loss blind spot, not an arbitrary tail guarantee. Small audio keeps its bounded startup and one-repair policy; explicit FEC modes keep their existing estimate. The stricter target of a drop_until_key stream is for its key frames: a non-key frame whose second retry still beats max_age comes late, not lost - its GOP survives - and takes the looser one (100 ms RTT, 3..5% loss: no parity for those frames, wire -8..-12%, video on time within 0.1 point, simulation).

## 35. the gate needs recent hard loss

`anliu.c`: fec_gate_update

Beyond bounded audio startup, only while the path has lost a packet, with hard evidence, in the last FEC_LOSS_RECENT_MS. Otherwise parity was 7..28% of the media on lossless real paths (audio duplicated for 5..10 minutes on one early rebuild - reordering, as it turned out). Small frames (audio) then on the repair time alone (the estimate dips between windows, and every dip cost seconds of unprotected audio on a lossy long path); large frames need 1% as well.

## 36. small blocks: full parity while the loss settles

`anliu.c`: fec_close_block

a small block (audio) as many parities as packets while the loss estimate settles: its bytes are few, and nothing else kept long-RTT audio on time (real cross-border paths: 99.9..100% at 100%, 38..62% at fixed 20..40%). Once it has, the binomial floor above: at 1..3% random loss 33% instead of 100%, audio on time within 0.1 point (simulation, 100..300 ms RTT)

## 37. the RTO counts from the last parity

`anliu.c`: fec_close_block

the RTO counts from the last parity too, as far as a retransmission then still makes fec_deadline (reach): a block collects up to fec_blk_ms, and timed from the send the RTO beat the rebuild's ACK (100 ms RTT: 80% of the retransmissions reached a peer that had rebuilt them). Not beyond: where FEC fails, that early retransmission is what keeps the frame on time (deferred all the way, video at 180 ms RTT and 15% loss went from 98.9 to 97.3% on time), and one that only just arrives counts as late - the ratio ran to its ceiling where retransmissions are in time

## 38. no raise while short of budget

`anliu.c`: fec_auto_count

not while large frames are short of parity budget (the bucket below half): those losses are likely our own congestion, more parity would add to it - the ratio ran to 100% on a 2 Mbps path and its key frames overflowed the queue (simulation). Only while network-limited or queueing: app-limited, the budget follows an estimate that shows only what was sent, and the losses are not ours - with fewer spurious retransmissions to inflate it, 20% random loss left the ratio at its floor (test.c, 5 of 140 seeds)

## 39. fec_block_wanted

`anliu.c`: fec_collect

A block opening now (with seg) could get parities (DESIGN 8.7): a fixed ratio or adaptive without the RTT gate always; the RTT gate only while it is open, in audio startup, before anything is known (the first key frame), or with a loss of hard evidence within FEC_LOSS_RECENT_MS (what opens it, fec_gate_update / fec_key_gate, needs that too) and then for a key frame of a drop_until_key stream, or a typical frame whose repair is past half of fec_deadline. The gate is judged when the block closes, with the RTT of then: a key frame's own queue raised it from 192 to 226 ms within the frame (2 Mbit, 20 ms) - hence the margin, and key frames whatever their repair. Otherwise the block's copies are not made and the buffers go; the first block collected again is the one that can open the gate

## 40. fec_block_ms

`anliu.c`: fec_block_ms

How long the block opening now collects (DESIGN 8.2). Adaptive parity: as long as fec_deadline leaves after the trip (srtt / 2), the last block's parities FEC_GAP apart and the jitter (two update intervals, 4 rttvar) - a longer block needs fewer parities for the same failure target (k = 9 at 5% loss: 44% for 0.1%; k = 23: 26%). At least FEC_BLOCK_MS: below that the parities would cost more than a late frame; a fixed ratio keeps it.

## 41. rcv_hole_hopeless

`anliu.c`: rcv_hole_hopeless

The hole at rcv_nxt is past saving: a retransmission of it - sent once our ACK has shown the hole to the sender, about a round trip after the data was sent, and half a round trip on its way - would arrive when the data is older than its lifetime (max_age here). Waiting for it then only holds back the frames behind it (head of line: real network, 170 ms RTT, FEC off, audio max_age 200 - each loss delayed the next ~4 packets past a 150 ms budget, audio on time 75..89% at 3..5% loss where SRT, which drops at its latency, had 95..97%). From the path's RTT (min_rtt, or what CTRL_ECHO gives a receive-only peer; not srtt: a noisy one would skip holes a retransmission still fills). Not while parities arrive: FEC may rebuild it sooner. rcv_deadline still bounds the wait as before (DESIGN 7.5)

## 42. vq_ms: the RTO waits for the backlog

`anliu.c`: vq_ms

The time a segment just sent waits behind that backlog: its RTO waits as much longer. A key frame's burst, paced above the bottleneck, delays its last segments and the frames after it: at 5 Mbit, 100 ms, 20% loss their RTT reached 140..210 ms against an RTO of 130 from the smoothed RTT, and 57% of the video retransmissions were of segments the peer already had. Drained at the faster of the estimate and the rate bursts went through, at most one srtt, and not while capacity is short: an app-limited or collapsed estimate read a backlog the link did not have, the late RTOs sent less, the estimate fell further - parity stayed at its floor under 20% loss, and a 4 Mbit path stayed capacity-short for 30 s after an 800 kbit stretch.

## 43. target_rate decrease

`anliu.c`: rate_update

what the path delivers now, or - when nothing gets through in time - RATE_DECREASE % less per step; not below what BBR keeps going at its smallest window. While the path delivers all it is sent (no loss beyond a sixteenth, cs_loss of the last step) the queue is our own burst draining: not below the payload delivered over the last few steps (dlv_avg). A key frame's burst into a slow shaper queues for a step (30 KB is 300 ms of an 800 kbit link) and its few acknowledgements in that step read as 8..24 kB/s: the target fell to that on every key frame and climbed back at 25%/s for 9 s, the encoder at 23..55% of the link (real network, closed loop). A bottleneck that got slower loses what is sent and gets this step's rate (bwstep 8 -> 2 Mbps within a step, as before).

## 44. target_rate under a policer

`anliu.c`: rate_update

A policer keeps no queue: the estimate (a token bucket's burst) and the target sat above it while a quarter of the payload was dropped (1200 kbit policer: target 150..222 kB/s, the line at 1.6x). Losing over a quarter of the payload - no random loss does that - or short of capacity (8.6): not above what the path delivers, less the margin; parities are not payload, so they are out already. The delivered payload is compared with what was sent a step earlier: at 170 ms a key frame's step sends 2x the average and its delivery shows a step later (against the same step the cap read 0.6 and held an 8 Mbps link's encoder at 0.8 Mbps)

## 45. capacity_short

`anliu.c`: rate_update

Capacity short (DESIGN 8.6): the bottleneck is slower than the media. Two signs, each smoothed over about 4 steps (a key frame's step sends 2x the average, its delivery shows a step later), each with its own hysteresis so that the state does not flap once the parity is gone and the ratio recovers a little:
- the path delivers under half of the payload sent: strong initial evidence of overflow (recovery is retested below; retransmissions and abandoned frames can also depress this ratio). The queue is no criterion: a shaper caps it (tc tbf at 100 ms: srtt 230 on a 170 ms path while it dropped 70%) - leaves above three quarters;
- a sixteenth or more of the semi-reliable payload expires at the sender before its first send (semi_drop_check): whatever the estimate says, the sender could not send the media in max_age. Losses on a good path never do this (a frame lost in flight is abandoned by the retransmission path, not here) - leaves below a sixty-fourth. Only once it has happened twice, at least 1 s apart, within 6 s: a bottleneck that is too slow expires frames every second or two for as long as it lasts, a one-off dip of the model (a route change, a burst of loss) flushes a backlog once, and one GOP is two seconds of the media - enough to read as a sixteenth for the next 3 s. Additional parity could deepen the apparent overflow: no adaptive parity (fec_close_block), gates closed (fec_gate_update), no budget. The estimate cannot tell: a token bucket's burst or a key frame measured it (1.2..1.9 Mbps on an 800 kbit shaper, real network). Nor is the sender app-limited then (anl_flush_internal): its queue is empty because it discarded the application's data, not because the application had nothing to send - marked app-limited, every sample was ignored, the filter never aged the burst's peak out, and the burst headroom kept pacing at 2.885x an estimate already 1.6x the link (simulation, tbf 800 kbit: 70% lost for a minute).

## 46. leaving capacity_short on calm steps

`anliu.c`: rate_update

The network's own signs of the shortage: payload lost (over a sixteenth) or a queue. A state entered on expiring frames alone ends after five steps (1 s) without either, whatever the expiries say: when the bottleneck recovers (tbf 800 kbit -> 3 Mbit) the estimate is still the slow link's, the backlog keeps expiring frames, and held short and network-limited the model could only grow by PROBE_BW's quarter per 2..3 s cycle (real network: short for 4..9 s after the switch, the first 10 s at 3 Mbit 63..97% on time against 100%). Not a state entered on loss (an outage, a policer): ending that one on calm alone let soak's outage phase leave 2 s earlier and the RTT jump that follows collapse the model in 3 of 6 seeds (hirtt 97 -> 72..76%).

## 47. parity budget while capacity is short

`anliu.c`: rate_update

parity budget (DESIGN 8.6): 90% of the estimate less all else sent, smoothed over about 8 steps (1.6 s): a key frame fills a 200 ms step by itself, and a budget that read 0 for that step shrank the bucket and threw its tokens away. Nothing while capacity is short: the estimate itself is what a token bucket's burst or a key frame measured, not what the path sustains (real network: 1.2..1.9 Mbps on an 800 kbit shaper)

## 48. fec_rto_hold

`anliu.c`: fec_rto_hold

The RTO of a first transmission that the peer can almost surely rebuild. Its retransmission is held back by the deadline (fec_close_block: it must still make fec_deadline), which comes before the rebuild's ACK can: 94% of the audio ones reached a peer that already had the segment (5 Mbit, 100 ms, 5%), 91..96% of the video ones (2 Mbit, 100..170 ms). Small block (audio): the members still unacknowledged plus the parities leave the block short only if more than m of them are lost: at twice the measured loss, no more than a tenth of the small-block target - hold the RTO for a round trip, once. Not near the link (a recent queue, capacity short): there losses come together and the independent estimate is too low. Large block (video): the members whose ACK is overdue count as lost, the others and the parities as on their way; held until the rebuild's ACK is due, once, while the block then fails at most FEC_HOLD_FAIL in 10000 (twice the measured loss), and only while a retransmission after that still makes max_age. The queue a key frame builds is no reason against it (it is there all the time at 2 Mbit); the losses already seen are. The earlier attempt held all blocks like small ones and cost 2 points of video at 2 Mbit 280 ms and 3..5 of a cold start: its retransmissions came after max_age. Returns when to retransmit, 0: now.

## 49. inflight: RACK-marked segments are out

`anliu.c`: anl_flush_internal

One walk of the list: sender-side dropping before computing budgets, then what is in flight - sent and not acknowledged, minus what RACK declared lost and is not resent yet (BBR's pipe). With the lost segments counted, a policer that dropped half of a STARTUP overshoot kept DRAIN from ever ending: inflight stayed far above the BDP, the drain gain slowed the retransmissions, their samples lowered btl_bw and so the pace - down to 0.4 Mbps on a 10 Mbps path for 20 s (DESIGN 6.8). Each stream's drop check and count concern that stream only.

## 50. abandoning past max_age is hard loss evidence

`anliu.c`: anl_flush_internal

past max_age: abandon instead of retransmitting (DESIGN 7.3). Not an FEC failure: the peer may well have it (repaired, its ACK still on the way) - only the peer's skips tell (handle_report, DESIGN 8.5). But a loss with hard evidence for the gate: unacknowledged for max_age while higher sn were - no reordering lasts that long (audio at 280 ms RTT never gets its retransmissions confirmed)

## 51. app-limited while capacity is short

`anliu.c`: anl_flush_internal

Not while capacity is short and the path is losing what is sent (rate_update): the queues are empty because frames were discarded for age, not because the application had nothing to send - the network is the limit. With the path delivering everything (a model that collapsed after an RTT jump, soak hirtt: frames expire behind a window of 33 segments at 390 ms) the app-limited samples are what lets the model climb back; held network-limited it fell further (bw 408 -> 117 kB/s, video 67%).

## 52. the first report and losses counted from ACK order

`anliu.c`: handle_report, handle_ack

Before the peer's first report the sender counts an original acknowledged after a higher sn (and a RACK mark the original's ACK proves wrong) as a loss: rebuilt from parity, or reordered - it cannot tell. On a reordering path without loss (unit test, 60..110 ms jitter) one reordered packet at 1.27 s, 10 ms before the first report, made the first window (50 packets) read 2%; the warm-up takes a higher measurement as it is and the later windows smooth by a quarter, so the estimate was still 0.85% at 15 s (the gate closes below 0.25%). It took a STARTUP change's timing to put the packet there. Now these counts are provisional per stream: at the first report, while their window is still open, no more of them stay than the rebuilds it reports (net of rebuilds whose original came after all). The report stays a baseline - nothing is added from it. Media regression (ASan, 24 scenarios): output unchanged.

## 53. a queued app-limited sample ends STARTUP

`anliu.c`: bbr_on_ack

An encoder following target_rate keeps the sender app-limited, and STARTUP's bandwidth plateau counts only network-limited rounds: STARTUP never ended, and every key frame went out at the STARTUP gain (2.9x the path) into its queue (closed loop, 2 Mbit, 200 ms: video on time 70%, key frames 24%). An app-limited sample that came back queued (TUNING.md 30) has filled the path: it ends STARTUP too, once a network-limited sample has been seen (not on the initial window's own queue, test_pacing).

## 54. the loss credit in bytes

`anliu.c`: bbr_on_ack

The send-rate credit (a sample with loss counts what was sent, not only what was delivered, so random loss does not drag the estimate down) took the send rate over the delivery rate. A burst (a key frame) leaves at up to the STARTUP gain and the bottleneck spreads it out: its send interval is a fraction of its ACKs', the two rates differed by 2.9x without any loss, and the credit put the estimate at 1.1..1.4x the link at 200..300 ms (closed loop, no random loss), which the STARTUP gain then tripled. Now the bytes sent over the sample's send interval against those delivered, capped at 1.5x as before. Simulation (FIFO, TBF and policers) and real network (F>G, emulated policer and TBF, 14 pairs against the previous version): audio +0.11 +-0.23, video -0.18 +-1.21, key frames -0.39 +-1.82 points, on-time video bitrate -0.00 +-1.13% - no regression.

## 55. an app-limited media stream behind a policer

`anliu.c`: bbr_policer (watching, the test, the probe's verdict)

A cloud host's egress policer (10 Mbit, a bucket of about 1 MB, a 1 Gbit line; real network) against an encoder wanting 19 Mbit: the key frames pass through the bucket at line rate, so burst_bw and the filter read 4-12 MB/s and the pace sits at 3-10x the policer's 1.2 MB/s. The detector saw the policer at 7 s (35-90% lost, delivery pinned at 1.2 MB/s) and confirmed it at 146 s, by luck: nearly every interval is app-limited - the pace is far above what the encoder produces - and all three stages required network-limited intervals. The detection intervals were discarded; a test interval paced at the policer's rate is app-limited too (the encoder follows the estimate down to it), so it failed and held off for 48 intervals (15 s); the probe's tail was underfed (the encoder cut back after the step's loss) and a first confirmation gave the ceiling up. Over the round: 20% of what was sent lost, video 96%, key frames 94%; once confirmed, pace at the rate and no retransmissions. The simulation of the same (1 Gbit line, 10 Mbit policer, 1 MB bucket, 20 ms, 180 s) never confirmed it: video 80.6%, key frames 149 of 180, 180k policer drops.

Three rules changed. An app-limited interval counts as a detection interval when over a quarter of what was sent was lost: what was delivered is then what the path took, whatever the sender had left over, and no random loss does that (over 10%, as for network-limited intervals, it was a small flow's 5% reading over 10% now and then, and the test's loss regressing to the mean passed it: a 5% random-loss unit test lost 5 frames of 243 to the false ceiling). An app-limited test interval counts when at least half the test rate was sent: random loss does not halve at any rate, and the probe that follows measures the ceiling; short of that it is no verdict, a hold of BBR_LT_SPAN rather than 48. A probe step or tail without enough offered load keeps the rate the test passed at as the ceiling until the next probe, for the first confirmation as for a retest (the probe's own 1/4 step was already seen to be lost when the tail is underfed). Same simulation: video 99.7%, key frames 179 of 180, 2k policer drops, wire bytes halved. Grid (10/12/30 Mbit policers, 64 KB and 1 MB buckets, 20/100 ms, 0/1% loss, 3 seeds): binding policers +8..+35 points of video and +5..+62 of key frames on time, drops down 70-99%; a 30 Mbit policer above the encoder's rate, a 30 Mbit FIFO at 0..3% and 10..15% random loss: unchanged to the byte. Real network (providers' policers, 1 Gbit lines, FEC off, encoder closed loop up to 19 Mbit, 2 seeds, variants alternating on each sender, 24 pairs): g5>t1 (10 Mbit) +100 ms, where the policer was never confirmed before - video 72 -> 97..98.7%, end-to-end loss 25..28% -> 1.2..2.7%; at +20 ms the same video (99%) with confirmation at 8..31 s instead of 7..53 (146 in an earlier round); t1>rb and rb>g5 (30 Mbit, not binding): no change. The rate it confirms can be low: at +100 ms the test rate is the detection intervals' delivery, which read 20-25% below what the link carried (simulation), and an app-limited encoder never fills a probe step to correct it (5.2..6.4 Mbit used of 10). Neither repeating an underfed step (1.25x the rate for seconds: 20 ms video 99 -> 87..94%) nor taking the previous step's delivery (the refilled bucket's: 1.1..1.5x the policer) helped; open.

## 56. the policer's rate from the peer's reports

`anliu.c`: bbr_policer, handle_report, write_report_seg, anl_input_plain (rx_net)

Dropping a frame (purge_frame: a frame expired, drop_until_key took the rest of its GOP in flight) takes its sent segments out of snd_buf, and those that still arrived are never acknowledged into delivered: behind a 10 Mbit policer with a 1 MB bucket at 100 ms the detection intervals read 772..853 kB/s while the path carried 22% more (per-packet audit), the test locked at 813 kB/s and the real network used 5.2..6.4 of 10 Mbit. The receiver now counts every data and parity segment that arrives (rx_net, the sent_wire estimate), whatever becomes of it, and every REPORT carries the count (rx_bytes, u32 after the 16 delay/FEC bytes; the development format now also requires a u16 sender timestamp echo, see 57). The sender advances prx_bytes / prx_ms on the newest report by the peer's clock only, and the detector's rate is prx_bytes over prx_ms when the reports cover at least half the interval, ACK-based otherwise. Reports are on by default for reliable streams too. Only the rate: kept on the sender (purged segments as ghosts, credited by SACK), the same delivery in BBR's samples and the encoder's target pushed the encoder past what expiring frames could carry (random loss at 100 ms: video 68 -> 32%), and its losses in the detector's made random loss look like a policer (fewer frames expire at a lower pace).
With the delivery right, the detection intervals of a stream that left STARTUP with a 1 MB bucket full read the bucket draining on top of the policer (2.0 MB/s on 1.5): the test failed and the 48-interval hold put confirmation off by 27 s. An initial test fed at its rate that delivered under 7/8 of both its rate and what it sent is repeated once at what it delivered; random loss over an eighth fails the retest as well.
Simulation (1 Gbit line, 10/12/30 Mbit policers, 64 KB / 1 MB buckets, 20/100 ms, 0/1% loss, 5 seeds, 120 s, against d57d4ee): binding policers at 100 ms video +0.80 +-1.44, key frames +1.21 +-1.39 points, timely video +280 +-264 kbps (12 Mbit / 1 MB: key frames +5.3); at 20 ms video -0.42 +-0.48, key frames -0.71 +-0.95; FIFO 20..200 ms at 0..3% and random loss 10..15%: unchanged to the byte. test_fec_capacity_recovery at 0..15%, 25 seeds: seeds 7, 9, 10 fail against 7, 11 before - a policer confirmed in the 800 kbps phase (a 7-packet FIFO's overflow halves at the test pace) whose probes the encoder cannot feed after the path recovers (open: the probe's offered load).


## 57. report sample boundaries and FIFO recovery

`anliu.c`: handle_report, bbr_report_age, bbr_lt_begin, bbr_policer

A cumulative report delta can span traffic from before a pace change or a long reporting gap. Comparing its elapsed receiver time with half the current interval does not establish coverage: a 1200 ms delta reported 1.625 MB/s for a 300 ms interval actually delivering 0.5 MB/s. REPORT now has a fixed 22-byte body: the eight delay/FEC u16 fields, rx_bytes (u32), and the receiver's latest sender timestamp (u16). This development format does not accept the old 16/20-byte bodies; ANL_VERSION remains 1. The echo is extended on the sender's clock and must be at or after the latest policer pace transition before a snapshot can seed a sample. Recent endpoints can be reused during a steady pace; after a gap or transition the first eligible snapshot is only a baseline. Report spans and endpoint ages are bounded, and insufficient coverage falls back to ACK delivery. The age allowance includes RTO_DEF: a receive-only peer has no ACK RTT and reports every 200 ms, even on a 20 ms path. Treating those normal reports as stale shortened the sample around key-frame bursts and regressed the policer grid. Interval resets share bbr_lt_begin, including skipped rounds and input-gap recovery.

The report-rate patch also made a shallow FIFO acquire a persistent low ceiling during capacity_short. At RTT 170 ms after 4 -> 0.8 -> 4 Mbit, seed 10 / 10% random loss and seed 9 / 15% both delivered zero timely video frames in the final 15 s; the pre-report baseline delivered 455/455 and 445/455. Do not start a new policer test during capacity_short: expiring frames and the source cutting back contaminate its loss-halving evidence, then shortage prevents feeding its recovery probes. Both cases are fixed and run as named regression tests, with the original recovery assertions. Of 25 seeds at 0/5/10/15%, only seed 7 / 10% retains the baseline's 626 ms of capacity_short in the final 10 s; its assertion is unchanged.

An initial media test can land between key frames after the encoder cuts back. One extra interval at the same test pace lets it obtain a supplied sample; a second underfed interval exits as before. This allowance is never applied to the above-rate probe. The original one-time lower-rate retest remains independent and bounded.

Validation against the report-rate patch before these fixes: 72 paired, FEC-off, 120 s policer simulations (10/12/30 Mbit, 64 KB / 1 MB buckets, RTT 20/100 ms, 0/1% random loss, seeds 1..3) have no video-timeliness regressions. At 100 ms the 10/12 Mbit groups improve by 2.26/2.72 percentage points on average; 20 ms video is unchanged except a small gain in one nonbinding 30 Mbit case. Release and ASan/UBSan CTest suites (including leak checks) pass, as do all 24 ASan media acceptance scenarios. New tests parse real report bodies through gaps, delayed pre-transition snapshots, idle resumption, and 16/32-bit clock wrap; they also check the bounded underfed-test retry. All configured random-loss scenarios and the simulation/real-network CLI limits are at most 15%; deliberate packet removal and complete-outage correctness tests remain separate fault injection.

FIFO check: 54 paired FEC-off scenarios at 30 Mbit, RTT 20/100/200 ms, 0/1/2/3/10/15% random loss and seeds 1..3. All FLOW output at 0..3% is identical. Three 10..15% cases change: video timeliness improves by 0.17..2.06 points, audio drops by 0.12..0.38 points; the 20 ms / 15% / seed 3 case loses one timely key frame (116 -> 115 of 120) and about 0.46 Mbit/s of timely video. These higher-loss tradeoffs are recorded rather than counted as unchanged. No real-network run was made for this revision.

## 58. a stall in the first probe step

`anliu.c`: bbr_policer (state 3)

A queue signal during the first confirmation's probe yields to ordinary congestion control and holds the detector off for 48 intervals: a FIFO bottleneck queues while it delivers its capacity. On the real network (g5>t1, a 10 Mbit provider policer, +20 ms) the intervals before confirmation, sent at 5..15 MB/s, also had stalls - a few hundred ms with 9..130 kB/s delivered and the RTT up - in both versions (slt 8, scx 12 in four rounds each, none after confirmation, none at +100 ms). One in the first probe step put confirmation off from 7..23 s to 32..49 s and doubled the end-to-end loss (0.2 -> 2.6%, 3.0 -> 6.7%). A queued interval that delivered under a quarter of the rate is now no verdict, as too little offered load is: the tested rate stands until the next probe. Simulation (policers 10/12/30 Mbit, 64 KB / 1 MB, 20/100 ms, 0/1%, 3 seeds; FIFO 20..200 ms at 0..3%): unchanged to the byte except 10 Mbit / 1 MB / 20 ms, video +1.9 and +3.2 points, key frames +2.2 and +3.9, policer drops -10k and -16k.
