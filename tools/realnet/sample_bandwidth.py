#!/usr/bin/env python3
"""Read just this run's TBF counters on the sender's monotonic clock.
Usage: sample_bandwidth.py SENDER_LOG DURATION_S DEV [TBF_HANDLE, default 40:]"""
import json,re,subprocess as sp,sys,time
from pathlib import Path
log=Path(sys.argv[1]);duration=int(sys.argv[2]);dev=sys.argv[3];handle=sys.argv[4] if len(sys.argv)>4 else '40:'
def snapshot(start,target):
 lo=time.monotonic_ns()/1000
 rows=json.loads(sp.check_output(['tc','-s','-j','qdisc','show','dev',dev],timeout=5))
 hi=time.monotonic_ns()/1000
 row=next(r for r in rows if r['handle']==handle and r['kind']=='tbf')
 print(json.dumps(dict(event='sample',target_s=target,mono_lo_us=lo,mono_hi_us=hi,offset_s=((lo+hi)/2-start)/1e6,**row)),flush=True)
end=time.monotonic()+40
while time.monotonic()<end:
 if log.exists():
  s=log.read_text(errors='replace')
  m=re.search(r'^TIMEBASE event=traffic_start event_mono_us=(\d+)',s,re.M)
  if m:break
 time.sleep(.05)
else:raise RuntimeError('sender traffic start marker missing')
start=int(m[1]);print(json.dumps(dict(event='window',start_mono_us=start,duration_s=duration)),flush=True)
for target in range(0,duration+1,10):
 delay=(start+target*1000000-time.monotonic_ns()/1000)/1000000
 if delay>0:time.sleep(delay)
 snapshot(start,target)
