#!/usr/bin/env python3
"""Shared-root scoped shaping for several concurrent rounds on one sender.
Root 6a0: prio (16 bands, unmatched traffic -> band 1, unshaped). Each round owns
one band 3..16 with its own TBF (burst 16k, latency 100 ms; above 100 Mbit burst 4 MB:
an "unlimited" round's band only counts) and one u32 filter
(pref 100+band) matching its peer IP and UDP source port. A host-wide lock
serializes changes; the root is removed when the last round releases its band.
--loss P (integer %): random loss in both directions on the sender alone - a
gact action on the round's egress filter (before its TBF) and an ingress u32
filter (pref 100+band) on datagrams from the peer to the round's port; the
same for any protocol, no in-application drop needed. gact netrand drops 1 in
VAL: VAL = round(100 / P), so 3% is 3.03%, 7% is 7.14%; clear prints the
counted packets and drops of both directions (LOSS_STATS).
Refuses to touch an interface whose root was not created by this script."""
import argparse,json,subprocess,time,pathlib,fcntl,re,os
p=argparse.ArgumentParser()
p.add_argument('action',choices=['setup','clear','deadman'])
p.add_argument('--dev',default='eth0');p.add_argument('--peer',required=True);p.add_argument('--port',type=int,required=True)
p.add_argument('--rate',type=int,default=2000);p.add_argument('--delay',type=int,default=0);p.add_argument('--hold',type=int,default=850);p.add_argument('--loss',type=int,default=0);p.add_argument('--burst',type=int,default=0);p.add_argument('--state',required=True)
p.add_argument('--queue-ms',type=int,default=100)   # the band's queue: 100 ms shapes; a few ms behaves like a policer (drops once the bucket is empty)
# --police: a token-bucket policer (tc police on the band's filter: --rate, bucket --burst, drops what
# exceeds, no queue) in front of a line of --line kbit (the band's TBF, its --queue-ms queue)
p.add_argument('--police',action='store_true');p.add_argument('--line',type=int,default=40000)
a=p.parse_args()
home=pathlib.Path.home();lockf=(home/'.anliu-multi-tc.lock').open('a');reg=home/'.anliu-multi-tc.json';state=pathlib.Path(a.state)
def tc(*x,check=True):
    r=subprocess.run(['sudo','-n','/usr/sbin/tc',*map(str,x)],capture_output=True,text=True)
    if check and r.returncode:raise RuntimeError(' '.join(map(str,x))+': '+r.stderr)
    return r.stdout
def roots():return [x for x in json.loads(tc('-j','qdisc','show','dev',a.dev)) if x.get('root')]
def load():return json.loads(reg.read_text()) if reg.exists() else {'dev':a.dev,'bands':{}}
def save(r):reg.write_text(json.dumps(r))
def locked(fn):
    fcntl.flock(lockf,fcntl.LOCK_EX)
    try:return fn()
    finally:fcntl.flock(lockf,fcntl.LOCK_UN)
def setup():
    if a.rate<1 or a.port<1024 or a.port>65535 or not 0<=a.loss<=20:raise RuntimeError('invalid rate/port/loss')
    if state.exists():raise RuntimeError('state exists')
    r=load();root=roots()
    if not r['bands']:
        if len(root)!=1 or root[0]['kind'] not in ('noqueue','pfifo_fast','fq_codel','mq'):raise RuntimeError('interface occupied: '+str(root))
        tc('qdisc','add','dev',a.dev,'root','handle','6a0:','prio','bands','16','priomap',*([1]*16))
        r={'dev':a.dev,'bands':{}}
    elif len(root)!=1 or root[0].get('handle')!='6a0:':raise RuntimeError('registry/root mismatch')
    used={int(b) for b in r['bands']}
    free=[b for b in range(3,17) if b not in used]
    if not free:raise RuntimeError('no free band')
    b=free[0]
    try:
        # --burst B (bytes): a bucket of about two datagrams lets nothing through at line rate -
        # a FIFO at the rate (queue: 100 ms of it plus the bucket) rather than a 16 KB shaper
        if a.police:tc('qdisc','add','dev',a.dev,'parent',f'6a0:{b:x}','handle',f'{0x6b0+b:x}:','tbf','rate',f'{a.line}kbit','burst','16k' if a.line<=100000 else '4mb','latency',f'{a.queue_ms}ms')
        else:tc('qdisc','add','dev',a.dev,'parent',f'6a0:{b:x}','handle',f'{0x6b0+b:x}:','tbf','rate',f'{a.rate}kbit','burst',str(a.burst) if a.burst else '16k' if a.rate<=100000 else '4mb','latency',f'{a.queue_ms}ms')
        if a.delay:
            # forward-only extra propagation for this round (child of its TBF)
            # the child holds the queue: limit it to queue_ms at the TBF rate plus what the delay line holds (1000-byte packets)
            lim=max(10,(a.line if a.police else a.rate)*(a.queue_ms+a.delay)//8//1000)
            tc('qdisc','add','dev',a.dev,'parent',f'{0x6b0+b:x}:1','handle',f'{0x7b0+b:x}:','netem','delay',f'{a.delay}ms','limit',lim)
        drop=['action','gact','pass','random','netrand','drop',round(100/a.loss)] if a.loss else []
        # the policer after the random loss: gact passes on to it (pipe) instead of ending the actions
        police=['action','police','rate',f'{a.rate}kbit','burst',str(a.burst or 65536),'mtu','64k','conform-exceed','drop/ok'] if a.police else []
        fwd=[('pipe' if x=='pass' and a.police else x) for x in drop]+police
        tc('filter','add','dev',a.dev,'protocol','ip','parent','6a0:','prio',100+b,'u32','match','ip','dst',a.peer+'/32','match','ip','protocol','17','0xff','match','ip','sport',a.port,'0xffff','flowid',f'6a0:{b:x}',*fwd)
        if a.loss:
            if not any(x.get('kind')=='ingress' for x in json.loads(tc('-j','qdisc','show','dev',a.dev))):tc('qdisc','add','dev',a.dev,'handle','ffff:','ingress')
            tc('filter','add','dev',a.dev,'parent','ffff:','protocol','ip','prio',100+b,'u32','match','ip','src',a.peer+'/32','match','ip','protocol','17','0xff','match','ip','dport',a.port,'0xffff',*drop)
    except Exception:
        tc('filter','del','dev',a.dev,'parent','6a0:','prio',100+b,check=False)
        tc('filter','del','dev',a.dev,'parent','ffff:','prio',100+b,check=False)
        tc('qdisc','del','dev',a.dev,'parent',f'6a0:{b:x}',check=False)
        if not r['bands']:tc('qdisc','del','dev',a.dev,'root',check=False)
        raise
    r['bands'][str(b)]={'peer':a.peer,'port':a.port,'rate':a.rate,'delay':a.delay,'loss':a.loss,'police':a.police,'state':str(state)}
    save(r);state.write_text(json.dumps({'band':b,'peer':a.peer,'port':a.port,'dev':a.dev,'rate':a.rate}))
    print('SETUP_OK band',b,flush=True)
def clear():
    if not state.exists():return
    s=json.loads(state.read_text());b=s['band'];r=load()
    ent=r['bands'].get(str(b))
    if not ent or ent['port']!=a.port or ent['peer']!=a.peer:raise RuntimeError('ownership mismatch')
    if ent.get('loss'):
        st={}
        for d,par in (('fwd','6a0:'),('rev','ffff:')):
            o=tc('-s','filter','show','dev',a.dev,'parent',par,'prio',100+b,check=False)
            m=re.search(r'Sent \d+ bytes (\d+) pkt \(dropped (\d+)',o)
            st[d]=(int(m.group(1)),int(m.group(2))) if m else (0,0)
        print('LOSS_STATS fwd_pkts %d fwd_drop %d rev_pkts %d rev_drop %d'%(*st['fwd'],*st['rev']),flush=True)
    if ent.get('police'):
        # the police action's counters: the last action of the forward filter
        o=tc('-s','filter','show','dev',a.dev,'parent','6a0:','prio',100+b,check=False)
        m=re.findall(r'Sent \d+ bytes (\d+) pkt \(dropped (\d+)',o)
        print('POLICE_STATS pkts %s drop %s'%(m[-1] if m else ('0','0')),flush=True)
    tc('filter','del','dev',a.dev,'parent','6a0:','prio',100+b,check=False)
    if ent.get('loss'):tc('filter','del','dev',a.dev,'parent','ffff:','prio',100+b,check=False)
    tc('qdisc','del','dev',a.dev,'parent',f'6a0:{b:x}',check=False)
    del r['bands'][str(b)]
    if not r['bands']:
        root=roots()
        if len(root)==1 and root[0].get('handle')=='6a0:':tc('qdisc','del','dev',a.dev,'root')
        if any(x.get('kind')=='ingress' for x in json.loads(tc('-j','qdisc','show','dev',a.dev))):tc('qdisc','del','dev',a.dev,'handle','ffff:','ingress',check=False)
    save(r);state.unlink();print('CLEARED band',b,flush=True)
if a.action=='setup':locked(setup)
elif a.action=='clear':locked(clear)
else:
    time.sleep(a.hold);locked(clear)
