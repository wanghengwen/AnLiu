#!/usr/bin/env python3
"""Shared pieces of the real-network rounds: ssh, the event log, metrics."""
import gzip, hashlib, json, re, shlex, subprocess as sp, threading, time
from hosts import WORK

DUR = 600
SSH = ['ssh', '-x', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12', '-o', 'ServerAliveInterval=10',
       '-o', 'ServerAliveCountMax=3', '-o', 'ControlMaster=auto', '-o', 'ControlPath=/tmp/anliu-rn-%C',
       '-o', 'ControlPersist=900']
q = shlex.quote
_mutex = threading.Lock()


def event(kind, **kw):
    line = json.dumps(dict(time=time.strftime('%FT%T%z'), kind=kind, **kw), ensure_ascii=False) + '\n'
    with _mutex:
        with (WORK / 'events.jsonl').open('a') as f:
            __import__('fcntl').flock(f, __import__('fcntl').LOCK_EX); f.write(line)


def ssh(h, command, timeout=45, check=True, retries=4):
    """run command on host h (a hosts.load() entry); transport errors (rc 255) are retried"""
    for attempt in range(retries):
        try:
            r = sp.run(SSH + [h['ssh'], command], capture_output=True, timeout=timeout)
        except sp.TimeoutExpired as e:
            r = sp.CompletedProcess(e.cmd, 255, e.stdout or b'', b'local SSH timeout')
        if r.returncode != 255:
            break
        event('ssh_transport_error', host=h['name'], stderr=r.stderr.decode(errors='replace')[-300:],
              command_sha256=hashlib.sha256(command.encode()).hexdigest())
        if attempt < retries - 1:
            time.sleep(15)
    if check and r.returncode:
        raise RuntimeError(f"{h['name']} SSH rc={r.returncode}: {r.stderr.decode(errors='replace')[-300:]}")
    return r


def upload(h, src, dst):
    sp.run(['scp', '-q', '-o', 'BatchMode=yes', str(src), h['ssh'] + ':' + dst], check=True, timeout=120)


def fetch(h, path, timeout=300):
    """a remote file's content, retried when the transfer is cut"""
    for attempt in range(4):
        try:
            return gzip.decompress(ssh(h, 'gzip -c ' + q(path), timeout=timeout).stdout)
        except (EOFError, OSError, RuntimeError):
            if attempt == 3:
                raise
            time.sleep(20)


def save_meta(path, meta):
    tmp = path.with_suffix('.json.tmp'); tmp.write_text(json.dumps(meta, indent=2) + '\n'); tmp.replace(path)


def fields(line):
    return {k: v for k, v in re.findall(r'([\w]+)=([^\s]+)', line)}


def metrics(meta, s, c, manifest_files):
    """the round's media metrics from the sender (s) and receiver (c) logs; errors: why it is invalid"""
    sender=s if meta['direction']=='down' else c
    receiver=c if meta['direction']=='down' else s
    errors=[]
    for role,t in [('srv',s),('cli',c)]:
        if not re.search(r'^HEALTH state=0 input_errors=0 output_errors=0 payload_errors=0 ',t,re.M): errors.append(f'{role} unhealthy or incomplete')
        for name,label in [('anliu.c','../anliu.c'),('anliu.h','../anliu.h'),('bench/realnet.c','realnet.c')]:
            if not re.search(r'^'+manifest_files[name]+r'\s+'+re.escape(label)+r'$',t,re.M): errors.append(f'{role} source mismatch {name}')
    ping=re.search(r'^PATH ping .*replies=(\d+)/20',c,re.M)
    if not ping or int(ping[1])==0: errors.append('zero/missing ping')
    def start(t):
        m=re.search(r'^TIMEBASE event=traffic_start .*wall_us=(\d+)',t,re.M)
        return int(m[1]) if m else None
    if not start(s) or not start(c) or start(s)>start(c): errors.append('missing/late server start')
    row={k:meta[k] for k in ['tag','sender','receiver','workload','rate_kbps','duration_s']}
    row['ping']=ping[0] if ping else None
    fec=re.search(r'^FECCOST total (.*)$',sender,re.M)
    if fec:
        v=fields(fec[1])
        for key,out in [('proto_bytes','protocol_kbps'),('parity_seg_bytes','parity_kbps'),('retrans_seg_bytes','retrans_kbps')]: row[out]=round(int(v.get(key,0))*8/DUR/1000,3)
    else: errors.append('sender FECCOST absent')
    wire=re.search(r'^SENDER anl wire_kbps=(\S+)',sender,re.M)
    row['wire_kbps']=float(wire[1]) if wire else None
    if meta['workload']=='media':
        sent={};received={}
        for line in sender.splitlines():
            if line.startswith('MDIAG_S '):
                v=list(map(int,line.split()[1:]));sent[tuple(v[:2])]=v
        for line in receiver.splitlines():
            if line.startswith('MDIAG_R '):
                v=list(map(int,line.split()[1:]));received[tuple(v[:2])]=v
        for f,name,budget in [(1,'audio',150000),(2,'video',300000)]:
            keys=[k for k in sent if k[0]==f]
            if len(keys)!=DUR*(50 if f==1 else 30): errors.append(f'incomplete source generation: {name}')
            mn=min((v[5] for k,v in received.items() if k[0]==f),default=0)
            good=[k for k in keys if k in received and received[k][5]-mn<=budget]
            delays=sorted((received[k][5]-mn)/1000 for k in keys if k in received)
            kk=[k for k in keys if sent[k][2]]
            row[name]={'generated':len(keys),'received':sum(k in received for k in keys),'ontime_pct':round(100*len(good)/max(1,len(keys)),3),
                       'timely_payload_kbps':round(sum(sent[k][3] for k in good)*8/DUR/1000,3),
                       'extra_delay_p95_ms':delays[int(.95*(len(delays)-1))] if delays else None,
                       'keys_generated':len(kk),'keys_ontime':sum(k in good for k in kk)}
        a=re.search(r'^ADAPTSUM .*mean_scale=(\d+)',sender,re.M)
        row['encoder_mean_pct']=int(a[1])/10 if a else None
    else:
        r=re.search(r'^RESULT anl stream (.*)$',receiver,re.M)
        if not r: errors.append('stream result absent')
        else:
            v=fields(r[1]);row['stream']={k:float(v[k]) for k in ['avg_Mbps','min_Mbps','p10_Mbps','p50_Mbps','max_Mbps']}
            row['stream']['bytes']=int(v['bytes'])
            row['stream']['utilization_pct']=round(row['stream']['avg_Mbps']*1000/meta['rate_kbps']*100,2) if meta['rate_kbps'] else None
            if int(v.get('secs',0))!=DUR: errors.append('incomplete stream duration')
        health=re.search(r'^HEALTH (.*)$',receiver,re.M)
        checked=int(fields(health[1]).get('checked_bytes',0)) if health else 0
        row['checked_bytes']=checked
        if checked<=0: errors.append('reliable payload not verified')
        gap=re.search(r'^BULKGAP (.*)$',receiver,re.M)
        if gap: row['stream_gaps']=fields(gap[1])
    row['errors']=errors
    return row,errors


def more_metrics(meta,s,c,bw,row,errors):
 row['loss_pct']=meta['loss_pct']
 sender=s if meta['direction']=='down' else c
 receiver=c if meta['direction']=='down' else s
 losses={}
 for role,t in [('sender',sender),('receiver',receiver)]:
  mm=re.search(r'^RXLOSS (.*)$',t,re.M)
  conf=re.search(r'^RXLOSS_CONFIG probability_pct=(\S+)',t,re.M)
  if not mm or not conf or float(conf[1])!=meta['loss_pct']:
   errors.append(f'{role} RXLOSS configuration/counters missing');continue
  v=fields(mm[1]);n=int(v['proto_packets']);d=int(v['dropped_packets'])
  losses[role]=dict(packets=n,dropped=d,observed_pct=round(100*d/max(1,n),3))
 row['receive_loss']=losses
 costs={}
 for role,t in [('sender',sender),('receiver',receiver)]:
  mm=re.search(r'^DATAGRAM_COST (.*)$',t,re.M)
  if not mm:errors.append(f'{role} datagram counters missing');continue
  costs[role]={k:int(v) for k,v in fields(mm[1]).items()}
 row['datagram_cost']=costs
 row['reverse_ipudp_kbps']=round(costs.get('receiver',{}).get('tx_ipudp_bytes',0)*8/600/1000,3)
 fec=re.search(r'^FECCOST total (.*)$',sender,re.M)
 if fec:
  v={k:int(v) for k,v in fields(fec[1]).items()};row['fec_total']=v
  row['fec_over_first_pct']=round(100*v['parity_seg_bytes']/max(1,v['first_seg_bytes']),3)
  row['retrans_over_first_pct']=round(100*v['retrans_seg_bytes']/max(1,v['first_seg_bytes']),3)
  if v.get('errors'):errors.append('FEC accounting errors')
 row['fec_by_flow']={}
 for tag,name in [(1,'audio'),(2,'video')]:
  mm=re.search(r'^FECCOST tag='+str(tag)+r' (.*)$',sender,re.M)
  if mm:row['fec_by_flow'][name]={k:int(v) for k,v in fields(mm[1]).items()}
 for f,name in [(1,'audio'),(2,'video')]:
  sent=[list(map(int,l.split()[1:])) for l in sender.splitlines() if l.startswith(f'MDIAG_S {f} ')]
  row[name]['generated_payload_kbps']=round(sum(v[3] for v in sent)*8/600/1000,3)
  row[name]['received_pct']=round(100*row[name]['received']/max(1,row[name]['generated']),3)
  row[name]['keys_ontime_pct']=round(100*row[name]['keys_ontime']/max(1,row[name]['keys_generated']),3)
 rows=[json.loads(l) for l in bw.splitlines()];samples=[r for r in rows if r['event']=='sample']
 if len(samples)!=61 or [r['target_s'] for r in samples]!=list(range(0,601,10)):
  errors.append('incomplete TBF samples');return
 first,last=samples[0],samples[-1]
 elapsed=last['offset_s']-first['offset_s'];nbytes=last['bytes']-first['bytes']
 if elapsed<598 or elapsed>602 or first['offset_s']<0 or first['offset_s']>2:
  errors.append('TBF sampler window misaligned')
 if any(b['bytes']<a['bytes'] for a,b in zip(samples,samples[1:])):errors.append('TBF counter reset')
 intervals=[(b['bytes']-a['bytes'])*8/1000/(b['offset_s']-a['offset_s']) for a,b in zip(samples,samples[1:])]
 avg=nbytes*8/1000/elapsed
 row['actual_bandwidth']=dict(tc_bytes=nbytes,interval_s=round(elapsed,6),start_offset_s=round(first['offset_s'],6),mean_kbps=round(avg,3),peak_10s_kbps=round(max(intervals),3),utilization_pct=round(avg/meta['rate_kbps']*100,3),packets=last['packets']-first['packets'],queue_drops=last['drops']-first['drops'],overlimits=last['overlimits']-first['overlimits'],counter_scope='matched sender TBF Linux qdisc accounted bytes, excludes SSH')
 row['errors']=errors
