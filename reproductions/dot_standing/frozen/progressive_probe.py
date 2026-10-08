"""Frozen progressive additive key class, followed by a finite frozen route."""
import hashlib,json,random,sys,time
from pathlib import Path
import numpy as np
from hill_probe import AZ,KA,CRIBS,rank,reduce_rows
from routed_probe import scatter,pullback
from cryptolab.research_bridge.cribsolve_perm import stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages

POSITIONS=sorted(CRIBS)

def design(kind,p):
    d=2*p if kind=='specific' else p+1
    a=[]
    for i in POSITIONS:
        row=[0]*d;r=i%p;q=i//p;row[r]=1;row[p+r if kind=='specific' else p]=q;a.append(row)
    return a

def period_lists():
    specific=[p for p in range(1,9) if all(rank(design('specific',p),q)==2*p for q in (2,13))]
    global_p=[p for p in range(1,13) if p not in specific and all(rank(design('global',p),q)==p+1 for q in (2,13))]
    return specific,global_p

def configs():
    a,b=period_lists()
    return [[kind,p,pa,ca,sign] for kind,periods in (('specific',a),('global',b)) for p in periods for pa in (AZ,KA) for ca in (AZ,KA) for sign in (1,-1)]

def primary_prepare(cfg):
    kind,p,pa,ca,sign=cfg;a=design(kind,p);d=len(a[0]);left=[]
    for q in (2,13):
        rows,piv=reduce_rows([v+[int(i==j) for j in range(24)] for i,v in enumerate(a)],q,d)
        assert len(piv)==d
        left.append(np.asarray([rows[i][d:] for i in range(d)],dtype=np.int16))
    return np.asarray(a,dtype=np.int16),left

def primary_key(ct,cfg,prepared):
    kind,p,pa,ca,sign=cfg;a,left=prepared
    y=np.asarray([(ca.index(ct[i])-sign*pa.index(CRIBS[i]))%26 for i in POSITIONS],dtype=np.int16)
    z2=(left[0]@y)%2;z13=(left[1]@y)%13;k=(13*z2+14*z13)%26
    if np.any((a@k-y)%26):return None
    return k.tolist()

def reference_prepare(cfg):
    # Independently derive q/residue groups directly from the known numeric indices.
    kind,p,*_=cfg;groups=[[i for i in range(21,34) if i%p==r]+[i for i in range(63,74) if i%p==r] for r in range(p)]
    if kind=='specific':
        maps=[]
        for indices in groups:
            table={bytes((a+b*(i//p))%26 for i in indices):(a,b) for a in range(26) for b in range(26)}
            assert len(table)==676
            maps.append(table)
        return groups,maps
    first={i:indices[0] for indices in groups for i in indices}
    order=list(range(21,34))+list(range(63,74))
    table={bytes((b*(i//p-first[i]//p))%26 for i in order):b for b in range(26)}
    assert len(table)==26
    return groups,(table,first,order)

def reference_key(ct,cfg,prepared):
    # Own alphabet dictionaries and crib construction; no primary residual helper.
    kind,p,pa,ca,sign=cfg;groups,table=prepared
    pindex={ch:j for j,ch in enumerate(pa)};cindex={ch:j for j,ch in enumerate(ca)}
    known=dict(enumerate('EASTNORTHEAST',21));known.update(dict(enumerate('BERLINCLOCK',63)))
    y={i:(cindex[ct[i]]-sign*pindex[ch])%26 for i,ch in known.items()}
    if kind=='specific':
        ab=[t.get(bytes(y[i] for i in indices)) for indices,t in zip(groups,table)]
        if any(v is None for v in ab):return None
        return [v[0] for v in ab]+[v[1] for v in ab]
    lookup,first,order=table;b=lookup.get(bytes((y[i]-y[first[i]])%26 for i in order))
    if b is None:return None
    return [(y[indices[0]]-b*(indices[0]//p))%26 for indices in groups]+[b]

def control_encode(pt,cfg,key):
    # Independent full-text direct encoder. No matrix, fitted rows or reference lookup.
    kind,period,palphabet,calphabet,sign=cfg
    output=[]
    for position,letter in enumerate(pt):
        quotient,remainder=divmod(position,period)
        base=key[remainder];slope=key[period+remainder] if kind=='specific' else key[period]
        output.append(calphabet[(sign*palphabet.index(letter)+base+quotient*slope)%26])
    return ''.join(output)

def compare_keys(ct,cfg,primary,reference):
    a=primary_key(ct,cfg,primary);b=reference_key(ct,cfg,reference)
    assert a==b,'primary/reference key discrepancy'
    return a

def decode(ct,cfg,key):
    kind,p,pa,ca,sign=cfg
    return ''.join(pa[(sign*(ca.index(ch)-key[i%p]-(key[p+i%p] if kind=='specific' else key[p])*(i//p)))%26] for i,ch in enumerate(ct))

def controls(out):
    started=time.time();routes=np.load(out/'routes.npy');meta=json.loads((out/'routes.json').read_text());rng=random.Random(2026100504)
    first={};last={}
    for i,m in enumerate(meta):
        k=(m['label'].split(':')[0],m['mode']);first.setdefault(k,i);last[k]=i
    samples=sorted(set(first.values())|set(last.values()));records=[]
    for cfg in configs():
        kind,p,pa,ca,sign=cfg;a=design(kind,p);d=len(a[0]);primary=primary_prepare(cfg);reference=reference_prepare(cfg)
        # A known out-of-family perturbation: remaining crib equations retain full
        # rank at both primes, fixing the original key before a changed heldout row.
        miss=next(j for j in range(24) if all(rank(a[:j]+a[j+1:],q)==d for q in (2,13)))
        for t in range(200):
            key=[rng.randrange(26) for _ in range(d)]
            if t==0:key=[0]*d
            elif t==1:key=[13]*d
            pt=[rng.choice(pa) for _ in range(97)]
            for i,ch in CRIBS.items():pt[i]=ch
            pt=''.join(pt);pre=control_encode(pt,cfg,key)
            idx=samples[t] if t<len(samples) else rng.randrange(len(routes));m=meta[idx]
            transformed=run_stages(stages_for_label(m['label'],97),pre,m['mode'])
            restored=pullback(transformed,routes[idx]);assert restored==pre
            recovered=compare_keys(restored,cfg,primary,reference);assert recovered==key
            decoded=decode(restored,cfg,recovered);assert decoded==pt
            assert scatter(control_encode(decoded,cfg,recovered),routes[idx])==transformed
            changed=list(pre);i=POSITIONS[miss];changed[i]=ca[(ca.index(changed[i])+1)%26]
            altered=run_stages(stages_for_label(m['label'],97),''.join(changed),m['mode'])
            assert compare_keys(pullback(altered,routes[idx]),cfg,primary,reference) is None
        for t in range(200):
            text=''.join(rng.choice(ca) for _ in range(97));idx=rng.randrange(len(routes))
            assert compare_keys(pullback(text,routes[idx]),cfg,primary,reference) is None
        records.append({'config':cfg,'unknowns':d,'crib_equations':24,'equation_redundancy':24-d,'positive_exact':200,'random_rejected':200,'guaranteed_out_of_class_near_miss_rejected':200,'near_miss_position':POSITIONS[miss],'remaining_rows_full_rank_mod2_and13':True})
    return {'passed':True,'periods_specific':period_lists()[0],'periods_global':period_lists()[1],'records':records,'positive_plants':19200,'random_negatives':19200,'near_miss_negatives':19200,'seconds':time.time()-started}

def target_task(task):
    outstr,cfg,indices=task;out=Path(outstr);start=time.time()
    if start>=1791329400:return {'config':cfg,'tested':0,'survivors':[],'seconds':0}
    routes=np.load(out/'routes.npy',mmap_mode='r');meta=json.loads((out/'routes.json').read_text());primary=primary_prepare(cfg);reference=reference_prepare(cfg)
    from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
    assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
    tested=0;survivors=[]
    for idx in indices:
        if (out/'survivor-worker-stop.json').exists() or time.time()>=1791329400 or time.time()-start>3500:break
        pre=pullback(K4_CIPHERTEXT,routes[idx]);key=compare_keys(pre,cfg,primary,reference);tested+=1
        if key is not None:
            pt=decode(pre,cfg,key);assert all(pt[i]==ch for i,ch in CRIBS.items())
            assert scatter(control_encode(pt,cfg,key),routes[idx])==K4_CIPHERTEXT
            m=meta[idx]
            assert run_stages(stages_for_label(m['label'],97),control_encode(pt,cfg,key),m['mode'])==K4_CIPHERTEXT
            survivor={'config':cfg,'key':key,'route_index':idx,'route':m,'plaintext':pt,'equation_redundancy':24-len(key),'full97letter_reencode':True,'is_solution':False}
            survivors.append(survivor)
            try:
                with (out/'survivor-worker-stop.json').open('x') as f:f.write(json.dumps(survivor)+'\n')
            except FileExistsError:pass
            break
    return {'config':cfg,'tested':tested,'survivors':survivors,'seconds':time.time()-start}

if __name__=='__main__':
    out=Path(sys.argv[2])
    if sys.argv[1]=='controls':
        res=controls(out);(out/'controls.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps({k:v for k,v in res.items() if k!='records'}))
    elif sys.argv[1]=='benchmark':
        cfg=['specific',8,AZ,KA,1];primary=primary_prepare(cfg);reference=reference_prepare(cfg);rng=random.Random(123);text=''.join(rng.choice(AZ) for _ in range(97));routes=np.load(out/'routes.npy');start=time.time()
        for row in routes[:1000]:compare_keys(pullback(text,row),cfg,primary,reference)
        print(json.dumps({'1000_synthetic_frames_seconds':time.time()-start,'predicted_single_worker_full_seconds':(time.time()-start)*len(routes)*len(configs())/1000,'no_target_read':True}))
