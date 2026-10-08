"""Finite frozen Hill/affine-Hill THEN route probe. All worker pools are host-owned."""
import hashlib,json,random,sys,time
from pathlib import Path
import numpy as np
from affine_probe import block_data,configs as affine_configs,solve,trusted_ct
from hill_probe import AZ,KA,CRIBS,fit,rank,inverse,encrypt
from cryptolab.tools.hill_cipher import matrix_is_invertible
from cryptolab.research_bridge.cribsolve_perm import family,PERMUTATION_SETS,stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages

def scatter(s,pos):
    out=['']*len(s)
    for i,j in enumerate(pos):out[int(j)]=s[i]
    return ''.join(out)

def pullback(s,pos):return ''.join(s[int(j)] for j in pos)

def build_routes(out):
    labels,rows,aliases=family(PERMUTATION_SETS,tuple(range(2,49)),97)
    seen=set();bank=[];meta=[]
    for label,row in zip(labels,rows):
        for mode,perm in (('encode',row),('decode',np.argsort(row))):
            key=perm.tobytes()
            if key in seen:continue
            seen.add(key);bank.append(perm);meta.append({'label':label,'mode':mode})
    bank=np.asarray(bank,dtype=np.int16)
    np.save(out/'routes.npy',bank)
    (out/'routes.json').write_text(json.dumps(meta)+'\n')
    return bank,meta

def base_configs():
    allowed,dropped=affine_configs()
    return [('affine',list(cfg)) for cfg in allowed]+[('pure',list(cfg)) for cfg in dropped]

def reference_bank(p,affine):
    d=len(p[0])+int(affine);a=np.arange(26**d,dtype=np.int64)
    coeff=np.stack([(a//26**i)%26 for i in range(d)],axis=1).astype(np.int16)
    rows=[v+[1] if affine else v for v in p]
    signatures=((np.asarray(rows,dtype=np.int16)@coeff.T)%26).T.astype(np.uint8)
    lookup={v.tobytes():i for i,v in enumerate(signatures)}
    assert len(lookup)==26**d,'not an identifiable coefficient universe'
    return coeff,lookup,affine

def reference_solve(c,bank):
    coeff,lookup,affine=bank;cols=[]
    for j in range(len(c[0])):
        k=lookup.get(bytes(v[j] for v in c))
        if k is None:return None
        cols.append(coeff[k].tolist())
    z=[list(v) for v in zip(*cols)]
    m=z[:-1] if affine else z;b=z[-1] if affine else [0]*len(m)
    if not matrix_is_invertible(m):return None
    return m,b

def primary_key(p,c,affine):
    if affine:return solve(p,c)
    n=len(p[0]);parts=[]
    for q in (2,13):
        m,r=fit(p,c,q)
        if m is None or r!=n:return None
        parts.append(m)
    m=[[(13*parts[0][i][j]+14*parts[1][i][j])%26 for j in range(n)] for i in range(n)]
    if rank(m,2)!=n or rank(m,13)!=n:return None
    return m,[0]*n

def frame_check(prect,base,reference):
    kind,cfg=base;n,phase,pa,ca=cfg;starts,p=block_data(n,phase,pa)
    c=[[ca.index(prect[i]) for i in range(s,s+n)] for s in starts]
    key=primary_key(p,c,kind=='affine');ref=reference_solve(c,reference)
    assert key==ref,'independent/algebraic solver discrepancy'
    if key is None:return None
    m,b=key;nums=[ca.index(v) for v in prect];shifted=list(nums)
    for s in range(phase,97-n+1,n):
        for j in range(n):shifted[s+j]=(nums[s+j]-b[j])%26
    dec=encrypt(shifted,inverse(m),n,phase)
    covered={i for s in range(phase,97-n+1,n) for i in range(s,s+n)}
    if any(pa[dec[i]]!=v for i,v in CRIBS.items() if i in covered):return None
    decoded=''.join(pa[v] for v in dec)
    rebuilt=trusted_ct(dec,m,b,n,phase,ca)
    assert all(rebuilt[i]==prect[i] for i in covered)
    return {'kind':kind,'config':cfg,'matrix':m,'offset':b,'plaintext':decoded,'unconstrained_edges':sorted(set(range(97))-covered),'complete_crib_blocks':len(starts),'equation_redundancy':n*(len(starts)-n-int(kind=='affine'))}

def audit_routes(routes,meta):
    # Two A-Z digit strings together uniquely label every index; trusted-engine
    # application must agree with every frozen gather/scatter map, not just a sample.
    strings=[''.join(AZ[(i//26)%26] for i in range(97)),''.join(AZ[i%26] for i in range(97))]
    for pos,m in zip(routes,meta):
        assert sorted(map(int,pos))==list(range(97))
        stages=stages_for_label(m['label'],97)
        for s in strings:
            assert run_stages(stages,s,m['mode'])==scatter(s,pos),(m,'direction')
        # Independent modular-index implementation for the full skip arm.
        if m['label'].startswith('skip:'):
            raw=m['label'][5:];step,start=map(int,raw.replace('s','').split('o'))
            gather=[(start+j*step)%97 for j in range(97)]
            hand=np.empty(97,dtype=np.int16)
            for j,i in enumerate(gather):hand[i]=j
            if m['mode']=='decode':hand=np.argsort(hand)
            assert np.array_equal(hand,pos)
    return len(routes)

def controls(out):
    start=time.time();routes=np.load(out/'routes.npy');meta=json.loads((out/'routes.json').read_text());rng=random.Random(2026100503)
    audited=audit_routes(routes,meta);records=[]
    # Deterministic spread includes every first-origin family and encode/decode.
    representative={};last={}
    for i,m in enumerate(meta):
        key=(m['label'].split(':')[0],m['mode']);representative.setdefault(key,i);last[key]=i
    samples=sorted(set(representative.values())|set(last.values()))
    for base in base_configs():
        kind,cfg=base;n,phase,pa,ca=cfg;_,p=block_data(n,phase,pa);ref=reference_bank(p,kind=='affine')
        for t in range(200):
            idx=samples[t] if t<len(samples) else rng.randrange(len(routes));pos=routes[idx];mdata=meta[idx]
            while True:
                matrix=[[rng.randrange(26) for _ in range(n)] for _ in range(n)]
                if matrix_is_invertible(matrix):break
            b=[rng.randrange(26) for _ in range(n)] if kind=='affine' else [0]*n
            if t==0:matrix=[[int(i==j) for j in range(n)] for i in range(n)];b=[0]*n
            pt=[rng.randrange(26) for _ in range(97)]
            for i,v in CRIBS.items():pt[i]=pa.index(v)
            pre=trusted_ct(pt,matrix,b,n,phase,ca)
            # Full independent trusted engine generates the transformed plant.
            ct=run_stages(stages_for_label(mdata['label'],97),pre,mdata['mode'])
            restored=pullback(ct,pos);assert restored==pre
            result=frame_check(restored,base,ref)
            assert result and result['matrix']==matrix and result['offset']==b
            assert all(result['plaintext'][i]==pa[pt[i]] for s in range(phase,97-n+1,n) for i in range(s,s+n))
            assert scatter(pre,pos)==ct
        for t in range(200):
            ct=''.join(AZ[rng.randrange(26)] for _ in range(97));idx=rng.randrange(len(routes))
            assert frame_check(pullback(ct,routes[idx]),base,ref) is None
        records.append({'base':base,'positive_exact':200,'negative_random_rejected':200,'reference_enumerated_per_output':26**(n+int(kind=='affine'))})
    return {'passed':True,'audited_routes':audited,'records':records,'positive_plants':4000,'negative_checks':4000,'seconds':time.time()-start}

def target_task(task):
    outstr,base,indices=task;out=Path(outstr);routes=np.load(out/'routes.npy',mmap_mode='r');meta=json.loads((out/'routes.json').read_text())
    kind,cfg=base;n,phase,pa,ca=cfg;_,p=block_data(n,phase,pa);ref=reference_bank(p,kind=='affine')
    from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
    assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
    survivors=[];tested=0;start=time.time()
    for i in indices:
        if (out/'survivor-worker-stop.json').exists():break
        if time.time()>1791329400 or time.time()-start>3500:break
        result=frame_check(pullback(K4_CIPHERTEXT,routes[i]),base,ref);tested+=1
        if result:
            result['route_index']=i;result['route']=meta[i];survivors.append(result)
            try:
                with (out/'survivor-worker-stop.json').open('x') as f:f.write(json.dumps(result)+'\n')
            except FileExistsError:pass
            break
    return {'base':base,'tested':tested,'survivors':survivors,'seconds':time.time()-start}

if __name__=='__main__':
    out=Path(sys.argv[2])
    if sys.argv[1]=='bank':
        r,m=build_routes(out);print(json.dumps({'unique_routes':len(r),'base_configs':20,'configurations':20*len(r)}))
    elif sys.argv[1]=='controls':
        res=controls(out);(out/'controls.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps({k:v for k,v in res.items() if k!='records'}))
    elif sys.argv[1]=='benchmark':
        start=time.time();routes=np.load(out/'routes.npy');base=base_configs()[8];kind,cfg=base;n,phase,pa,ca=cfg;_,p=block_data(n,phase,pa);ref=reference_bank(p,True)
        rng=random.Random(100);text=''.join(AZ[rng.randrange(26)] for _ in range(97));t0=time.time()
        for pos in routes[:1000]:frame_check(pullback(text,pos),base,ref)
        print(json.dumps({'reference_seconds':t0-start,'1000_synthetic_frames_seconds':time.time()-t0,'predicted_one_worker_full_base_seconds':(time.time()-t0)*len(routes)/1000,'never_read_target':True}))
