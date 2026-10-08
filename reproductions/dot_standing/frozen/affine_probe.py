"""Campaign-only fixed-affine Hill probe with an independent exhaustive equation solver."""
import hashlib,json,random,sys,time
from pathlib import Path
import numpy as np
from hill_probe import AZ,KA,CRIBS,fit,rank,inverse,encrypt

def encode(p,m,b):
    return [[(sum(v[k]*m[k][j] for k in range(len(m)))+b[j])%26 for j in range(len(m))] for v in p]

def solve(p,c):
    n=len(p[0]); parts=[]
    for prime in (2,13):
        m,r=fit([v+[1] for v in p],c,prime)
        if m is None or r!=n+1:return None
        parts.append(m)
    z=[[(13*parts[0][i][j]+14*parts[1][i][j])%26 for j in range(n)] for i in range(n+1)]
    m=z[:n]; b=z[n]
    if rank(m,2)!=n or rank(m,13)!=n:return None
    return m,b

def block_data(n,phase,pa):
    starts=[s for s in range(phase,97-n+1,n) if all(i in CRIBS for i in range(s,s+n))]
    return starts,[[pa.index(CRIBS[i]) for i in range(s,s+n)] for s in starts]

def configs():
    allowed=[]; dropped=[]
    for n in (2,3):
        for phase in range(n):
            for pa in (AZ,KA):
                _,p=block_data(n,phase,pa); ranks=[rank([v+[1] for v in p],q) for q in (2,13)]
                for ca in (AZ,KA):
                    entry=(n,phase,pa,ca)
                    (allowed if min(ranks)==n+1 else dropped).append(entry)
    return allowed,dropped

def exhaustive_predictions(p):
    d=len(p[0])+1
    a=np.arange(26**d,dtype=np.int64)
    coeff=np.stack([(a//(26**i))%26 for i in range(d)],axis=1).astype(np.int16)
    pred=(np.asarray([v+[1] for v in p],dtype=np.int16)@coeff.T)%26
    return coeff,pred

def brute(p,c,bank=None):
    coeff,pred=bank if bank is not None else exhaustive_predictions(p)
    cols=[]
    for j in range(len(c[0])):
        hit=np.flatnonzero(np.all(pred==np.asarray([v[j] for v in c],dtype=np.int16)[:,None],axis=0))
        if len(hit)!=1:return None
        cols.append(coeff[hit[0]].tolist())
    z=[list(v) for v in zip(*cols)]; m=z[:-1]; b=z[-1]
    from cryptolab.tools.hill_cipher import matrix_is_invertible
    if not matrix_is_invertible(m):return None
    return m,b

def check(ct,cfg,bank=None):
    n,phase,pa,ca=cfg; starts,p=block_data(n,phase,pa)
    c=[[ca.index(ct[i]) for i in range(s,s+n)] for s in starts]
    answer=solve(p,c); independent=brute(p,c,bank)
    assert answer==independent,'primary/exhaustive mismatch'
    row={'config':cfg,'class':'rejected','independent_agreement':True}
    if answer is None:return row
    m,b=answer; nums=[ca.index(v) for v in ct]
    shifted=list(nums)
    for s in range(phase,97-n+1,n):
        for j in range(n):shifted[s+j]=(nums[s+j]-b[j])%26
    dec=encrypt(shifted,inverse(m),n,phase)
    covered={i for s in range(phase,97-n+1,n) for i in range(s,s+n)}
    if any(pa[dec[i]]!=v for i,v in CRIBS.items() if i in covered):return row
    vectors=[dec[s:s+n] for s in range(phase,97-n+1,n)]
    assert encode(vectors,m,b)==[nums[s:s+n] for s in range(phase,97-n+1,n)]
    row.update({'class':'survivor','matrix':m,'offset':b,'plaintext':''.join(pa[v] for v in dec),'unconstrained_edges':sorted(set(range(97))-covered)})
    return row

def trusted_ct(pt,m,b,n,phase,ca):
    from cryptolab.tools.hill_cipher import _mat_vec
    mt=[list(v) for v in zip(*m)]; out=list(pt)
    for s in range(phase,97-n+1,n):
        v=_mat_vec(mt,pt[s:s+n]); out[s:s+n]=[(x+y)%26 for x,y in zip(v,b)]
    return ''.join(ca[v] for v in out)

def controls():
    start=time.time(); rng=random.Random(2026100502); records=[]
    allowed,dropped=configs()
    for cfg in allowed:
        n,phase,pa,ca=cfg; _,p=block_data(n,phase,pa); bank=exhaustive_predictions(p)
        for t in range(200):
            while True:
                m=[[rng.randrange(26) for _ in range(n)] for _ in range(n)]
                if rank(m,2)==n and rank(m,13)==n:break
            b=[rng.randrange(26) for _ in range(n)]
            if t==0:m=[[int(i==j) for j in range(n)] for i in range(n)]; b=[0]*n
            elif t==1:b=[0]*n
            pt=[rng.randrange(26) for _ in range(97)]
            for i,c in CRIBS.items():pt[i]=pa.index(c)
            row=check(trusted_ct(pt,m,b,n,phase,ca),cfg,bank)
            assert row['class']=='survivor' and row['matrix']==m and row['offset']==b
            assert all(row['plaintext'][i]==pa[pt[i]] for s in range(phase,97-n+1,n) for i in range(s,s+n))
        null=0
        for t in range(200):
            ct=''.join(ca[rng.randrange(26)] for _ in range(97))
            if check(ct,cfg,bank)['class']=='survivor':null+=1
        assert null==0,'unexpected random control survivor; target gate closed'
        m=[[0]*n for _ in range(n)]; b=[25]*n
        assert check(trusted_ct(pt,m,b,n,phase,ca),cfg,bank)['class']=='rejected'
        records.append({'config':cfg,'positive_exact':200,'random_negatives_rejected':200,'singular_rejected':1,'independent_exhaustive_agreement':True})
    return {'passed':True,'records':records,'dropped':dropped,'positive_plants':200*len(allowed),'negative_random':200*len(allowed),'seconds':time.time()-start}

if __name__=='__main__':
    out=Path(sys.argv[2])
    if sys.argv[1]=='controls':res=controls()
    else:
        assert json.loads((out/'review-approved.json').read_text())['approved']
        assert json.loads((out/'controls.json').read_text())['passed']
        from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
        assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
        allowed,dropped=configs(); res={'rows':[check(K4_CIPHERTEXT,cfg) for cfg in allowed],'dropped':dropped}
    (out/(sys.argv[1]+'.json')).write_text(json.dumps(res,indent=2)+'\n')
    print(json.dumps({k:v for k,v in res.items() if k!='records'}))
