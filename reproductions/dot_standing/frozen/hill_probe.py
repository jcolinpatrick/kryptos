"""Exact direct-frame Hill compatibility, campaign-only experimental instrument."""
import hashlib,json,random,time,sys
from pathlib import Path

AZ='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
KA='KRYPTOSABCDEFGHIJLMNQUVWXZ'
CRIBS={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))}

def reduce_rows(rows,p,width):
    a=[[x%p for x in row] for row in rows]; piv=[]; r=0
    for c in range(width):
        k=next((k for k in range(r,len(a)) if a[k][c]),None)
        if k is None: continue
        a[r],a[k]=a[k],a[r]; inv=pow(a[r][c],-1,p)
        a[r]=[x*inv%p for x in a[r]]
        for k in range(len(a)):
            if k!=r:
                factor=a[k][c]; a[k]=[(x-factor*y)%p for x,y in zip(a[k],a[r])]
        piv.append(c); r+=1
        if r==len(a): break
    return a,piv

def rank(a,p):
    return len(reduce_rows(a,p,len(a[0]))[1]) if a else 0

def fit(pt,ct,p):
    n=len(pt[0]); rows,piv=reduce_rows([a+b for a,b in zip(pt,ct)],p,n)
    if any(not any(row[:n]) and any(row[n:]) for row in rows): return None,len(piv)
    m=[[0]*n for _ in range(n)]
    for i,c in enumerate(piv): m[c]=rows[i][n:]
    return m,len(piv)

def encrypt(pt,m,n,phase):
    out=list(pt)
    for s in range(phase,len(pt)-n+1,n):
        for j in range(n): out[s+j]=sum(pt[s+k]*m[k][j] for k in range(n))%26
    return out

def inverse(m):
    n=len(m); parts=[]
    for p in (2,13):
        a,piv=reduce_rows([row+[int(i==j) for j in range(n)] for i,row in enumerate(m)],p,n)
        assert len(piv)==n
        parts.append([row[n:] for row in a])
    return [[(13*parts[0][i][j]+14*parts[1][i][j])%26 for j in range(n)] for i in range(n)]

def check(ct,n,phase,pa,ca,cribs=CRIBS):
    starts=[s for s in range(phase,len(ct)-n+1,n) if all(i in cribs for i in range(s,s+n))]
    pt=[[pa.index(cribs[i]) for i in range(s,s+n)] for s in starts]
    cc=[[ca.index(ct[i]) for i in range(s,s+n)] for s in starts]
    result={'n':n,'phase':phase,'pa':pa,'ca':ca,'blocks':len(starts),'ranks':[],'class':'rejected'}
    if not pt: result['class']='compatible_nonidentifiable'; return result
    parts=[]
    for prime in (2,13):
        m,r=fit(pt,cc,prime); result['ranks'].append(r)
        if m is None or rank(cc,prime)!=r: return result
        parts.append(m)
    if min(result['ranks'])<n: result['class']='compatible_nonidentifiable'; return result
    m=[[(13*parts[0][i][j]+14*parts[1][i][j])%26 for j in range(n)] for i in range(n)]
    nums=[ca.index(c) for c in ct]; dec=encrypt(nums,inverse(m),n,phase)
    covered=set(i for s in range(phase,len(ct)-n+1,n) for i in range(s,s+n))
    if any(pa[dec[i]]!=v for i,v in cribs.items() if i in covered): return result
    result.update({'class':'unique_compatible','matrix':m,'plaintext':''.join(pa[x] for x in dec),'unconstrained_edges':sorted(set(range(len(ct)))-covered)})
    return result

def configs():
    return [(n,phase,pa,ca) for n in (2,3,4) for phase in range(n) if n!=4 or phase in (1,2) for pa in (AZ,KA) for ca in (AZ,KA)]

def trusted_encrypt(pt,m,n,phase):
    from cryptolab.tools.hill_cipher import _mat_vec, matrix_is_invertible
    mt=[list(x) for x in zip(*m)]
    assert matrix_is_invertible(mt)
    out=list(pt)
    for s in range(phase,len(pt)-n+1,n): out[s:s+n]=_mat_vec(mt,pt[s:s+n])
    return out

def controls():
    start=time.time(); rng=random.Random(2026100501); records=[]
    for n,phase,pa,ca in configs():
        recovered=0; compatible=0
        for t in range(20):
            while True:
                m=[[rng.randrange(26) for _ in range(n)] for _ in range(n)]
                if rank(m,2)==n and rank(m,13)==n: break
            pt=[rng.randrange(26) for _ in range(97)]
            for i,c in CRIBS.items(): pt[i]=pa.index(c)
            ct=''.join(ca[x] for x in trusted_encrypt(pt,m,n,phase))
            result=check(ct,n,phase,pa,ca)
            assert result['class']!='rejected',result
            if result['class']=='unique_compatible':
                assert result['matrix']==m
                covered=[i for s in range(phase,97-n+1,n) for i in range(s,s+n)]
                assert all(result['plaintext'][i]==pa[pt[i]] for i in covered)
                recovered+=1
            else: compatible+=1
        # Additional independent random-known-span plants force every matrix recoverable.
        for t in range(20):
            while True:
                v=[rng.randrange(26) for _ in range(97)]
                random_cribs={i:pa[v[i]] for i in CRIBS}
                blocks=[[v[i] for i in range(s,s+n)] for s in range(phase,97-n+1,n) if all(i in random_cribs for i in range(s,s+n))]
                if rank(blocks,2)==n and rank(blocks,13)==n: break
            ct=''.join(ca[x] for x in trusted_encrypt(v,m,n,phase))
            result=check(ct,n,phase,pa,ca,random_cribs)
            assert result['class']=='unique_compatible' and result['matrix']==m
        records.append({'config':[n,phase,pa,ca],'true_crib_plants':20,'exact':recovered,'compatible':compatible,'random_span_exact':20})
    return {'passed':True,'plants':40*len(configs()),'seconds':time.time()-start,'records':records}

if __name__=='__main__':
    root=Path(sys.argv[2]); root.mkdir(exist_ok=True)
    if sys.argv[1]=='controls': result=controls()
    else:
        assert json.loads((root/'controls.json').read_text())['passed']
        assert json.loads((root/'review-approved.json').read_text())['approved']
        from cryptolab.research_bridge.k4 import K4_CIPHERTEXT,K4_SHA256
        assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()==K4_SHA256
        result={'rows':[check(K4_CIPHERTEXT,*cfg) for cfg in configs()]}
    (root/(sys.argv[1]+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result if sys.argv[1]!='controls' else {'passed':True,'plants':result['plants'],'seconds':result['seconds']}))
