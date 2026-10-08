"""Hill-2 compatibility core: no target ciphertext import or search entry point."""
import itertools, math
import numpy as np
from hill_probe import AZ, KA, CRIBS, inverse, trusted_encrypt

REFERENCE_CRIBS={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))}
UNIT_INVERSE=np.asarray([pow(x,-1,26) if math.gcd(x,26)==1 else -1 for x in range(26)],dtype=np.int16)
WEIGHTS=np.asarray([26**i for i in range(11)],dtype=np.uint64)
_PRIMARY={};_REFERENCE={}

def configs():return [(phase,pa,ca) for phase in (0,1) for pa in (AZ,KA) for ca in (AZ,KA)]

def _geometry(cfg,known):
    phase,pa,ca=cfg
    full=[s for s in range(phase,96,2) if s in known and s+1 in known]
    partial=sorted({phase+2*((i-phase)//2) for i in known if not all(j in known for j in (phase+2*((i-phase)//2),phase+2*((i-phase)//2)+1))})
    assert len(full)==11 and len(partial)==2 and all(phase<=i<phase+96 for i in known)
    rows=np.asarray([[pa.index(known[s]),pa.index(known[s+1])] for s in full],dtype=np.int16)
    return full,partial,rows

def _primary_geometry(cfg):
    cfg=tuple(cfg)
    if cfg not in _PRIMARY:
        full,partial,rows=_geometry(cfg,CRIBS);pivots={}
        for prime in (2,13):
            found=None
            for a,b in itertools.combinations(range(11),2):
                x,y=rows[a];z,w=rows[b];det=int(x*w-y*z)%prime
                if det:
                    found=([a,b],(np.asarray([[w,-y],[-z,x]],dtype=np.int16)*pow(det,-1,prime))%prime);break
            assert found is not None,'unpowered public geometry is not covered'
            pivots[prime]=found
        _PRIMARY[cfg]=(full,partial,rows,pivots)
    return _PRIMARY[cfg]

def _reference_geometry(cfg):
    cfg=tuple(cfg)
    if cfg not in _REFERENCE:
        full,partial,rows=_geometry(cfg,REFERENCE_CRIBS);entries=[]
        for x,y in itertools.product(range(26),repeat=2):
            signature=sum(((int(a)*x+int(b)*y)%26)*26**i for i,(a,b) in enumerate(rows))
            entries.append((signature,(x,y)))
        entries.sort();assert len({sig for sig,key in entries})==676,'rank-deficient geometry requires full candidate fibers'
        _REFERENCE[cfg]=(full,partial,np.asarray([sig for sig,key in entries],dtype=np.uint64),np.asarray([key for sig,key in entries],dtype=np.int16))
    return _REFERENCE[cfg]

def geometry():
    result=[]
    for cfg in configs():
        full,partial,rows,pivots=_primary_geometry(cfg);_reference_geometry(cfg)
        result.append({'config':cfg,'known_complete_blocks':full,'partial_blocks':partial,'ranks':{'2':2,'13':2},'field_pivot_rows':{str(q):v[0] for q,v in pivots.items()},'reference_column_signatures':676,'covered_crib_letters':24})
    return result

def _primary_partial(data,index,key,cfg,partial):
    phase,pa,ca=cfg;a,b=key[0];c,d=key[1];inv=pow((a*d-b*c)%26,-1,26)
    for s in partial:
        x,y=map(int,data[index,s:s+2]);plain=[((x*d-y*c)*inv)%26,((-x*b+y*a)*inv)%26]
        if any(pa[plain[j]]!=CRIBS[s+j] for j in (0,1) if s+j in CRIBS):return False
    return True

def primary_assignments(data,cfg):
    full,partial,rows,pivots=_primary_geometry(cfg);positions=[i for s in full for i in (s,s+1)];ys=data[:,positions].reshape(len(data),11,2).astype(np.int16);parts={}
    for q,(selected,left_inverse) in pivots.items():parts[q]=np.einsum('ij,njk->nik',left_inverse,ys[:,selected,:])%q
    matrices=parts[13]+13*((parts[2]-parts[13])%2)
    predicted=np.einsum('ri,nij->nrj',rows,matrices)%26
    determinants=(matrices[:,0,0]*matrices[:,1,1]-matrices[:,0,1]*matrices[:,1,0])%26
    good=np.all(predicted==ys,axis=(1,2))&(UNIT_INVERSE[determinants]>=0);result={}
    for index in np.flatnonzero(good):
        key=matrices[index].tolist()
        if _primary_partial(data,int(index),key,cfg,partial):result[int(index)]=key
    return result

def _reference_partial(data,index,key,cfg,partial):
    phase,pa,ca=cfg
    for start in partial:
        given=next(i for i in (0,1) if start+i in REFERENCE_CRIBS);known=pa.index(REFERENCE_CRIBS[start+given]);observed=tuple(map(int,data[index,start:start+2]));solutions=[]
        for other in range(26):
            pt=[0,0];pt[given]=known;pt[1-given]=other
            if tuple(sum(pt[k]*key[k][j] for k in range(2))%26 for j in range(2))==observed:solutions.append(other)
        if len(solutions)!=1:return False
    return True

def reference_assignments(data,cfg):
    full,partial,signatures,coefficients=_reference_geometry(cfg);ys=data[:,[i for s in full for i in (s,s+1)]].reshape(len(data),11,2);valid=np.ones(len(data),dtype=bool);columns=[]
    for col in (0,1):
        code=np.einsum('nr,r->n',ys[:,:,col].astype(np.uint64),WEIGHTS);locations=np.searchsorted(signatures,code);safe=np.minimum(locations,len(signatures)-1);valid &= (locations<len(signatures))&(signatures[safe]==code);columns.append(coefficients[safe])
    result={}
    for index in np.flatnonzero(valid):
        key=[[int(columns[j][index,i]) for j in (0,1)] for i in (0,1)];a,b=key[0];c,d=key[1]
        if math.gcd(a*d-b*c,26)==1 and _reference_partial(data,int(index),key,cfg,partial):result[int(index)]=key
    return result

def match_data(data,cfg,reference_data=None):
    primary=primary_assignments(data,cfg)
    reference=reference_assignments(data if reference_data is None else reference_data,cfg)
    if primary!=reference:raise RuntimeError('Hill CRT fitter versus exhaustive coefficient-signature oracle disagreement')
    return primary

def encrypt(plaintext,key,cfg):
    phase,pa,ca=cfg;nums=[pa.index(ch) for ch in plaintext];return ''.join(ca[x] for x in trusted_encrypt(nums,key,2,phase))

def decode(ciphertext,key,cfg):
    phase,pa,ca=cfg;nums=[ca.index(ch) for ch in ciphertext];inv=inverse(key);out=list(nums)
    for start in range(phase,len(nums)-1,2):
        out[start:start+2]=[sum(nums[start+k]*inv[k][j] for k in range(2))%26 for j in range(2)]
    return ''.join(pa[x] for x in out)

def coefficient_fibers(rows,outputs):
    """Small exact oracle retaining ALL matrices even for deficient toy rows."""
    columns=[]
    for j in (0,1):
        columns.append([(a,b) for a,b in itertools.product(range(26),repeat=2) if all((int(row[0])*a+int(row[1])*b)%26==int(y[j]) for row,y in zip(rows,outputs))])
    return {((u[0],v[0]),(u[1],v[1])) for u,v in itertools.product(*columns) if math.gcd(u[0]*v[1]-v[0]*u[1],26)==1}
