"""Exact two-key direct period7 class; prior invalid manual contact is disclosed."""
import hashlib,itertools,json,random,sys,time
from pathlib import Path
import numpy as np
from hill_probe import AZ,KA,CRIBS,reduce_rows
from progressive_probe import design

J=sorted(CRIBS)
CHANGES=[6,20,34,48,62,76,90]

def configs():return [[pa,ca,s] for pa in (AZ,KA) for ca in (AZ,KA) for s in (1,-1)]

def class_key(cfg):
    pa,ca,s=cfg;p=[pa.index(CRIBS[i]) for i in J];right=[]
    for r in range(6):
        values={i//7:pa.index(CRIBS[i]) for i in J if i%7==r}
        right.append(s*(values[9]+5*values[3]-6*values[4])%26)
        if r<4:right.append(s*(values[10]+6*values[3]-7*values[4])%26)
    parity=(s*(pa.index(CRIBS[69])-pa.index(CRIBS[27])))%2
    c=[(ca.index(ch)-ca.index('A'))%26 for ch in AZ]
    return min(tuple((u*x)%26 for x in c+right)+(parity,) for u in range(26) if u%2 and u%13)

def prepare():
    a=np.asarray(design('specific',7),dtype=np.int16);rows=[];pivots=[]
    for p in (2,13):
        r,piv=reduce_rows([v.tolist()+[int(i==j) for j in range(24)] for i,v in enumerate(a)],p,14)
        rows.append(np.asarray(r,dtype=np.int16));pivots.append(piv)
    assert len(pivots[0])==13 and len(pivots[1])==14
    free=[i for i in range(14) if i not in pivots[0]];assert free==[13]
    return a,rows,pivots

def keys(ct,cfg,prepared):
    pa,ca,s=cfg;a,rows,piv=prepared
    y=np.asarray([(ca.index(ct[i])-s*pa.index(CRIBS[i]))%26 for i in J],dtype=np.int16)
    z13=(rows[1][:14,14:]@y)%13;sets=[]
    rhs=(rows[0][:13,14:]@y)%2
    for bit in (0,1):
        z2=np.zeros(14,dtype=np.int16);z2[13]=bit
        for r,c in enumerate(piv[0]):z2[c]=(rhs[r]-rows[0][r,13]*bit)%2
        z=(13*z2+14*z13)%26
        if not np.any((a@z-y)%26):sets.append(tuple(map(int,z)))
    assert len(sets) in (0,2)
    return sorted(sets)

def oracle(ct,cfg):
    # Independent literal q/r groups and exhaustive 676 pairs; no primary rows.
    pa,ca,s=cfg;pi={c:i for i,c in enumerate(pa)};ci={c:i for i,c in enumerate(ca)}
    known=dict(enumerate('EASTNORTHEAST',21));known.update(dict(enumerate('BERLINCLOCK',63)))
    groups=[]
    for residue in range(7):
        indices=[i for i in known if i%7==residue]
        matches=[(a,b) for a in range(26) for b in range(26) if all(ci[ct[i]]==(s*pi[known[i]]+a+b*(i//7))%26 for i in indices)]
        if not matches:return []
        groups.append(matches)
    result=[tuple(a for a,b in choices)+tuple(b for a,b in choices) for choices in itertools.product(*groups)]
    assert len(result)==2
    return sorted(result)

def encode(pt,cfg,key):
    pa,ca,s=cfg;out=[]
    for i,ch in enumerate(pt):
        q,r=divmod(i,7);out.append(ca[(s*pa.index(ch)+key[r]+key[7+r]*q)%26])
    return ''.join(out)

def decode(ct,cfg,key):
    pa,ca,s=cfg
    return ''.join(pa[(s*(ca.index(ch)-key[i%7]-key[7+i%7]*(i//7)))%26] for i,ch in enumerate(ct))

def encoder_signature(cfg,key):
    # Canonicalize parameter aliases by the entire 97x26 letter substitution
    # function, not by a chosen plaintext or by ciphertext data.
    return ''.join(encode(ch*97,cfg,key) for ch in AZ)

def controls(out):
    start=time.time();rng=random.Random(2026100508);prepared=prepare();records=[];other_cells=0
    for truth_index,truth in enumerate(configs()):
        pa,ca,s=truth;nonunique=0;max_cells=0
        for t in range(200):
            key=[rng.randrange(26) for _ in range(14)]
            if t==0:key=[0]*14
            elif t==1:key=[13]*14
            pt=[rng.choice(pa) for _ in range(97)]
            for i,ch in CRIBS.items():pt[i]=ch
            pt=''.join(pt);ct=encode(pt,truth,key);found=[]
            for ci,cfg in enumerate(configs()):
                k=keys(ct,cfg,prepared);ref=oracle(ct,cfg);assert k==ref
                if k:found.append((ci,k))
            assert any(ci==truth_index for ci,k in found)
            alternatives=next(k for ci,k in found if ci==truth_index);assert tuple(key) in alternatives and len(alternatives)==2
            if len(found)>1:nonunique+=1;other_cells+=len(found)-1
            max_cells=max(max_cells,len(found))
            # The all-zero key in same-alphabet positive-sign cells is identity
            # in both AZ and KA: real parameter-subspace overlap, not a bug.
            # Report all matching cells; every returned key must independently
            # satisfy the entire class and re-encode its decoded plaintext.
            for ci,candidates in found:
                cfg=configs()[ci]
                for candidate in candidates:
                    alternative=decode(ct,cfg,candidate)
                    assert encode(alternative,cfg,candidate)==ct and all(alternative[i]==ch for i,ch in CRIBS.items())
                    assert len(encoder_signature(cfg,candidate))==2522
            texts=[decode(ct,truth,k) for k in alternatives];assert pt in texts
            assert [i for i in range(97) if texts[0][i]!=texts[1][i]]==CHANGES
            for i in CHANGES:assert (pa.index(texts[0][i])-pa.index(texts[1][i]))%26==13
            for text,k in zip(texts,alternatives):assert encode(text,truth,k)==ct and all(text[i]==ch for i,ch in CRIBS.items())
            near=list(ct);near[63]=ca[(ca.index(near[63])+1)%26];near=''.join(near)
            random_ct=''.join(rng.choice(ca) for _ in range(97))
            for negative in (near,random_ct):
                for cfg in configs():
                    k=keys(negative,cfg,prepared);ref=oracle(negative,cfg);assert k==ref and not k
        records.append({'truth_cfg':truth,'plants':200,'blind_entire8cell_recovery':200,'exact2keysets_in_true_cell_with_true_fullplaintext':200,'seven_position13shift_verified':200,'near_miss_fullscope_rejected':200,'random_fullscope_rejected':200,'plants_matching_additional_cells':nonunique,'max_matching_cells':max_cells})
    return {'passed':True,'plants':1600,'near_miss_negatives':1600,'random_negatives':1600,'fullscope_checks':38400,'records':records,'seconds':time.time()-start,'ranks_mod2_mod13':[13,14],'expected_key_count_per_compatible_cell':2,'changed_plaintext_positions':CHANGES,'additional_matching_cell_count':other_cells,'configuration_uniqueness_not_claimed':True,'parameter_overlap_example':'all-zero key with same plaintext/cipher alphabet and positive sign is identity for AZ and KA; both cells legitimately recover that plant'}

def target(out):
    from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
    assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
    prepared=prepare();survivors=[];tested=0;start=time.time()
    for index,cfg in enumerate(configs()):
        if time.time()>=1791329400:break
        k=keys(K4_CIPHERTEXT,cfg,prepared);ref=oracle(K4_CIPHERTEXT,cfg);assert k==ref;tested+=1
        if k:
            texts=[decode(K4_CIPHERTEXT,cfg,v) for v in k]
            assert [i for i in range(97) if texts[0][i]!=texts[1][i]]==CHANGES
            for pt,key in zip(texts,k):assert encode(pt,cfg,key)==K4_CIPHERTEXT
            survivors.append({'config_index':index,'config':cfg,'keys':k,'plaintexts':texts,'ambiguity':'two keys within first compatible cell; valuation shift13 mod26 at exactly7 predeclared positions; other cells not exhaustively listed after stop','is_solution':False});break
    return {'rows_tested':tested,'expected':8,'survivors':survivors,'seconds':time.time()-start}

if __name__=='__main__':
    out=Path(sys.argv[2]);res=controls(out);(out/'controls.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps({k:v for k,v in res.items() if k!='records'}))
