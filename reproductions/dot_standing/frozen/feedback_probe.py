"""Direct ciphertext-feedback class screen; primer prefixes are explicitly free."""
import hashlib,json,random,sys,time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import numpy as np
from hill_probe import AZ,KA,CRIBS

KNOWN=sorted(CRIBS)

def configs():return [[lag,pa,ca,ka,sp,sk] for lag in range(1,26) for pa in (AZ,KA) for ca in (AZ,KA) for ka in (AZ,KA) for sp in (1,-1) for sk in (1,-1)]

def class_key(cfg):
    lag,pa,ca,ka,sp,sk=cfg;j=[i for i in KNOWN if i>=lag]
    c=[(ca.index(ch)-ca.index('A'))%26 for ch in AZ]
    k=[(sk*(ka.index(ch)-ka.index('A')))%26 for ch in AZ]
    p=[(sp*(pa.index(CRIBS[i])-pa.index(CRIBS[j[0]])))%26 for i in j]
    # Unknown d absorbs constants; multiplication of every constraint by a
    # modulo26 unit is a proven equivalence. This key never inspects ciphertext.
    units=[v for v in range(26) if v%2 and v%13]
    return lag,tuple(j),min(tuple((u*x)%26 for x in c+k+p) for u in units)

def encode(pt,cfg,d,primer):
    lag,pa,ca,ka,sp,sk=cfg;assert len(primer)==lag
    out=[]
    for i,ch in enumerate(pt):
        p=pa.index(ch)
        key=primer[i] if i<lag else sk*ka.index(out[i-lag])+d
        out.append(ca[(sp*p+key)%26])
    return ''.join(out)

def match(ct,cfg):
    lag,pa,ca,ka,sp,sk=cfg
    v=[(ca.index(ct[i])-sp*pa.index(CRIBS[i])-sk*ka.index(ct[i-lag]))%26 for i in KNOWN if i>=lag]
    return v[0] if len(set(v))==1 else None

def oracle(ct,cfg):
    lag,pa,ca,ka,sp,sk=cfg
    pd={ch:i for i,ch in enumerate(pa)};cd={ch:i for i,ch in enumerate(ca)};kd={ch:i for i,ch in enumerate(ka)}
    known=dict(enumerate('EASTNORTHEAST',21));known.update(dict(enumerate('BERLINCLOCK',63)))
    return [d for d in range(26) if all(cd[ct[i]]==(sp*pd[ch]+sk*kd[ct[i-lag]]+d)%26 for i,ch in known.items() if i>=lag)]

def decode(ct,cfg,d):
    lag,pa,ca,ka,sp,sk=cfg
    return ''.join(CRIBS.get(i,'?') if i<lag else pa[(sp*(ca.index(ch)-sk*ka.index(ct[i-lag])-d))%26] for i,ch in enumerate(ct))

def prefix_witness(ct,cfg,partial):
    lag,pa,ca,ka,sp,sk=cfg
    pt=''.join(pa[0] if ch=='?' else ch for ch in partial)
    primer=[(ca.index(ct[i])-sp*pa.index(pt[i]))%26 for i in range(lag)]
    return pt,primer

def scan_all(data):
    n=len(data);counts=np.zeros(n,dtype=np.uint16);first=np.full(n,65535,dtype=np.uint16);constants=np.zeros(n,dtype=np.uint8)
    for ci,cfg in enumerate(configs()):
        lag,pa,ca,ka,sp,sk=cfg;j=np.asarray([i for i in KNOWN if i>=lag]);p=np.asarray([pa.index(CRIBS[int(i)]) for i in j],dtype=np.int16)
        cm=np.asarray([ca.index(ch) for ch in AZ],dtype=np.int16);km=np.asarray([ka.index(ch) for ch in AZ],dtype=np.int16)
        delta=(cm[data[:,j]]-sp*p[None,:]-sk*km[data[:,j-lag]])%26
        hit=np.all(delta==delta[:,0,None],axis=1)
        new=hit & (counts==0);first[new]=ci;constants[new]=delta[new,0];counts+=hit.astype(np.uint16)
    return counts,first,constants

def full_scope(data,workers=4):
    chunks=[a for a in np.array_split(data,workers) if len(a)]
    with ProcessPoolExecutor(max_workers=workers) as pool:parts=list(pool.map(scan_all,chunks))
    return tuple(np.concatenate([p[i] for p in parts]) for i in range(3))

def controls(out):
    start=time.time();rng=random.Random(2026100505);cfgs=configs();total=160000
    positive=np.zeros((total,97),dtype=np.uint8);near=np.zeros_like(positive);random_negative=np.zeros_like(positive)
    expected_cfg=np.repeat(np.arange(800,dtype=np.uint16),200);expected_d=np.zeros(total,dtype=np.uint8);records=[]
    cursor=0;scalar_bad=0
    for ci,cfg in enumerate(cfgs):
        lag,pa,ca,ka,sp,sk=cfg;constrained=[i for i in KNOWN if i>=lag];j=constrained[0]
        assert len(constrained)>=20
        for t in range(200):
            pt=[rng.choice(pa) for _ in range(97)]
            for i,ch in CRIBS.items():pt[i]=ch
            pt=''.join(pt);d=rng.randrange(26);primer=[rng.randrange(26) for _ in range(lag)]
            if t==0:d=0
            elif t==1:d=13
            ct=encode(pt,cfg,d,primer);a=match(ct,cfg);b=oracle(ct,cfg)
            assert a==d and b==[d]
            partial=decode(ct,cfg,d);assert partial[lag:]==pt[lag:]
            # Construction only, not recovery evidence: actual prefix/primer are
            # in the returned set, and an arbitrary witness also re-encodes.
            assert all(partial[i] in ('?',pt[i]) for i in range(lag))
            witness,derived=prefix_witness(ct,cfg,partial);assert encode(witness,cfg,d,derived)==ct
            changed=list(ct);changed[j]=ca[(ca.index(changed[j])+1)%26];changed=''.join(changed)
            assert oracle(changed,cfg)==[] and match(changed,cfg) is None
            # Changing C_j affects at most rows j and j+lag; >=18 other rows
            # keep d fixed, and changed row j differs by1, so this is out of class.
            positive[cursor]=[AZ.index(ch) for ch in ct];near[cursor]=[AZ.index(ch) for ch in changed]
            random_negative[cursor]=[rng.randrange(26) for _ in range(97)];expected_d[cursor]=d;cursor+=1
        records.append({'config':cfg,'constrained_crib_letters':len(constrained),'suffix_length':97-lag,'plants':200,'scalar_primary_oracle_d_suffix_exact':200,'near_miss_rejected_in_true_config':200})
    pos_count,pos_first,pos_d=full_scope(positive)
    near_count,_,_=full_scope(near)
    null_count,_,_=full_scope(random_negative)
    np.save(out/'plant-survivor-counts.npy',pos_count);np.save(out/'near-miss-survivor-counts.npy',near_count);np.save(out/'random-survivor-counts.npy',null_count)
    missed=int(np.sum(pos_count==0));nonunique=int(np.sum(pos_count!=1));wrong=int(np.sum((pos_first!=expected_cfg)|(pos_d!=expected_d)))
    report={'passed':missed==0 and nonunique==0 and wrong==0 and not np.any(null_count),'base_configurations':800,'positive_plants':total,'scalar_primary_oracle_recovery_passed':total,'full_scope_scans_per_plant':800,'full_scope_configuration_checks':total*800*3,'missed_true_plants':missed,'plants_with_nonunique_frame_classes':nonunique,'wrong_unique_config_or_d':wrong,'positive_hit_total':int(pos_count.sum()),'positive_hits_min':int(pos_count.min()),'positive_hits_max':int(pos_count.max()),'near_miss_negatives':total,'near_miss_hits_other_config_count':int(np.sum(near_count>0)),'near_miss_hit_total':int(near_count.sum()),'near_miss_true_config_rejected':total,'random_negatives':total,'random_hit_total':int(null_count.sum()),'records':records,'seconds':time.time()-start,'prefix_membership_is_construction_only':True,'controls_workers':4,'threads_each':1,'constraints_min':20}
    return report

def target(out):
    from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
    assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
    ct=K4_CIPHERTEXT;survivors=[];tested=0;start=time.time()
    for ci,cfg in enumerate(configs()):
        if time.time()>=1791329400:break
        a=match(ct,cfg);b=oracle(ct,cfg);assert b==([] if a is None else [a]);tested+=1
        if a is not None:
            partial=decode(ct,cfg,a);witness,primer=prefix_witness(ct,cfg,partial);assert encode(witness,cfg,a,primer)==ct
            survivors.append({'config_index':ci,'config':cfg,'constant':a,'partial_plaintext':partial,'unknown_prefix_letters':partial[:cfg[0]].count('?'),'suffix_length':97-cfg[0],'underidentified':True,'is_solution':False,'arbitrary_witness_reencoded':True});break
    return {'rows_tested':tested,'expected':800,'survivors':survivors,'seconds':time.time()-start}

if __name__=='__main__':
    out=Path(sys.argv[2])
    if sys.argv[1]=='controls':
        res=controls(out);(out/'controls.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps({k:v for k,v in res.items() if k!='records'}))
