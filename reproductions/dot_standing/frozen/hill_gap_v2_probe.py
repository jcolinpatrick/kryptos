"""Missing direct Hill phases, inverse-constraint solver plus exhaustive oracle."""
import hashlib,itertools,json,random,time,sys
from pathlib import Path
import numpy as np
from hill_probe import AZ,KA,CRIBS,rank,reduce_rows,inverse,encrypt,trusted_encrypt

def configs():return [(phase,pa,ca) for phase in (0,3) for pa in (AZ,KA) for ca in (AZ,KA)]
def public_ranks():
 return [[phase,pa,*[rank([[pa.index(CRIBS[i]) for i in range(s,s+4)] for s in range(phase,94,4) if all(i in CRIBS for i in range(s,s+4))],q) for q in (2,13)]] for phase in (0,3) for pa in (AZ,KA)]
def encode(pt,cfg,m):
 phase,pa,ca=cfg
 return ''.join(ca[x] for x in trusted_encrypt([pa.index(ch) for ch in pt],m,4,phase))
def equations(ct,cfg,col):
 phase,pa,ca=cfg;rows=[];rhs=[]
 for i,ch in CRIBS.items():
  s=phase+((i-phase)//4)*4
  if i-s==col:rows.append([ca.index(ct[j]) for j in range(s,s+4)]);rhs.append(pa.index(ch))
 return rows,rhs

def affine(rows,rhs,q):
 a,piv=reduce_rows([r+[v] for r,v in zip(rows,rhs)],q,4)
 if any(not any(r[:4]) and r[4] for r in a):return []
 free=[i for i in range(4) if i not in piv];res=[]
 # Enumerate all nullspace dimensions; explicit finite operational cap.
 if q**len(free)>28561:raise RuntimeError("field vector operational cap")
 for values in itertools.product(range(q),repeat=len(free)):
  x=[0]*4
  for j,v in zip(free,values):x[j]=v
  for i,j in enumerate(piv):x[j]=(a[i][4]-sum(a[i][k]*x[k] for k in free))%q
  res.append(tuple(x))
 return res

def initial_possible(ct,cfg):
 phase,pa,ca=cfg
 starts=[s for s in range(phase,94,4) if all(i in CRIBS for i in range(s,s+4))]
 p=[[pa.index(CRIBS[i]) for i in range(s,s+4)] for s in starts]
 c=[[ca.index(ct[i]) for i in range(s,s+4)] for s in starts]
 return all(rank(p,q)==rank(c,q) for q in (2,13))

def solve(ct,cfg):
 if not initial_possible(ct,cfg):return []
 columns=[]
 for j in range(4):
  rows,rhs=equations(ct,cfg,j);v2=affine(rows,rhs,2);v13=affine(rows,rhs,13)
  if not v2 or not v13:return []
  columns.append([tuple((13*x+14*y)%26 for x,y in zip(a,b)) for a in v2 for b in v13])
 result=[]
 count=int(np.prod([len(c) for c in columns]));
 if count>10000:raise RuntimeError("primary matrix candidate operational cap exceeded: "+str(count))
 for cols in itertools.product(*columns):
  n=[list(row) for row in zip(*cols)]
  if rank(n,2)<4 or rank(n,13)<4:continue
  m=inverse(n);result.append(tuple(sum(m,[])))
 return sorted(result)

V={q:np.asarray(list(itertools.product(range(q),repeat=4)),dtype=np.int32) for q in (2,13)}
PERMS=list(itertools.permutations(range(4)))
def det(m):
 return sum((-1)**sum(perm[i]>perm[j] for i in range(4) for j in range(i+1,4))*np.prod([m[i][perm[i]] for i in range(4)],dtype=np.int64) for perm in PERMS)
def reference(ct,cfg):
 # Independent literal cribs, block indexing, field brute force, determinant
 # and trusted adjugate inversion; no fast path rank/affine/reduction calls.
 from cryptolab.tools.hill_cipher import _mat_inverse_mod
 phase,pa,ca=cfg;known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};columns=[]
 for col in range(4):
  rows=[];values=[]
  for start in range(phase,97-3,4):
   if start+col in known:
    rows.append([ca.index(ch) for ch in ct[start:start+4]]);values.append(pa.index(known[start+col]))
  a=np.asarray(rows,dtype=np.int32);b=np.asarray(values,dtype=np.int32);parts=[]
  for q in (2,13):parts.append(V[q][np.all((V[q]@a.T-b)%q==0,axis=1)].tolist())
  if not all(parts):return []
  columns.append([tuple((13*x+14*y)%26 for x,y in zip(a,b)) for a in parts[0] for b in parts[1]])
 count=int(np.prod([len(c) for c in columns]));
 if count>10000:raise RuntimeError("oracle matrix candidate operational cap exceeded: "+str(count))
 result=[]
 for cols in itertools.product(*columns):
  n=[list(row) for row in zip(*cols)];d=int(det(n))
  if d%2==0 or d%13==0:continue
  m=_mat_inverse_mod(n);assert m is not None;result.append(tuple(sum(m,[])))
 return sorted(result)

def verify(ct,cfg,key):
 phase,pa,ca=cfg;m=[list(key[i:i+4]) for i in range(0,16,4)];nums=encrypt([ca.index(c) for c in ct],inverse(m),4,phase)
 pt=''.join(pa[x] for x in nums);covered=set(i for s in range(phase,94,4) for i in range(s,s+4))
 assert all(pt[i]==ch for i,ch in CRIBS.items())
 enc=encode(pt,cfg,m);assert all(enc[i]==ct[i] for i in covered)
 return {'key':key,'plaintext_covered':''.join(pt[i] if i in covered else '?' for i in range(97)),'unconstrained_edges':sorted(set(range(97))-covered)}

def controls(out):
 rng=random.Random(2026100610);start=time.time();records=[];positive=negative=0;structured=[];distinct=set()
 for cfg in configs():
  keycounts=[];extra_negative_hits=0
  for t in range(200):
   while True:
    m=[[rng.randrange(26) for _ in range(4)] for _ in range(4)]
    if rank(m,2)==4 and rank(m,13)==4:break
   if tuple(sum(m,[])) in distinct:raise RuntimeError("unexpected duplicate planted key")
   distinct.add(tuple(sum(m,[])))
   pt=[rng.choice(cfg[1]) for _ in range(97)]
   for i,ch in CRIBS.items():pt[i]=ch
   pt=''.join(pt);ct=encode(pt,cfg,m);a=solve(ct,cfg);b=reference(ct,cfg)
   assert a==b and tuple(sum(m,[])) in a
   for key in a:verify(ct,cfg,key)
   keycounts.append(len(a));positive+=1
   if t<10:
    variants=[("cross-cell",ct), ("permuted-ciphertext",ct[::-1])]
    for phase2 in (1,2):variants.append(("phase"+str(phase2),encode(pt,(phase2,cfg[1],cfg[2]),m)))
    m3=[[1,2,3],[0,1,2],[0,0,1]];variants.append(("Hill3",''.join(cfg[2][v] for v in trusted_encrypt([cfg[1].index(ch) for ch in pt],m3,3,0))))
    for label,fixture in variants:
     for other in configs():
      aa=solve(fixture,other);bb=reference(fixture,other);assert aa==bb
      for key in aa:verify(fixture,other,key)
      structured.append({"type":label,"truth":cfg,"tested":other,"compatible_keys":len(aa)})
   random_ct=''.join(rng.choice(cfg[2]) for _ in range(97));a=solve(random_ct,cfg);b=reference(random_ct,cfg);assert a==b
   # Random compatible keys are leads, not automatically solver defects.
   extra_negative_hits+=len(a);negative+=1
  zero=cfg[2][0]*97;assert solve(zero,cfg)==reference(zero,cfg)==[]
  records.append({'zero_out_of_class_rejected':True,'config':cfg,'plants':200,'random_cases':200,'all_keysets_agree':True,'planted_key_count_min':min(keycounts),'planted_key_count_max':max(keycounts),'random_compatible_keys':extra_negative_hits})
 return {'passed':True,'plants':positive,'random_controls':negative,'seconds':time.time()-start,'records':records,'public_ranks':public_ranks(),'structured_evaluations':len(structured),'structured_compatible_keys':sum(x['compatible_keys'] for x in structured),'structured_records':structured,'distinct_plant_keys':len(distinct),'no_false_positive_probability_claim':True}

def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 start=time.time();tested=0;survivors=[]
 for cfg in configs():
  assert time.time()<1791329400
  try:
   a=solve(K4_CIPHERTEXT,cfg);b=reference(K4_CIPHERTEXT,cfg);assert a==b
  except Exception as exc:return {"rows_tested":tested,"expected":8,"survivors":survivors,"seconds":time.time()-start,"failure":repr(exc),"verdict":"INCONCLUSIVE"}
  tested+=1
  if a:survivors.append({'config':cfg,'keys':[verify(K4_CIPHERTEXT,cfg,key) for key in a],'is_solution':False,'other_cells_not_exhaustively_listed':True});break
 return {'rows_tested':tested,'expected':8,'survivors':survivors,'seconds':time.time()-start}
if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))

