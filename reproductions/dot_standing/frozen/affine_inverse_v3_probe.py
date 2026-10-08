"""Direct affine Hill inverse constraints, independent field exhaustive oracle."""
import hashlib,itertools,json,random,time,sys,os
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
import numpy as np
from hill_probe import AZ,KA,CRIBS,rank,reduce_rows,inverse,encrypt,trusted_encrypt
from cryptolab.tools.hill_cipher import _mat_inverse_mod
CAP=50000
class CapExceeded(RuntimeError):
 def __init__(self,count,implementation):
  self.count=count;self.implementation=implementation;super().__init__(implementation+" candidate cap "+str(count))

def configs():return [(n,phase,pa,ca) for n in (3,4) for phase in range(n) for pa in (AZ,KA) for ca in (AZ,KA)]
def geometry():
 return [{'config':cfg,'equations_per_column':[sum((i-cfg[1])%cfg[0]==j for i in CRIBS) for j in range(cfg[0])],'fullknown_augmented_ranks': [rank([[cfg[2].index(CRIBS[i]) for i in range(s,s+cfg[0])]+[1] for s in range(cfg[1],98-cfg[0],cfg[0]) if all(i in CRIBS for i in range(s,s+cfg[0]))],q) for q in (2,13)]} for cfg in configs()]
def encode(pt,cfg,m,b):
 n,phase,pa,ca=cfg;nums=trusted_encrypt([pa.index(ch) for ch in pt],m,n,phase)
 for s in range(phase,len(pt)-n+1,n):
  for j in range(n):nums[s+j]=(nums[s+j]+b[j])%26
 return ''.join(ca[x] for x in nums)

def singular_encode(pt,cfg,m,b):
 n,phase,pa,ca=cfg;nums=encrypt([pa.index(c) for c in pt],m,n,phase)
 for start in range(phase,98-n,n):
  for j in range(n):nums[start+j]=(nums[start+j]+b[j])%26
 return ''.join(ca[x] for x in nums)

def affine(rows,rhs,q,d):
 a,piv=reduce_rows([r+[v] for r,v in zip(rows,rhs)],q,d)
 if any(not any(r[:d]) and r[d] for r in a):return []
 free=[i for i in range(d) if i not in piv];count=q**len(free)
 if count>371293:raise RuntimeError('field operational cap '+str(count))
 res=[]
 for values in itertools.product(range(q),repeat=len(free)):
  x=[0]*d
  for j,v in zip(free,values):x[j]=v
  for i,j in enumerate(piv):x[j]=(a[i][d]-sum(a[i][k]*x[k] for k in free))%q
  res.append(tuple(x))
 return res

def solve(ct,cfg):
 n,phase,pa,ca=cfg;columns=[]
 for col in range(n):
  rows=[];rhs=[]
  for i,ch in CRIBS.items():
   s=phase+((i-phase)//n)*n
   if i-s==col:rows.append([ca.index(ct[j]) for j in range(s,s+n)]+[1]);rhs.append(pa.index(ch))
  parts=[affine(rows,rhs,q,n+1) for q in (2,13)]
  if not all(parts):return []
  columns.append([tuple((13*x+14*y)%26 for x,y in zip(a,b)) for a in parts[0] for b in parts[1]])
 count=int(np.prod([len(c) for c in columns]))
 if count>CAP:raise CapExceeded(count,'primary')
 keys=[]
 for cols in itertools.product(*columns):
  nn=[list(row) for row in zip(*(c[:n] for c in cols))];t=[c[n] for c in cols]
  if rank(nn,2)<n or rank(nn,13)<n:continue
  m=inverse(nn);b=[-sum(t[k]*m[k][j] for k in range(n))%26 for j in range(n)]
  keys.append(tuple(sum(m,[])+b))
 return sorted(keys)

V={};PERMS={n:list(itertools.permutations(range(n))) for n in (3,4)}
def vectors(q,d):
 if (q,d) not in V:V[q,d]=np.asarray(list(itertools.product(range(q),repeat=d)),dtype=np.int32)
 return V[q,d]
def determinant(m):
 n=len(m)
 return sum((-1)**sum(perm[i]>perm[j] for i in range(n) for j in range(i+1,n))*np.prod([m[i][perm[i]] for i in range(n)],dtype=np.int64) for perm in PERMS[n])
def reference(ct,cfg):
 n,phase,pa,ca=cfg;known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};cols=[]
 for j in range(n):
  rows=[];rhs=[]
  for s in range(phase,97-n+1,n):
   if s+j in known:rows.append([ca.index(ch) for ch in ct[s:s+n]]+[1]);rhs.append(pa.index(known[s+j]))
  a=np.asarray(rows,dtype=np.int32);b=np.asarray(rhs,dtype=np.int32);parts=[]
  for q in (2,13):
   v=vectors(q,n+1);parts.append(v[np.all((v@a.T-b)%q==0,axis=1)].tolist())
  if not all(parts):return []
  cols.append([tuple((13*x+14*y)%26 for x,y in zip(a,b)) for a in parts[0] for b in parts[1]])
 count=int(np.prod([len(c) for c in cols]))
 if count>CAP:raise CapExceeded(count,'oracle')
 keys=[]
 for selected in itertools.product(*cols):
  nn=[list(row) for row in zip(*(c[:n] for c in selected))];t=[c[n] for c in selected];det=int(determinant(nn))
  if det%2==0 or det%13==0:continue
  m=_mat_inverse_mod(nn);assert m is not None
  offset=[sum(-t[i]*m[i][j] for i in range(n))%26 for j in range(n)]
  keys.append(tuple(sum(m,[])+offset))
 return sorted(keys)

def verify(ct,cfg,key):
 n,phase,pa,ca=cfg;m=[list(key[i:i+n]) for i in range(0,n*n,n)];b=key[n*n:];nums=[ca.index(c) for c in ct]
 for s in range(phase,98-n,n):
  for j in range(n):nums[s+j]=(nums[s+j]-b[j])%26
 dec=encrypt(nums,inverse(m),n,phase);pt=''.join(pa[x] for x in dec);covered=set(i for s in range(phase,98-n,n) for i in range(s,s+n))
 assert all(pt[i]==ch for i,ch in CRIBS.items());enc=encode(pt,cfg,m,b);assert all(enc[i]==ct[i] for i in covered)
 return {'matrix':m,'offset':b,'covered_plaintext':''.join(ch if i in covered else '?' for i,ch in enumerate(pt)),'unconstrained_edges':sorted(set(range(97))-covered)}

def control_cell(arg):
 index,cfg,outstr=arg;out=Path(outstr);n,phase,pa,ca=cfg;rng=random.Random(202610061100+index);start=time.time();counts=[];distinct=set();structured=[];randomhits=0
 for trial in range(200):
  if trial%25==0:(out/('control-cell-'+str(index)+'.json')).write_text(json.dumps({'cell':index,'cfg':cfg,'next_trial':trial,'elapsed_seconds':time.time()-start})+'\n')
  assert time.time()<1791329400 and time.time()-start<1500
  while True:
   m=[[rng.randrange(26) for _ in range(n)] for _ in range(n)];b=[rng.randrange(26) for _ in range(n)]
   if rank(m,2)==n and rank(m,13)==n and tuple(sum(m,[])+b) not in distinct:break
  truth=tuple(sum(m,[])+b);distinct.add(truth);pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);ct=encode(pt,cfg,m,b);a=solve(ct,cfg);ref=reference(ct,cfg);assert a==ref and truth in a
  for key in a:verify(ct,cfg,key)
  counts.append(len(a))
  random_ct=''.join(rng.choice(ca) for _ in range(97));a=solve(random_ct,cfg);ref=reference(random_ct,cfg);assert a==ref;randomhits+=len(a)
  for key in a:verify(random_ct,cfg,key)
  if trial<5:
   variants=[('zerooffset',encode(pt,cfg,m,[0]*n)),('reverse',ct[::-1]),('wrongphase',encode(pt,(n,(phase+1)%n,pa,ca),m,b)),('crossalphabet',encode(pt,(n,phase,pa,KA if ca==AZ else AZ),m,b))]
   singular=[row[:] for row in m];singular[-1]=[0]*n;variants.append(('singular_source',singular_encode(pt,cfg,singular,b)))
   other_n=4 if n==3 else 3;other_m=[[int(i==j) for j in range(other_n)] for i in range(other_n)];variants.append(('wrong_n',encode(pt,(other_n,0,pa,ca),other_m,list(range(other_n)))))
   for label,v in variants:
    try:
     a=solve(v,cfg);ref=reference(v,cfg);assert a==ref
    except CapExceeded as exc:
     if label=='zerooffset':raise
     structured.append({'type':label,'status':'CAP_EXCEEDED','candidate_count':exc.count,'implementation':exc.implementation,'no_rejection_or_agreement_claim':True});continue
    for key in a:verify(v,cfg,key)
    structured.append({'type':label,'status':'COMPLETE','compatible_keys':len(a)})
 zero=ca[0]*97;assert solve(zero,cfg)==reference(zero,cfg)==[]
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as log:log.write(__import__('datetime').datetime.now(__import__('datetime').UTC).isoformat()+' dot-standing-014 controlcell'+str(index)+' complete200plants+200random+30structured+1zero;maxkeys'+str(max(counts))+';'+str(time.time()-start)+'s;target0\n')
 return {'config':cfg,'plants':200,'distinct_keys_offsets':len(distinct),'all_truekeys_recovered':True,'all_keysets_agree':True,'candidate_key_count_min':min(counts),'candidate_key_count_max':max(counts),'random_cases':200,'random_compatible_keys':randomhits,'structured':structured,'zero_cipher_rejected':True,'seconds':time.time()-start}

def controls(out):
 start=time.time()
 with ProcessPoolExecutor(max_workers=4) as pool:records=list(pool.map(control_cell,[(i,cfg,str(out)) for i,cfg in enumerate(configs())]))
 return {'passed':True,'plants':sum(r['plants'] for r in records),'random_cases':sum(r['random_cases'] for r in records),'structured_evaluations':sum(len(r['structured']) for r in records),'zero_out_of_class_cases':len(records),'records':records,'seconds':time.time()-start,'workers':4,'threads_each':1,'geometry':geometry(),'no_statistical_or_blind_claim':True}
def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 tested=0;survivors=[];start=time.time();cells=[];inconclusive=[]
 for cfg in configs():
  try:
   assert time.time()<1791329400
   a=solve(K4_CIPHERTEXT,cfg);b=reference(K4_CIPHERTEXT,cfg);assert a==b
   if a:survivors.append({'config':cfg,'compatible_keys':[verify(K4_CIPHERTEXT,cfg,key) for key in a],'is_solution':False,'other_cells_not_exhaustively_listed':True})
  except CapExceeded as e:
   cells.append({'config':cfg,'status':'INCONCLUSIVE-CAP','candidate_count':e.count,'implementation':e.implementation});inconclusive.append(cfg);tested+=1;continue
  except Exception as e:return {'rows_tested':tested,'expected':28,'survivors':survivors,'failure':repr(e),'seconds':time.time()-start,'cells':cells}
  cells.append({'config':cfg,'status':'SURVIVOR' if a else 'NULL','compatible_keys':len(a)})
  tested+=1
  if survivors:break
 return {'rows_tested':tested,'expected':28,'survivors':survivors,'seconds':time.time()-start,'cells':cells,'inconclusive_cells':inconclusive,'failure':'cap-limited cells' if inconclusive else None}
if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
