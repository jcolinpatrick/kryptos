"""Finite routed integer-valued quadratic key universe; full-scope synthetic scans."""
import hashlib,json,itertools,random,time,sys,os,datetime
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,KA,CRIBS,rank,reduce_rows
from routed_probe import scatter,pullback
from cryptolab.research_bridge.cribsolve_perm import stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages
J=sorted(CRIBS);PERIODS=(5,)
def configs():return [(p,pa,ca,s) for p in PERIODS for pa in (AZ,KA) for ca in (AZ,KA) for s in (1,-1)]
def basis(q):return (1,q,q*(q-1)//2)
def design(p):return [[basis(i//p)[z] if i%p==r else 0 for z in range(3) for r in range(p)] for i in J]
def geometry():return [{'period':p,'unknowns':3*p,'ranks':[rank(design(p),q) for q in (2,13)],'crib_equations':24} for p in range(1,9)]
def search_space_size(out):return 8*len(np.load(out/'routes.npy',mmap_mode='r'))
@lru_cache(None)
def prepare(p):
 a=design(p);d=3*p;left=[];nulls=[]
 for q in (2,13):
  rows,piv=reduce_rows([v+[int(i==j) for j in range(24)] for i,v in enumerate(a)],q,d);free=[i for i in range(d) if i not in piv];matrix=np.zeros((d,24),dtype=np.int32)
  for r,c in enumerate(piv):matrix[c]=rows[r][d:]
  basis=[]
  for f in free:
   v=np.zeros(d,dtype=np.int32);v[f]=1
   for r,c in enumerate(piv):v[c]=-rows[r][f]%q
   basis.append(v)
  offsets=[sum((v*z for v,z in zip(basis,zs)),np.zeros(d,dtype=np.int32))%q for zs in itertools.product(range(q),repeat=len(free))]
  left.append(matrix);nulls.append(offsets)
 assert len(nulls[0])==4 and len(nulls[1])==1
 return np.asarray(a,dtype=np.int32)%26,left,nulls
@lru_cache(None)
def reference_prepare(period):
 groups=[[i for i in list(range(21,34))+list(range(63,74)) if i%period==r] for r in range(period)];tables=[]
 for indices in groups:
  table={}
  for a,b,c in itertools.product(range(26),repeat=3):
   sig=bytes((a+b*(i//period)+c*((i//period)*((i//period)-1)//2))%26 for i in indices);table.setdefault(sig,[]).append((a,b,c))
  assert sum(map(len,table.values()))==17576;tables.append(table)
 return groups,tables

def encode(pt,cfg,key):
 period,pa,ca,sign=cfg;out=[]
 for i,ch in enumerate(pt):
  q,r=divmod(i,period);out.append(ca[(sign*pa.index(ch)+key[r]+q*key[period+r]+q*(q-1)//2*key[2*period+r])%26])
 return ''.join(out)
def decode(ct,cfg,key):
 p,pa,ca,s=cfg
 return ''.join(pa[(s*(ca.index(ch)-key[i%p]-key[p+i%p]*(i//p)-key[2*p+i%p]*((i//p)*((i//p)-1)//2)))%26] for i,ch in enumerate(ct))
def compare_one(ct,cfg):
 routes=np.arange(97,dtype=np.int16).reshape(1,97);r=scan(ct,cfg,routes)
 return [h['key'] for h in r['survivors']]

def scan(ct,cfg,routes,stop_path=None,metadata=None):
 # This exact scanner is shared by every full-universe control and target.
 p,pa,ca,sign=cfg;a,left,nulls=prepare(p)
 nums=np.asarray([ca.index(ch) for ch in ct],dtype=np.int32);y=(nums[routes[:,J]]-sign*np.asarray([pa.index(CRIBS[i]) for i in J],dtype=np.int32))%26
 primary={};k2=(y@left[0].T)%2;k13=(y@left[1].T)%13
 for n2 in nulls[0]:
  for n13 in nulls[1]:
   k=(13*((k2+n2)%2)+14*((k13+n13)%13))%26;valid=np.flatnonzero(np.all((k@a.T-y)%26==0,axis=1))
   for i in valid:primary.setdefault(int(i),[]).append(k[i].tolist())
 primary={i:sorted(v) for i,v in primary.items()}
 # Own alphabet maps, crib literal and grouping. Do not reuse primary residuals.
 groups,tables=reference_prepare(p);known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};pi={ch:i for i,ch in enumerate(pa)};ci={ch:i for i,ch in enumerate(ca)}
 cnums=np.asarray([ci[ch] for ch in ct],dtype=np.int32);ref={}
 pulled=cnums[routes];group_columns=[np.asarray(g,dtype=np.int32) for g in groups];pub=[[sign*pi[known[i]] for i in g] for g in groups]
 for index,row in enumerate(pulled):
  if stop_path is not None and stop_path.exists():return {"tested":0,"survivors":[],"stopped":True}
  coeff=[]
  for g,t,offset in zip(group_columns,tables,pub):
   value=t.get(bytes(((row[g]-offset)%26).tolist()))
   if value is None:break
   coeff.append(value)
  if len(coeff)==p:ref[index]=sorted([[v[z] for z in range(3) for v in option] for option in itertools.product(*coeff)])
 if primary!=ref:raise RuntimeError('bulk-primary/exhaustive-reference disagreement')
 survivors=[]
 for index,keys in primary.items():
  for key in keys:
   pre=pullback(ct,routes[index]);pt=decode(pre,cfg,key);assert all(pt[i]==ch for i,ch in CRIBS.items())
   assert scatter(encode(pt,cfg,key),routes[index])==ct
   hit={'config':cfg,'route_index':index,'key':key,'plaintext':pt,'is_solution':False}
   if stop_path is not None:
    m=metadata[index];assert run_stages(stages_for_label(m['label'],97),encode(pt,cfg,key),m['mode'])==ct;hit['route']=m
    try:
     with stop_path.open('x') as f:f.write(json.dumps(hit)+'\n')
    except FileExistsError:pass
    survivors.append(hit);break
   survivors.append(hit)
 return {'tested':len(routes),'survivors':survivors}

_BANK={}
def bank(outstr):
 if outstr not in _BANK:
  out=Path(outstr);_BANK[outstr]=(np.load(out/'routes.npy',mmap_mode='r'),json.loads((out/'routes.json').read_text()))
 return _BANK[outstr]
def scan_task(task):
 outstr,cfg,ct,fixture_id,stop=task;routes,meta=bank(outstr);out=Path(outstr)
 if stop and (out/'survivor-worker-stop.json').exists():return {'fixture':fixture_id,'config':cfg,'tested':0,'survivors':[]}
 if time.time()>=1791329400:raise RuntimeError('authorization ended')
 result=scan(ct,cfg,routes,out/'survivor-worker-stop.json' if stop else None,meta if stop else None)
 for hit in result['survivors']:
  m=meta[hit['route_index']];assert run_stages(stages_for_label(m['label'],97),encode(hit['plaintext'],cfg,hit['key']),m['mode'])==ct;hit['route']=m
  if stop:
   try:
    with (out/'survivor-worker-stop.json').open('x') as f:f.write(json.dumps(hit)+'\n')
   except FileExistsError:pass
   break
 return {'fixture':fixture_id,'config':cfg,**result}

def controls(out):
 start=time.time();routes,meta=bank(str(out));rng=random.Random(2026100612);records=[]
 for cfg in configs():
  p,pa,ca,sign=cfg;a=design(p);d=3*p
  miss=next(j for j in range(24) if all(rank(a[:j]+a[j+1:],q)==rank(a,q) for q in (2,13)))
  for trial in range(200):
   key=[rng.randrange(26) for _ in range(d)];pt=[rng.choice(pa) for _ in range(97)]
   if trial==0:key=[0]*d
   if trial==1:key=[13]*d
   for i,ch in CRIBS.items():pt[i]=ch
   pt=''.join(pt);idx=rng.randrange(len(routes));m=meta[idx];pre=encode(pt,cfg,key);ct=run_stages(stages_for_label(m['label'],97),pre,m['mode'])
   restored=pullback(ct,routes[idx]);assert restored==pre;recovered=compare_one(restored,cfg);assert key in recovered and len(recovered)==4 and decode(restored,cfg,key)==pt
   near=list(pre);i=J[miss];near[i]=ca[(ca.index(near[i])+1)%26];assert compare_one(''.join(near),cfg) ==[]
   random_text=''.join(rng.choice(ca) for _ in range(97));assert compare_one(random_text,cfg) ==[]
  records.append({'config':cfg,'positive':200,'random_rejected':200,'certified_near_miss_rejected':200,'heldout_row':J[miss],'remaining_design_preserves_rank_both_fields':True,'all_four_keys_retained':True})
  progress(out.name+' quadratic localcontrols cfg'+str(len(records))+'/8 completed200plants+200near+200random;target0')
 fixtures=[]
 for fid,cfg in enumerate(configs()):
  p,pa,ca,sign=cfg;key=[rng.randrange(26) for _ in range(3*p)];pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);idx=rng.randrange(len(routes));m=meta[idx];ct=run_stages(stages_for_label(m['label'],97),encode(pt,cfg,key),m['mode'])
  fixtures.append({'id':fid,'truth_config':cfg,'truth_route':idx,'truth_key':key,'plaintext':pt,'ciphertext':ct})
 for j in range(8):fixtures.append({'id':8+j,'ciphertext':''.join(rng.choice(AZ) for _ in range(97)),'random_only':True})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=12) as pool:
  for fixture in fixtures:
   results=list(pool.map(scan_task,[(str(out),cfg,fixture['ciphertext'],fixture['id'],False) for cfg in configs()]))
   assert sum(r['tested'] for r in results)==212896
   hits=[h for r in results for h in r['survivors']]
   if not fixture.get('random_only'):
    assert any(tuple(h['config'])==tuple(fixture['truth_config']) and h['route_index']==fixture['truth_route'] and h['key']==fixture['truth_key'] and h['plaintext']==fixture['plaintext'] for h in hits)
   dedup=len({hashlib.sha256(h['plaintext'].encode()).hexdigest() for h in hits})
   summary={'fixture_id':fixture['id'],'tested':212896,'compatible_candidates':len(hits),'distinct_plaintexts':dedup,'true_config_route_key_plaintext_recovered':not fixture.get('random_only'),'random_only':fixture.get('random_only',False)};full.append(summary)
   (out/('full-control-'+str(fixture['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n')
   progress(out.name+' full-universe syntheticfixture'+str(fixture['id'])+'/15;212896configs tested;compatible'+str(len(hits))+';target0')
 return {'passed':True,'plants':1600,'random_cases':1600,'near_miss_cases':1600,'full_universe_plants':8,'full_universe_randoms':8,'full_universe_evaluations':sum(r['tested'] for r in full),'full_scope_controls':full,'configuration_uniqueness_not_claimed':True,'records':records,'seconds':time.time()-start,'workers':12,'threads_each':1,'bank_size':len(routes),'no_statistical_or_blind_K4_claim':True}
def progress(s):
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' '+s+'\n')

def execute_stop_on_survivor(ct,out):
 start=time.time();pool=ProcessPoolExecutor(max_workers=12);results=[];survivors=[];failed=False
 try:
  pending={pool.submit(scan_task,(str(out),cfg,ct,'single-pass',True)) for cfg in configs()}
  while pending:
   done,pending=wait(pending,timeout=0.1,return_when=FIRST_COMPLETED)
   for f in done:results.append(f.result())
   if (out/'survivor-worker-stop.json').exists():
    survivors=[json.loads((out/'survivor-worker-stop.json').read_text())];break
   if time.time()>=1791329400:raise RuntimeError('authorization ended')
 except Exception:
  failed=True;raise
 finally:
  if survivors or failed:
   for worker in list(pool._processes.values()):worker.terminate()
   pool.shutdown(wait=True,cancel_futures=True)
  else:pool.shutdown(wait=True)
 return {'rows_tested':sum(r['tested'] for r in results),'expected':212896,'survivors':survivors,'seconds':time.time()-start,'coverage_complete':len(results)==8 and not survivors,'all_owned_workers_closed':True,'workers':12,'threads_each':1}
def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 return execute_stop_on_survivor(K4_CIPHERTEXT,out)

if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
