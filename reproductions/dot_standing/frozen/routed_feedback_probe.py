"""Ciphertext feedback followed by finite route, with full-offset forward oracle."""
import hashlib,json,random,time,sys,os,itertools,datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,KA,CRIBS
from feedback_probe import configs,encode,decode,oracle
from routed_probe import pullback,scatter
from cryptolab.research_bridge.cribsolve_perm import stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages
WORKERS=int(os.environ.get('K4_NUMERIC_WORKERS','12'));assert 1<=WORKERS<=26
J=sorted(CRIBS);_BANK={}
def geometry():return [{'lag':l,'eligible_cribs':sum(i>=l for i in J),'unrecovered_primer':l,'recovered_suffix':97-l,'route_independent':True} for l in range(1,26)]
def search_space_size(out):return 800*len(np.load(out/'routes.npy',mmap_mode='r'))
def bank(outstr):
 if outstr not in _BANK:
  o=Path(outstr);_BANK[outstr]=(np.load(o/'routes.npy',mmap_mode='r'),json.loads((o/'routes.json').read_text()))
 return _BANK[outstr]
def match_data(data,cfg):
 lag,pa,ca,ka,sp,sk=cfg;j=np.asarray([i for i in J if i>=lag]);assert len(j)>=20
 cp=np.asarray([ca.index(ch) for ch in AZ],dtype=np.int16);kp=np.asarray([ka.index(ch) for ch in AZ],dtype=np.int16);pv=np.asarray([pa.index(CRIBS[int(i)]) for i in j],dtype=np.int16)
 delta=(cp[data[:,j]]-sp*pv-sk*kp[data[:,j-lag]])%26
 good=np.flatnonzero(np.all(delta==delta[:,0,None],axis=1));primary={int(i):int(delta[i,0]) for i in good}
 # Independent forward oracle: own literal/alphabets, all26 offset choices,
 # exact first-two necessary predicates before the complete remaining check.
 known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};pos=np.asarray([i for i in known if i>=lag]);pmap={ch:i for i,ch in enumerate(pa)};cmap={ch:i for i,ch in enumerate(ca)};kmap={ch:i for i,ch in enumerate(ka)}
 cv=np.asarray([cmap[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int16);kv=np.asarray([kmap[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int16);plain=np.asarray([sp*pmap[known[int(i)]] for i in pos],dtype=np.int16)
 f0=plain[0]+sk*kv[data[:,pos[0]-lag]];f1=plain[1]+sk*kv[data[:,pos[1]-lag]];actual0=cv[data[:,pos[0]]];actual1=cv[data[:,pos[1]]];reference={}
 for offset in range(26):
  cand=np.flatnonzero((actual0==(f0+offset)%26)&(actual1==(f1+offset)%26))
  if not len(cand):continue
  expected=(plain+sk*kv[data[cand[:,None],(pos-lag)[None,:]]]+offset)%26
  accept=np.all(cv[data[cand[:,None],pos[None,:]]]==expected,axis=1)
  for i in cand[accept]:reference[int(i)]=offset
 if primary!=reference:raise RuntimeError('residual/forward-all26offset-oracle disagreement')
 return primary

def verify(ct,cfg,d):
 lag,pa,ca,ka,sp,sk=cfg;assert oracle(ct,cfg)==[d]
 partial=decode(ct,cfg,d);out=list(ct[:lag])
 for i in range(lag,97):out.append(ca[(sp*pa.index(partial[i])+sk*ka.index(out[i-lag])+d)%26])
 assert ''.join(out)==ct
 return {'config':cfg,'offset':d,'partial_plaintext':partial,'recovered_suffix':partial[lag:],'suffix_length':97-lag,'primer_length':lag,'primer_unrecovered':True,'prefix_crib_letters_are_givens_not_recovery':{i:ch for i,ch in CRIBS.items() if i<lag},'reencode_is_suffix_implementation_check_not_primer_recovery':True,'is_solution':False}
def scan_task(task):
 outstr,cfg,ct,fid,stop=task;o=Path(outstr);routes,meta=bank(outstr);flag=o/'survivor-worker-stop.json'
 if stop and flag.exists():return {'fixture':fid,'config':cfg,'tested':0,'survivors':[]}
 if time.time()>=1791329400:raise RuntimeError('authorization ended')
 nums=np.asarray([AZ.index(ch) for ch in ct],dtype=np.uint8);data=nums[routes];matches=match_data(data,cfg);hits=[]
 for i,d in matches.items():
  if stop and flag.exists():break
  pre=''.join(AZ[int(v)] for v in data[i]);h=verify(pre,cfg,d);m=meta[i];assert run_stages(stages_for_label(m['label'],97),pre,m['mode'])==ct
  h.update(route_index=i,route=m);hits.append(h)
  if stop:
   try:
    with flag.open('x') as f:f.write(json.dumps(h)+'\n')
   except FileExistsError:pass
   break
 return {'fixture':fid,'config':cfg,'tested':len(routes),'survivors':hits}
def progress(s):
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' '+s+'\n')
def control_cell(task):
 outstr,ci,cfg=task;routes,meta=bank(outstr);lag,pa,ca,ka,sp,sk=cfg;rng=random.Random(202610061500+ci);positive=[];near=[];randoms=[];ds=[];pts=[]
 for t in range(200):
  assert time.time()<1791329400
  pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);d=rng.randrange(26);primer=[rng.randrange(26) for _ in range(lag)];pre=encode(pt,cfg,d,primer)
  idx=(ci*200+t)%len(routes);m=meta[idx];ct=run_stages(stages_for_label(m['label'],97),pre,m['mode']);restored=pullback(ct,routes[idx]);assert restored==pre
  h=verify(restored,cfg,d);assert h['recovered_suffix']==pt[lag:]
  miss=next(i for i in J if i>=lag);changed=list(pre);changed[miss]=ca[(ca.index(changed[miss])+1)%26];changed=''.join(changed)
  # Only PUB rows miss and miss+lag can change, leaving >=18 fixing offset.
  assert oracle(changed,cfg)==[]
  positive.append([AZ.index(ch) for ch in restored]);near.append([AZ.index(ch) for ch in changed]);randoms.append([rng.randrange(26) for _ in range(97)]);ds.append(d);pts.append(pt)
 a=match_data(np.asarray(positive,dtype=np.uint8),cfg);b=match_data(np.asarray(near,dtype=np.uint8),cfg);c=match_data(np.asarray(randoms,dtype=np.uint8),cfg)
 assert a=={i:d for i,d in enumerate(ds)} and not b and not c
 if ci%25==0:progress(Path(outstr).name+' feedbacklocalcell'+str(ci)+'/799;200truthsuffix+200certifiednear+200random pass;target0')
 return {'config':cfg,'plants':200,'exact_offset_suffix_recovered':200,'near_miss_rejected':200,'random_rejected':200,'eligible_cribs':sum(i>=lag for i in J),'primer_not_recovered':True,'route_indices_cycled':'every26612map hit at least6times across160000plants'}
def controls(out):
 start=time.time();routes,meta=bank(str(out));cfgs=configs()
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:records=list(pool.map(control_cell,[(str(out),i,c) for i,c in enumerate(cfgs)]))
 rng=random.Random(202610061501);fixtures=[];strata={}
 for i,m in enumerate(meta):strata.setdefault((m['label'].split(':')[0],m['mode']),i)
 route_samples=list(strata.values())
 for fid,alphabet_signs in enumerate(itertools.product((AZ,KA),(AZ,KA),(AZ,KA),(1,-1),(1,-1))):
  lag=1+fid%25;cfg=[lag,*alphabet_signs];pa=cfg[1];pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);d=rng.randrange(26);primer=[rng.randrange(26) for _ in range(lag)];idx=route_samples[fid%len(route_samples)];m=meta[idx];ct=run_stages(stages_for_label(m['label'],97),encode(pt,cfg,d,primer),m['mode'])
  fixtures.append({'id':fid,'truth_config':cfg,'truth_route':idx,'truth_offset':d,'plaintext':pt,'primer':primer,'ciphertext':ct})
 for j in range(8):fixtures.append({'id':32+j,'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:
  for f in fixtures:
   t=time.time();rs=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in cfgs]));hits=[h for r in rs for h in r['survivors']];assert sum(r['tested'] for r in rs)==21289600
   if not f.get('random_only'):assert any(h['config']==f['truth_config'] and h['route_index']==f['truth_route'] and h['offset']==f['truth_offset'] and h['recovered_suffix']==f['plaintext'][f['truth_config'][0]:] for h in hits)
   summary={'fixture_id':f['id'],'tested':21289600,'candidates':len(hits),'distinct_partial_plaintexts':len({hashlib.sha256(h['partial_plaintext'].encode()).hexdigest() for h in hits}),'true_cfg_route_offset_suffix_recovered':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary)
   (out/('full-control-'+str(f['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n');progress(out.name+' feedbackfullfixture'+str(f['id'])+'/39;21289600configs;candidates'+str(len(hits))+';target0;'+str(summary['seconds'])+'s')
 return {'passed':True,'plants':160000,'random_cases':160000,'near_miss_cases':160000,'base_configurations':800,'records':records,'full_universe_plants':32,'full_universe_randoms':8,'full_universe_evaluations':sum(r['tested'] for r in full),'full_scope_controls':full,'seconds':time.time()-start,'workers':WORKERS,'threads_each':1,'minimum_eligible_cribs':20,'primer_membership_never_counted_as_recovery':True,'bank_size':len(routes),'no_statistical_or_blind_K4_claim':True}
def execute_stop_on_survivor(ct,out):
 start=time.time();pool=ProcessPoolExecutor(max_workers=WORKERS);results=[];hits=[];failed=False
 try:
  pending={pool.submit(scan_task,(str(out),cfg,ct,'single-pass',True)) for cfg in configs()}
  while pending:
   done,pending=wait(pending,timeout=0.1,return_when=FIRST_COMPLETED)
   for f in done:results.append(f.result())
   if (out/'survivor-worker-stop.json').exists():hits=[json.loads((out/'survivor-worker-stop.json').read_text())];break
   if time.time()>=1791329400:raise RuntimeError('authorization ended')
 except Exception:failed=True;raise
 finally:
  if hits or failed:
   for worker in list(pool._processes.values()):worker.terminate()
   pool.shutdown(wait=True,cancel_futures=True)
  else:pool.shutdown(wait=True)
 expected=search_space_size(out);tested=sum(r['tested'] for r in results)
 return {'rows_tested':tested,'expected':expected,'survivors':hits,'seconds':time.time()-start,'coverage_complete':tested==expected and len(results)==800 and len({tuple(r['config']) for r in results})==800 and not hits,'all_owned_workers_closed':True,'workers':WORKERS,'threads_each':1}
def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 return execute_stop_on_survivor(K4_CIPHERTEXT,out)
if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
