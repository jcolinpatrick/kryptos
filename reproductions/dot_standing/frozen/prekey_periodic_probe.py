"""Plaintext scatter then unit-affine periodic key; explicit geometry-restricted universe."""
import hashlib,json,random,time,sys,os,itertools,datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,KA,CRIBS
from routed_probe import pullback,scatter
from cryptolab.research_bridge.cribsolve_perm import stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages
UNITS=(1,3,5,7,9,11,15,17,19,21,23,25);PERIODS=tuple(range(1,13));WORKERS=12;J=sorted(CRIBS);_BANK={};_GEOMETRY=[]
def configs():return [(period,pa,ca,g) for period in PERIODS for pa in (AZ,KA) for ca in (AZ,KA) for g in UNITS]
def eligible(routes,period):
 positions=routes[:,J]%period
 return np.logical_and.reduce([np.any(positions==r,axis=1) for r in range(period)])
def geometry():return _GEOMETRY
def bank(outstr):
 if outstr not in _BANK:
  o=Path(outstr);_BANK[outstr]=(np.load(o/'routes.npy',mmap_mode='r'),json.loads((o/'routes.json').read_text()))
 return _BANK[outstr]
def search_space_size(out):
 global _GEOMETRY
 routes=np.load(out/'routes.npy');_GEOMETRY=[{'period':p,'eligible_routes':int(np.count_nonzero(eligible(routes,p))),'ineligible_routes':int(np.count_nonzero(~eligible(routes,p))),'redundant_equations':24-p} for p in PERIODS]
 result={'periods':_GEOMETRY,'route_bank_size':len(routes),'involutions':int(np.count_nonzero(np.all(np.take_along_axis(routes,routes,axis=1)==np.arange(97),axis=1))),'gate_inputs':'route array and24PUBinputindices only; no ciphertext','route_direction':'inputi -> middleoutput route[i]'}
 payload=json.dumps(result,indent=2)+'\n';path=out/'eligibility.json'
 if path.exists():assert path.read_text()==payload
 else:path.write_text(payload)
 return sum(r['eligible_routes']*48 for r in _GEOMETRY)
def encode(pt,cfg,key,route):
 period,pa,ca,g=cfg;middle=scatter(pt,route)
 return ''.join(ca[(g*pa.index(ch)+key[j%period])%26] for j,ch in enumerate(middle))
def decode(ct,cfg,key,route):
 period,pa,ca,g=cfg;inverse=pow(g,-1,26);middle=''.join(pa[(inverse*(ca.index(ch)-key[j%period]))%26] for j,ch in enumerate(ct))
 return pullback(middle,route)
def primary_data(data,cfg,routes):
 period,pa,ca,g=cfg;allowed=np.flatnonzero(eligible(routes,period));positions=routes[allowed][:,J];residues=positions%period
 mapping=np.asarray([ca.index(ch) for ch in AZ],dtype=np.int32);known=np.asarray([pa.index(CRIBS[i]) for i in J],dtype=np.int32);y=(np.take_along_axis(mapping[data[allowed]],positions,axis=1)-g*known)%26;keys=np.zeros((len(allowed),period),dtype=np.int32);rows=np.arange(len(allowed))
 for r in range(period):keys[:,r]=y[rows,np.argmax(residues==r,axis=1)]
 good=np.flatnonzero(np.all(y==keys[rows[:,None],residues],axis=1));return {int(allowed[i]):keys[i].tolist() for i in good},len(allowed)
def reference_data(data,cfg,routes):
 period,pa,ca,g=cfg;known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};indices=list(known);pd={ch:i for i,ch in enumerate(pa)};cd={ch:i for i,ch in enumerate(ca)};actual=np.asarray([cd[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int32)[data];positions=np.asarray(routes[:,indices],dtype=np.int32);keys=np.zeros((len(routes),period),dtype=np.int32);covered=np.ones(len(routes),dtype=bool);rows=np.arange(len(routes))
 for r in range(period):
  mask=positions%period==r;covered &= np.any(mask,axis=1);last=len(indices)-1-np.argmax(mask[:,::-1],axis=1);anchor=positions[rows,last];plain=np.asarray([pd[known[i]] for i in indices],dtype=np.int32);keys[:,r]=(actual[rows,anchor]-g*plain[last])%26
 accept=covered.copy()
 for col,i in enumerate(indices):accept &= actual[rows,positions[:,col]]==(g*pd[known[i]]+keys[rows,positions[:,col]%period])%26
 return {int(i):keys[i].tolist() for i in np.flatnonzero(accept)}
def scan(ct,cfg,routes,stop_path=None,metadata=None):
 data=np.broadcast_to(np.asarray([AZ.index(ch) for ch in ct],dtype=np.uint8),(len(routes),97));primary_hits,tested=primary_data(data,cfg,routes);primary=primary_hits
 if primary!=reference_data(data,cfg,routes):raise RuntimeError('firstanchor bulk/lastanchor independentforward disagreement')
 survivors=[]
 for index,key in primary.items():
  pt=decode(ct,cfg,key,routes[index]);assert all(pt[i]==ch for i,ch in CRIBS.items());assert encode(pt,cfg,key,routes[index])==ct
  hit={'config':cfg,'route_index':index,'key':key,'plaintext':pt,'is_solution':False}
  if metadata is not None:
   m=metadata[index];middle=run_stages(stages_for_label(m['label'],97),pt,m['mode']);period,pa,ca,g=cfg;independent=''.join(ca[(g*pa.index(ch)+key[j%period])%26] for j,ch in enumerate(middle));assert independent==ct;hit['route']=m
  survivors.append(hit)
  if stop_path is not None:
   try:
    with stop_path.open('x') as f:f.write(json.dumps(hit)+'\n')
   except FileExistsError:pass
   break
 return {'tested':tested,'survivors':survivors}

def match_batch(data,cfg,routes):
 a,tested=primary_data(data,cfg,routes);b=reference_data(data,cfg,routes)
 if a!=b:raise RuntimeError('batched first/last-anchor mismatch')
 return a

def progress(text):
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' '+text+'\n')
def scan_task(task):
 outstr,cfg,ct,fid,stop=task;out=Path(outstr);routes,meta=bank(outstr);flag=out/'survivor-worker-stop.json'
 if stop and flag.exists():return {'fixture':fid,'config':cfg,'tested':0,'survivors':[],'stopped':True}
 assert time.time()<1791329400
 result=scan(ct,cfg,routes,flag if stop else None,meta);return {'fixture':fid,'config':cfg,**result}
def control_cell(task):
 outstr,ci,cfg=task;routes,meta=bank(outstr);period,pa,ca,g=cfg;allowed=np.flatnonzero(eligible(routes,period));rng=random.Random(202610062300+ci);positive=[];near=[];randoms=[];route_rows=[];keys=[];direction_checked=0
 for trial in range(200):
  assert time.time()<1791329400
  key=[rng.randrange(26) for _ in range(period)];pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);idx=int(rng.choice(allowed));route=routes[idx];m=meta[idx];ct=encode(pt,cfg,key,route);assert decode(ct,cfg,key,route)==pt
  middle=run_stages(stages_for_label(m['label'],97),pt,m['mode']);independent=''.join(ca[(g*pa.index(ch)+key[j%period])%26] for j,ch in enumerate(middle));assert independent==ct
  positions=[int(route[i]) for i in J];miss=next(j for j in positions if sum(x%period==j%period for x in positions)>=2);changed=list(ct);changed[miss]=ca[(ca.index(changed[miss])+1)%26]
  positive.append([AZ.index(ch) for ch in ct]);near.append([AZ.index(ch) for ch in changed]);randoms.append([rng.randrange(26) for _ in range(97)]);route_rows.append(route);keys.append(key)
  if trial==0 and not np.array_equal(route,np.argsort(route)):
   inv=np.argsort(route);result=scan(ct,cfg,np.asarray([inv]))
   if not result['survivors']:direction_checked+=1
 a=match_batch(np.asarray(positive,dtype=np.uint8),cfg,np.asarray(route_rows));b=match_batch(np.asarray(near,dtype=np.uint8),cfg,np.asarray(route_rows));c=match_batch(np.asarray(randoms,dtype=np.uint8),cfg,np.asarray(route_rows));assert a=={i:key for i,key in enumerate(keys)} and not b and not c
 if ci%32==0:progress(Path(outstr).name+' prekeyperiodic local'+str(ci)+'/575;200truth+200certifiednear+200random pass;target0')
 return {'config':cfg,'plants':200,'near_rejected':200,'random_rejected':200,'eligible_routes':len(allowed),'direction_negative_examples':direction_checked,'full_plaintext_recovered':200,'prekey_stage_roundtrips':200}
def controls(out):
 start=time.time();routes,meta=bank(str(out));cfgs=configs();expected=search_space_size(out)
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:records=list(pool.map(control_cell,[(str(out),i,c) for i,c in enumerate(cfgs)]))
 rng=random.Random(202610062301);fixtures=[]
 for fid,(pa,ca,g) in enumerate(itertools.product((AZ,KA),(AZ,KA),UNITS)):
  period=1+fid%12;cfg=(period,pa,ca,g);key=[rng.randrange(26) for _ in range(period)];pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);idx=int(rng.choice(np.flatnonzero(eligible(routes,period))));m=meta[idx];ct=encode(pt,cfg,key,routes[idx]);fixtures.append({'id':fid,'truth_config':cfg,'truth_route':idx,'truth_key':key,'plaintext':pt,'ciphertext':ct})
 for j in range(8):fixtures.append({'id':48+j,'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:
  for f in fixtures:
   t=time.time();rs=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in cfgs]));hits=[h for r in rs for h in r['survivors']];assert sum(r['tested'] for r in rs)==expected
   if not f.get('random_only'):assert any(tuple(h['config'])==tuple(f['truth_config']) and h['route_index']==f['truth_route'] and h['key']==f['truth_key'] and h['plaintext']==f['plaintext'] for h in hits)
   else:assert not hits
   summary={'fixture_id':f['id'],'tested':expected,'compatible_candidates':len(hits),'distinct_plaintexts':len({h['plaintext'] for h in hits}),'true_config_route_key_plaintext_recovered':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary);(out/('full-control-'+str(f['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n');progress(out.name+' prekeyfullfixture'+str(f['id'])+'/55;'+str(expected)+'contexts;candidates'+str(len(hits))+';target0;'+str(summary['seconds'])+'s')
 return {'passed':True,'plants':115200,'near_miss_cases':115200,'random_cases':115200,'records':records,'full_universe_plants':48,'full_universe_randoms':8,'full_scope_controls':full,'full_universe_evaluations':sum(x['tested'] for x in full),'seconds':time.time()-start,'workers':12,'threads_each':1,'geometry':json.loads((out/'eligibility.json').read_text()),'ineligible_cells_untested':True,'no_blind_or_statistical_claim':True}
def execute_stop_on_survivor(ct,out):
 start=time.time();pool=ProcessPoolExecutor(max_workers=WORKERS);results=[];survivors=[];failed=False
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
 return {'rows_tested':sum(r['tested'] for r in results),'expected':search_space_size(out),'survivors':survivors,'seconds':time.time()-start,'coverage_complete':len(results)==len(configs()) and sum(r['tested'] for r in results)==search_space_size(out) and len({tuple(r['config']) for r in results})==len(configs()) and not survivors,'all_owned_workers_closed':True,'workers':WORKERS,'threads_each':1}
def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 return execute_stop_on_survivor(K4_CIPHERTEXT,out)

if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
