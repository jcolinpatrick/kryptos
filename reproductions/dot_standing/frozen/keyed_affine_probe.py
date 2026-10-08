"""Constant unit-affine alphabet map plus exhaustive keyed-columnar bank."""
import hashlib,json,random,time,sys,os,itertools,datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,KA,CRIBS
from routed_probe import pullback,scatter
import keyed_routes
UNITS=(1,3,5,7,9,11,15,17,19,21,23,25);WORKERS=12;J=sorted(CRIBS);_BANK={};_GEOMETRY={}
def configs():return [(pa,ca,g) for pa in (AZ,KA) for ca in (AZ,KA) for g in UNITS]
def geometry():return _GEOMETRY
def bank(outstr):
 if outstr not in _BANK:
  o=Path(outstr);_BANK[outstr]=(np.load(o/'routes.npy',mmap_mode='r'),json.loads((o/'routes.json').read_text()),np.load(o/'reference_routes.npy',mmap_mode='r'))
 return _BANK[outstr]
def search_space_size(out):
 global _GEOMETRY
 _GEOMETRY=json.loads((out/'bank-audit.json').read_text());assert _GEOMETRY['passed'];return len(configs())*_GEOMETRY['unique_maps']
def encode(pt,cfg,offset):
 pa,ca,g=cfg;return ''.join(ca[(g*pa.index(ch)+offset)%26] for ch in pt)
def decode(pre,cfg,offset):
 pa,ca,g=cfg;return ''.join(pa[(pow(g,-1,26)*(ca.index(ch)-offset))%26] for ch in pre)
def primary_offsets(data,cfg):
 pa,ca,g=cfg;mapping=np.asarray([ca.index(ch) for ch in AZ],dtype=np.int32);p=np.asarray([pa.index(CRIBS[i]) for i in J],dtype=np.int32);delta=(mapping[data[:,J]]-g*p)%26;valid=np.flatnonzero(np.all(delta==delta[:,0,None],axis=1));primary={int(i):int(delta[i,0]) for i in valid}
 return primary
def reference_offsets(data,cfg):
 pa,ca,g=cfg;known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};positions=list(known);pd={ch:i for i,ch in enumerate(pa)};cd={ch:i for i,ch in enumerate(ca)};values=np.asarray([cd[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int32)[data];reference={}
 for offset in range(26):
  cand=np.flatnonzero((values[:,positions[0]]==(g*pd[known[positions[0]]]+offset)%26)&(values[:,positions[1]]==(g*pd[known[positions[1]]]+offset)%26))
  if not len(cand):continue
  accept=np.all(values[cand[:,None],positions]==np.asarray([(g*pd[known[i]]+offset)%26 for i in positions])[None,:],axis=1)
  for i in cand[accept]:reference[int(i)]=offset
 return reference
def match_data(data,cfg,reference_data=None):
 primary=primary_offsets(data,cfg)
 if primary!=reference_offsets(data if reference_data is None else reference_data,cfg):raise RuntimeError('constantresidual/full26offset independentforward disagreement')
 return primary
def scan(ct,cfg,routes,stop_path=None,metadata=None,reference_routes=None):
 nums=np.asarray([AZ.index(ch) for ch in ct],dtype=np.uint8);data=nums[routes];reference_data=data if reference_routes is None else nums[reference_routes];primary=match_data(data,cfg,reference_data);survivors=[]
 for index,key in primary.items():
  pre=pullback(ct,routes[index]);pt=decode(pre,cfg,key);assert all(pt[i]==ch for i,ch in CRIBS.items());assert scatter(encode(pt,cfg,key),routes[index])==ct
  hit={'config':cfg,'route_index':index,'offset':key,'plaintext':pt,'is_solution':False}
  if metadata is not None:hit['route']=metadata[index];assert keyed_routes.apply(metadata[index],encode(pt,cfg,key))==ct
  survivors.append(hit)
  if stop_path is not None:
   try:
    with stop_path.open('x') as f:f.write(json.dumps(hit)+'\n')
   except FileExistsError:pass
   break
 return {'tested':len(routes),'survivors':survivors}
def scan_task(task):
 outstr,cfg,ct,fid,stop=task;out=Path(outstr);routes,meta,ref=bank(outstr);flag=out/'survivor-worker-stop.json'
 if stop and flag.exists():return {'fixture':fid,'config':cfg,'tested':0,'survivors':[],'stopped':True}
 assert time.time()<1791329400;return {'fixture':fid,'config':cfg,**scan(ct,cfg,routes,flag if stop else None,meta,ref)}
def progress(text):
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' '+text+'\n')
def controls(out):
 start=time.time();routes,meta,ref=bank(str(out));assert np.array_equal(routes,ref);rng=random.Random(2026100625);records=[]
 for cfg in configs():
  pa,ca,g=cfg;positive=[];near=[];randoms=[];offsets=[]
  for trial in range(200):
   assert time.time()<1791329400
   pt=[rng.choice(pa) for _ in range(97)]
   for i,ch in CRIBS.items():pt[i]=ch
   pt=''.join(pt);offset=(0 if trial==0 else 13 if trial==1 else rng.randrange(26));idx=rng.randrange(len(routes));ct=keyed_routes.apply(meta[idx],encode(pt,cfg,offset));pre=pullback(ct,routes[idx]);assert decode(pre,cfg,offset)==pt
   independent=keyed_routes.apply({**meta[idx],'mode':'decode' if meta[idx]['mode']=='encode' else 'encode'},ct);assert independent==pre
   changed=list(pre);miss=J[1];changed[miss]=ca[(ca.index(changed[miss])+1)%26];positive.append([AZ.index(ch) for ch in pre]);near.append([AZ.index(ch) for ch in changed]);randoms.append([rng.randrange(26) for _ in range(97)]);offsets.append(offset)
  assert match_data(np.asarray(positive,dtype=np.uint8),cfg)=={i:o for i,o in enumerate(offsets)} and not match_data(np.asarray(near,dtype=np.uint8),cfg) and not match_data(np.asarray(randoms,dtype=np.uint8),cfg)
  records.append({'config':cfg,'plants':200,'near_rejected':200,'random_rejected':200,'plaintext97_recovered':200});progress(out.name+' keyedaffine local'+str(len(records))+'/48 passed200truth+200nonfirstcorruptions+200random;target0')
 fixtures=[]
 for fid,cfg in enumerate(configs()):
  pt=[rng.choice(cfg[0]) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);offset=rng.randrange(26);idx=rng.randrange(len(routes));fixtures.append({'id':fid,'truth_config':cfg,'truth_route':idx,'truth_offset':offset,'plaintext':pt,'ciphertext':keyed_routes.apply(meta[idx],encode(pt,cfg,offset))})
 for j in range(8):fixtures.append({'id':48+j,'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[];expected=search_space_size(out)
 with ProcessPoolExecutor(max_workers=12) as pool:
  for f in fixtures:
   t=time.time();rs=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in configs()]));hits=[h for r in rs for h in r['survivors']];assert sum(r['tested'] for r in rs)==expected
   if not f.get('random_only'):assert any(tuple(h['config'])==tuple(f['truth_config']) and h['route_index']==f['truth_route'] and h['offset']==f['truth_offset'] and h['plaintext']==f['plaintext'] for h in hits)
   else:assert not hits
   summary={'fixture_id':f['id'],'tested':expected,'compatible_candidates':len(hits),'distinct_plaintexts':len({h['plaintext'] for h in hits}),'true_config_route_offset_plaintext_recovered':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary);(out/('full-control-'+str(f['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n');progress(out.name+' keyedaffine fullfixture'+str(f['id'])+'/55;'+str(expected)+'contexts;candidates'+str(len(hits))+';target0;'+str(summary['seconds'])+'s')
 return {'passed':True,'plants':9600,'near_miss_cases':9600,'random_cases':9600,'records':records,'bank_audit':json.loads((out/'bank-audit.json').read_text()),'full_scope_controls':full,'full_universe_evaluations':sum(x['tested'] for x in full),'full_universe_plants':48,'full_universe_randoms':8,'seconds':time.time()-start,'workers':12,'threads_each':1,'no_blind_or_statistical_claim':True}
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
