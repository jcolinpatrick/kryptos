"""Hill-2 then exhaustive keyed columnar; synthetic controls precede every target."""
import datetime,hashlib,json,math,os,random,sys,time,itertools
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
import hill_columnar_core as core
import keyed_bank_access as access
import keyed_routes
from hill_probe import AZ,KA,CRIBS,inverse
from routed_probe import pullback,scatter

WORKERS=int(os.environ.get('K4_WORKERS','2'));BATCH_SIZE=int(os.environ.get('K4_BATCH_SIZE','65536'))
assert 1<=WORKERS<=26 and 1<=BATCH_SIZE<=65536
configs=core.configs;bank=access.bank;match_data=core.match_data
_GEOMETRY={}

def progress(message):
 with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' '+message+'\n')

def search_space_size(out):
 global _GEOMETRY
 audit=json.loads((Path(out)/'bank-audit.json').read_text());assert audit['passed'];_GEOMETRY={'bank':audit,'bases':core.geometry()};return len(configs())*audit['unique_maps']
def geometry():return _GEOMETRY

def scan(ct,cfg,routes,stop_path=None,metadata=None,reference_routes=None):
 nums=np.asarray([cfg[2].index(ch) for ch in ct],dtype=np.uint8);survivors=[];tested=0
 for route_offset in range(0,len(routes),BATCH_SIZE):
  assert time.time()<1791329400
  subset=routes[route_offset:route_offset+BATCH_SIZE];ref=subset if reference_routes is None else reference_routes[route_offset:route_offset+BATCH_SIZE]
  primary=match_data(nums[subset],cfg,nums[ref]);tested+=len(subset)
  for local_index,key in primary.items():
   index=route_offset+local_index;pre=pullback(ct,routes[index]);pt=core.decode(pre,key,cfg);assert all(pt[i]==ch for i,ch in CRIBS.items());encoded=core.encrypt(pt,key,cfg);assert scatter(encoded,routes[index])==ct
   hit={'config':cfg,'route_index':index,'key':key,'plaintext':pt,'is_solution':False}
   if metadata is not None:hit['route']=metadata[index];assert keyed_routes.apply(metadata[index],encoded)==ct
   survivors.append(hit)
   if stop_path is not None:
    try:
     with stop_path.open('x') as f:json.dump(hit,f)
    except FileExistsError:pass
    return {'tested':tested,'survivors':survivors}
 return {'tested':tested,'survivors':survivors}

def scan_task(task):
 outstr,cfg,ct,fid,stop=task;out=Path(outstr);routes,meta,reference=bank(outstr);flag=out/'survivor-worker-stop.json'
 if stop and flag.exists():return {'fixture':fid,'config':cfg,'tested':0,'survivors':[],'stopped':True}
 return {'fixture':fid,'config':cfg,**scan(ct,cfg,routes,flag if stop else None,meta,reference)}

def random_key(rng):
 while True:
  key=[[rng.randrange(26),rng.randrange(26)],[rng.randrange(26),rng.randrange(26)]]
  if math.gcd(key[0][0]*key[1][1]-key[0][1]*key[1][0],26)==1:return key
def plaintext(rng):
 pt=[rng.choice(AZ) for _ in range(97)]
 for i,ch in CRIBS.items():pt[i]=ch
 return ''.join(pt)

def control_base(task):
 outstr,cfg=task;out=Path(outstr);routes,meta,reference=bank(outstr);ci=configs().index(tuple(cfg));rng=random.Random(202610063000+ci);seen=set()
 for trial in range(200):
  key=random_key(rng)
  while tuple(map(tuple,key)) in seen:key=random_key(rng)
  seen.add(tuple(map(tuple,key)));pt=plaintext(rng);idx=rng.randrange(len(routes));pre=core.encrypt(pt,key,cfg);ct=keyed_routes.apply(meta[idx],pre)
  result=scan(ct,cfg,routes[[idx]],metadata=[meta[idx]],reference_routes=reference[[idx]]);hit=next(h for h in result['survivors'] if h['route_index']==0);assert hit['key']==key and hit['plaintext']==pt
  full,partial,rows,pivots=core._primary_geometry(cfg);start=partial[0];known=next(j for j in (0,1) if start+j in CRIBS);inv=inverse(key);column=next(k for k in (0,1) if inv[k][known]%26);bad=list(pre);bad[start+column]=cfg[2][(cfg[2].index(bad[start+column])+1)%26]
  for text in (''.join(bad),''.join(rng.choice(AZ) for _ in range(97))):assert not match_data(np.asarray([[cfg[2].index(ch) for ch in text]],dtype=np.uint8),cfg)
 record={'config':cfg,'plants':200,'distinct_keys':len(seen),'exact_key_plaintext_recovered':200,'certified_partial_corruptions_rejected':200,'random_rejected':200};(out/('base-control-'+str(ci)+'.json')).write_text(json.dumps(record)+'\n');progress(out.name+' Hill2 base'+str(ci)+' plants200/200 exactkey/PT,near200,random200;target0');return record

def control_provenance(out):
 spec=json.loads((out/'spec.json').read_text())
 files=[Path(__file__),Path(core.__file__),Path(access.__file__),Path(keyed_routes.__file__),Path(sys.modules['hill_probe'].__file__)]
 return {'sources':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in files},'bank_source_hashes':spec['bank_source_hashes'],'search_space_size':search_space_size(out)}

def controls(out,resume=False):
 start=time.time();routes,meta,reference=bank(str(out));stamp=control_provenance(out);strata=[(w,mode) for w in _GEOMETRY['bank']['widths'] for mode in ('encode','decode')]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:records=list(pool.map(control_base,[(str(out),cfg) for cfg in configs()]))
 fixtures=[];rng=random.Random(202610063099)
 for ci,cfg in enumerate(configs()):
  for width,mode in strata:
   rank=rng.randrange(math.factorial(width))
   if ci==0 and width==2 and mode=='encode':rank=0
   if ci==0 and width==max(w for w,m in strata) and mode=='decode':rank=math.factorial(width)-1
   idx=meta.index(width,mode,rank);pt=plaintext(rng);key=random_key(rng);fixtures.append({'id':len(fixtures),'truth_config':cfg,'truth_route':idx,'truth_key':key,'plaintext':pt,'ciphertext':keyed_routes.apply(meta[idx],core.encrypt(pt,key,cfg))})
 for _ in range(8):fixtures.append({'id':len(fixtures),'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:
  for f in fixtures:
   path=out/('full-control-'+str(f['id'])+'.json');digest=hashlib.sha256(f['ciphertext'].encode()).hexdigest()
   if resume and path.exists():
    saved=json.loads(path.read_text());assert saved['provenance']==stamp and saved['summary']['ciphertext_sha256']==digest;full.append(saved['summary']);continue
   t=time.time();results=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in configs()]));hits=[hit for result in results for hit in result['survivors']];assert sum(result['tested'] for result in results)==stamp['search_space_size']
   if not f.get('random_only'):
    true=next(h for h in hits if tuple(h['config'])==tuple(f['truth_config']) and h['route_index']==f['truth_route']);assert true['key']==f['truth_key'] and true['plaintext']==f['plaintext']
   else:assert not hits
   summary={'fixture_id':f['id'],'ciphertext_sha256':digest,'tested':stamp['search_space_size'],'compatible_candidates':len(hits),'true_key_route_plaintext_recovered':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary);tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps({'summary':summary,'hits':hits,'provenance':stamp})+'\n');tmp.replace(path);progress(out.name+' Hill2 fullfixture'+str(f['id'])+'/'+str(len(fixtures)-1)+' '+str(summary['tested'])+'contexts hits'+str(len(hits))+';target0')
 return {'passed':True,'plants':sum(r['plants'] for r in records),'records':records,'base_records':records,'full_scope_controls':full,'full_universe_plants':len(fixtures)-8,'full_universe_randoms':8,'full_universe_evaluations':sum(r['tested'] for r in full),'seconds':time.time()-start,'workers':WORKERS,'threads_each':1,'matrix_universe_per_base':157248,'scope':'Hill2 first, then frozen keyed columnar; 24 crib letters; numeric edge pass-through; no probability or blind-target claim'}

def execute_stop_on_survivor(ct,out):
 start=time.time();pool=ProcessPoolExecutor(max_workers=WORKERS);results=[];survivors=[];failed=False
 try:
  pending={pool.submit(scan_task,(str(out),cfg,ct,'single-pass',True)) for cfg in configs()}
  while pending:
   done,pending=wait(pending,timeout=.1,return_when=FIRST_COMPLETED)
   for future in done:results.append(future.result())
   if (out/'survivor-worker-stop.json').exists():survivors=[json.loads((out/'survivor-worker-stop.json').read_text())];break
   if time.time()>=1791329400:raise RuntimeError('authorization ended')
 except BaseException:failed=True;raise
 finally:
  if survivors or failed:
   for worker in list(pool._processes.values()):worker.terminate()
   pool.shutdown(wait=True,cancel_futures=True)
  else:pool.shutdown(wait=True)
 expected=search_space_size(out)
 return {'rows_tested':sum(r['tested'] for r in results),'expected':expected,'survivors':survivors,'seconds':time.time()-start,'coverage_complete':len(results)==len(configs()) and len({tuple(r['config']) for r in results})==len(configs()) and sum(r['tested'] for r in results)==expected and not survivors,'all_owned_workers_closed':True,'workers':WORKERS,'threads_each':1}

def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 return execute_stop_on_survivor(K4_CIPHERTEXT,out)

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['controls','benchmark']);parser.add_argument('out');parser.add_argument('--workers',type=int,default=WORKERS);parser.add_argument('--batch-size',type=int,default=BATCH_SIZE);parser.add_argument('--affinity',choices=['none'],default='none');parser.add_argument('--resume',action='store_true');args=parser.parse_args();WORKERS=args.workers;BATCH_SIZE=args.batch_size;assert 1<=WORKERS<=26 and 1<=BATCH_SIZE<=65536;out=Path(args.out)
 if args.mode=='controls':
  result=controls(out,args.resume);(out/'controls.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('records','base_records','full_scope_controls')}))
 else:
  fixture=next(f for f in json.loads((out/'synthetic-fixtures.json').read_text()) if f.get('random_only'));start=time.time()
  with ProcessPoolExecutor(max_workers=WORKERS) as pool:results=list(pool.map(scan_task,[(str(out),cfg,fixture['ciphertext'],'synthetic-benchmark',False) for cfg in configs()]))
  assert not any(r['survivors'] for r in results);print(json.dumps({'synthetic_only':True,'tested':sum(r['tested'] for r in results),'seconds':time.time()-start,'workers':WORKERS,'batch_size':BATCH_SIZE,'affinity':'inherited'}))
