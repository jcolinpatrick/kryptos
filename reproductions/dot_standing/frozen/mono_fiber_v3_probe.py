"""Complete bijective monoalphabetic key fibers over a frozen route bank."""
import hashlib,json,random,time,sys,os,itertools,datetime,math
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,CRIBS
from routed_probe import pullback,scatter
import keyed_routes
WORKERS=int(os.environ.get("K4_WORKERS","2"));BATCH_SIZE=int(os.environ.get("K4_BATCH_SIZE","65536"));assert 1<=WORKERS<=26 and BATCH_SIZE>0;J=sorted(CRIBS);LETTERS=sorted(set(CRIBS.values()));GROUPS=[[i for i in J if CRIBS[i]==ch] for ch in LETTERS];_BANK={};_GEOMETRY={}
def configs():return [('any_bijective_monoalphabetic',)]
def bank(outstr):
 if outstr not in _BANK:
  o=Path(outstr);_BANK[outstr]=(np.load(o/'routes.npy',mmap_mode='r'),json.loads((o/'routes.json').read_text()),np.load(o/'reference_routes.npy',mmap_mode='r'))
 return _BANK[outstr]
def geometry():return _GEOMETRY
def search_space_size(out):
 global _GEOMETRY
 _GEOMETRY=json.loads((out/'bank-audit.json').read_text());assert _GEOMETRY['passed'];return _GEOMETRY['unique_maps']
def make_fiber(pre,known,alphabet=AZ):
 assigned={};inverse={}
 for i,p in known.items():
  c=pre[i]
  if p not in alphabet or c not in alphabet:return None
  if p in assigned and assigned[p]!=c:return None
  if c in inverse and inverse[c]!=p:return None
  assigned[p]=c;inverse[c]=p
 unused_p=''.join(ch for ch in alphabet if ch not in assigned);unused_c=''.join(ch for ch in alphabet if ch not in inverse);assert len(unused_p)==len(unused_c)
 witness={**assigned,**dict(zip(unused_p,unused_c))};witness_inverse={c:p for p,c in witness.items()};partial=''.join(inverse.get(ch,'?') for ch in pre)
 return {'assigned':assigned,'unused_plaintext_letters':unused_p,'unused_ciphertext_letters':unused_c,'completion_count':math.factorial(len(unused_p)),'remaining_assignments':'ALL bijections of unused sets; exact, untruncated','unresolved_symbols':[ch for ch in unused_c if ch in pre],'remaining_assignments_all_different':True,'partial_plaintext':partial,'witness_kind':'WITNESS_NOT_UNIQUE_RECOVERY','witness_full_map':witness,'witness_plaintext':''.join(witness_inverse[ch] for ch in pre)}
def _primary_chunk(data):
 good=np.ones(len(data),dtype=bool);mapped=[]
 for group in GROUPS:
  values=data[:,group];good &= np.all(values==values[:,0,None],axis=1);mapped.append(values[:,0])
 matrix=np.asarray(mapped,dtype=np.uint8).T;ordered=np.sort(matrix,axis=1);good &= np.all(ordered[:,1:]!=ordered[:,:-1],axis=1)
 return {int(i):{p:AZ[int(c)] for p,c in zip(LETTERS,matrix[i])} for i in np.flatnonzero(good)}
def _reference_chunk(data):
 known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};e=[i for i,p in known.items() if p=='E'];candidates=np.flatnonzero(np.all(data[:,e]==data[:,e[0],None],axis=1));result={}
 for index in candidates:
  forward={};inverse={};valid=True
  for i,p in known.items():
   c='ABCDEFGHIJKLMNOPQRSTUVWXYZ'[int(data[index,i])]
   if (p in forward and forward[p]!=c) or (c in inverse and inverse[c]!=p):valid=False;break
   forward[p]=c;inverse[c]=p
  if valid:result[int(index)]=forward
 return result
def primary_assignments(data):
 result={}
 for start in range(0,len(data),BATCH_SIZE):result.update({start+i:key for i,key in _primary_chunk(data[start:start+BATCH_SIZE]).items()})
 return result
def reference_assignments(data):
 result={}
 for start in range(0,len(data),BATCH_SIZE):result.update({start+i:key for i,key in _reference_chunk(data[start:start+BATCH_SIZE]).items()})
 return result
def match_data(data,cfg,reference_data=None):
 primary=primary_assignments(data)
 if primary!=reference_assignments(data if reference_data is None else reference_data):raise RuntimeError('vectorrepetition/injectivity versus scalarbidirectionaldict disagreement')
 return primary
def scan(ct,cfg,routes,stop_path=None,metadata=None,reference_routes=None):
 nums=np.asarray([AZ.index(ch) for ch in ct],dtype=np.uint8);data=nums[routes];primary=match_data(data,cfg,data if reference_routes is None else nums[reference_routes]);survivors=[]
 for index,key in primary.items():
  pre=pullback(ct,routes[index]);fiber=make_fiber(pre,CRIBS);assert fiber and fiber['assigned']==key and len(key)==13 and fiber['completion_count']==math.factorial(13)
  witness=fiber['witness_plaintext'];assert all(witness[i]==p for i,p in CRIBS.items());encoded=''.join(fiber['witness_full_map'][p] for p in witness);assert scatter(encoded,routes[index])==ct
  hit={'config':cfg,'route_index':index,'fiber':fiber,'partial_plaintext':fiber['partial_plaintext'],'witness_plaintext':witness,'witness_only':True,'is_solution':False}
  if metadata is not None:hit['route']=metadata[index];assert keyed_routes.apply(metadata[index],encoded)==ct
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
def membership(hit,truth_key,plaintext):
 fiber=hit['fiber'];assigned={p:truth_key[p] for p in LETTERS};assert fiber['assigned']==assigned and len(assigned)==13 and fiber['completion_count']==math.factorial(13)
 assert set(fiber['unused_plaintext_letters'])==set(AZ)-set(assigned)
 assert {truth_key[p] for p in fiber['unused_plaintext_letters']}==set(fiber['unused_ciphertext_letters'])
 assert {**assigned,**{p:truth_key[p] for p in fiber['unused_plaintext_letters']}}==truth_key
 assert all(ch=='?' or ch==plaintext[i] for i,ch in enumerate(fiber['partial_plaintext']))
 return True
def control_stratum(task):
 outstr,width,mode=task;out=Path(outstr);routes,meta,ref=bank(outstr);group=[i for i,m in enumerate(meta) if m['width']==width and m['mode']==mode];assert group;rng=random.Random(202610062600+width*10+(mode=='decode'));file=out/('stratum-'+str(width)+'-'+mode+'.json');records=json.loads(file.read_text()) if file.exists() else [];completed=len(records);seen=set()
 for trial in range(200):
  assert time.time()<1791329400
  rng=random.Random(202610062800+width*10+(mode=="decode")+trial*1000000)
  shuffled=rng.sample(AZ,26);truth=dict(zip(AZ,shuffled));assert tuple(shuffled) not in seen;seen.add(tuple(shuffled));pt=[rng.choice(AZ) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);idx=rng.choice(group);pre=''.join(truth[ch] for ch in pt);ct=keyed_routes.apply(meta[idx],pre)
  if trial<completed:assert records[trial]['trial']==trial and records[trial]['truth_route']==idx;continue
  result=scan(ct,configs()[0],routes,metadata=meta,reference_routes=ref);hits=result['survivors'];h=next(h for h in hits if h['route_index']==idx);assert membership(h,truth,pt)
  bad=list(pre);e=[i for i,p in CRIBS.items() if p=='E'][1];bad[e]=AZ[(AZ.index(bad[e])+1)%26];collision=pre.replace(truth['B'],truth['E']);random_text=''.join(rng.choice(AZ) for _ in range(97))
  for negative in (''.join(bad),collision,random_text):
   assert make_fiber(negative,CRIBS) is None;assert not match_data(np.asarray([[AZ.index(ch) for ch in negative]],dtype=np.uint8),configs()[0])
  equivalent=sum(np.array_equal(routes[a['route_index']][J],routes[idx][J]) for a in hits if a['route_index']!=idx);records.append({'trial':trial,'truth_route':idx,'accepted_routes':len(hits),'other_crib_position_equivalent_routes':equivalent,'true_fullkey_and_plaintext_membership_recovered':True,'fixed_pairs':13,'key_completions':math.factorial(13)})
  temp=file.with_suffix('.tmp');temp.write_text(json.dumps(records)+'\n');temp.replace(file)
  if trial%25==0:progress(out.name+' monofiber w'+str(width)+mode+' trial'+str(trial)+'/199 fullbankplants/keyfiber membership passed;target0')
 file=out/('stratum-'+str(width)+'-'+mode+'.json');file.write_text(json.dumps(records)+'\n');return {'width':width,'mode':mode,'plants':200,'distinct_fullkeys':len(seen),'true_key_plaintext_membership':200,'corruption_rejected':200,'collision_rejected':200,'random_rejected':200,'full_universe_evaluations':len(routes)*200,'minimum_routes_accepted':min(r['accepted_routes'] for r in records),'maximum_routes_accepted':max(r['accepted_routes'] for r in records),'other_crib_position_equivalent_routes':sum(r['other_crib_position_equivalent_routes'] for r in records),'details_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
def controls(out):
 start=time.time();routes,meta,ref=bank(str(out));strata=sorted({(m['width'],m['mode']) for m in meta});assert len(strata)==2*len(set(w for w,m in strata)) and set(w for w,m in strata)==set(range(2,max(w for w,m in strata)+1))
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:records=list(pool.map(control_stratum,[(str(out),w,m) for w,m in strata]))
 rng=random.Random(202610062601);fixtures=[]
 for fid in range(48):
  width,mode=strata[fid%len(strata)];choices=[i for i,m in enumerate(meta) if m['width']==width and m['mode']==mode];idx=rng.choice(choices);truth=dict(zip(AZ,rng.sample(AZ,26)));pt=[rng.choice(AZ) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);fixtures.append({'id':fid,'truth_config':configs()[0],'truth_route':idx,'truth_full_map':truth,'plaintext':pt,'ciphertext':keyed_routes.apply(meta[idx],''.join(truth[ch] for ch in pt))})
 for j in range(8):fixtures.append({'id':48+j,'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:
  for f in fixtures:
   t=time.time();rs=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in configs()]));hits=[h for r in rs for h in r['survivors']];assert sum(r['tested'] for r in rs)==len(routes)
   if not f.get('random_only'):assert membership(next(h for h in hits if h['route_index']==f['truth_route']),f['truth_full_map'],f['plaintext'])
   else:assert not hits
   summary={'fixture_id':f['id'],'tested':len(routes),'accepted_route_fibers':len(hits),'true_route_fullkey_plaintext_in_complete_fiber':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary);(out/('full-control-'+str(f['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n');progress(out.name+' monofiber fullfixture'+str(f['id'])+'/55;'+str(len(routes))+'routes;fibers'+str(len(hits))+';target0')
 return {'passed':True,'plants':200*len(strata),'repeated_letter_corruptions':200*len(strata),'injectivity_collisions':200*len(strata),'local_randoms':200*len(strata),'records':records,'base_records':[{'config':configs()[0],'plants':200*len(strata)}],'full_scope_controls':full,'full_universe_plants':48,'full_universe_randoms':8,'local_full_universe_evaluations':sum(r['full_universe_evaluations'] for r in records),'full_universe_evaluations':sum(r['tested'] for r in full),'seconds':time.time()-start,'workers':WORKERS,'threads_each':1,'key_universe':str(math.factorial(26)),'completions_per_accepted_route':math.factorial(13),'recovery_means_exact_fiber_membership_not_unique_full_decryption':True,'witness_never_counted_as_true_plaintext_recovery':True,'no_blind_or_statistical_claim':True}
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
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['controls','benchmark']);parser.add_argument('out');parser.add_argument('--workers',type=int,default=WORKERS);parser.add_argument('--batch-size',type=int,default=BATCH_SIZE);parser.add_argument('--affinity',choices=['inherited'],default='inherited');args=parser.parse_args();WORKERS=args.workers;BATCH_SIZE=args.batch_size;assert 1<=WORKERS<=26 and BATCH_SIZE>0;out=Path(args.out)
 if args.mode=='controls':r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
 else:
  fixture=next(f for f in json.loads((out/'synthetic-fixtures.json').read_text()) if f.get('random_only'));start=time.time();r=scan_task((str(out),configs()[0],fixture['ciphertext'],'synthetic-benchmark',False));assert not r['survivors'];print(json.dumps({'synthetic_only':True,'tested':r['tested'],'seconds':time.time()-start,'workers':WORKERS,'active_tasks':1,'batch_size':BATCH_SIZE,'affinity':'inherited'}))
