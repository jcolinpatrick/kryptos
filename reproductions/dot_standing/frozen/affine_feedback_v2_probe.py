"""Unit-affine ciphertext feedback: complete26-h elimination versus312-pair oracle."""
import hashlib,json,random,time,sys,os,itertools,datetime,math
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor,wait,FIRST_COMPLETED
import numpy as np
from hill_probe import AZ,KA,CRIBS,rank
from routed_probe import pullback,scatter
from cryptolab.research_bridge.cribsolve_perm import stages_for_label
from cryptolab.research_bridge.cribsolve import run_stages
UNITS=[g for g in range(26) if math.gcd(g,26)==1];UNIT_MASK=np.asarray([math.gcd(g,26)==1 for g in range(26)]);WORKERS=int(os.environ.get('K4_NUMERIC_WORKERS','12'));assert 1<=WORKERS<=26
J=sorted(CRIBS);_BANK={}
def configs():return [[lag,pa,ca,ka] for lag in range(1,32) for pa in (AZ,KA) for ca in (AZ,KA) for ka in (AZ,KA)]
def geometry():return [{'lag':lag,'eligible_cribs':sum(i>=lag for i in J),'suffix_length':97-lag,'unknowns':3,'anchors':[63,64],'maximum_compatible_triples':26} for lag in range(1,32)]
def search_space_size(out):return 248*len(np.load(out/'routes.npy',mmap_mode='r'))
def bank(outstr):
 if outstr not in _BANK:
  o=Path(outstr);_BANK[outstr]=(np.load(o/'routes.npy',mmap_mode='r'),json.loads((o/'routes.json').read_text()))
 return _BANK[outstr]
def encode(pt,cfg,g,h,d,primer):
 lag,pa,ca,ka=cfg;assert g in UNITS and len(primer)==lag;out=[]
 for i,ch in enumerate(pt):out.append(ca[(g*pa.index(ch)+(primer[i] if i<lag else h*ka.index(out[i-lag])+d))%26])
 return ''.join(out)
def field_allowed(a,y,q):
 aa=a%q;yy=y%q;nonzero=np.any(aa!=0,axis=1);first=np.argmax(aa!=0,axis=1);r=np.arange(len(a));iv=np.asarray([0]+[pow(v,-1,q) for v in range(1,q)],dtype=np.int32);v=(yy[r,first]*iv[aa[r,first]])%q
 valid=np.all((aa*v[:,None])%q==yy,axis=1)
 return ((~nonzero[:,None])|(np.arange(q)[None,:]==v[:,None]))&valid[:,None]
def primary_data(data,cfg):
 lag,pa,ca,ka=cfg;j=np.asarray([i for i in J if i>=lag]);assert len(j)>=14 and pa.index('E')-pa.index('B')==3
 cm=np.asarray([ca.index(ch) for ch in AZ],dtype=np.int32);km=np.asarray([ka.index(ch) for ch in AZ],dtype=np.int32);cp=cm[data[:,j]];kp=km[data[:,j-lag]];p=np.asarray([pa.index(CRIBS[int(i)]) for i in j],dtype=np.int32)
 cb=cm[data[:,63]];ce=cm[data[:,64]];kb=km[data[:,63-lag]];ke=km[data[:,64-lag]];dc=ce-cb;dk=ke-kb;factor=(9*(p-pa.index('B')))%26
 a=(kp-kb[:,None]-factor*dk[:,None])%26;y=(cp-cb[:,None]-factor*dc[:,None])%26;f2=field_allowed(a,y,2);f13=field_allowed(a,y,13);hits={}
 for h in range(26):
  g=(9*(dc-h*dk))%26;d=(cb-g*pa.index('B')-h*kb)%26;good=np.flatnonzero(f2[:,h%2]&f13[:,h%13]&UNIT_MASK[g])
  for i in good:hits.setdefault(int(i),[]).append((int(g[i]),h,int(d[i])))
 return {i:sorted(v) for i,v in hits.items()}
def oracle_data(data,cfg):
 # Independent first-eligible-row anchor, explicit g/h enumeration, forward PUB.
 lag,pa,ca,ka=cfg;known={**dict(enumerate('EASTNORTHEAST',21)),**dict(enumerate('BERLINCLOCK',63))};pos=np.asarray([i for i in known if i>=lag]);pd={ch:i for i,ch in enumerate(pa)};cd={ch:i for i,ch in enumerate(ca)};kd={ch:i for i,ch in enumerate(ka)}
 cv=np.asarray([cd[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int32);kv=np.asarray([kd[ch] for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],dtype=np.int32);p=np.asarray([pd[known[int(i)]] for i in pos],dtype=np.int32);c=cv[data[:,pos]];k=kv[data[:,pos-lag]];hits={}
 for g in [1,3,5,7,9,11,15,17,19,21,23,25]:
  for h in range(26):
   d=(c[:,0]-g*p[0]-h*k[:,0])%26;idx=np.flatnonzero((c[:,1]==(g*p[1]+h*k[:,1]+d)%26)&(c[:,2]==(g*p[2]+h*k[:,2]+d)%26))
   if not len(idx):continue
   accept=np.all(c[idx]==(g*p+h*k[idx]+d[idx,None])%26,axis=1)
   for i in idx[accept]:hits.setdefault(int(i),[]).append((g,h,int(d[i])))
 return {i:sorted(v) for i,v in hits.items()}
def match_data(data,cfg):
 a=primary_data(data,cfg);b=oracle_data(data,cfg)
 if a!=b:raise RuntimeError('scalarfield-elimination/full312pair-forward-oracle disagreement')
 return a
def scalar_oracle(ct,cfg):
 lag,pa,ca,ka=cfg;pd={ch:i for i,ch in enumerate(pa)};cd={ch:i for i,ch in enumerate(ca)};kd={ch:i for i,ch in enumerate(ka)};eligible=[i for i in J if i>=lag];i0=eligible[0];hits=[]
 for g in UNITS:
  for h in range(26):
   d=(cd[ct[i0]]-g*pd[CRIBS[i0]]-h*kd[ct[i0-lag]])%26
   if all(cd[ct[i]]==(g*pd[CRIBS[i]]+h*kd[ct[i-lag]]+d)%26 for i in eligible):hits.append((g,h,d))
 return sorted(hits)
def verify(ct,cfg,triple):
 lag,pa,ca,ka=cfg;g,h,d=triple;assert triple in scalar_oracle(ct,cfg);inverse_g=pow(g,-1,26);partial=''.join(CRIBS.get(i,'?') if i<lag else pa[(inverse_g*(ca.index(ch)-h*ka.index(ct[i-lag])-d))%26] for i,ch in enumerate(ct));out=list(ct[:lag])
 for i in range(lag,97):out.append(ca[(g*pa.index(partial[i])+h*ka.index(out[i-lag])+d)%26])
 assert ''.join(out)==ct
 return {'config':cfg,'parameters':triple,'partial_plaintext':partial,'recovered_suffix':partial[lag:],'suffix_length':97-lag,'primer_length':lag,'primer_unrecovered':True,'prefix_cribs_are_givens':{i:ch for i,ch in CRIBS.items() if i<lag},'is_solution':False}

def scan_task(task):
 outstr,cfg,ct,fid,stop=task;o=Path(outstr);routes,meta=bank(outstr);flag=o/'survivor-worker-stop.json'
 if stop and flag.exists():return {'fixture':fid,'config':cfg,'tested':0,'survivors':[]}
 if time.time()>=1791329400:raise RuntimeError('authorization ended')
 nums=np.asarray([AZ.index(ch) for ch in ct],dtype=np.uint8);data=nums[routes];matches=match_data(data,cfg);hits=[]
 for i,triples in matches.items():
  d=triples[0] if stop else None
  for d in ([d] if stop else triples):
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
 outstr,ci,cfg=task;routes,meta=bank(outstr);lag,pa,ca,ka=cfg;rng=random.Random(202610061700+ci);positive=[];near=[];randoms=[];truth=[];seen=set();certified=0
 for t in range(200):
  assert time.time()<1791329400
  while True:
   triple=(UNITS[t%12],rng.randrange(26),rng.randrange(26))
   if triple not in seen:seen.add(triple);break
  g,h,d=triple;pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);pre=encode(pt,cfg,g,h,d,[rng.randrange(26) for _ in range(lag)]);idx=(ci*200+t)%len(routes);m=meta[idx];ct=run_stages(stages_for_label(m['label'],97),pre,m['mode']);assert pullback(ct,routes[idx])==pre
  assert verify(pre,cfg,triple)['recovered_suffix']==pt[lag:]
  eligible=[i for i in J if i>=lag];rows={i:[pa.index(CRIBS[i]),ka.index(pre[i-lag]),1] for i in eligible};miss=None
  for j in eligible:
   base=[rows[i] for i in eligible if i not in (j,j+lag)]
   if all(rank(base,q)==rank(base+[rows[j]],q) for q in (2,13)):miss=j;break
  assert miss is not None,'no certified near-miss row'
  changed=list(pre);changed[miss]=ca[(ca.index(changed[miss])+1)%26];changed=''.join(changed);assert not scalar_oracle(changed,cfg);certified+=1
  positive.append([AZ.index(ch) for ch in pre]);near.append([AZ.index(ch) for ch in changed]);randoms.append([rng.randrange(26) for _ in range(97)]);truth.append(triple)
 a=match_data(np.asarray(positive,dtype=np.uint8),cfg);b=match_data(np.asarray(near,dtype=np.uint8),cfg);c=match_data(np.asarray(randoms,dtype=np.uint8),cfg)
 assert all(v in a.get(i,[]) for i,v in enumerate(truth)) and not b and not c
 if ci%16==0:progress(Path(outstr).name+' affinefeedback local'+str(ci)+'/247;200distincttruth+200certifiednear+200random pass;target0')
 return {'config':cfg,'plants':200,'distinct_triples':len(seen),'near_miss_rejected':certified,'random_rejected':200,'maximum_key_multiplicity':max(map(len,a.values())),'primer_not_recovered':True}
def controls(out):
 start=time.time();routes,meta=bank(str(out));cfgs=configs()
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:records=list(pool.map(control_cell,[(str(out),i,c) for i,c in enumerate(cfgs)]))
 rng=random.Random(202610061501);fixtures=[];strata={}
 for i,m in enumerate(meta):strata.setdefault((m['label'].split(':')[0],m['mode']),i)
 route_samples=list(strata.values())
 for fid in range(32):
  alphabet_signs=list(itertools.product((AZ,KA),(AZ,KA),(AZ,KA)))[fid%8]
  lag=1+fid%31;cfg=[lag,*alphabet_signs];pa=cfg[1];pt=[rng.choice(pa) for _ in range(97)]
  for i,ch in CRIBS.items():pt[i]=ch
  pt=''.join(pt);triple=(UNITS[fid%12],[0,13,1,25][fid//8],rng.randrange(26));primer=[rng.randrange(26) for _ in range(lag)];idx=route_samples[fid%len(route_samples)];m=meta[idx];ct=run_stages(stages_for_label(m['label'],97),encode(pt,cfg,*triple,primer),m['mode'])
  fixtures.append({'id':fid,'truth_config':cfg,'truth_route':idx,'truth_parameters':triple,'plaintext':pt,'primer':primer,'ciphertext':ct})
 for j in range(8):fixtures.append({'id':32+j,'random_only':True,'ciphertext':''.join(rng.choice(AZ) for _ in range(97))})
 (out/'synthetic-fixtures.json').write_text(json.dumps(fixtures,indent=2)+'\n');full=[]
 with ProcessPoolExecutor(max_workers=WORKERS) as pool:
  for f in fixtures:
   t=time.time();rs=list(pool.map(scan_task,[(str(out),cfg,f['ciphertext'],f['id'],False) for cfg in cfgs]));hits=[h for r in rs for h in r['survivors']];assert sum(r['tested'] for r in rs)==6599776
   if not f.get('random_only'):assert any(h['config']==f['truth_config'] and h['route_index']==f['truth_route'] and tuple(h['parameters'])==tuple(f['truth_parameters']) and h['recovered_suffix']==f['plaintext'][f['truth_config'][0]:] for h in hits)
   summary={'fixture_id':f['id'],'tested':6599776,'candidates':len(hits),'distinct_partial_plaintexts':len({hashlib.sha256(h['partial_plaintext'].encode()).hexdigest() for h in hits}),'true_cfg_route_offset_suffix_recovered':not f.get('random_only'),'random_only':f.get('random_only',False),'seconds':time.time()-t};full.append(summary)
   (out/('full-control-'+str(f['id'])+'.json')).write_text(json.dumps({'summary':summary,'hits':hits})+'\n');progress(out.name+' affinefeedbackfullfixture'+str(f['id'])+'/39;6599776configs;candidates'+str(len(hits))+';target0;'+str(summary['seconds'])+'s')
 return {'passed':True,'plants':49600,'random_cases':49600,'near_miss_cases':49600,'base_configurations':248,'records':records,'full_universe_plants':32,'full_universe_randoms':8,'full_universe_evaluations':sum(r['tested'] for r in full),'full_scope_controls':full,'seconds':time.time()-start,'workers':WORKERS,'threads_each':1,'minimum_eligible_cribs':14,'primer_membership_never_counted_as_recovery':True,'bank_size':len(routes),'no_statistical_or_blind_K4_claim':True}
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
 return {'rows_tested':tested,'expected':expected,'survivors':hits,'seconds':time.time()-start,'coverage_complete':tested==expected and len(results)==248 and len({tuple(r['config']) for r in results})==248 and not hits,'all_owned_workers_closed':True,'workers':WORKERS,'threads_each':1}
def target(out):
 from cryptolab.research_bridge.k4 import K4_CIPHERTEXT
 assert len(K4_CIPHERTEXT)==97 and hashlib.sha256(K4_CIPHERTEXT.encode()).hexdigest()=='eea813570c7f1fd3b34674e47b5c3da8948026f5cefee612a0b38ffaa515ceab'
 return execute_stop_on_survivor(K4_CIPHERTEXT,out)
if __name__=='__main__':
 out=Path(sys.argv[2]);r=controls(out);(out/'controls.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='records'}))
