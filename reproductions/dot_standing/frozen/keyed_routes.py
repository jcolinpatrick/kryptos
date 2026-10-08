"""Exhaustive keyed-columnar literal maps with separate ragged row-list audit."""
import itertools,json,hashlib,time,datetime
from pathlib import Path
import numpy as np
def mapping(length,width,order):
 heights=[1+(length-1-c)//width for c in range(width)];assert heights==[length//width+int(c<length%width) for c in range(width)] and sum(heights)==length
 start={};cursor=0
 for c in order:start[c]=cursor;cursor+=heights[c]
 return np.asarray([start[i%width]+i//width for i in range(length)],dtype=np.int16)
def apply(meta,text):
 width=meta['width'];order=meta['column_order'];length=len(text)
 if meta['mode']=='encode':
  rows=[list(text[i:i+width]) for i in range(0,length,width)];return ''.join(row[c] for c in order for row in rows if c<len(row))
 columns={};cursor=0
 for c in order:
  height=sum(c<len(text[i:i+width]) for i in range(0,length,width));columns[c]=text[cursor:cursor+height];cursor+=height
 return ''.join(columns[c][r] for r in range((length+width-1)//width) for c in range(width) if r<len(columns[c]))
def build(out,max_width=8,length=97):
 start=time.time();seen={};routes=[];references=[];metadata=[];recipes=0;per_width=[];tens=''.join(str(i//10) for i in range(length));ones=''.join(str(i%10) for i in range(length))
 for width in range(2,max_width+1):
  before=len(routes)
  for order in itertools.permutations(range(width)):
   forward=mapping(length,width,order)
   for mode,route in [('encode',forward),('decode',np.argsort(forward).astype(np.int16))]:
    assert time.time()<1791329400
    meta={'model':'row-write-keyed-column-read-left-ragged','width':width,'column_order':list(order),'mode':mode};a=apply(meta,tens);b=apply(meta,ones);source=np.asarray([10*int(x)+int(y) for x,y in zip(a,b)],dtype=np.int16);assert sorted(source.tolist())==list(range(length));reference=np.argsort(source).astype(np.int16);assert np.array_equal(reference,route)
    encoded=apply(meta,tens);assert apply({**meta,'mode':'decode' if mode=='encode' else 'encode'},encoded)==tens
    recipes+=1;key=route.tobytes()
    if key not in seen:seen[key]=len(routes);routes.append(route);references.append(reference);metadata.append(meta)
  per_width.append({'width':width,'unique_added':len(routes)-before,'recipes_audited':2*__import__('math').factorial(width)})
  with Path('/home/cpatrick/cryptolab_queue_outcomes/k4-progress.log').open('a') as f:f.write(datetime.datetime.now(datetime.UTC).isoformat()+' keyedcolumnar bankwidth'+str(width)+' allrecipesauditpass;distinctmaps'+str(len(routes))+';target0\n')
 out.mkdir(exist_ok=True);np.save(out/'routes.npy',np.asarray(routes,dtype=np.int16));np.save(out/'reference_routes.npy',np.asarray(references,dtype=np.int16));(out/'routes.json').write_text(json.dumps(metadata)+'\n');audit={'passed':True,'recipes_audited':recipes,'unique_maps':len(routes),'length':length,'widths':list(range(2,max_width+1)),'per_width':per_width,'independent_digit_plane_map_bijection_roundtrip_all_recipes':True,'seconds':time.time()-start,'no_target_ciphertext_used':True};(out/'bank-audit.json').write_text(json.dumps(audit,indent=2)+'\n');return audit
