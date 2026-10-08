"""Compact deterministic metadata access for fully audited, duplicate-free keyed banks."""
import math,json
from pathlib import Path
import numpy as np
_CACHE={}
class Metadata:
 def __init__(self,audit):
  assert audit['passed'] and audit['recipes_audited']==audit['unique_maps']
  self.bounds=[];start=0
  for row in audit['per_width']:
   width=row['width'];count=2*math.factorial(width);assert row['recipes_audited']==row['unique_added']==count
   self.bounds.append((start,start+count,width));start+=count
  assert start==audit['unique_maps'];self.size=start
 def __len__(self):return self.size
 def __getitem__(self,index):
  index=int(index)
  if not 0<=index<self.size:raise IndexError(index)
  start,end,width=next(row for row in self.bounds if row[0]<=index<row[1]);offset=index-start;rank=offset//2;pool=list(range(width));order=[]
  for remaining in range(width,0,-1):
   digit,rank=divmod(rank,math.factorial(remaining-1));order.append(pool.pop(digit))
  assert rank==0
  return {'model':'row-write-keyed-column-read-left-ragged','width':width,'column_order':order,'mode':'encode' if offset%2==0 else 'decode'}
 def index(self,width,mode,permutation_rank):
  start,end,w=next(row for row in self.bounds if row[2]==width);assert mode in ('encode','decode') and 0<=permutation_rank<math.factorial(width)
  return start+2*permutation_rank+(mode=='decode')
def bank(outstr):
 if outstr not in _CACHE:
  out=Path(outstr);audit=json.loads((out/'bank-audit.json').read_text());meta=Metadata(audit);routes=np.load(out/'routes.npy',mmap_mode='r');reference=np.load(out/'reference_routes.npy',mmap_mode='r');assert routes.shape==reference.shape==(len(meta),97);_CACHE[outstr]=(routes,meta,reference)
 return _CACHE[outstr]
