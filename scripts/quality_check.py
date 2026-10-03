#!/usr/bin/env python3
"""Validate recorded copy/asset review; does not judge appearance or prove authorship."""
import argparse,json,hashlib
from pathlib import Path
PURPOSES={'task-content','control','essential-warning','error','approved-name'}
def check(root):
 root=Path(root).resolve(); errors=[]
 try:
  inventory=json.loads((root/'.absolute/content-inventory.json').read_text())
  review=json.loads((root/'.absolute/quality-review.json').read_text())
  if not isinstance(inventory,list) or not inventory:raise ValueError('Content inventory must be a nonempty list')
  ids=set()
  for item in inventory:
   if not isinstance(item,dict):raise ValueError('Content item must be an object')
   for key in ['id','text','state','purpose','reason','basis']:
    if not isinstance(item.get(key),str) or not item[key].strip():errors.append('Missing content field: '+key)
   ident=item.get('id')
   if ident in ids:errors.append('Duplicate content id')
   ids.add(ident)
   if item.get('purpose') not in PURPOSES:errors.append('Unsupported content purpose')
  if review.get('status')!='reviewed':errors.append('Review not complete')
  if review.get('unresolved')!=[]:errors.append('Unresolved review issues')
  expected=hashlib.sha256((root/'.absolute/content-inventory.json').read_bytes()).hexdigest()
  if review.get('inventory_sha256')!=expected:errors.append('Stale content review')
  for section in ['content_review','asset_review']:
   rows=review.get(section)
   if not isinstance(rows,list) or not rows:errors.append('Missing '+section);continue
   for row in rows:
    if not isinstance(row,dict):raise ValueError('Review entry must be an object')
    if not isinstance(row.get('finding'),str) or not row['finding'].strip():errors.append('Review needs a concrete finding')
    evidence=row.get('evidence')
    if not isinstance(evidence,list) or not evidence:errors.append('Missing review evidence');continue
    for record in evidence:
     if not isinstance(record,dict) or not isinstance(record.get('path'),str):raise ValueError('Invalid evidence record')
     path=(root/record['path']).resolve()
     if not path.is_relative_to(root) or not path.is_file():errors.append('Invalid evidence path');continue
     if hashlib.sha256(path.read_bytes()).hexdigest()!=record.get('sha256'):errors.append('Changed evidence')
 except (OSError,ValueError,TypeError,AttributeError) as exc:errors.append(str(exc))
 return {'passed':not errors,'errors':errors,'limits':'Record completeness and evidence hashes only; manual content/visual review required.'}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('project',type=Path);args=p.parse_args();result=check(args.project);print(json.dumps(result,ensure_ascii=False,indent=2));raise SystemExit(0 if result['passed'] else 1)
