#!/usr/bin/env python3
"""Check concept records, references and selection; not originality or market validation."""
import argparse,hashlib,json,re
from pathlib import Path
from urllib.parse import urlsplit

def check(project,stage='explored'):
 root=Path(project).resolve();errors=[]
 def fail(t):errors.append(t)
 def string(row,key):
  v=row.get(key)
  if not isinstance(v,str) or not v.strip():raise ValueError('Missing meaningful '+key)
  return v
 def local(name):
  if not isinstance(name,str):raise ValueError('Expected local path')
  p=(root/name).resolve()
  if not p.is_relative_to(root) or not p.is_file():raise ValueError('Missing or escaping evidence path')
  return p
 try:
  c=json.loads((root/'.absolute/concept-plan.json').read_text())
  if c.get('schema_version')!=1:fail('Unsupported concept schema')
  if c.get('scope') not in ['product','test-fixture']:fail('Invalid scope')
  audience=c.get('audience',{})
  for k in ['context','need','outcome']:string(audience,k)
  if audience.get('evidence_status') not in ['hypothesis','user-provided','researched']:fail('Label audience evidence')
  research=c.get('research');ids=set()
  if not isinstance(research,list) or not research:raise ValueError('Research records required, including explicit limitations when blocked')
  for row in research:
   rid=string(row,'id')
   if rid in ids:fail('Duplicate research id')
   ids.add(rid)
   for k in ['observation','decision_effect','access_level']:string(row,k)
   if row.get('status') not in ['observed','provided','unavailable']:fail('Research status missing')
   if row.get('status')!='unavailable':
    kind=row.get('source_kind','web')
    if kind=='web':
     u=urlsplit(string(row,'url'))
     if u.scheme!='https' or not u.hostname or u.username or u.password:fail('Invalid public source URL')
    elif kind=='local':
     string(row,'source_label')
    else:fail('Unknown source kind')
    p=local(row.get('evidence_path'))
    if hashlib.sha256(p.read_bytes()).hexdigest()!=row.get('evidence_sha256'):fail('Changed research evidence')
   else:string(row,'limitation')
  concepts=c.get('concepts');cids=set();cycles=set()
  if not isinstance(concepts,list) or not concepts:raise ValueError('Concepts required')
  if len(concepts)<2 and not c.get('single_concept_reason'):fail('Explain single concept / existing choice')
  for row in concepts:
   cid=string(row,'id')
   if cid in cids:fail('Duplicate concept id')
   cids.add(cid)
   for k in ['mechanic','value','difference','failure_reason','complexity','validation']:string(row,k)
   links=row.get('research_ids')
   if not isinstance(links,list) or not links or any(x not in ids for x in links):fail('Concept must reference known research')
   states=row.get('first_experience')
   if not isinstance(states,list) or len(states)<3:fail('Entry/action/result states required');continue
   for state in states:
    for k in ['state','user_action','system_response']:string(state,k)
   cycle=re.sub(r'\s+',' ',row['mechanic'].strip().casefold())
   if cycle in cycles:fail('Repeated mechanic; color variants are not concepts')
   cycles.add(cycle)
  if stage=='selected':
   if c.get('phase')!='selected' or c.get('selected_concept') not in cids:fail('Selected concept required')
   selection=c.get('selection',{});origin=selection.get('origin')
   if origin not in ['user','test-harness']:fail('Selection origin required')
   if origin=='test-harness' and c.get('scope')!='test-fixture':fail('Synthetic selection cannot approve product')
   quote=string(selection,'quote')
   if quote not in local(selection.get('record')).read_text():fail('Selection quote absent from record')
 except (OSError,ValueError,TypeError,AttributeError) as exc:fail(str(exc))
 return {'passed':not errors,'stage':stage,'errors':errors,'limits':'Completeness, literal duplicate mechanics, reference hashes and recorded selection only; no semantic novelty, human approval authenticity or user outcome measurement.'}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('project',type=Path);p.add_argument('--stage',choices=['explored','selected'],default='explored');a=p.parse_args();r=check(a.project,a.stage);print(json.dumps(r,ensure_ascii=False,indent=2));raise SystemExit(0 if r['passed'] else 1)
