// Node.js 20+; run from local, trusted, read-only object store; never executes firmware.
import {readFileSync,statSync,writeFileSync,mkdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {canon,parseCanonical,validatePack,validateObs,evaluate} from './core.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const [packPath,obsPath,store,receipts]=process.argv.slice(2);
if(process.argv.length!==6){console.error('Usage: node verify.mjs PACK OBS OBJECT_DIR RECEIPT_DIR');process.exit(2);}
function bounded(path,limit){const s=statSync(path);if(!s.isFile()||s.size>limit)throw Error('file type or size');const b=readFileSync(path);if(b.length>limit)throw Error('file size');return b;}
let receipt={version:'0.2',run_id:randomUUID(),utc:new Date().toISOString(),runtime:process.version,platform:process.platform+'-'+process.arch,pack_sha256:null,observations_sha256:null,engine_sha256:null,runner_sha256:null,results:[],run_error:null};
let code=2;
try{
  receipt.engine_sha256=hash(readFileSync(new URL('./core.mjs',import.meta.url)));
  receipt.runner_sha256=hash(readFileSync(new URL('./verify.mjs',import.meta.url)));
  const p=bounded(packPath,8*1024*1024),o=bounded(obsPath,8*1024*1024);
  receipt.pack_sha256=hash(p);receipt.observations_sha256=hash(o);
  const pack=validatePack(parseCanonical(p.toString('utf8'))),obs=validateObs(parseCanonical(o.toString('utf8')),pack);
  // Strict canonical ASCII prevents replacement of malformed UTF-8 from passing.
  receipt.results=evaluate(pack,obs,h=>bounded(join(resolve(store),h),64*1024*1024),hash);
  code=receipt.results.some(x=>x.verdict==='FAIL')?1:receipt.results.some(x=>x.verdict==='BLOCKED')?2:0;
}catch(e){receipt.run_error='invalid_or_unavailable_input';console.error('Validation failed:',e.message);}
try{
  mkdirSync(receipts,{recursive:true});
  const bytes=canon(receipt)+'\n',name=hash(bytes)+'.json';
  writeFileSync(join(receipts,name),bytes,{flag:'wx',encoding:'utf8'});
  console.log(name);
}catch(e){console.error('Receipt write failed:',e.message);process.exit(2);}
process.exitCode=code;
