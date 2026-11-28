// Reference core v0.2. No extraction or attestation; payload verification is conditional on observations.
function req(ok,msg){if(!ok)throw new Error(msg);}

function obj(x,keys){req(x!==null&&typeof x==="object"&&!Array.isArray(x),"expected object");req(Object.keys(x).sort().join("|")===keys.split(" ").sort().join("|"),"missing or unknown fields");}

function ascii(x){return typeof x==="string"&&/^[\x20-\x7e]+$/.test(x)&&x.length<=1024;}

function id(x){return typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(x);}

function sha(x){return typeof x==="string"&&/^[0-9a-f]{64}$/.test(x);}

function commit(x){return typeof x==="string"&&/^[0-9a-f]{40}$/.test(x);}

function uint(x){return Number.isSafeInteger(x)&&x>=0;}

function size(x){return uint(x)&&x<=64*1024*1024;}

function uniq(xs){return new Set(xs).size===xs.length;}

function canon(x){
  if(x===null||typeof x==="boolean")return JSON.stringify(x);
  if(typeof x==="number"){req(uint(x)&&!Object.is(x,-0),"unsupported number");return JSON.stringify(x);}
  if(typeof x==="string"){req(ascii(x),"unsupported string");return JSON.stringify(x);}
  if(Array.isArray(x))return "["+x.map(canon).join(",")+"]";
  req(x&&typeof x==="object","unsupported JSON");
  return "{"+Object.keys(x).sort().map(k=>{req(ascii(k),"unsupported key");return JSON.stringify(k)+":"+canon(x[k]);}).join(",")+"}";
}

function parseCanonical(s){req(typeof s==="string"&&s.length<=8*1024*1024,"document size");const v=JSON.parse(s);req(canon(v)+"\n"===s,"noncanonical JSON (including duplicate keys)");return v;}

function equal(x,y){return canon(x)===canon(y);}

function offsets(x){return Array.isArray(x)&&x.every((n,i)=>size(n)&&(i===0||x[i-1]<n));}

function bytesref(x,pair=false){
  obj(x,"input offset length");req(["a","b"].includes(x.input)&&size(x.offset)&&(x.length==="rest"||size(x.length)),"bad range");
  if(pair)req(x.input==="b","right input must be b");
}

function validatePack(p){
  obj(p,"version artifacts selectors claims");req(p.version==="0.2","version");
  req(Array.isArray(p.artifacts)&&p.artifacts.length>0&&p.artifacts.length<=64,"artifacts");
  for(const a of p.artifacts){obj(a,"id sha256 size");req(id(a.id)&&sha(a.sha256)&&size(a.size)&&a.size>0,"artifact");}
  req(uniq(p.artifacts.map(a=>a.id)),"duplicate artifacts");
  req(Array.isArray(p.selectors)&&p.selectors.length>0&&p.selectors.length<=1024,"selectors");
  for(const s of p.selectors){obj(s,"id kind guid section_type");req(id(s.id)&&s.kind==="unique_ffs_leaf_v1"&&/^[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$/.test(s.guid)&&s.section_type===25,"selector");}
  req(uniq(p.selectors.map(s=>s.id)),"duplicate selectors");
  req(Array.isArray(p.claims)&&p.claims.length>0&&p.claims.length<=1024,"claims");
  for(const c of p.claims){
    obj(c,"id selector inputs sources predecessor checks");
    req(id(c.id)&&p.selectors.some(s=>s.id===c.selector),"claim/selector");
    obj(c.inputs,"a b");req(c.inputs.a!==c.inputs.b&&Object.values(c.inputs).every(x=>p.artifacts.some(a=>a.id===x)),"inputs");
    req(Array.isArray(c.sources)&&c.sources.length>0,"source refs");
    for(const s of c.sources){obj(s,"commit path anchor");req(commit(s.commit)&&ascii(s.path)&&ascii(s.anchor),"source");}
    if(c.predecessor!==null){obj(c.predecessor,"commit path id");req(commit(c.predecessor.commit)&&ascii(c.predecessor.path)&&id(c.predecessor.id),"predecessor");}
    req(Array.isArray(c.checks)&&c.checks.length>0&&c.checks.length<=64,"checks");
    for(const k of c.checks){
      obj(k,"id op args expected");req(id(k.id),"check id");
      const a=k.args;
      if(k.op==="size_v1"||k.op==="sha256_v1"){obj(a,"input");req(["a","b"].includes(a.input),"input");req(k.op==="size_v1"?size(k.expected):sha(k.expected),"expected");}
      else if(k.op==="read_u32_le_v1"){obj(a,"input offset");req(["a","b"].includes(a.input)&&size(a.offset)&&uint(k.expected)&&k.expected<=4294967295,"u32");}
      else if(k.op==="range_sha256_v1"){bytesref(a);req(sha(k.expected),"expected digest");}
      else if(k.op==="range_equal_v1"){obj(a,"left right");bytesref(a.left);bytesref(a.right,true);req(a.left.input==="a"&&typeof k.expected==="boolean","range equal");}
      else if(k.op==="diff_offsets_v1"){obj(a,"left right");req(a.left==="a"&&a.right==="b"&&offsets(k.expected)&&k.expected.length<=4096,"diff offsets");}
      else throw new Error("unknown operation");
    }
    req(uniq(c.checks.map(k=>k.id)),"duplicate check ids");
  }
  req(uniq(p.claims.map(c=>c.id)),"duplicate claim ids");
  return p;
}

function validateObs(o,p){
  obj(o,"version adapter entries");req(o.version==="0.2","observation version");
  obj(o.adapter,"id sha256 toolchain");req(id(o.adapter.id)&&sha(o.adapter.sha256)&&ascii(o.adapter.toolchain),"adapter identity");
  req(Array.isArray(o.entries)&&o.entries.length<=65536,"entries");
  const needed=new Set(p.claims.flatMap(c=>Object.values(c.inputs).map(a=>a+"/"+c.selector)));
  const got=[];
  for(const e of o.entries){
    obj(e,"artifact selector coverage owner_count raw_node_count leaf_count issues payload locator");
    const key=e.artifact+"/"+e.selector;req(needed.has(key),"unexpected observation key");got.push(key);
    req(["complete","incomplete","unknown"].includes(e.coverage),"coverage");
    req([e.owner_count,e.raw_node_count,e.leaf_count].every(x=>x===null||uint(x)),"counts");
    req(Array.isArray(e.issues)&&e.issues.every(id)&&uniq(e.issues),"issue codes");
    if(e.coverage==="complete")req([e.owner_count,e.raw_node_count,e.leaf_count].every(uint),"unknown count for complete");
    if(e.payload!==null){obj(e.payload,"sha256 size");req(sha(e.payload.sha256)&&size(e.payload.size),"payload");}
    req(e.locator===null||ascii(e.locator),"locator");
    if(e.coverage==="complete"&&e.owner_count===1&&e.raw_node_count===1&&e.leaf_count===1&&e.issues.length===0)
      req(e.payload!==null&&e.locator!==null,"unique leaf without payload/locator");
  }
  req(uniq(got)&&got.length===needed.size,"missing/duplicate observations");
  return o;
}

function range(ref,inputs){
  const b=inputs[ref.input];const end=ref.length==="rest"?b.length:ref.offset+ref.length;
  req(ref.offset<=b.length&&end<=b.length,"range outside payload");return b.subarray(ref.offset,end);
}

function sameBytes(a,b){return a.length===b.length&&a.every((v,i)=>v===b[i]);}

function measure(k,inputs,digest){
  const a=k.args;
  if(k.op==="size_v1")return inputs[a.input].length;
  if(k.op==="sha256_v1")return digest(inputs[a.input]);
  if(k.op==="read_u32_le_v1"){const b=inputs[a.input];req(a.offset+4<=b.length,"u32 outside payload");return b[a.offset]+256*b[a.offset+1]+65536*b[a.offset+2]+16777216*b[a.offset+3];}
  if(k.op==="range_sha256_v1")return digest(range(a,inputs));
  if(k.op==="range_equal_v1")return sameBytes(range(a.left,inputs),range(a.right,inputs));
  if(k.op==="diff_offsets_v1"){const x=inputs.a,y=inputs.b;req(x.length===y.length,"diff requires equal length");const out=[];for(let i=0;i<x.length;i++)if(x[i]!==y[i]){out.push(i);req(out.length<=4096,"diff limit");}return out;}
  throw new Error("unknown op");
}

function evaluate(pack,obs,readObject,digest){
  validatePack(pack);validateObs(obs,pack);
  const results=[];
  const cache=new Map();
  function load(ref){
    if(!cache.has(ref.sha256)){const b=readObject(ref.sha256);req(b instanceof Uint8Array&&size(b.length),"object unavailable/oversize");req(digest(b)===ref.sha256,"object digest mismatch");cache.set(ref.sha256,b);}
    const b=cache.get(ref.sha256);req(b.length===ref.size,"object size mismatch");return b;
  }
  for(const c of pack.claims){
    const checks=[];let blocked=null;const inputs={};
    try{
      for(const role of ["a","b"]){
        const artifact=pack.artifacts.find(a=>a.id===c.inputs[role]);load(artifact);
        const e=obs.entries.find(e=>e.artifact===artifact.id&&e.selector===c.selector);
        req(e.coverage==="complete"&&e.issues.length===0&&e.owner_count===1&&e.raw_node_count===1&&e.leaf_count===1&&e.payload!==null,"selection unresolved or ambiguous");
        inputs[role]=load(e.payload);
      }
    }catch(e){blocked="input_or_selection_unverified";}
    for(const k of c.checks){
      if(blocked){checks.push({id:k.id,verdict:"BLOCKED",reason:blocked});continue;}
      try{const value=measure(k,inputs,digest);checks.push({id:k.id,verdict:equal(value,k.expected)?"PASS":"FAIL",observed:value});}
      catch(e){checks.push({id:k.id,verdict:"BLOCKED",reason:"operation_undefined_or_limit"});}
    }
    const verdict=checks.some(k=>k.verdict==="FAIL")?"FAIL":checks.some(k=>k.verdict==="BLOCKED")?"BLOCKED":"PASS";
    results.push({id:c.id,verdict,checks});
  }
  return results;
}
export {canon,parseCanonical,validatePack,validateObs,evaluate};
