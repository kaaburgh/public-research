import {canon,parseCanonical,validatePack,evaluate} from './core.mjs';
function tests(api){
  const {canon,parseCanonical,validatePack,evaluate}=api;
  const assert=(v,m)=>{if(!v)throw Error(m);};
  const expectReject=(f,m)=>{let threw=false;try{f();}catch{threw=true;}assert(threw,m);};
  const clone=x=>JSON.parse(JSON.stringify(x));
  const digest=b=>Array.from(b,x=>x.toString(16).padStart(2,"0")).join("").padEnd(64,"0"); // test-only, not crypto
  const romA=Uint8Array.of(77),romB=Uint8Array.of(78),a=Uint8Array.of(0,1,0,0,0,9),b=Uint8Array.of(2,1,0,0,0,9);
  const objects=new Map([romA,romB,a,b].map(x=>[digest(x),x]));
  const read=h=>{if(!objects.has(h))throw Error("missing");return objects.get(h);};
  const ref=x=>({sha256:digest(x),size:x.length});
  const p={version:"0.2",artifacts:[{id:"r1",...ref(romA)},{id:"r2",...ref(romB)}],selectors:[{id:"s",kind:"unique_ffs_leaf_v1",guid:"CC0F8A3F-3DEA-4376-9679-5426BA0A907E",section_type:25}],claims:[{id:"c",selector:"s",inputs:{a:"r1",b:"r2"},sources:[{commit:"a".repeat(40),path:"test",anchor:"test"}],predecessor:null,checks:[
    {id:"size",op:"size_v1",args:{input:"a"},expected:6},
    {id:"hash",op:"sha256_v1",args:{input:"a"},expected:digest(a)},
    {id:"read",op:"read_u32_le_v1",args:{input:"b",offset:1},expected:1},
    {id:"rangehash",op:"range_sha256_v1",args:{input:"b",offset:5,length:"rest"},expected:digest(b.subarray(5))},
    {id:"equal",op:"range_equal_v1",args:{left:{input:"a",offset:5,length:"rest"},right:{input:"b",offset:5,length:"rest"}},expected:true},
    {id:"diff",op:"diff_offsets_v1",args:{left:"a",right:"b"},expected:[0]}
  ]}]};
  const o={version:"0.2",adapter:{id:"test",sha256:"a".repeat(64),toolchain:"test"},entries:[["r1",a],["r2",b]].map(([artifact,x])=>({artifact,selector:"s",coverage:"complete",owner_count:1,raw_node_count:1,leaf_count:1,issues:[],payload:ref(x),locator:"test"}))};
  let n=0;
  function test(name,f){f();n++;}
  const run=(pp=p,oo=o,rr=read)=>evaluate(pp,oo,rr,digest)[0];
  test("six ops",()=>assert(run().verdict==="PASS","positive"));
  test("different value",()=>{const q=clone(p);q.claims[0].checks[0].expected=7;assert(run(q).verdict==="FAIL","wrong expected");});
  test("extra raw node",()=>{const q=clone(o);q.entries[0].raw_node_count=2;assert(run(p,q).verdict==="BLOCKED","extra");});
  test("unknown coverage",()=>{const q=clone(o);q.entries[0].coverage="unknown";assert(run(p,q).verdict==="BLOCKED","coverage");});
  test("parse issue",()=>{const q=clone(o);q.entries[0].issues=["malformed"];assert(run(p,q).verdict==="BLOCKED","issue");});
  test("missing object",()=>assert(run(p,o,()=>{throw Error("missing");}).verdict==="BLOCKED","missing"));
  test("wrong object",()=>assert(run(p,o,()=>Uint8Array.of(255)).verdict==="BLOCKED","wrong object"));
  test("duplicate obs",()=>{const q=clone(o);q.entries.push(q.entries[0]);expectReject(()=>run(p,q),"duplicate obs");});
  test("missing obs",()=>{const q=clone(o);q.entries.pop();expectReject(()=>run(p,q),"missing obs");});
  test("unknown op",()=>{const q=clone(p);q.claims[0].checks[0].op="eval";expectReject(()=>validatePack(q),"unknown op");});
  test("duplicate check",()=>{const q=clone(p);q.claims[0].checks.push(q.claims[0].checks[0]);expectReject(()=>validatePack(q),"duplicate check");});
  test("duplicate json key",()=>expectReject(()=>parseCanonical('{"x":1,"x":1}\n'),"duplicate key"));
  test("noncanonical",()=>expectReject(()=>parseCanonical('{"z":1,"a":2}\n'),"unordered keys"));
  test("canonical",()=>assert(parseCanonical(canon(p)+"\n").version==="0.2","canonical"));
  test("u32 bounds",()=>{const q=clone(p);q.claims[0].checks[2].args.offset=5;assert(run(q).verdict==="BLOCKED","bounds");});
  test("exact diff",()=>{const q=clone(p);q.claims[0].checks[5].expected=[0,1];assert(run(q).verdict==="FAIL","diff subset");});
  test("noninteger",()=>{const q=clone(p);q.claims[0].checks[0].expected=6.5;expectReject(()=>validatePack(q),"fraction");});
  test("fail and blocked",()=>{const q=clone(p);q.claims[0].checks[0].expected=7;q.claims[0].checks[2].args.offset=5;assert(run(q).verdict==="FAIL","aggregate");});
  return n;
}
console.log('core synthetic tests passed:',tests({canon,parseCanonical,validatePack,evaluate}));
