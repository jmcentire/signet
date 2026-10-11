import test from 'node:test';import assert from 'node:assert/strict';import {Readable} from 'node:stream';import {createR2} from './r2.mjs';
const key='a'.repeat(64)+'.head.json',config={accountId:'0'.repeat(32),bucket:'synthetic-bucket',credentials:{accessKeyId:'synthetic-test-only',secretAccessKey:'synthetic-test-only'}};
test('SDK receives exact opaque/create-only preconditions and unmodified JSON bytes',async()=>{
 const seen=[];const t=createR2({...config,send:async c=>{seen.push(c);return {ETag:'"opaque"'};}}),body=Buffer.from('{"total_minor":1000000}').toString('base64');
 await t({method:'PUT',key,headers:{'cache-control':'no-store','if-match':'"opaque"'},body});assert.equal(seen[0].input.IfMatch,'"opaque"');assert.equal(seen[0].input.Body.toString(),'{"total_minor":1000000}');
 await t({method:'PUT',key,headers:{'cache-control':'no-store','if-none-match':'*'},body});assert.equal(seen[1].input.IfNoneMatch,'*');
 await assert.rejects(t({method:'PUT',key,headers:{'cache-control':'no-store'},body}));
});
test('uncached reads preserve ETag; conflict explicit and timeout unknown with no silent retries',async()=>{
 const t=createR2({...config,send:async()=>({ETag:'"opaque"',Body:Readable.from([Buffer.from('{}')])})});assert.deepEqual(await t({method:'GET',key,headers:{'cache-control':'no-store'}}),{status:200,etag:'"opaque"',body:'e30='});
 for(const status of [412,503]){let calls=0;const t=createR2({...config,send:async()=>{calls++;throw {$metadata:{httpStatusCode:status}};}});assert.equal((await t({method:'PUT',key,headers:{'cache-control':'no-store','if-none-match':'*'},body:'e30='})).status,status);assert.equal(calls,1);}
});
test('reject ambient credentials, arbitrary endpoint and unscoped keys',async()=>{
 assert.throws(()=>createR2({...config,credentials:null}));assert.throws(()=>createR2({...config,accountId:'attacker.test'}));const t=createR2({...config,send:async()=>{throw new Error('must not run');}});await assert.rejects(t({method:'GET',key:'../../other',headers:{'cache-control':'no-store'}}));
});
