// Fixed Cloud Run workload identity route. No ADC files, browser credentials or caller URL.
const versionPattern=/^projects\/[A-Za-z0-9_-]+\/locations\/[A-Za-z0-9_-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/;
async function boundedJson(response){if(!response.ok)throw new Error('KMS unavailable');const reader=response.body.getReader();let total=0,parts=[];for(;;){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>65536){await reader.cancel();throw new Error('Response exceeds limit');}parts.push(Buffer.from(value));}return JSON.parse(Buffer.concat(parts).toString('utf8'));}
export function createKms({fetchImpl=fetch}={}){return async({key_version,request})=>{
 if(!versionPattern.test(key_version)||!request||Object.keys(request).sort().join(',')!=='data,dataCrc32c'||typeof request.data!=='string'||request.data.length>87000||!/^\d+$/.test(request.dataCrc32c))throw new Error('Invalid signing request');
 const options={redirect:'error',signal:AbortSignal.timeout(10000)};
 const metadata=await fetchImpl('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',{...options,headers:{'Metadata-Flavor':'Google'}});
 if(metadata.headers.get('Metadata-Flavor')!=='Google')throw new Error('Invalid workload identity response');
 const token=await boundedJson(metadata);
 if(token.token_type!=='Bearer'||typeof token.access_token!=='string'||!token.access_token||/[\r\n]/.test(token.access_token)||!Number.isFinite(token.expires_in)||token.expires_in<30)throw new Error('Invalid workload identity token');
 const response=await fetchImpl(`https://cloudkms.googleapis.com/v1/${key_version}:asymmetricSign`,{method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),headers:{Authorization:`Bearer ${token.access_token}`,'Content-Type':'application/json'},body:JSON.stringify(request)});
 return boundedJson(response);
};}
