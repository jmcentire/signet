import {S3Client, GetObjectCommand, PutObjectCommand} from '@aws-sdk/client-s3';
const MAX=8*1024*1024;
export function createR2({accountId,bucket,credentials,send}) {
  if(!/^[a-f0-9]{32}$/.test(accountId)||!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket))throw new Error('Invalid approved R2 endpoint');
  if(!credentials?.accessKeyId||!credentials?.secretAccessKey)throw new Error('Explicit R2 credentials required');
  const client=send?null:new S3Client({region:'auto',endpoint:`https://${accountId}.r2.cloudflarestorage.com`,credentials,forcePathStyle:true,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',maxAttempts:1});
  const call=send||((command,options)=>client.send(command,options));
  return async request=>{
    if(!/^[a-f0-9]{64}\.(head|[a-f0-9]{64})\.json$/.test(request.key)||request.headers?.['cache-control']!=='no-store')throw new Error('Invalid scoped uncached request');
    const params={Bucket:bucket,Key:request.key};let command;
    if(request.method==='GET')command=new GetObjectCommand(params);
    else if(request.method==='PUT'){
      const match=request.headers['if-match'],absent=request.headers['if-none-match'];
      if((typeof match==='string'&&match.length>0)===Boolean(absent==='*'))throw new Error('Exactly one precondition required');
      const body=Buffer.from(request.body,'base64');if(body.length>MAX)throw new Error('Object too large');
      command=new PutObjectCommand({...params,Body:body,ContentType:'application/json',CacheControl:'no-store',...(match?{IfMatch:match}:{IfNoneMatch:'*'})});
    }else throw new Error('Operation not supported');
    try{
      const result=await call(command,{abortSignal:AbortSignal.timeout(15000)});const chunks=[];let size=0;
      if(request.method==='GET')for await(const chunk of result.Body){size+=chunk.length;if(size>MAX){result.Body.destroy?.();throw new Error('Object too large');}chunks.push(chunk);}
      return {status:200,etag:result.ETag??null,body:Buffer.concat(chunks).toString('base64')};
    }catch(error){const status=error?.$metadata?.httpStatusCode;return {status:status===404&&request.method==='GET'?404:status===412?412:503,etag:null,body:''};}
  };
}
