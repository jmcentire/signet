// Private process protocol. Only explicit runtime R2 secrets, never ambient AWS credentials.
import {createR2} from './r2.mjs';
let size=0,parts=[];
try {
  for await(const part of process.stdin){size+=part.length;if(size>12*1024*1024)throw new Error('Request too large');parts.push(part);}
  const request=JSON.parse(Buffer.concat(parts).toString('utf8'));
  const transport=createR2({accountId:process.env.SIGNET_R2_ACCOUNT_ID,bucket:process.env.SIGNET_R2_BUCKET,credentials:{accessKeyId:process.env.SIGNET_R2_ACCESS_KEY_ID,secretAccessKey:process.env.SIGNET_R2_SECRET_ACCESS_KEY}});
  process.stdout.write(JSON.stringify(await transport(request)));
}catch{process.stdout.write(JSON.stringify({status:503,etag:null,body:''}));process.exitCode=1;}
