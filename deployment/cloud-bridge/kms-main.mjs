import {createKms} from './kms.mjs';
try{let n=0,parts=[];for await(const part of process.stdin){n+=part.length;if(n>100000)throw new Error('Request too large');parts.push(part);}process.stdout.write(JSON.stringify(await createKms()(JSON.parse(Buffer.concat(parts).toString('utf8')))));}catch{process.stdout.write('{"error":"Cloud KMS unavailable"}');process.exitCode=1;}
