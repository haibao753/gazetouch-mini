// Zero-knowledge ciphertext vault. No usernames, raw gaze features, or passphrases received.
const json=(body,status=200,origin='')=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json; charset=utf-8',...(origin?{'access-control-allow-origin':origin,'vary':'Origin'}:{})}});
const bytesToHex=a=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
const hash=async s=>bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s))));
export default {async fetch(request,env){
 const origin=request.headers.get('origin')||'';
 const allowed=origin===env.ALLOWED_ORIGIN || (!origin && request.headers.get('sec-fetch-site')!=='cross-site');
 const cors={...(allowed&&origin?{'Access-Control-Allow-Origin':origin,'Vary':'Origin'}:{}),'Access-Control-Allow-Methods':'GET,PUT,DELETE,OPTIONS','Access-Control-Allow-Headers':'Authorization,Content-Type,If-Match'};
 if(request.method==='OPTIONS')return new Response(null,{status:allowed?204:403,headers:cors});
 if(!allowed)return json({error:'origin_not_allowed'},403);
 const url=new URL(request.url);
 if(url.pathname==='/health')return json({ok:true,version:1},200,origin);
 if(url.pathname!=='/v1/vault'||!['GET','PUT','DELETE'].includes(request.method))return json({error:'not_found'},404,origin);
 const bearer=request.headers.get('authorization')||'';
 const match=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(bearer);
 if(!match)return json({error:'missing_or_invalid_key'},401,origin);
 const vaultId=await hash(match[1]);
 try{
  if(request.method==='GET'){
   const record=await env.DB.prepare('SELECT ciphertext,revision,updated_at FROM vaults WHERE vault_id=?').bind(vaultId).first();
   return record?json(record,200,origin):json({error:'not_found'},404,origin);
  }
  if(request.method==='DELETE'){
   await env.DB.prepare('DELETE FROM vaults WHERE vault_id=?').bind(vaultId).run();
   return json({deleted:true},200,origin);
  }
  const length=Number(request.headers.get('content-length')||0);
  if(length>180000)return json({error:'payload_too_large'},413,origin);
  const raw=await request.text();
  if(raw.length>180000)return json({error:'payload_too_large'},413,origin);
  let body;try{body=JSON.parse(raw)}catch{return json({error:'invalid_json'},400,origin)}
  if(typeof body.ciphertext!=='string'||body.ciphertext.length>175000||!/^[A-Za-z0-9+/=]+$/.test(body.ciphertext))return json({error:'invalid_ciphertext'},400,origin);
  const expected=Number(request.headers.get('if-match'));
  if(!Number.isSafeInteger(expected)||expected<0)return json({error:'missing_revision'},400,origin);
  // Atomic compare-and-swap; prevents stale devices silently overwriting newer updates.
  if(expected===0){
   const insert=await env.DB.prepare('INSERT OR IGNORE INTO vaults(vault_id,ciphertext,revision) VALUES(?,?,1)').bind(vaultId,body.ciphertext).run();
   if(insert.meta.changes===1)return json({revision:1},200,origin);
  }else{
   const up=await env.DB.prepare("UPDATE vaults SET ciphertext=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE vault_id=? AND revision=?").bind(body.ciphertext,vaultId,expected).run();
   if(up.meta.changes===1)return json({revision:expected+1},200,origin);
  }
  return json({error:'revision_conflict'},409,origin);
 }catch(e){return json({error:'service_unavailable'},503,origin)}
}};
