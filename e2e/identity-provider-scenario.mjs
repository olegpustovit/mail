import assert from 'node:assert/strict';
import {createServer as httpServer, request as httpRequest} from 'node:http';
import {createServer as httpsServer} from 'node:https';
import {randomBytes, createHash} from 'node:crypto';
import {readFile, readdir, writeFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {spawn, execFileSync} from 'node:child_process';

// Called only by Identity's owned PostgreSQL/captured-email runner, inside an
// independently owned native Mongo process. No configured production service.
export async function lifecycle({browser,base,mail,setupCode,root,fixtureSql}) {
  assert(['localhost','127.0.0.1'].includes(new URL(base).hostname));
  assert(/^mongodb:\/\/127\.0\.0\.1:\d+$/.test(process.env.MAIL_TEST_MONGODB_URI||''),'owned loopback Mongo required');
  const contexts=[];
  async function context() {
    const ctx=await browser.newContext({ignoreHTTPSErrors:true});contexts.push(ctx);
    ctx.setDefaultTimeout(5000);ctx.setDefaultNavigationTimeout(5000);return ctx;
  }
  async function listen(server) { await new Promise((ok,fail)=>{server.once('error',fail);server.listen(0,'127.0.0.1',ok)});return server.address().port; }
  async function close(server) {server.closeAllConnections?.();await new Promise(ok=>server.close(ok))}
  const callback=httpServer((_,response)=>response.end('Owned eval callback'));
  const callbackURL=`http://127.0.0.1:${await listen(callback)}/callback`;
  const reservation=httpServer();const appPort=await listen(reservation);await close(reservation);
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',join(root,'mail-key.pem'),'-out',join(root,'mail-cert.pem')],{stdio:'ignore',timeout:5000});
  const proxy=httpsServer({key:await readFile(join(root,'mail-key.pem')),cert:await readFile(join(root,'mail-cert.pem'))},(request,response)=>{
    const upstream=httpRequest({host:'127.0.0.1',port:appPort,path:request.url,method:request.method,headers:request.headers},reply=>{response.writeHead(reply.statusCode,reply.headers);reply.pipe(response)});
    upstream.on('error',()=>{if(!response.headersSent)response.writeHead(502);response.end()});
    request.pipe(upstream);response.on('close',()=>upstream.destroy());
  });
  const appOrigin=`https://localhost:${await listen(proxy)}`;
  let child,missingTable=false;
  try {
    const owner=await context(),admin=await owner.newPage();
    const password=randomBytes(24).toString('base64url');
    await admin.goto(base+'/setup');await admin.locator('[name=code]').fill(setupCode);await admin.getByRole('button',{name:'Continue',exact:true}).click();
    await admin.locator('[name=name]').fill('Eval Mail Owner');await admin.locator('[name=email]').fill('eval-owner@example.test');await admin.locator('[name=password]').fill(password);await admin.locator('[name=passkey]').uncheck();await admin.getByRole('button',{name:'Create account',exact:true}).click();await admin.waitForURL(base+'/welcome');
    const registered=await owner.request.post(base+'/register',{data:{client_name:'Eval Mail registration',redirect_uris:[callbackURL],token_endpoint_auth_method:'none'},timeout:5000});assert.equal(registered.status(),201);
    const mcpID=(await registered.json()).client_id,verifier=randomBytes(32).toString('base64url'),state=randomBytes(24).toString('base64url');
    const query=new URLSearchParams({client_id:mcpID,redirect_uri:callbackURL,response_type:'code',scope:'mcp:admin',resource:base+'/mcp',state,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
    await admin.goto(base+'/authorize?'+query);await admin.locator('button[name=decision][value=continue]').click();await admin.getByRole('button',{name:'Allow',exact:true}).click();await admin.waitForURL(callbackURL+'**');
    const code=new URL(admin.url()).searchParams.get('code');assert(code);
    const exchange=await owner.request.post(base+'/token',{form:{client_id:mcpID,grant_type:'authorization_code',code,redirect_uri:callbackURL,code_verifier:verifier,resource:base+'/mcp'},timeout:5000});assert.equal(exchange.status(),200);
    const headers={authorization:'Bearer '+(await exchange.json()).access_token,accept:'application/json, text/event-stream','mcp-protocol-version':'2025-11-25'};
    let requestID=0;
    async function rpc(method,params,notification=false) {
      const id=notification?undefined:++requestID;
      const response=await owner.request.post(base+'/mcp',{headers,data:{jsonrpc:'2.0',...(notification?{}:{id}),method,params},timeout:5000});
      if(notification){assert([200,202,204].includes(response.status()));return}
      assert.equal(response.status(),200,'ID fixture MCP failed');const session=response.headers()['mcp-session-id'];if(session)headers['mcp-session-id']=session;
      const text=await response.text();let message;
      try{message=response.headers()['content-type'].includes('application/json')?JSON.parse(text):text.split('\n').filter(l=>l.startsWith('data:')).map(l=>JSON.parse(l.slice(5))).find(v=>v.id===id)}catch{throw Error('Invalid fixture MCP response (body withheld)')}
      assert(message?.result&&!message.error);return message.result;
    }
    await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'mail-owned-test',version:'1'}});await rpc('notifications/initialized',{},true);
    async function tool(name,args){const result=await rpc('tools/call',{name,arguments:args});assert(!result.isError&&result.structuredContent,'ID fixture tool failed');return result.structuredContent}
    const created=await tool('app_create',{kind:'confidential',settings:{name:'Eval Mail',home_url:appOrigin,redirect_uris:[appOrigin+'/api/auth/id/callback'],trusted:true,refresh:false}});assert(created.app.id&&created.client_secret);
    for(const email of ['eval-native@olegpustovit.com','eval-outsider@example.test']) {
      assert((await tool('invite_create',{email,max_uses:1,valid_hours:72})).email_sent);
      let invite;const deadline=Date.now()+5000;
      while(!invite&&Date.now()<deadline){for(const file of await readdir(mail)){const item=JSON.parse(await readFile(join(mail,file),'utf8'));if(item.to.includes(email))invite=item.text.split('\n').find(line=>line.startsWith(base+'/join/'))}if(!invite)await new Promise(ok=>setTimeout(ok,50))}
      assert(invite,'captured invitation missing');const ctx=await context(),page=await ctx.newPage();await page.goto(invite);await page.locator('[name=name]').fill('Eval Mail Member');await page.locator('[name=password]').fill(password);await page.locator('[name=passkey]').uncheck();await page.getByRole('button',{name:'Create account',exact:true}).click();await page.waitForURL(base+'/joined');
      await page.goto(base+'/account');const csrf=await page.locator('form[action="/signout"] [name=csrf]').inputValue();assert.equal((await ctx.request.post(base+'/signout',{form:{csrf},maxRedirects:0,timeout:5000})).status(),303);
    }
    const ids=JSON.parse(fixtureSql('COPY (SELECT json_object_agg(email::text,id) FROM users) TO STDOUT').trim());
    await admin.goto(base+'/access');const csrf=await admin.locator('#access-page').getAttribute('data-csrf');assert(csrf);
    async function save(groups,overrides) {
      const summary=await owner.request.get(base+'/admin/access/summary',{timeout:5000});assert.equal(summary.status(),200);
      const response=await owner.request.post(base+'/admin/access/changes',{headers:{Origin:base,'X-CSRF-Token':csrf},data:{changes:{expected_revision:(await summary.json()).revision,groups,overrides},reason:'eval reviewed native Mail access policy',idempotency_key:randomBytes(20).toString('hex'),acknowledge_broad_masks:false},timeout:5000});assert.equal(response.status(),200,'fixture policy failed');
    }
    await save([{id:'eval-mail-native',name:'eval Mail native',description:'Owned fixture',archived:false,selectors:['eval-native@olegpustovit.com','eval-outsider@example.test'],members:[],apps:[created.app.id]}],[]);
    const binary=resolve(import.meta.dirname,'../mail-server');
    child=spawn(binary,[],{cwd:resolve(import.meta.dirname,'..'),stdio:['ignore','pipe','pipe'],env:{...process.env,MAIL_BASE_URL:appOrigin,MAIL_ADDR:`127.0.0.1:${appPort}`,MAIL_MONGODB_URI:process.env.MAIL_TEST_MONGODB_URI,MAIL_ENCRYPTION_KEY:randomBytes(32).toString('base64'),MAIL_ID_ISSUER:base,MAIL_ID_CLIENT_ID:created.app.id,MAIL_ID_CLIENT_SECRET:created.client_secret,MAIL_ID_COOKIE_KEY:randomBytes(32).toString('base64'),MAIL_ID_ACCESS_ENABLED:'true'}});
    // Retain no process output: no credentials or fixture setup links in reports.
    child.stdout.resume();child.stderr.resume();child.on('error',()=>{});
    let ready=false;const deadline=Date.now()+15000;
    while(Date.now()<deadline){assert.equal(child.exitCode,null,'Mail exited at startup');try{const response=await owner.request.get(appOrigin+'/healthz',{timeout:1000});ready=response.ok()&&(await response.json()).access_enforced===true}catch{}if(ready)break;await new Promise(ok=>setTimeout(ok,50))}assert(ready,'Mail not ready');
    async function signIn(email,status=303) {
      const ctx=await context(),page=await ctx.newPage();await page.goto(appOrigin+'/');await page.locator('#id-login').click();await page.getByLabel('Email',{exact:true}).fill(email);await page.getByRole('button',{name:'Next',exact:true}).click();await page.getByLabel('Password',{exact:true}).fill(password);
      const returned=page.waitForResponse(r=>new URL(r.url()).origin===appOrigin&&new URL(r.url()).pathname==='/api/auth/id/callback');await page.getByRole('button',{name:'Sign in',exact:true}).click();const callback=await returned;assert.equal(callback.status(),status,'native callback status');
      if(status===303){await page.waitForURL(appOrigin+'/');const cookie=(await ctx.cookies(appOrigin)).find(c=>c.name==='__Host-mail_session');assert(cookie?.secure&&cookie.httpOnly&&cookie.sameSite==='Lax');assert.equal((await ctx.request.get(callback.url(),{maxRedirects:0,timeout:5000})).status(),403,'callback replay accepted')}
      else assert(!(await ctx.cookies(appOrigin)).some(c=>c.name==='__Host-mail_session'),'denied callback created session');
      return {ctx,page};
    }
    // Central allow alone does not remove Mail's existing local email restriction.
    await signIn('eval-outsider@example.test',403);
    const signed=await signIn('eval-native@olegpustovit.com');
    const api=path=>signed.ctx.request.get(appOrigin+path,{timeout:5000});assert.equal((await api('/api/me')).status(),200);
    const local=await signed.ctx.request.post(appOrigin+'/oauth/register',{data:{client_name:'eval Mail MCP',redirect_uris:[callbackURL],token_endpoint_auth_method:'none'},timeout:5000});assert.equal(local.status(),201);const clientID=(await local.json()).client_id;
    const localVerifier=randomBytes(32).toString('base64url');const localQuery=new URLSearchParams({client_id:clientID,redirect_uri:callbackURL,response_type:'code',scope:'mail',state:'eval-local-state',resource:appOrigin+'/mcp',code_challenge:createHash('sha256').update(localVerifier).digest('base64url'),code_challenge_method:'S256'});
    const authURL=appOrigin+'/oauth/authorize?'+localQuery;await signed.page.goto(authURL);const consent=await signed.page.locator('[name=consent]').inputValue();
    const consented=await signed.ctx.request.post(authURL,{headers:{Origin:appOrigin},form:{consent,decision:'allow'},maxRedirects:0,timeout:5000});assert.equal(consented.status(),303);
    const localCode=new URL(consented.headers().location).searchParams.get('code');assert(localCode);
    const tokens=await signed.ctx.request.post(appOrigin+'/oauth/token',{form:{grant_type:'authorization_code',client_id:clientID,code:localCode,redirect_uri:callbackURL,code_verifier:localVerifier,resource:appOrigin+'/mcp'},timeout:5000});assert.equal(tokens.status(),200);const credentials=await tokens.json();assert(credentials.access_token&&credentials.refresh_token);
    const refresh=()=>signed.ctx.request.post(appOrigin+'/oauth/token',{form:{grant_type:'refresh_token',client_id:clientID,refresh_token:credentials.refresh_token,resource:appOrigin+'/mcp'},timeout:5000});
    const mcp=()=>signed.ctx.request.post(appOrigin+'/mcp',{headers:{Authorization:'Bearer '+credentials.access_token,Accept:'application/json, text/event-stream'},data:{jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'eval',version:'1'}}},timeout:5000});assert.equal((await mcp()).status(),200);
    const block=async decision=>save([],[{user_id:ids['eval-native@olegpustovit.com'],client_id:created.app.id,decision}]);
    await block('block');assert.equal((await api('/api/me')).status(),403);assert.equal((await mcp()).status(),403);assert.equal((await refresh()).status(),403);assert.equal((await api('/oauth/authorize?'+localQuery)).status(),403);
    await block(null);assert.equal((await api('/api/me')).status(),200);
    fixtureSql('ALTER TABLE access_policy_state RENAME TO eval_mail_policy_unavailable');missingTable=true;
    assert.equal((await api('/api/me')).status(),503);assert.equal((await mcp()).status(),503);assert.equal((await refresh()).status(),503);
    fixtureSql('ALTER TABLE eval_mail_policy_unavailable RENAME TO access_policy_state');missingTable=false;
    assert.equal((await api('/api/me')).status(),200);assert.equal((await refresh()).status(),200,'denial/outage consumed valid refresh');
    await block('block');assert.equal((await api('/api/me')).status(),403);
    assert.equal((await signed.ctx.request.post(appOrigin+'/api/auth/id/logout',{headers:{Origin:appOrigin},maxRedirects:0,timeout:5000})).status(),303);assert.equal((await api('/api/me')).status(),401);
    assert.equal((await signed.ctx.request.get(base+'/account',{maxRedirects:0,timeout:5000})).status(),200,'app logout removed global ID device');
    const report={scope:'Owned actual Identity + Mail binaries, native PostgreSQL and Mongo, captured verified invitations and explicit reviewed policy',callback:'pass',local_restriction:'pass',callback_replay:'denied',cookie_mcp_oauth_refresh:'pass',removal_and_real_policy_storage_outage:'fail closed',refresh_restoration:'pass',blocked_cookie_logout:'pass',global_device_preserved:true,mailbox_network:'not used; separately covered with owned simulated IMAP/SMTP transports'};
    if(process.env.MAIL_ID_REHEARSAL_REPORT)await writeFile(process.env.MAIL_ID_REHEARSAL_REPORT,JSON.stringify(report,null,2)+'\n',{mode:0o600});
    console.log('Mail real Identity: verified callback, local restriction, replay, browser/OAuth/MCP, removal, real ID storage outage, refresh restoration and blocked-cookie logout passed');
  } finally {
    if(missingTable)fixtureSql('ALTER TABLE eval_mail_policy_unavailable RENAME TO access_policy_state');
    if(child&&child.exitCode===null&&child.signalCode===null){const stopped=new Promise(ok=>child.once('exit',ok));child.kill('SIGTERM');const timeout=setTimeout(()=>child.kill('SIGKILL'),5000);await stopped;clearTimeout(timeout)}
    await close(proxy);await close(callback);for(const ctx of contexts)await ctx.close();
  }
}
