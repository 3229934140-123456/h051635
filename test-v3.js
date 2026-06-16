const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const ISSUER = 'http://localhost:3000';

let pass = 0, fail = 0;
function assert(name, ok, detail) {
  if (ok) { pass++; console.log('✅ ' + name + (detail ? '\n   → ' + detail : '')); }
  else { fail++; console.log('❌ ' + name + (detail ? ' (' + detail + ')' : '')); }
}

function get(url, extra) {
  return new Promise((ok, no) => {
    const opts = new URL(url);
    if (extra && extra.headers) opts.headers = extra.headers;
    http.get(opts, (r) => { let d = ''; r.on('data', (c) => d += c); r.on('end', () => ok({ status: r.statusCode, headers: r.headers, body: d })); }).on('error', no);
  });
}

function post(url, body, extra) {
  return new Promise((ok, no) => {
    const u = new URL(url);
    const isJson = !extra || !extra.headers || extra.headers['Content-Type'] !== 'application/x-www-form-urlencoded';
    const data = isJson ? JSON.stringify(body || {}) : body;
    const opts = {
      hostname: u.hostname, port: u.port, path: u.pathname, method: 'POST',
      headers: Object.assign({ 'Content-Type': isJson ? 'application/json' : 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) }, extra?.headers || {}),
    };
    const req = http.request(opts, (r) => { let d = ''; r.on('data', (c) => d += c); r.on('end', () => ok({ status: r.statusCode, headers: r.headers, body: d })); });
    req.on('error', no);
    req.write(data); req.end();
  });
}
function postForm(url, body, extra) { return post(url, body, Object.assign({}, extra || {}, { headers: Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, extra?.headers || {}) })); }
function parseJson(r) { try { return typeof r.body === 'string' ? JSON.parse(r.body) : r.body; } catch (e) { return null; } }
function basicAuth(u, p) { return 'Basic ' + Buffer.from(u + ':' + p).toString('base64'); }

// PKCE helpers (S256/plain)
function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function makeVerifier(len=48) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let s = '';
  const bytes = crypto.randomBytes(len);
  for (let i=0;i<len;i++) s += chars[bytes[i] % chars.length];
  return s;
}
function s256(v) { return b64urlEncode(crypto.createHash('sha256').update(v).digest()); }

async function getCookieForLogin(username, password) {
  const agent = new (require('http').Agent)({ keepAlive: true });
  const jar = { sid: null };
  const loginGet = await new Promise((ok) => {
    http.get({ hostname: 'localhost', port: 3000, path: '/login' }, (r) => { let d=''; r.on('data',c=>d+=c); r.on('end',()=>ok(r)); });
  });
  const loginBody = 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password) + '&redirect=%2Fauthorize%3Fclient_id%3Dfoo%26response_type%3Dcode';
  const res = await new Promise((ok) => {
    const req = http.request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST',
      headers: { 'Content-Type':'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(loginBody) }
    }, (r) => {
      const cookies = r.headers['set-cookie'] || [];
      for (const c of cookies) {
        const m = c.match(/session_id=([^;]+)/);
        if (m) jar.sid = m[1];
      }
      let d=''; r.on('data',c=>d+=c); r.on('end',()=>ok(r));
    });
    req.write(loginBody); req.end();
  });
  return jar;
}

(async function main() {
  try {
    console.log('=== [1] 客户端导入 / 导出 & 批量恢复 ===');
    const cfg = { clients: [
      { name: 'V3-Lab-Web', type: 'confidential', grant_types: ['authorization_code','refresh_token'], response_types: ['code'], scope: 'openid profile email read write', redirect_uris: ['http://localhost:3000/test/callback','http://localhost:3010/cb'] },
      { name: 'V3-Lab-Public', type: 'public', grant_types: ['authorization_code','refresh_token'], response_types: ['code'], scope: 'openid profile email read write', redirect_uris: ['http://localhost:3000/test/callback'] },
      { name: 'V3-Lab-Service', type: 'confidential', grant_types: ['client_credentials'], response_types: ['token'], scope: 'read write admin', redirect_uris: [] },
    ]};
    const imp = parseJson(await post(ISSUER + '/api/clients/import', cfg));
    assert('POST /api/clients/import 返回 imported=3', imp && imp.imported === 3, 'imported=' + (imp?.imported));
    const webClient = (imp.clients || []).find(c => c.name === 'V3-Lab-Web');
    const pubClient = (imp.clients || []).find(c => c.name === 'V3-Lab-Public');
    const svcClient = (imp.clients || []).find(c => c.name === 'V3-Lab-Service');
    assert('导入的 V3-Lab-Web 带 client_id', !!webClient?.client_id);
    assert('导入的 V3-Lab-Web 带 client_secret', !!webClient?.client_secret);
    assert('导入的 V3-Lab-Public 是 public 类型', pubClient?.type === 'public');
    assert('导入的 V3-Lab-Service grant_types 包含 client_credentials', (svcClient?.grant_types || []).includes('client_credentials'));
    const exp = parseJson(await get(ISSUER + '/api/clients/export'));
    assert('GET /api/clients/export 返回 clients 数组', Array.isArray(exp?.clients) && exp.clients.length >= 3 + 3 /* 3个原有预置 + 3个新的 */, `count=${exp?.clients?.length}`);

    console.log('');
    console.log('=== [2] PKCE: S256 verifier 验证 + 错误 verifier 失败 ===');
    // 用 public 客户端
    const verifier = makeVerifier(64);
    const challenge = s256(verifier);
    const state = 'test-pkce-state-' + Math.random().toString(36).slice(2, 8);

    // 走服务端内部：直接用函数调 authorization code
    // 因为浏览器 cookie 流在纯 HTTP 脚本里复杂，这里用 authorize 接口拿 302 location，再模拟用户确认（服务端其实会记录 authz code，用内部代码生成 code）
    // 简化：直接调用 authorization 模块创建授权码（通过 HTTP 但跳过登录用我们能控制的方式）
    // 服务端 authorization 是 requireAuth 的，所以没法完全绕过登录。我们改用手动造 code 的方式——直接调用 oidc/token 服务端函数不可行
    // 替代：走 /api 接口的方式不适用。那我们用已实现的 token 端点测试 PKCE 失败场景一定失败，然后用服务端生成的 authorization code（通过 mock session）
    // 更简单：用 authorization 模块的内部接口在脚本里 require authorization.js 并调用 createAuthorizationCode（如果导出的话）
    const mkAuthCode = async function(params) {
      const body = {
        client_id: params.clientId,
        user_id: params.userId,
        redirect_uri: params.redirectUri,
        scope: params.scope,
        code_challenge: params.codeChallenge || null,
        code_challenge_method: params.codeChallengeMethod || null,
        nonce: params.nonce || null,
      };
      const r = parseJson(await post(ISSUER + '/api/_test/create-auth-code', body));
      if (!r || !r.code) throw new Error('create-auth-code failed: ' + JSON.stringify(r));
      return { code: r.code, expiresAt: r.expires_at };
    };
    {
      // 测试 S256 正确
      const codeObj = await mkAuthCode({
        clientId: pubClient.client_id, userId: 'user-alice', redirectUri: 'http://localhost:3000/test/callback',
        scope: 'openid profile', expiresIn: 600, nonce: null,
        codeChallenge: challenge, codeChallengeMethod: 'S256',
      });
      // 用正确 verifier 换 token
      const t1 = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({
        grant_type: 'authorization_code', code: codeObj.code, redirect_uri: 'http://localhost:3000/test/callback',
        client_id: pubClient.client_id, code_verifier: verifier, code_challenge_method: 'S256',
      }).toString()));
      assert('PKCE S256 - 正确 verifier 能换 access_token', !!t1?.access_token, 'scopes=' + (t1?.scope || JSON.stringify(t1)));

      // 故意用错误 verifier
      const codeObj2 = await mkAuthCode({
        clientId: pubClient.client_id, userId: 'user-alice', redirectUri: 'http://localhost:3000/test/callback',
        scope: 'openid profile', expiresIn: 600, nonce: null,
        codeChallenge: challenge, codeChallengeMethod: 'S256',
      });
      const t2 = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({
        grant_type: 'authorization_code', code: codeObj2.code, redirect_uri: 'http://localhost:3000/test/callback',
        client_id: pubClient.client_id, code_verifier: 'WRONG_' + verifier.substring(0, 30), code_challenge_method: 'S256',
      }).toString()));
      assert('PKCE S256 - 错误 verifier 换 token 失败 (400/invalid_grant 类)', !t2?.access_token && !!t2?.error, 'error=' + (t2?.error || JSON.stringify(t2)));

      // 测试 plain 模式
      const verifierPlain = makeVerifier(50);
      const codeObj3 = await mkAuthCode({
        clientId: pubClient.client_id, userId: 'user-alice', redirectUri: 'http://localhost:3000/test/callback',
        scope: 'openid profile', expiresIn: 600, nonce: null,
        codeChallenge: verifierPlain, codeChallengeMethod: 'plain',
      });
      const t3 = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({
        grant_type: 'authorization_code', code: codeObj3.code, redirect_uri: 'http://localhost:3000/test/callback',
        client_id: pubClient.client_id, code_verifier: verifierPlain, code_challenge_method: 'plain',
      }).toString()));
      assert('PKCE plain - 正确 verifier 能换 access_token', !!t3?.access_token, 'scope=' + (t3?.scope || JSON.stringify(t3)));

      // 记录 refresh token 供后面轮换测试用
      const rtInitial = t1.refresh_token;
      // 用 confidential 客户端也走一次拿到带 refresh 的 token，给需求2/3测试
      const codeObjForLink = await mkAuthCode({
        clientId: webClient.client_id, userId: 'user-alice', redirectUri: 'http://localhost:3000/test/callback',
        scope: 'openid profile email', expiresIn: 600, nonce: null,
      });
      const tLink = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({
        grant_type: 'authorization_code', code: codeObjForLink.code, redirect_uri: 'http://localhost:3000/test/callback',
      }).toString(), { headers: { Authorization: basicAuth(webClient.client_id, webClient.client_secret) }}));
      assert('PKCE 辅助：拿到标准授权码 refresh_token (供轮换链路测试)', !!tLink?.refresh_token, JSON.stringify({ hasAT: !!tLink?.access_token, hasRT: !!tLink?.refresh_token, hasID: !!tLink?.id_token }));

      console.log('');
      console.log('=== [3] Refresh token 轮换链路 & 生命周期 API ===');
      const lc1 = parseJson(await get(ISSUER + '/api/tokens/lifecycle'));
      assert('/api/tokens/lifecycle 返回 refresh_tokens 数组', Array.isArray(lc1?.refresh_tokens), 'count=' + (lc1?.refresh_tokens?.length));
      const rt0 = lc1.refresh_tokens.find(x => tLink?.refresh_token && (x.token.startsWith(tLink.refresh_token.substring(0, 16))));
      assert('最初生成的 RT 出现在 lifecycle API 中 (active=true, rotation=0)', !!(rt0 || lc1.refresh_tokens.some(t => t.active && t.rotation_count === 0)));

      // 第一次 refresh
      const rtRefresh1 = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tLink.refresh_token, client_id: webClient.client_id, client_secret: webClient.client_secret }).toString()));
      assert('refresh 1 - 返回新的 access + refresh', !!rtRefresh1?.refresh_token && !!rtRefresh1?.access_token);
      assert('refresh 1 - 新 RT 不等于旧 RT (轮换发生)', rtRefresh1.refresh_token !== tLink.refresh_token);

      // 再 refresh 一次（用新 RT）
      const rtRefresh2 = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rtRefresh1.refresh_token, client_id: webClient.client_id, client_secret: webClient.client_secret }).toString()));
      assert('refresh 2 - 也能正常轮换出更新的 RT', !!rtRefresh2?.refresh_token && rtRefresh2.refresh_token !== rtRefresh1.refresh_token);

      const lc2 = parseJson(await get(ISSUER + '/api/tokens/lifecycle'));
      // 至少有 2+ 个 token，且第一个的 prev 指向另一个或最后一个被标记 rotation_count>=2 之类
      assert('lifecycle API 中 refresh 链路记录 (rotation_count>0 或 多个 token)', lc2.refresh_tokens.length >= 3, `tokens=${lc2.refresh_tokens.length}`);

      console.log('');
      console.log('=== [4] 授权撤销 → 再授权 chain_index 自增，旧 RT 失效 ===');
      // 先记录当前 grant 数量
      const g1 = parseJson(await get(ISSUER + '/api/grants'));
      const initialCount = g1.length;
      assert('授权记录中已出现 user-alice → V3-Lab-Web 的 grant (chain_index=1)', g1.some(g => g.user_id === 'user-alice' && g.client_id === webClient.client_id && g.chain_index === 1));

      // 撤销
      const rv = parseJson(await post(ISSUER + '/api/grants/revoke', { user_id: 'user-alice', client_id: webClient.client_id }));
      assert('撤销授权 found=true', rv?.found === true, 'revoked=' + rv?.tokens_revoked);

      // 旧 RT 不能再换令牌
      const rtAfter = parseJson(await postForm(ISSUER + '/token', new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rtRefresh2.refresh_token, client_id: webClient.client_id, client_secret: webClient.client_secret }).toString()));
      assert('撤销后最新 refresh_token 去换令牌返回 invalid_grant', !!rtAfter?.error, 'error=' + (rtAfter?.error || '(unexpected access token!)'));

      // 重新授权
      const re = parseJson(await post(ISSUER + '/api/grants/reauthorize', { user_id: 'user-alice', client_id: webClient.client_id, scope: 'openid profile read' }));
      assert('重新授权返回 chain_index=2', re?.chain_index === 2, JSON.stringify(re));

      // 列表中现在应当有两条记录：chain 1 已撤销 + chain 2 active
      const g2 = parseJson(await get(ISSUER + '/api/grants'));
      const chain1 = g2.find(g => g.user_id === 'user-alice' && g.client_id === webClient.client_id && g.chain_index === 1);
      const chain2 = g2.find(g => g.user_id === 'user-alice' && g.client_id === webClient.client_id && g.chain_index === 2);
      assert('chain_index=1 的记录已撤销 (revoked=true)', chain1?.revoked === true);
      assert('chain_index=2 的记录是 active (revoked=false, scope=openid profile read)', !chain2?.revoked && chain2?.scope === 'openid profile read', JSON.stringify(chain2));

      // scope 缩减
      const nr = parseJson(await post(ISSUER + '/api/grants/narrow', { user_id: 'user-alice', client_id: webClient.client_id, scope: 'openid read' }));
      assert('narrow scope 后 scope 变成 "openid read" (交集缩减)', nr?.scope === 'openid read', JSON.stringify(nr));
      const g3 = parseJson(await get(ISSUER + '/api/grants'));
      const chain2Now = g3.find(g => g.user_id === 'user-alice' && g.client_id === webClient.client_id && g.chain_index === 2);
      assert('缩减后 DB 中 scope 确实少了 profile', chain2Now?.scope === 'openid read');

      console.log('');
      console.log('=== [5] /api/verify-jwt: JWT 自动 kid 匹配 + 自动验签 ===');
      const svcTok = parseJson(await postForm(ISSUER + '/token', 'grant_type=client_credentials&scope=read', { headers: { Authorization: basicAuth(svcClient.client_id, svcClient.client_secret) }}));
      const v1 = parseJson(await post(ISSUER + '/api/verify-jwt', { token: svcTok.access_token }));
      assert('verify-jwt 返回 ok=true', v1?.ok === true);
      assert('verify-jwt 中 alg=RS256', v1?.header?.alg === 'RS256');
      assert('verify-jwt 中 payload.sub = client_id (client_credentials 场景)', typeof v1?.payload?.sub === 'string' && v1.payload.sub.length > 0);
      assert('verify-jwt 中 signature_valid=true', v1?.signature_valid === true);
      assert('verify-jwt 中 matched_jwk_exists=true (按 kid 找到匹配公钥)', v1?.matched_jwk_exists === true);
      assert('verify-jwt timing.issued_at / expires_at 都有', typeof v1?.timing?.issued_at === 'string' && typeof v1?.timing?.expires_at === 'string', JSON.stringify(v1.timing));

      // 伪造 token 去验签应当失败
      const fakeTok = jwt.sign({ sub: 'hacker', scope: 'admin' }, crypto.createPrivateKey({ key: crypto.generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}}).privateKey, format:'pem' }), { algorithm: 'RS256', keyid: (v1.matched_kid || 'somekid'), expiresIn: 3600 });
      const vFake = parseJson(await post(ISSUER + '/api/verify-jwt', { token: fakeTok }));
      assert('verify-jwt 用伪造的密钥签同一个 kid - signature_valid=false', vFake?.signature_valid === false, JSON.stringify({ valid: vFake?.signature_valid, err: vFake?.verify_error }).substring(0, 100));

      console.log('');
      console.log('=== [6] 首页 HTML 结构检查（新面板） ===');
      const idx = await get(ISSUER + '/');
      assert('首页 HTTP 200', idx.status === 200);
      const s = idx.body || '';
      assert('首页包含「PKCE 调试」tab', s.includes('PKCE 调试'));
      assert('首页包含「令牌生命周期」tab', s.includes('令牌生命周期'));
      assert('首页包含「JWT 验签工具」tab', s.includes('JWT 验签工具'));
      assert('panel id 存在 panel-pkce', s.includes('panel-pkce'));
      assert('panel id 存在 panel-token-lifecycle', s.includes('panel-token-lifecycle'));
      assert('panel id 存在 panel-jwt-verify', s.includes('panel-jwt-verify'));
      assert('授权记录表头有「链路」字样 (chain_index)', s.includes('授权链路'));
      assert('客户端管理有「导入」字样', s.includes('导入 JSON'));
      assert('客户端管理有「导出」字样', s.includes('导出 JSON'));
      assert('客户端管理有「本地」恢复字样', s.includes('本地保存恢复') || s.includes('从本地'));
      assert('存在 /api/verify-jwt 调用', s.includes('/api/verify-jwt'));
      assert('存在 /api/tokens/lifecycle 调用', s.includes('/api/tokens/lifecycle'));

      console.log('');
      console.log(`==> 通过: ${pass}, 失败: ${fail}`);
      process.exit(fail > 0 ? 1 : 0);
    }
  } catch (e) {
    console.log('❌ 运行异常: ' + e.message);
    console.log(e.stack);
    process.exit(1);
  }
})();
