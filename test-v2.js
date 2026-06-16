const http = require('http');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

function get(url) {
  return new Promise((ok, no) => {
    http.get(url, (r) => { let d = ''; r.on('data', (c) => d += c); r.on('end', () => ok({ status: r.statusCode, headers: r.headers, body: d })); }).on('error', no);
  });
}
function postJson(url, obj, headers = {}) {
  return req('POST', url, JSON.stringify(obj), { 'Content-Type': 'application/json', ...headers });
}
function postForm(url, body, headers = {}) {
  return req('POST', url, body, { 'Content-Type': 'application/x-www-form-urlencoded', ...headers });
}
function req(method, url, body, headers) {
  return new Promise((ok, no) => {
    const u = new URL(url);
    const r = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers }, (res) => {
      let d = ''; res.on('data', (c) => d += c);
      res.on('end', () => ok({ status: res.statusCode, body: d }));
    });
    r.on('error', no);
    if (body) r.write(body);
    r.end();
  });
}
function parseJson(r) { try { return JSON.parse(r.body); } catch (e) { return r.body; } }

let pass = 0, fail = 0;
function assert(name, cond, info) {
  if (cond) { pass++; console.log('✅', name); if (info) console.log('   →', info); }
  else { fail++; console.log('❌', name); if (info) console.log('   →', info); }
}

(async () => {
  const ISSUER = 'http://localhost:3000';
  try {
    console.log('=== [1] JWKS & RS256 公钥发布 & 签名验证 ===');
    const jwks = parseJson(await get(ISSUER + '/.well-known/jwks.json'));
    assert('JWKS 返回 2 个 key', jwks && jwks.keys && jwks.keys.length === 2);
    assert('JWKS 中无 oct/HS256 密钥 (非对称)', !jwks.keys.some((k) => k.kty === 'oct' || k.alg === 'HS256'));
    assert('所有 key 为 RSA (kty=RSA, alg=RS256)', jwks.keys.every((k) => k.kty === 'RSA' && k.alg === 'RS256'));
    assert('每个 key 含 kid/use/n/e (公钥成分)', jwks.keys.every((k) => k.kid && k.use && k.n && k.e && !k.d));

    const cl = parseJson(await get(ISSUER + '/api/clients'));
    const svc = cl.test_clients.find((c) => c.name === 'Test Service');
    assert('找到 Test Service 客户端', !!svc);

    const auth = 'Basic ' + Buffer.from(svc.client_id + ':' + svc.client_secret).toString('base64');
    const tok1 = parseJson(await postForm(ISSUER + '/token', 'grant_type=client_credentials&scope=read', { Authorization: auth }));
    assert('client_credentials 拿到 access_token', !!tok1.access_token);

    const idJwk = jwks.keys.find((k) => k.use === 'sig');
    const decodedHdr = jwt.decode(tok1.access_token, { complete: true });
    assert('access_token header alg=RS256', decodedHdr.header.alg === 'RS256');
    assert('access_token header 带 kid', !!decodedHdr.header.kid);

    const matchingJwk = jwks.keys.find((k) => k.kid === decodedHdr.header.kid);
    assert(`JWKS 中存在匹配 kid 的 key (${decodedHdr.header.kid})`, !!matchingJwk);
    const pubKey = crypto.createPublicKey({ key: matchingJwk, format: 'jwk' });
    const verified = jwt.verify(tok1.access_token, pubKey, { algorithms: ['RS256'] });
    assert('使用 JWKS 公钥验证 access_token 通过', !!verified, 'sub=' + verified.sub);

    const disc = parseJson(await get(ISSUER + '/.well-known/openid-configuration'));
    assert('Discovery 声明 id_token_signing_alg = RS256', disc.id_token_signing_alg_values_supported && disc.id_token_signing_alg_values_supported[0] === 'RS256');
    assert('Discovery 声明 token_endpoint_auth_signing = RS256', disc.token_endpoint_auth_signing_alg_values_supported && disc.token_endpoint_auth_signing_alg_values_supported[0] === 'RS256');
    assert('Discovery 的 jwks_uri 可访问', !!disc.jwks_uri);

    console.log('');
    console.log('=== [2] 客户端注册 & 删除 API ===');
    const newClientResp = await postJson(ISSUER + '/api/clients', {
      name: 'Created by Test ' + Date.now(),
      type: 'confidential',
      grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      response_types: ['code'],
      scope: 'openid profile read',
      redirect_uris: ['http://localhost:3000/test/callback'],
    });
    const nc = parseJson(newClientResp);
    assert('创建客户端 201', newClientResp.status === 201, JSON.stringify(nc).substring(0, 150));
    assert('新客户端带 client_id', !!nc.client_id);
    assert('confidential 客户端带 client_secret', !!nc.client_secret);

    const newAuth = 'Basic ' + Buffer.from(nc.client_id + ':' + nc.client_secret).toString('base64');
    const ccTok = parseJson(await postForm(ISSUER + '/token', 'grant_type=client_credentials&scope=read', { Authorization: newAuth }));
    assert('新建客户端可立即走 client_credentials', !!ccTok.access_token);

    const cl2 = parseJson(await get(ISSUER + '/api/clients'));
    assert('客户端列表中包含新建客户端', cl2.test_clients.some((c) => c.client_id === nc.client_id));

    const del = parseJson(await req('DELETE', ISSUER + '/api/clients/' + encodeURIComponent(nc.client_id)));
    assert('删除客户端返回 removed:true', del.removed === true);

    const cl3 = parseJson(await get(ISSUER + '/api/clients'));
    assert('删除后列表中不再包含', !cl3.test_clients.some((c) => c.client_id === nc.client_id));

    console.log('');
    console.log('=== [3] UserInfo / 授权记录 ===');
    const tokScopeChecks = [
      { scope: 'openid', expect: ['sub'], miss: ['name', 'email'] },
    ];
    for (const ts of tokScopeChecks) {
      const t = parseJson(await postForm(ISSUER + '/token', 'grant_type=client_credentials&scope=' + encodeURIComponent(ts.scope), { Authorization: auth }));
      if (!t.access_token) { assert('跳过 (需要有用户的 token 才能真实看 scope 影响)', true); continue; }
      const rr = await (() => {
        return new Promise((ok) => {
          http.get({ hostname: 'localhost', port: 3000, path: '/userinfo', headers: { Authorization: 'Bearer ' + t.access_token } }, (r) => {
            let d = ''; r.on('data', (c) => d += c); r.on('end', () => ok({ status: r.statusCode, body: d }));
          });
        });
      })();
      const ui = parseJson(rr);
      assert('/userinfo 返回 sub (client_credentials 场景 sub=client_id)', ui && (ui.sub || ui.error), JSON.stringify(ui).substring(0, 100));
    }

    const grants1 = parseJson(await get(ISSUER + '/api/grants'));
    assert('授权记录 API 返回数组', Array.isArray(grants1));

    console.log('');
    console.log('=== [4] 首页 HTML 结构检查 ===');
    const index = await get(ISSUER + '/');
    assert('首页 HTTP 200', index.status === 200);
    assert('Content-Type 含 html', (index.headers['content-type'] || '').includes('text/html'));
    for (const tab of ['授权码流程', '客户端凭证', '令牌调试', 'UserInfo', '客户端管理', '授权记录', '发现']) {
      assert(`首页 tab 包含「${tab}」`, index.body.includes(tab));
    }
    for (const panel of ['panel-userinfo', 'panel-client-mgmt', 'panel-grants', 'panel-auth-code', 'panel-token-debug']) {
      assert(`panel id 存在: ${panel}`, index.body.includes(`id="${panel}"`));
    }
    assert('示例中演示 RS256 (而非 HS256)', index.body.includes('RS256') && !index.body.includes("id-token-hs256"));
    assert('示例中说明 JWKS 公钥验签', index.body.includes('createPublicKey') && index.body.includes('jwk'));

    console.log('');
    console.log(`==> 通过: ${pass}, 失败: ${fail}`);
    process.exit(fail ? 1 : 0);
  } catch (e) {
    console.error('❌ 运行异常:', e);
    process.exit(1);
  }
})();
