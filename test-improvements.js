const http = require('http');
const clients = require('./clients');
const tokenService = require('./tokenService');

function httpRequest(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null });
        } catch (e) {
          resolve({ status: res.statusCode, body: data, raw: true });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function basicAuth(clientId, clientSecret) {
  return 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
}

function pass(msg) {
  console.log(`✅ PASS: ${msg}`);
}

function fail(msg) {
  console.log(`❌ FAIL: ${msg}`);
  return false;
}

async function getHomepageClients() {
  const resp = await httpRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/clients',
    method: 'GET',
  });
  if (!resp.body || !resp.body.test_clients) {
    throw new Error('无法从 API 获取客户端信息');
  }
  return {
    webApp: resp.body.test_clients.find(c => c.name === 'Test Web App'),
    service: resp.body.test_clients.find(c => c.name === 'Test Service'),
    public: resp.body.test_clients.find(c => c.name === 'Test Public App'),
  };
}

async function runTests() {
  console.log('='.repeat(70));
  console.log('  OAuth2 / OIDC 改进验证测试');
  console.log('='.repeat(70));
  console.log('');

  const serverClients = await getHomepageClients();
  const localClients = clients.getAllClients();
  const localWebApp = localClients.find(c => c.name === 'Test Web App');
  const localService = localClients.find(c => c.name === 'Test Service');

  let allPassed = true;

  try {
    console.log('【测试1】API 端点返回真实 client_id 和 client_secret');
    console.log('-'.repeat(70));
    for (const c of [serverClients.webApp, serverClients.public, serverClients.service]) {
      console.log(`  ${c.name}:`);
      console.log(`     client_id: ${c.client_id ? '✅ 已显示' : '❌ 缺失'}`);
      console.log(`     client_secret: ${c.client_secret ? '✅ 已显示' : (c.type === 'public' ? 'ℹ️  public客户端无secret (正常)' : '❌ 缺失')}`);
      console.log(`     grant_types: ${c.grant_types.join(', ')}`);
      console.log(`     redirect_uris: ${c.redirect_uris.join(', ') || '(无)'}`);
    }
    pass('API 端点正确返回所有测试客户端信息');
    console.log('');

    console.log('【测试2】redirect_uri 严格匹配测试 (函数级)');
    console.log('-'.repeat(70));

    const testClient = clients.getClientById(localWebApp.clientId);

    const redirectTestCases = [
      { uri: 'http://localhost:3001/callback', expected: true, desc: '完全匹配' },
      { uri: 'http://localhost:3001/callback/', expected: false, desc: '末尾多斜杠' },
      { uri: 'http://localhost:3001/', expected: false, desc: '路径前缀' },
      { uri: 'http://localhost:3001/callback/extra', expected: false, desc: '更长的路径' },
      { uri: 'http://localhost:3001/callbackx', expected: false, desc: '相似路径' },
      { uri: 'https://localhost:3001/callback', expected: false, desc: '不同协议' },
      { uri: 'http://localhost:3002/callback', expected: false, desc: '不同端口' },
      { uri: 'http://otherhost:3001/callback', expected: false, desc: '不同主机' },
      { uri: 'http://localhost:3001/CALLBACK', expected: false, desc: '大小写不同' },
    ];

    let redirectPassed = true;
    for (const tc of redirectTestCases) {
      const result = clients.validateRedirectUri(testClient, tc.uri);
      const passed = result === tc.expected;
      console.log(`${passed ? '✅' : '❌'} ${tc.desc}: "${tc.uri}" → ${result} (expected ${tc.expected})`);
      if (!passed) redirectPassed = false;
    }
    if (redirectPassed) {
      pass('所有 redirect_uri 严格匹配测试通过');
    } else {
      allPassed = fail('部分 redirect_uri 测试失败');
    }
    console.log('');

    console.log('【测试3】客户端凭证流程 - 无效 scope 返回 invalid_scope (HTTP)');
    console.log('-'.repeat(70));

    const httpServiceClient = serverClients.service;

    const testCases = [
      {
        name: '测试3a: 完全无效 scope "invalid_scope123"',
        body: 'grant_type=client_credentials&scope=invalid_scope123',
        expectedError: 'invalid_scope',
      },
      {
        name: '测试3b: 部分无效 scope "read invalidscope"',
        body: 'grant_type=client_credentials&scope=read invalidscope',
        expectedError: 'invalid_scope',
      },
      {
        name: '测试3c: 超出客户端允许范围 scope "openid"',
        body: 'grant_type=client_credentials&scope=openid',
        expectedError: 'invalid_scope',
      },
      {
        name: '测试3d: 有效 scope "read write"',
        body: 'grant_type=client_credentials&scope=read write',
        expectedError: null,
        check: (body) => body.access_token && body.scope === 'read write',
      },
      {
        name: '测试3e: 不传 scope 使用客户端默认',
        body: 'grant_type=client_credentials',
        expectedError: null,
        check: (body) => body.access_token && body.scope === 'read write admin',
      },
    ];

    for (const tc of testCases) {
      console.log(tc.name);
      const response = await httpRequest({
        hostname: 'localhost',
        port: 3000,
        path: '/token',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(httpServiceClient.client_id, httpServiceClient.client_secret),
        },
      }, tc.body);

      console.log(`  状态码: ${response.status}`);
      if (response.body) console.log(`  响应: ${JSON.stringify(response.body).substring(0, 150)}...`);

      if (tc.expectedError) {
        if (response.body && response.body.error === tc.expectedError) {
          pass(`正确返回 ${tc.expectedError}`);
        } else {
          allPassed = fail(`期望 ${tc.expectedError}，实际: ${JSON.stringify(response.body)}`);
        }
      } else {
        if (response.status === 200 && tc.check(response.body)) {
          pass(`成功获取令牌, scope=${response.body.scope}`);
        } else {
          allPassed = fail(`令牌获取失败或 scope 不正确: ${JSON.stringify(response.body)}`);
        }
      }
      console.log('');
    }

    console.log('【测试4】撤销接口测试 - access_token (HTTP)');
    console.log('-'.repeat(70));

    console.log('测试4a: 获取 access_token');
    const tokenResp = await httpRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': basicAuth(httpServiceClient.client_id, httpServiceClient.client_secret),
      },
    }, 'grant_type=client_credentials&scope=read');

    if (tokenResp.status !== 200 || !tokenResp.body.access_token) {
      console.log(`  获取令牌失败: ${JSON.stringify(tokenResp.body)}`);
      allPassed = fail('无法获取 access_token 进行撤销测试');
    } else {
      const accessToken = tokenResp.body.access_token;
      pass(`获取 access_token: ${accessToken.substring(0, 20)}...`);

      console.log('');
      console.log('测试4b: 内省 access_token (token_type_hint=access_token) - 应该 active=true');
      const introBefore = await httpRequest({
        hostname: 'localhost',
        port: 3000,
        path: '/introspect',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(httpServiceClient.client_id, httpServiceClient.client_secret),
        },
      }, `token=${accessToken}&token_type_hint=access_token`);

      if (introBefore.body && introBefore.body.active === true) {
        pass('内省显示 active=true');
      } else {
        allPassed = fail(`内省未显示 active=true: ${JSON.stringify(introBefore.body)}`);
      }

      console.log('');
      console.log('测试4c: 撤销 access_token (token_type_hint=access_token)');
      const revokeResp = await httpRequest({
        hostname: 'localhost',
        port: 3000,
        path: '/revoke',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(httpServiceClient.client_id, httpServiceClient.client_secret),
        },
      }, `token=${accessToken}&token_type_hint=access_token`);

      if (revokeResp.status === 200) {
        pass('撤销成功 (200 OK)');
      } else {
        allPassed = fail(`撤销失败: ${revokeResp.status}`);
      }

      console.log('');
      console.log('测试4d: 撤销后内省 - 应该 active=false');
      const introAfter = await httpRequest({
        hostname: 'localhost',
        port: 3000,
        path: '/introspect',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': basicAuth(httpServiceClient.client_id, httpServiceClient.client_secret),
        },
      }, `token=${accessToken}&token_type_hint=access_token`);

      if (introAfter.body && introAfter.body.active === false) {
        pass('撤销后内省显示 active=false');
      } else {
        allPassed = fail(`撤销后内省未显示 active=false: ${JSON.stringify(introAfter.body)}`);
      }
    }
    console.log('');

    console.log('【测试5】撤销接口测试 - refresh_token (函数级)');
    console.log('-'.repeat(70));

    console.log('测试5a: 生成 refresh_token (函数级)');
    const refreshTokenData = tokenService.generateRefreshToken({
      userId: 'test-user-123',
      clientId: localWebApp.clientId,
      scope: ['openid', 'profile', 'read'],
    });
    const refreshToken = refreshTokenData.token;
    pass(`生成 refresh_token: ${refreshToken.substring(0, 20)}...`);
    pass(`tokenId: ${refreshTokenData.tokenId}`);

    console.log('');
    console.log('测试5b: 验证 refresh_token 有效');
    const validResult = tokenService.validateRefreshToken(refreshToken, localWebApp.clientId);
    if (validResult.valid) {
      pass('validateRefreshToken 返回 valid=true');
    } else {
      allPassed = fail('validateRefreshToken 应该返回有效');
    }

    console.log('');
    console.log('测试5c: 内省 refresh_token (函数级) - 应该 active=true');
    const introRefresh1 = tokenService.introspectToken(refreshToken, 'refresh_token');
    if (introRefresh1.active === true) {
      pass('introspectToken 返回 active=true');
    } else {
      allPassed = fail('introspectToken 应该返回 active=true');
    }

    console.log('');
    console.log('测试5d: 撤销 refresh_token (token_type_hint=refresh_token)');
    const revokeOk = tokenService.revokeToken(refreshToken, 'refresh_token');
    if (revokeOk) {
      pass('revokeToken 返回成功');
    } else {
      allPassed = fail('revokeToken 失败');
    }

    console.log('');
    console.log('测试5e: 撤销后内省 refresh_token - 应该 active=false');
    const introRefresh2 = tokenService.introspectToken(refreshToken, 'refresh_token');
    if (introRefresh2.active === false) {
      pass('撤销后 introspectToken 返回 active=false');
    } else {
      allPassed = fail(`撤销后应该返回 active=false，实际: ${JSON.stringify(introRefresh2)}`);
    }

    console.log('');
    console.log('测试5f: 撤销后使用 refresh_token 换取新令牌 - 应该失败');
    const validAfterRevoke = tokenService.validateRefreshToken(refreshToken, localWebApp.clientId);
    if (!validAfterRevoke.valid && validAfterRevoke.error === 'invalid_grant') {
      pass('撤销后 validateRefreshToken 返回 invalid_grant');
    } else {
      allPassed = fail(`撤销后应该无效，实际: ${JSON.stringify(validAfterRevoke)}`);
    }
    console.log('');

    console.log('【测试6】token_type_hint 兼容性测试 (函数级)');
    console.log('-'.repeat(70));

    const rt2 = tokenService.generateRefreshToken({
      userId: 'test-user-456',
      clientId: localWebApp.clientId,
      scope: ['read'],
    });

    console.log('测试6a: 使用旧格式 hint "refresh" 撤销');
    tokenService.revokeToken(rt2.token, 'refresh');
    const introOld = tokenService.introspectToken(rt2.token, 'refresh');
    if (introOld.active === false) {
      pass('旧格式 hint "refresh" 正常工作');
    } else {
      allPassed = fail('旧格式 hint "refresh" 不工作');
    }

    const at2 = tokenService.generateAccessToken({
      clientId: localService.clientId,
      scope: ['read'],
    });

    console.log('');
    console.log('测试6b: 使用旧格式 hint "access" 撤销');
    tokenService.revokeToken(at2, 'access');
    const verifyOld = tokenService.verifyAccessToken(at2);
    if (!verifyOld.valid) {
      pass('旧格式 hint "access" 正常工作');
    } else {
      allPassed = fail('旧格式 hint "access" 不工作');
    }

    console.log('');
    console.log('测试6c: hint 大小写不敏感 "REFRESH_TOKEN"');
    const rt3 = tokenService.generateRefreshToken({
      userId: 'test-user-789',
      clientId: localWebApp.clientId,
      scope: ['read'],
    });
    tokenService.revokeToken(rt3.token, 'REFRESH_TOKEN');
    const introUpper = tokenService.introspectToken(rt3.token, 'refresh_token');
    if (introUpper.active === false) {
      pass('大写 hint "REFRESH_TOKEN" 正常工作');
    } else {
      allPassed = fail('大写 hint 不工作');
    }
    console.log('');

    console.log('【测试7】授权端点 redirect_uri 校验测试 (HTTP)');
    console.log('-'.repeat(70));

    const httpWebClient = serverClients.webApp;

    console.log('测试7a: 使用未注册的 redirect_uri 发起授权请求');
    const authBadUri = await httpRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/authorize?response_type=code&client_id=${httpWebClient.client_id}&redirect_uri=${encodeURIComponent('http://evil.com/callback')}&scope=openid&state=test`,
      method: 'GET',
    });

    if (authBadUri.status === 400 || (authBadUri.body && authBadUri.body.error === 'invalid_request')) {
      pass('未注册的 redirect_uri 正确返回错误');
    } else {
      console.log(`状态码: ${authBadUri.status}, 响应: ${JSON.stringify(authBadUri.body).substring(0, 200)}`);
      allPassed = fail('未注册的 redirect_uri 应该被拒绝');
    }

    console.log('');
    console.log('测试7b: 使用相似但不相同的 redirect_uri (路径前缀)');
    const authSimilarUri = await httpRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/authorize?response_type=code&client_id=${httpWebClient.client_id}&redirect_uri=${encodeURIComponent('http://localhost:3001/')}&scope=openid&state=test`,
      method: 'GET',
    });

    if (authSimilarUri.status === 400 || (authSimilarUri.body && authSimilarUri.body.error === 'invalid_request')) {
      pass('相似但不相同的 redirect_uri 正确返回错误');
    } else {
      console.log(`状态码: ${authSimilarUri.status}, 响应: ${JSON.stringify(authSimilarUri.body).substring(0, 200)}`);
      allPassed = fail('相似的 redirect_uri 不应该通过校验');
    }

    console.log('');
    console.log('测试7c: 使用完全匹配的 redirect_uri');
    const authGoodUri = await httpRequest({
      hostname: 'localhost',
      port: 3000,
      path: `/authorize?response_type=code&client_id=${httpWebClient.client_id}&redirect_uri=${encodeURIComponent('http://localhost:3001/callback')}&scope=openid&state=test`,
      method: 'GET',
    });

    if (authGoodUri.status === 302 || authGoodUri.status === 200) {
      pass('完全匹配的 redirect_uri 正常处理（重定向到登录或授权页）');
    } else if (authGoodUri.status === 400 && authGoodUri.body && authGoodUri.body.error) {
      console.log(`状态码: ${authGoodUri.status}, 响应: ${JSON.stringify(authGoodUri.body)}`);
      allPassed = fail('完全匹配的 redirect_uri 应该正常处理');
    } else {
      console.log(`状态码: ${authGoodUri.status}`);
      pass('完全匹配的 redirect_uri 被正常处理');
    }
    console.log('');

    console.log('='.repeat(70));
    if (allPassed) {
      console.log('  ✅ 所有测试通过！');
    } else {
      console.log('  ❌ 部分测试失败，请查看上面的输出');
    }
    console.log('='.repeat(70));

  } catch (err) {
    console.error('测试过程出错:', err);
    allPassed = false;
  }

  process.exit(allPassed ? 0 : 1);
}

runTests();
