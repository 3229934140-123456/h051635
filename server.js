const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const config = require('./config');
const clients = require('./clients');
const auth = require('./auth');
const tokenService = require('./tokenService');
const grants = require('./grants');
const authorizationRouter = require('./authorization');
const tokenRouter = require('./token');
const oidc = require('./oidc');
const clientsModule = require('./clients');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  const allClients = clients.getAllClients();
  const testClients = allClients.map((client) => ({
    name: client.name,
    client_id: client.clientId,
    client_secret: client.clientSecret,
    type: client.type,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    scope: client.scope,
    redirect_uris: client.redirectUris,
    created_at: client.createdAt,
  }));

  const testUsers = [
    { username: 'alice', password: 'password123', name: 'Alice Wang', user_id: 'user-alice' },
    { username: 'bob', password: 'password456', name: 'Bob Li', user_id: 'user-bob' },
  ];

  const scopes = Object.entries(config.scopes).map(([key, desc]) => ({ key, desc }));
  const issuer = config.server.issuer;

  const allGrants = grants.getAllGrants().map((g) => ({
    grant_id: g.grantId,
    user_id: g.userId,
    user_name: testUsers.find((u) => u.user_id === g.userId)?.name || g.userId,
    client_id: g.clientId,
    client_name: testClients.find((c) => c.client_id === g.clientId)?.name || g.clientId,
    scope: Array.isArray(g.scope) ? g.scope.join(' ') : g.scope,
    created_at: new Date(g.createdAt).toISOString(),
    updated_at: new Date(g.updatedAt).toISOString(),
    authorization_count: g.authorizationCount,
    chain_index: g.chainIndex || 1,
    revoked: !!g.revoked,
    revoked_at: g.revokedAt ? new Date(g.revokedAt).toISOString() : null,
  }));

  res.render('index', {
    testClients,
    testUsers,
    scopes,
    allGrants,
    issuer,
    idTokenKid: config.tokens.idToken.kid,
    accessTokenKid: config.tokens.accessToken.kid,
  });
});

app.post('/api/clients', (req, res) => {
  try {
    const {
      name,
      redirect_uris = [],
      grant_types = ['authorization_code', 'refresh_token'],
      response_types = ['code'],
      scope = 'openid profile',
      type = 'confidential',
    } = req.body || {};

    const registered = clients.registerClient({
      name,
      redirectUris: Array.isArray(redirect_uris) ? redirect_uris : redirect_uris.split(/\s+/).filter(Boolean),
      grantTypes: Array.isArray(grant_types) ? grant_types : grant_types.split(/\s+/).filter(Boolean),
      responseTypes: Array.isArray(response_types) ? response_types : response_types.split(/\s+/).filter(Boolean),
      scope: Array.isArray(scope) ? scope.join(' ') : scope,
      type,
    });

    res.status(201).json({
      client_id: registered.clientId,
      client_secret: registered.clientSecret,
      name: registered.name,
      redirect_uris: registered.redirectUris,
      grant_types: registered.grantTypes,
      response_types: registered.responseTypes,
      scope: registered.scope,
      type: registered.type,
      created_at: registered.createdAt,
    });
  } catch (err) {
    res.status(400).json({ error: 'invalid_request', error_description: err.message });
  }
});

app.delete('/api/clients/:clientId', (req, res) => {
  const removed = clients._removeClient && clients._removeClient(req.params.clientId);
  if (!removed && typeof clients._removeClient !== 'function') {
    return res.status(501).json({ error: 'not_implemented', error_description: 'Client removal not supported' });
  }
  if (removed) {
    return res.json({ removed: true });
  }
  res.status(404).json({ error: 'not_found', error_description: 'Client not found' });
});

app.get('/api/grants', (req, res) => {
  const allClients = clients.getAllClients();
  const testUsers = [
    { username: 'alice', password: 'password123', name: 'Alice Wang', user_id: 'user-alice' },
    { username: 'bob', password: 'password456', name: 'Bob Li', user_id: 'user-bob' },
  ];

  const allGrants = grants.getAllGrants().map((g) => ({
    grant_id: g.grantId,
    user_id: g.userId,
    user_name: testUsers.find((u) => u.user_id === g.userId)?.name || g.userId,
    client_id: g.clientId,
    client_name: allClients.find((c) => c.clientId === g.clientId)?.name || g.clientId,
    scope: Array.isArray(g.scope) ? g.scope.join(' ') : g.scope,
    created_at: new Date(g.createdAt).toISOString(),
    updated_at: new Date(g.updatedAt).toISOString(),
    authorization_count: g.authorizationCount,
    chain_index: g.chainIndex || 1,
    revoked: !!g.revoked,
    revoked_at: g.revokedAt ? new Date(g.revokedAt).toISOString() : null,
  }));

  res.json(allGrants);
});

app.post('/api/grants/revoke', (req, res) => {
  const { user_id, client_id } = req.body || {};
  if (!user_id || !client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'user_id and client_id are required' });
  }

  const result = grants.revokeUserGrantAndTokens(user_id, client_id);
  res.json({
    found: result.found,
    tokens_revoked: result.tokensRevoked,
  });
});

app.post('/api/grants/reauthorize', (req, res) => {
  const { user_id, client_id, scope } = req.body || {};
  if (!user_id || !client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'user_id and client_id are required' });
  }

  const newGrant = grants.reauthorizeGrant({ userId: user_id, clientId: client_id, scope });
  res.json({
    grant_id: newGrant.grantId,
    scope: Array.isArray(newGrant.scope) ? newGrant.scope.join(' ') : newGrant.scope,
    chain_index: newGrant.chainIndex,
  });
});

app.post('/api/grants/narrow', (req, res) => {
  const { user_id, client_id, scope } = req.body || {};
  if (!user_id || !client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'user_id, client_id, scope required' });
  }
  const g = grants.narrowGrantScope(user_id, client_id, scope);
  if (!g) return res.status(404).json({ error: 'not_found' });
  res.json({
    grant_id: g.grantId,
    scope: Array.isArray(g.scope) ? g.scope.join(' ') : g.scope,
  });
});

app.get('/api/tokens/lifecycle', (req, res) => {
  const rtMap = tokenService._getRefreshTokenMap ? tokenService._getRefreshTokenMap() : new Map();
  const revoked = tokenService._getRevokedRefreshTokenIds ? tokenService._getRevokedRefreshTokenIds() : new Set();
  const tokens = [];
  for (const [tokenStr, td] of rtMap.entries()) {
    const createdAt = td.createdAt || Date.now();
    const expiresAt = td.expiresAt || (createdAt + 86400 * 1000);
    const ttl = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
    tokens.push({
      token: tokenStr.substring(0, 16) + '...' + tokenStr.substring(tokenStr.length - 8),
      token_id: td.tokenId,
      prev_id: td.prevTokenId || null,
      next_id: td.nextTokenId || null,
      user_id: td.userId,
      client_id: td.clientId,
      type: 'refresh_token',
      created_at: new Date(createdAt).toISOString(),
      expires_at: new Date(expiresAt).toISOString(),
      ttl_seconds: ttl,
      active: !revoked.has(td.tokenId) && ttl > 0,
      revoked: revoked.has(td.tokenId),
      rotation_count: td.rotationCount || 0,
    });
  }
  tokens.sort((a, b) => (b.created_at > a.created_at ? 1 : -1));
  res.json({ refresh_tokens: tokens });
});

app.post('/api/clients/import', (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : req.body.clients;
  if (!Array.isArray(arr)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Expected array of clients' });
  }
  const created = [];
  for (const c of arr) {
    try {
      const r = clientsModule.registerClient({
        name: c.name || 'Imported Client',
        redirectUris: c.redirect_uris || [],
        grantTypes: c.grant_types || ['authorization_code', 'refresh_token'],
        responseTypes: c.response_types || ['code'],
        scope: c.scope || 'openid profile',
        type: c.type || 'confidential',
      });
      created.push({
        client_id: r.clientId,
        client_secret: r.clientSecret,
        name: r.name,
        redirect_uris: r.redirectUris,
        grant_types: r.grantTypes,
        response_types: r.responseTypes,
        scope: r.scope,
        type: r.type,
        created_at: r.createdAt,
      });
    } catch (e) { /* skip */ }
  }
  res.json({ imported: created.length, clients: created });
});

app.get('/api/clients/export', (req, res) => {
  const list = clientsModule.getAllClients ? clientsModule.getAllClients() : [];
  res.json({
    clients: list.map((c) => ({
      name: c.name,
      type: c.type,
      grant_types: c.grantTypes,
      response_types: c.responseTypes,
      scope: c.scope,
      redirect_uris: c.redirectUris,
      _client_id: c.clientId,
      _client_secret: c.clientSecret,
    })),
    exported_at: new Date().toISOString(),
  });
});

app.post('/api/verify-jwt', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return res.status(400).json({ ok: false, error: 'not a JWT' });
    const kid = decoded.header && decoded.header.kid;
    const jwk = kid ? config.jwks.keys.find((k) => k.kid === kid) : null;
    let verified = null;
    let verifyError = null;
    if (jwk) {
      try {
        const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
        verified = jwt.verify(token, pubKey, { algorithms: ['RS256'], ignoreExpiration: true, ignoreNotBefore: true });
      } catch (e) {
        verifyError = e.message;
      }
    }
    const { exp, iat, nbf } = (decoded.payload || {});
    const now = Math.floor(Date.now() / 1000);
    res.json({
      ok: true,
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      matched_kid: kid || null,
      matched_jwk_exists: !!jwk,
      signature_valid: !!verified,
      verify_error: verifyError,
      timing: {
        issued_at: iat ? new Date(iat * 1000).toISOString() : null,
        expires_at: exp ? new Date(exp * 1000).toISOString() : null,
        not_before: nbf ? new Date(nbf * 1000).toISOString() : null,
        expires_in: exp ? Math.max(0, exp - now) : null,
        expired: exp ? now > exp : null,
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/_test/create-auth-code', (req, res) => {
  try {
    const {
      client_id, user_id, redirect_uri, scope = 'openid profile',
      nonce = null, code_challenge = null, code_challenge_method = 'S256',
    } = req.body || {};
    if (!client_id || !user_id || !redirect_uri) {
      return res.status(400).json({ error: 'client_id, user_id, redirect_uri required' });
    }
    const codeData = tokenService.generateAuthorizationCode({
      clientId: client_id, userId: user_id, redirectUri: redirect_uri,
      scope, codeChallenge: code_challenge, codeChallengeMethod: code_challenge ? (code_challenge_method || 'S256') : null,
      nonce,
    });
    res.json({
      code: codeData.code,
      expires_at: new Date(codeData.expiresAt).toISOString(),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/clients', (req, res) => {
  const allClients = clients.getAllClients();
  res.json({
    test_clients: allClients.map((client) => ({
      name: client.name,
      client_id: client.clientId,
      client_secret: client.clientSecret,
      type: client.type,
      grant_types: client.grantTypes,
      response_types: client.responseTypes,
      scope: client.scope,
      redirect_uris: client.redirectUris,
      created_at: client.createdAt,
    })),
    test_users: [
      { username: 'alice', password: 'password123', name: 'Alice Wang', user_id: 'user-alice' },
      { username: 'bob', password: 'password456', name: 'Bob Li', user_id: 'user-bob' },
    ],
  });
});

app.get('/test/callback', (req, res) => {
  const { code, state, error, error_description } = req.query;

  res.render('callback', {
    code: code || null,
    state: state || null,
    error: error || null,
    errorDescription: error_description || null,
  });
});

app.get('/login', (req, res) => {
  res.render('login', {
    error: null,
    redirect: req.query.redirect || '/',
  });
});

app.post('/login', (req, res) => {
  const { username, password, redirect } = req.body;

  const result = auth.authenticateUser(username, password);
  if (!result.authenticated) {
    return res.render('login', {
      error: '用户名或密码错误',
      redirect: redirect || '/',
    });
  }

  const session = auth.createSession(result.user.id);
  res.cookie('session_id', session.sessionId, {
    httpOnly: true,
    maxAge: config.session.expiresIn * 1000,
  });

  const safeRedirect = redirect && redirect.startsWith('/') ? redirect : '/';
  res.redirect(safeRedirect);
});

app.post('/logout', (req, res) => {
  const sessionId = req.cookies && req.cookies.session_id;
  if (sessionId) {
    auth.deleteSession(sessionId);
    res.clearCookie('session_id');
  }
  res.redirect('/login');
});

app.use('/', authorizationRouter);
app.use('/', tokenRouter);
app.use('/', oidc.router);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'server_error',
    error_description: 'Internal server error',
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: 'not_found',
    error_description: 'Endpoint not found',
  });
});

app.listen(config.server.port, () => {
  console.log('');
  console.log('========================================');
  console.log('  OAuth2 / OIDC Authorization Server');
  console.log('========================================');
  console.log('');
  console.log(`Server running at: ${config.server.issuer}`);
  console.log(`Port: ${config.server.port}`);
  console.log('');
  console.log('--- Endpoints ---');
  console.log(`  Authorization:   ${config.server.issuer}/authorize`);
  console.log(`  Token:           ${config.server.issuer}/token`);
  console.log(`  Revoke:          ${config.server.issuer}/revoke`);
  console.log(`  Introspect:      ${config.server.issuer}/introspect`);
  console.log(`  UserInfo:        ${config.server.issuer}/userinfo`);
  console.log(`  Discovery:       ${config.server.issuer}/.well-known/openid-configuration`);
  console.log(`  Login:           ${config.server.issuer}/login`);
  console.log('');
  console.log('--- Test Users ---');
  console.log('  alice / password123  (Alice Wang)');
  console.log('  bob   / password456  (Bob Li)');
  console.log('');
  console.log('Press Ctrl+C to stop');
  console.log('');
});
