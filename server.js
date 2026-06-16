const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');

const config = require('./config');
const clients = require('./clients');
const auth = require('./auth');
const tokenService = require('./tokenService');
const authorizationRouter = require('./authorization');
const tokenRouter = require('./token');
const oidc = require('./oidc');

const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  const allClients = [];
  for (const [id, client] of Object.entries({})) {}

  const testClients = [
    { name: 'Test Web App', type: 'confidential', redirect: 'http://localhost:3001/callback' },
    { name: 'Test Public App', type: 'public', redirect: 'http://localhost:3002/callback' },
    { name: 'Test Service', type: 'confidential (client_credentials)', redirect: 'N/A' },
  ];

  const testUsers = [
    { username: 'alice', password: 'password123', name: 'Alice Wang' },
    { username: 'bob', password: 'password456', name: 'Bob Li' },
  ];

  res.json({
    name: 'OAuth2 / OIDC Authorization Server',
    version: '1.0.0',
    endpoints: {
      authorization: `${config.server.issuer}/authorize`,
      token: `${config.server.issuer}/token`,
      revoke: `${config.server.issuer}/revoke`,
      introspect: `${config.server.issuer}/introspect`,
      userinfo: `${config.server.issuer}/userinfo`,
      discovery: `${config.server.issuer}/.well-known/openid-configuration`,
      jwks: `${config.server.issuer}/.well-known/jwks.json`,
      login: `${config.server.issuer}/login`,
    },
    test_clients: testClients,
    test_users: testUsers,
    flows_supported: [
      'Authorization Code Flow (with PKCE)',
      'Client Credentials Flow',
      'Refresh Token Flow (with Rotation)',
      'OpenID Connect (ID Token + UserInfo)',
    ],
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
