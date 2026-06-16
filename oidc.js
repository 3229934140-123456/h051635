const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');
const tokenService = require('./tokenService');
const auth = require('./auth');
const clients = require('./clients');

const router = express.Router();

function generateIdToken({ user, clientId, nonce, scope, accessToken, code }) {
  const now = Math.floor(Date.now() / 1000);
  const userClaims = auth.getUserClaims(user, scope);

  const payload = {
    iss: config.server.issuer,
    sub: user.id,
    aud: clientId,
    exp: now + config.tokens.idToken.expiresIn,
    iat: now,
    jti: uuidv4(),
    auth_time: now,
    ...userClaims,
  };

  if (nonce) {
    payload.nonce = nonce;
  }

  if (accessToken) {
    payload.at_hash = computeAtHash(accessToken);
  }

  if (code) {
    payload.c_hash = computeCodeHash(code);
  }

  return jwt.sign(payload, config.tokens.idToken.privateKey, {
    algorithm: 'RS256',
    keyid: config.tokens.idToken.kid,
  });
}

function computeAtHash(accessToken) {
  const hash = require('crypto').createHash('sha256').update(accessToken, 'ascii').digest();
  const leftMost = hash.slice(0, 16);
  return base64UrlEncode(leftMost);
}

function computeCodeHash(code) {
  const hash = require('crypto').createHash('sha256').update(code, 'ascii').digest();
  const leftMost = hash.slice(0, 16);
  return base64UrlEncode(leftMost);
}

function base64UrlEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function verifyIdToken(token) {
  try {
    const decoded = jwt.verify(token, config.tokens.idToken.publicKey, {
      algorithms: ['RS256'],
      issuer: config.server.issuer,
    });
    return { valid: true, decoded, error: null };
  } catch (err) {
    let errorDescription = 'Invalid ID token';
    if (err.name === 'TokenExpiredError') {
      errorDescription = 'ID token has expired';
    } else if (err.name === 'JsonWebTokenError') {
      errorDescription = err.message;
    }
    return { valid: false, error: 'invalid_token', errorDescription };
  }
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token', error_description: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.slice(7);
  const result = tokenService.verifyAccessToken(token);

  if (!result.valid) {
    return res.status(401).json({ error: result.error, error_description: result.errorDescription });
  }

  req.token = result.decoded;
  next();
}

router.get('/userinfo', authenticateToken, (req, res) => {
  const userId = req.token.sub || req.token.user_id;
  if (!userId) {
    return res.status(400).json({ error: 'invalid_token', error_description: 'Token does not contain user identity' });
  }

  const user = auth.getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'not_found', error_description: 'User not found' });
  }

  const tokenScopes = req.token.scope
    ? (Array.isArray(req.token.scope) ? req.token.scope : req.token.scope.split(/\s+/))
    : [];

  const claims = auth.getUserClaims(user, tokenScopes);

  res.json(claims);
});

router.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = config.server.issuer;

  const discovery = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    registration_endpoint: `${issuer}/connect/register`,
    scopes_supported: Object.keys(config.scopes),
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment'],
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    token_endpoint_auth_signing_alg_values_supported: ['RS256'],
    service_documentation: `${issuer}/.well-known/openid-configuration`,
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    id_token_encryption_alg_values_supported: [],
    id_token_encryption_enc_values_supported: [],
    userinfo_signing_alg_values_supported: [],
    userinfo_encryption_enc_values_supported: [],
    request_object_signing_alg_values_supported: [],
    display_values_supported: [],
    claim_types_supported: ['normal'],
    claims_supported: [
      'sub',
      'iss',
      'aud',
      'exp',
      'iat',
      'auth_time',
      'nonce',
      'at_hash',
      'c_hash',
      'name',
      'given_name',
      'family_name',
      'middle_name',
      'nickname',
      'preferred_username',
      'profile',
      'picture',
      'website',
      'email',
      'email_verified',
      'gender',
      'birthdate',
      'zoneinfo',
      'locale',
      'updated_at',
    ],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    require_request_uri_registration: false,
    code_challenge_methods_supported: ['plain', 'S256'],
  };

  res.json(discovery);
});

router.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: config.jwks.keys });
});

module.exports = {
  router,
  generateIdToken,
  verifyIdToken,
  authenticateToken,
};
