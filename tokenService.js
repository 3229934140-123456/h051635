const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');

const authorizationCodes = new Map();
const refreshTokens = new Map();
const revokedTokens = new Set();
const revokedRefreshTokenIds = new Set();
const refreshTokenChains = new Map();

function generateAuthorizationCode({
  clientId,
  userId,
  redirectUri,
  scope,
  codeChallenge,
  codeChallengeMethod,
  nonce,
}) {
  const code = crypto.randomBytes(config.tokens.authorizationCode.length).toString('hex');
  const expiresAt = Date.now() + config.tokens.authorizationCode.expiresIn * 1000;

  const codeData = {
    code,
    clientId,
    userId,
    redirectUri,
    scope,
    codeChallenge: codeChallenge || null,
    codeChallengeMethod: codeChallengeMethod || 'S256',
    nonce: nonce || null,
    expiresAt,
    used: false,
    createdAt: Date.now(),
  };

  authorizationCodes.set(code, codeData);
  return codeData;
}

function getAuthorizationCode(code) {
  return authorizationCodes.get(code) || null;
}

function validateAuthorizationCode(code, clientId, redirectUri, codeVerifier) {
  const codeData = getAuthorizationCode(code);

  if (!codeData) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Invalid authorization code' };
  }

  if (codeData.used) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Authorization code has already been used' };
  }

  if (codeData.expiresAt < Date.now()) {
    authorizationCodes.delete(code);
    return { valid: false, error: 'invalid_grant', errorDescription: 'Authorization code has expired' };
  }

  if (codeData.clientId !== clientId) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Authorization code does not belong to this client' };
  }

  if (codeData.redirectUri !== redirectUri) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Redirect URI mismatch' };
  }

  if (codeData.codeChallenge) {
    if (!codeVerifier) {
      return { valid: false, error: 'invalid_request', errorDescription: 'Code verifier required' };
    }

    const computedChallenge = computeCodeChallenge(codeVerifier, codeData.codeChallengeMethod);
    if (computedChallenge !== codeData.codeChallenge) {
      return { valid: false, error: 'invalid_grant', errorDescription: 'PKCE verification failed' };
    }
  }

  return { valid: true, codeData, error: null };
}

function markAuthorizationCodeUsed(code) {
  const codeData = getAuthorizationCode(code);
  if (codeData) {
    codeData.used = true;
  }
}

function computeCodeChallenge(codeVerifier, method = 'S256') {
  if (method === 'plain') {
    return codeVerifier;
  }
  if (method === 'S256') {
    return crypto
      .createHash('sha256')
      .update(codeVerifier, 'ascii')
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  throw new Error('Unsupported code challenge method');
}

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function generateAccessToken({ userId, clientId, scope, additionalClaims = {} }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: config.server.issuer,
    sub: userId || clientId,
    aud: clientId,
    iat: now,
    exp: now + config.tokens.accessToken.expiresIn,
    jti: uuidv4(),
    scope: Array.isArray(scope) ? scope.join(' ') : scope,
    client_id: clientId,
    ...additionalClaims,
  };

  if (userId) {
    payload.sub = userId;
    payload.user_id = userId;
  }

  return jwt.sign(payload, config.tokens.accessToken.secret, { algorithm: 'HS256' });
}

function verifyAccessToken(token) {
  try {
    if (revokedTokens.has(token)) {
      return { valid: false, error: 'invalid_token', errorDescription: 'Token has been revoked' };
    }

    const decoded = jwt.verify(token, config.tokens.accessToken.secret, {
      algorithms: ['HS256'],
      issuer: config.server.issuer,
    });

    return { valid: true, decoded, error: null };
  } catch (err) {
    let errorDescription = 'Invalid token';
    if (err.name === 'TokenExpiredError') {
      errorDescription = 'Token has expired';
    } else if (err.name === 'JsonWebTokenError') {
      errorDescription = err.message;
    }
    return { valid: false, error: 'invalid_token', errorDescription };
  }
}

function generateRefreshToken({ userId, clientId, scope }) {
  const token = crypto.randomBytes(64).toString('hex');
  const expiresAt = Date.now() + config.tokens.refreshToken.expiresIn * 1000;
  const tokenId = uuidv4();

  const tokenData = {
    token,
    tokenId,
    userId,
    clientId,
    scope,
    expiresAt,
    createdAt: Date.now(),
    rotated: false,
    previousTokenId: null,
  };

  refreshTokens.set(token, tokenData);
  return tokenData;
}

function validateRefreshToken(token, clientId) {
  const tokenData = refreshTokens.get(token);

  if (!tokenData) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Invalid refresh token' };
  }

  if (revokedRefreshTokenIds.has(tokenData.tokenId)) {
    refreshTokens.delete(token);
    return { valid: false, error: 'invalid_grant', errorDescription: 'Refresh token has been revoked' };
  }

  if (tokenData.expiresAt < Date.now()) {
    refreshTokens.delete(token);
    return { valid: false, error: 'invalid_grant', errorDescription: 'Refresh token has expired' };
  }

  if (tokenData.clientId !== clientId) {
    return { valid: false, error: 'invalid_grant', errorDescription: 'Refresh token does not belong to this client' };
  }

  if (tokenData.rotated) {
    revokeRefreshTokenChain(tokenData.tokenId);
    return { valid: false, error: 'invalid_grant', errorDescription: 'Refresh token has already been used (possible token theft detected)' };
  }

  return { valid: true, tokenData, error: null };
}

function rotateRefreshToken(oldTokenData) {
  refreshTokens.get(oldTokenData.token).rotated = true;

  const newToken = generateRefreshToken({
    userId: oldTokenData.userId,
    clientId: oldTokenData.clientId,
    scope: oldTokenData.scope,
  });

  newToken.previousTokenId = oldTokenData.tokenId;

  if (!refreshTokenChains.has(oldTokenData.clientId)) {
    refreshTokenChains.set(oldTokenData.clientId, new Map());
  }
  const clientChains = refreshTokenChains.get(oldTokenData.clientId);
  clientChains.set(oldTokenData.tokenId, newToken.tokenId);

  return newToken;
}

function revokeRefreshTokenChain(tokenId) {
  const toRevoke = [tokenId];
  const visited = new Set();

  while (toRevoke.length > 0) {
    const current = toRevoke.pop();
    if (visited.has(current)) continue;
    visited.add(current);

    revokedRefreshTokenIds.add(current);

    for (const [token, data] of refreshTokens) {
      if (data.tokenId === current || data.previousTokenId === current) {
        refreshTokens.delete(token);
      }
    }

    for (const [clientId, chains] of refreshTokenChains) {
      for (const [prev, next] of chains) {
        if (prev === current && !visited.has(next)) {
          toRevoke.push(next);
        }
        if (next === current && !visited.has(prev)) {
          toRevoke.push(prev);
        }
      }
    }
  }
}

function normalizeTokenType(type) {
  if (!type) return 'access';
  const lowerType = type.toLowerCase();
  if (lowerType === 'access' || lowerType === 'access_token') return 'access';
  if (lowerType === 'refresh' || lowerType === 'refresh_token') return 'refresh';
  return 'access';
}

function revokeToken(token, type = 'access') {
  const normalizedType = normalizeTokenType(type);
  if (normalizedType === 'access') {
    revokedTokens.add(token);
    return true;
  }
  if (normalizedType === 'refresh') {
    const tokenData = refreshTokens.get(token);
    if (tokenData) {
      revokeRefreshTokenChain(tokenData.tokenId);
    }
    return true;
  }
  return false;
}

function introspectToken(token, tokenTypeHint = null) {
  const normalizedHint = tokenTypeHint ? normalizeTokenType(tokenTypeHint) : null;

  if (normalizedHint === 'refresh' || !normalizedHint) {
    const refreshData = refreshTokens.get(token);
    if (refreshData) {
      const revoked = revokedRefreshTokenIds.has(refreshData.tokenId);
      const active = !revoked && refreshData.expiresAt >= Date.now() && !refreshData.rotated;
      return {
        active,
        scope: Array.isArray(refreshData.scope) ? refreshData.scope.join(' ') : refreshData.scope,
        client_id: refreshData.clientId,
        sub: refreshData.userId || refreshData.clientId,
        exp: Math.floor(refreshData.expiresAt / 1000),
        iat: Math.floor(refreshData.createdAt / 1000),
        token_type: 'refresh_token',
      };
    }
  }

  if (normalizedHint === 'access' || !normalizedHint) {
    const result = verifyAccessToken(token);
    if (result.valid) {
      return {
        active: true,
        scope: result.decoded.scope,
        client_id: result.decoded.client_id,
        sub: result.decoded.sub,
        aud: result.decoded.aud,
        iss: result.decoded.iss,
        exp: result.decoded.exp,
        iat: result.decoded.iat,
        jti: result.decoded.jti,
        token_type: 'access_token',
      };
    }
  }

  return { active: false };
}

function hasScope(tokenScopes, requiredScope) {
  const scopes = Array.isArray(tokenScopes) ? tokenScopes : tokenScopes.split(/\s+/);
  return scopes.includes(requiredScope);
}

function validateScopeAccess(decodedToken, requiredScopes) {
  const tokenScopes = decodedToken.scope
    ? (Array.isArray(decodedToken.scope) ? decodedToken.scope : decodedToken.scope.split(/\s+/))
    : [];

  const missing = requiredScopes.filter((s) => !tokenScopes.includes(s));
  return {
    authorized: missing.length === 0,
    missingScopes: missing,
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authorizationCodes) {
    if (data.expiresAt < now) {
      authorizationCodes.delete(code);
    }
  }
  for (const [token, data] of refreshTokens) {
    if (data.expiresAt < now) {
      refreshTokens.delete(token);
    }
  }
}, 60000);

module.exports = {
  generateAuthorizationCode,
  getAuthorizationCode,
  validateAuthorizationCode,
  markAuthorizationCodeUsed,
  computeCodeChallenge,
  generateCodeVerifier,
  generateAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  validateRefreshToken,
  rotateRefreshToken,
  revokeToken,
  revokeRefreshTokenChain,
  introspectToken,
  hasScope,
  validateScopeAccess,
};
