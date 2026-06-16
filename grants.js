const { v4: uuidv4 } = require('uuid');
const tokenService = require('./tokenService');

const grants = new Map();

function grantKey(userId, clientId) {
  return `${userId}:${clientId}`;
}

function recordGrant({ userId, clientId, scope }) {
  if (!userId || !clientId) return null;

  const key = grantKey(userId, clientId);
  const existing = grants.get(key);
  const scopeList = Array.isArray(scope) ? scope : (scope || '').split(/\s+/).filter(Boolean);

  if (existing) {
    const merged = Array.from(new Set([...(existing.scope || []), ...scopeList]));
    existing.scope = merged;
    existing.updatedAt = Date.now();
    existing.authorizationCount = (existing.authorizationCount || 1) + 1;
    return existing;
  }

  const grant = {
    grantId: uuidv4(),
    userId,
    clientId,
    scope: scopeList,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    authorizationCount: 1,
    revoked: false,
  };
  grants.set(key, grant);
  return grant;
}

function getGrant(userId, clientId) {
  const key = grantKey(userId, clientId);
  const g = grants.get(key);
  return g && !g.revoked ? g : null;
}

function getAllGrants() {
  return Array.from(grants.values());
}

function getGrantsForUser(userId) {
  return Array.from(grants.values()).filter((g) => g.userId === userId && !g.revoked);
}

function getGrantsForClient(clientId) {
  return Array.from(grants.values()).filter((g) => g.clientId === clientId && !g.revoked);
}

function revokeGrant(userId, clientId) {
  const key = grantKey(userId, clientId);
  const grant = grants.get(key);
  if (!grant) return false;

  grant.revoked = true;
  grant.revokedAt = Date.now();

  for (const [token, data] of Object.entries(tokenService)) {}
  return true;
}

function revokeUserGrantAndTokens(userId, clientId) {
  const key = grantKey(userId, clientId);
  const grant = grants.get(key);
  if (!grant) return { found: false, tokensRevoked: 0 };

  grant.revoked = true;
  grant.revokedAt = Date.now();

  const tokenMap = tokenService._getRefreshTokenMap ? tokenService._getRefreshTokenMap() : null;
  let count = 0;
  if (tokenMap) {
    for (const [tokenStr, tokenData] of tokenMap.entries()) {
      if (tokenData.userId === userId && tokenData.clientId === clientId) {
        tokenService.revokeToken(tokenStr, 'refresh_token');
        count++;
      }
    }
  } else {
    for (const tData of grant._tokens || []) {
      tokenService.revokeRefreshTokenChain(tData.tokenId);
      count++;
    }
  }

  return { found: true, tokensRevoked: count };
}

function attachRefreshTokenToGrant(userId, clientId, tokenId, token) {
  const key = grantKey(userId, clientId);
  const grant = grants.get(key);
  if (!grant) return;
  if (!grant._tokens) grant._tokens = [];
  grant._tokens.push({ tokenId, token, attachedAt: Date.now() });
}

module.exports = {
  recordGrant,
  getGrant,
  getAllGrants,
  getGrantsForUser,
  getGrantsForClient,
  revokeGrant,
  revokeUserGrantAndTokens,
  attachRefreshTokenToGrant,
};
