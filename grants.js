const { v4: uuidv4 } = require('uuid');
const tokenService = require('./tokenService');

const grantsHistory = [];

function findActiveGrant(userId, clientId) {
  return grantsHistory.find(
    (g) => g.userId === userId && g.clientId === clientId && !g.revoked
  );
}

function recordGrant({ userId, clientId, scope }) {
  if (!userId || !clientId) return null;

  const scopeList = Array.isArray(scope) ? scope : (scope || '').split(/\s+/).filter(Boolean);
  const active = findActiveGrant(userId, clientId);

  if (active) {
    const newScopes = Array.from(new Set([...(active.scope || []), ...scopeList]));
    active.scope = newScopes;
    active.updatedAt = Date.now();
    active.authorizationCount = (active.authorizationCount || 1) + 1;
    return active;
  }

  const previousChain = grantsHistory.filter(
    (g) => g.userId === userId && g.clientId === clientId
  ).length;

  const grant = {
    grantId: uuidv4(),
    userId,
    clientId,
    scope: scopeList,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    authorizationCount: 1,
    revoked: false,
    chainIndex: previousChain + 1,
  };
  grantsHistory.push(grant);
  return grant;
}

function narrowGrantScope(userId, clientId, reducedScope) {
  const active = findActiveGrant(userId, clientId);
  if (!active) return null;

  const original = Array.isArray(active.scope) ? active.scope : active.scope.split(/\s+/);
  const reduced = Array.isArray(reducedScope) ? reducedScope : reducedScope.split(/\s+/).filter(Boolean);
  const intersection = original.filter((s) => reduced.includes(s));
  if (intersection.length === 0) return active;

  active.scope = intersection;
  active.updatedAt = Date.now();
  return active;
}

function reauthorizeGrant({ userId, clientId, scope }) {
  const existing = findActiveGrant(userId, clientId);
  if (existing) {
    revokeUserGrantAndTokens(userId, clientId);
  }
  return recordGrant({ userId, clientId, scope: scope || 'openid profile' });
}

function getGrant(userId, clientId) {
  return findActiveGrant(userId, clientId) || null;
}

function getAllGrants(includeRevoked = true) {
  const sorted = [...grantsHistory].sort((a, b) => b.updatedAt - a.updatedAt);
  if (includeRevoked) return sorted;
  return sorted.filter((g) => !g.revoked);
}

function getGrantsForUser(userId) {
  return getAllGrants().filter((g) => g.userId === userId);
}

function getGrantsForClient(clientId) {
  return getAllGrants().filter((g) => g.clientId === clientId);
}

function revokeGrant(userId, clientId) {
  const g = findActiveGrant(userId, clientId);
  if (!g) return false;
  g.revoked = true;
  g.revokedAt = Date.now();
  return true;
}

function revokeUserGrantAndTokens(userId, clientId) {
  const grant = findActiveGrant(userId, clientId);
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
  }
  return { found: true, tokensRevoked: count };
}

function attachRefreshTokenToGrant(userId, clientId, tokenId, token, { chainGrantId = null } = {}) {
  let grant;
  if (chainGrantId) {
    grant = grantsHistory.find((g) => g.grantId === chainGrantId);
  }
  if (!grant) grant = findActiveGrant(userId, clientId);
  if (!grant) return;
  if (!grant._tokens) grant._tokens = [];
  grant._tokens.push({ tokenId, token, attachedAt: Date.now() });
}

function getGrantById(grantId) {
  return grantsHistory.find((g) => g.grantId === grantId) || null;
}

module.exports = {
  recordGrant,
  narrowGrantScope,
  reauthorizeGrant,
  getGrant,
  getGrantById,
  getAllGrants,
  getGrantsForUser,
  getGrantsForClient,
  revokeGrant,
  revokeUserGrantAndTokens,
  attachRefreshTokenToGrant,
};
