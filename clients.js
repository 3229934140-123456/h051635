const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const clients = new Map();
const testClientSecrets = new Map();

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function generateClientId() {
  return uuidv4();
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function registerClient({
  name,
  redirectUris = [],
  grantTypes = ['authorization_code', 'refresh_token'],
  responseTypes = ['code'],
  scope = 'openid profile',
  type = 'confidential',
}) {
  if (!name) {
    throw new Error('Client name is required');
  }

  const needsRedirectUris = grantTypes.some((g) =>
    ['authorization_code', 'implicit'].includes(g)
  );
  if (needsRedirectUris && (!redirectUris || redirectUris.length === 0)) {
    throw new Error('Redirect URIs are required for authorization_code and implicit grant types');
  }

  const clientId = generateClientId();
  const clientSecret = type === 'confidential' ? generateClientSecret() : null;

  const client = {
    clientId,
    clientSecretHash: clientSecret ? hashSecret(clientSecret) : null,
    name,
    redirectUris,
    grantTypes,
    responseTypes,
    scope,
    type,
    createdAt: new Date().toISOString(),
  };

  clients.set(clientId, client);
  if (clientSecret) {
    testClientSecrets.set(clientId, clientSecret);
  }

  return {
    clientId,
    clientSecret,
    ...client,
  };
}

function getClientById(clientId) {
  return clients.get(clientId) || null;
}

function getAllClients() {
  const result = [];
  for (const [clientId, client] of clients) {
    result.push({
      ...client,
      clientSecret: testClientSecrets.get(clientId) || null,
    });
  }
  return result;
}

function getClientSecret(clientId) {
  return testClientSecrets.get(clientId) || null;
}

function validateClientCredentials(clientId, clientSecret) {
  const client = getClientById(clientId);
  if (!client) {
    return { valid: false, client: null, error: 'invalid_client' };
  }

  if (client.type === 'public') {
    return { valid: true, client, error: null };
  }

  if (!clientSecret) {
    return { valid: false, client, error: 'invalid_client' };
  }

  if (hashSecret(clientSecret) !== client.clientSecretHash) {
    return { valid: false, client, error: 'invalid_client' };
  }

  return { valid: true, client, error: null };
}

function validateRedirectUri(client, redirectUri) {
  if (!client || !redirectUri) return false;
  return client.redirectUris.some((uri) => uri === redirectUri);
}

function validateGrantType(client, grantType) {
  if (!client || !grantType) return false;
  return client.grantTypes.includes(grantType);
}

function validateResponseType(client, responseType) {
  if (!client || !responseType) return false;
  return client.responseTypes.includes(responseType);
}

function parseScope(scopeStr) {
  if (!scopeStr) return [];
  return scopeStr.split(/\s+/).filter(Boolean);
}

function validateScope(client, requestedScopes, availableScopes) {
  const clientScopes = parseScope(client.scope);
  const requested = parseScope(requestedScopes);

  const validScopes = requested.filter(
    (scope) => clientScopes.includes(scope) && availableScopes[scope]
  );

  return validScopes;
}

registerClient({
  name: 'Test Web App',
  redirectUris: ['http://localhost:3001/callback', 'http://localhost:3000/test/callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scope: 'openid profile email read write',
  type: 'confidential',
});

registerClient({
  name: 'Test Public App',
  redirectUris: ['http://localhost:3002/callback', 'http://localhost:3000/test/callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  scope: 'openid profile email read',
  type: 'public',
});

registerClient({
  name: 'Test Service',
  redirectUris: [],
  grantTypes: ['client_credentials'],
  responseTypes: [],
  scope: 'read write admin',
  type: 'confidential',
});

module.exports = {
  registerClient,
  getClientById,
  getAllClients,
  getClientSecret,
  validateClientCredentials,
  validateRedirectUri,
  validateGrantType,
  validateResponseType,
  parseScope,
  validateScope,
  hashSecret,
  _removeClient: (clientId) => {
    const exists = clients.has(clientId);
    if (exists) {
      clients.delete(clientId);
      testClientSecrets.delete(clientId);
    }
    return exists;
  },
};
