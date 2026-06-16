const express = require('express');
const config = require('./config');
const clients = require('./clients');
const auth = require('./auth');
const tokenService = require('./tokenService');
const grants = require('./grants');

const router = express.Router();

function extractClientCredentials(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Basic ')) {
    const encoded = authHeader.slice(6);
    const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
    const [clientId, clientSecret] = decoded.split(':');
    return { clientId, clientSecret };
  }

  return {
    clientId: req.body.client_id,
    clientSecret: req.body.client_secret,
  };
}

function sendTokenError(res, error, errorDescription, statusCode = 400) {
  res.status(statusCode).json({
    error,
    error_description: errorDescription,
  });
}

router.post('/token', async (req, res) => {
  const { grant_type } = req.body;
  const { clientId, clientSecret } = extractClientCredentials(req);

  if (!grant_type) {
    return sendTokenError(res, 'invalid_request', 'grant_type is required');
  }

  if (!clientId) {
    return sendTokenError(res, 'invalid_client', 'client_id is required', 401);
  }

  const credResult = clients.validateClientCredentials(clientId, clientSecret);
  if (!credResult.valid) {
    return sendTokenError(res, credResult.error, 'Invalid client credentials', 401);
  }

  const client = credResult.client;

  if (!clients.validateGrantType(client, grant_type)) {
    return sendTokenError(res, 'unsupported_grant_type', `Grant type ${grant_type} is not supported for this client`);
  }

  switch (grant_type) {
    case 'authorization_code':
      return handleAuthorizationCode(req, res, client);
    case 'client_credentials':
      return handleClientCredentials(req, res, client);
    case 'refresh_token':
      return handleRefreshToken(req, res, client);
    default:
      return sendTokenError(res, 'unsupported_grant_type', `Unsupported grant type: ${grant_type}`);
  }
});

function handleAuthorizationCode(req, res, client) {
  const { code, redirect_uri, code_verifier } = req.body;

  if (!code) {
    return sendTokenError(res, 'invalid_request', 'code is required');
  }

  if (!redirect_uri) {
    return sendTokenError(res, 'invalid_request', 'redirect_uri is required');
  }

  const validation = tokenService.validateAuthorizationCode(
    code,
    client.clientId,
    redirect_uri,
    code_verifier
  );

  if (!validation.valid) {
    return sendTokenError(res, validation.error, validation.errorDescription);
  }

  tokenService.markAuthorizationCodeUsed(code);

  const { codeData } = validation;
  const scopes = clients.parseScope(codeData.scope);

  grants.recordGrant({
    userId: codeData.userId,
    clientId: client.clientId,
    scope: scopes,
  });

  const accessToken = tokenService.generateAccessToken({
    userId: codeData.userId,
    clientId: client.clientId,
    scope: scopes,
  });

  const refreshTokenData = tokenService.generateRefreshToken({
    userId: codeData.userId,
    clientId: client.clientId,
    scope: scopes,
  });

  grants.attachRefreshTokenToGrant(
    codeData.userId,
    client.clientId,
    refreshTokenData.tokenId,
    refreshTokenData.token
  );

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.tokens.accessToken.expiresIn,
    scope: codeData.scope,
    refresh_token: refreshTokenData.token,
  };

  if (scopes.includes('openid')) {
    const oidc = require('./oidc');
    const user = auth.getUserById(codeData.userId);
    if (user) {
      const idToken = oidc.generateIdToken({
        user,
        clientId: client.clientId,
        nonce: codeData.nonce,
        scope: scopes,
      });
      response.id_token = idToken;
    }
  }

  res.json(response);
}

function handleClientCredentials(req, res, client) {
  const { scope } = req.body;

  const clientScopes = clients.parseScope(client.scope);
  const availableScopes = config.scopes;

  if (scope) {
    const requestedScopes = clients.parseScope(scope);
    const invalidScopes = requestedScopes.filter(
      (s) => !clientScopes.includes(s) || !availableScopes[s]
    );

    if (invalidScopes.length > 0) {
      return sendTokenError(
        res,
        'invalid_scope',
        `Invalid scope(s): ${invalidScopes.join(', ')}. Requested scope not in client allowed scope or not supported by server.`,
        400
      );
    }

    const finalScopes = requestedScopes;

    const accessToken = tokenService.generateAccessToken({
      clientId: client.clientId,
      scope: finalScopes,
    });

    const response = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.tokens.accessToken.expiresIn,
      scope: finalScopes.join(' '),
    };

    return res.json(response);
  }

  const finalScopes = clientScopes;

  const accessToken = tokenService.generateAccessToken({
    clientId: client.clientId,
    scope: finalScopes,
  });

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.tokens.accessToken.expiresIn,
    scope: finalScopes.join(' '),
  };

  res.json(response);
}

function handleRefreshToken(req, res, client) {
  const { refresh_token, scope } = req.body;

  if (!refresh_token) {
    return sendTokenError(res, 'invalid_request', 'refresh_token is required');
  }

  const validation = tokenService.validateRefreshToken(refresh_token, client.clientId);
  if (!validation.valid) {
    return sendTokenError(res, validation.error, validation.errorDescription);
  }

  const { tokenData } = validation;
  let finalScopes = tokenData.scope;

  if (scope) {
    const requestedScopes = clients.parseScope(scope);
    const originalScopes = Array.isArray(tokenData.scope) ? tokenData.scope : clients.parseScope(tokenData.scope);

    const narrowed = requestedScopes.filter((s) => originalScopes.includes(s));
    if (narrowed.length > 0) {
      finalScopes = narrowed;
    }
  }

  const accessToken = tokenService.generateAccessToken({
    userId: tokenData.userId,
    clientId: client.clientId,
    scope: finalScopes,
  });

  let response;
  if (config.tokens.refreshToken.rotationEnabled) {
    const newRefreshToken = tokenService.rotateRefreshToken(tokenData);

    if (tokenData.userId) {
      grants.attachRefreshTokenToGrant(
        tokenData.userId,
        client.clientId,
        newRefreshToken.tokenId,
        newRefreshToken.token
      );
    }

    response = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.tokens.accessToken.expiresIn,
      scope: Array.isArray(finalScopes) ? finalScopes.join(' ') : finalScopes,
      refresh_token: newRefreshToken.token,
    };
  } else {
    response = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.tokens.accessToken.expiresIn,
      scope: Array.isArray(finalScopes) ? finalScopes.join(' ') : finalScopes,
    };
  }

  const scopeList = Array.isArray(finalScopes) ? finalScopes : clients.parseScope(finalScopes);
  if (tokenData.userId && scopeList.includes('openid')) {
    const oidc = require('./oidc');
    const user = auth.getUserById(tokenData.userId);
    if (user) {
      const idToken = oidc.generateIdToken({
        user,
        clientId: client.clientId,
        scope: scopeList,
      });
      response.id_token = idToken;
    }
  }

  res.json(response);
}

router.post('/revoke', (req, res) => {
  const { token, token_type_hint } = req.body;
  const { clientId, clientSecret } = extractClientCredentials(req);

  if (!clientId) {
    return sendTokenError(res, 'invalid_client', 'client_id is required', 401);
  }

  const credResult = clients.validateClientCredentials(clientId, clientSecret);
  if (!credResult.valid) {
    return sendTokenError(res, credResult.error, 'Invalid client credentials', 401);
  }

  if (!token) {
    return res.status(200).json({});
  }

  tokenService.revokeToken(token, token_type_hint || 'access');
  res.status(200).json({});
});

router.post('/introspect', (req, res) => {
  const { token, token_type_hint } = req.body;
  const { clientId, clientSecret } = extractClientCredentials(req);

  if (!clientId) {
    return sendTokenError(res, 'invalid_client', 'client_id is required', 401);
  }

  const credResult = clients.validateClientCredentials(clientId, clientSecret);
  if (!credResult.valid) {
    return sendTokenError(res, credResult.error, 'Invalid client credentials', 401);
  }

  if (!token) {
    return res.json({ active: false });
  }

  const result = tokenService.introspectToken(token, token_type_hint);
  res.json(result);
});

module.exports = router;
