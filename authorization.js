const express = require('express');
const url = require('url');
const config = require('./config');
const clients = require('./clients');
const auth = require('./auth');
const tokenService = require('./tokenService');

const router = express.Router();

function buildRedirectUri(baseUri, params, hash = false) {
  const parsed = new URL(baseUri);
  if (hash) {
    const hashParams = new URLSearchParams(params).toString();
    parsed.hash = hashParams;
  } else {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        parsed.searchParams.set(key, value);
      }
    }
  }
  return parsed.toString();
}

function sendError(redirectUri, error, errorDescription, state, responseMode) {
  const params = { error };
  if (errorDescription) params.error_description = errorDescription;
  if (state) params.state = state;

  if (responseMode === 'fragment') {
    return buildRedirectUri(redirectUri, params, true);
  }
  return buildRedirectUri(redirectUri, params, false);
}

router.get('/authorize', auth.requireAuth, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    nonce,
    code_challenge,
    code_challenge_method,
    response_mode,
  } = req.query;

  if (!client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_id is required' });
  }

  const client = clients.getClientById(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client' });
  }

  if (!redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri is required' });
  }

  if (!clients.validateRedirectUri(client, redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  }

  if (!response_type) {
    const errorUrl = sendError(redirect_uri, 'invalid_request', 'response_type is required', state, response_mode);
    return res.redirect(errorUrl);
  }

  if (!clients.validateResponseType(client, response_type)) {
    const errorUrl = sendError(redirect_uri, 'unsupported_response_type', 'Unsupported response type', state, response_mode);
    return res.redirect(errorUrl);
  }

  if (config.pkce.enabled && client.type === 'public' && config.pkce.requiredForPublicClients) {
    if (!code_challenge) {
      const errorUrl = sendError(redirect_uri, 'invalid_request', 'PKCE code_challenge is required for public clients', state, response_mode);
      return res.redirect(errorUrl);
    }
  }

  if (code_challenge_method && !['plain', 'S256'].includes(code_challenge_method)) {
    const errorUrl = sendError(redirect_uri, 'invalid_request', 'Invalid code_challenge_method, must be plain or S256', state, response_mode);
    return res.redirect(errorUrl);
  }

  const validScopes = clients.validateScope(client, scope, config.scopes);
  if (validScopes.length === 0 && scope) {
    const errorUrl = sendError(redirect_uri, 'invalid_scope', 'No valid scopes requested', state, response_mode);
    return res.redirect(errorUrl);
  }

  const finalScopes = validScopes.length > 0 ? validScopes : config.defaultScopes;

  const scopeDescriptions = finalScopes.map((s) => ({
    scope: s,
    description: config.scopes[s] || s,
  }));

  return res.render('authorize', {
    client,
    user: req.user,
    scopes: scopeDescriptions,
    state,
    nonce: nonce || null,
    redirectUri: redirect_uri,
    responseType: response_type,
    responseMode: response_mode || null,
    codeChallenge: code_challenge || null,
    codeChallengeMethod: code_challenge_method || 'S256',
    finalScopes: finalScopes.join(' '),
  });
});

router.post('/authorize', auth.requireAuth, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    nonce,
    code_challenge,
    code_challenge_method,
    response_mode,
    scope,
    action,
  } = req.body;

  if (action !== 'allow') {
    const errorUrl = sendError(redirect_uri, 'access_denied', 'User denied the authorization request', state, response_mode);
    return res.redirect(errorUrl);
  }

  const client = clients.getClientById(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client' });
  }

  if (!clients.validateRedirectUri(client, redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
  }

  if (!clients.validateResponseType(client, response_type)) {
    const errorUrl = sendError(redirect_uri, 'unsupported_response_type', 'Unsupported response type', state, response_mode);
    return res.redirect(errorUrl);
  }

  if (response_type === 'code') {
    const codeData = tokenService.generateAuthorizationCode({
      clientId: client_id,
      userId: req.user.id,
      redirectUri: redirect_uri,
      scope: scope,
      codeChallenge: code_challenge || null,
      codeChallengeMethod: code_challenge_method || null,
      nonce: nonce || null,
    });

    const params = { code: codeData.code };
    if (state) params.state = state;

    const redirectUrl = response_mode === 'fragment'
      ? buildRedirectUri(redirect_uri, params, true)
      : buildRedirectUri(redirect_uri, params, false);

    return res.redirect(redirectUrl);
  }

  const errorUrl = sendError(redirect_uri, 'unsupported_response_type', 'Only code response type is supported', state, response_mode);
  return res.redirect(errorUrl);
});

module.exports = router;
