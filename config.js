const crypto = require('crypto');

const config = {
  server: {
    port: process.env.PORT || 3000,
    issuer: process.env.ISSUER || 'http://localhost:3000',
  },

  tokens: {
    accessToken: {
      secret: process.env.ACCESS_TOKEN_SECRET || crypto.randomBytes(64).toString('hex'),
      expiresIn: 900,
    },
    refreshToken: {
      secret: process.env.REFRESH_TOKEN_SECRET || crypto.randomBytes(64).toString('hex'),
      expiresIn: 2592000,
      rotationEnabled: true,
    },
    idToken: {
      secret: process.env.ID_TOKEN_SECRET || crypto.randomBytes(64).toString('hex'),
      expiresIn: 3600,
    },
    authorizationCode: {
      expiresIn: 600,
      length: 32,
    },
  },

  scopes: {
    'openid': 'OpenID Connect identity scope',
    'profile': 'User profile information',
    'email': 'User email address',
    'read': 'Read access to resources',
    'write': 'Write access to resources',
    'admin': 'Administrative access',
  },

  defaultScopes: ['openid', 'profile'],

  session: {
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    expiresIn: 3600,
  },

  pkce: {
    enabled: true,
    requiredForPublicClients: true,
  },
};

module.exports = config;
