const crypto = require('crypto');

function generateRsaKeyPair() {
  const keyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const publicDer = crypto.createPublicKey({ key: keyPair.publicKey, format: 'pem' })
    .export({ type: 'spki', format: 'der' });
  const kid = crypto.createHash('sha256').update(publicDer).digest('base64url').slice(0, 16);
  return { ...keyPair, kid };
}

const signingKeys = {
  accessToken: generateRsaKeyPair(),
  idToken: generateRsaKeyPair(),
};

function getJwkFromPem(pemKey, kid, use) {
  const pubObj = crypto.createPublicKey({ key: pemKey, format: 'pem' });
  const jwk = pubObj.export({ format: 'jwk' });
  return {
    ...jwk,
    use,
    kid,
    alg: 'RS256',
  };
}

const config = {
  server: {
    port: process.env.PORT || 3000,
    issuer: process.env.ISSUER || 'http://localhost:3000',
  },

  tokens: {
    accessToken: {
      algorithm: 'RS256',
      privateKey: signingKeys.accessToken.privateKey,
      publicKey: signingKeys.accessToken.publicKey,
      kid: signingKeys.accessToken.kid,
      expiresIn: 900,
    },
    refreshToken: {
      secret: process.env.REFRESH_TOKEN_SECRET || crypto.randomBytes(64).toString('hex'),
      expiresIn: 2592000,
      rotationEnabled: true,
    },
    idToken: {
      algorithm: 'RS256',
      privateKey: signingKeys.idToken.privateKey,
      publicKey: signingKeys.idToken.publicKey,
      kid: signingKeys.idToken.kid,
      expiresIn: 3600,
    },
    authorizationCode: {
      expiresIn: 600,
      length: 32,
    },
  },

  jwks: {
    keys: [
      getJwkFromPem(signingKeys.idToken.publicKey, signingKeys.idToken.kid, 'sig'),
      getJwkFromPem(signingKeys.accessToken.publicKey, signingKeys.accessToken.kid, 'sig'),
    ],
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
