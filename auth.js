const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');

const users = new Map();
const sessions = new Map();

function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512')
    .toString('hex');
  return { salt: actualSalt, hash };
}

function registerUser({ username, password, email, name, profile = {} }) {
  if (!username || !password) {
    throw new Error('Username and password are required');
  }

  if (users.has(username)) {
    throw new Error('Username already exists');
  }

  const { salt, hash } = hashPassword(password);
  const userId = uuidv4();

  const user = {
    id: userId,
    username,
    email: email || null,
    name: name || username,
    passwordSalt: salt,
    passwordHash: hash,
    profile: {
      given_name: profile.given_name || name || username,
      family_name: profile.family_name || '',
      middle_name: profile.middle_name || '',
      nickname: profile.nickname || username,
      preferred_username: username,
      profile: profile.profile || '',
      picture: profile.picture || '',
      website: profile.website || '',
      gender: profile.gender || '',
      birthdate: profile.birthdate || '',
      zoneinfo: profile.zoneinfo || 'Asia/Shanghai',
      locale: profile.locale || 'zh-CN',
      updated_at: new Date().toISOString(),
    },
    createdAt: new Date().toISOString(),
  };

  users.set(username, user);
  return { id: user.id, username: user.username, email: user.email, name: user.name };
}

function authenticateUser(username, password) {
  const user = users.get(username);
  if (!user) {
    return { authenticated: false, user: null, error: 'invalid_credentials' };
  }

  const { hash } = hashPassword(password, user.passwordSalt);
  if (hash !== user.passwordHash) {
    return { authenticated: false, user: null, error: 'invalid_credentials' };
  }

  return { authenticated: true, user, error: null };
}

function createSession(userId) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + config.session.expiresIn * 1000;

  const session = {
    sessionId,
    userId,
    expiresAt,
    createdAt: Date.now(),
  };

  sessions.set(sessionId, session);
  return session;
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  if (session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

function deleteSession(sessionId) {
  return sessions.delete(sessionId);
}

function getUserById(userId) {
  for (const user of users.values()) {
    if (user.id === userId) {
      return user;
    }
  }
  return null;
}

function getUserClaims(user, scopes) {
  const claims = {
    sub: user.id,
  };

  const scopeList = Array.isArray(scopes) ? scopes : [scopes];

  if (scopeList.includes('profile')) {
    Object.assign(claims, user.profile);
  }

  if (scopeList.includes('email')) {
    claims.email = user.email;
    claims.email_verified = !!user.email;
  }

  return claims;
}

function requireAuth(req, res, next) {
  const sessionId = req.cookies && req.cookies.session_id;
  if (!sessionId) {
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  const session = getSession(sessionId);
  if (!session) {
    res.clearCookie('session_id');
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  const user = getUserById(session.userId);
  if (!user) {
    res.clearCookie('session_id');
    deleteSession(sessionId);
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
  }

  req.user = user;
  req.session = session;
  next();
}

registerUser({
  username: 'alice',
  password: 'password123',
  email: 'alice@example.com',
  name: 'Alice Wang',
  profile: {
    given_name: 'Alice',
    family_name: 'Wang',
    nickname: 'Ali',
    locale: 'zh-CN',
  },
});

registerUser({
  username: 'bob',
  password: 'password456',
  email: 'bob@example.com',
  name: 'Bob Li',
  profile: {
    given_name: 'Bob',
    family_name: 'Li',
    nickname: 'Bobby',
    locale: 'en-US',
  },
});

module.exports = {
  registerUser,
  authenticateUser,
  createSession,
  getSession,
  deleteSession,
  getUserById,
  getUserClaims,
  requireAuth,
};
