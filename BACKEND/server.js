// server.js
require('dotenv').config();
const express       = require('express');
const cookieParser  = require('cookie-parser');
const cors          = require('cors');
const jwt           = require('jsonwebtoken');
const bcrypt        = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const { createClient } = require('redis');
const rateLimit     = require('express-rate-limit');
const csurf         = require('csurf');

const prisma = new PrismaClient();

// Redis client - use REDIS_URL if provided
const redis = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redis.on('error', (err) => console.error('Redis error', err));

const app = express();
app.use(express.json());
app.use(cookieParser());

// Allow requests from the React dev server
app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true
  })
);

// CSRF via cookie
const csrfProtection = csurf({ cookie: true });

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// Rate limiter for signin
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later'
});

// Token helpers
function createAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '15m' });
}
function createRefreshToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

// Connect Redis before starting server
async function start() {
  await redis.connect().catch((err) => {
    console.error('Redis connect failed:', err);
    process.exit(1);
  });

  // 1. Provide CSRF token to client (cookie will be set by csurf)
  app.get('/csrf-token', csrfProtection, (req, res) => {
    console.log('[CSRF] serving token to client');
    res.json({ csrfToken: req.csrfToken() });
  });

  // 2. User registration
  app.post('/signup', csrfProtection, async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Missing username/password' });

      const hashed = await bcrypt.hash(password, 12);
      await prisma.user.create({
        data: { username, password: hashed }
      });
      console.log(`[SIGNUP] ${username} created`);
      res.status(201).json({ message: 'User created' });
    } catch (err) {
      console.error('[SIGNUP] error', err);
      res.status(400).json({ error: 'Username already exists or db error' });
    }
  });

  // 3. Signin with rate limiting
  app.post('/signin', loginLimiter, csrfProtection, async (req, res) => {
    try {
      const { username, password } = req.body;
      const user = await prisma.user.findUnique({ where: { username } });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        console.log(`[SIGNIN] failed attempt for ${username}`);
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const accessToken  = createAccessToken({ username });
      const refreshToken = createRefreshToken({ username });

      // store refresh token in redis (so we can rotate/blacklist)
      await redis.set(`refresh:${refreshToken}`, username, {
        EX: 7 * 24 * 3600
      });

      // Cookies: httpOnly, sameSite = 'lax' works for localhost (same registrable domain)
      res
        .cookie('accessToken',  accessToken,  { httpOnly: true, maxAge: 15 * 60 * 1000 })
        .cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 })
        .status(200)
        .json({ message: 'Logged in' });

      console.log(`[SIGNIN] ${username} logged in`);
    } catch (err) {
      console.error('[SIGNIN] error', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // 4. Token rotation
  app.post('/refresh', csrfProtection, async (req, res) => {
    try {
      const { refreshToken } = req.cookies;
      if (!refreshToken) return res.sendStatus(401);

      let payload;
      try {
        payload = jwt.verify(refreshToken, JWT_SECRET);
      } catch (err) {
        console.log('[REFRESH] invalid refresh token');
        return res.sendStatus(403);
      }

      const stored = await redis.get(`refresh:${refreshToken}`);
      if (!stored) {
        console.log('[REFRESH] token not found in redis');
        return res.sendStatus(403);
      }

      // Invalidate old refresh token
      await redis.del(`refresh:${refreshToken}`);

      // Issue new tokens
      const newAccess  = createAccessToken({ username: payload.username });
      const newRefresh = createRefreshToken({ username: payload.username });
      await redis.set(`refresh:${newRefresh}`, payload.username, {
        EX: 7 * 24 * 3600
      });

      res
        .cookie('accessToken',  newAccess,  { httpOnly: true, maxAge: 15 * 60 * 1000 })
        .cookie('refreshToken', newRefresh, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 })
        .json({ message: 'Tokens refreshed' });

      console.log(`[REFRESH] rotated for ${payload.username}`);
    } catch (err) {
      console.error('[REFRESH] error', err);
      res.sendStatus(500);
    }
  });

  // 5. Auth guard middleware
  function authGuard(req, res, next) {
    const token = req.cookies.accessToken;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch (err) {
      console.log('[AUTH] access token invalid/expired');
      res.status(403).json({ error: 'Token invalid or expired' });
    }
  }

  // 6. Protected user info
  app.get('/user', authGuard, (req, res) => {
    res.json({ username: req.user.username });
  });

  // 7. Logout
  app.post('/logout', csrfProtection, async (req, res) => {
    try {
      const { refreshToken } = req.cookies;
      if (refreshToken) await redis.del(`refresh:${refreshToken}`);
      res.clearCookie('accessToken').clearCookie('refreshToken');
      console.log('[LOGOUT] user logged out');
      res.json({ message: 'Logged out' });
    } catch (err) {
      console.error('[LOGOUT] error', err);
      res.sendStatus(500);
    }
  });

  const PORT = process.env.PORT || 4000;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed starting server', err);
  process.exit(1);
});
