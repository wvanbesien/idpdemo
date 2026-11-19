// Shared bootstrap (identical copy lives in both apps): express, session cookie, health check, HTTP/HTTPS listener.
import express from 'express';
import session from 'express-session';
import memorystore from 'memorystore';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { envBool, envInt } from './ui.js';

export function boot(defaultCookieName) {
  const port = envInt('PORT', 8080);
  const tlsCert = process.env.TLS_CERT_FILE;
  const tlsKey = process.env.TLS_KEY_FILE;
  const useTls = !!(tlsCert && tlsKey);
  const baseUrl = (process.env.BASE_URL || `${useTls ? 'https' : 'http'}://localhost:${port}`).replace(/\/+$/, '');
  const secure = envBool('COOKIE_SECURE', baseUrl.startsWith('https://'));
  const sameSite = (process.env.COOKIE_SAMESITE || 'lax').toLowerCase();
  const scfg = {
    cookieName: process.env.COOKIE_NAME || defaultCookieName,
    timeoutSeconds: envInt('SESSION_TIMEOUT_SECONDS', 3600),
    rolling: envBool('SESSION_ROLLING', true),
    secure,
    sameSite,
    secretGenerated: !process.env.SESSION_SECRET,
  };
  const Store = memorystore(session);
  const app = express();
  app.disable('x-powered-by');
  const tp = process.env.TRUST_PROXY;
  app.set('trust proxy', tp === undefined || tp === '' ? false : /^\d+$/.test(tp) ? Number(tp) : /^(true|false)$/i.test(tp) ? tp === 'true' : tp);
  app.get('/healthz', (_req, res) => res.type('text').send('ok'));
  app.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  app.use(
    session({
      name: scfg.cookieName,
      secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
      resave: false,
      saveUninitialized: false,
      rolling: scfg.rolling,
      store: new Store({ checkPeriod: 60_000, ttl: scfg.timeoutSeconds * 1000 }),
      cookie: { httpOnly: true, secure: scfg.secure, sameSite: sameSite === 'none' ? 'none' : sameSite, maxAge: scfg.timeoutSeconds * 1000, path: '/' },
    }),
  );
  const listen = () => {
    const server = useTls
      ? https.createServer({ cert: fs.readFileSync(tlsCert), key: fs.readFileSync(tlsKey) }, app)
      : http.createServer(app);
    server.listen(port, () => console.log(`Listening on ${useTls ? 'https' : 'http'}://0.0.0.0:${port}  (BASE_URL=${baseUrl})`));
    const stop = () => server.close(() => process.exit(0));
    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
  };
  return { app, listen, baseUrl, scfg, port, useTls };
}

export const sessionP = (req) => ({
  regenerate: () => new Promise((res, rej) => req.session.regenerate((e) => (e ? rej(e) : res()))),
  destroy: () => new Promise((res) => req.session.destroy(() => res())),
  save: () => new Promise((res, rej) => req.session.save((e) => (e ? rej(e) : res()))),
});
