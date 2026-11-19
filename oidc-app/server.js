import * as client from 'openid-client';
import { boot, sessionP } from './lib/boot.js';
import {
  esc, raw, kv, grid, code, json, section, when, countdown, decodeJwt, environmentInfo, requestInfo,
  sessionCookieInfo, page, errorPage, envBool, mask, iso,
} from './lib/ui.js';

const TITLE = 'IDP Demo – OIDC Client';
const PROTO = 'OpenID Connect';
const { app, listen, baseUrl, scfg } = boot('oidcdemo.sid');

// ---------- configuration ----------
const issuerEnv = (process.env.OIDC_ISSUER || '').replace(/\/\.well-known\/openid-configuration\/?$/, '');
const cfg = {
  issuer: issuerEnv,
  clientId: process.env.OIDC_CLIENT_ID || '',
  clientSecret: process.env.OIDC_CLIENT_SECRET || '',
  clientAuth: (process.env.OIDC_CLIENT_AUTH || (process.env.OIDC_CLIENT_SECRET ? 'post' : 'none')).toLowerCase(),
  scope: process.env.OIDC_SCOPE || 'openid profile email',
  redirectPath: process.env.OIDC_REDIRECT_PATH || '/callback',
  pkce: envBool('OIDC_PKCE', true),
  allowInsecure: envBool('OIDC_ALLOW_INSECURE', false),
  postLogoutRedirect: process.env.OIDC_POST_LOGOUT_REDIRECT_URI || `${baseUrl}/logged-out`,
  extraAuthParams: (() => { try { return JSON.parse(process.env.OIDC_EXTRA_AUTH_PARAMS || '{}'); } catch { return {}; } })(),
};
cfg.redirectUri = baseUrl + cfg.redirectPath;
const configured = !!(cfg.issuer && cfg.clientId);

let oidc; // discovered client.Configuration
let discoveryError;
async function getOidc() {
  if (oidc) return oidc;
  try {
    const auth = cfg.clientAuth === 'basic' ? client.ClientSecretBasic(cfg.clientSecret)
      : cfg.clientAuth === 'none' ? client.None() : client.ClientSecretPost(cfg.clientSecret);
    oidc = await client.discovery(new URL(cfg.issuer), cfg.clientId, undefined, auth,
      cfg.allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined);
    discoveryError = undefined;
    return oidc;
  } catch (e) {
    discoveryError = e;
    throw e;
  }
}

const needsLogin = (req, res, next) => (req.session?.oidc ? next() : res.redirect('/login'));

// ---------- routes ----------
app.get('/login', async (req, res) => {
  if (!configured) return res.send(setupPage());
  try {
    const c = await getOidc();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const params = { redirect_uri: cfg.redirectUri, scope: cfg.scope, state, nonce, ...cfg.extraAuthParams };
    let verifier;
    if (cfg.pkce) {
      verifier = client.randomPKCECodeVerifier();
      params.code_challenge = await client.calculatePKCECodeChallenge(verifier);
      params.code_challenge_method = 'S256';
    }
    req.session.login = { state, nonce, verifier, startedAt: Date.now(), authUrl: undefined };
    const url = client.buildAuthorizationUrl(c, params);
    req.session.login.authUrl = url.href;
    await sessionP(req).save();
    res.redirect(url.href);
  } catch (e) {
    res.status(502).send(errorPage(TITLE, PROTO, 'Could not start login', explain(e), `<p class="muted">Issuer: <code>${esc(cfg.issuer)}</code></p>`));
  }
});

app.get(cfg.redirectPath, async (req, res) => {
  const login = req.session.login;
  if (req.query.error) {
    return res.status(400).send(errorPage(TITLE, PROTO, 'The IdP returned an error', `${req.query.error}: ${req.query.error_description || ''}`));
  }
  if (!login) {
    return res.status(400).send(errorPage(TITLE, PROTO, 'No login in progress',
      'No pending login was found in your session (cookie missing/expired, or the callback was opened directly). Start again.'));
  }
  try {
    const c = await getOidc();
    const currentUrl = new URL(req.originalUrl, baseUrl + '/');
    const t0 = Date.now();
    const tokens = await client.authorizationCodeGrant(c, currentUrl, {
      pkceCodeVerifier: login.verifier, expectedState: login.state, expectedNonce: login.nonce, idTokenExpected: true,
    });
    const claims = tokens.claims();
    const plain = JSON.parse(JSON.stringify(tokens));
    let userinfo, userinfoError;
    if (c.serverMetadata().userinfo_endpoint && tokens.access_token) {
      try { userinfo = await client.fetchUserInfo(c, tokens.access_token, claims?.sub); } catch (e) { userinfoError = String(e.message || e); }
    }
    const callbackParams = Object.fromEntries(currentUrl.searchParams);
    await sessionP(req).regenerate();
    req.session.createdAt = Date.now();
    req.session.oidc = {
      tokens: plain, userinfo, userinfoError, receivedAt: Date.now(), tokenRequestMs: Date.now() - t0,
      authUrl: login.authUrl, callbackParams: { ...callbackParams, code: callbackParams.code ? '(redacted)' : undefined },
      pkce: !!login.verifier, nonce: login.nonce, state: login.state,
    };
    await sessionP(req).save();
    res.redirect('/');
  } catch (e) {
    res.status(400).send(errorPage(TITLE, PROTO, 'Token exchange / validation failed', explain(e)));
  }
});

app.get('/', needsLogin, async (req, res) => {
  const s = req.session.oidc;
  const t = s.tokens;
  const idt = decodeJwt(t.id_token);
  const claims = idt?.payload || {};
  const at = decodeJwt(t.access_token);
  const exp = t.expires_in ? new Date(s.receivedAt + t.expires_in * 1000) : undefined;
  const ck = sessionCookieInfo(req, scfg);
  const env = environmentInfo();
  const meta = oidc?.serverMetadata?.() || {};
  const name = userinfoName(claims, s.userinfo);

  const tokenBlock = (label, token, decoded) =>
    token
      ? code(token, { label: `${label} (raw)` }) +
        (decoded
          ? `<h3>Header</h3>${json(decoded.header)}<h3>Payload (claims)</h3>${json(decoded.payload)}<h3>Claims, annotated</h3>${claimTable(decoded.payload)}`
          : '<p class="muted">Opaque token – not a JWT, nothing to decode locally.</p>')
      : '<p class="muted">Not issued.</p>';

  const body = [
    section('Signed-in user',
      `<div class="hero"><div class="avatar">${esc((name || '?')[0].toUpperCase())}</div><div><strong style="font-size:18px">${esc(name || claims.sub)}</strong><br><span class="muted">sub: ${esc(claims.sub)}</span></div></div>` +
      kv([
        ['Issuer (iss)', claims.iss], ['Subject (sub)', claims.sub], ['Email', claims.email ?? s.userinfo?.email],
        ['Audience (aud)', [].concat(claims.aud ?? []).join(', ')], ['Authorized party (azp)', claims.azp],
        ['Auth time', claims.auth_time ? when(claims.auth_time * 1000) : ''], ['ACR', claims.acr], ['AMR', [].concat(claims.amr ?? []).join(', ')],
      ])),
    section('Token response', kv([
      ['token_type', t.token_type], ['scope granted', t.scope], ['expires_in', t.expires_in !== undefined ? `${t.expires_in} s` : ''],
      ['Access token expires', exp ? countdown(exp) : ''], ['Tokens received', when(s.receivedAt)], ['Token endpoint round trip', `${s.tokenRequestMs} ms`],
      ['Other fields in response', Object.keys(t).filter((k) => !['access_token', 'id_token', 'refresh_token', 'token_type', 'scope', 'expires_in'].includes(k)).map((k) => `${k}=${JSON.stringify(t[k])}`).join(', ')],
    ]) + `<div class="actions" style="margin-top:10px">${t.refresh_token ? '<form method="post" action="/refresh"><button class="btn sec">Refresh tokens now</button></form>' : '<span class="muted">No refresh token issued (request the offline_access scope if the IdP supports it).</span>'}</div>` +
      (s.refreshedAt ? `<p class="note">Last refreshed ${iso(s.refreshedAt)}</p>` : '')),
    section('ID token', tokenBlock('ID token', t.id_token, idt)),
    section('Access token', tokenBlock('Access token', t.access_token, at)),
    section('Refresh token', t.refresh_token ? code(t.refresh_token, { label: 'Refresh token' }) + ((decodeJwt(t.refresh_token)) ? json(decodeJwt(t.refresh_token).payload) : '') : '<p class="muted">Not issued.</p>', { open: false }),
    section('UserInfo endpoint response',
      s.userinfo ? json(s.userinfo) : `<p class="muted">${esc(s.userinfoError || 'No userinfo_endpoint advertised by the IdP.')}</p>`, { open: false }),
    section('SSO session (this application)', ck.html + `<h3>Cookies explained</h3><p class="note">This app keeps tokens server-side; the browser only holds the opaque, signed session cookie above. The IdP keeps its own separate SSO session cookie on the IdP domain – that is what lets other apps sign in without a prompt, and its lifetime is set in the IdP, not here.</p>`),
    section('Login flow details', kv([
      ['Authorization request URL', raw(`<code style="word-break:break-all">${esc(s.authUrl)}</code>`)],
      ['Callback parameters', JSON.stringify(s.callbackParams)], ['state', s.state], ['nonce', s.nonce], ['PKCE (S256)', s.pkce ? 'yes' : 'no'],
    ]), { open: false }),
    section('Application configuration', kv([
      ['Base URL', baseUrl], ['Redirect URI (register this at the IdP)', cfg.redirectUri], ['Post-logout redirect URI', cfg.postLogoutRedirect],
      ['Issuer', cfg.issuer], ['Client ID', cfg.clientId], ['Client secret', cfg.clientSecret ? mask(cfg.clientSecret) : '(none – public client)'],
      ['Client authentication', cfg.clientAuth], ['Scopes requested', cfg.scope], ['PKCE', String(cfg.pkce)],
      ['Extra authorization params', JSON.stringify(cfg.extraAuthParams)], ['Allow insecure (http) IdP', String(cfg.allowInsecure)],
      ['Session secret', scfg.secretGenerated ? 'randomly generated at start (sessions break on restart / with >1 replica)' : 'from SESSION_SECRET'],
    ]) + '<h3>IdP discovery document</h3>' + json(meta), { open: false }),
    section('Environment', env.summary + '<h3>Relevant environment variables</h3>' + env.vars + '<h3>This request</h3>' + requestInfo(req), { open: false }),
  ].join('');

  res.send(page({
    title: TITLE, protocol: PROTO, user: name || claims.sub, body,
    actions: `<form method="post" action="/logout"><button class="btn danger">Log out</button></form> <form method="post" action="/logout?local=1"><button class="btn sec" title="Only destroys the app session, leaves the IdP session alone">Local logout only</button></form>`,
  }));
});

app.post('/refresh', needsLogin, async (req, res) => {
  const s = req.session.oidc;
  try {
    const c = await getOidc();
    const r = JSON.parse(JSON.stringify(await client.refreshTokenGrant(c, s.tokens.refresh_token)));
    s.tokens = { ...s.tokens, ...r, refresh_token: r.refresh_token || s.tokens.refresh_token };
    s.receivedAt = Date.now();
    s.refreshedAt = Date.now();
    res.redirect('/');
  } catch (e) {
    res.status(400).send(errorPage(TITLE, PROTO, 'Refresh failed', explain(e)));
  }
});

app.post('/logout', async (req, res) => {
  const idToken = req.session.oidc?.tokens?.id_token;
  await sessionP(req).destroy();
  res.clearCookie(scfg.cookieName, { path: '/' });
  if (req.query.local) return res.redirect('/logged-out');
  try {
    const c = await getOidc();
    if (!c.serverMetadata().end_session_endpoint) return res.redirect('/logged-out?note=no_end_session_endpoint');
    const url = client.buildEndSessionUrl(c, { post_logout_redirect_uri: cfg.postLogoutRedirect, ...(idToken ? { id_token_hint: idToken } : {}) });
    res.redirect(url.href);
  } catch {
    res.redirect('/logged-out?note=idp_unreachable');
  }
});

app.get('/logged-out', (req, res) => {
  const notes = { no_end_session_endpoint: 'The IdP does not advertise an end_session_endpoint, so only the application session was ended.', idp_unreachable: 'Could not reach the IdP for RP-initiated logout; only the application session was ended.' };
  res.send(page({ title: TITLE, protocol: PROTO, body: `<div class="card"><div class="inner"><h2>You have been logged out</h2><p>The application session has been destroyed.</p>${notes[req.query.note] ? `<p class="note">${esc(notes[req.query.note])}</p>` : ''}<p><a class="btn" href="/login">Log in again</a></p></div></div>` }));
});

app.get('/debug.json', needsLogin, (req, res) => res.json({ session: req.session.oidc, discovery: oidc?.serverMetadata?.() }));

app.get('/{*any}', (_req, res) => res.redirect('/'));

// ---------- helpers ----------
function setupPage() {
  return page({ title: TITLE, protocol: PROTO, body: section('Not configured yet',
    `<p>Set these environment variables and restart:</p>` + kv([
      ['OIDC_ISSUER', cfg.issuer || '(missing)', 'e.g. https://<tenant>.id.cyberark.cloud/<app-id>/'],
      ['OIDC_CLIENT_ID', cfg.clientId || '(missing)'], ['OIDC_CLIENT_SECRET', cfg.clientSecret ? mask(cfg.clientSecret) : '(not set – OK for public/PKCE clients)'],
      ['Redirect URI to register at the IdP', cfg.redirectUri, 'derived from BASE_URL'],
    ]) + environmentInfo().vars) });
}
function explain(e) {
  const bits = [e.message || String(e)];
  if (e.code) bits.push(`code=${e.code}`);
  if (e.error) bits.push(`error=${e.error}`);
  if (e.error_description) bits.push(`error_description=${e.error_description}`);
  if (e.cause?.message) bits.push(`cause=${e.cause.message}`);
  return bits.join(' | ');
}
function userinfoName(claims, ui) {
  return claims.name || ui?.name || claims.preferred_username || claims.email || ui?.email || claims.sub;
}
const CLAIM_DOC = {
  iss: 'Issuer of the token', sub: 'Subject – unique user ID at the issuer', aud: 'Intended audience (client ID)', exp: 'Expiry time', iat: 'Issued-at time',
  nbf: 'Not valid before', auth_time: 'When the user actually authenticated', nonce: 'Replay protection value echoed from the request', azp: 'Authorized party',
  acr: 'Authentication context class achieved', amr: 'Authentication methods used', sid: 'IdP session ID (used for logout)', at_hash: 'Hash of the access token', jti: 'Unique token ID',
};
function claimTable(p) {
  return grid(['Claim', 'Value', 'Meaning'], Object.entries(p).map(([k, v]) => [
    k,
    ['exp', 'iat', 'nbf', 'auth_time'].includes(k) && typeof v === 'number' ? raw(`${esc(v)} → ${when(v * 1000).html}`) : typeof v === 'object' ? JSON.stringify(v) : String(v),
    CLAIM_DOC[k] || '',
  ]));
}

app.use((err, _req, res, _next) => { console.error(err); res.status(500).send(errorPage(TITLE, PROTO, 'Unexpected error', explain(err))); });

console.log(`${TITLE} starting. Configured: ${configured}. Redirect URI: ${cfg.redirectUri}`);
listen();
if (configured) getOidc().then(() => console.log('OIDC discovery OK')).catch((e) => console.warn('OIDC discovery failed (will retry on login):', e.message));
