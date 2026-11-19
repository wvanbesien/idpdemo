import fs from 'node:fs';
import express from 'express';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import { XMLParser } from 'fast-xml-parser';
import { boot, sessionP } from './lib/boot.js';
import {
  esc, raw, kv, grid, code, json, section, when, countdown, environmentInfo, requestInfo,
  sessionCookieInfo, page, errorPage, envBool, envInt, fingerprint, mask, iso,
} from './lib/ui.js';

const TITLE = 'IDP Demo – SAML Service Provider';
const PROTO = 'SAML 2.0';
const { app, listen, baseUrl, scfg } = boot('samldemo.sid');
const xml = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', removeNSPrefix: true, textNodeName: '#text', parseAttributeValue: false });
const arr = (x) => (x === undefined || x === null ? [] : Array.isArray(x) ? x : [x]);
const txt = (x) => (x && typeof x === 'object' ? x['#text'] ?? '' : x ?? '');
const readMaybeFile = (v, f) => v || (f && fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '');

// ---------- configuration ----------
const cfg = {
  spEntityId: process.env.SAML_SP_ENTITY_ID || `${baseUrl}/metadata`,
  acsPath: '/saml/acs',
  sloPath: '/saml/slo',
  metadataUrl: process.env.SAML_IDP_METADATA_URL || '',
  metadataFile: process.env.SAML_IDP_METADATA_FILE || '',
  ssoUrl: process.env.SAML_IDP_SSO_URL || '',
  sloUrl: process.env.SAML_IDP_SLO_URL || '',
  idpEntityId: process.env.SAML_IDP_ENTITY_ID || '',
  idpCert: readMaybeFile(process.env.SAML_IDP_CERT, process.env.SAML_IDP_CERT_FILE),
  nameIdFormat: process.env.SAML_NAMEID_FORMAT || undefined,
  binding: (process.env.SAML_AUTHN_BINDING || 'redirect').toLowerCase(),
  forceAuthn: envBool('SAML_FORCE_AUTHN', false),
  wantAssertionsSigned: envBool('SAML_WANT_ASSERTIONS_SIGNED', true),
  wantResponseSigned: envBool('SAML_WANT_RESPONSE_SIGNED', false),
  disableAuthnContext: envBool('SAML_DISABLE_REQUESTED_AUTHN_CONTEXT', true),
  clockSkewSeconds: envInt('SAML_CLOCK_SKEW_SECONDS', 60),
  audience: process.env.SAML_AUDIENCE === 'false' ? false : process.env.SAML_AUDIENCE || undefined,
  honorSessionNotOnOrAfter: envBool('SAML_HONOR_SESSION_NOT_ON_OR_AFTER', true),
  spKey: readMaybeFile(process.env.SAML_SP_PRIVATE_KEY, process.env.SAML_SP_PRIVATE_KEY_FILE),
  spCert: readMaybeFile(process.env.SAML_SP_CERT, process.env.SAML_SP_CERT_FILE),
  signRequests: envBool('SAML_SIGN_REQUESTS', false),
  sigAlg: process.env.SAML_SIGNATURE_ALGORITHM || 'sha256',
};
cfg.acsUrl = baseUrl + cfg.acsPath;
cfg.sloCallbackUrl = baseUrl + cfg.sloPath;

let idp = { source: 'none' }; // resolved IdP settings
let saml;
let setupError;

// ---------- IdP metadata ----------
function findKey(o, key) {
  if (!o || typeof o !== 'object') return undefined;
  if (key in o) return o[key];
  for (const v of Object.values(o)) { const r = findKey(v, key); if (r !== undefined) return r; }
  return undefined;
}
function parseIdpMetadata(text) {
  const doc = xml.parse(text);
  const ent = findKey(doc, 'EntityDescriptor');
  const entity = arr(ent).find((e) => e.IDPSSODescriptor) || arr(ent)[0];
  const d = entity?.IDPSSODescriptor;
  if (!d) throw new Error('No IDPSSODescriptor found in metadata');
  const pickBinding = (list, pref) => {
    const l = arr(list);
    return (l.find((s) => /HTTP-Redirect/.test(s['@_Binding'])) || l.find((s) => /HTTP-POST/.test(s['@_Binding'])) || l[0])?.['@_Location'];
  };
  const certs = arr(d.KeyDescriptor).filter((k) => k['@_use'] !== 'encryption').flatMap((k) => arr(k.KeyInfo?.X509Data).map((x) => txt(x.X509Certificate).replace(/\s+/g, '')));
  return {
    entityId: entity['@_entityID'], ssoUrl: pickBinding(d.SingleSignOnService), sloUrl: pickBinding(d.SingleLogoutService), certs: certs.filter(Boolean),
    ssoBindings: arr(d.SingleSignOnService).map((s) => `${s['@_Binding'].split(':').pop()} → ${s['@_Location']}`),
    nameIdFormats: arr(d.NameIDFormat).map(txt), wantAuthnRequestsSigned: d['@_WantAuthnRequestsSigned'],
  };
}
async function loadIdp() {
  let src = 'manual env vars', meta = {};
  try {
    let text;
    if (cfg.metadataUrl) { const r = await fetch(cfg.metadataUrl); if (!r.ok) throw new Error(`HTTP ${r.status} fetching ${cfg.metadataUrl}`); text = await r.text(); src = `metadata URL ${cfg.metadataUrl}`; }
    else if (cfg.metadataFile) { text = fs.readFileSync(cfg.metadataFile, 'utf8'); src = `metadata file ${cfg.metadataFile}`; }
    if (text) meta = parseIdpMetadata(text);
  } catch (e) { setupError = `IdP metadata: ${e.message}`; throw e; }
  const certs = cfg.idpCert ? [cfg.idpCert] : meta.certs || [];
  idp = {
    source: src, entityId: cfg.idpEntityId || meta.entityId, ssoUrl: cfg.ssoUrl || meta.ssoUrl, sloUrl: cfg.sloUrl || meta.sloUrl,
    certs, ssoBindings: meta.ssoBindings, nameIdFormats: meta.nameIdFormats, wantAuthnRequestsSigned: meta.wantAuthnRequestsSigned,
  };
  if (!idp.ssoUrl || !certs.length) throw new Error('IdP SSO URL and signing certificate are both required (set SAML_IDP_METADATA_URL or SAML_IDP_SSO_URL + SAML_IDP_CERT)');
  saml = new SAML({
    callbackUrl: cfg.acsUrl, entryPoint: idp.ssoUrl, issuer: cfg.spEntityId, idpCert: certs, idpIssuer: idp.entityId || undefined,
    audience: cfg.audience, identifierFormat: cfg.nameIdFormat, wantAssertionsSigned: cfg.wantAssertionsSigned, wantAuthnResponseSigned: cfg.wantResponseSigned,
    disableRequestedAuthnContext: cfg.disableAuthnContext, forceAuthn: cfg.forceAuthn, acceptedClockSkewMs: cfg.clockSkewSeconds * 1000,
    validateInResponseTo: ValidateInResponseTo.ifPresent, signatureAlgorithm: cfg.sigAlg,
    logoutUrl: idp.sloUrl || undefined, logoutCallbackUrl: cfg.sloCallbackUrl,
    ...(cfg.spKey ? { privateKey: cfg.spKey, decryptionPvk: cfg.spKey } : {}),
    ...(cfg.spCert ? { publicCert: cfg.spCert } : {}),
    ...(cfg.signRequests && cfg.spKey ? { privateKey: cfg.spKey } : {}),
  });
  setupError = undefined;
}
async function ensureIdp() {
  if (saml) return saml;
  await loadIdp();
  return saml;
}

// ---------- assertion parsing ----------
function analyseResponse(responseXml, assertionXml) {
  const out = { attributes: [], conditions: {}, authn: {}, subject: {}, signature: {}, response: {} };
  try {
    const r = xml.parse(responseXml);
    const resp = r.Response || r.LogoutResponse || {};
    out.response = { id: resp['@_ID'], inResponseTo: resp['@_InResponseTo'], destination: resp['@_Destination'], issueInstant: resp['@_IssueInstant'], issuer: txt(resp.Issuer),
      status: resp.Status?.StatusCode?.['@_Value'], version: resp['@_Version'] };
    out.encrypted = !!resp.EncryptedAssertion;
    out.signature.response = !!resp.Signature;
    const a = xml.parse(assertionXml || responseXml);
    const as = a.Assertion || resp.Assertion || a.Response?.Assertion;
    if (!as) return out;
    out.assertionId = as['@_ID'];
    out.issueInstant = as['@_IssueInstant'];
    out.signature.assertion = !!(resp.Assertion?.Signature || as.Signature);
    const sig = (resp.Assertion?.Signature || as.Signature || resp.Signature)?.SignedInfo;
    if (sig) out.signature.algorithms = { signature: sig.SignatureMethod?.['@_Algorithm'], digest: sig.Reference?.DigestMethod?.['@_Algorithm'], canonicalization: sig.CanonicalizationMethod?.['@_Algorithm'] };
    const sd = arr(as.Subject?.SubjectConfirmation)[0]?.SubjectConfirmationData || {};
    out.subject = { nameId: txt(as.Subject?.NameID), format: as.Subject?.NameID?.['@_Format'], recipient: sd['@_Recipient'], inResponseTo: sd['@_InResponseTo'], notOnOrAfter: sd['@_NotOnOrAfter'] };
    const c = as.Conditions || {};
    out.conditions = { notBefore: c['@_NotBefore'], notOnOrAfter: c['@_NotOnOrAfter'], audiences: arr(c.AudienceRestriction).flatMap((x) => arr(x.Audience).map(txt)) };
    const au = arr(as.AuthnStatement)[0] || {};
    out.authn = { instant: au['@_AuthnInstant'], sessionIndex: au['@_SessionIndex'], sessionNotOnOrAfter: au['@_SessionNotOnOrAfter'], contextClass: txt(au.AuthnContext?.AuthnContextClassRef) };
    out.attributes = arr(as.AttributeStatement).flatMap((st) => arr(st.Attribute)).map((at) => ({
      name: at['@_Name'], friendlyName: at['@_FriendlyName'], nameFormat: at['@_NameFormat']?.split(':').pop(), values: arr(at.AttributeValue).map((v) => (typeof v === 'object' ? txt(v) || JSON.stringify(v) : v)),
    }));
  } catch (e) { out.parseError = e.message; }
  return out;
}
const pretty = (s) => { try { return s.replace(/></g, '>\n<'); } catch { return s; } };

// ---------- routes ----------
app.get('/metadata', async (_req, res) => {
  try {
    const s = saml || new SAML({ callbackUrl: cfg.acsUrl, issuer: cfg.spEntityId, idpCert: 'x', logoutCallbackUrl: cfg.sloCallbackUrl, identifierFormat: cfg.nameIdFormat, wantAssertionsSigned: cfg.wantAssertionsSigned,
      ...(cfg.spKey ? { privateKey: cfg.spKey, decryptionPvk: cfg.spKey } : {}), ...(cfg.spCert ? { publicCert: cfg.spCert } : {}) });
    res.type('application/samlmetadata+xml').send(s.generateServiceProviderMetadata(cfg.spCert || null, cfg.spCert || null));
  } catch (e) { res.status(500).type('text').send(e.message); }
});

app.get('/login', async (req, res) => {
  try {
    const s = await ensureIdp();
    const relay = typeof req.query.next === 'string' && req.query.next.startsWith('/') && !req.query.next.startsWith('//') ? req.query.next : '/';
    if (cfg.binding === 'post') return res.send(await s.getAuthorizeFormAsync(relay, req.get('host')));
    res.redirect(await s.getAuthorizeUrlAsync(relay, req.get('host'), {}));
  } catch (e) { res.status(500).send(errorPage(TITLE, PROTO, 'Could not start login', `${e.message}`, setupHint())); }
});

app.post(cfg.acsPath, express.urlencoded({ extended: false, limit: '2mb' }), async (req, res) => {
  try {
    const s = await ensureIdp();
    const b64 = req.body.SAMLResponse;
    if (!b64) throw new Error('POST contained no SAMLResponse field');
    const responseXml = Buffer.from(b64, 'base64').toString('utf8');
    const { profile, loggedOut } = await s.validatePostResponseAsync(req.body);
    if (loggedOut || !profile) throw new Error('Response was a logout response, not an authentication response');
    const assertionXml = typeof profile.getAssertionXml === 'function' ? profile.getAssertionXml() : undefined;
    const info = analyseResponse(responseXml, assertionXml);
    const libProfile = JSON.parse(JSON.stringify(profile));
    await sessionP(req).regenerate();
    req.session.createdAt = Date.now();
    const sno = info.authn.sessionNotOnOrAfter ? Date.parse(info.authn.sessionNotOnOrAfter) : undefined;
    req.session.saml = {
      receivedAt: Date.now(), relayState: req.body.RelayState, info, libProfile, responseXml, assertionXml: assertionXml || '', sessionNotOnOrAfter: sno,
      logout: { nameID: profile.nameID, nameIDFormat: profile.nameIDFormat, sessionIndex: profile.sessionIndex, nameQualifier: profile.nameQualifier, spNameQualifier: profile.spNameQualifier, issuer: profile.issuer },
      postFields: Object.keys(req.body),
    };
    if (cfg.honorSessionNotOnOrAfter && sno && sno > Date.now()) req.session.cookie.maxAge = Math.min(scfg.timeoutSeconds * 1000, sno - Date.now());
    await sessionP(req).save();
    const next = typeof req.body.RelayState === 'string' && req.body.RelayState.startsWith('/') && !req.body.RelayState.startsWith('//') ? req.body.RelayState : '/';
    res.redirect(next);
  } catch (e) {
    console.error('ACS error:', e.message);
    const body = req.body?.SAMLResponse ? Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8') : '';
    res.status(400).send(errorPage(TITLE, PROTO, 'SAML response rejected', e.message, (body ? section('Received SAMLResponse (unvalidated)', code(pretty(body)), { open: false }) : '')));
  }
});

// Enforce SessionNotOnOrAfter from the assertion
app.use((req, res, next) => {
  const s = req.session?.saml;
  if (s && cfg.honorSessionNotOnOrAfter && s.sessionNotOnOrAfter && Date.now() > s.sessionNotOnOrAfter) {
    return req.session.destroy(() => res.status(401).send(page({ title: TITLE, protocol: PROTO, body: `<div class="card"><div class="inner"><h2>Session expired</h2><p>The IdP's <code>SessionNotOnOrAfter</code> time has passed.</p><a class="btn" href="/login">Log in again</a></div></div>` })));
  }
  next();
});
const needsLogin = (req, res, next) => (req.session?.saml ? next() : res.redirect('/login'));

app.get('/', needsLogin, (req, res) => {
  const s = req.session.saml;
  const i = s.info;
  const ck = sessionCookieInfo(req, scfg);
  const env = environmentInfo();
  const attrVal = (...names) => i.attributes.find((a) => names.some((n) => a.name === n || a.friendlyName === n || a.name?.endsWith('/' + n)))?.values[0];
  const display = attrVal('displayName', 'name', 'givenname', 'cn', 'email', 'mail', 'emailaddress') || i.subject.nameId;
  const sessionEnds = s.sessionNotOnOrAfter && cfg.honorSessionNotOnOrAfter ? Math.min(s.sessionNotOnOrAfter, ck.expires.getTime()) : ck.expires;
  const body = [
    section('Signed-in user', `<div class="hero"><div class="avatar">${esc((display || '?')[0].toUpperCase())}</div><div><strong style="font-size:18px">${esc(display)}</strong><br><span class="muted">NameID: ${esc(i.subject.nameId)}</span></div></div>` +
      kv([['NameID', i.subject.nameId], ['NameID format', i.subject.format], ['Issuer (IdP entity ID)', i.response.issuer || s.logout.issuer], ['Authentication time', i.authn.instant ? when(i.authn.instant) : ''],
        ['AuthnContext', i.authn.contextClass], ['Session index', i.authn.sessionIndex]])),
    section(`Attributes / claims (${i.attributes.length})`, i.attributes.length
      ? grid(['Name', 'Friendly name', 'Name format', 'Value(s)'], i.attributes.map((a) => [a.name, a.friendlyName, a.nameFormat, raw(a.values.map((v) => esc(v)).join('<br>'))]))
      : '<p class="muted">The assertion carried no AttributeStatement. Configure attribute mappings at the IdP.</p>', { note: 'Taken directly from the assertion that passed signature validation.' }),
    section('Validation results', kv([
      ['Response status', i.response.status?.split(':').pop()], ['Response signed', i.signature.response ? 'yes' : 'no'], ['Assertion signed', i.signature.assertion ? 'yes' : 'no'],
      ['Assertion encrypted', i.encrypted ? 'yes (decrypted with SP private key)' : 'no'], ['Signature algorithm', i.signature.algorithms?.signature?.split('#').pop()], ['Digest algorithm', i.signature.algorithms?.digest?.split('#').pop()],
      ['Signed with certificate (SHA-256)', idp.certs?.map(fingerprint).join('\n')],
      ['Destination', i.response.destination], ['Response ID', i.response.id], ['InResponseTo', i.response.inResponseTo || '(none – IdP-initiated)'], ['Assertion ID', i.assertionId],
      ['Subject recipient (ACS)', i.subject.recipient], ['Assertion issued', i.issueInstant ? when(i.issueInstant) : ''],
    ])),
    section('Assertion lifetime & conditions', kv([
      ['Conditions NotBefore', i.conditions.notBefore ? when(i.conditions.notBefore) : ''], ['Conditions NotOnOrAfter', i.conditions.notOnOrAfter ? when(i.conditions.notOnOrAfter) : '', 'assertion must be consumed before this'],
      ['SubjectConfirmation NotOnOrAfter', i.subject.notOnOrAfter ? when(i.subject.notOnOrAfter) : ''],
      ['SessionNotOnOrAfter', i.authn.sessionNotOnOrAfter ? when(i.authn.sessionNotOnOrAfter) : '(not sent by IdP)', 'IdP-requested session end'],
      ['Audience restriction', i.conditions.audiences.join('\n')],
    ])),
    section('SSO session (this application)', ck.html + kv([
      ['Honor SessionNotOnOrAfter', String(cfg.honorSessionNotOnOrAfter)], ['Effective session end', countdown(sessionEnds), 'earlier of cookie timeout and SessionNotOnOrAfter'],
      ['ACS POST fields received', s.postFields.join(', ')], ['RelayState', s.relayState],
    ]) + `<p class="note">This app keeps the assertion data server-side; the browser only holds the opaque signed session cookie. The IdP has its own SSO session cookie on its own domain – its lifetime is controlled at the IdP.</p>`),
    section('Raw SAML assertion (XML)', s.assertionXml ? code(pretty(s.assertionXml), { label: 'Assertion' }) : '<p class="muted">Assertion XML not available.</p>', { open: false }),
    section('Raw SAML response (XML, as received)', code(pretty(s.responseXml), { label: 'Response' }), { open: false, note: 'If the assertion was encrypted, only the encrypted form appears here; the decrypted assertion is above.' }),
    section('Profile as parsed by node-saml', json(s.libProfile), { open: false }),
    section('Application configuration', kv([
      ['Base URL', baseUrl], ['SP entity ID / audience', cfg.spEntityId, 'give this to the IdP'], ['ACS URL', cfg.acsUrl, 'give this to the IdP (HTTP-POST)'], ['SLO URL', cfg.sloCallbackUrl],
      ['SP metadata', raw(`<a href="/metadata">${esc(baseUrl)}/metadata</a>`)],
      ['IdP settings source', idp.source], ['IdP entity ID', idp.entityId], ['IdP SSO URL', idp.ssoUrl], ['IdP SLO URL', idp.sloUrl || '(none – local logout only)'],
      ['IdP signing cert fingerprint(s)', (idp.certs || []).map(fingerprint).join('\n')], ['AuthnRequest binding', cfg.binding], ['Requested NameID format', cfg.nameIdFormat || '(library default: unspecified)'],
      ['Require signed assertion / response', `${cfg.wantAssertionsSigned} / ${cfg.wantResponseSigned}`], ['Force re-authentication', String(cfg.forceAuthn)], ['RequestedAuthnContext disabled', String(cfg.disableAuthnContext)],
      ['Clock skew tolerated', `${cfg.clockSkewSeconds} s`], ['Audience check', cfg.audience === false ? 'disabled' : cfg.audience || 'SP entity ID'],
      ['SP private key', cfg.spKey ? mask(cfg.spKey) : '(none – requests unsigned, no assertion decryption)'], ['SP certificate fingerprint', cfg.spCert ? fingerprint(cfg.spCert) : ''],
      ['Session secret', scfg.secretGenerated ? 'randomly generated at start (sessions break on restart / with >1 replica)' : 'from SESSION_SECRET'],
    ]), { open: false }),
    section('Environment', env.summary + '<h3>Relevant environment variables</h3>' + env.vars + '<h3>This request</h3>' + requestInfo(req), { open: false }),
  ].join('');
  res.send(page({
    title: TITLE, protocol: PROTO, user: display, body,
    actions: `<form method="post" action="/logout"><button class="btn danger">Log out</button></form> <form method="post" action="/logout?local=1"><button class="btn sec" title="Only destroys the app session, leaves the IdP session alone">Local logout only</button></form>`,
  }));
});

app.post('/logout', async (req, res) => {
  const lg = req.session?.saml?.logout;
  await sessionP(req).destroy();
  res.clearCookie(scfg.cookieName, { path: '/' });
  if (req.query.local || !lg) return res.redirect('/logged-out');
  try {
    const s = await ensureIdp();
    if (!idp.sloUrl) return res.redirect('/logged-out?note=no_slo');
    res.redirect(await s.getLogoutUrlAsync(lg, '/logged-out', {}));
  } catch (e) { console.error('SLO start failed:', e.message); res.redirect('/logged-out?note=slo_failed'); }
});

// Single Logout endpoint: handles the IdP's LogoutResponse (SP-initiated) and LogoutRequest (IdP-initiated)
app.all(cfg.sloPath, express.urlencoded({ extended: false }), async (req, res) => {
  const params = req.method === 'POST' ? req.body : req.query;
  let result = 'received';
  try {
    const s = await ensureIdp();
    if (req.method === 'GET') {
      const rawQuery = req.originalUrl.split('?')[1] || '';
      const r = await s.validateRedirectAsync(req.query, rawQuery);
      result = r.loggedOut ? 'validated' : 'processed';
      if (params.SAMLRequest && r.profile) {
        await sessionP(req).destroy(); res.clearCookie(scfg.cookieName, { path: '/' });
        return res.redirect(await s.getLogoutResponseUrlAsync(r.profile, params.RelayState || '', {}, true));
      }
    } else if (params.SAMLResponse) { await s.validatePostResponseAsync(params); result = 'validated'; }
  } catch (e) { result = `not validated: ${e.message}`; }
  await sessionP(req).destroy().catch(() => {});
  res.clearCookie(scfg.cookieName, { path: '/' });
  res.redirect(`/logged-out?note=slo_${encodeURIComponent(/^validated|processed/.test(result) ? 'ok' : 'unverified')}`);
});

app.get('/logged-out', (req, res) => {
  const notes = { no_slo: 'The IdP has no single-logout endpoint configured, so only the application session was ended.', slo_failed: 'Could not start single logout at the IdP; only the application session was ended.', slo_ok: 'The IdP confirmed single logout.', slo_unverified: 'A logout message came back from the IdP but its signature could not be verified (IdP may not sign logout messages).' };
  res.send(page({ title: TITLE, protocol: PROTO, body: `<div class="card"><div class="inner"><h2>You have been logged out</h2><p>The application session has been destroyed.</p>${notes[req.query.note] ? `<p class="note">${esc(notes[req.query.note])}</p>` : ''}<p><a class="btn" href="/login">Log in again</a></p></div></div>` }));
});

app.get('/debug.json', needsLogin, (req, res) => res.json(req.session.saml));
app.get('/{*any}', (_req, res) => res.redirect('/'));

function setupHint() {
  return kv([
    ['SP entity ID', cfg.spEntityId], ['ACS URL (HTTP-POST)', cfg.acsUrl], ['SLO URL', cfg.sloCallbackUrl], ['SP metadata', raw(`<a href="/metadata">${esc(baseUrl)}/metadata</a>`)],
    ['Needed', 'SAML_IDP_METADATA_URL  — or —  SAML_IDP_SSO_URL + SAML_IDP_CERT'],
  ]);
}
app.use((err, _req, res, _next) => { console.error(err); res.status(500).send(errorPage(TITLE, PROTO, 'Unexpected error', err.message)); });

console.log(`${TITLE} starting. SP entity ID: ${cfg.spEntityId}  ACS: ${cfg.acsUrl}`);
listen();
if (cfg.metadataUrl || cfg.metadataFile || cfg.ssoUrl) ensureIdp().then(() => console.log('IdP configuration loaded from', idp.source)).catch((e) => console.warn('IdP config not ready (will retry on login):', e.message));
