// Shared helpers (identical copy lives in both apps). No framework, just HTML strings.
import os from 'node:os';
import fs from 'node:fs';
import crypto from 'node:crypto';

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Marks a string as already-safe HTML. */
export class Raw { constructor(h) { this.html = h; } }
export const raw = (h) => new Raw(h);
const cell = (v) => (v instanceof Raw ? v.html : v === undefined || v === null || v === '' ? '<span class="muted">—</span>' : esc(v));

export const envBool = (name, def) => {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  return /^(1|true|yes|on)$/i.test(v.trim());
};
export const envInt = (name, def) => {
  const n = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) ? n : def;
};

export const mask = (v) => (v ? `•••••••• (${String(v).length} chars)` : '');
export const fingerprint = (certOrPem) => {
  try {
    const b64 = String(certOrPem).replace(/-----[^-]+-----|\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    return crypto.createHash('sha256').update(der).digest('hex').match(/../g).join(':').toUpperCase();
  } catch { return ''; }
};

export const kv = (rows) =>
  `<table class="kv">${rows
    .filter((r) => r)
    .map(([k, v, hint]) => `<tr><th>${esc(k)}${hint ? `<small>${esc(hint)}</small>` : ''}</th><td>${cell(v)}</td></tr>`)
    .join('')}</table>`;

export const grid = (head, rows) =>
  `<table class="grid"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows
    .map((r) => `<tr>${r.map((c) => `<td>${cell(c)}</td>`).join('')}</tr>`)
    .join('')}</tbody></table>`;

let codeId = 0;
export const code = (text, { copy = true, label = '' } = {}) => {
  const id = `c${++codeId}`;
  return `<div class="codewrap">${label ? `<div class="codelabel">${esc(label)}</div>` : ''}${
    copy ? `<button type="button" class="copy" data-copy="${id}">Copy</button>` : ''
  }<pre id="${id}">${esc(text)}</pre></div>`;
};
export const json = (o, opts) => code(JSON.stringify(o, null, 2), opts);

export const section = (title, html, { open = true, note = '' } = {}) =>
  `<details class="card" ${open ? 'open' : ''}><summary>${esc(title)}</summary><div class="inner">${
    note ? `<p class="note">${note}</p>` : ''
  }${html}</div></details>`;

export const iso = (d) => (d ? new Date(d).toISOString() : '');
export const when = (d) =>
  d ? raw(`<time class="ts" datetime="${iso(d)}">${iso(d)}</time> <span class="rel" data-rel="${iso(d)}"></span>`) : '';
export const countdown = (d) => raw(`<strong class="cd" data-t="${iso(d)}">${iso(d)}</strong> <span class="muted">(${iso(d)})</span>`);

export const decodeJwt = (token) => {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return null;
  try {
    const dec = (p) => JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    return { header: dec(parts[0]), payload: dec(parts[1]), signature: parts[2] || '' };
  } catch { return null; }
};

export function environmentInfo() {
  const showEnv = /^(APP_|OIDC_|SAML_|SESSION_|COOKIE_|TLS_|BASE_URL$|PORT$|TRUST_PROXY$|NODE_|HOSTNAME$|HTTPS?_PROXY$|NO_PROXY$|TZ$)/i;
  const secret = /(SECRET|PASSWORD|PASSWD|TOKEN|PRIVATE|_KEY|CERT)/i;
  const vars = Object.keys(process.env)
    .filter((k) => showEnv.test(k))
    .sort()
    .map((k) => [k, secret.test(k) ? (process.env[k] ? `[set, ${process.env[k].length} chars — hidden]` : '') : process.env[k]]);
  let container = 'no';
  try { if (fs.existsSync('/.dockerenv')) container = 'yes (/.dockerenv)'; } catch {}
  try { if (/docker|kubepods|containerd/.test(fs.readFileSync('/proc/1/cgroup', 'utf8'))) container = 'yes (cgroup)'; } catch {}
  if (process.env.KUBERNETES_SERVICE_HOST) container = 'yes (Kubernetes)';
  const mem = process.memoryUsage();
  return {
    summary: kv([
      ['Hostname / pod', os.hostname()],
      ['Running in container', container],
      ['Node.js', process.version],
      ['Platform', `${os.platform()} ${os.arch()} (${os.release()})`],
      ['PID', String(process.pid)],
      ['Process uptime', `${Math.round(process.uptime())} s`],
      ['Memory (RSS)', `${(mem.rss / 1048576).toFixed(1)} MiB`],
      ['Server time (UTC)', new Date().toISOString()],
      ['Server timezone', Intl.DateTimeFormat().resolvedOptions().timeZone],
      ['App version / image', process.env.APP_VERSION || process.env.IMAGE_TAG || ''],
    ]),
    vars: kv(vars.length ? vars : [['(none)', '']]),
  };
}

export function requestInfo(req) {
  const h = req.headers;
  const fwd = Object.entries(h).filter(([k]) => /^(x-forwarded-|forwarded|x-real-ip|via|x-envoy|x-request-id)/i.test(k));
  return kv([
    ['Request URL as seen by app', `${req.protocol}://${req.get('host')}${req.originalUrl}`],
    ['Protocol (after trust proxy)', req.protocol],
    ['Client IP', req.ip],
    ['Socket remote address', req.socket?.remoteAddress],
    ['User-Agent', h['user-agent']],
    ['Cookies received (names only)', Object.keys(parseCookies(h.cookie)).join(', ')],
    ...fwd.map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v]),
  ]);
}

export function parseCookies(header = '') {
  const out = {};
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function sessionCookieInfo(req, scfg) {
  const c = req.session.cookie;
  const cj = c.toJSON();
  const now = Date.now();
  const expires = scfg.rolling ? new Date(now + scfg.timeoutSeconds * 1000) : c.expires;
  const rawCookie = parseCookies(req.headers.cookie)[scfg.cookieName];
  return {
    expires,
    html: kv([
      ['Cookie name', scfg.cookieName],
      ['Session ID (server side)', req.sessionID],
      ['Cookie value as sent by browser', rawCookie ? decodeURIComponent(rawCookie) : '', 's:<sessionId>.<HMAC signature>'],
      ['Path', cj.path],
      ['HttpOnly', String(cj.httpOnly)],
      ['Secure', String(!!cj.secure)],
      ['SameSite', String(cj.sameSite)],
      ['Domain', cj.domain || '(host-only)'],
      ['Max-Age', `${scfg.timeoutSeconds} s`],
      ['Timeout type', scfg.rolling ? 'Idle / sliding (reset on every request)' : 'Absolute (fixed from login)'],
      ['Session created', when(req.session.createdAt)],
      ['Last request', when(now)],
      ['App session expires', countdown(expires), scfg.rolling ? 'if no further requests are made' : ''],
      ['Session store', 'In-memory (lost when container restarts)'],
    ]),
  };
}

const CSS = `
:root{--bg:#f5f6f8;--fg:#1c2330;--muted:#6b7686;--card:#fff;--line:#e1e5eb;--accent:#0b5fff;--accent2:#e8f0ff;--code:#0f1623;--codefg:#d6e2ff;--ok:#0a7d3b;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#10141b;--fg:#e6eaf2;--muted:#93a0b3;--card:#171d27;--line:#273041;--accent:#6ea0ff;--accent2:#1d2a44;--code:#0a0e15;--codefg:#c9d8ff;--ok:#5fd08b;--bad:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 24px;display:flex;gap:16px;align-items:center;flex-wrap:wrap;position:sticky;top:0;z-index:5}
header h1{font-size:18px;margin:0}header .sp{flex:1}
.badge{background:var(--accent2);color:var(--accent);padding:2px 10px;border-radius:99px;font-weight:600;font-size:12px}
main{max-width:1100px;margin:20px auto;padding:0 16px 60px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:14px 0}
.card>summary{cursor:pointer;padding:12px 16px;font-weight:600;font-size:15px}
.inner{padding:2px 16px 16px;overflow-x:auto}.note{color:var(--muted);margin:0 0 10px}
table{border-collapse:collapse;width:100%}table.kv th{text-align:left;vertical-align:top;width:260px;padding:6px 12px 6px 0;color:var(--muted);font-weight:500}
table.kv th small{display:block;font-size:11px;opacity:.8}table.kv td{padding:6px 0;word-break:break-word;border-bottom:1px solid var(--line)}
table.kv tr:last-child td{border-bottom:0}
table.grid th,table.grid td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}table.grid th{color:var(--muted);font-weight:600}
.muted{color:var(--muted)}.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
.codewrap{position:relative;margin:8px 0}.codelabel{font-size:12px;color:var(--muted);margin-bottom:2px}
pre{background:var(--code);color:var(--codefg);padding:12px;border-radius:8px;overflow:auto;max-height:420px;margin:0;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.copy{position:absolute;right:8px;top:8px;font-size:11px;padding:2px 8px;border-radius:5px;border:1px solid #445;background:#223;color:#cde;cursor:pointer;z-index:1}
.btn,button.btn{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 16px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none}
.btn.sec{background:transparent;color:var(--accent);border:1px solid var(--accent)}.btn.danger{background:var(--bad)}
form{display:inline}.actions{display:flex;gap:8px;flex-wrap:wrap}
h3{margin:18px 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.hero{display:flex;gap:16px;align-items:center}.avatar{width:48px;height:48px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:20px}
.err{border-left:4px solid var(--bad);padding:8px 14px;background:var(--card);border-radius:6px}
code{font:12px ui-monospace,Menlo,Consolas,monospace;background:var(--accent2);padding:1px 5px;border-radius:4px}
`;

const JS = `
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',()=>{const t=document.getElementById(b.dataset.copy).innerText;(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>{b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)}).catch(()=>{const r=document.createRange();r.selectNodeContents(document.getElementById(b.dataset.copy));getSelection().removeAllRanges();getSelection().addRange(r)})}));
const fmt=s=>{const neg=s<0;s=Math.abs(Math.round(s));const h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;return (neg?'expired ':'')+(h?h+'h ':'')+(m||h?m+'m ':'')+x+'s'+(neg?' ago':'')};
function tick(){const n=Date.now();document.querySelectorAll('.cd').forEach(e=>{const d=(new Date(e.dataset.t)-n)/1000;e.textContent=d>=0?fmt(d)+' remaining':fmt(d);e.className='cd '+(d>=0?'ok':'bad')});
document.querySelectorAll('.rel').forEach(e=>{const d=(new Date(e.dataset.rel)-n)/1000;e.textContent=Math.abs(d)<5?'(just now)':'('+(d>=0?'in '+fmt(d):fmt(d))+')'});}
document.querySelectorAll('time.ts').forEach(e=>{e.title='UTC: '+e.getAttribute('datetime');e.textContent=new Date(e.getAttribute('datetime')).toLocaleString()+' local'});
tick();setInterval(tick,1000);
`;

export const page = ({ title, protocol, user, body, actions = '' }) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>
<header><h1>${esc(title)}</h1><span class="badge">${esc(protocol)}</span><span class="sp"></span>
${user ? `<span class="muted">Signed in as <strong>${esc(user)}</strong></span>` : ''}${actions}</header>
<main>${body}</main><script>${JS}</script></body></html>`;

export const errorPage = (title, protocol, heading, detail, extra = '') =>
  page({ title, protocol, body: `<div class="card"><div class="inner"><h2>${esc(heading)}</h2><div class="err">${esc(detail)}</div>${extra}<p><a class="btn" href="/login">Try again</a></p></div></div>` });
