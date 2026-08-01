/**
 * netip-edge — the serverless backend for whatismynetip.com
 *
 * One Cloudflare Worker, three jobs (all sharing KV + the CF DNS API):
 *   1. IP API        GET  /ip            -> caller's public IP (text/plain)
 *                    GET  /json          -> full JSON (ip, asn, country from CF)
 *   2. Dynamic DNS   POST /register      -> claim <host>.whatismynetip.com, get an update token
 *                    GET  /nic/update    -> dyndns2 protocol (routers speak this natively)
 *                    GET  /update        -> simple ?hostname=&token=[&myip=] variant
 *   3. Short links   POST /shorten       -> make a short link to a URL or IP:port
 *                    GET  /<slug>        -> 302 redirect  (served on s.whatismynetip.com)
 *
 * Bindings (see wrangler.toml):
 *   KV            Workers KV — keys "ddns:<host>" and "link:<slug>"
 *   CF_API_TOKEN  secret — Cloudflare token with DNS:Edit on the zone
 *   TURNSTILE_SECRET secret — Turnstile siteverify key (anti-bot on /register + /shorten)
 *   MAILER_KEY    secret — shared key for the probe backend's /send-ddns-token mail relay
 *   CF_ZONE_ID    var    — zone id for whatismynetip.com
 *   ZONE_NAME     var    — "whatismynetip.com"
 */

const SITE_ORIGIN = 'https://whatismynetip.com';
const CORS = {
  'Access-Control-Allow-Origin': SITE_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Site-only gate for the tools that exist to serve the page rather than as a public endpoint.
// A browser always sends Origin on a cross-origin POST; curl sends neither header unless told
// to. Soft by design: it stops drive-by scraping, not someone who copies one header. CORS
// alone would do nothing here — browsers enforce it, command-line clients ignore it outright.
function fromSite(req) {
  const o = req.headers.get('Origin');
  if (o) return o === SITE_ORIGIN;
  const r = req.headers.get('Referer') || '';
  return r.startsWith(SITE_ORIGIN + '/');
}
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
const text = (body, status = 200) =>
  new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS } });

const HOST_RE = /^[a-z0-9][a-z0-9-]{1,30}$/;      // 2–31 chars, DDNS label
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;      // 2–32 chars, short-link slug
const RESERVED = new Set(['www', 'api', 's', 'ns', 'mail', 'admin', 'root', 'whatismynetip', 'ftp']);

function clientIp(req) { return req.headers.get('CF-Connecting-IP') || ''; }
function randHex(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function sha256(s) { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join(''); }
function randSlug() { const c = 'abcdefghijkmnpqrstuvwxyz23456789'; const b = new Uint8Array(6); crypto.getRandomValues(b); return [...b].map(x => c[x % c.length]).join(''); }

// Anti-bot: verify a Turnstile token (from the page widget) with siteverify. Fails open only
// if the secret isn't configured, so a missing secret can't brick the API.
async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
      signal: AbortSignal.timeout(5000),
    });
    return !!(await r.json()).success;
  } catch { return false; }
}

// Best-effort per-IP rate limit on KV (eventually consistent — a backstop, not a wall;
// Turnstile is the primary gate). Counter expires with the window.
async function rateLimit(env, bucket, ip, limit, windowSecs) {
  const key = `rl:${bucket}:${ip}`;
  const cur = parseInt((await env.KV.get(key)) || '0', 10);
  if (cur >= limit) return false;
  await env.KV.put(key, String(cur + 1), { expirationTtl: windowSecs });
  return true;
}

async function cf(env, method, path, body) {
  const r = await fetch('https://api.cloudflare.com/client/v4' + path, {
    method,
    headers: { Authorization: `Bearer ${env.CF_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return r.json();
}

// Reverse DNS (PTR) via Cloudflare's OWN resolver (1.1.1.1 DoH) — keeps the whole lookup on
// Cloudflare, no third party. IPv4 only for now (v6 ip6.arpa nibble form is a later add).
async function reversePtr(ip) {
  try {
    if (!ip || ip.includes(':')) return null;
    const rev = ip.split('.').reverse().join('.') + '.in-addr.arpa';
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${rev}&type=PTR`,
      { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(3000) });
    const d = await r.json();
    if (d.Answer && d.Answer.length) return d.Answer[d.Answer.length - 1].data.replace(/\.$/, '');
  } catch { /* no PTR / timeout */ }
  return null;
}

// VPN/datacenter hint from the AS org name — a free heuristic. Hosting/cloud/VPN ASNs are very
// likely proxy/VPN exit nodes; residential ISPs are not. Not authoritative; the UI labels it a hint.
const HOSTING_RE = /(hosting|datacen|data.?cent|colo|cloud|\bvps\b|dedicated|ovh|hetzner|digitalocean|linode|vultr|amazon|aws|google llc|azure|microsoft|oracle|leaseweb|choopa|m247|contabo|scaleway|equinix|quadranet|psychz|zenlayer|gcore|\bvpn\b|proxy|\btor\b)/i;
function hostingHint(org) { return HOSTING_RE.test(org || ''); }

// Blacklist / DNSBL check via DoH. NOTE: big lists (Spamhaus, Barracuda) refuse queries from public
// resolvers — we detect the 127.255.255.x sentinel and mark those "n/a" instead of a false "clean".
// A definitive check needs the probe backend querying via a direct resolver (roadmap).
const DNSBLS = ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net', 'b.barracudacentral.org', 'all.s5h.net'];
async function rblCheck(ip) {
  if (!ip || ip.includes(':')) return json({ ip, supported: false, note: 'IPv4 only' });
  const rev = ip.split('.').reverse().join('.');
  const results = await Promise.all(DNSBLS.map(async (bl) => {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${rev}.${bl}&type=A`,
        { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) });
      const ans = ((await r.json()).Answer || []).map((a) => a.data);
      if (ans.some((a) => a.startsWith('127.255.255.'))) return { bl, status: 'n/a' };
      if (ans.length) return { bl, status: 'listed', codes: ans };
      return { bl, status: 'clean' };
    } catch { return { bl, status: 'n/a' }; }
  }));
  const listed = results.filter((r) => r.status === 'listed');
  return json({ ip, listed_count: listed.length, listed: listed.map((r) => r.bl), results });
}

/* ---- Dynamic DNS ---- */
async function register(req, env) {
  let body; try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const rlIp = clientIp(req);
  if (!(await rateLimit(env, 'reg', rlIp, 5, 3600))) return json({ error: 'Too many registrations from your IP — try again in an hour.' }, 429);
  if (!(await verifyTurnstile(env, body.turnstile, rlIp))) return json({ error: 'Bot check failed — reload the page and try again.' }, 403);
  const host = String(body.hostname || '').trim().toLowerCase();
  const email = String(body.email || '').trim();
  if (!HOST_RE.test(host) || RESERVED.has(host)) return json({ error: 'Choose a hostname of 2–31 letters, numbers or hyphens.' }, 400);
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) return json({ error: 'A valid email is required.' }, 400);
  if (await env.KV.get('ddns:' + host)) return json({ error: `${host}.${env.ZONE_NAME} is already taken.` }, 409);

  const ip = clientIp(req);
  const fqdn = `${host}.${env.ZONE_NAME}`;
  const rec = await cf(env, 'POST', `/zones/${env.CF_ZONE_ID}/dns_records`,
    { type: 'A', name: fqdn, content: ip || '0.0.0.0', proxied: false, ttl: 60, comment: 'DDNS: ' + email });
  if (!rec.success) return json({ error: 'Could not create the DNS record.', detail: rec.errors }, 502);

  const token = randHex(24);
  await env.KV.put('ddns:' + host, JSON.stringify({
    recId: rec.result.id, tokenHash: await sha256(token), email, ip, created: Date.now(),
  }));

  // Email the token (only copy — proves the address is real). If the mail can't be sent the
  // user would own an unusable hostname, so roll the registration back and let them retry.
  let mailed = false;
  try {
    const r = await fetch('https://probe.whatismynetip.com/send-ddns-token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Mailer-Key': env.MAILER_KEY || '',
        'User-Agent': 'netip-edge-worker',   // some WAFs drop UA-less requests
      },
      body: JSON.stringify({ email, hostname: fqdn, token, ip }),
      signal: AbortSignal.timeout(20000),
    });
    mailed = r.ok;
  } catch { /* mailed stays false */ }
  if (!mailed) {
    await cf(env, 'DELETE', `/zones/${env.CF_ZONE_ID}/dns_records/${rec.result.id}`);
    await env.KV.delete('ddns:' + host);
    return json({ error: 'Could not email your token — nothing was registered. Please try again shortly.' }, 502);
  }
  return json({ hostname: fqdn, ip, emailed: true, update_url: `https://api.${env.ZONE_NAME}/nic/update` });
}

async function doUpdate(env, host, token, wantIp, req) {
  const raw = await env.KV.get('ddns:' + host);
  if (!raw) return { code: 'nohost', status: 404 };
  const e = JSON.parse(raw);
  if (await sha256(token) !== e.tokenHash) return { code: 'badauth', status: 401 };
  const ip = (wantIp && /^[0-9.]+$|:/.test(wantIp)) ? wantIp : clientIp(req);
  if (ip === e.ip) {
    // still refresh the liveness stamp — routers send periodic nochg updates, and the
    // expiry sweep must not reap a host whose IP simply never changed.
    e.updated = Date.now();
    await env.KV.put('ddns:' + host, JSON.stringify(e));
    return { code: 'nochg ' + ip, status: 200, ip };
  }
  const upd = await cf(env, 'PATCH', `/zones/${env.CF_ZONE_ID}/dns_records/${e.recId}`, { content: ip });
  if (!upd.success) return { code: 'dnserr', status: 502 };
  e.ip = ip; e.updated = Date.now();
  await env.KV.put('ddns:' + host, JSON.stringify(e));
  return { code: 'good ' + ip, status: 200, ip };
}

// dyndns2: GET /nic/update?hostname=&myip=  with HTTP Basic auth (user:token)
async function nicUpdate(req, env, url) {
  const auth = req.headers.get('Authorization') || '';
  let token = '';
  if (auth.startsWith('Basic ')) { try { token = atob(auth.slice(6)).split(':')[1] || ''; } catch {} }
  const host = (url.searchParams.get('hostname') || '').replace('.' + env.ZONE_NAME, '').toLowerCase();
  if (!host) return text('notfqdn', 400);
  if (!token) return text('badauth', 401);
  const r = await doUpdate(env, host, token, url.searchParams.get('myip'), req);
  return text(r.code, r.status);
}

// simple: GET /update?hostname=&token=&myip=
async function simpleUpdate(req, env, url) {
  const host = (url.searchParams.get('hostname') || '').replace('.' + env.ZONE_NAME, '').toLowerCase();
  const token = url.searchParams.get('token') || '';
  if (!host || !token) return json({ error: 'hostname and token required' }, 400);
  const r = await doUpdate(env, host, token, url.searchParams.get('myip'), req);
  return json({ status: r.code, ip: r.ip || null }, r.status);
}

/* ---- Expiry sweep (daily cron): reap DDNS hosts silent for 90+ days ---- */
const DDNS_MAX_IDLE_MS = 90 * 86400 * 1000;
async function sweepDdns(env) {
  let cursor, reaped = 0;
  do {
    const page = await env.KV.list({ prefix: 'ddns:', cursor });
    for (const k of page.keys) {
      const raw = await env.KV.get(k.name);
      if (!raw) continue;
      const e = JSON.parse(raw);
      if (Date.now() - (e.updated || e.created || 0) <= DDNS_MAX_IDLE_MS) continue;
      // DNS record first — if that fails, keep the KV entry so the next run retries.
      if (e.recId) {
        const del = await cf(env, 'DELETE', `/zones/${env.CF_ZONE_ID}/dns_records/${e.recId}`);
        if (!del.success && !(del.errors || []).some((x) => x.code === 81044)) continue; // 81044 = already gone
      }
      await env.KV.delete(k.name);
      reaped++;
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  console.log(`ddns sweep: reaped ${reaped} stale host(s)`);
}

/* ---- Short-link abuse filter ---- */
// Domain reputation via Cloudflare's security resolver (1.1.1.2): known malware/phishing
// domains resolve to 0.0.0.0. Domain-level only; fails OPEN on resolver trouble so an
// outage can't break link creation.
async function domainFlagged(host) {
  try {
    const r = await fetch(`https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(4000) });
    return ((await r.json()).Answer || []).some((a) => a.data === '0.0.0.0');
  } catch { return false; }
}
function isIpHost(h) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.startsWith('['); }

// Re-check a link's target on the redirect path (URLs often turn malicious AFTER creation).
// Runs via ctx.waitUntil — never delays the visitor. Rewrites KV preserving the 1-year TTL.
const LINK_RECHECK_MS = 86400000; // 24h
const LINK_TTL_MS = 31536000000;  // 1 year (matches creation expirationTtl)
async function recheckLink(env, slug, e) {
  let host = null;
  try { host = new URL(e.target).hostname.toLowerCase(); } catch { /* leave null */ }
  if (host && !isIpHost(host) && await domainFlagged(host)) { e.disabled = true; e.flaggedAt = Date.now(); }
  e.checked = Date.now();
  const remain = Math.max(60, Math.floor(((e.created || Date.now()) + LINK_TTL_MS - Date.now()) / 1000));
  await env.KV.put('link:' + slug, JSON.stringify(e), { expirationTtl: remain });
}

/* ---- Short links ---- */
function normalizeTarget(t) {
  t = String(t || '').trim();
  if (!t) return null;
  if (/^https?:\/\//i.test(t)) return t;                              // full URL
  if (/^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(t)) return 'https://' + t; // bare domain
  if (/^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?(\/.*)?$/.test(t)) return 'http://' + t; // IPv4[:port]
  if (/^\[?[0-9a-f:]+\]?(:\d{1,5})?$/i.test(t)) return 'http://' + t;   // IPv6
  return null;
}
async function shorten(req, env) {
  let body; try { body = await req.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
  const rlIp = clientIp(req);
  if (!(await rateLimit(env, 'sh', rlIp, 15, 3600))) return json({ error: 'Too many short links from your IP — try again in an hour.' }, 429);
  if (!(await verifyTurnstile(env, body.turnstile, rlIp))) return json({ error: 'Bot check failed — reload the page and try again.' }, 403);
  const target = normalizeTarget(body.target);
  if (!target) return json({ error: 'Enter a valid URL or IP:port.' }, 400);
  let u; try { u = new URL(target); } catch { return json({ error: 'Enter a valid URL or IP:port.' }, 400); }
  const thost = u.hostname.toLowerCase();
  if (u.username || u.password) return json({ error: 'URLs with embedded credentials are not allowed.' }, 400);
  if (thost === `s.${env.ZONE_NAME}` || thost === `api.${env.ZONE_NAME}`) return json({ error: 'Cannot shorten a short link.' }, 400);
  if (!isIpHost(thost) && await domainFlagged(thost)) return json({ error: 'That destination is flagged as malicious/phishing — refusing to shorten it.' }, 400);
  let slug = String(body.slug || '').trim().toLowerCase();
  if (slug) {
    if (!SLUG_RE.test(slug) || RESERVED.has(slug)) return json({ error: 'Slug: 2–32 letters, numbers or hyphens.' }, 400);
    if (await env.KV.get('link:' + slug)) return json({ error: `/${slug} is taken — pick another.` }, 409);
  } else {
    for (let i = 0; i < 5; i++) { slug = randSlug(); if (!(await env.KV.get('link:' + slug))) break; }
  }
  // Ownership without accounts: a one-time manage token (only its hash is stored) lets the
  // creator delete the link. Links auto-expire after 1 year via KV TTL — no sweep needed.
  const manage = randHex(12);
  await env.KV.put('link:' + slug,
    JSON.stringify({ target, created: Date.now(), manageHash: await sha256(manage), checked: Date.now() }),
    { expirationTtl: 31536000 });
  return json({ slug, target, short_url: `https://s.${env.ZONE_NAME}/${slug}`, manage_token: manage, expires_days: 365 });
}
async function deleteLink(req, env, slug, url) {
  const token = url.searchParams.get('token') || (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const raw = await env.KV.get('link:' + slug);
  if (!raw) return json({ error: 'No such link.' }, 404);
  const e = JSON.parse(raw);
  if (!token || !e.manageHash || await sha256(token) !== e.manageHash) return json({ error: 'Bad or missing delete token.' }, 403);
  await env.KV.delete('link:' + slug);
  return json({ deleted: slug });
}
async function redirect(env, slug, ctx) {
  const raw = await env.KV.get('link:' + slug);
  if (!raw) return text('Short link not found.', 404);
  const e = JSON.parse(raw);
  if (e.disabled) return text('This short link was disabled — its destination was flagged as unsafe.', 410);
  if (ctx && Date.now() - (e.checked || 0) > LINK_RECHECK_MS) ctx.waitUntil(recheckLink(env, slug, e));
  return new Response(null, { status: 302, headers: { Location: e.target, 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    // short-link redirect: s.whatismynetip.com/<slug>  OR  <any-host>/s/<slug>
    let slug = null;
    if (url.hostname.startsWith('s.')) slug = path.slice(1);
    else if (path.startsWith('/s/')) slug = path.slice(3);
    if (slug !== null) {
      if (!slug || slug === 'favicon.ico') return text('whatismynetip.com short links', 200);
      return redirect(env, slug, ctx);
    }

    // api.whatismynetip.com/...
    if (path === '/ip') return text(clientIp(req));
    if (path === '/json') {
      const cf = req.cf || {};
      const ip = clientIp(req);
      return json({
        ip,
        version: ip.includes(':') ? 6 : 4,
        reverse_dns: await reversePtr(ip),
        city: cf.city || null,
        region: cf.region || null,
        country: cf.country || null,
        postal: cf.postalCode || null,
        continent: cf.continent || null,
        latitude: cf.latitude || null,
        longitude: cf.longitude || null,
        timezone: cf.timezone || null,
        asn: cf.asn || null,
        as_org: cf.asOrganization || null,
        is_hosting: hostingHint(cf.asOrganization),
        connection_type: hostingHint(cf.asOrganization) ? 'datacenter / hosting' : 'ISP / residential',
        colo: cf.colo || null,   // the Cloudflare datacenter that served the request
      });
    }
    // Site tool, not a public endpoint: POST from the page only, and never for an arbitrary IP.
    if (path === '/rbl') {
      if (req.method !== 'POST' || !fromSite(req)) return text('Not found', 404);
      return rblCheck(clientIp(req));
    }
    if (path === '/headers') return json({
      your_ip: clientIp(req),                       // == the CF-Connecting-IP header value
      note: 'These are the headers Cloudflare handed this Worker. The client cannot forge CF-Connecting-IP — CF overwrites it.',
      headers: Object.fromEntries([...req.headers].sort()),
    });
    if (path === '/register' && req.method === 'POST') return register(req, env);
    if (path === '/nic/update') return nicUpdate(req, env, url);
    if (path === '/update') return simpleUpdate(req, env, url);
    if (path === '/shorten' && req.method === 'POST') return shorten(req, env);
    if (path.startsWith('/shorten/') && req.method === 'DELETE') return deleteLink(req, env, path.slice(9).toLowerCase(), url);
    // No service banner and no endpoint list on '/': finding the hostname should not hand
    // anyone a menu. Falls through to the same 404 every unknown path gets.
    return text('Not found', 404);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(sweepDdns(env));
  },
};
