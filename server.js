// ============================================================
// JSSM Portal - Admin Login Server (Node.js + Express)
// Password sirf yahan server par rehta hai, website ke code me NAHI.
// ============================================================
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '100kb' }));

// ---- CORS (agar website aur server alag-alag host ho tab kaam aayega) ----
app.use('/api', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---- Config: Render dashboard me Environment Variables me set karein ----
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Jssm@2026#Adm!X9k';
const SECRET = process.env.SESSION_SECRET || 'jssm-change-this-secret-in-production';
const PORT = process.env.PORT || 3000;

// ---- Token helpers (HMAC-signed, 12 ghante valid) ----
function makeToken(user) {
  const exp = Date.now() + 12 * 3600 * 1000;
  const payload = user + '.' + exp;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
  return Buffer.from(payload + '.' + sig).toString('base64url');
}
function checkToken(tok) {
  try {
    const raw = Buffer.from(String(tok || ''), 'base64url').toString('utf8');
    const parts = raw.split('.');
    if (parts.length !== 3) return null;
    const user = parts[0], exp = parts[1], sig = parts[2];
    if (!user || !exp || !sig) return null;
    if (Date.now() > parseInt(exp, 10)) return null; // expired
    const expect = crypto.createHmac('sha256', SECRET).update(user + '.' + exp).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
    return user;
  } catch (e) { return null; }
}

// ---- Brute-force protection: 1 min me max 10 koshish per IP ----
const attempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'x';
  const now = Date.now();
  let rec = attempts.get(ip) || { n: 0, t: now };
  if (now - rec.t > 60000) { rec = { n: 0, t: now }; }
  rec.n++;
  attempts.set(ip, rec);
  if (rec.n > 10) return res.status(429).json({ ok: false, msg: 'Bahut zyada koshish - 1 minute ruko' });
  next();
}

// ---- API: POST /api/login ----
app.post('/api/login', rateLimit, (req, res) => {
  const b = req.body || {};
  const user = b.user, pass = b.pass;
  if (typeof user !== 'string' || typeof pass !== 'string') {
    return res.status(400).json({ ok: false, msg: 'Invalid request' });
  }
  // timing-safe compare (password kabhi client ko nahi bheja jata)
  let uOk = false, pOk = false;
  try {
    uOk = user.length === ADMIN_USER.length &&
      crypto.timingSafeEqual(Buffer.from(user), Buffer.from(ADMIN_USER));
    pOk = pass.length === ADMIN_PASS.length &&
      crypto.timingSafeEqual(Buffer.from(pass), Buffer.from(ADMIN_PASS));
  } catch (e) { uOk = false; pOk = false; }

  if (uOk && pOk) {
    attempts.delete(req.ip);
    return res.json({ ok: true, token: makeToken(ADMIN_USER) });
  }
  setTimeout(() => res.status(401).json({ ok: false, msg: 'Galat username ya password' }), 600);
});

// ---- API: GET /api/verify (token check) ----
app.get('/api/verify', (req, res) => {
  const tok = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const user = checkToken(tok);
  res.json({ ok: !!user, user: user || null });
});

// ---- API: GET /api/health ----
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ---- Static website serve karo (root me index.html) ----
// Sirf index.html serve hota hai, server.js/package.json kabhi expose nahi hote
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log('JSSM server running on port ' + PORT));
