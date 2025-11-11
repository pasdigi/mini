// NOTE: Deploy this file to functions/api/[[path]].js in your Cloudflare Pages project.
//
// This version is tolerant to different incoming path mappings and explicitly
// registers the login route under several common permutations so that
// POST /api/login will definitely match even if the platform routing
// adds/strips an `/api` prefix unpredictably.
//
// It also includes request logging so you can inspect the exact pathname
// that the function receives in your Pages logs.

import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { handle } from 'hono/cloudflare-pages';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

/*
* Bindings:
* DB, JWT_SECRET, PASPAY_API_KEY, PASPAY_API_URL, PASPAY_WEBHOOK_TOKEN, PASPAY_PROJECT_ID
*/

// --- Simple crypto helpers (for password verification in DB) ---
const bufferToHex = (buffer) => [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2,'0')).join('');
const hexToBuffer = (hex) => {
  const bytes = new Uint8Array(hex.length/2);
  for (let i=0;i<hex.length;i+=2) bytes[i/2] = parseInt(hex.substr(i,2),16);
  return bytes.buffer;
};
const verifyPassword = async (password, storedHash) => {
  try {
    const [saltHex, hashHex] = (storedHash || '').split(':');
    if (!saltHex || !hashHex) return false;
    const salt = hexToBuffer(saltHex);
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    return bufferToHex(derivedBits) === hashHex;
  } catch (e) {
    console.error('verifyPassword error', e && e.message);
    return false;
  }
};

// --- Zod schemas (kept small for demo) ---
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

// --- App init ---
// IMPORTANT: do NOT call basePath('/api') here if this file is placed under functions/api/[[path]].js
// Cloudflare Pages already routes /api/* to this file. We'll register routes in a tolerant way.
const app = new Hono();

// --- Debug logging middleware ---
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname, 'host=', u.host);
    } catch (e) { /* ignore */ }
  } catch (e) {
    console.log('[INCOMING] failed to inspect request url', e && e.message);
  }
  await next();
});

// --- Helper: robust JSON parsing for responses ---
async function parseJsonResponse(res) {
  const txt = await res.text();
  try {
    return { ok: res.ok, status: res.status, json: JSON.parse(txt), raw: txt };
  } catch (e) {
    return { ok: res.ok, status: res.status, json: null, raw: txt };
  }
}

// --- LOGIN handler (single implementation, registered for multiple paths) ---
async function loginHandler(c) {
  /** @type {Bindings} */
  const env = c.env;
  // validate payload
  let body;
  try {
    body = await c.req.json();
  } catch (e) {
    return c.json({ error: 'Invalid JSON' }, 400);
  }
  try {
    loginSchema.parse(body);
  } catch (zerr) {
    return c.json({ error: 'Invalid payload', detail: zerr.errors }, 422);
  }

  const user = await env.DB.prepare("SELECT id, password_hash, role, status FROM users WHERE email = ?").bind(body.email).first();
  if (!user) return c.json({ error: 'Email atau password salah' }, 401);

  const ok = await verifyPassword(body.password, user.password_hash);
  if (!ok) return c.json({ error: 'Email atau password salah' }, 401);
  if (user.status !== 'active') return c.json({ error: 'Akun tidak aktif' }, 403);

  const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now()/1000) + (60*60*24) };
  const token = await sign(payload, env.JWT_SECRET, 'HS256');

  // Determine secure flag: Pages is https in production (pages.dev), so secure should be true.
  // If you're testing on http://localhost, set NODE_ENV=development in your env to make secure=false.
  const isDev = (typeof process !== 'undefined' && process.env.NODE_ENV === 'development');
  // If the request host contains "localhost" you can also set isDev accordingly
  try {
    const host = c.req.headers.get('host') || '';
    if (host.includes('localhost')) {
      // override for local preview
      // eslint-disable-next-line no-nested-ternary
      // intentionally keep secure false for local
      // (but in production on pages.dev secure=true is correct)
    }
  } catch (_) {}

  // SameSite: Lax is fine for same-origin pages. If your UI is on a different origin and you need cross-site cookie,
  // use SameSite: 'None' and secure: true (and ensure HTTPS).
  setCookie(c, 'auth_token', token, {
    path: '/',
    httpOnly: true,
    secure: !isDev, // secure=false in development
    sameSite: 'Lax',
    maxAge: 60*60*24
  });

  // Also return token in JSON as a fallback (useful for debugging or for clients that don't use cookies)
  return c.json({ success: true, message: 'Login berhasil', token });
}

// --- Register login route in several common permutations ---
// This ensures that if the Pages platform routes /api/* to this function, and/or if
// the frontend calls /api/login or /login (or even /api/api/login), one of these will match.
app.post('/login', loginHandler);
app.post('/api/login', loginHandler);
app.post('/api/api/login', loginHandler); // defensive fallback

// --- Example public routes (lightweight) ---
// You can keep all your other routes here (store, products, admin, etc).
// For brevity, include a simple health route and a sample GET store products route:

app.get('/health', (c) => c.json({ ok: true }));

app.get('/store/products', async (c) => {
  const env = c.env;
  try {
    const { results } = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.image_url, c.name as category_name
       FROM products p
       LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.is_active = 1`
    ).all();
    return c.json(results || []);
  } catch (e) {
    console.error('store/products error', e && e.message);
    return c.json({ error: 'Gagal mengambil data produk: ' + e.message }, 500);
  }
});

// --- Admin router registration (if you have the full admin routes, mount them) ---
// If you already have adminRouter defined elsewhere in this file, ensure you mount it:
// app.route('/admin', adminRouter); app.route('/api/admin', adminRouter);

// --- Fallback: helpful logging for unmatched routes ---
app.all('*', (c) => {
  try {
    console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[NO MATCH.pathname]', u.pathname);
    } catch (e) { /* ignore */ }
  } catch (e) {
    console.log('[NO MATCH] logging failed', e && e.message);
  }
  return c.json({ error: 'Not Found' }, 404);
});

// --- Export handler ---
export const onRequest = handle(app);
