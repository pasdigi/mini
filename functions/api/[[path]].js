/**
 * functions/api/[[path]].js
 * Minimal, robust Hono app that ensures JSON responses and OPTIONS/CORS handling.
 * Place exactly at functions/api/[[path]].js and redeploy.
 *
 * Requirements:
 * - D1 binding named DB
 * - JWT_SECRET env var
 *
 * NOTE: keep this file atomic and minimal to avoid build issues.
 */

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';

const app = new Hono();

// --- Helpers ---
function normalizeAllResult(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  return [];
}
function slugify(s = '') {
  return String(s).trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-_]/g, '').replace(/-+/g, '-').replace(/^-|-$/g, '');
}
async function verifyPassword(password, storedHash) {
  try {
    if (!storedHash || !password) return false;
    if (!storedHash.includes(':')) return password === storedHash; // fallback
    const [saltHex, hashHex] = storedHash.split(':');
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(h => parseInt(h,16))).buffer;
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' }, keyMaterial, 256);
    const derivedHex = [...new Uint8Array(derivedBits)].map(b => b.toString(16).padStart(2,'0')).join('');
    return derivedHex === hashHex;
  } catch (e) {
    console.error('verifyPassword error', e && e.message);
    return false;
  }
}
async function tableHasColumn(db, tableName, columnName) {
  try {
    const raw = await db.prepare(`PRAGMA table_info('${tableName}')`).all();
    const rows = normalizeAllResult(raw);
    return rows.some(r => (r.name || '').toLowerCase() === columnName.toLowerCase());
  } catch (e) {
    return false;
  }
}

// --- Standard JSON + CORS wrapper middleware ---
app.use('*', async (c, next) => {
  // basic logging
  try {
    console.log('[INCOMING]', c.req.method, c.req.url);
  } catch (e) {}
  // allow cross-origin simple requests for testing (adjust for production)
  c.res.headers.set('Access-Control-Allow-Origin', c.req.headers.get('Origin') || '*');
  c.res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  c.res.headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  c.res.headers.set('Content-Type', 'application/json; charset=utf-8');
  await next();
});

// Explicit OPTIONS handler to avoid 405 preflight failures
app.options('*', (c) => {
  c.res.headers.set('Access-Control-Max-Age', '600');
  // return empty JSON so client sees valid JSON
  return c.json({ ok: true });
});

// Utility to register both forms (no /api prefix and with /api prefix) to be tolerant
function registerBoth(method, path, handler) {
  const m = method.toLowerCase();
  app[m](path, handler);
  app[m]('/api' + path, handler);
  app[m]('/api/api' + path, handler); // defensive
}

/* -------------------------
   Public store handlers
   ------------------------- */

registerBoth('get', '/store/products', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
  try {
    const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
    const sql = hasIsActive
      ? `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name
         FROM products p LEFT JOIN categories c ON p.category_id = c.id
         WHERE (p.is_active IS NULL OR p.is_active = 1) ORDER BY p.name ASC`
      : `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name
         FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC`;
    const raw = await env.DB.prepare(sql).all();
    const rows = normalizeAllResult(raw);
    const normalized = rows.map(r => ({
      id: r.id,
      slug: r.slug ?? null,
      name: r.name,
      description: r.description,
      price: typeof r.price === 'number' ? r.price : (r.price ? Number(r.price) : 0),
      image_url: r.image_url ?? r.image ?? null,
      category_name: r.category_name ?? null
    }));
    return c.json(normalized);
  } catch (e) {
    console.error('store/products error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

registerBoth('get', '/store/products/:id', async (c) => {
  const env = c.env;
  const id = c.req.param('id');
  if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
  try {
    const p = await env.DB.prepare(
      `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.id = ? LIMIT 1`
    ).bind(id).first();
    if (!p) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    const galleryRaw = await env.DB.prepare('SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all();
    const gallery = normalizeAllResult(galleryRaw).map(g => g.image_url || g.image || null);
    return c.json({ id: p.id, slug: p.slug ?? null, name: p.name, price: p.price, description: p.description, image_url: p.image_url, category_name: p.category_name, digital_content: p.digital_content, product_type: p.product_type, gallery });
  } catch (e) {
    console.error('store/product by id error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

registerBoth('get', '/store/products/slug/:slug', async (c) => {
  const env = c.env;
  const slug = c.req.param('slug');
  if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
  try {
    const p = await env.DB.prepare(
      `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.slug = ? LIMIT 1`
    ).bind(slug).first();
    if (!p) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    const galleryRaw = await env.DB.prepare('SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(p.id).all();
    const gallery = normalizeAllResult(galleryRaw).map(g => g.image_url || g.image || null);
    return c.json({ id: p.id, slug: p.slug ?? null, name: p.name, price: p.price, description: p.description, image_url: p.image_url, category_name: p.category_name, digital_content: p.digital_content, product_type: p.product_type, gallery });
  } catch (e) {
    console.error('store/product by slug error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

/* -------------------------
   Auth handlers (login/logout)
   ------------------------- */

async function loginHandler(c) {
  const env = c.env;
  let body;
  try { body = await c.req.json(); } catch (e) { return c.json({ error: 'Invalid JSON' }, 400); }
  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string') return c.json({ error: 'Email dan password wajib' }, 422);
  if (!env.JWT_SECRET) {
    console.error('[LOGIN] JWT_SECRET missing');
    return c.json({ error: 'Server misconfiguration' }, 500);
  }

  try {
    const user = await env.DB.prepare('SELECT id, password_hash, role, status FROM users WHERE email = ?').bind(body.email).first();
    if (!user) return c.json({ error: 'Email atau password salah' }, 401);
    const ok = await verifyPassword(body.password, user.password_hash);
    if (!ok) return c.json({ error: 'Email atau password salah' }, 401);
    if (user.status !== 'active') return c.json({ error: 'Akun tidak aktif' }, 403);

    const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now()/1000) + 60*60*24 };
    const token = await sign(payload, env.JWT_SECRET, 'HS256');
    const host = (c.req.headers.get('host') || '').toLowerCase();
    const isDev = host.includes('localhost') || (typeof process !== 'undefined' && process.env.NODE_ENV === 'development');
    setCookie(c, 'auth_token', token, { path: '/', httpOnly: true, secure: !isDev, sameSite: 'Lax', maxAge: 60*60*24 });

    return c.json({ success: true, message: 'Login berhasil' });
  } catch (e) {
    console.error('login error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

registerBoth('post', '/login', loginHandler);
registerBoth('post', '/logout', (c) => { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ success: true }); });

/* -------------------------
   Admin example (products list) - protected
   ------------------------- */
async function authMiddleware(c, next) {
  const env = c.env;
  const token = getCookie(c, 'auth_token');
  if (!token) return c.json({ error: 'Tidak terotentikasi' }, 401);
  try {
    const payload = await verify(token, env.JWT_SECRET, 'HS256');
    const user = await env.DB.prepare('SELECT id, role, status FROM users WHERE id = ?').bind(payload.sub).first();
    if (!user) { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ error: 'User tidak ditemukan' }, 401); }
    if (user.status !== 'active') { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ error: 'Akun nonaktif' }, 403); }
    c.set('user', user);
    await next();
  } catch (e) {
    console.error('[AUTH] verify failed', e && e.message);
    setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 });
    return c.json({ error: 'Token tidak valid atau kedaluwarsa' }, 401);
  }
}
async function adminMiddleware(c, next) {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Tidak terotentikasi' }, 401);
  if (user.role !== 'admin') return c.json({ error: 'Akses ditolak' }, 403);
  await next();
}

registerBoth('get', '/admin/products', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env;
  const raw = await env.DB.prepare('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC').all();
  return c.json(normalizeAllResult(raw));
});

/* -------------------------
   Fallback
   ------------------------- */
app.all('*', (c) => {
  return c.json({ error: 'Not Found' }, 404);
});

export const onRequest = handle(app);
