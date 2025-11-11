/**
 * functions/api/[[path]].js
 * Full Hono backend (single-file) for Cloudflare Pages Functions.
 *
 * - Place at functions/api/[[path]].js
 * - Exports: export const onRequest = handle(app);
 * - Uses D1 binding named DB and env var JWT_SECRET.
 *
 * Notes:
 * - Keep JWT_SECRET set in Pages Environment variables.
 * - After deploy, check Pages logs to confirm [INCOMING] entries.
 */

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';

/* minimal zod usage removed to avoid extra deps here; validate manually for simplicity */

/* ---------- Helpers ---------- */

const app = new Hono();

function normalizeAllResult(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  return [];
}

function slugify(s = '') {
  return String(s || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-_]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

async function tableHasColumn(db, tableName, columnName) {
  try {
    const raw = await db.prepare(`PRAGMA table_info('${tableName}')`).all();
    const rows = normalizeAllResult(raw);
    return rows.some((r) => (r.name || '').toLowerCase() === columnName.toLowerCase());
  } catch (e) {
    console.warn('tableHasColumn failed', e && e.message);
    return false;
  }
}

// PBKDF2 verify helper (uses Web Crypto); expects storedHash "saltHex:hashHex"
async function verifyPassword(password, storedHash) {
  try {
    if (!storedHash || !password) return false;
    const parts = storedHash.split(':');
    if (parts.length !== 2) {
      // fallback: direct compare (legacy)
      return password === storedHash;
    }
    const [saltHex, hashHex] = parts;
    if (!saltHex || !hashHex) return false;
    const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map((h) => parseInt(h, 16))).buffer;
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    const derivedHex = [...new Uint8Array(derivedBits)].map(b => b.toString(16).padStart(2, '0')).join('');
    return derivedHex === hashHex;
  } catch (e) {
    console.error('verifyPassword error', e && e.message);
    return false;
  }
}

/* ---------- Logging middleware ---------- */
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname);
    } catch (e) {}
  } catch (e) {}
  await next();
});

/* ---------- Simple route registrar (tolerant) ---------- */
function register(method, path, ...handlers) {
  const m = method.toLowerCase();
  if (typeof app[m] !== 'function') throw new Error('Invalid method: ' + method);
  app[m](path, ...handlers);
  app[m]('/api' + path, ...handlers);
  app[m]('/api/api' + path, ...handlers);
}

/* ---------- Public Store Handlers ---------- */

register('get', '/store/products', async (c) => {
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
    const normalized = rows.map((r) => ({
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

register('get', '/store/products/:id', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
  const id = c.req.param('id');
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

register('get', '/store/products/slug/:slug', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
  const slug = c.req.param('slug');
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

/* ---------- Auth handlers (simple, consistent flow) ---------- */

async function loginHandler(c) {
  const env = c.env;
  let body;
  try {
    body = await c.req.json();
  } catch (e) {
    return c.json({ error: 'Invalid JSON' }, 400);
  }
  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string') {
    return c.json({ error: 'Email dan password wajib' }, 422);
  }
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

register('post', '/login', loginHandler);
register('post', '/logout', (c) => { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ success: true }); });

/* ---------- Admin: categories, products, stock, gallery, orders, users ---------- */

// Categories
register('get', '/admin/categories', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const raw = await env.DB.prepare('SELECT * FROM categories ORDER BY name ASC').all(); return c.json(normalizeAllResult(raw));
});
register('post', '/admin/categories', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const body = await c.req.json(); const { results } = await env.DB.prepare('INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *').bind(body.name, body.slug).all(); return c.json(normalizeAllResult(results)[0], 201);
});
register('put', '/admin/categories/:id', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = await c.req.json(); const { results } = await env.DB.prepare('UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *').bind(body.name, body.slug, id).all(); return c.json(normalizeAllResult(results)[0]);
});
register('delete', '/admin/categories/:id', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const id = c.req.param('id'); await env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run(); return c.json({ success: true }); });

// Products (create/list/get/update/delete) - adapt to is_active and slug existence
register('get', '/admin/products', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const raw = await env.DB.prepare('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC').all(); return c.json(normalizeAllResult(raw));
});
register('get', '/admin/products/:id', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const id = c.req.param('id'); const product = await env.DB.prepare('SELECT * FROM products WHERE id = ?').bind(id).first(); if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404); const galleryRaw = await env.DB.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all(); return c.json({ ...product, gallery: normalizeAllResult(galleryRaw) });
});
register('post', '/admin/products', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const body = await c.req.json();
  let slug = (body.slug || '').trim(); if (!slug) slug = slugify(body.name || '') || `p-${Date.now()}`;
  let candidate = slug; let i = 1;
  while (true) { const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ?').bind(candidate).first(); if (!exists) break; candidate = `${slug}-${i++}`; }
  slug = candidate;
  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
  if (hasIsActive) {
    const { results } = await env.DB.prepare(`INSERT INTO products (slug,name,description,price,product_type,digital_content,image_url,category_id,is_active) VALUES (?,?,?,?,?,?,?,?,?) RETURNING *`).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0).all();
    return c.json(normalizeAllResult(results)[0], 201);
  } else {
    const { results } = await env.DB.prepare(`INSERT INTO products (slug,name,description,price,product_type,digital_content,image_url,category_id) VALUES (?,?,?,?,?,?,?,?) RETURNING *`).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null).all();
    return c.json(normalizeAllResult(results)[0], 201);
  }
});
register('put', '/admin/products/:id', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = await c.req.json();
  let slug = (body.slug || '').trim(); if (!slug) slug = slugify(body.name || '') || `p-${id}`;
  let candidate = slug; let i = 1;
  while (true) { const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ? AND id != ?').bind(candidate, id).first(); if (!exists) break; candidate = `${slug}-${i++}`; }
  slug = candidate;
  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
  if (hasIsActive) {
    const { results } = await env.DB.prepare(`UPDATE products SET slug=?,name=?,description=?,price=?,product_type=?,digital_content=?,image_url=?,category_id=?,is_active=? WHERE id = ? RETURNING *`).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, id).all();
    return c.json(normalizeAllResult(results)[0]);
  } else {
    const { results } = await env.DB.prepare(`UPDATE products SET slug=?,name=?,description=?,price=?,product_type=?,digital_content=?,image_url=?,category_id=? WHERE id = ? RETURNING *`).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, id).all();
    return c.json(normalizeAllResult(results)[0]);
  }
});
register('delete', '/admin/products/:id', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const id = c.req.param('id');
  const stmts = [ env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id), env.DB.prepare('DELETE FROM product_stock_unique WHERE product_id = ?').bind(id), env.DB.prepare('DELETE FROM product_images WHERE product_id = ?').bind(id) ];
  await env.DB.batch(stmts);
  return c.json({ success: true });
});

// Stock & gallery
register('get', '/admin/products/:id/stock', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const id = c.req.param('id'); const raw = await env.DB.prepare('SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC').bind(id).all(); return c.json(normalizeAllResult(raw)); });
register('post', '/admin/products/:id/stock', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const id = c.req.param('id'); const body = await c.req.json(); const stmts = body.stock_items.map(s => env.DB.prepare('INSERT INTO product_stock_unique (product_id, content, is_sold) VALUES (?, ?, 0)').bind(id, s)); await env.DB.batch(stmts); return c.json({ success: true }); });
register('delete', '/admin/stock/:stockId', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const stockId = c.req.param('stockId'); await env.DB.prepare('DELETE FROM product_stock_unique WHERE id = ?').bind(stockId).run(); return c.json({ success: true }); });

register('get', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const id = c.req.param('id'); const raw = await env.DB.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all(); return c.json(normalizeAllResult(raw)); });
register('post', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const id = c.req.param('id'); const body = await c.req.json(); const deleteStmt = env.DB.prepare('DELETE FROM product_images WHERE product_id = ?').bind(id); const insertStmts = body.images.map((u,i) => env.DB.prepare('INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)').bind(id, u, i)); await env.DB.batch([deleteStmt, ...insertStmts]); return c.json({ success: true }); });
register('delete', '/admin/gallery/:imageId', authMiddleware, adminMiddleware, async (c) => { const env = c.env; const imageId = c.req.param('imageId'); await env.DB.prepare('DELETE FROM product_images WHERE id = ?').bind(imageId).run(); return c.json({ success: true }); });

/* Orders & users (admin) */
register('get', '/admin/orders', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env;
  const raw = await env.DB.prepare(`SELECT o.*, p.name as product_name, u.email as user_email FROM orders o LEFT JOIN products p ON o.product_id = p.id LEFT JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`).all();
  return c.json(normalizeAllResult(raw));
});
register('get', '/admin/users', authMiddleware, adminMiddleware, async (c) => {
  const env = c.env; const raw = await env.DB.prepare('SELECT id, email, name, role, status, created_at FROM users ORDER BY created_at DESC').all(); return c.json(normalizeAllResult(raw));
});

/* Checkout & webhook stubs */
register('post', '/store/checkout', async (c) => { return c.json({ error: 'Checkout not configured' }, 501); });
register('post', '/webhook/paspay', async (c) => { return c.json({ success: true }); });

/* Debug route (optional) */
register('get', '/debug/db', async (c) => {
  const token = c.req.query('token') || '';
  if (!c.env.DEBUG_TOKEN || token !== c.env.DEBUG_TOKEN) return c.json({ error: 'Unauthorized' }, 401);
  const env = c.env;
  const out = {};
  out.products = normalizeAllResult(await env.DB.prepare('SELECT * FROM products ORDER BY id DESC LIMIT 50').all());
  out.table_info = normalizeAllResult(await env.DB.prepare("PRAGMA table_info('products')").all());
  return c.json(out);
});

/* Fallback */
app.all('*', (c) => {
  try { console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url); } catch (e) {}
  return c.json({ error: 'Not Found' }, 404);
});

/* Export */
export const onRequest = handle(app);
