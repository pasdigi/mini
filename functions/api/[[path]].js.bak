/**
 * functions/api/[[path]].js
 *
 * Full Hono backend for Cloudflare Pages.
 * - Normalizes D1 return shapes
 * - Adds slug handling and uniqueness
 * - Detects products.is_active column presence
 * - Auth (login/logout) with JWT cookie
 * - Admin protected routes (categories, products, stock, gallery, orders, users)
 * - Public store routes (list, detail by id, detail by slug)
 * - Debug route protected by DEBUG_TOKEN (optional)
 *
 * Deploy to: functions/api/[[path]].js
 */

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

const app = new Hono();

/* -------------------------
   Utilities
   ------------------------- */

function normalizeAllResult(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  return [];
}

function slugify(input = '') {
  return String(input || '')
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

/* -------------------------
   Logging middleware
   ------------------------- */
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING]', c.req.method, c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname);
    } catch (e) {}
  } catch (e) {}
  await next();
});

/* -------------------------
   Schemas
   ------------------------- */
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

const productSchema = z.object({
  name: z.string().min(1),
  slug: z.string().optional().nullable(),
  price: z.number().nonnegative(),
  product_type: z.enum(['STANDARD', 'UNIQUE']),
  description: z.string().optional().nullable(),
  digital_content: z.string().optional().nullable(),
  image_url: z.string().optional().nullable(),
  category_id: z.number().int().optional().nullable(),
  is_active: z.boolean().optional()
});

const categorySchema = z.object({ name: z.string().min(1), slug: z.string().min(1) });
const stockSchema = z.object({ stock_items: z.array(z.string().min(1)) });
const gallerySchema = z.object({ images: z.array(z.string().url()) });

/* -------------------------
   Auth middlewares
   ------------------------- */
const authMiddleware = async (c, next) => {
  const env = c.env;
  const token = getCookie(c, 'auth_token');
  if (!token) return c.json({ error: 'Tidak terotentikasi' }, 401);
  try {
    const payload = await verify(token, env.JWT_SECRET, 'HS256');
    const user = await env.DB.prepare('SELECT id, email, role, status FROM users WHERE id = ?').bind(payload.sub).first();
    if (!user) {
      setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 });
      return c.json({ error: 'User tidak ditemukan' }, 401);
    }
    if (user.status !== 'active') {
      setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 });
      return c.json({ error: 'Akun nonaktif' }, 403);
    }
    c.set('user', user);
    await next();
  } catch (e) {
    console.log('[AUTH] verify failed', e && e.message);
    setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 });
    return c.json({ error: 'Token tidak valid atau kedaluwarsa' }, 401);
  }
};

const adminMiddleware = async (c, next) => {
  const user = c.get('user');
  if (!user) return c.json({ error: 'Tidak terotentikasi' }, 401);
  if (user.role !== 'admin') return c.json({ error: 'Akses ditolak. Memerlukan hak admin.' }, 403);
  await next();
};

/* -------------------------
   Tolerant route registrar
   ------------------------- */
function register(method, path, ...handlers) {
  const m = method.toLowerCase();
  if (typeof app[m] !== 'function') throw new Error('Invalid method: ' + method);
  app[m](path, ...handlers);
  app[m]('/api' + path, ...handlers);
  app[m]('/api/api' + path, ...handlers);
}

/* -------------------------
   Public: Store handlers
   ------------------------- */

async function storeProductsHandler(c) {
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
}

async function storeProductByIdHandler(c) {
  const env = c.env;
  const id = c.req.param('id');
  try {
    const p = await env.DB.prepare(
      `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.id = ? LIMIT 1`
    ).bind(id).first();
    if (!p) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    const galleryRaw = await env.DB.prepare('SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all();
    const gallery = normalizeAllResult(galleryRaw).map((g) => g.image_url || g.image || null);
    return c.json({
      id: p.id,
      slug: p.slug ?? null,
      name: p.name,
      price: p.price,
      description: p.description,
      image_url: p.image_url,
      category_name: p.category_name,
      digital_content: p.digital_content,
      product_type: p.product_type,
      gallery
    });
  } catch (e) {
    console.error('store/product by id error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

async function storeProductBySlugHandler(c) {
  const env = c.env;
  const slug = c.req.param('slug');
  try {
    const p = await env.DB.prepare(
      `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.slug = ? LIMIT 1`
    ).bind(slug).first();
    if (!p) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    const galleryRaw = await env.DB.prepare('SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(p.id).all();
    const gallery = normalizeAllResult(galleryRaw).map((g) => g.image_url || g.image || null);
    return c.json({
      id: p.id,
      slug: p.slug ?? null,
      name: p.name,
      price: p.price,
      description: p.description,
      image_url: p.image_url,
      category_name: p.category_name,
      digital_content: p.digital_content,
      product_type: p.product_type,
      gallery
    });
  } catch (e) {
    console.error('store/product by slug error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

/* -------------------------
   Auth handlers
   ------------------------- */

async function loginHandler(c) {
  const env = c.env;
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

  try {
    const user = await env.DB.prepare('SELECT id, password_hash, role, status FROM users WHERE email = ?').bind(body.email).first();
    if (!user) return c.json({ error: 'Email atau password salah' }, 401);

    // verify password (PBKDF2 style) if possible; fallback to direct compare
    let verified = false;
    try {
      const [saltHex, hashHex] = (user.password_hash || '').split(':');
      if (saltHex && hashHex) {
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map((b) => parseInt(b, 16))).buffer;
        const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(body.password), { name: 'PBKDF2' }, false, ['deriveBits']);
        const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
        const derivedHex = [...new Uint8Array(derivedBits)].map((b) => b.toString(16).padStart(2, '0')).join('');
        verified = derivedHex === hashHex;
      } else {
        verified = body.password === user.password_hash;
      }
    } catch (pwErr) {
      console.warn('Password verify failed', pwErr && pwErr.message);
    }

    if (!verified) return c.json({ error: 'Email atau password salah' }, 401);
    if (user.status !== 'active') return c.json({ error: 'Akun tidak aktif' }, 403);

    const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 };
    const token = await sign(payload, env.JWT_SECRET, 'HS256');

    const isDev = (typeof process !== 'undefined' && process.env.NODE_ENV === 'development') || (c.req.headers.get('host') || '').includes('localhost');

    setCookie(c, 'auth_token', token, { path: '/', httpOnly: true, secure: !isDev, sameSite: 'Lax', maxAge: 60 * 60 * 24 });

    return c.json({ success: true, message: 'Login berhasil' });
  } catch (e) {
    console.error('login error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

async function logoutHandler(c) {
  setCookie(c, 'auth_token', '', { path: '/', secure: false, httpOnly: true, sameSite: 'Lax', maxAge: 0 });
  return c.json({ success: true, message: 'Logout berhasil' });
}

/* -------------------------
   Admin: categories
   ------------------------- */

async function adminListCategories(c) {
  const env = c.env;
  const raw = await env.DB.prepare('SELECT * FROM categories ORDER BY name ASC').all();
  return c.json(normalizeAllResult(raw));
}

async function adminCreateCategory(c) {
  const env = c.env;
  const body = c.req.valid('json');
  const { results } = await env.DB.prepare('INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *').bind(body.name, body.slug).all();
  return c.json(normalizeAllResult(results)[0], 201);
}

async function adminUpdateCategory(c) {
  const env = c.env;
  const id = c.req.param('id');
  const body = c.req.valid('json');
  const { results } = await env.DB.prepare('UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *').bind(body.name, body.slug, id).all();
  return c.json(normalizeAllResult(results)[0]);
}

async function adminDeleteCategory(c) {
  const env = c.env;
  const id = c.req.param('id');
  await env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
  return c.json({ success: true, message: 'Kategori dihapus' });
}

/* -------------------------
   Admin: products CRUD
   ------------------------- */

async function adminListProducts(c) {
  const env = c.env;
  const raw = await env.DB.prepare('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC').all();
  return c.json(normalizeAllResult(raw));
}

async function adminGetProduct(c) {
  const env = c.env;
  const id = c.req.param('id');
  const product = await env.DB.prepare('SELECT * FROM products WHERE id = ?').bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
  const galleryRaw = await env.DB.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all();
  const gallery = normalizeAllResult(galleryRaw);
  return c.json({ ...product, gallery });
}

async function adminCreateProduct(c) {
  const env = c.env;
  const body = c.req.valid('json');

  let slug = (body.slug || '').trim();
  if (!slug) slug = slugify(body.name || '');
  if (!slug) slug = `p-${Date.now()}`;

  // ensure unique slug
  let candidate = slug;
  let i = 1;
  while (true) {
    const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ?').bind(candidate).first();
    if (!exists) break;
    candidate = `${slug}-${i++}`;
  }
  slug = candidate;

  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');

  if (hasIsActive) {
    const { results } = await env.DB.prepare(
      `INSERT INTO products (slug, name, description, price, product_type, digital_content, image_url, category_id, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
    ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0).all();
    return c.json(normalizeAllResult(results)[0], 201);
  } else {
    const { results } = await env.DB.prepare(
      `INSERT INTO products (slug, name, description, price, product_type, digital_content, image_url, category_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
    ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null).all();
    return c.json(normalizeAllResult(results)[0], 201);
  }
}

async function adminUpdateProduct(c) {
  const env = c.env;
  const id = c.req.param('id');
  const body = c.req.valid('json');

  let slug = (body.slug || '').trim();
  if (!slug) slug = slugify(body.name || '') || `p-${id}`;

  // ensure unique (excluding current id)
  let candidate = slug;
  let i = 1;
  while (true) {
    const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ? AND id != ?').bind(candidate, id).first();
    if (!exists) break;
    candidate = `${slug}-${i++}`;
  }
  slug = candidate;

  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
  if (hasIsActive) {
    const { results } = await env.DB.prepare(
      `UPDATE products SET slug = ?, name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, is_active = ? WHERE id = ? RETURNING *`
    ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, id).all();
    return c.json(normalizeAllResult(results)[0]);
  } else {
    const { results } = await env.DB.prepare(
      `UPDATE products SET slug = ?, name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ? WHERE id = ? RETURNING *`
    ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, id).all();
    return c.json(normalizeAllResult(results)[0]);
  }
}

async function adminDeleteProduct(c) {
  const env = c.env;
  const id = c.req.param('id');
  const stmts = [
    env.DB.prepare('DELETE FROM products WHERE id = ?').bind(id),
    env.DB.prepare('DELETE FROM product_stock_unique WHERE product_id = ?').bind(id),
    env.DB.prepare('DELETE FROM product_images WHERE product_id = ?').bind(id)
  ];
  await env.DB.batch(stmts);
  return c.json({ success: true, message: 'Produk (dan stok/galeri terkait) dihapus' });
}

/* -------------------------
   Admin: stock & gallery
   ------------------------- */

async function adminListStock(c) {
  const env = c.env;
  const id = c.req.param('id');
  const raw = await env.DB.prepare('SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC').bind(id).all();
  return c.json(normalizeAllResult(raw));
}

async function adminAddStock(c) {
  const env = c.env;
  const id = c.req.param('id');
  const body = c.req.valid('json');
  const product = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND product_type = 'UNIQUE'").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan atau bukan tipe UNIQUE' }, 404);
  const stmts = body.stock_items.map((content) => env.DB.prepare('INSERT INTO product_stock_unique (product_id, content, is_sold) VALUES (?, ?, 0)').bind(id, content));
  if (stmts.length === 0) return c.json({ error: 'Tidak ada stok yang diberikan' }, 400);
  await env.DB.batch(stmts);
  return c.json({ success: true, message: `${stmts.length} item stok ditambahkan` }, 201);
}

async function adminDeleteStock(c) {
  const env = c.env;
  const stockId = c.req.param('stockId');
  const { changes } = await env.DB.prepare('DELETE FROM product_stock_unique WHERE id = ? AND is_sold = 0').bind(stockId).run();
  if (changes === 0) return c.json({ error: 'Gagal menghapus stok (mungkin sudah terjual atau tidak ditemukan)' }, 404);
  return c.json({ success: true, message: 'Stok dihapus' });
}

async function adminListGallery(c) {
  const env = c.env;
  const id = c.req.param('id');
  const raw = await env.DB.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC').bind(id).all();
  return c.json(normalizeAllResult(raw));
}

async function adminSyncGallery(c) {
  const env = c.env;
  const id = c.req.param('id');
  const body = c.req.valid('json');
  const deleteStmt = env.DB.prepare('DELETE FROM product_images WHERE product_id = ?').bind(id);
  const insertStmts = body.images.map((url, index) => env.DB.prepare('INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)').bind(id, url, index));
  await env.DB.batch([deleteStmt, ...insertStmts]);
  return c.json({ success: true, message: `Galeri disinkronkan (${insertStmts.length} gambar)` }, 201);
}

async function adminDeleteGallery(c) {
  const env = c.env;
  const imageId = c.req.param('imageId');
  await env.DB.prepare('DELETE FROM product_images WHERE id = ?').bind(imageId).run();
  return c.json({ success: true, message: 'Gambar Galeri Dihapus' });
}

/* -------------------------
   Admin: orders & users
   ------------------------- */

async function adminListOrders(c) {
  const env = c.env;
  const raw = await env.DB.prepare(
    `SELECT o.*, p.name as product_name, u.email as user_email
     FROM orders o
     LEFT JOIN products p ON o.product_id = p.id
     LEFT JOIN users u ON o.user_id = u.id
     ORDER BY o.created_at DESC`
  ).all();
  return c.json(normalizeAllResult(raw));
}

async function adminListUsers(c) {
  const env = c.env;
  const raw = await env.DB.prepare('SELECT id, email, name, role, status, created_at FROM users ORDER BY created_at DESC').all();
  return c.json(normalizeAllResult(raw));
}

/* -------------------------
   Checkout & Webhook
   ------------------------- */

async function storeCheckoutHandler(c) {
  const env = c.env;
  const body = c.req.valid('json');
  try {
    const product = await env.DB.prepare('SELECT id, name, price, product_type FROM products WHERE id = ?').bind(body.product_id).first();
    if (!product) return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);

    if (!env.PASPAY_API_URL || !env.PASPAY_API_KEY) {
      const { meta } = await env.DB.prepare('INSERT INTO orders (product_id, status, total_amount, customer_email, created_at, user_id) VALUES (?, ?, ?, ?, ?, 0)').bind(product.id, 'UNPAID', product.price, body.email, Math.floor(Date.now() / 1000)).run();
      return c.json({ success: true, order_id: meta?.last_row_id || null, message: 'Order created (local)' });
    }

    return c.json({ error: 'External payment integration not configured' }, 501);
  } catch (e) {
    console.error('checkout error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

async function paspayWebhookHandler(c) {
  const env = c.env;
  const authHeader = c.req.header('Authorization');
  const incoming = authHeader ? authHeader.split(' ')[1] : '';
  if (!env.PASPAY_WEBHOOK_TOKEN || incoming !== env.PASPAY_WEBHOOK_TOKEN) return c.json({ error: 'Unauthorized' }, 401);

  const payload = c.req.valid('json');
  console.log('Webhook received', payload);
  return c.json({ success: true });
}

/* -------------------------
   Debug
   ------------------------- */

async function debugDbHandler(c) {
  const env = c.env;
  const token = c.req.query('token') || '';
  const expected = env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) return c.json({ error: 'Unauthorized' }, 401);
  if (!env.DB) return c.json({ error: 'DB binding not present' }, 500);

  const out = {};
  const cntAll = await env.DB.prepare('SELECT COUNT(*) as cnt FROM products').first();
  const cntActive = await env.DB.prepare('SELECT COUNT(*) as cnt FROM products WHERE is_active = 1').first().catch(() => null);
  out.counts = { total: cntAll?.cnt ?? 0, active_1: cntActive?.cnt ?? 0 };
  out.sample_products = normalizeAllResult(await env.DB.prepare('SELECT * FROM products ORDER BY id DESC LIMIT 50').all());
  out.products_table_info = normalizeAllResult(await env.DB.prepare("PRAGMA table_info('products')").all());
  return c.json(out);
}

/* -------------------------
   Register routes
   ------------------------- */

// Public store routes
register('get', '/store/products', storeProductsHandler);
register('get', '/store/products/:id', storeProductByIdHandler);
register('get', '/store/products/slug/:slug', storeProductBySlugHandler);

// Auth
register('post', '/login', zValidator('json', loginSchema), loginHandler);
register('post', '/logout', logoutHandler);

// Checkout & webhook
register('post', '/store/checkout', zValidator('json', z.object({ product_id: z.number().int(), email: z.string().email(), name: z.string().optional() })), storeCheckoutHandler);
register('post', '/webhook/paspay', zValidator('json', z.object({ event: z.string(), data: z.any().optional() })), paspayWebhookHandler);

// Admin categories
register('get', '/admin/categories', authMiddleware, adminMiddleware, adminListCategories);
register('post', '/admin/categories', authMiddleware, adminMiddleware, zValidator('json', categorySchema), adminCreateCategory);
register('put', '/admin/categories/:id', authMiddleware, adminMiddleware, zValidator('json', categorySchema), adminUpdateCategory);
register('delete', '/admin/categories/:id', authMiddleware, adminMiddleware, adminDeleteCategory);

// Admin products
register('get', '/admin/products', authMiddleware, adminMiddleware, adminListProducts);
register('get', '/admin/products/:id', authMiddleware, adminMiddleware, adminGetProduct);
register('post', '/admin/products', authMiddleware, adminMiddleware, zValidator('json', productSchema), adminCreateProduct);
register('put', '/admin/products/:id', authMiddleware, adminMiddleware, zValidator('json', productSchema), adminUpdateProduct);
register('delete', '/admin/products/:id', authMiddleware, adminMiddleware, adminDeleteProduct);

// Admin stock & gallery
register('get', '/admin/products/:id/stock', authMiddleware, adminMiddleware, adminListStock);
register('post', '/admin/products/:id/stock', authMiddleware, adminMiddleware, zValidator('json', stockSchema), adminAddStock);
register('delete', '/admin/stock/:stockId', authMiddleware, adminMiddleware, adminDeleteStock);

register('get', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, adminListGallery);
register('post', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, zValidator('json', gallerySchema), adminSyncGallery);
register('delete', '/admin/gallery/:imageId', authMiddleware, adminMiddleware, adminDeleteGallery);

// Admin orders & users
register('get', '/admin/orders', authMiddleware, adminMiddleware, adminListOrders);
register('get', '/admin/users', authMiddleware, adminMiddleware, adminListUsers);

// Debug
register('get', '/debug/db', debugDbHandler);

/* -------------------------
   Fallback
   ------------------------- */
app.all('*', (c) => {
  try { console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url); } catch (e) {}
  return c.json({ error: 'Not Found' }, 404);
});

/* -------------------------
   Export
   ------------------------- */
export const onRequest = handle(app);
