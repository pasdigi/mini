/**
 * Full Hono handler for Cloudflare Pages (functions/api/[[path]].js)
 * - Robust store/products endpoint: detects whether products table has `is_active`
 *   column and applies filter only if column exists. Normalizes column names.
 * - Admin create/update product endpoints adapt to presence/absence of `is_active`.
 * - Retains login, auth middlewares, admin handlers, and tolerant route registration.
 *
 * Deploy this file to functions/api/[[path]].js and redeploy Pages.
 */

import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { handle } from 'hono/cloudflare-pages';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

/* ---------- Helpers ---------- */
const bufferToHex = (buffer) =>
  [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
const hexToBuffer = (hex) => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes.buffer;
};
const verifyPassword = async (password, storedHash) => {
  try {
    const [saltHex, hashHex] = (storedHash || '').split(':');
    if (!saltHex || !hashHex) return false;
    const salt = hexToBuffer(saltHex);
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    return bufferToHex(derivedBits) === hashHex;
  } catch (e) {
    console.error('verifyPassword error', e && e.message);
    return false;
  }
};

// Normalize results returned by D1 driver (some shapes have { results: [...] }, some return object)
function normalizeAllResult(raw) {
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  if (raw && typeof raw === 'object' && raw.results) return raw.results;
  // unknown shape: return empty array to avoid exceptions
  return [];
}

// Check whether a table has a column (uses PRAGMA table_info)
async function tableHasColumn(db, tableName, columnName) {
  try {
    const raw = await db.prepare(`PRAGMA table_info('${tableName}')`).all();
    const rows = normalizeAllResult(raw);
    return rows.some((r) => (r.name || r.column_name || r[0]) === columnName);
  } catch (e) {
    console.warn('tableHasColumn failed:', e && e.message);
    return false;
  }
}

/* ---------- Validation Schemas (Zod) ---------- */
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

const categorySchema = z.object({ name: z.string().min(1), slug: z.string().min(1) });

const productSchema = z.object({
  name: z.string().min(1),
  price: z.number().positive(),
  product_type: z.enum(['STANDARD', 'UNIQUE']),
  description: z.string().optional().nullable(),
  digital_content: z.string().optional().nullable(),
  image_url: z.string().optional().nullable(),
  category_id: z.number().int().optional().nullable(),
  is_active: z.boolean().optional()
});

const stockSchema = z.object({ stock_items: z.array(z.string().min(1)) });
const gallerySchema = z.object({ images: z.array(z.string().url()) });

/* ---------- App Init ---------- */
// Do NOT set basePath('/api') when file is in functions/api/[[path]].js on Pages.
const app = new Hono();

/* ---------- Logging Middleware ---------- */
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname);
    } catch (e) { /* ignore parse error */ }
  } catch (e) {
    console.log('[INCOMING] logging failed', e && e.message);
  }
  await next();
});

/* ---------- Auth Middlewares ---------- */
const authMiddleware = async (c, next) => {
  const env = c.env;
  const token = getCookie(c, 'auth_token');
  if (!token) return c.json({ error: 'Tidak terotentikasi' }, 401);
  try {
    const payload = await verify(token, env.JWT_SECRET, 'HS256');
    const user = await env.DB.prepare("SELECT id, role, status FROM users WHERE id = ?").bind(payload.sub).first();
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

/* ---------- Helper: register tolerant routes ---------- */
function register(method, path, ...handlers) {
  const m = method.toLowerCase();
  if (typeof app[m] !== 'function') throw new Error('Invalid method: ' + method);
  app[m](path, ...handlers);
  app[m]('/api' + path, ...handlers);
  app[m]('/api/api' + path, ...handlers);
}

/* ---------- Handlers: Public (Store) ---------- */

// List products (robust: detect if is_active exists and apply filter only if present)
async function storeProductsHandler(c) {
  const env = c.env;
  if (!env || !env.DB) return c.json({ error: 'DB binding not found' }, 500);

  try {
    const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');

    let sql;
    if (hasIsActive) {
      sql = `
        SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        WHERE (p.is_active IS NULL OR p.is_active = 1)
        ORDER BY p.name ASC
      `;
    } else {
      // no is_active column: return all products
      sql = `
        SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        ORDER BY p.name ASC
      `;
    }

    const raw = await env.DB.prepare(sql).all();
    const rows = normalizeAllResult(raw);

    // Normalize rows for frontend
    const normalized = rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: (typeof r.price === 'number') ? r.price : (r.price ? Number(r.price) : 0),
      image_url: r.image_url ?? r.image ?? null,
      category_name: r.category_name ?? null
    }));

    return c.json(normalized);
  } catch (e) {
    console.error('store/products error', e && e.stack);
    return c.json({ error: 'Internal Server Error: ' + (e && e.message) }, 500);
  }
}

// Product detail
async function storeProductDetailHandler(c) {
  const env = c.env;
  const id = c.req.param('id');
  try {
    const productRaw = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.id = ?`
    ).bind(id).first();

    if (!productRaw) return c.json({ error: 'Produk tidak ditemukan' }, 404);

    const galleryRaw = await env.DB.prepare("SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
    const gallery = normalizeAllResult(galleryRaw).map(g => g.image_url || g.image || null);

    const product = {
      id: productRaw.id,
      name: productRaw.name,
      price: productRaw.price,
      description: productRaw.description,
      image_url: productRaw.image_url,
      category_name: productRaw.category_name,
      digital_content: productRaw.digital_content,
      product_type: productRaw.product_type,
      gallery
    };

    return c.json(product);
  } catch (e) {
    console.error('store/product detail error', e && e.stack);
    return c.json({ error: 'Internal Server Error: ' + (e && e.message) }, 500);
  }
}

/* ---------- Handlers: Auth (login/logout) ---------- */
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
    const user = await env.DB.prepare("SELECT id, password_hash, role, status FROM users WHERE email = ?").bind(body.email).first();
    if (!user) return c.json({ error: 'Email atau password salah' }, 401);

    const ok = await verifyPassword(body.password, user.password_hash);
    if (!ok) return c.json({ error: 'Email atau password salah' }, 401);
    if (user.status !== 'active') return c.json({ error: 'Akun tidak aktif' }, 403);

    const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 };
    const token = await sign(payload, env.JWT_SECRET, 'HS256');

    const isDev = (typeof process !== 'undefined' && process.env.NODE_ENV === 'development') || (c.req.headers.get('host') || '').includes('localhost');
    setCookie(c, 'auth_token', token, {
      path: '/',
      httpOnly: true,
      secure: !isDev,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24
    });

    return c.json({ success: true, message: 'Login berhasil', token });
  } catch (e) {
    console.error('login error', e && e.stack);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}

async function logoutHandler(c) {
  setCookie(c, 'auth_token', '', { path: '/', secure: false, httpOnly: true, sameSite: 'Lax', maxAge: 0 });
  return c.json({ success: true, message: 'Logout berhasil' });
}

/* ---------- Admin: Categories ---------- */
async function adminListCategories(c) {
  const env = c.env;
  const { results } = await env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all();
  return c.json(normalizeAllResult(results));
}
async function adminCreateCategory(c) {
  const env = c.env;
  const body = c.req.valid('json');
  const { results } = await env.DB.prepare("INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *").bind(body.name, body.slug).all();
  return c.json(normalizeAllResult(results)[0], 201);
}
async function adminUpdateCategory(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const { results } = await env.DB.prepare("UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *").bind(body.name, body.slug, id).all();
  return c.json(normalizeAllResult(results)[0]);
}
async function adminDeleteCategory(c) {
  const env = c.env; const id = c.req.param('id');
  await env.DB.prepare("DELETE FROM categories WHERE id = ?").bind(id).run();
  return c.json({ success: true, message: 'Kategori dihapus' });
}

/* ---------- Admin: Products (CREATE/READ/UPDATE/DELETE) ---------- */
/*
  Note: admin create/update will adapt to presence of is_active column.
  If is_active exists, we include it in INSERT/UPDATE; otherwise we omit it.
*/
async function adminListProducts(c) {
  const env = c.env;
  const raw = await env.DB.prepare(`SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC`).all();
  return c.json(normalizeAllResult(raw));
}

async function adminGetProduct(c) {
  const env = c.env; const id = c.req.param('id');
  const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
  const galleryRaw = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  const gallery = normalizeAllResult(galleryRaw);
  return c.json({ ...product, gallery });
}

async function adminCreateProduct(c) {
  const env = c.env;
  const body = c.req.valid('json');

  // detect if is_active exists
  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');

  // Build SQL and params dynamically
  if (hasIsActive) {
    const { results } = await env.DB.prepare(
      `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
    ).bind(
      body.name,
      body.description || null,
      body.price,
      body.product_type,
      body.digital_content || null,
      body.image_url || null,
      body.category_id || null,
      body.is_active ? 1 : 0
    ).all();
    return c.json(normalizeAllResult(results)[0], 201);
  } else {
    const { results } = await env.DB.prepare(
      `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
    ).bind(
      body.name,
      body.description || null,
      body.price,
      body.product_type,
      body.digital_content || null,
      body.image_url || null,
      body.category_id || null
    ).all();
    return c.json(normalizeAllResult(results)[0], 201);
  }
}

async function adminUpdateProduct(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');

  if (hasIsActive) {
    const { results } = await env.DB.prepare(
      `UPDATE products SET name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, is_active = ? WHERE id = ? RETURNING *`
    ).bind(
      body.name,
      body.description || null,
      body.price,
      body.product_type,
      body.digital_content || null,
      body.image_url || null,
      body.category_id || null,
      body.is_active ? 1 : 0,
      id
    ).all();
    return c.json(normalizeAllResult(results)[0]);
  } else {
    const { results } = await env.DB.prepare(
      `UPDATE products SET name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ? WHERE id = ? RETURNING *`
    ).bind(
      body.name,
      body.description || null,
      body.price,
      body.product_type,
      body.digital_content || null,
      body.image_url || null,
      body.category_id || null,
      id
    ).all();
    return c.json(normalizeAllResult(results)[0]);
  }
}

async function adminDeleteProduct(c) {
  const env = c.env; const id = c.req.param('id');
  const stmts = [
    env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id),
    env.DB.prepare("DELETE FROM product_stock_unique WHERE product_id = ?").bind(id),
    env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id),
  ];
  await env.DB.batch(stmts);
  return c.json({ success: true, message: 'Produk (dan stok/galeri terkait) dihapus' });
}

/* ---------- Admin: Stock & Gallery ---------- */
async function adminListStock(c) {
  const env = c.env; const id = c.req.param('id');
  const raw = await env.DB.prepare("SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC").bind(id).all();
  return c.json(normalizeAllResult(raw));
}
async function adminAddStock(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const product = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND product_type = 'UNIQUE'").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan atau bukan tipe UNIQUE' }, 404);
  const stmts = body.stock_items.map(content => env.DB.prepare("INSERT INTO product_stock_unique (product_id, content, is_sold) VALUES (?, ?, 0)").bind(id, content));
  if (stmts.length === 0) return c.json({ error: 'Tidak ada stok yang diberikan' }, 400);
  await env.DB.batch(stmts);
  return c.json({ success: true, message: `${stmts.length} item stok ditambahkan` }, 201);
}
async function adminDeleteStock(c) {
  const env = c.env; const stockId = c.req.param('stockId');
  const { changes } = await env.DB.prepare("DELETE FROM product_stock_unique WHERE id = ? AND is_sold = 0").bind(stockId).run();
  if (changes === 0) return c.json({ error: 'Gagal menghapus stok (mungkin sudah terjual atau tidak ditemukan)' }, 404);
  return c.json({ success: true, message: 'Stok dihapus' });
}

async function adminListGallery(c) {
  const env = c.env; const id = c.req.param('id');
  const raw = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  return c.json(normalizeAllResult(raw));
}
async function adminSyncGallery(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const deleteStmt = env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id);
  const insertStmts = body.images.map((url, index) => env.DB.prepare("INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)").bind(id, url, index));
  await env.DB.batch([deleteStmt, ...insertStmts]);
  return c.json({ success: true, message: `Galeri disinkronkan (${insertStmts.length} gambar)` }, 201);
}
async function adminDeleteGallery(c) {
  const env = c.env; const imageId = c.req.param('imageId');
  await env.DB.prepare("DELETE FROM product_images WHERE id = ?").bind(imageId).run();
  return c.json({ success: true, message: 'Gambar Galeri Dihapus' });
}

/* ---------- Admin: Orders & Users ---------- */
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
  const raw = await env.DB.prepare("SELECT id, email, name, role, status, created_at FROM users ORDER BY created_at DESC").all();
  return c.json(normalizeAllResult(raw));
}

/* ---------- Webhook (Paspay) & Checkout (ke Paspay) ---------- */
async function paspayWebhookHandler(c) {
  const env = c.env;
  const authHeader = c.req.header('Authorization');
  const incomingToken = authHeader ? authHeader.split(' ')[1] : '';
  if (incomingToken !== env.PASPAY_WEBHOOK_TOKEN) return c.json({ error: 'Unauthorized: Token webhook tidak valid' }, 401);

  const payload = c.req.valid('json');
  if (payload.event !== 'payment.success' || !payload.data) return c.json({ success: true, message: 'Event diabaikan' }, 200);

  const tx = payload.data;
  try {
    const order = await env.DB.prepare("SELECT * FROM orders WHERE paspay_reference_id = ? AND status = 'UNPAID'").bind(tx.reference_id).first();
    if (!order) return c.json({ error: 'Order tidak ditemukan atau sudah diproses' }, 404);

    const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(order.product_id).first();
    if (!product) return c.json({ error: 'Produk terkait tidak ditemukan' }, 404);

    let delivered_content = null;
    if (product.product_type === 'STANDARD') {
      delivered_content = product.digital_content;
    } else if (product.product_type === 'UNIQUE') {
      const stock = await env.DB.prepare("SELECT content FROM product_stock_unique WHERE order_id = ? AND product_id = ?").bind(order.id, product.id).first();
      if (!stock) return c.json({ error: 'Stok internal tidak ditemukan' }, 500);
      delivered_content = stock.content;
    }

    await env.DB.prepare("UPDATE orders SET status = 'PAID', delivered_content = ? WHERE id = ?").bind(delivered_content, order.id).run();
    console.log(`Webhook delivered to ${order.customer_email}`);
    return c.json({ success: true, message: 'Webhook diproses' }, 200);
  } catch (e) {
    console.error('Webhook failed', e && e.stack);
    return c.json({ error: 'Internal Server Error: ' + e.message }, 500);
  }
}

async function storeCheckoutHandler(c) {
  const env = c.env;
  const body = c.req.valid('json');
  try {
    const product = await env.DB.prepare("SELECT id, name, price, product_type FROM products WHERE id = ?").bind(body.product_id).first();
    if (!product) return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);

    const paspayPayload = {
      project_id: parseInt(env.PASPAY_PROJECT_ID, 10),
      payment_channel_id: [1, 3],
      amount: product.price,
      internal_ref_id: `MINI-${product.id}-${Math.floor(Date.now() / 1000)}`,
      description: `Pembelian: ${product.name}`,
      customer_email: body.email,
      customer_name: body.name || 'Customer'
    };

    const paspayResponse = await fetch(env.PASPAY_API_URL + '/transactions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.PASPAY_API_KEY}` },
      body: JSON.stringify(paspayPayload)
    });
    const paspayResult = await paspayResponse.json();
    if (!paspayResponse.ok) {
      console.error('Paspay error', paspayResult);
      return c.json({ error: 'Gagal membuat invoice Paspay', detail: paspayResult.error || paspayResult }, 500);
    }

    const { meta } = await env.DB.prepare(
      `INSERT INTO orders (product_id, status, paspay_reference_id, total_amount, customer_email, created_at, user_id)
       VALUES (?, 'UNPAID', ?, ?, ?, ?, 0)`
    ).bind(product.id, paspayResult.reference_id, paspayResult.total_amount_expected, body.email, Math.floor(Date.now() / 1000)).run();

    const newOrderId = meta?.last_row_id;
    if (!newOrderId) return c.json({ error: 'Gagal menyimpan order' }, 500);

    if (product.product_type === 'UNIQUE') {
      const stock = await env.DB.prepare("SELECT id FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1").bind(product.id).first();
      if (!stock) return c.json({ error: 'Stok produk ini telah habis!' }, 410);
      const { changes } = await env.DB.prepare("UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ? AND is_sold = 0").bind(newOrderId, stock.id).run();
      if (changes === 0) return c.json({ error: 'Stok produk baru saja habis. Silakan coba lagi.' }, 409);
    }

    return c.json(paspayResult);
  } catch (e) {
    console.error('checkout error', e && e.stack);
    return c.json({ error: 'Terjadi kesalahan saat checkout: ' + (e && e.message) }, 500);
  }
}

/* ---------- Register routes (tolerant) ---------- */

// Public
register('post', '/login', zValidator('json', loginSchema), loginHandler);
register('post', '/logout', logoutHandler);
register('get', '/health', (c) => c.json({ ok: true }));

// Store
register('get', '/store/products', storeProductsHandler);
register('get', '/store/products/:id', storeProductDetailHandler);
register('post', '/store/checkout', zValidator('json', z.object({ product_id: z.number().int(), email: z.string().email(), name: z.string().optional() })), storeCheckoutHandler);

// Webhook
register('post', '/webhook/paspay', zValidator('json', z.object({ event: z.string(), data: z.object({ reference_id: z.string() }).optional() })), paspayWebhookHandler);

// Admin - categories
register('get', '/admin/categories', authMiddleware, adminMiddleware, adminListCategories);
register('post', '/admin/categories', authMiddleware, adminMiddleware, zValidator('json', categorySchema), adminCreateCategory);
register('put', '/admin/categories/:id', authMiddleware, adminMiddleware, zValidator('json', categorySchema), adminUpdateCategory);
register('delete', '/admin/categories/:id', authMiddleware, adminMiddleware, adminDeleteCategory);

// Admin - products
register('get', '/admin/products', authMiddleware, adminMiddleware, adminListProducts);
register('get', '/admin/products/:id', authMiddleware, adminMiddleware, adminGetProduct);
register('post', '/admin/products', authMiddleware, adminMiddleware, zValidator('json', productSchema), adminCreateProduct);
register('put', '/admin/products/:id', authMiddleware, adminMiddleware, zValidator('json', productSchema), adminUpdateProduct);
register('delete', '/admin/products/:id', authMiddleware, adminMiddleware, adminDeleteProduct);

// Admin - stock & gallery
register('get', '/admin/products/:id/stock', authMiddleware, adminMiddleware, adminListStock);
register('post', '/admin/products/:id/stock', authMiddleware, adminMiddleware, zValidator('json', stockSchema), adminAddStock);
register('delete', '/admin/stock/:stockId', authMiddleware, adminMiddleware, adminDeleteStock);

register('get', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, adminListGallery);
register('post', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, zValidator('json', gallerySchema), adminSyncGallery);
register('delete', '/admin/gallery/:imageId', authMiddleware, adminMiddleware, adminDeleteGallery);

// Admin - orders & users
register('get', '/admin/orders', authMiddleware, adminMiddleware, adminListOrders);
register('get', '/admin/users', authMiddleware, adminMiddleware, adminListUsers);

/* ---------- Fallback ---------- */
app.all('*', (c) => {
  try {
    console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url);
  } catch (e) {}
  return c.json({ error: 'Not Found' }, 404);
});

/* ---------- Export handler ---------- */
export const onRequest = handle(app);
