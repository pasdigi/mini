/**
 * Complete Hono handler for Cloudflare Pages functions/api/[[path]].js
 * - Registers every route in a "tolerant" way so requests to:
 *     /path, /api/path, and /api/api/path
 *   will all match (prevents 404 due to /api prefix mapping differences).
 * - Adds request logging ([INCOMING]) and fallback logging ([NO MATCH]).
 * - Implements authentication (cookie + JWT) and admin middleware.
 * - All admin endpoints are protected and registered with the tolerant helper.
 *
 * Deploy this file exactly at functions/api/[[path]].js in your Pages repo.
 */

import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { handle } from 'hono/cloudflare-pages';
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

/* ---------------------------
   Helpers & Validation
   --------------------------- */
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

// Zod schemas
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const checkoutSchema = z.object({ product_id: z.number().int().positive(), email: z.string().email(), name: z.string().optional() });
const categorySchema = z.object({ name: z.string().min(1), slug: z.string().min(1) });
const productSchema = z.object({
  name: z.string().min(1),
  price: z.number().positive(),
  product_type: z.enum(['STANDARD', 'UNIQUE']),
  description: z.string().optional().nullable(),
  digital_content: z.string().optional().nullable(),
  image_url: z.string().optional().nullable(),
  category_id: z.number().int().optional().nullable(),
  is_active: z.boolean().optional().default(true),
});
const stockSchema = z.object({ stock_items: z.array(z.string().min(1)) });
const gallerySchema = z.object({ images: z.array(z.string().url()) });

/* ---------------------------
   App initialization
   --------------------------- */
// Do NOT set basePath('/api') when deploying at functions/api/[[path]].js on Pages.
// Pages will map requests under /api/* to this function file.
const app = new Hono();

/* ---------------------------
   Logging middleware
   --------------------------- */
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname, 'host=', u.host);
    } catch (e) { /** ignore */ }
  } catch (e) {
    console.log('[INCOMING] logging failed', e && e.message);
  }
  await next();
});

/* ---------------------------
   Utility: tolerant route registrar
   Registers a handler for path, /api/path, /api/api/path
   --------------------------- */
function register(method, path, ...handlers) {
  const m = method.toLowerCase();
  if (typeof app[m] !== 'function') throw new Error('Invalid method: ' + method);
  // primary path
  app[m](path, ...handlers);
  // with /api prefix
  app[m]('/api' + path, ...handlers);
  // defensive extra /api/api
  app[m]('/api/api' + path, ...handlers);
}

/* ---------------------------
   Auth middlewares
   --------------------------- */
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

/* ---------------------------
   Handlers (core)
   --------------------------- */

// LOGIN
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
    maxAge: 60 * 60 * 24,
  });

  return c.json({ success: true, message: 'Login berhasil', token });
}

// LOGOUT
async function logoutHandler(c) {
  setCookie(c, 'auth_token', '', { path: '/', secure: false, httpOnly: true, sameSite: 'Lax', maxAge: 0 });
  return c.json({ success: true, message: 'Logout berhasil' });
}

// STORE: products list
async function storeProductsHandler(c) {
  const env = c.env;
  try {
    const { results } = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
       FROM products p
       LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.is_active = 1
       ORDER BY p.name ASC`
    ).all();
    return c.json(results || []);
  } catch (e) {
    console.error('store/products error', e && e.message);
    return c.json({ error: 'Gagal mengambil data produk: ' + e.message }, 500);
  }
}

// STORE: product detail
async function storeProductDetailHandler(c) {
  const env = c.env;
  const id = c.req.param('id');
  try {
    const product = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.id = ? AND p.is_active = 1`
    ).bind(id).first();
    if (!product) return c.json({ error: 'Produk tidak ditemukan atau tidak aktif' }, 404);

    const { results: gallery } = await env.DB.prepare("SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
    return c.json({ ...product, gallery: gallery.map(r => r.image_url) });
  } catch (e) {
    console.error('store/product detail error', e && e.message);
    return c.json({ error: 'Gagal mengambil detail produk: ' + e.message }, 500);
  }
}

// STORE: checkout (ke Paspay)
async function storeCheckoutHandler(c) {
  const env = c.env;
  const body = c.req.valid('json'); // caller must use zValidator
  try {
    const product = await env.DB.prepare("SELECT id, name, price, product_type FROM products WHERE id = ? AND is_active = 1").bind(body.product_id).first();
    if (!product) return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);

    // Call external Paspay API
    const paspayPayload = {
      project_id: parseInt(env.PASPAY_PROJECT_ID, 10),
      payment_channel_id: [1, 3],
      amount: product.price,
      internal_ref_id: `MINI-${product.id}-${Math.floor(Date.now() / 1000)}`,
      description: `Pembelian: ${product.name}`,
      customer_email: body.email,
      customer_name: body.name || 'Customer',
    };

    const paspayResponse = await fetch(env.PASPAY_API_URL + '/transactions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.PASPAY_API_KEY}` },
      body: JSON.stringify(paspayPayload),
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

    // Lock stock for UNIQUE
    if (product.product_type === 'UNIQUE') {
      const stock = await env.DB.prepare("SELECT id FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1").bind(product.id).first();
      if (!stock) return c.json({ error: 'Stok produk ini telah habis!' }, 410);
      const { changes } = await env.DB.prepare("UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ? AND is_sold = 0").bind(newOrderId, stock.id).run();
      if (changes === 0) return c.json({ error: 'Stok produk baru saja habis. Silakan coba lagi.' }, 409);
    }

    return c.json(paspayResult);
  } catch (e) {
    console.error('checkout error', e && e.message);
    return c.json({ error: 'Terjadi kesalahan saat checkout: ' + e.message }, 500);
  }
}

// WEBHOOK (Paspay)
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
    console.error('Webhook failed', e && e.message);
    return c.json({ error: 'Internal Server Error: ' + e.message }, 500);
  }
}

/* ---------------------------
   Admin routes (protected)
   All admin handlers will be registered under:
     /admin/..., /api/admin/..., /api/api/admin/...
   via the register helper below.
   --------------------------- */

// Admin: list categories
async function adminListCategories(c) {
  const env = c.env;
  const { results } = await env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all();
  return c.json(results || []);
}
async function adminCreateCategory(c) {
  const env = c.env;
  const body = c.req.valid('json');
  const { results } = await env.DB.prepare("INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *").bind(body.name, body.slug).all();
  return c.json(results[0], 201);
}
async function adminUpdateCategory(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const { results } = await env.DB.prepare("UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *").bind(body.name, body.slug, id).all();
  return c.json(results[0]);
}
async function adminDeleteCategory(c) {
  const env = c.env; const id = c.req.param('id');
  await env.DB.prepare("DELETE FROM categories WHERE id = ?").bind(id).run();
  return c.json({ success: true, message: 'Kategori dihapus' });
}

// Admin: products list & CRUD
async function adminListProducts(c) {
  const env = c.env;
  const { results } = await env.DB.prepare(
    `SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC`
  ).all();
  return c.json(results || []);
}
async function adminGetProduct(c) {
  const env = c.env; const id = c.req.param('id');
  const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
  const { results: gallery } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  return c.json({ ...product, gallery: gallery || [] });
}
async function adminCreateProduct(c) {
  const env = c.env; const body = c.req.valid('json');
  const { results } = await env.DB.prepare(
    `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id, is_active)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
  ).bind(body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0).all();
  return c.json(results[0], 201);
}
async function adminUpdateProduct(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const { results } = await env.DB.prepare(
    `UPDATE products SET name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, is_active = ?
     WHERE id = ? RETURNING *`
  ).bind(body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, id).all();
  return c.json(results[0]);
}
async function adminDeleteProduct(c) {
  const env = c.env; const id = c.req.param('id');
  const statements = [
    env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id),
    env.DB.prepare("DELETE FROM product_stock_unique WHERE product_id = ?").bind(id),
    env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id),
  ];
  await env.DB.batch(statements);
  return c.json({ success: true, message: 'Produk (dan stok/galeri terkait) dihapus' });
}

// Admin: stock endpoints
async function adminListStock(c) {
  const env = c.env; const id = c.req.param('id');
  const { results } = await env.DB.prepare("SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC").bind(id).all();
  return c.json(results || []);
}
async function adminAddStock(c) {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const product = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND product_type = 'UNIQUE'").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan atau bukan tipe UNIQUE' }, 404);
  const statements = body.stock_items.map(content => env.DB.prepare("INSERT INTO product_stock_unique (product_id, content, is_sold) VALUES (?, ?, 0)").bind(id, content));
  if (statements.length === 0) return c.json({ error: 'Tidak ada stok yang diberikan' }, 400);
  await env.DB.batch(statements);
  return c.json({ success: true, message: `${statements.length} item stok ditambahkan` }, 201);
}
async function adminDeleteStock(c) {
  const env = c.env; const stockId = c.req.param('stockId');
  const { changes } = await env.DB.prepare("DELETE FROM product_stock_unique WHERE id = ? AND is_sold = 0").bind(stockId).run();
  if (changes === 0) return c.json({ error: 'Gagal menghapus stok (mungkin sudah terjual atau tidak ditemukan)' }, 404);
  return c.json({ success: true, message: 'Stok dihapus' });
}

// Admin: gallery endpoints
async function adminListGallery(c) {
  const env = c.env; const id = c.req.param('id');
  const { results } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  return c.json(results || []);
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

// Admin: orders & users
async function adminListOrders(c) {
  const env = c.env;
  const { results } = await env.DB.prepare(
    `SELECT o.*, p.name as product_name, u.email as user_email
     FROM orders o
     LEFT JOIN products p ON o.product_id = p.id
     LEFT JOIN users u ON o.user_id = u.id
     ORDER BY o.created_at DESC`
  ).all();
  return c.json(results || []);
}
async function adminListUsers(c) {
  const env = c.env;
  const { results } = await env.DB.prepare("SELECT id, email, name, role, status, created_at FROM users ORDER BY created_at DESC").all();
  return c.json(results || []);
}

/* ---------------------------
   Register all routes (tolerantly)
   --------------------------- */

// Public routes
register('post', '/login', loginHandler);
register('post', '/logout', logoutHandler);
register('get', '/health', (c) => c.json({ ok: true }));

// Store - public
register('get', '/store/products', storeProductsHandler);
register('get', '/store/products/:id', storeProductDetailHandler);
register('post', '/store/checkout', zValidator('json', checkoutSchema), storeCheckoutHandler);

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

// Admin - stock
register('get', '/admin/products/:id/stock', authMiddleware, adminMiddleware, adminListStock);
register('post', '/admin/products/:id/stock', authMiddleware, adminMiddleware, zValidator('json', stockSchema), adminAddStock);
register('delete', '/admin/stock/:stockId', authMiddleware, adminMiddleware, adminDeleteStock);

// Admin - gallery
register('get', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, adminListGallery);
register('post', '/admin/products/:id/gallery', authMiddleware, adminMiddleware, zValidator('json', gallerySchema), adminSyncGallery);
register('delete', '/admin/gallery/:imageId', authMiddleware, adminMiddleware, adminDeleteGallery);

// Admin - orders & users
register('get', '/admin/orders', authMiddleware, adminMiddleware, adminListOrders);
register('get', '/admin/users', authMiddleware, adminMiddleware, adminListUsers);

/* ---------------------------
   Fallback logging route
   --------------------------- */
app.all('*', (c) => {
  try {
    console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[NO MATCH.pathname]', u.pathname);
    } catch (e) {}
  } catch (e) {
    console.log('[NO MATCH] logging failed', e && e.message);
  }
  return c.json({ error: 'Not Found' }, 404);
});

/* ---------------------------
   Export handler
   --------------------------- */
export const onRequest = handle(app);
