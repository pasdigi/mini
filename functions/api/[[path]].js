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

// --- Crypto utils ---
const bufferToHex = (buffer) => {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
};
const hexToBuffer = (hex) => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes.buffer;
};

const verifyPassword = async (password, storedHash) => {
  try {
    const [saltHex, hashHex] = storedHash.split(':');
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

// --- Zod schemas ---
const loginSchema = z.object({ email: z.string().email('Format email tidak valid'), password: z.string().min(1, 'Password wajib diisi') });
const checkoutSchema = z.object({ product_id: z.number().int().positive('ID Produk tidak valid'), email: z.string().email('Format email tidak valid'), name: z.string().optional() });
const paspayWebhookSchema = z.object({ event: z.string(), data: z.object({ reference_id: z.string() }).optional() });
const categorySchema = z.object({ name: z.string().min(1, 'Nama kategori wajib diisi'), slug: z.string().min(1, 'Slug wajib diisi') });
const productSchema = z.object({
  name: z.string().min(1), price: z.number().positive(), product_type: z.enum(['STANDARD','UNIQUE']),
  description: z.string().optional().nullable(), digital_content: z.string().optional().nullable(),
  image_url: z.string().optional().nullable(), category_id: z.number().int().optional().nullable(), is_active: z.boolean().optional().default(true)
});
const stockSchema = z.object({ stock_items: z.array(z.string().min(1)) });
const gallerySchema = z.object({ images: z.array(z.string().url()) });

// --- App init ---
// Do NOT set basePath('/api') here because CF Pages functions in functions/api/[[path]].js
// will be invoked for /api/*; we provide aliases below instead.
const app = new Hono();

// --- Debug logging middleware ---
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING]', c.req.method, c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname);
    } catch (_) {}
  } catch (e) {
    console.log('[INCOMING] error reading url', e && e.message);
  }
  await next();
});

// --- Helper: register alias routes (with and without /api prefix) ---
function register(method, path, handler) {
  // Register original path
  app[method](path, handler);
  // Register with /api prefix as alias
  const apiPath = '/api' + path;
  app[method](apiPath, handler);
}

// --- Auth middleware ---
const authMiddleware = async (c, next) => {
  const env = c.env;
  const token = getCookie(c, 'auth_token');
  console.log('[AUTH] token present=', Boolean(token));
  if (!token) return c.json({ error: 'Tidak terotentikasi' }, 401);
  try {
    const payload = await verify(token, env.JWT_SECRET, 'HS256');
    const user = await env.DB.prepare("SELECT id, role, status FROM users WHERE id = ?").bind(payload.sub).first();
    if (!user) { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ error: 'User tidak ditemukan' }, 401); }
    if (user.status !== 'active') { setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); return c.json({ error: 'Akun Anda nonaktif atau di-suspend' }, 403); }
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

// --- Public routes ---
// LOGIN (register alias)
register('post', '/login', zValidator('json', loginSchema), async (c) => {
  const env = c.env;
  const body = c.req.valid('json');
  const user = await env.DB.prepare("SELECT id, password_hash, role, status FROM users WHERE email = ?").bind(body.email).first();
  if (!user) return c.json({ error: 'Email atau password salah' }, 401);
  const ok = await verifyPassword(body.password, user.password_hash);
  if (!ok) return c.json({ error: 'Email atau password salah' }, 401);
  if (user.status !== 'active') return c.json({ error: 'Akun Anda nonaktif atau di-suspend' }, 403);

  const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + (60*60*24) };
  const token = await sign(payload, env.JWT_SECRET, 'HS256');

  // If running in dev without TLS, secure should be false; keep secure:true for prod.
  const isDev = (typeof process !== 'undefined' && process.env.NODE_ENV === 'development');
  setCookie(c, 'auth_token', token, { path: '/', secure: !isDev, httpOnly: true, sameSite: 'Lax', maxAge: 60*60*24 });
  return c.json({ success: true, message: 'Login berhasil' });
});

// Logout
register('post', '/logout', (c) => {
  setCookie(c, 'auth_token', '', { path: '/', secure: false, httpOnly: true, sameSite: 'Lax', maxAge: 0 });
  return c.json({ success: true, message: 'Logout berhasil' });
});

// Store routes
register('get', '/store/products', async (c) => {
  const env = c.env;
  try {
    const { results } = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.image_url, c.name as category_name
       FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.is_active = 1`
    ).all();
    return c.json(results || []);
  } catch (e) {
    console.error('store/products error', e && e.message);
    return c.json({ error: 'Gagal mengambil data produk: ' + e.message }, 500);
  }
});

register('get', '/store/products/:id', async (c) => {
  const env = c.env; const id = c.req.param('id');
  try {
    const product = await env.DB.prepare(
      `SELECT p.id,p.name,p.price,p.description,p.image_url,c.name as category_name
       FROM products p LEFT JOIN categories c ON p.category_id = c.id WHERE p.id = ? AND p.is_active = 1`
    ).bind(id).first();
    if (!product) return c.json({ error: 'Produk tidak ditemukan atau tidak aktif' }, 404);
    const { results: gallery } = await env.DB.prepare("SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
    const { digital_content, ...pub } = product;
    return c.json({ ...pub, gallery: gallery.map(g => g.image_url) });
  } catch (e) { console.error('store detail error', e && e.message); return c.json({ error: 'Gagal mengambil detail produk: ' + e.message }, 500); }
});

register('post', '/store/checkout', zValidator('json', checkoutSchema), async (c) => {
  const env = c.env; const body = c.req.valid('json'); const now = Math.floor(Date.now()/1000);
  const product = await env.DB.prepare("SELECT id,name,price,product_type FROM products WHERE id = ? AND is_active = 1").bind(body.product_id).first();
  if (!product) return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);
  try {
    const paspayPayload = { project_id: parseInt(c.env.PASPAY_PROJECT_ID,10), payment_channel_id: [1,3], amount: product.price, internal_ref_id: `MINI-${product.id}-${now}`, description: `Pembelian: ${product.name}`, customer_email: body.email, customer_name: body.name || 'Customer' };
    const paspayResponse = await fetch(env.PASPAY_API_URL + '/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${env.PASPAY_API_KEY}` }, body: JSON.stringify(paspayPayload) });
    const paspayResult = await paspayResponse.json();
    if (!paspayResponse.ok) { console.error('Paspay error', paspayResult); return c.json({ error: 'Gagal membuat invoice Paspay', detail: paspayResult.error || 'Unknown' }, 500); }
    const { meta } = await env.DB.prepare(`INSERT INTO orders (product_id, status, paspay_reference_id, total_amount, customer_email, created_at, user_id) VALUES (?, 'UNPAID', ?, ?, ?, ?, 0)`).bind(product.id, paspayResult.reference_id, paspayResult.total_amount_expected, body.email, now).run();
    const newOrderId = meta.last_row_id; if (!newOrderId) return c.json({ error: 'Gagal menyimpan order' }, 500);

    if (product.product_type === 'UNIQUE') {
      const stock = await env.DB.prepare("SELECT id FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1").bind(product.id).first();
      if (!stock) return c.json({ error: 'Stok produk ini telah habis!' }, 410);
      const { changes } = await env.DB.prepare("UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ? AND is_sold = 0").bind(newOrderId, stock.id).run();
      if (changes === 0) return c.json({ error: 'Stok produk baru saja habis. Silakan coba lagi.' }, 409);
    }

    return c.json(paspayResult);
  } catch (e) { console.error('checkout error', e && e.message); return c.json({ error: 'Terjadi kesalahan saat checkout: ' + e.message }, 500); }
});

// Webhook
register('post', '/webhook/paspay', zValidator('json', paspayWebhookSchema), async (c) => {
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
    if (product.product_type === 'STANDARD') delivered_content = product.digital_content;
    else {
      const stock = await env.DB.prepare("SELECT content FROM product_stock_unique WHERE order_id = ? AND product_id = ?").bind(order.id, product.id).first();
      if (!stock) { console.error('Webhook stock missing', order.id); return c.json({ error: 'Stok internal tidak ditemukan' }, 500); }
      delivered_content = stock.content;
    }
    await env.DB.prepare("UPDATE orders SET status = 'PAID', delivered_content = ? WHERE id = ?").bind(delivered_content, order.id).run();
    console.log(`Webhook delivered to ${order.customer_email}`);
    return c.json({ success: true, message: 'Webhook diproses' }, 200);
  } catch (e) { console.error('webhook error', e && e.message); return c.json({ error: 'Internal Server Error: ' + e.message }, 500); }
});

// --- Admin router (apply auth & admin middleware) ---
// We also mount adminRouter both at '/admin' and '/api/admin' via register below
const adminRouter = new Hono();
adminRouter.use('*', authMiddleware, adminMiddleware);

adminRouter.get('/categories', async (c) => {
  const env = c.env;
  const { results } = await env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all();
  return c.json(results || []);
});
adminRouter.post('/categories', zValidator('json', categorySchema), async (c) => {
  const env = c.env; const body = c.req.valid('json');
  const { results } = await env.DB.prepare("INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *").bind(body.name, body.slug).all();
  return c.json(results[0], 201);
});
adminRouter.put('/categories/:id', zValidator('json', categorySchema), async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const { results } = await env.DB.prepare("UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *").bind(body.name, body.slug, id).all();
  return c.json(results[0]);
});
adminRouter.delete('/categories/:id', async (c) => {
  const env = c.env; const id = c.req.param('id'); await env.DB.prepare("DELETE FROM categories WHERE id = ?").bind(id).run(); return c.json({ success: true, message: 'Kategori dihapus' });
});

// products admin
adminRouter.get('/products', async (c) => {
  const env = c.env;
  const { results } = await env.DB.prepare(`SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC`).all();
  return c.json(results || []);
});
adminRouter.get('/products/:id', async (c) => {
  const env = c.env; const id = c.req.param('id'); const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
  const { results: gallery } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  return c.json({ ...product, gallery: gallery || [] });
});
adminRouter.post('/products', zValidator('json', productSchema), async (c) => {
  const env = c.env; const body = c.req.valid('json');
  const { results } = await env.DB.prepare(`INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
    .bind(body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0).all();
  return c.json(results[0], 201);
});
adminRouter.put('/products/:id', zValidator('json', productSchema), async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const { results } = await env.DB.prepare(`UPDATE products SET name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, is_active = ? WHERE id = ? RETURNING *`)
    .bind(body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, id).all();
  return c.json(results[0]);
});
adminRouter.delete('/products/:id', async (c) => {
  const env = c.env; const id = c.req.param('id');
  const statements = [ env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id), env.DB.prepare("DELETE FROM product_stock_unique WHERE product_id = ?").bind(id), env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id) ];
  await env.DB.batch(statements);
  return c.json({ success: true, message: 'Produk (dan stok/galeri terkait) dihapus' });
});

// stock & gallery etc. (same as earlier)...
adminRouter.get('/products/:id/stock', async (c) => {
  const env = c.env; const id = c.req.param('id');
  const { results } = await env.DB.prepare("SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC").bind(id).all();
  return c.json(results || []);
});
adminRouter.post('/products/:id/stock', zValidator('json', stockSchema), async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const product = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND product_type = 'UNIQUE'").bind(id).first();
  if (!product) return c.json({ error: 'Produk tidak ditemukan atau bukan tipe UNIQUE' }, 404);
  const statements = body.stock_items.map(content => env.DB.prepare("INSERT INTO product_stock_unique (product_id, content, is_sold) VALUES (?, ?, 0)").bind(id, content));
  if (statements.length === 0) return c.json({ error: 'Tidak ada stok yang diberikan' }, 400);
  await env.DB.batch(statements);
  return c.json({ success: true, message: `${statements.length} item stok ditambahkan` }, 201);
});
adminRouter.delete('/stock/:stockId', async (c) => {
  const env = c.env; const stockId = c.req.param('stockId');
  const { changes } = await env.DB.prepare("DELETE FROM product_stock_unique WHERE id = ? AND is_sold = 0").bind(stockId).run();
  if (changes === 0) return c.json({ error: 'Gagal menghapus stok (mungkin sudah terjual atau tidak ditemukan)' }, 404);
  return c.json({ success: true, message: 'Stok dihapus' });
});

adminRouter.get('/products/:id/gallery', async (c) => {
  const env = c.env; const id = c.req.param('id');
  const { results } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC").bind(id).all();
  return c.json(results || []);
});
adminRouter.post('/products/:id/gallery', zValidator('json', gallerySchema), async (c) => {
  const env = c.env; const id = c.req.param('id'); const body = c.req.valid('json');
  const deleteStmt = env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id);
  const insertStmts = body.images.map((url, index) => env.DB.prepare("INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)").bind(id, url, index));
  await env.DB.batch([deleteStmt, ...insertStmts]);
  return c.json({ success: true, message: `Galeri disinkronkan (${insertStmts.length} gambar)` }, 201);
});
adminRouter.delete('/gallery/:imageId', async (c) => {
  const env = c.env; const imageId = c.req.param('imageId');
  await env.DB.prepare("DELETE FROM product_images WHERE id = ?").bind(imageId).run();
  return c.json({ success: true, message: 'Gambar Galeri Dihapus' });
});
adminRouter.get('/orders', async (c) => {
  const env = c.env;
  const { results } = await env.DB.prepare(`SELECT o.*, p.name as product_name, u.email as user_email FROM orders o LEFT JOIN products p ON o.product_id = p.id LEFT JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`).all();
  return c.json(results || []);
});
adminRouter.get('/users', async (c) => {
  const env = c.env;
  const { results } = await env.DB.prepare("SELECT id, email, name, role, status, created_at FROM users ORDER BY created_at DESC").all();
  return c.json(results || []);
});

// mount admin both as '/admin' and '/api/admin' to make sure both variants work
app.route('/admin', adminRouter);
app.route('/api/admin', adminRouter);

// --- Fallback (logs + 404) ---
app.all('*', (c) => {
  try {
    console.log('[NO MATCH] method=', c.req.method, 'url=', c.req.url);
    try { const u = new URL(c.req.url); console.log('[NO MATCH.pathname]', u.pathname); } catch (_) {}
  } catch (e) {
    console.log('[NO MATCH] logging failed', e && e.message);
  }
  return c.json({ error: 'Not Found' }, 404);
});

// --- Export handler ---
export const onRequest = handle(app);
