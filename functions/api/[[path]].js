// Debug + robust store/products handler - paste ini into your existing functions/api/[[path]].js
// or replace the store/products handler with this one temporarily.
// This route prints DB shapes and sample rows so we can see why results are [].

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';

const app = new Hono();

// Logging middleware
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING]', c.req.method, c.req.url);
    try { const u = new URL(c.req.url); console.log('[INCOMING.pathname]', u.pathname); } catch (e) {}
  } catch (e) {}
  await next();
});

// Helper wrappers
async function safeAll(db, sql, params = []) {
  try {
    const res = await db.prepare(sql).bind(...params).all();
    // return raw object to inspect shape
    return { ok: true, raw: res, results: res.results ?? null };
  } catch (e) {
    return { ok: false, error: String(e && (e.message || e)) };
  }
}
async function safeFirst(db, sql, params = []) {
  try {
    const row = await db.prepare(sql).bind(...params).first();
    return { ok: true, row };
  } catch (e) {
    return { ok: false, error: String(e && (e.message || e)) };
  }
}

// Debug route (protected by token query param)
app.get('/debug/db', async (c) => {
  const env = c.env;
  const token = c.req.query('token') || '';
  const expected = env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) {
    return c.json({ error: 'Unauthorized - set DEBUG_TOKEN env var and pass ?token=...' }, 401);
  }
  if (!env.DB) return c.json({ error: 'No DB binding (env.DB not present)' }, 500);

  const out = {};

  // schema info (if supported)
  out.products_table_info = await safeAll(env.DB, "PRAGMA table_info('products')");

  // counts
  const cntAll = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM products');
  const cntActive = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM products WHERE is_active = 1');
  out.counts = {
    products_total: cntAll.ok ? (cntAll.row?.cnt ?? 0) : cntAll.error,
    products_active_1: cntActive.ok ? (cntActive.row?.cnt ?? 0) : cntActive.error
  };

  // sample rows
  out.sample_products = await safeAll(env.DB, 'SELECT * FROM products ORDER BY id DESC LIMIT 50');
  out.sample_categories = await safeAll(env.DB, 'SELECT * FROM categories ORDER BY id DESC LIMIT 50');
  out.sample_images = await safeAll(env.DB, 'SELECT * FROM product_images ORDER BY id DESC LIMIT 50');
  out.sample_stock = await safeAll(env.DB, 'SELECT * FROM product_stock_unique ORDER BY id DESC LIMIT 50');

  // the exact store query (with and without is_active filter)
  const storeSql = `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.is_active = 1
    ORDER BY p.name ASC
  `;
  out.store_query_with_filter = await safeAll(env.DB, storeSql);
  out.store_query_without_filter = await safeAll(env.DB, `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    ORDER BY p.name ASC
  `);

  return c.json(out);
});

// Robust store/products handler
app.get('/store/products', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'No DB binding' }, 500);
  try {
    // Use explicit prepare().all() and log raw response
    const raw = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
       FROM products p
       LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.is_active = 1
       ORDER BY p.name ASC`
    ).all();
    console.log('DB.raw store/products:', JSON.stringify(raw, null, 2));
    // Normalise: if driver returns { results } or returns array directly
    const rows = raw.results ?? raw;
    // If rows is an object (unlikely), convert if it has .results property deeper
    if (Array.isArray(rows)) return c.json(rows);
    // fallback: try to return raw.results or empty
    return c.json(raw.results ?? raw ?? []);
  } catch (e) {
    console.error('store/products error', e && e.message);
    return c.json({ error: 'Internal Server Error: ' + (e && e.message) }, 500);
  }
});
// Also register tolerant alias in case
app.get('/api/store/products', async (c) => {
  return app.handle(c.req, c.env);
});
app.get('/api/api/store/products', async (c) => {
  return app.handle(c.req, c.env);
});

// Fallback
app.all('*', (c) => c.json({ error: 'Not Found' }, 404));

export const onRequest = handle(app);
