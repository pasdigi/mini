// Debug-enabled functions file (add or replace in functions/api/[[path]].js)
// IMPORTANT: set an env var DEBUG_TOKEN in your Pages environment (random secret).
// Then call: https://<your-site>/api/debug/db?token=THE_SECRET
// The route returns counts, sample rows and schema info for quick debugging.

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';

const app = new Hono();

// Simple logging middleware
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING]', c.req.method, c.req.url);
    try { const u = new URL(c.req.url); console.log('[INCOMING.pathname]', u.pathname); } catch (e) {}
  } catch (e) {}
  await next();
});

// Helper to run a query and return results safely
async function safeAll(db, sql, params = []) {
  try {
    const { results } = await db.prepare(sql).bind(...params).all();
    return { ok: true, results: results || [] };
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

// Protected debug route
app.get('/debug/db', async (c) => {
  const env = c.env;
  const token = c.req.query('token') || '';
  const expected = env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) {
    return c.json({ error: 'Unauthorized. Provide ?token=... and set DEBUG_TOKEN env var' }, 401);
  }

  if (!env.DB) {
    return c.json({ error: 'No DB binding found on env.DB' }, 500);
  }

  const out = {};

  // counts
  const cntProducts = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM products');
  const cntCategories = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM categories');
  const cntImages = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM product_images');
  const cntStock = await safeFirst(env.DB, 'SELECT COUNT(*) as cnt FROM product_stock_unique');

  out.counts = {
    products: cntProducts.ok ? (cntProducts.row?.cnt ?? 0) : cntProducts.error,
    categories: cntCategories.ok ? (cntCategories.row?.cnt ?? 0) : cntCategories.error,
    product_images: cntImages.ok ? (cntImages.row?.cnt ?? 0) : cntImages.error,
    product_stock_unique: cntStock.ok ? (cntStock.row?.cnt ?? 0) : cntStock.error,
  };

  // sample rows
  const sampleProducts = await safeAll(env.DB, 'SELECT * FROM products ORDER BY id DESC LIMIT 50');
  const sampleCategories = await safeAll(env.DB, 'SELECT * FROM categories ORDER BY id DESC LIMIT 50');
  const sampleImages = await safeAll(env.DB, 'SELECT * FROM product_images ORDER BY id DESC LIMIT 50');
  const sampleStock = await safeAll(env.DB, 'SELECT * FROM product_stock_unique ORDER BY id DESC LIMIT 50');

  out.samples = {
    products: sampleProducts,
    categories: sampleCategories,
    product_images: sampleImages,
    product_stock_unique: sampleStock,
  };

  // The exact query used by the store endpoint
  const storeQuery = `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.is_active = 1
    ORDER BY p.name ASC
  `;
  const storeSamples = await safeAll(env.DB, storeQuery);
  out.store_query = { sql: storeQuery.trim(), result: storeSamples };

  // optional: show schema info if supported
  const pragma = await safeAll(env.DB, "PRAGMA table_info('products')");
  out.products_table_info = pragma;

  return c.json(out);
});

// Also register /api/debug/db just in case
app.get('/api/debug/db', async (c) => {
  // redirect to /debug/db so logic centralized
  return app.handle(c.req, c.env);
});

// Provide the store/products route as typical (returns array)
app.get('/store/products', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'No DB binding' }, 500);
  try {
    const { results } = await env.DB.prepare(
      `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       WHERE p.is_active = 1 ORDER BY p.name ASC`
    ).all();
    return c.json(results || []);
  } catch (e) {
    console.error('store/products error', e && e.message);
    return c.json({ error: 'Internal Server Error: ' + (e && e.message) }, 500);
  }
});
app.get('/api/store/products', async (c) => {
  return app.handle(c.req, c.env); // ensure tolerant mapping hits same handler
});

// Fallback
app.all('*', (c) => {
  return c.json({ error: 'Not Found' }, 404);
});

export const onRequest = handle(app);
