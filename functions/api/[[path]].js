// functions/api/[[path]].js
// Robust store/products handler with verbose error logging for debugging.
// Deploy this file to functions/api/[[path]].js (Cloudflare Pages).
// TEMPORARY: returns stack traces in responses for debugging — remove before production.

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';

const app = new Hono();

// Logging middleware
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try { const u = new URL(c.req.url); console.log('[INCOMING.pathname]', u.pathname); } catch (e) {}
  } catch (e) {}
  await next();
});

// helper: safe .all() wrapper that preserves raw return so we can inspect shape
async function runAll(db, sql, params = []) {
  try {
    const raw = await db.prepare(sql).bind(...params).all();
    // raw might be: { results: [...] } OR an array [...]
    let rows = null;
    if (Array.isArray(raw)) {
      rows = raw;
    } else if (raw && Array.isArray(raw.results)) {
      rows = raw.results;
    } else if (raw && typeof raw === 'object' && raw.results) {
      rows = raw.results;
    } else {
      // unknown shape: return raw so we can inspect
      rows = raw;
    }
    return { ok: true, raw, rows };
  } catch (e) {
    return { ok: false, error: String(e && (e.message || e)) , stack: e && e.stack };
  }
}

// Debug route (protected by token query param) - set DEBUG_TOKEN env var and call ?token=...
app.get('/debug/db', async (c) => {
  const env = c.env;
  const token = c.req.query('token') || '';
  const expected = env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) return c.json({ error: 'Unauthorized. Set DEBUG_TOKEN and pass ?token=...' }, 401);

  if (!env.DB) return c.json({ error: 'No DB binding on env.DB' }, 500);

  const out = {};

  // counts
  try {
    const cntAll = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM products').first();
    const cntActive = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM products WHERE is_active = 1').first();
    out.counts = { total: cntAll?.cnt ?? 0, active_1: cntActive?.cnt ?? 0 };
  } catch (e) {
    out.counts_error = String(e && (e.message || e));
  }

  // sample rows and store query both ways
  out.sample_products = await runAll(env.DB, 'SELECT * FROM products ORDER BY id DESC LIMIT 50');
  out.sample_categories = await runAll(env.DB, 'SELECT * FROM categories ORDER BY id DESC LIMIT 50');
  out.sample_images = await runAll(env.DB, 'SELECT * FROM product_images ORDER BY id DESC LIMIT 50');

  const storeSql = `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.is_active = 1
    ORDER BY p.name ASC
  `;
  out.store_with_filter = await runAll(env.DB, storeSql);
  out.store_without_filter = await runAll(env.DB, `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    ORDER BY p.name ASC
  `);

  // PRAGMA table_info if supported
  try {
    const pragma = await env.DB.prepare("PRAGMA table_info('products')").all();
    out.products_table_info = pragma;
  } catch (e) {
    out.products_table_info_error = String(e && (e.message || e));
  }

  return c.json(out);
});

// Robust store/products handler
app.get('/store/products', async (c) => {
  const env = c.env;
  if (!env.DB) return c.json({ error: 'No DB binding (env.DB missing)' }, 500);

  // run query and normalize any shape returned by driver
  const sql = `
    SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    WHERE p.is_active = 1
    ORDER BY p.name ASC
  `;

  try {
    const result = await runAll(env.DB, sql);
    if (!result.ok) {
      console.error('DB query error', result.error, result.stack);
      // return debug info temporarily
      return c.json({ error: 'DB query failed', detail: result.error, stack: result.stack }, 500);
    }

    const rows = result.rows;

    // If rows is null or empty array, but raw contains other shape, include raw for debugging
    if (!rows || (Array.isArray(rows) && rows.length === 0)) {
      console.log('store/products: rows empty, returning raw for inspection', JSON.stringify(result.raw));
      // For debugging: if there are rows in raw.results, normalize; otherwise return empty array
      // But also include raw in response for debugging
      // WARNING: remove raw in production
      return c.json({ data: rows ?? [], raw: result.raw });
    }

    // Ensure rows is an array; map and return minimal fields
    const normalized = (Array.isArray(rows) ? rows : []).map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      price: typeof r.price === 'number' ? r.price : (r.price ? Number(r.price) : 0),
      image_url: r.image_url,
      category_name: r.category_name
    }));

    return c.json(normalized);
  } catch (e) {
    console.error('store/products unexpected error', e && e.stack);
    // TEMP: return stack trace to help debug
    return c.json({ error: 'Unexpected error', message: String(e && (e.message || e)), stack: e && e.stack }, 500);
  }
});

// Also register tolerant alias so frontend calling /api/store/products hits this handler
app.get('/api/store/products', async (c) => {
  return app.handle(c.req, c.env);
});
app.get('/api/api/store/products', async (c) => {
  return app.handle(c.req, c.env);
});

// Fallback
app.all('*', (c) => {
  return c.json({ error: 'Not Found' }, 404);
});

export const onRequest = handle(app);
