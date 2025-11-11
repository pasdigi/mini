/**
 * Debug Cloudflare Pages Function (temporary)
 * - Place at functions/api/debug_db.js
 * - Set Environment variable DEBUG_TOKEN in Pages to a secret string.
 * - Call: GET /api/debug/db?token=YOUR_DEBUG_TOKEN
 *
 * Returns:
 * - DB binding presence
 * - product counts
 * - PRAGMA table_info('products')
 * - sample rows
 * - the exact store query result
 *
 * REMOVE this file after debugging.
 */

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';

const app = new Hono();

function normalizeAllResult(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  return [];
}

app.use('*', async (c, next) => {
  try { console.log('[DEBUG-INCOMING] ', c.req.method, c.req.url); } catch (e) {}
  await next();
});

app.get('/debug/db', async (c) => {
  const env = c.env;
  const token = c.req.query('token') || '';
  const expected = env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) {
    return c.json({ error: 'Unauthorized. Set DEBUG_TOKEN env var and pass ?token=...' }, 401);
  }

  if (!env.DB) {
    return c.json({ error: 'DB binding "DB" not found on env' }, 500);
  }

  const out = {};
  try {
    // counts
    const cntAll = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM products').first().catch(e => ({ error: String(e && e.message) }));
    const cntActive = await env.DB.prepare('SELECT COUNT(*) AS cnt FROM products WHERE is_active = 1').first().catch(e => ({ error: String(e && e.message) }));
    out.counts = { total: cntAll?.cnt ?? cntAll, active_1: cntActive?.cnt ?? cntActive };

    // sample rows
    out.sample_products = normalizeAllResult(await env.DB.prepare('SELECT * FROM products ORDER BY id DESC LIMIT 50').all().catch(e => ({ error: String(e && e.message) })));

    // store query (the one used by store/products)
    const storeSql = `
      SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name
      FROM products p LEFT JOIN categories c ON p.category_id = c.id
      WHERE p.is_active = 1
      ORDER BY p.name ASC
    `;
    out.store_query = { sql: storeSql.trim(), result: normalizeAllResult(await env.DB.prepare(storeSql).all().catch(e => ({ error: String(e && e.message) }))) };

    // pragma info
    out.products_table_info = normalizeAllResult(await env.DB.prepare("PRAGMA table_info('products')").all().catch(e => ({ error: String(e && e.message) })));

    return c.json(out);
  } catch (e) {
    console.error('[DEBUG] unexpected', e && e.stack);
    return c.json({ error: 'Unexpected error', detail: String(e && e.message), stack: e && e.stack }, 500);
  }
});

// also expose tolerant alias
app.get('/api/debug/db', async (c) => {
  return app.handle(c.req, c.env);
});

export const onRequest = handle(app);
