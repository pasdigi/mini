import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';

/*
 Temporary debug + robust handler for /store/products
 - Wraps all handlers with try/catch and returns stack trace in JSON (for debugging).
 - Logs incoming path and raw DB result.
 - Registers both /store/products and /api/store/products aliases.
 
 IMPORTANT: This file returns stack traces in responses for debugging.
 Remove debug info and revert to production-safe responses after issue is fixed.
*/

const app = new Hono();

// Logging + global error wrapper middleware
app.use('*', async (c, next) => {
  try {
    console.log('[INCOMING] method=', c.req.method, 'url=', c.req.url);
    try {
      const u = new URL(c.req.url);
      console.log('[INCOMING.pathname]', u.pathname);
    } catch (e) { /* ignore */ }

    // execute next handler and catch runtime errors
    try {
      const res = await next();
      return res;
    } catch (handlerErr) {
      // Log the error server-side
      console.error('[HANDLER ERROR]', handlerErr && (handlerErr.stack || handlerErr.message || handlerErr));
      // Return JSON with details temporarily for debugging
      return c.json({ error: String(handlerErr && handlerErr.message || handlerErr || 'Handler error'), stack: handlerErr && handlerErr.stack }, 500);
    }
  } catch (e) {
    // If logging itself fails, still attempt to run next
    console.error('[MIDDLEWARE LOGGING ERROR]', e && e.stack);
    try {
      return await next();
    } catch (handlerErr) {
      console.error('[HANDLER ERROR 2]', handlerErr && handlerErr.stack);
      return c.json({ error: String(handlerErr && handlerErr.message || handlerErr), stack: handlerErr && handlerErr.stack }, 500);
    }
  }
});

// Helper to run .all() and normalize different driver shapes
async function runAllAndNormalize(db, sql, params = []) {
  const raw = await db.prepare(sql).bind(...params).all();
  console.log('[DB RAW]', JSON.stringify(raw));
  // raw might be { results: [...] } or an array, or other shape
  if (Array.isArray(raw)) return raw;
  if (raw && Array.isArray(raw.results)) return raw.results;
  // If raw has no results array, try to find nested results
  if (raw && raw?.results === undefined && typeof raw === 'object') {
    // return object as single-element array so frontend sees something
    return [raw];
  }
  return [];
}

// Primary handler: list products (no strict filtering) - for debugging we avoid tight WHERE
async function storeProductsHandler(c) {
  const env = c.env;
  if (!env || !env.DB) {
    throw new Error('DB binding "DB" not found in env');
  }

  // Try multiple queries: first the intended one, then fallback
  const queries = [
    // original intended query (with is_active filter)
    `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
     FROM products p
     LEFT JOIN categories c ON p.category_id = c.id
     WHERE p.is_active = 1
     ORDER BY p.name ASC`,
    // fallback: without filter
    `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
     FROM products p
     LEFT JOIN categories c ON p.category_id = c.id
     ORDER BY p.name ASC`,
    // extra fallback: select all columns from products (to inspect schema)
    `SELECT * FROM products ORDER BY id DESC LIMIT 100`
  ];

  for (let i = 0; i < queries.length; i++) {
    const sql = queries[i];
    try {
      const rows = await runAllAndNormalize(env.DB, sql);
      console.log(`[QUERY ${i}] returned ${Array.isArray(rows) ? rows.length : typeof rows}`);
      // if we have any rows, normalize shape and return
      if (Array.isArray(rows) && rows.length > 0) {
        const normalized = rows.map(r => ({
          id: r.id,
          name: r.name ?? r.title ?? null,
          description: r.description ?? null,
          price: (typeof r.price === 'number') ? r.price : (r.price ? Number(r.price) : null),
          image_url: r.image_url ?? r.image ?? r.imageUrl ?? null,
          category_name: r.category_name ?? r.category ?? null,
          is_active: r.is_active ?? r.active ?? null,
          raw: r
        }));
        // Also log normalized sample to pages logs
        console.log('[NORMALIZED SAMPLE]', JSON.stringify(normalized.slice(0, 5)));
        return c.json({ sourceQueryIndex: i, count: normalized.length, products: normalized });
      }
    } catch (qerr) {
      // log and continue to next fallback query
      console.error(`[QUERY ${i}] error:`, qerr && (qerr.stack || qerr.message || qerr));
      // expose error for debugging
      return c.json({ error: `Query failed (index ${i})`, message: String(qerr && (qerr.message || qerr)), stack: qerr && qerr.stack }, 500);
    }
  }

  // If reach here, no rows found from any query
  return c.json({ count: 0, products: [] });
}

// Register routes (both forms)
app.get('/store/products', storeProductsHandler);
app.get('/api/store/products', storeProductsHandler);
app.get('/api/api/store/products', storeProductsHandler);

// Optional debug route to inspect raw tables (protected by query token if you set one)
app.get('/debug/db', async (c) => {
  const token = c.req.query('token') || '';
  const expected = c.env.DEBUG_TOKEN || '';
  if (!expected || token !== expected) return c.json({ error: 'Unauthorized - set DEBUG_TOKEN env var and pass ?token=...' }, 401);
  if (!c.env.DB) return c.json({ error: 'DB binding not found' }, 500);

  const out = {};
  try {
    out.products = await runAllAndNormalize(c.env.DB, 'SELECT * FROM products ORDER BY id DESC LIMIT 50');
    out.categories = await runAllAndNormalize(c.env.DB, 'SELECT * FROM categories ORDER BY id DESC LIMIT 50');
    out.product_images = await runAllAndNormalize(c.env.DB, 'SELECT * FROM product_images ORDER BY id DESC LIMIT 50');
  } catch (e) {
    console.error('debug/db error', e && e.stack);
    return c.json({ error: 'debug query failed', message: String(e && e.message), stack: e && e.stack }, 500);
  }
  return c.json(out);
});

// Fallback
app.all('*', (c) => c.json({ error: 'Not Found' }, 404));

export const onRequest = handle(app);
