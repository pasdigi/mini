/**
 * functions/[[path]].js
 *
 * Hono backend LENGKAP untuk Cloudflare Pages, mengikuti arsitektur file tunggal.
 * - Menangani semua rute API di bawah /api
 * - Menangani rute /product/* secara spesifik (dinamis)
 * - Menyajikan file statis dari /public
 * - SEMUA ZOD DAN VALIDATOR DIHAPUS.
 *
 * Catatan: Rute dinamis /product/:slug harus diletakkan SEBELUM app.get('*', serveStatic)
 * untuk menghindari fallback ke file statis.
 */

import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { serveStatic } from 'hono/cloudflare-pages';

// --- Inisialisasi Hono ---
const app = new Hono();
// Semua rute API sekarang ada di bawah /api
const api = app.basePath('/api');


/* -------------------------
    Utilities (Tidak Berubah)
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
    Logging middleware (Tidak Berubah)
    ------------------------- */
app.use('*', async (c, next) => {
    try {
        console.log(`[REQ START] ${c.req.method} ${c.req.url}`);
    } catch (e) {}
    await next();
    console.log(`[REQ END] ${c.req.method} ${c.req.url} - Status: ${c.res.status}`);
});

/* -------------------------
    PENANGANAN ERROR GLOBAL
    ------------------------- */
app.onError((err, c) => {
    console.error('======================================');
    console.error(`[GLOBAL ERROR] Terjadi error pada: ${c.req.method} ${c.req.url}`);
    console.error('Pesan Error:', err.message);
    console.error('Stack Trace:', err.stack);
    console.error('======================================');
    return c.json({ error: 'Internal Server Error', message: err.message }, 500);
});

/* -------------------------
    Auth middlewares
    ------------------------- */
const authMiddleware = async (c, next) => {
    const env = c.env;
    const token = getCookie(c, 'auth_token');
    if (!token) return c.json({ error: 'Tidak terotentikasi' }, 401);
    try {
        const payload = await verify(token, env.JWT_SECRET, 'HS256');
        
        // MENGAMBIL SEMUA KOLOM USER BARU (TERMASUK UNTUK PENGEMBANGAN MASA DEPAN)
        const user = await env.DB.prepare(
            `SELECT 
                id, email, name, role, status, created_at,
                phone, gender, address_line_1, address_line_2, city, province, country, zip_code,
                auth_token, refresh_token, telegram_user_id, google_user_id
             FROM users WHERE id = ?`
        ).bind(payload.sub).first();
        
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
    Public: Store handlers
    ------------------------- */
async function storeBannersHandler(c) {
    const env = c.env;
    if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
    try {
        const raw = await env.DB.prepare(
            `SELECT id, banner_name, banner_description, banner_image_url, banner_link
             FROM banners WHERE is_active = 1 ORDER BY sort_order ASC`
        ).all();
        return c.json(normalizeAllResult(raw));
    } catch (e) {
        if (e.message.includes('no such table')) return c.json([]);
        console.error('[STORE BANNERS CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

async function storeProductsHandler(c) {
    const env = c.env;
    if (!env.DB) return c.json({ error: 'DB binding not found' }, 500);
    try {
        const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
        const sql = hasIsActive
            ?
            `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.rating, p.review_count, p.is_featured
               FROM products p LEFT JOIN categories c ON p.category_id = c.id
               WHERE (p.is_active IS NULL OR p.is_active = 1) ORDER BY p.name ASC`
            : `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.rating, p.review_count, p.is_featured
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
            category_name: r.category_name ?? null,
            rating: r.rating ? Number(r.rating) : 4.5,
            review_count: r.review_count ? Number(r.review_count) : 29,
            is_featured: r.is_featured === 1 || r.is_featured === '1'
        }));
        return c.json(normalized);
    } catch (e) {
        console.error('[STORE PRODUCTS CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

async function storeProductByIdHandler(c) {
    const env = c.env;
    const id = c.req.param('id');
    try {
        const p = await env.DB.prepare(
            `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type, p.rating, p.review_count, p.is_featured
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
            rating: p.rating ? Number(p.rating) : 4.5,
            review_count: p.review_count ? Number(p.review_count) : 29,
            is_featured: p.is_featured === 1 || p.is_featured === '1',
            gallery
        });
    } catch (e) {
        console.error('[STORE PRODUCT BY ID CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

async function storeProductBySlugHandler(c) {
    const env = c.env;
    const slug = c.req.param('slug');
    try {
        const p = await env.DB.prepare(
            `SELECT p.id, p.slug, p.name, p.price, p.description, p.image_url, c.name as category_name, p.digital_content, p.product_type, p.rating, p.review_count, p.is_featured
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
            rating: p.rating ? Number(p.rating) : 4.5,
            review_count: p.review_count ? Number(p.review_count) : 29,
            is_featured: p.is_featured === 1 || p.is_featured === '1',
            gallery
        });
    } catch (e) {
        console.error('[STORE PRODUCT BY SLUG CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

/* -------------------------
    Auth handlers (Validasi manual TANPA ZOD)
    ------------------------- */
async function loginHandler(c) {
    console.log('[LOGIN HANDLER] Mulai.');
    const env = c.env;
    let body;
    try {
        body = await c.req.json();
        console.log('[LOGIN HANDLER] 1. Body JSON berhasil di-parse.');
    } catch (e) {
        console.error('[LOGIN HANDLER] GAGAL parse JSON body:', e.message);
        return c.json({ error: 'Invalid JSON' }, 400);
    }
    
    if (!body || !body.email || !body.password) {
        return c.json({ error: 'Email dan password wajib diisi' }, 400);
    }

    try {
        if (!env.DB) {
            throw new Error('Database binding (DB) tidak ditemukan.');
        }
        
        // MENGAMBIL SEMUA KOLOM USER BARU UNTUK PROSES AUTH
        const user = await env.DB.prepare(
            `SELECT 
                id, password_hash, role, status, 
                phone, gender, address_line_1, address_line_2, city, province, country, zip_code,
                auth_token, refresh_token, telegram_user_id, google_user_id
             FROM users WHERE email = ?`
        ).bind(body.email).first();
        
        if (!user) {
            return c.json({ error: 'Email atau password salah' }, 401);
        }

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

        if (!verified) {
            return c.json({ error: 'Email atau password salah' }, 401);
        }

        if (user.status !== 'active') {
            return c.json({ error: 'Akun tidak aktif' }, 403);
        }
        
        if (!env.JWT_SECRET) {
            throw new Error('JWT_SECRET environment variable tidak di-set.');
        }
        
        const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 };
        const token = await sign(payload, env.JWT_SECRET, 'HS256');

        const isDev = (typeof process !== 'undefined' && process.env.NODE_ENV === 'development') ||
            (c.req.header('host') || '').includes('localhost');

        setCookie(c, 'auth_token', token, { path: '/', httpOnly: true, secure: !isDev, sameSite: 'Lax', maxAge: 60 * 60 * 24 });
        
        return c.json({ success: true, message: 'Login berhasil' });
        
    } catch (e) {
        console.error('======================================');
        console.error('[LOGIN HANDLER CRASH]');
        console.error('Pesan Error:', e.message);
        console.error('Stack Trace:', e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

async function logoutHandler(c) {
    setCookie(c, 'auth_token', '', { path: '/', secure: false, httpOnly: true, sameSite: 'Lax', maxAge: 0 });
    return c.json({ success: true, message: 'Logout berhasil' });
}

// BARU: Handler Registrasi Member
async function registerHandler(c) {
    const env = c.env;
    const body = await c.req.json().catch(() => null);

    if (!body || !body.name || !body.email || !body.password) {
        return c.json({ error: 'Nama, email, dan password wajib diisi' }, 400);
    }

    // 1. Cek duplikasi email
    const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(body.email).first();
    if (existingUser) {
        return c.json({ error: 'Email sudah terdaftar' }, 409);
    }

    // 2. Hash Password (Simple Hash/Mock)
    let passwordHash = body.password; // Menggunakan plain text untuk mock dev
    
    // 3. Masukkan ke DB
    try {
        const { meta } = await env.DB.prepare(
            `INSERT INTO users (email, password_hash, name, role, status, created_at)
             VALUES (?, ?, ?, 'member', 'active', ?)`
        ).bind(body.email, passwordHash, body.name, Math.floor(Date.now() / 1000)).run();

        return c.json({ success: true, user_id: meta.last_row_id }, 201);
    } catch (e) {
        console.error('[REGISTER CRASH]', e.message, e.stack);
        return c.json({ error: 'Gagal mendaftarkan pengguna' }, 500);
    }
}

// BARU: Handler Profil Member (READ)
async function profileHandler(c) {
    // Data user sudah di-set oleh authMiddleware
    const user = c.get('user');
    // Hapus data sensitif seperti password_hash sebelum dikirim ke frontend
    const { password_hash, auth_token, refresh_token, ...safeUser } = user;
    return c.json(safeUser);
}

// BARU: Handler Profil Member (UPDATE)
async function updateProfileHandler(c) {
    const env = c.env;
    const userIdFromToken = c.get('user').id;
    const userIdFromParams = c.req.param('id');
    const body = await c.req.json().catch(() => null);

    // Keamanan: Pastikan ID dari token sesuai dengan ID yang diminta di params
    if (String(userIdFromToken) !== String(userIdFromParams)) {
        return c.json({ error: 'Akses ditolak: ID pengguna tidak cocok' }, 403);
    }

    if (!body || !body.name) {
        return c.json({ error: 'Nama wajib diisi' }, 400);
    }

    try {
        const { results } = await env.DB.prepare(
            `UPDATE users SET 
                name = ?, 
                phone = ?, 
                gender = ?, 
                address_line_1 = ?, 
                address_line_2 = ?, 
                city = ?, 
                province = ?, 
                country = ?, 
                zip_code = ? 
             WHERE id = ? RETURNING id`
        ).bind(
            body.name || null, 
            body.phone || null, 
            body.gender || null, 
            body.address_line_1 || null, 
            body.address_line_2 || null, 
            body.city || null, 
            body.province || null, 
            body.country || null, 
            body.zip_code || null,
            userIdFromToken
        ).all();
        
        if (results.length === 0) {
            return c.json({ error: 'Gagal memperbarui data pengguna' }, 404);
        }

        return c.json({ success: true, message: 'Profil berhasil diperbarui' });

    } catch (e) {
        console.error('[UPDATE PROFILE CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error saat pembaruan profil' }, 500);
    }
}

// BARU: Handler untuk mengambil daftar orders berdasarkan member_id
async function memberOrdersHandler(c) {
    const env = c.env;
    const user = c.get('user');
    const memberId = user.id;

    try {
        // NOTE: Menggunakan LEFT JOIN untuk mengambil nama produk
        const raw = await env.DB.prepare(
            `SELECT o.id, o.status, o.total_amount, o.created_at, p.name as product_name
             FROM orders o
             LEFT JOIN products p ON o.product_id = p.id
             WHERE o.user_id = ?
             ORDER BY o.created_at DESC`
        ).bind(memberId).all();

        return c.json(normalizeAllResult(raw));
    } catch (e) {
        console.error('[MEMBER ORDERS CRASH]', e.message, e.stack);
        return c.json({ error: 'Gagal memuat daftar pesanan' }, 500);
    }
}

// BARU: Handler untuk mengambil dan menyimpan pengaturan admin (Paspay)
async function adminSettingsHandler(c) {
    const env = c.env;
    
    // Pastikan tabel settings ada
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)').run().catch(() => {});

    if (c.req.method === 'GET') {
        const keyQuery = c.req.query('key');
        if (!keyQuery) return c.json({ error: 'Query parameter key wajib diisi' }, 400);

        // READ
        try {
            const raw = await env.DB.prepare('SELECT value FROM settings WHERE key = ? LIMIT 1').bind(keyQuery).first();
            if (!raw) return c.json({ error: 'Pengaturan tidak ditemukan' }, 404);
            return c.json(raw);
        } catch (e) {
            return c.json({ error: 'Gagal membaca pengaturan' }, 500);
        }
    } else if (c.req.method === 'POST') {
        const { key, value } = await c.req.json().catch(() => ({ key: null, value: null }));
        
        if (!key || !value) return c.json({ error: 'Body properties key dan value wajib diisi' }, 400);

        // CREATE/UPDATE (Upsert)
        try {
            // Menggunakan REPLACE INTO untuk membuat atau memperbarui
            await env.DB.prepare('REPLACE INTO settings (key, value) VALUES (?, ?)').bind(key, value).run();
            return c.json({ success: true, message: 'Pengaturan berhasil disimpan' });
        } catch (e) {
            return c.json({ error: 'Gagal menyimpan pengaturan' }, 500);
        }
    }
    
    return c.json({ error: 'Metode tidak valid' }, 405);
}


/* -------------------------
    Admin: categories (Validasi manual TANPA ZOD)
    ------------------------- */
async function adminListCategories(c) {
    const env = c.env;
    const raw = await env.DB.prepare('SELECT * FROM categories ORDER BY name ASC').all();
    return c.json(normalizeAllResult(raw));
}

async function adminCreateCategory(c) {
    const env = c.env;
    const body = await c.req.json().catch(() => null);
    
    if (!body || !body.name || !body.slug) {
        return c.json({ error: 'Nama dan slug wajib diisi' }, 400);
    }
    
    const { results } = await env.DB.prepare('INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *').bind(body.name, body.slug).all();
    return c.json(normalizeAllResult(results)[0], 201);
}

async function adminUpdateCategory(c) {
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);

    if (!body || !body.name || !body.slug) {
        return c.json({ error: 'Nama dan slug wajib diisi' }, 400);
    }
    
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
    Admin: banners CRUD
    ------------------------- */
async function adminListBanners(c) {
    const env = c.env;
    const raw = await env.DB.prepare('SELECT * FROM banners ORDER BY sort_order ASC').all();
    return c.json(normalizeAllResult(raw));
}

async function adminCreateBanner(c) {
    const env = c.env;
    const body = await c.req.json().catch(() => null);
    
    if (!body || !body.banner_name || !body.banner_image_url || !body.banner_link) {
        return c.json({ error: 'Nama, URL Gambar, dan Link Tujuan wajib diisi' }, 400);
    }
    
    const { results } = await env.DB.prepare(
        `INSERT INTO banners (banner_name, banner_description, banner_image_url, banner_link, is_active, sort_order) 
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(body.banner_name, body.banner_description || null, body.banner_image_url, body.banner_link, body.is_active ? 1 : 0, body.sort_order || 0).all();
    return c.json(normalizeAllResult(results)[0], 201);
}

async function adminUpdateBanner(c) {
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);

    if (!body || !body.banner_name || !body.banner_image_url || !body.banner_link) {
        return c.json({ error: 'Nama, URL Gambar, dan Link Tujuan wajib diisi' }, 400);
    }
    
    const { results } = await env.DB.prepare(
        `UPDATE banners SET banner_name = ?, banner_description = ?, banner_image_url = ?, banner_link = ?, is_active = ?, sort_order = ? 
         WHERE id = ? RETURNING *`
    ).bind(body.banner_name, body.banner_description || null, body.banner_image_url, body.banner_link, body.is_active ? 1 : 0, body.sort_order || 0, id).all();
    return c.json(normalizeAllResult(results)[0]);
}

async function adminDeleteBanner(c) {
    const env = c.env;
    const id = c.req.param('id');
    await env.DB.prepare('DELETE FROM banners WHERE id = ?').bind(id).run();
    return c.json({ success: true, message: 'Banner dihapus' });
}


/* -------------------------
    Admin: products CRUD (DIUBAH untuk is_featured)
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
    const body = await c.req.json().catch(() => null);

    if (!body || !body.name || typeof body.price !== 'number' || !body.product_type) {
        return c.json({ error: 'Nama, harga (angka), dan tipe produk wajib diisi' }, 400);
    }

    let slug = (body.slug || '').trim();
    if (!slug) slug = slugify(body.name || '');
    if (!slug) slug = `p-${Date.now()}`;
    let candidate = slug;
    let i = 1;
    while (true) {
        const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ?').bind(candidate).first();
        if (!exists) break;
        candidate = `${slug}-${i++}`;
    }
    slug = candidate;

    // Menyiapkan nilai untuk rating, review_count, dan is_featured
    const rating = body.rating ?? 0;
    const review_count = body.review_count ?? 0;
    const is_featured = body.is_featured ? 1 : 0;

    const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
    
    if (hasIsActive) {
        const { results } = await env.DB.prepare(
            `INSERT INTO products (slug, name, description, price, product_type, digital_content, image_url, category_id, is_active, rating, review_count, is_featured)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
        ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, rating, review_count, is_featured).all();
        return c.json(normalizeAllResult(results)[0], 201);
    } else {
        const { results } = await env.DB.prepare(
            `INSERT INTO products (slug, name, description, price, product_type, digital_content, image_url, category_id, rating, review_count, is_featured)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
        ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, rating, review_count, is_featured).all();
        return c.json(normalizeAllResult(results)[0], 201);
    }
}

async function adminUpdateProduct(c) {
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => null);

    if (!body || !body.name || typeof body.price !== 'number' || !body.product_type) {
        return c.json({ error: 'Nama, harga (angka), dan tipe produk wajib diisi' }, 400);
    }
    
    let slug = (body.slug || '').trim();
    if (!slug) slug = slugify(body.name || '') || `p-${id}`;
    let candidate = slug;
    let i = 1;
    while (true) {
        const exists = await env.DB.prepare('SELECT id FROM products WHERE slug = ? AND id != ?').bind(candidate, id).first();
        if (!exists) break;
        candidate = `${slug}-${i++}`;
    }
    slug = candidate;
    
    const rating = body.rating ?? 0;
    const review_count = body.review_count ?? 0;
    const is_featured = body.is_featured ? 1 : 0;

    const hasIsActive = await tableHasColumn(env.DB, 'products', 'is_active');
    if (hasIsActive) {
        const { results } = await env.DB.prepare(
            `UPDATE products SET slug = ?, name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, is_active = ?, rating = ?, review_count = ?, is_featured = ? WHERE id = ? RETURNING *`
        ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, body.is_active ? 1 : 0, rating, review_count, is_featured, id).all();
        return c.json(normalizeAllResult(results)[0]);
    } else {
        const { results } = await env.DB.prepare(
            `UPDATE products SET slug = ?, name = ?, description = ?, price = ?, product_type = ?, digital_content = ?, image_url = ?, category_id = ?, rating = ?, review_count = ?, is_featured = ? WHERE id = ? RETURNING *`
        ).bind(slug, body.name, body.description || null, body.price, body.product_type, body.digital_content || null, body.image_url || null, body.category_id || null, rating, review_count, is_featured, id).all();
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
    Admin: stock & gallery (Validasi manual TANPA ZOD)
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
    const body = await c.req.json().catch(() => null);
    
    if (!body || !body.stock_items || !Array.isArray(body.stock_items)) {
        return c.json({ error: 'stock_items (array) wajib diisi' }, 400);
    }
    
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
    const body = await c.req.json().catch(() => null);

    if (!body || !body.images || !Array.isArray(body.images)) {
        return c.json({ error: 'images (array) wajib diisi' }, 400);
    }

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
    Admin: orders & users (DIUBAH untuk kolom user baru)
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
    // MENGAMBIL SEMUA KOLOM USER BARU
    const raw = await env.DB.prepare(
        `SELECT 
            id, email, name, role, status, created_at,
            phone, gender, address_line_1, address_line_2, city, province, country, zip_code,
            telegram_user_id, google_user_id 
        FROM users ORDER BY created_at DESC`
    ).all();
    return c.json(normalizeAllResult(raw));
}

/* -------------------------
    Checkout & Webhook (Validasi manual TANPA ZOD)
    ------------------------- */
async function storeCheckoutHandler(c) {
    const env = c.env;
    const body = await c.req.json().catch(() => null);

    if (!body || !body.product_id || !body.email) {
        return c.json({ error: 'product_id dan email wajib diisi' }, 400);
    }

    try {
        const product = await env.DB.prepare('SELECT id, name, price, product_type FROM products WHERE id = ?').bind(body.product_id).first();
        if (!product) return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);
        if (!env.PASPAY_API_URL || !env.PASPAY_API_KEY) {
            const { meta } = await env.DB.prepare('INSERT INTO orders (product_id, status, total_amount, customer_email, created_at, user_id) VALUES (?, ?, ?, ?, ?, 0)').bind(product.id, 'UNPAID', product.price, body.email, Math.floor(Date.now() / 1000)).run();
            return c.json({ success: true, order_id: meta?.last_row_id || null, message: 'Order created (local)' });
        }

        return c.json({ error: 'External payment integration not configured' }, 501);
    } catch (e) {
        console.error('[CHECKOUT CRASH]', e.message, e.stack);
        return c.json({ error: 'Internal Server Error' }, 500);
    }
}

async function paspayWebhookHandler(c) {
    const env = c.env;
    const authHeader = c.req.header('Authorization');
    const incoming = authHeader ?
        authHeader.split(' ')[1] : '';
    if (!env.PASPAY_WEBHOOK_TOKEN || incoming !== env.PASPAY_WEBHOOK_TOKEN) return c.json({ error: 'Unauthorized' }, 401);

    const body = await c.req.json().catch(() => null);

    if (!body || !body.event) {
        return c.json({ error: 'Payload JSON dengan properti "event" wajib diisi' }, 400);
    }
    
    console.log('Webhook received', body);
    return c.json({ success: true });
}

/* -------------------------
    Debug (Tidak Berubah)
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
    Register routes API
    ------------------------- */

// Public store routes (API JSON)
api.get('/store/products', storeProductsHandler);
api.get('/store/products/:id', storeProductByIdHandler);
api.get('/store/products/slug/:slug', storeProductBySlugHandler);
api.get('/store/banners', storeBannersHandler);

// Auth
api.post('/login', loginHandler);
api.post('/logout', logoutHandler);
api.post('/member/register', registerHandler); // BARU: Register
api.get('/member/profile', authMiddleware, profileHandler); // READ Profil Member
api.put('/member/profile/:id', authMiddleware, updateProfileHandler); // UPDATE Profil Member
api.get('/member/orders', authMiddleware, memberOrdersHandler); // BARU: Orders Member

// Checkout & webhook
api.post('/store/checkout', storeCheckoutHandler);
api.post('/webhook/paspay', paspayWebhookHandler);

// Admin categories
api.get('/admin/categories', authMiddleware, adminMiddleware, adminListCategories);
api.post('/admin/categories', authMiddleware, adminMiddleware, adminCreateCategory);
api.put('/admin/categories/:id', authMiddleware, adminMiddleware, adminUpdateCategory);
api.delete('/admin/categories/:id', authMiddleware, adminMiddleware, adminDeleteCategory);

// Admin banners
api.get('/admin/banners', authMiddleware, adminMiddleware, adminListBanners);
api.post('/admin/banners', authMiddleware, adminMiddleware, adminCreateBanner);
api.put('/admin/banners/:id', authMiddleware, adminMiddleware, adminUpdateBanner);
api.delete('/admin/banners/:id', authMiddleware, adminMiddleware, adminDeleteBanner);

// Admin products
api.get('/admin/products', authMiddleware, adminMiddleware, adminListProducts);
api.get('/admin/products/:id', authMiddleware, adminMiddleware, adminGetProduct);
api.post('/admin/products', authMiddleware, adminMiddleware, adminCreateProduct);
api.put('/admin/products/:id', authMiddleware, adminMiddleware, adminUpdateProduct);
api.delete('/admin/products/:id', authMiddleware, adminMiddleware, adminDeleteProduct);
// Admin stock & gallery
api.get('/admin/products/:id/stock', authMiddleware, adminMiddleware, adminListStock);
api.post('/admin/products/:id/stock', authMiddleware, adminMiddleware, adminAddStock);
api.delete('/admin/stock/:stockId', authMiddleware, adminMiddleware, adminDeleteStock);

api.get('/admin/products/:id/gallery', authMiddleware, adminMiddleware, adminListGallery);
api.post('/admin/products/:id/gallery', authMiddleware, adminMiddleware, adminSyncGallery);
api.delete('/admin/gallery/:imageId', authMiddleware, adminMiddleware, adminDeleteGallery);

// Admin orders & users
api.get('/admin/orders', authMiddleware, adminMiddleware, adminListOrders);
api.get('/admin/users', authMiddleware, adminMiddleware, adminListUsers);
// BARU: Admin Settings (Paspay Gateway)
api.get('/admin/settings', authMiddleware, adminMiddleware, adminSettingsHandler); // READ
api.post('/admin/settings', authMiddleware, adminMiddleware, adminSettingsHandler); // UPSERT

// Debug
api.get('/debug/db', debugDbHandler);


/* -------------------------
    Fallback (API)
    ------------------------- */
api.all('*', (c) => {
    try { console.log(`[API NO MATCH] ${c.req.method} ${c.req.url}`); } catch (e) {}
    return c.json({ error: 'API Not Found' }, 404);
});

/* -----------------------------------------------
    RUTE HALAMAN STATIS & DINAMIS (Client-Side Rendering Shells)
    Memisahkan index.html dan product.html.
    ----------------------------------------------- */
// Rute detail produk memuat shell product.html
app.get('/product/:slug', serveStatic({ 
    root: './public',
    path: 'product.html' // Shell khusus untuk detail produk
}));

// Rute login member
app.get('/member/login.html', serveStatic({
    root: './public',
    path: 'member/login.html'
}));

// Rute member area memuat shell member dashboard
app.get('/member/dashboard.html', serveStatic({ 
    root: './public',
    path: 'member/dashboard.html'
}));

// Rute pendaftaran memuat shell register
app.get('/member/register.html', serveStatic({ 
    root: './public',
    path: 'member/register.html'
}));

// Rute orders member
app.get('/member/orders.html', serveStatic({
    root: './public',
    path: 'member/orders.html'
}));

// Rute profil member
app.get('/member/profile.html', serveStatic({
    root: './public',
    path: 'member/profile.html'
}));

// Rute admin settings paspay
app.get('/admin/paspay-settings.html', serveStatic({
    root: './public',
    path: 'admin/paspay-settings.html'
}));


// Rute dasar / (beranda) dan semua rute lain yang tidak terdefinisi (seperti /admin/login, /style.css)
// memuat dari direktori statis /public, dengan fallback ke index.html untuk path root.
app.get('*', serveStatic({ root: './public' }));


/* -------------------------
    Export (Tidak Berubah)
    ------------------------- */
export const onRequest = handle(app);
