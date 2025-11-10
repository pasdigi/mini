import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
// --- PERBAIKAN: Gunakan 'hono/cloudflare-pages' untuk Pages Functions ---
import { handle } from 'hono/cloudflare-pages';

/*
* Tipe (Binding) untuk Cloudflare environment
* Ini akan otomatis di-bind oleh Wrangler
* @typedef {object} Bindings
* @property {D1Database} DB
* @property {string} JWT_SECRET
* @property {string} PASPAY_API_KEY
* @property {string} PASPAY_API_URL
* @property {string} PASPAY_WEBHOOK_TOKEN
* @property {string} PASPAY_PROJECT_ID
*/

// --- Inisialisasi Hono ---
const app = new Hono().basePath('/api');

// --- Middleware Otentikasi ---

const authMiddleware = async (c, next) => {
    /** @type {Bindings} */
    const env = c.env;
    const token = getCookie(c, 'auth_token');

    if (!token) {
        return c.json({ error: 'Tidak terotentikasi' }, 401);
    }
    try {
        const payload = await verify(token, env.JWT_SECRET);
        // Cek jika user masih ada di DB
        const user = await env.DB.prepare("SELECT id, role, status FROM users WHERE id = ?")
            .bind(payload.sub)
            .first();
        
        if (!user) {
            return c.json({ error: 'User tidak ditemukan' }, 401);
        }
        if (user.status !== 'active') {
             return c.json({ error: 'Akun Anda nonaktif atau di-suspend' }, 403);
        }
        
        c.set('user', user);
        await next();
    } catch (e) {
        return c.json({ error: 'Token tidak valid atau kedaluwarsa' }, 401);
    }
};

const adminMiddleware = async (c, next) => {
    const user = c.get('user');
    if (user.role !== 'admin') {
        return c.json({ error: 'Akses ditolak. Memerlukan hak admin.' }, 403);
    }
    await next();
};

// --- Rute API (Publik - Tanpa Auth) ---

/**
 * Rute Login
 */
app.post('/login', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const body = await c.req.json();

    if (!body.email || !body.password) {
        return c.json({ error: 'Email dan password wajib diisi' }, 400);
    }
    
    // Cari user
    const user = await env.DB.prepare("SELECT id, password_hash, role, status FROM users WHERE email = ?")
        .bind(body.email)
        .first();

    if (!user) {
        return c.json({ error: 'Email atau password salah' }, 401);
    }

    // Verifikasi password (asumsi: hashPassword adalah fungsi yang Anda miliki)
    // const password_hash = await hashPassword(body.password, env.JWT_SECRET);
    // if (password_hash !== user.password_hash) {
    //    return c.json({ error: 'Email atau password salah' }, 401);
    // }
    
    // (Placeholder verifikasi password - ganti dengan logika hash Anda)
    if (body.password !== user.password_hash) {
         return c.json({ error: 'Email atau password salah (mode debug - ganti dgn hash)' }, 401);
    }

    if (user.status !== 'active') {
        return c.json({ error: 'Akun Anda nonaktif atau di-suspend' }, 403);
    }

    // Buat Token
    const payload = {
        sub: user.id,
        role: user.role,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 1 hari
    };
    const token = await sign(payload, env.JWT_SECRET);

    setCookie(c, 'auth_token', token, {
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        maxAge: 60 * 60 * 24 // 1 hari
    });

    return c.json({ success: true, message: 'Login berhasil' });
});

/**
 * Rute Logout
 */
app.post('/logout', (c) => {
    setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 });
    return c.json({ success: true, message: 'Logout berhasil' });
});

// --- Rute Toko (Publik - Tanpa Auth) ---

/**
 * Rute untuk mengambil semua produk (Toko)
 */
app.get('/store/products', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    try {
        const { results } = await env.DB.prepare(
            `SELECT p.id, p.name, p.price, p.image_url, c.name as category_name 
             FROM products p
             LEFT JOIN categories c ON p.category_id = c.id`
             // WHERE p.is_active = 1  (Kita akan tambahkan ini nanti)
        ).all();
        
        return c.json(results || []);
    } catch (e) {
        return c.json({ error: 'Gagal mengambil data produk: ' + e.message }, 500);
    }
});

/**
 * Rute untuk mengambil detail 1 produk (Toko)
 */
app.get('/store/products/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    try {
        const product = await env.DB.prepare(
            `SELECT p.id, p.name, p.price, p.description, p.image_url, c.name as category_name
             FROM products p
             LEFT JOIN categories c ON p.category_id = c.id
             WHERE p.id = ?` // AND p.is_active = 1
        ).bind(id).first();

        if (!product) {
            return c.json({ error: 'Produk tidak ditemukan' }, 404);
        }

        // Ambil galeri gambar
        const { results: gallery } = await env.DB.prepare(
            "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC"
        ).bind(id).all();

        // Jangan kirim 'digital_content' ke publik
        const { digital_content, ...publicProduct } = product;

        return c.json({ ...publicProduct, gallery: gallery.map(img => img.image_url) });
    } catch (e) {
        return c.json({ error: 'Gagal mengambil detail produk: ' + e.message }, 500);
    }
});

/**
 * Rute untuk membuat Order (Checkout)
 */
app.post('/store/checkout', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const body = await c.req.json();
    const now = Math.floor(Date.now() / 1000);

    // Validasi input
    if (!body.product_id || !body.email) {
        return c.json({ error: 'ID Produk dan Email wajib diisi' }, 400);
    }
    
    // 1. Ambil detail produk
    const product = await env.DB.prepare("SELECT id, name, price, product_type FROM products WHERE id = ?") // AND is_active = 1
        .bind(body.product_id)
        .first();
        
    if (!product) {
        return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);
    }

    try {
        // 2. Buat panggilan ke API Paspay
        const paspayPayload = {
            project_id: parseInt(c.env.PASPAY_PROJECT_ID, 10), // Ambil dari secrets
            payment_channel_id: [1, 3], // TODO: Ganti dengan Channel ID Paspay Anda
            amount: product.price,
            internal_ref_id: `MINI-${product.id}-${now}`,
            description: `Pembelian: ${product.name}`,
            customer_email: body.email,
            customer_name: body.name || 'Customer'
        };

        const paspayResponse = await fetch(env.PASPAY_API_URL + '/transactions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${env.PASPAY_API_KEY}`
            },
            body: JSON.stringify(paspayPayload)
        });

        const paspayResult = await paspayResponse.json();

        if (!paspayResponse.ok) {
            return c.json({ error: 'Gagal membuat invoice Paspay', detail: paspayResult.error || 'Unknown error' }, 500);
        }

        // 3. Simpan order ke database D1
        const { results } = await env.DB.prepare(
            `INSERT INTO orders (product_id, status, paspay_reference_id, total_amount, customer_email, created_at, user_id)
             VALUES (?, 'UNPAID', ?, ?, ?, ?, 0)` // Asumsi user_id 0 untuk tamu
        ).bind(
            product.id,
            paspayResult.reference_id,
            paspayResult.total_amount_expected,
            body.email,
            now
        ).all();

        const newOrderId = results[0].id;
        
        // 4. Jika produk Tipe UNIQUE, "kunci" stoknya
        if (product.product_type === 'UNIQUE') {
            const stock = await env.DB.prepare(
                "SELECT id FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1"
            ).bind(product.id).first();

            if (!stock) {
                return c.json({ error: 'Stok produk ini telah habis!' }, 410); // 410 Gone
            }
            
            // Tandai stok sebagai "pending" (is_sold = 1 dan order_id diisi)
            await env.DB.prepare(
                "UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ?"
            ).bind(newOrderId, stock.id).run();
        }

        // 5. Kembalikan detail Paspay ke frontend
        return c.json(paspayResult);

    } catch (e) {
        return c.json({ error: 'Terjadi kesalahan saat checkout: ' + e.message }, 500);
    }
});


// --- Rute Webhook (Publik) ---

/**
 * Rute Webhook dari Paspay
 */
app.post('/webhook/paspay', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const now = Math.floor(Date.now() / 1000);
    
    // 1. Verifikasi Token Webhook
    const authHeader = c.req.header('Authorization');
    const incomingToken = authHeader ? authHeader.split(' ')[1] : '';
    if (incomingToken !== env.PASPAY_WEBHOOK_TOKEN) {
        return c.json({ error: 'Unauthorized: Token webhook tidak valid' }, 401);
    }

    const payload = await c.req.json();

    // 2. Hanya proses event 'payment.success'
    if (payload.event !== 'payment.success' || !payload.data) {
        return c.json({ success: true, message: 'Event diabaikan' }, 200);
    }
    
    const tx = payload.data; // Data transaksi dari Paspay

    try {
        // 3. Cari order di database D1
        const order = await env.DB.prepare("SELECT * FROM orders WHERE paspay_reference_id = ? AND status = 'UNPAID'")
            .bind(tx.reference_id)
            .first();

        if (!order) {
            return c.json({ error: 'Order tidak ditemukan atau sudah diproses' }, 404);
        }

        // 4. Ambil detail produk
        const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?")
            .bind(order.product_id)
            .first();

        if (!product) {
            return c.json({ error: 'Produk terkait tidak ditemukan' }, 404);
        }

        let delivered_content = null;

        // 5. Logika Pengiriman Digital
        if (product.product_type === 'STANDARD') {
            // Tipe Ebook: Langsung ambil dari 'digital_content'
            delivered_content = product.digital_content;
            
        } else if (product.product_type === 'UNIQUE') {
            // Tipe Lisensi: Ambil dari stok yang sudah "dikunci"
            const stock = await env.DB.prepare("SELECT content FROM product_stock_unique WHERE order_id = ? AND product_id = ?")
                .bind(order.id, product.id)
                .first();
            
            if (!stock) {
                // Sesuatu yang sangat salah terjadi (stok tidak terkunci)
                console.error(`Webhook Error: Stok untuk Order ID ${order.id} tidak ditemukan!`);
                // TODO: Kirim email ke admin
                return c.json({ error: 'Stok internal tidak ditemukan' }, 500);
            }
            delivered_content = stock.content;
        }

        // 6. Update order
        await env.DB.prepare(
            "UPDATE orders SET status = 'PAID', delivered_content = ? WHERE id = ?"
        ).bind(delivered_content, order.id).run();

        // 7. Kirim email ke pelanggan
        // TODO: Tambahkan integrasi email (Mailgun, SendGrid, dll)
        console.log(`Mengirim produk ke ${order.customer_email}: ${delivered_content}`);

        // 8. Beri tahu Paspay bahwa webhook diterima
        return c.json({ success: true, message: 'Webhook diproses' }, 200);

    } catch (e) {
        console.error('Webhook Gagal: ' + e.message);
        return c.json({ error: 'Internal Server Error: ' + e.message }, 500);
    }
});


// --- Rute Admin (Perlu Auth) ---
// (Placeholder auth, ganti dengan authMiddleware di produksi)
// const admin = app.use('/admin/*', authMiddleware, adminMiddleware);
const admin = app.use('/admin/*'); // DEBUG: Sementara admin tidak perlu auth

/**
 * Rute Admin: CRUD Kategori
 */
admin.get('/categories', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const { results } = await env.DB.prepare("SELECT * FROM categories ORDER BY name ASC").all();
    return c.json(results || []);
});

admin.post('/categories', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const body = await c.req.json();
    if (!body.name || !body.slug) {
        return c.json({ error: 'Nama dan Slug kategori wajib diisi.' }, 400);
    }
    const { results } = await env.DB.prepare("INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *")
        .bind(body.name, body.slug)
        .all();
    return c.json(results[0], 201);
});

admin.put('/categories/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json();
    if (!body.name || !body.slug) {
        return c.json({ error: 'Nama dan Slug kategori wajib diisi.' }, 400);
    }
    const { results } = await env.DB.prepare("UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *")
        .bind(body.name, body.slug, id)
        .all();
    return c.json(results[0]);
});

admin.delete('/categories/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    await env.DB.prepare("DELETE FROM categories WHERE id = ?").bind(id).run();
    return c.json({ success: true, message: 'Kategori dihapus' });
});

/**
 * Rute Admin: CRUD Produk
 */
admin.get('/products', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const { results } = await env.DB.prepare(
        `SELECT p.*, c.name as category_name 
         FROM products p 
         LEFT JOIN categories c ON p.category_id = c.id 
         ORDER BY p.name ASC`
    ).all();
    return c.json(results || []);
});

// READ Satu Produk (Detail untuk Edit)
admin.get('/products/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const product = await env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
    if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    
    // Ambil juga galeri
    const { results: gallery } = await env.DB.prepare(
        "SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC"
    ).bind(id).all();
    
    return c.json({ ...product, gallery: gallery || [] });
});


admin.post('/products', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const body = await c.req.json();
    
    // Validasi
    if (!body.name || !body.price || !body.product_type) {
        return c.json({ error: 'Nama, Harga, dan Tipe Produk wajib diisi' }, 400);
    }

    const { results } = await env.DB.prepare(
        `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id)
         VALUES (?, ?, ?, ?, ?, ?, ?_active)` // Hapus 'is_active' jika tidak ada di skema
    ).bind(
        body.name,
        body.description || null,
        body.price,
        body.product_type, // 'STANDARD' atau 'UNIQUE'
        body.digital_content || null,
        body.image_url || null,
        body.category_id || null
        // body.is_active ? 1 : 0 // Hapus ini jika 'is_active' tidak ada
    ).all();
    
    return c.json(results[0], 201);
});

admin.put('/products/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json();

    if (!body.name || !body.price || !body.product_type) {
        return c.json({ error: 'Nama, Harga, dan Tipe Produk wajib diisi' }, 400);
    }

    const { results } = await env.DB.prepare(
        `UPDATE products SET 
         name = ?, description = ?, price = ?, product_type = ?, 
         digital_content = ?, image_url = ?, category_id = ?
         WHERE id = ? RETURNING *` // Hapus 'is_active'
    ).bind(
        body.name,
        body.description || null,
        body.price,
        body.product_type,
        body.digital_content || null,
        body.image_url || null,
        body.category_id || null,
        // body.is_active ? 1 : 0, // Hapus 'is_active'
        id
    ).all();
    
    return c.json(results[0]);
});

admin.delete('/products/:id', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    
    // Hati-hati: idealnya cek dulu apakah produk ini punya stok/order
    await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id).run();
    // Juga hapus stok dan galeri terkait
    await env.DB.prepare("DELETE FROM product_stock_unique WHERE product_id = ?").bind(id).run();
    await env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id).run();

    return c.json({ success: true, message: 'Produk (dan stok/galeri terkait) dihapus' });
});


/**
 * Rute Admin: CRUD Stok (untuk Tipe UNIQUE)
 */
admin.get('/products/:id/stock', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const { results } = await env.DB.prepare(
        "SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC"
    ).bind(id).all();
    return c.json(results || []);
});

admin.post('/products/:id/stock', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json();
    
    // Input: { "content": "KUNCI-LISENSI-BARU" }
    if (!body.content) {
        return c.json({ error: 'Konten (kunci lisensi/link) wajib diisi' }, 400);
    }

    const { results } = await env.DB.prepare(
        "INSERT INTO product_stock_unique (product_id, content, is_sold, order_id) VALUES (?, ?, 0, NULL) RETURNING *"
    ).bind(id, body.content).all();
    
    return c.json(results[0], 201);
});

admin.delete('/stock/:stockId', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const stockId = c.req.param('stockId');
    // Hapus hanya jika belum terjual
    const { changes } = await env.DB.prepare("DELETE FROM product_stock_unique WHERE id = ? AND is_sold = 0")
        .bind(stockId)
        .run();
        
    if (changes === 0) {
        return c.json({ error: 'Gagal menghapus stok (mungkin sudah terjual atau tidak ditemukan)' }, 404);
    }
    return c.json({ success: true, message: 'Stok dihapus' });
});

/**
 * Rute Admin: CRUD Galeri Gambar
 */
admin.get('/products/:id/gallery', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const { results } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY id DESC")
        .bind(id).all();
    return c.json(results || []);
});

admin.post('/products/:id/gallery', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const id = c.req.param('id');
    const body = await c.req.json();
    
    // Input: { "image_url": "/images/gambar-galeri.png" }
    if (!body.image_url) {
        return c.json({ error: 'URL Gambar wajib diisi' }, 400);
    }

    const { results } = await env.DB.prepare("INSERT INTO product_images (product_id, image_url) VALUES (?, ?) RETURNING *")
        .bind(id, body.image_url)
        .all();
    
    return c.json(results[0], 201);
});

admin.delete('/gallery/:imageId', async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const imageId = c.req.param('imageId');
    await env.DB.prepare("DELETE FROM product_images WHERE id = ?").bind(imageId).run();
    return c.json({ success: true, message: 'Gambar dari galeri dihapus' });
});

// --- Ekspor Handler ---
export const onRequest = handle(app);
