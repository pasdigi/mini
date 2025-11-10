import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { handle } from 'hono/cloudflare-pages';
// --- PERBAIKAN: Impor Zod untuk Validasi ---
import { z } from 'zod';
import { zValidator } from '@hono/zod-validator';

/*
* Tipe (Binding) untuk Cloudflare environment
* @typedef {object} Bindings
* @property {D1Database} DB
* @property {string} JWT_SECRET
* @property {string} PASPAY_API_KEY
* @property {string} PASPAY_API_URL
* @property {string} PASPAY_WEBHOOK_TOKEN
* @property {string} PASPAY_PROJECT_ID
*/

// --- Utilitas Kriptografi (BARU) ---
// (Ini adalah implementasi PBKDF2. Anda memerlukan fungsi 'hashPassword'
// serupa di rute registrasi Anda untuk *membuat* hash ini)

// Helper untuk mengubah ArrayBuffer (dari Web Crypto) ke Hex string
const bufferToHex = (buffer) => {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

// Helper untuk mengubah Hex string kembali ke ArrayBuffer
const hexToBuffer = (hex) => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
};

/**
 * Verifikasi password.
 * @param {string} password - Password (plain text) dari user
 * @param {string} storedHash - Hash yang disimpan di DB (format: salt:hash)
 * @returns {Promise<boolean>}
 */
const verifyPassword = async (password, storedHash) => {
  try {
    const [saltHex, hashHex] = storedHash.split(':');
    if (!saltHex || !hashHex) {
      console.error('Format hash tidak valid. Harus "salt:hash"');
      return false;
    }

    const salt = hexToBuffer(saltHex);
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    // Iterasi harus cocok dengan yang digunakan saat membuat hash
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial, 256 // 256 bits
    );
    const derivedHashHex = bufferToHex(derivedBits);
    
    // Perbandingan string sederhana sudah cukup aman di JS
    return derivedHashHex === hashHex;
  } catch (e) {
    console.error("Kesalahan saat verifikasi password:", e.message);
    return false;
  }
};

// --- Skema Validasi (Zod) ---

const loginSchema = z.object({
  email: z.string().email('Format email tidak valid'),
  password: z.string().min(1, 'Password wajib diisi'),
});

const checkoutSchema = z.object({
  product_id: z.number().int().positive('ID Produk tidak valid'),
  email: z.string().email('Format email tidak valid'),
  name: z.string().optional(),
});

// Skema dasar untuk Paspay webhook
const paspayWebhookSchema = z.object({
  event: z.string(),
  data: z.object({
    reference_id: z.string(),
    // Tambahkan field data lain yang Anda perlukan
  }).optional(),
});

const categorySchema = z.object({
  name: z.string().min(1, 'Nama kategori wajib diisi'),
  slug: z.string().min(1, 'Slug wajib diisi'),
});

const productSchema = z.object({
  name: z.string().min(1, 'Nama produk wajib diisi'),
  price: z.number().positive('Harga harus angka positif'),
  product_type: z.enum(['STANDARD', 'UNIQUE'], { message: "Tipe produk harus 'STANDARD' atau 'UNIQUE'" }),
  description: z.string().optional().nullable(),
  digital_content: z.string().optional().nullable(),
  image_url: z.string().optional().nullable(),
  category_id: z.number().int().optional().nullable(),
  // is_active: z.boolean().optional(),
});

const stockSchema = z.object({
  content: z.string().min(1, 'Konten stok (lisensi/link) wajib diisi'),
});

const gallerySchema = z.object({
  image_url: z.string().url('URL Gambar tidak valid'),
});


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
            // Token valid, tapi user dihapus
            setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); // Hapus cookie
            return c.json({ error: 'User tidak ditemukan' }, 401);
        }
        if (user.status !== 'active') {
             setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); // Hapus cookie
             return c.json({ error: 'Akun Anda nonaktif atau di-suspend' }, 403);
        }
        
        c.set('user', user);
        await next();
    } catch (e) {
        // Token tidak valid atau kedaluwarsa
        setCookie(c, 'auth_token', '', { path: '/', maxAge: 0 }); // Hapus cookie
        return c.json({ error: 'Token tidak valid atau kedaluwarsa' }, 401);
    }
};

const adminMiddleware = async (c, next) => {
    const user = c.get('user'); // Diambil dari authMiddleware
    if (user.role !== 'admin') {
        return c.json({ error: 'Akses ditolak. Memerlukan hak admin.' }, 403);
    }
    await next();
};

// --- Rute API (Publik - Tanpa Auth) ---

/**
 * Rute Login
 */
app.post('/login', zValidator('json', loginSchema), async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    // --- PERBAIKAN: Ambil body yang sudah divalidasi Zod ---
    const body = c.req.valid('json');

    // Cari user
    const user = await env.DB.prepare("SELECT id, password_hash, role, status FROM users WHERE email = ?")
        .bind(body.email)
        .first();

    if (!user) {
        return c.json({ error: 'Email atau password salah' }, 401);
    }
    
    // --- PERBAIKAN: Verifikasi Hash Password ---
    // (Asumsi: 'user.password_hash' disimpan di DB dengan format 'salt:hash')
    const isPasswordValid = await verifyPassword(body.password, user.password_hash);
    if (!isPasswordValid) {
        return c.json({ error: 'Email atau password salah' }, 401);
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
        secure: true, // Selalu true di produksi
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
    // Hapus cookie dengan mengatur maxAge ke 0
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
        // Filter hanya produk yang aktif
        const { results } = await env.DB.prepare(
            `SELECT p.id, p.name, p.price, p.image_url, c.name as category_name 
             FROM products p
             LEFT JOIN categories c ON p.category_id = c.id
             WHERE p.is_active = 1` // Asumsi Anda punya kolom 'is_active'
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
             WHERE p.id = ? AND p.is_active = 1`
        ).bind(id).first();

        if (!product) {
            return c.json({ error: 'Produk tidak ditemukan atau tidak aktif' }, 404);
        }

        // Ambil galeri gambar
        const { results: gallery } = await env.DB.prepare(
            "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY sort_order ASC"
        ).bind(id).all();

        // Pastikan digital_content tidak terekspos (jika ada di tabel)
        const { digital_content, ...publicProduct } = product;

        return c.json({ ...publicProduct, gallery: gallery.map(img => img.image_url) });
    } catch (e) {
        return c.json({ error: 'Gagal mengambil detail produk: ' + e.message }, 500);
    }
});

/**
 * Rute untuk membuat Order (Checkout)
 */
app.post('/store/checkout', zValidator('json', checkoutSchema), async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const body = c.req.valid('json'); // Body sudah divalidasi
    const now = Math.floor(Date.now() / 1000);

    // 1. Ambil detail produk
    const product = await env.DB.prepare("SELECT id, name, price, product_type FROM products WHERE id = ? AND is_active = 1")
        .bind(body.product_id)
        .first();
        
    if (!product) {
        return c.json({ error: 'Produk tidak valid atau tidak aktif' }, 404);
    }

    try {
        // 2. Buat panggilan ke API Paspay
        const paspayPayload = {
            project_id: parseInt(c.env.PASPAY_PROJECT_ID, 10),
            payment_channel_id: [1, 3], // TODO: Ganti
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
            console.error("Paspay API Error:", paspayResult);
            return c.json({ error: 'Gagal membuat invoice Paspay', detail: paspayResult.error || 'Unknown error' }, 500);
        }

        // 3. Simpan order ke database D1
        // Menggunakan RETURNING * (jika didukung D1/SQLite) atau `last_row_id`
        const { meta } = await env.DB.prepare(
            `INSERT INTO orders (product_id, status, paspay_reference_id, total_amount, customer_email, created_at, user_id)
             VALUES (?, 'UNPAID', ?, ?, ?, ?, 0)` // Asumsi user_id 0 untuk tamu
        ).bind(
            product.id,
            paspayResult.reference_id,
            paspayResult.total_amount_expected,
            body.email,
            now
        ).run();
        
        const newOrderId = meta.last_row_id;
        if (!newOrderId) {
            return c.json({ error: 'Gagal menyimpan order' }, 500);
        }
        
        // 4. --- PERBAIKAN: Kunci Stok (Atomic Race Condition Fix) ---
        if (product.product_type === 'UNIQUE') {
            // 4a. Cari stok yang tersedia
            const stock = await env.DB.prepare(
                "SELECT id FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1"
            ).bind(product.id).first();

            if (!stock) {
                // Stok habis bahkan sebelum kita mencoba
                // TODO: Idealnya, batalkan invoice Paspay yang baru dibuat.
                return c.json({ error: 'Stok produk ini telah habis!' }, 410); // 410 Gone
            }
            
            // 4b. Coba kunci stok.id spesifik, tapi pastikan masih is_sold = 0
            const { changes } = await env.DB.prepare(
                "UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ? AND is_sold = 0"
            ).bind(newOrderId, stock.id).run();

            if (changes === 0) {
                // Gagal update! Berarti race condition terjadi.
                // Stok.id ini sudah diambil oleh orang lain di antara SELECT dan UPDATE kita.
                // TODO: Idealnya, batalkan invoice Paspay.
                return c.json({ error: 'Stok produk baru saja habis. Silakan coba lagi.' }, 409); // 409 Conflict
            }
            // Jika 'changes' === 1, kita berhasil mengunci stok.
        }

        // 5. Kembalikan detail Paspay ke frontend
        return c.json(paspayResult);

    } catch (e) {
        console.error("Checkout Error:", e);
        return c.json({ error: 'Terjadi kesalahan saat checkout: ' + e.message }, 500);
    }
});


// --- Rute Webhook (Publik) ---

/**
 * Rute Webhook dari Paspay
 */
app.post('/webhook/paspay', zValidator('json', paspayWebhookSchema), async (c) => {
    /** @type {Bindings} */
    const env = c.env;
    const now = Math.floor(Date.now() / 1000);
    
    // 1. Verifikasi Token Webhook
    const authHeader = c.req.header('Authorization');
    const incomingToken = authHeader ? authHeader.split(' ')[1] : '';
    if (incomingToken !== env.PASPAY_WEBHOOK_TOKEN) {
        return c.json({ error: 'Unauthorized: Token webhook tidak valid' }, 401);
    }

    const payload = c.req.valid('json'); // Body sudah divalidasi

    // 2. Hanya proses event 'payment.success'
    if (payload.event !== 'payment.success' || !payload.data) {
        return c.json({ success: true, message: 'Event diabaikan' }, 200);
    }
    
    const tx = payload.data; // Data transaksi dari Paspay

    try {
        // 3. Cari order di database D1
        // Pastikan idempotency (hanya proses jika status 'UNPAID')
        const order = await env.DB.prepare("SELECT * FROM orders WHERE paspay_reference_id = ? AND status = 'UNPAID'")
            .bind(tx.reference_id)
  D1.prepare(
        `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id, is_active)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
        body.name,
        body.description || null,
        body.price,
        body.product_type,
        body.digital_content || null,
        body.image_url || null,
        body.category_id || null,
        body.is_active ? 1 : 0 // Asumsi 'is_active' ada di skema
end(
             "SELECT * FROM product_stock_unique WHERE product_id = ? ORDER BY id DESC"
         ).bind(id).all();
        return c.json(results || []);
    });
    
    admin.post('/products/:id/stock', zValidator('json', stockSchema), async (c) => {
        /** @type {Bindings} */
        const env = c.env;
        const id = c.req.param('id');
        const body = c.req.valid('json');
        
        // Pastikan produk ada dan tipenya 'UNIQUE'
        const product = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND product_type = 'UNIQUE'")
            .bind(id).first();
        if (!product) {
            return c.json({ error: 'Produk tidak ditemukan atau bukan tipe UNIQUE' }, 404);
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
        const { results } = await env.DB.prepare("SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC")
            .bind(id).all();
        return c.json(results || []);
    });

    admin.post('/products/:id/gallery', zValidator('json', gallerySchema), async (c) => {
        /** @type {Bindings} */
        const env = c.env;
        const id = c.req.param('id');
        const body = c.req.valid('json');
        
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
