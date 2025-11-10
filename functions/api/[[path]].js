import { Hono } from 'hono';
import { handle } from 'hono/functions';

// --- Inisialisasi Hono ---
// 'Bindings' akan secara otomatis di-bind oleh Cloudflare (D1, Secrets)
const app = new Hono().basePath('/api');

// --- Middleware (Placeholder) ---
// (Anda dapat menggantinya dengan logika JWT/Auth Anda yang sebenarnya)

const authMiddleware = async (c, next) => {
    // TODO: Implementasikan logika validasi JWT Anda di sini
    // const token = getCookie(c, 'auth_token');
    // const payload = await verify(token, c.env.JWT_SECRET);
    // c.set('user', payload);
    
    // Untuk sekarang, kita buat user palsu untuk testing
    c.set('user', { sub: 1, role: 'admin' }); // Hapus ini di produksi
    await next();
};

const adminMiddleware = async (c, next) => {
    const user = c.get('user');
    // Di produksi, cek user.role
    if (user.role !== 'admin') {
        return c.json({ error: 'Akses ditolak' }, 403);
    }
    await next();
};


// ===========================================
// RUTE ADMIN (CRUD KATEGORI)
// ===========================================

// 1. CREATE Kategori Baru
app.post('/admin/categories', adminMiddleware, async (c) => {
    const body = await c.req.json();
    if (!body.name || !body.slug) {
        return c.json({ error: 'Nama dan Slug kategori wajib diisi.' }, 400);
    }
    try {
        const query = c.env.DB.prepare(
            `INSERT INTO categories (name, slug) VALUES (?, ?) RETURNING *`
        ).bind(body.name, body.slug);
        const newCategory = await query.first();
        return c.json({ message: 'Kategori berhasil dibuat', data: newCategory }, 201);
    } catch (e) {
        if (e.message.includes('UNIQUE constraint')) {
            return c.json({ error: 'Slug ini sudah digunakan.' }, 409);
        }
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});

// 2. READ Semua Kategori
app.get('/admin/categories', adminMiddleware, async (c) => {
    const { results } = await c.env.DB.prepare(
        "SELECT * FROM categories ORDER BY name ASC"
    ).all();
    return c.json({ data: results || [] });
});

// 3. UPDATE Kategori
app.put('/admin/categories/:id', adminMiddleware, async (c) => {
    const id = c.req.param('id');
    const body = await c.req.json();
    if (!body.name || !body.slug) {
        return c.json({ error: 'Nama dan Slug kategori wajib diisi.' }, 400);
    }
    try {
        const query = c.env.DB.prepare(
            `UPDATE categories SET name = ?, slug = ? WHERE id = ? RETURNING *`
        ).bind(body.name, body.slug, id);
        const updatedCategory = await query.first();
        if (!updatedCategory) return c.json({ error: 'Kategori tidak ditemukan' }, 404);
        return c.json({ message: 'Kategori berhasil diperbarui', data: updatedCategory });
    } catch (e) {
        if (e.message.includes('UNIQUE constraint')) {
            return c.json({ error: 'Slug ini sudah digunakan.' }, 409);
        }
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});

// 4. DELETE Kategori
app.delete('/admin/categories/:id', adminMiddleware, async (c) => {
    const id = c.req.param('id');
    try {
        // TODO: Cek dulu apakah ada produk yang menggunakan kategori ini
        const { changes } = await c.env.DB.prepare(
            "DELETE FROM categories WHERE id = ?"
        ).bind(id).run();
        if (changes === 0) return c.json({ error: 'Kategori tidak ditemukan' }, 404);
        return c.json({ message: 'Kategori berhasil dihapus' });
    } catch (e) {
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});


// ===========================================
// RUTE ADMIN (CRUD PRODUK)
// ===========================================

// 1. CREATE Produk Baru
app.post('/admin/products', adminMiddleware, async (c) => {
    const body = await c.req.json();
    try {
        const { name, description, price, product_type, digital_content, image_url, category_id } = body;
        if (!name || !price || !product_type) {
            return c.json({ error: 'Nama, Harga, dan Tipe Produk wajib diisi.' }, 400);
        }

        const query = c.env.DB.prepare(
            `INSERT INTO products (name, description, price, product_type, digital_content, image_url, category_id)
             VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`
        ).bind(name, description, price, product_type, digital_content, image_url, category_id);
        const newProduct = await query.first();
        return c.json({ message: 'Produk berhasil dibuat', data: newProduct }, 201);
    } catch (e) {
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});

// 2. READ Semua Produk (Simple)
app.get('/admin/products', adminMiddleware, async (c) => {
    const { results } = await c.env.DB.prepare(
        "SELECT p.id, p.name, p.price, p.product_type, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC"
    ).all();
    return c.json({ data: results || [] });
});

// 3. READ Satu Produk (Detail untuk Edit)
app.get('/admin/products/:id', adminMiddleware, async (c) => {
    const id = c.req.param('id');
    const product = await c.env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
    if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    
    // Ambil juga galeri
    const { results: gallery } = await c.env.DB.prepare(
        "SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC"
    ).bind(id).all();
    
    return c.json({ data: { ...product, gallery: gallery || [] } });
});


// 4. UPDATE Produk
app.put('/admin/products/:id', adminMiddleware, async (c) => {
    const id = c.req.param('id');
    const body = await c.req.json();
    try {
        const { name, description, price, product_type, digital_content, image_url, category_id } = body;
        if (!name || !price || !product_type) {
            return c.json({ error: 'Nama, Harga, dan Tipe Produk wajib diisi.' }, 400);
        }

        const query = c.env.DB.prepare(
            `UPDATE products SET 
             name = ?, description = ?, price = ?, product_type = ?, 
             digital_content = ?, image_url = ?, category_id = ?
             WHERE id = ? RETURNING *`
        ).bind(name, description, price, product_type, digital_content, image_url, category_id, id);
        const updatedProduct = await query.first();
        
        if (!updatedProduct) return c.json({ error: 'Produk tidak ditemukan' }, 404);
        return c.json({ message: 'Produk berhasil diperbarui', data: updatedProduct });
    } catch (e) {
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});

// 5. DELETE Produk
app.delete('/admin/products/:id', adminMiddleware, async (c) => {
    const id = c.req.param('id');
    // Transaksi D1 untuk menghapus produk DAN stok/galeri terkait
    try {
        const queries = [
            c.env.DB.prepare("DELETE FROM products WHERE id = ?").bind(id),
            c.env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(id),
            c.env.DB.prepare("DELETE FROM product_stock_unique WHERE product_id = ?").bind(id)
        ];
        await c.env.DB.batch(queries);
        return c.json({ message: 'Produk dan semua data terkait berhasil dihapus' });
    } catch (e) {
        return c.json({ error: 'Kesalahan internal: ' + e.message }, 500);
    }
});

// ===========================================
// RUTE ADMIN (GALERI & STOK)
// ===========================================

// READ Galeri (sudah ada di /admin/products/:id)

// UPDATE Galeri (Overwrite)
app.post('/admin/products/:id/gallery', adminMiddleware, async (c) => {
    const productId = c.req.param('id');
    const body = await c.req.json(); // { images: ["/images/url1.png", "/images/url2.png"] }
    if (!body.images || !Array.isArray(body.images)) {
        return c.json({ error: 'Input harus berupa array { "images": [...] }' }, 400);
    }
    try {
        const queries = [
            c.env.DB.prepare("DELETE FROM product_images WHERE product_id = ?").bind(productId)
        ];
        let sortOrder = 0;
        for (const imageUrl of body.images) {
            queries.push(
                c.env.DB.prepare(
                    "INSERT INTO product_images (product_id, image_url, sort_order) VALUES (?, ?, ?)"
                ).bind(productId, imageUrl, sortOrder)
            );
            sortOrder++;
        }
        await c.env.DB.batch(queries);
        return c.json({ message: `Galeri berhasil diperbarui dengan ${body.images.length} gambar.` });
    } catch (e) {
        return c.json({ error: 'Gagal memperbarui galeri: ' + e.message }, 500);
    }
});

// CREATE/UPDATE Stok Unik (Bulk)
app.post('/admin/products/:id/stock', adminMiddleware, async (c) => {
    const productId = c.req.param('id');
    const body = await c.req.json(); // { stock_items: ["key1", "key2", "key3"] }
    if (!body.stock_items || !Array.isArray(body.stock_items)) {
        return c.json({ error: 'Input harus berupa array { "stock_items": [...] }' }, 400);
    }
    try {
        const queries = body.stock_items.map(item => 
            c.env.DB.prepare(
                "INSERT INTO product_stock_unique (product_id, content) VALUES (?, ?)"
            ).bind(productId, item)
        );
        await c.env.DB.batch(queries);
        return c.json({ message: `Stok berhasil ditambahkan: ${body.stock_items.length} item.` }, 201);
    } catch (e) {
        return c.json({ error: 'Gagal menambah stok: ' + e.message }, 500);
    }
});


// ===========================================
// RUTE TOKO PUBLIK (FRONTEND)
// ===========================================

// 1. READ Semua Produk (Publik)
app.get('/shop/products', async (c) => {
    // TODO: Tambahkan paginasi
    const { results } = await c.env.DB.prepare(
        "SELECT p.id, p.name, p.price, p.image_url, c.name as category_name, c.slug as category_slug FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.name ASC"
    ).all();
    return c.json({ data: results || [] });
});

// 2. READ Satu Produk (Publik)
app.get('/shop/products/:id', async (c) => {
    const id = c.req.param('id');
    const product = await c.env.DB.prepare("SELECT * FROM products WHERE id = ?").bind(id).first();
    if (!product) return c.json({ error: 'Produk tidak ditemukan' }, 404);
    
    const { results: gallery } = await c.env.DB.prepare(
        "SELECT * FROM product_images WHERE product_id = ? ORDER BY sort_order ASC"
    ).bind(id).all();
    
    // Jangan kirim 'digital_content' ke publik
    const { digital_content, ...publicProduct } = product;
    
    return c.json({ data: { ...publicProduct, gallery: gallery || [] } });
});


// ===========================================
// RUTE CHECKOUT (PASPAY)
// ===========================================

// Helper untuk mengambil harga dasar dari Paspay API
// (Di Hono, kita tidak bisa menggunakan 'calculateTransactionDetails'
// karena kode unik Paspay dibuat di server Paspay, bukan di sini)
async function getPaspayInvoice(c, productId, userId) {
    const product = await c.env.DB.prepare("SELECT id, name, price FROM products WHERE id = ?").bind(productId).first();
    if (!product) throw new Error('Produk tidak ditemukan');

    const user = await c.env.DB.prepare("SELECT email, name FROM users WHERE id = ?").bind(userId).first();
    
    const paspayApiUrl = c.env.PASPAY_API_URL || 'https://paspay.id/api/v1/transactions';
    const paspayApiKey = c.env.PASPAY_API_KEY;

    // TODO: Ganti 'payment_channel_id' agar dinamis atau dari konfigurasi
    const payload = {
        project_id: c.env.PASPAY_PROJECT_ID, // Harus diset di secrets
        payment_channel_id: [1, 3], // Contoh: [QRIS, VA]
        amount: product.price,
        internal_ref_id: `MINICOM-${product.id}-${Date.now()}`,
        description: `Pembelian: ${product.name}`,
        customer_email: user?.email,
        customer_name: user?.name
    };

    const response = await fetch(paspayApiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${paspayApiKey}`
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(`Paspay API Error: ${err.error || response.statusText}`);
    }

    const data = await response.json();
    return { paspayData: data, product: product };
}


// 1. CREATE Order (Memulai Checkout)
// Ini dipanggil oleh user (terotentikasi) saat klik "Beli"
app.post('/checkout/create-order', authMiddleware, async (c) => {
    const user = c.get('user');
    const body = await c.req.json(); // { product_id: 123 }
    
    if (!body.product_id) return c.json({ error: 'product_id wajib diisi' }, 400);

    try {
        // 1. Panggil Paspay untuk membuat invoice
        const { paspayData, product } = await getPaspayInvoice(c, body.product_id, user.sub);
        
        // 2. Simpan order ke D1
        const query = c.env.DB.prepare(
            `INSERT INTO orders (user_id, product_id, status, paspay_reference_id, total_amount, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
            user.sub,
            product.id,
            'UNPAID',
            paspayData.reference_id,
            paspayData.total_amount_expected,
            Math.floor(Date.now() / 1000)
        );
        await query.run();

        // 3. Kembalikan detail pembayaran ke frontend
        return c.json(paspayData);

    } catch (e) {
        return c.json({ error: 'Gagal membuat order: ' + e.message }, 500);
    }
});


// 2. WEBHOOK dari Paspay
app.post('/webhook/paspay', async (c) => {
    const body = await c.req.json();
    
    // 1. Validasi Keamanan Webhook
    const expectedToken = c.env.PASPAY_WEBHOOK_TOKEN; // Harus diset di secrets
    const authHeader = c.req.header('Authorization');
    const incoming_token = (authHeader || '').replace('Bearer ', '');

    if (!expectedToken || incoming_token !== expectedToken) {
        return c.json({ error: 'Unauthorized' }, 401);
    }
    
    if (!body || body.event !== 'payment.success' || !body.data) {
        return c.json({ error: 'Payload tidak valid' }, 400);
    }

    // 2. Proses Logika Pengiriman
    const txData = body.data;
    const referenceId = txData.reference_id;

    try {
        // Cari order di D1
        const order = await c.env.DB.prepare(
            "SELECT * FROM orders WHERE paspay_reference_id = ? AND status = 'UNPAID'"
        ).bind(referenceId).first();

        if (!order) {
            console.log(`Webhook diterima untuk order yang tidak ditemukan/sudah lunas: ${referenceId}`);
            return c.json({ message: 'OK (Sudah diproses)' });
        }

        // Ambil info produk
        const product = await c.env.DB.prepare(
            "SELECT * FROM products WHERE id = ?"
        ).bind(order.product_id).first();
        
        if (!product) throw new Error(`Produk (ID: ${order.product_id}) tidak ditemukan.`);

        let delivered_content = null;

        if (product.product_type === 'STANDARD') {
            // Ebook/link: stok tak terbatas, langsung ambil
            delivered_content = product.digital_content;
        
        } else if (product.product_type === 'UNIQUE') {
            // Lisensi: ambil satu, tandai terjual
            const stock = await c.env.DB.prepare(
                "SELECT id, content FROM product_stock_unique WHERE product_id = ? AND is_sold = 0 LIMIT 1"
            ).bind(product.id).first();

            if (!stock) {
                // STOK HABIS!
                throw new Error(`Stok habis untuk produk ${product.id}`);
            }
            
            // Tandai terjual
            await c.env.DB.prepare(
                "UPDATE product_stock_unique SET is_sold = 1, order_id = ? WHERE id = ?"
            ).bind(order.id, stock.id).run();
            
            delivered_content = stock.content;
        }

        if (delivered_content) {
            // Update order
            await c.env.DB.prepare(
                "UPDATE orders SET status = 'PAID', delivered_content = ? WHERE id = ?"
            ).bind(delivered_content, order.id).run();

            // TODO: Kirim email ke pelanggan berisi 'delivered_content'
            // sendEmail(user.email, "Produk Anda Siap!", ...);
            
        } else {
            throw new Error('Konten digital tidak ditemukan (product_type tidak valid?)');
        }

        return c.json({ message: 'OK' }); // Wajib HTTP 200

    } catch (e) {
        console.error(`Webhook Gagal Diproses (Ref: ${referenceId}): ${e.message}`);
        // Kirim 500 agar Paspay mencoba lagi (jika stok habis, ini akan terus gagal)
        return c.json({ error: 'Gagal memproses pengiriman: ' + e.message }, 500);
    }
});

// Ekspor handler untuk Cloudflare
export const onRequest = handle(app);
