// Ganti hanya fungsi loginHandler di functions/api/[[path]].js dengan ini.
// Mengasumsikan `verifyPassword` dan `sign` serta `setCookie` sudah terdefinisi di file.
async function loginHandler(c) {
  const env = c.env;
  let body;
  try {
    body = await c.req.json();
  } catch (e) {
    return c.json({ error: 'Invalid JSON' }, 400);
  }

  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string') {
    return c.json({ error: 'Email dan password wajib' }, 422);
  }

  if (!env.JWT_SECRET) {
    // Fail fast with safe message — this indicates server misconfiguration
    console.error('[LOGIN] JWT_SECRET missing');
    return c.json({ error: 'Server configuration error' }, 500);
  }

  try {
    const user = await env.DB.prepare('SELECT id, password_hash, role, status FROM users WHERE email = ?').bind(body.email).first();
    if (!user) return c.json({ error: 'Email atau password salah' }, 401);

    const ok = await verifyPassword(body.password, user.password_hash);
    if (!ok) return c.json({ error: 'Email atau password salah' }, 401);

    if (user.status !== 'active') return c.json({ error: 'Akun tidak aktif' }, 403);

    const payload = { sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 };
    const token = await sign(payload, env.JWT_SECRET, 'HS256');

    const host = (c.req.headers.get('host') || '').toLowerCase();
    const isDev = host.includes('localhost') || (typeof process !== 'undefined' && process.env.NODE_ENV === 'development');

    setCookie(c, 'auth_token', token, {
      path: '/',
      httpOnly: true,
      secure: !isDev,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24
    });

    return c.json({ success: true, message: 'Login berhasil' });
  } catch (e) {
    console.error('[LOGIN] unexpected error', e && (e.stack || e.message || e));
    // Return generic error to client (no stack)
    return c.json({ error: 'Internal Server Error' }, 500);
  }
}
