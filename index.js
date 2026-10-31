const express = require('express');
const Database = require('better-sqlite3');
const session = require('express-session');
const helmet = require('helmet');

const app = express();
const db = new Database('database.db');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'drake_panel_secret_key_999',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE,
    duration INTEGER,
    status TEXT DEFAULT 'unused',
    device_id TEXT,
    expires_at DATETIME
  );
  
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  );
`);

const adminCheck = db.prepare('SELECT * FROM admins WHERE username = ?').get('admin');
if (!adminCheck) {
    db.prepare('INSERT INTO admins (username, password) VALUES (?, ?)').run('admin', 'admin123');
}

// --- ADMIN ROUTES ---
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    const admin = db.prepare('SELECT * FROM admins WHERE username = ? AND password = ?').get(username, password);
    if (admin) {
        req.session.isAdmin = true;
        return res.redirect('/admin');
    }
    res.send('Invalid Credentials. <a href="/admin">Try Again</a>');
});

app.get('/admin', (req, res) => {
    if (!req.session.isAdmin) {
        return res.send(`
            <h2>Admin Login</h2>
            <form method="POST" action="/admin/login">
                <input type="text" name="username" placeholder="Username" required /><br><br>
                <input type="password" name="password" placeholder="Password" required /><br><br>
                <button type="submit">Login</button>
            </form>
        `);
    }

    const keys = db.prepare('SELECT * FROM keys ORDER BY id DESC').all();
    let rowsHtml = keys.map(k => `
        <tr>
            <td>${k.key_code}</td>
            <td>${k.duration} Hours</td>
            <td>${k.status}</td>
            <td>${k.device_id || 'None'}</td>
            <td>${k.expires_at || 'Not Started'}</td>
            <td><a href="/admin/delete/${k.id}">Delete</a></td>
        </tr>
    `).join('');

    res.send(`
        <h1>Drake Panel Admin Dashboard</h1>
        <form method="POST" action="/admin/generate">
            <label>Duration (Hours):</label>
            <input type="number" name="duration" value="24" required />
            <label>Quantity:</label>
            <input type="number" name="qty" value="1" required />
            <button type="submit">Generate Keys</button>
        </form>
        <br>
        <table border="1" cellpadding="10">
            <tr>
                <th>Key Code</th>
                <th>Duration</th>
                <th>Status</th>
                <th>Device ID</th>
                <th>Expires At</th>
                <th>Action</th>
            </tr>
            ${rowsHtml}
        </table>
        <br><a href="/admin/logout">Logout</a>
    `);
});

app.post('/admin/generate', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Unauthorized');
    const { duration, qty } = req.body;
    const insert = db.prepare('INSERT INTO keys (key_code, duration) VALUES (?, ?)');
    for (let i = 0; i < qty; i++) {
        const randomCode = 'DRKE-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
        try {
            insert.run(randomCode, duration);
        } catch (e) {
            i--;
        }
    }
    res.redirect('/admin');
});

app.get('/admin/delete/:id', (req, res) => {
    if (!req.session.isAdmin) return res.status(403).send('Unauthorized');
    db.prepare('DELETE FROM keys WHERE id = ?').run(req.params.id);
    res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// --- USER & MOD API ROUTES ---
app.post('/api/verify', (req, res) => {
    const { key, deviceId } = req.body;
    const keyRow = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);

    if (!keyRow) {
        return jsonResponse(res, false, 'Invalid Key');
    }

    const now = new Date();

    if (keyRow.status === 'expired' || (keyRow.expires_at && new Date(keyRow.expires_at) < now)) {
        db.prepare("UPDATE keys SET status = 'expired' WHERE id = ?").run(keyRow.id);
        return jsonResponse(res, false, 'Key Expired');
    }

    if (keyRow.status === 'unused') {
        const expiresAt = new Date(now.getTime() + keyRow.duration * 3600 * 1000).toISOString();
        db.prepare("UPDATE keys SET status = 'active', device_id = ?, expires_at = ? WHERE id = ?").run(deviceId || 'WEB_USER', expiresAt, keyRow.id);
        return jsonResponse(res, true, 'Key activated successfully', { expires_at: expiresAt });
    }

    if (keyRow.status === 'active') {
        return jsonResponse(res, true, 'Already active', { expires_at: keyRow.expires_at });
    }

    res.json({ success: false, message: 'Unknown error' });
});

app.post('/api/check-mod', (req, res) => {
  const { key } = req.body;
  const keyRow = db.prepare('SELECT * FROM keys WHERE key_code = ?').get(key);

  if (!keyRow || keyRow.status !== 'active') {
    return res.json({ success: false, message: 'Invalid or expired key' });
  }

  res.json({
    success: true,
    message: 'Access granted',
    features: { marker: true, aimpoint: true, glooWallAngle: 180, fastRevive: true }
  });
});

app.get('/sub/:key', (req, res) => {
    const key = req.params.key;
    const keyRow = db.prepare('SELECT * FROM keys WHERE key_code = ? AND status = ?').get(key, 'active');

    if (!keyRow) {
        return res.status(403).send('Forbidden: Invalid or Expired Subscription Key');
    }

    const vlessConfig = `vless://drake-${key}@127.0.0.1:443?encryption=none&security=none&type=tcp#Drake-Key-${key}`;
    res.send(Buffer.from(vlessConfig).toString('base64'));
});

function jsonResponse(res, success, message, extra = {}) {
    res.json({ success, message, ...extra });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Drake Panel running on port ${PORT}`);
});
