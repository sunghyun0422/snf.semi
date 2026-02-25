const { createClient } = require("@libsql/client");

const url = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

if (!url) throw new Error("Missing TURSO_DATABASE_URL");
if (!authToken) throw new Error("Missing TURSO_AUTH_TOKEN");

const client = createClient({ url, authToken });

async function exec(sql) {
  return client.execute(sql);
}
async function get(sql, args = []) {
  const r = await client.execute({ sql, args });
  return r.rows[0] || null;
}
async function all(sql, args = []) {
  const r = await client.execute({ sql, args });
  return r.rows || [];
}
async function run(sql, args = []) {
  return client.execute({ sql, args });
}

async function migrate() {
  await exec(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      thumbnail_path TEXT,
      is_published INTEGER NOT NULL DEFAULT 1,
      offer_json TEXT,
      offer_note TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // ✅ home_settings: 새 스키마 + 구 스키마(hero_text/about_text) 둘 다 지원
  await exec(`
    CREATE TABLE IF NOT EXISTS home_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      hero_title TEXT NOT NULL DEFAULT 'SNF SEMI',
      hero_subtitle TEXT NOT NULL DEFAULT 'Welcome',
      about_title TEXT NOT NULL DEFAULT 'About',
      about_text TEXT NOT NULL DEFAULT 'About SNF SEMI',
      hero_text TEXT NOT NULL DEFAULT 'Welcome',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // ✅ 기존 DB 업그레이드: 컬럼 없으면 추가(있으면 에러 -> 무시)
  try { await exec(`ALTER TABLE home_settings ADD COLUMN hero_text TEXT NOT NULL DEFAULT 'Welcome';`); } catch (_) {}
  try { await exec(`ALTER TABLE home_settings ADD COLUMN hero_title TEXT NOT NULL DEFAULT 'SNF SEMI';`); } catch (_) {}
  try { await exec(`ALTER TABLE home_settings ADD COLUMN hero_subtitle TEXT NOT NULL DEFAULT 'Welcome';`); } catch (_) {}
  try { await exec(`ALTER TABLE home_settings ADD COLUMN about_title TEXT NOT NULL DEFAULT 'About';`); } catch (_) {}
  try { await exec(`ALTER TABLE home_settings ADD COLUMN about_text TEXT NOT NULL DEFAULT 'About SNF SEMI';`); } catch (_) {}

  await exec(`
    CREATE TABLE IF NOT EXISTS offer_access_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // ✅ id=1 row 보장 + 구/신 스키마 값 동기화
  const home = await get(`SELECT * FROM home_settings WHERE id=1`);
  if (!home) {
    await run(
      `INSERT INTO home_settings (id, hero_title, hero_subtitle, about_title, about_text, hero_text)
       VALUES (1, ?, ?, ?, ?, ?)`,
      ["SNF SEMI", "Welcome", "About", "About SNF SEMI", "Welcome"]
    );
  } else {
    if (!home.hero_text) {
      await run(`UPDATE home_settings SET hero_text=?, updated_at=datetime('now') WHERE id=1`, [
        home.hero_subtitle || "Welcome",
      ]);
    }
    if (!home.hero_title) {
      await run(`UPDATE home_settings SET hero_title=?, updated_at=datetime('now') WHERE id=1`, ["SNF SEMI"]);
    }
    if (!home.hero_subtitle) {
      await run(`UPDATE home_settings SET hero_subtitle=?, updated_at=datetime('now') WHERE id=1`, [
        home.hero_text || "Welcome",
      ]);
    }
    if (!home.about_title) {
      await run(`UPDATE home_settings SET about_title=?, updated_at=datetime('now') WHERE id=1`, ["About"]);
    }
    if (!home.about_text) {
      await run(`UPDATE home_settings SET about_text=?, updated_at=datetime('now') WHERE id=1`, ["About SNF SEMI"]);
    }
  }

  const offer = await get(`SELECT * FROM offer_access_settings WHERE id=1`);
  if (!offer) {
    const bcrypt = require("bcrypt");
    const hash = bcrypt.hashSync("offer1234", 10);
    await run(`INSERT INTO offer_access_settings (id, password_hash) VALUES (1, ?)`, [hash]);
  }

  // =========================
  // ✅ admin_users / admin_otp
  // =========================
  await exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS admin_otp (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      otp_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const admin = await get(`SELECT * FROM admin_users WHERE id=1`);
  if (!admin) {
    const bcrypt = require("bcrypt");
    const hash = bcrypt.hashSync("essenef007", 10);
    await run(
      `INSERT INTO admin_users (id, username, password_hash) VALUES (1, ?, ?)`,
      ["keennice", hash]
    );
  }

  // =========================
  // ✅ attachments
  // =========================
  await exec(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      data BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (post_id) REFERENCES posts(id)
    );
  `);

  await exec(`CREATE INDEX IF NOT EXISTS idx_attachments_post_id ON attachments(post_id);`);
}

module.exports = { exec, get, all, run, migrate };