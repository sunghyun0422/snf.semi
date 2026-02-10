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

  await exec(`
    CREATE TABLE IF NOT EXISTS home_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      hero_title TEXT NOT NULL DEFAULT 'SNF SEMI',
      hero_subtitle TEXT NOT NULL DEFAULT 'Welcome',
      about_title TEXT NOT NULL DEFAULT 'About',
      about_text TEXT NOT NULL DEFAULT 'About SNF SEMI',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  await exec(`
    CREATE TABLE IF NOT EXISTS offer_access_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      password_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const home = await get(`SELECT * FROM home_settings WHERE id=1`);
  if (!home) {
    await run(
      `INSERT INTO home_settings (id, hero_title, hero_subtitle, about_title, about_text) VALUES (1, ?, ?, ?, ?)`,
      ["SNF SEMI", "Welcome", "About", "About SNF SEMI"]
    );
  }

  const offer = await get(`SELECT * FROM offer_access_settings WHERE id=1`);
  if (!offer) {
    const bcrypt = require("bcrypt");
    const hash = bcrypt.hashSync("offer1234", 10);
    await run(`INSERT INTO offer_access_settings (id, password_hash) VALUES (1, ?)`, [hash]);
  }
}

module.exports = { exec, get, all, run, migrate };
