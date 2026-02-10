const Database = require("better-sqlite3");
const path = require("path");

const dbPath = path.join(__dirname, "data", "app.db");
const db = new Database(dbPath);

// posts
db.exec(`
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  thumbnail_path TEXT,
  is_published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
`);

// ✅ 기존 DB 업그레이드: 오퍼시트 저장 컬럼 추가
try { db.exec(`ALTER TABLE posts ADD COLUMN offer_json TEXT;`); } catch (_) {}
try { db.exec(`ALTER TABLE posts ADD COLUMN offer_note TEXT;`); } catch (_) {}

// post_images
db.exec(`
CREATE TABLE IF NOT EXISTS post_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  image_path TEXT NOT NULL,
  sort_order INTEGER DEFAULT 0,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);
`);

// home_settings (2개 문구)
db.exec(`
CREATE TABLE IF NOT EXISTS home_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  hero_text TEXT NOT NULL DEFAULT 'Welcome',
  about_text TEXT NOT NULL DEFAULT 'About SNF SEMI',
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
`);

// ✅ 기존 DB 사용자 업그레이드(컬럼 추가)
try { db.exec(`ALTER TABLE home_settings ADD COLUMN hero_text TEXT NOT NULL DEFAULT 'Welcome';`); } catch (_) {}
try { db.exec(`ALTER TABLE home_settings ADD COLUMN about_text TEXT NOT NULL DEFAULT 'About SNF SEMI';`); } catch (_) {}

// ✅ id=1 row 강제 생성
const home = db.prepare("SELECT * FROM home_settings WHERE id=1").get();
if (!home) {
  db.prepare("INSERT INTO home_settings (id, hero_text, about_text) VALUES (1, ?, ?)").run(
    "Welcome",
    "About SNF SEMI"
  );
}

// offer_access_settings (offers 페이지 비밀번호)
db.exec(`
CREATE TABLE IF NOT EXISTS offer_access_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
`);

// id=1 row 강제 생성 (기본 비번: offer1234)
const offerAccess = db.prepare("SELECT * FROM offer_access_settings WHERE id=1").get();
if (!offerAccess) {
  const bcrypt = require("bcrypt");
  const hash = bcrypt.hashSync("offer1234", 10);
  db.prepare("INSERT INTO offer_access_settings (id, password_hash) VALUES (1, ?)").run(hash);
}

module.exports = db;
