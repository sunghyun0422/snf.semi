const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./db");

const app = express();
const PORT = 3000;

// =========================
// 관리자 계정 (필요하면 여기만 바꿔)
// =========================
const ADMIN_ID = "keennice";
const ADMIN_PASSWORD_HASH = bcrypt.hashSync("essenef007", 10);

// =========================
// 기본 설정
// =========================
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/public", express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "snf-semi-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// =========================
// 미들웨어
// =========================
function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect("/admin/login");
}

function requireOfferAccess(req, res, next) {
  // ✅ 관리자는 offers 비번 없이 바로 통과
  if (req.session?.isAdmin) return next();

  // ✅ 일반 사용자는 offers 비번 통과해야 함
  if (req.session?.offerAccess) return next();

  return res.redirect("/offers/login");
}


// =========================
// DB 안전 업그레이드 (없으면 추가)
// =========================
try {
  db.exec(`ALTER TABLE posts ADD COLUMN offer_json TEXT;`);
} catch (_) {}
try {
  db.exec(`ALTER TABLE posts ADD COLUMN offer_note TEXT;`);
} catch (_) {}

db.exec(`
CREATE TABLE IF NOT EXISTS offer_access_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
`);

// 기본 offer 비밀번호 row 생성 (기본: offer1234)
const offerAccess = db.prepare("SELECT * FROM offer_access_settings WHERE id=1").get();
if (!offerAccess) {
  const hash = bcrypt.hashSync("offer1234", 10);
  db.prepare("INSERT INTO offer_access_settings (id, password_hash) VALUES (1, ?)").run(hash);
}

// =========================
// 홈
// =========================
app.get("/", (req, res) => {
  const home = db.prepare(`SELECT * FROM home_settings WHERE id=1`).get();
  res.render("home", { siteName: "SNF SEMI", home });
});

// =========================
// OFFERS 접근 비번 입력
// =========================
app.get("/offers/login", (req, res) => {
  res.render("offers_login", { siteName: "SNF SEMI", error: null });
});

app.post("/offers/login", (req, res) => {
  const { password } = req.body;

  const row = db.prepare("SELECT password_hash FROM offer_access_settings WHERE id=1").get();
  const ok = row && bcrypt.compareSync(password || "", row.password_hash);

  if (!ok) {
    return res.render("offers_login", { siteName: "SNF SEMI", error: "Wrong password." });
  }

  req.session.offerAccess = true;
  res.redirect("/offers");
});

app.post("/offers/logout", (req, res) => {
  req.session.offerAccess = false;
  res.redirect("/");
});

// =========================
// OFFERS 리스트 (비번 통과해야 접근 가능)
// =========================
app.get("/offers", requireOfferAccess, (req, res) => {
  const posts = db
    .prepare(`
      SELECT id, title, created_at, offer_json
      FROM posts
      WHERE is_published=1
      ORDER BY id DESC
    `)
    .all();

  res.render("offers", { siteName: "SNF SEMI", posts });
});

// =========================
// 오퍼 상세 (비번 통과해야 접근 가능)
// =========================
app.get("/post/:id", requireOfferAccess, (req, res) => {
  const id = Number(req.params.id);

  const post = db.prepare(`SELECT * FROM posts WHERE id=? AND is_published=1`).get(id);
  if (!post) return res.status(404).send("Offer not found.");

  let offer = null;
  try {
    offer = post.offer_json ? JSON.parse(post.offer_json) : null;
  } catch (_) {
    offer = null;
  }

  res.render("post", { siteName: "SNF SEMI", post, offer });
});

// =========================
// 관리자 로그인
// =========================
app.get("/admin/login", (req, res) => res.render("admin_login", { error: null }));

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (username !== ADMIN_ID) {
    return res.render("admin_login", { error: "아이디 또는 비밀번호가 틀렸습니다." });
  }

  const ok = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
  if (!ok) {
    return res.render("admin_login", { error: "아이디 또는 비밀번호가 틀렸습니다." });
  }

  req.session.isAdmin = true;
  res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// =========================
// 관리자 대시보드
// =========================
app.get("/admin", requireAdmin, (req, res) => {
  const posts = db
    .prepare(`SELECT id, title, is_published, created_at, updated_at FROM posts ORDER BY id DESC`)
    .all();

  res.render("admin_dashboard", { siteName: "SNF SEMI", posts });
});

// =========================
// 관리자: 홈 문구 편집
// =========================
app.get("/admin/home", requireAdmin, (req, res) => {
  const home = db.prepare(`SELECT * FROM home_settings WHERE id=1`).get();
  res.render("admin_home", { siteName: "SNF SEMI", home });
});

app.post("/admin/home", requireAdmin, (req, res) => {
  const { hero_title, hero_subtitle, about_title, about_text } = req.body;

  // home_settings 컬럼 안전 업그레이드
  try { db.exec(`ALTER TABLE home_settings ADD COLUMN hero_title TEXT NOT NULL DEFAULT 'SNF SEMI';`); } catch (_) {}
  try { db.exec(`ALTER TABLE home_settings ADD COLUMN hero_subtitle TEXT NOT NULL DEFAULT 'Welcome';`); } catch (_) {}
  try { db.exec(`ALTER TABLE home_settings ADD COLUMN about_title TEXT NOT NULL DEFAULT 'About';`); } catch (_) {}
  try { db.exec(`ALTER TABLE home_settings ADD COLUMN about_text TEXT NOT NULL DEFAULT 'About SNF SEMI';`); } catch (_) {}

  db.prepare(`
    UPDATE home_settings
    SET hero_title=?,
        hero_subtitle=?,
        about_title=?,
        about_text=?,
        updated_at=datetime('now','localtime')
    WHERE id=1
  `).run(
    hero_title || "SNF SEMI",
    hero_subtitle || "Welcome",
    about_title || "About",
    about_text || "About SNF SEMI"
  );

  res.redirect("/admin/home");
});

// =========================
// 관리자: OFFERS 접근 비밀번호 변경
// =========================
app.get("/admin/offers-password", requireAdmin, (req, res) => {
  res.render("admin_offers_password", { siteName: "SNF SEMI", error: null, success: null });
});

app.post("/admin/offers-password", requireAdmin, (req, res) => {
  const { new_password, new_password_confirm } = req.body;

  if (!new_password || new_password.length < 4) {
    return res.render("admin_offers_password", { siteName: "SNF SEMI", error: "비밀번호는 최소 4자 이상", success: null });
  }
  if (new_password !== new_password_confirm) {
    return res.render("admin_offers_password", { siteName: "SNF SEMI", error: "비밀번호 확인이 다릅니다.", success: null });
  }

  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare(`
    UPDATE offer_access_settings
    SET password_hash=?, updated_at=datetime('now','localtime')
    WHERE id=1
  `).run(hash);

  // 기존 세션 offerAccess도 다시 요구하고 싶으면 아래 한 줄 추가 가능:
  // req.session.offerAccess = false;

  return res.render("admin_offers_password", { siteName: "SNF SEMI", error: null, success: "저장 완료!" });
});

// =========================
// 관리자: 오퍼 작성/수정 (오퍼시트 폼)
// =========================
function buildOfferFromBody(body) {
  const items = [];

  const descArr = Array.isArray(body["item_desc[]"]) ? body["item_desc[]"] : body["item_desc[]"] ? [body["item_desc[]"]] : [];
  const qtyArr = Array.isArray(body["item_qty[]"]) ? body["item_qty[]"] : body["item_qty[]"] ? [body["item_qty[]"]] : [];
  const unitArr = Array.isArray(body["item_unit[]"]) ? body["item_unit[]"] : body["item_unit[]"] ? [body["item_unit[]"]] : [];

  const len = Math.max(descArr.length, qtyArr.length, unitArr.length);
  for (let i = 0; i < len; i++) {
    const desc = (descArr[i] ?? "").trim();
    const qty = (qtyArr[i] ?? "").toString().trim();
    const unit = (unitArr[i] ?? "").toString().trim();

    if (!desc && !qty && !unit) continue;
    items.push({ desc, qty, unit });
  }

  return {
    messrs: body.messrs || "",
    buyer_address: body.buyer_address || "",
    date: body.date || "",
    invoice_no: body.invoice_no || "",
    destination: body.destination || "",
    payment: body.payment || "",
    price_terms: body.price_terms || "",
    shipment: body.shipment || "",
    origin: body.origin || "",
    packing: body.packing || "",
    bank_info: body.bank_info || "",
    items,
  };
}

app.get("/admin/new", requireAdmin, (req, res) => {
  res.render("admin_edit", {
    siteName: "SNF SEMI",
    mode: "new",
    post: {
      title: "",
      is_published: 1,
      offer_note: "",
      offer: { items: [{ desc: "", qty: "", unit: "" }] },
    },
  });
});

app.post("/admin/new", requireAdmin, (req, res) => {
  const { title, is_published, offer_note } = req.body;

  const offer = buildOfferFromBody(req.body);
  const offer_json = JSON.stringify(offer);

  db.prepare(`
    INSERT INTO posts (title, content, thumbnail_path, is_published, offer_json, offer_note)
    VALUES (?,?,?,?,?,?)
  `).run(
    title,
    "",        // content는 이제 안 씀
    null,      // thumbnail도 안 씀
    Number(is_published),
    offer_json,
    offer_note || ""
  );

  res.redirect("/admin");
});

app.get("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const post = db.prepare(`SELECT * FROM posts WHERE id=?`).get(id);
  if (!post) return res.status(404).send("Offer not found");

  let offer = null;
  try { offer = post.offer_json ? JSON.parse(post.offer_json) : null; } catch (_) { offer = null; }
  if (!offer) offer = { items: [{ desc: "", qty: "", unit: "" }] };

  res.render("admin_edit", {
    siteName: "SNF SEMI",
    mode: "edit",
    post: { ...post, offer },
  });
});

app.post("/admin/edit/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const current = db.prepare(`SELECT * FROM posts WHERE id=?`).get(id);
  if (!current) return res.status(404).send("Offer not found");

  const { title, is_published, offer_note } = req.body;

  const offer = buildOfferFromBody(req.body);
  const offer_json = JSON.stringify(offer);

  db.prepare(`
    UPDATE posts
    SET title=?,
        is_published=?,
        offer_json=?,
        offer_note=?,
        updated_at=datetime('now','localtime')
    WHERE id=?
  `).run(
    title,
    Number(is_published),
    offer_json,
    offer_note || "",
    id
  );

  res.redirect("/admin");
});

app.post("/admin/toggle/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare(`SELECT is_published FROM posts WHERE id=?`).get(id);
  if (!row) return res.status(404).send("Offer not found");

  const next = row.is_published === 1 ? 0 : 1;
  db.prepare(`UPDATE posts SET is_published=?, updated_at=datetime('now','localtime') WHERE id=?`).run(next, id);
  res.redirect("/admin");
});

app.post("/admin/delete/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare(`DELETE FROM posts WHERE id=?`).run(id);
  res.redirect("/admin");
});

// =========================
// 서버 시작
// =========================
app.listen(PORT, () => console.log(`SNF SEMI running → http://localhost:${PORT}`));
