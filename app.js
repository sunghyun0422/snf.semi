const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const db = require("./db");

const app = express();
const OFFER_TTL_MS = 30 * 60 * 1000; // 30분

// =========================
// 관리자 계정 (운영에서는 env 권장)
// =========================
const ADMIN_ID = process.env.ADMIN_ID || "keennice";
const ADMIN_PASSWORD_HASH =
  process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync("essenef007", 10);

// =========================
// 기본 설정
// =========================
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/public", express.static(path.join(__dirname, "public")));

app.use(cookieParser(process.env.COOKIE_SECRET || "snf-semi-secret-key"));

// =========================
// DB 마이그레이션(첫 요청 1회만)
// =========================
let migrated = false;
async function ensureDb() {
  if (migrated) return;
  await db.migrate();
  migrated = true;
}

// =========================
// 미들웨어 (signed cookie)
// =========================
function requireAdmin(req, res, next) {
  if (req.signedCookies?.admin === "1") return next();
  return res.redirect("/admin/login");
}

function requireOfferAccess(req, res, next) {
  // ✅ 관리자는 offers 비번 없이 통과
  if (req.signedCookies?.admin === "1") return next();

  const raw = req.signedCookies?.offer; // 우리가 timestamp 저장할 거
  if (!raw) return res.redirect("/offers/login");

  const ts = Number(raw);
  if (!Number.isFinite(ts)) {
    res.clearCookie("offer", { path: "/" });
    return res.redirect("/offers/login");
  }

  // ✅ 30분 지나면 만료
  if (Date.now() - ts > OFFER_TTL_MS) {
    res.clearCookie("offer", { path: "/" });
    return res.redirect("/offers/login");
  }

  return next();
}


// =========================
// 홈
// =========================
app.get("/", async (req, res) => {
  await ensureDb();
  const home = await db.get(`SELECT * FROM home_settings WHERE id=1`);
  res.render("home", { siteName: "SNF SEMI", home });
});

// =========================
// OFFERS 로그인
// =========================
app.get("/offers/login", async (req, res) => {
  await ensureDb();
  res.render("offers_login", { siteName: "SNF SEMI", error: null });
});

app.post("/offers/login", async (req, res) => {
  await ensureDb();

  const { password } = req.body;
  const row = await db.get(`SELECT password_hash FROM offer_access_settings WHERE id=1`);
  const ok = row && bcrypt.compareSync(password || "", row.password_hash);

  if (!ok) {
    return res.render("offers_login", { siteName: "SNF SEMI", error: "Wrong password." });
  }

  // 세션 쿠키(브라우저 종료하면 보통 만료)
  res.cookie("offer", "1", {
  signed: true,
  httpOnly: true,
  sameSite: "strict",
  // maxAge를 주지 않으면 세션 쿠키(브라우저 닫으면 만료)
  // (일부 브라우저가 세션복원할 수 있어 strict로 더 빡세게)
});

  return res.redirect("/offers");
});

app.post("/offers/logout", (req, res) => {
  res.clearCookie("offer", { signed: true });
  res.redirect("/");
});


// =========================
// OFFERS 리스트
// =========================
app.get("/offers", requireOfferAccess, async (req, res) => {
  await ensureDb();

  const posts = await db.all(
    `SELECT id, title, created_at, offer_json
     FROM posts
     WHERE is_published=1
     ORDER BY id DESC`
  );

  res.render("offers", { siteName: "SNF SEMI", posts });
});

// =========================
// 오퍼 상세
// =========================
app.get("/post/:id", requireOfferAccess, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  const post = await db.get(`SELECT * FROM posts WHERE id=? AND is_published=1`, [id]);
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
app.get("/admin/login", async (req, res) => {
  await ensureDb();
  res.render("admin_login", { error: null });
});

app.post("/admin/login", async (req, res) => {
  await ensureDb();

  const { username, password } = req.body;

  if (username !== ADMIN_ID) {
    return res.render("admin_login", { error: "아이디 또는 비밀번호가 틀렸습니다." });
  }

  const ok = bcrypt.compareSync(password || "", ADMIN_PASSWORD_HASH);
  if (!ok) {
    return res.render("admin_login", { error: "아이디 또는 비밀번호가 틀렸습니다." });
  }

  res.cookie("admin", "1", { signed: true, httpOnly: true, sameSite: "lax" });
  res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("admin");
  res.redirect("/");
});

// =========================
// 관리자 대시보드
// =========================
app.get("/admin", requireAdmin, async (req, res) => {
  await ensureDb();

  const posts = await db.all(
    `SELECT id, title, is_published, created_at, updated_at
     FROM posts
     ORDER BY id DESC`
  );

  res.render("admin_dashboard", { siteName: "SNF SEMI", posts });
});

// =========================
// 관리자: 홈 문구 편집 (양쪽 스키마 자동 호환)
// admin_home.ejs는 hero_text / about_text 사용
// =========================
app.get("/admin/home", requireAdmin, async (req, res) => {
  await ensureDb();
  const home = await db.get(`SELECT * FROM home_settings WHERE id=1`);
  res.render("admin_home", { siteName: "SNF SEMI", home });
});

app.post("/admin/home", requireAdmin, async (req, res) => {
  await ensureDb();

  const hero_text = (req.body.hero_text ?? "").toString();
  const about_text = (req.body.about_text ?? "").toString();

  // 1) hero_text/about_text 컬럼이 있으면 그걸로 저장
  try {
    await db.run(
      `UPDATE home_settings
       SET hero_text=?, about_text=?, updated_at=datetime('now')
       WHERE id=1`,
      [hero_text || "Welcome", about_text || "About SNF SEMI"]
    );
    return res.redirect("/admin/home");
  } catch (_) {}

  // 2) 없으면 hero_title/hero_subtitle/about_title/about_text 스키마로 저장
  await db.run(
    `UPDATE home_settings
     SET hero_subtitle=?, about_text=?, updated_at=datetime('now')
     WHERE id=1`,
    [hero_text || "Welcome", about_text || "About SNF SEMI"]
  );

  res.redirect("/admin/home");
});

// =========================
// 관리자: OFFERS 비번 변경
// =========================
app.get("/admin/offers-password", requireAdmin, async (req, res) => {
  await ensureDb();
  res.render("admin_offers_password", { siteName: "SNF SEMI", error: null, success: null });
});

app.post("/admin/offers-password", requireAdmin, async (req, res) => {
  await ensureDb();

  const { new_password, new_password_confirm } = req.body;

  if (!new_password || new_password.length < 4) {
    return res.render("admin_offers_password", {
      siteName: "SNF SEMI",
      error: "비밀번호는 최소 4자 이상",
      success: null,
    });
  }
  if (new_password !== new_password_confirm) {
    return res.render("admin_offers_password", {
      siteName: "SNF SEMI",
      error: "비밀번호 확인이 다릅니다.",
      success: null,
    });
  }

  const hash = bcrypt.hashSync(new_password, 10);
  await db.run(
    `UPDATE offer_access_settings
     SET password_hash=?, updated_at=datetime('now')
     WHERE id=1`,
    [hash]
  );

  return res.render("admin_offers_password", {
    siteName: "SNF SEMI",
    error: null,
    success: "저장 완료!",
  });
});

// =========================
// 오퍼 폼 파서 (✅ 예전 방식: unit = 단가 USD)
// form name: item_desc[] / item_qty[] / item_unit[]
// =========================
function buildOfferFromBody(body) {
  const items = [];
  const arr = (v) => (Array.isArray(v) ? v : v != null ? [v] : []);

  // ✅ [] 붙어서 오든, 안 붙어서 오든 모두 받기
  const descArr = arr(body["item_desc[]"] ?? body.item_desc);
  const qtyArr  = arr(body["item_qty[]"]  ?? body.item_qty);

  // ✅ 예전 방식: item_unit[] = 단가(Unit Price)
  // ✅ 혹시 새 방식(item_price[]) 섞였어도 단가로 흡수
  const unitArr  = arr(body["item_unit[]"]  ?? body.item_unit);
  const priceArr = arr(body["item_price[]"] ?? body.item_price);

  const len = Math.max(descArr.length, qtyArr.length, unitArr.length, priceArr.length);

  for (let i = 0; i < len; i++) {
    const desc = (descArr[i] ?? "").toString().trim();
    const qty  = (qtyArr[i]  ?? "").toString().trim();

    // unit(단가)는 unitArr 우선, 없으면 priceArr fallback
    const unit =
      ((unitArr[i] ?? "").toString().trim()) ||
      ((priceArr[i] ?? "").toString().trim());

    if (!desc && !qty && !unit) continue;
    items.push({ desc, qty, unit }); // ✅ post.ejs가 qty X unit으로 계산하는 구조
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


// =========================
// 관리자: 새 오퍼
// =========================
app.get("/admin/new", requireAdmin, async (req, res) => {
  await ensureDb();

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

app.post("/admin/new", requireAdmin, async (req, res) => {
  await ensureDb();

  const { title, is_published, offer_note } = req.body;

  const offer = buildOfferFromBody(req.body);
  const offer_json = JSON.stringify(offer);

  await db.run(
    `INSERT INTO posts (title, content, thumbnail_path, is_published, offer_json, offer_note, created_at, updated_at)
     VALUES (?, '', NULL, ?, ?, ?, datetime('now'), datetime('now'))`,
    [title, Number(is_published), offer_json, offer_note || ""]
  );

  res.redirect("/admin");
});

// =========================
// 관리자: 수정
// =========================
app.get("/admin/edit/:id", requireAdmin, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  const post = await db.get(`SELECT * FROM posts WHERE id=?`, [id]);
  if (!post) return res.status(404).send("Offer not found");

  let offer = null;
  try {
    offer = post.offer_json ? JSON.parse(post.offer_json) : null;
  } catch (_) {
    offer = null;
  }
  if (!offer) offer = { items: [{ desc: "", qty: "", unit: "" }] };

  res.render("admin_edit", {
    siteName: "SNF SEMI",
    mode: "edit",
    post: { ...post, offer },
  });
});

app.post("/admin/edit/:id", requireAdmin, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  const current = await db.get(`SELECT * FROM posts WHERE id=?`, [id]);
  if (!current) return res.status(404).send("Offer not found");

  const { title, is_published, offer_note } = req.body;

  const offer = buildOfferFromBody(req.body);
  const offer_json = JSON.stringify(offer);

  await db.run(
    `UPDATE posts
     SET title=?,
         is_published=?,
         offer_json=?,
         offer_note=?,
         updated_at=datetime('now')
     WHERE id=?`,
    [title, Number(is_published), offer_json, offer_note || "", id]
  );

  res.redirect("/admin");
});

app.post("/admin/toggle/:id", requireAdmin, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  const row = await db.get(`SELECT is_published FROM posts WHERE id=?`, [id]);
  if (!row) return res.status(404).send("Offer not found");

  const next = Number(row.is_published) === 1 ? 0 : 1;
  await db.run(`UPDATE posts SET is_published=?, updated_at=datetime('now') WHERE id=?`, [next, id]);
  res.redirect("/admin");
});

app.post("/admin/delete/:id", requireAdmin, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  await db.run(`DELETE FROM posts WHERE id=?`, [id]);
  res.redirect("/admin");
});

module.exports = app;
