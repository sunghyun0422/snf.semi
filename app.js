const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const db = require("./db");

const app = express();

// =========================
// 관리자 계정 (공개 repo면 env로 빼는 걸 강력 추천)
// =========================
const ADMIN_ID = process.env.ADMIN_ID || "keennice";

// ⚠️ 운영에서는 ADMIN_PASSWORD_HASH를 env로 넣어라.
// 기본값은 기존과 동일하게 essenef007을 해시해서 사용.
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

// 서버리스 안정 쿠키(세션 대체)
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
// 미들웨어 (세션 -> signed cookie)
// =========================
function requireAdmin(req, res, next) {
  if (req.signedCookies?.admin === "1") return next();
  return res.redirect("/admin/login");
}

function requireOfferAccess(req, res, next) {
  // ✅ 관리자는 offers 비번 없이 바로 통과
  if (req.signedCookies?.admin === "1") return next();

  // ✅ 일반 사용자는 offers 비번 통과해야 함
  if (req.signedCookies?.offer === "1") return next();

  return res.redirect("/offers/login");
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
// OFFERS 접근 비번 입력
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

  // offerAccess -> signed cookie
  res.cookie("offer", "1", { signed: true, httpOnly: true, sameSite: "lax" });
  return res.redirect("/offers");
});

app.post("/offers/logout", async (req, res) => {
  res.clearCookie("offer");
  res.redirect("/");
});

// =========================
// OFFERS 리스트 (비번 통과해야 접근 가능)
// =========================
app.get("/offers", requireOfferAccess, async (req, res) => {
  await ensureDb();

  const posts = await db.all(
    `
      SELECT id, title, created_at, offer_json
      FROM posts
      WHERE is_published=1
      ORDER BY id DESC
    `
  );

  res.render("offers", { siteName: "SNF SEMI", posts });
});

// =========================
// 오퍼 상세 (비번 통과해야 접근 가능)
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

  // isAdmin -> signed cookie
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
    `SELECT id, title, is_published, created_at, updated_at FROM posts ORDER BY id DESC`
  );

  res.render("admin_dashboard", { siteName: "SNF SEMI", posts });
});

// =========================
// 관리자: 홈 문구 편집
// =========================
app.get("/admin/home", requireAdmin, async (req, res) => {
  await ensureDb();

  // 너 기존 home.ejs가 hero_text/about_text를 쓰든,
  // hero_title/hero_subtitle/about_title/about_text를 쓰든 둘 다 커버하려고
  // DB에는 migrate에서 hero_text/about_text가 있다고 가정(네 db.js 버전 기준)
  const home = await db.get(`SELECT * FROM home_settings WHERE id=1`);
  res.render("admin_home", { siteName: "SNF SEMI", home });
});

app.post("/admin/home", requireAdmin, async (req, res) => {
  await ensureDb();

  // ✅ 네 기존 server.js는 hero_title/hero_subtitle/about_title/about_text를 받는데,
  // ✅ db.js(네가 교체한 turso migrate 버전)는 hero_text/about_text 버전일 수도 있고,
  // ✅ 내가 전에 준 migrate는 hero_title/hero_subtitle/about_title/about_text 버전임.
  //
  // 여기서는 “둘 중 뭐를 쓰든” 깨지지 않게:
  // 1) hero_title 등이 있으면 그걸 우선 반영
  // 2) 없다면 hero_text/about_text로라도 반영

  const body = req.body || {};

  const hero_title = body.hero_title ?? body.hero_text ?? null;
  const hero_subtitle = body.hero_subtitle ?? null;
  const about_title = body.about_title ?? null;
  const about_text = body.about_text ?? null;

  // 컬럼 존재 여부를 모를 때는 "업데이트 시도 -> 실패하면 fallback" 방식이 안전함.
  // Turso(libsql) 에러 캐치해서 fallback.
  try {
    // hero_title/hero_subtitle/about_title/about_text 스키마
    await db.run(
      `
      UPDATE home_settings
      SET hero_title=?,
          hero_subtitle=?,
          about_title=?,
          about_text=?,
          updated_at=datetime('now')
      WHERE id=1
      `,
      [
        hero_title || "SNF SEMI",
        hero_subtitle || "Welcome",
        about_title || "About",
        about_text || "About SNF SEMI",
      ]
    );
  } catch (e) {
    // hero_text/about_text 스키마
    await db.run(
      `
      UPDATE home_settings
      SET hero_text=?,
          about_text=?,
          updated_at=datetime('now')
      WHERE id=1
      `,
      [
        hero_title || "Welcome",
        about_text || "About SNF SEMI",
      ]
    );
  }

  res.redirect("/admin/home");
});

// =========================
// 관리자: OFFERS 접근 비밀번호 변경
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
    `
    UPDATE offer_access_settings
    SET password_hash=?, updated_at=datetime('now')
    WHERE id=1
    `,
    [hash]
  );

  // 기존 offer 쿠키를 다시 요구하고 싶으면 아래 한 줄
  // res.clearCookie("offer");

  return res.render("admin_offers_password", {
    siteName: "SNF SEMI",
    error: null,
    success: "저장 완료!",
  });
});

// =========================
// 관리자: 오퍼 작성/수정 (오퍼시트 폼)
// =========================
function buildOfferFromBody(body) {
  const items = [];

  const descArr = Array.isArray(body["item_desc[]"])
    ? body["item_desc[]"]
    : body["item_desc[]"]
    ? [body["item_desc[]"]]
    : [];
  const qtyArr = Array.isArray(body["item_qty[]"])
    ? body["item_qty[]"]
    : body["item_qty[]"]
    ? [body["item_qty[]"]]
    : [];
  const unitArr = Array.isArray(body["item_unit[]"])
    ? body["item_unit[]"]
    : body["item_unit[]"]
    ? [body["item_unit[]"]]
    : [];

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
    `
    INSERT INTO posts (title, content, thumbnail_path, is_published, offer_json, offer_note, created_at, updated_at)
    VALUES (?, '', NULL, ?, ?, ?, datetime('now'), datetime('now'))
    `,
    [title, Number(is_published), offer_json, offer_note || ""]
  );

  res.redirect("/admin");
});

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
    `
    UPDATE posts
    SET title=?,
        is_published=?,
        offer_json=?,
        offer_note=?,
        updated_at=datetime('now')
    WHERE id=?
    `,
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
