require("dotenv").config();
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const db = require("./db");

const app = express();
const OFFER_TTL_MS = 30 * 60 * 1000; // 30분

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
// 메일 발송 설정 (Gmail SMTP)
// =========================
const mailEnabled =
  !!process.env.SMTP_HOST &&
  !!process.env.SMTP_PORT &&
  !!process.env.SMTP_USER &&
  !!process.env.SMTP_PASS &&
  !!process.env.OWNER_EMAIL;

// ✅ 관리자 인증코드(OTP)용 메일 체크 (OWNER_EMAIL 없어도 동작)
const adminMailEnabled =
  !!process.env.SMTP_HOST &&
  !!process.env.SMTP_PORT &&
  !!process.env.SMTP_USER &&
  !!process.env.SMTP_PASS &&
  !!process.env.ADMIN_EMAIL;

const transporter =
  mailEnabled || adminMailEnabled
    ? nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: String(process.env.SMTP_SECURE || "true") === "true",
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      })
    : null;

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

  const raw = req.signedCookies?.offer; // timestamp
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
// OTP 유틸
// =========================
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function makeCode6() {
  return String(Math.floor(100000 + Math.random() * 900000));
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
  const row = await db.get(
    `SELECT password_hash FROM offer_access_settings WHERE id=1`
  );
  const ok = row && bcrypt.compareSync(password || "", row.password_hash);

  if (!ok) {
    return res.render("offers_login", {
      siteName: "SNF SEMI",
      error: "Wrong password.",
    });
  }

  res.cookie("offer", String(Date.now()), {
    signed: true,
    httpOnly: true,
    sameSite: "lax",
    path: "/",
  });

  return res.redirect("/offers");
});

app.post("/offers/logout", (req, res) => {
  res.clearCookie("offer", { path: "/" });
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
  const post = await db.get(
    `SELECT * FROM posts WHERE id=? AND is_published=1`,
    [id]
  );
  if (!post) return res.status(404).send("Offer not found.");

  let offer = null;
  try {
    offer = post.offer_json ? JSON.parse(post.offer_json) : null;
  } catch (_) {
    offer = null;
  }

  const submitted = String(req.query.submitted || "");
  res.render("post", { siteName: "SNF SEMI", post, offer, submitted });
});

// =========================
// ✅ Buyer 제출 → 메일 발송
// =========================
app.post("/post/:id/buyer-submit", requireOfferAccess, async (req, res) => {
  await ensureDb();

  try {
    const id = Number(req.params.id);
    const buyerName = (req.body.buyerName || "").toString().trim();
    const buyerEmail = (req.body.buyerEmail || "").toString().trim();

    if (!buyerName || !buyerEmail) {
      return res.status(400).send("Buyer Name/Email is required.");
    }

    // 오퍼 존재 확인(제목 같이 보내려고)
    const post = await db.get(
      `SELECT id, title FROM posts WHERE id=? AND is_published=1`,
      [id]
    );
    if (!post) return res.status(404).send("Offer not found.");

    if (!mailEnabled || !transporter) {
      return res
        .status(500)
        .send(
          "Mail settings are missing. Please set SMTP_* and OWNER_EMAIL in .env"
        );
    }

    const subject = `[SNF SEMI] New Inquiry - ${post.title} (post:${id})`;
    const link = `${req.protocol}://${req.get("host")}/post/${id}`;

    const text = [
      "New buyer inquiry received.",
      "",
      `Buyer Name : ${buyerName}`,
      `Buyer Email: ${buyerEmail}`,
      "",
      `Offer Title: ${post.title}`,
      `Link      : ${link}`,
      "",
      `Submitted : ${new Date().toISOString()}`,
    ].join("\n");

    await transporter.sendMail({
      from: `"SNF SEMI" <${process.env.SMTP_USER}>`,
      to: process.env.OWNER_EMAIL, // ✅ buyer 문의는 여기로
      replyTo: buyerEmail, // ✅ 답장 누르면 구매자에게 바로
      subject,
      text,
    });

    return res.redirect(`/post/${id}?submitted=1`);
  } catch (err) {
    console.error("MAIL ERROR:", err);
    return res.status(500).send("Mail send failed.");
  }
});

// =========================
// 관리자 로그인
// =========================
app.get("/admin/login", async (req, res) => {
  await ensureDb();
  res.render("admin_login", { error: null });
});

// ✅ DB 기반 관리자 로그인 (admin_users id=1)
app.post("/admin/login", async (req, res) => {
  await ensureDb();

  const { username, password } = req.body;

  const admin = await db.get(`SELECT * FROM admin_users WHERE id=1`);
  if (!admin) {
    return res.render("admin_login", { error: "관리자 계정이 DB에 없습니다." });
  }

  if ((username || "") !== admin.username) {
    return res.render("admin_login", {
      error: "아이디 또는 비밀번호가 틀렸습니다.",
    });
  }

  const ok = bcrypt.compareSync(password || "", admin.password_hash);
  if (!ok) {
    return res.render("admin_login", {
      error: "아이디 또는 비밀번호가 틀렸습니다.",
    });
  }

  res.cookie("admin", "1", { signed: true, httpOnly: true, sameSite: "lax" });
  return res.redirect("/admin");
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("admin");
  res.redirect("/");
});

// =========================
// ✅ 관리자 계정 변경 (메일 OTP)
// =========================
app.get("/admin/account", requireAdmin, async (req, res) => {
  await ensureDb();

  const admin = await db.get(`SELECT username FROM admin_users WHERE id=1`);
  return res.render("admin_account", {
    siteName: "SNF SEMI",
    admin,
    sent: req.query.sent || "",
    ok: req.query.ok || "",
    err: req.query.err || "",
  });
});

app.post("/admin/account/send-code", requireAdmin, async (req, res) => {
  await ensureDb();

  if (!adminMailEnabled || !transporter) {
    return res.redirect("/admin/account?err=mail_not_ready");
  }

  const code = makeCode6();
  const otpHash = sha256(code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await db.run(`INSERT INTO admin_otp (otp_hash, expires_at) VALUES (?, ?)`, [
    otpHash,
    expiresAt,
  ]);

  await transporter.sendMail({
    from: `"SNF SEMI" <${process.env.SMTP_USER}>`,
    to: process.env.ADMIN_EMAIL, // ✅ 인증코드 받는 메일
    subject: "[SNF] 관리자 변경 인증코드",
    text: `인증코드: ${code}\n유효시간: 10분`,
  });

  return res.redirect("/admin/account?sent=1");
});

app.post("/admin/account/update", requireAdmin, async (req, res) => {
  await ensureDb();

  const newUsername = (req.body.newUsername || "").toString().trim();
  const newPassword = (req.body.newPassword || "").toString().trim();
  const otpCode = (req.body.otpCode || "").toString().trim();

  if (!otpCode) return res.redirect("/admin/account?err=need_code");

  const otp = await db.get(`SELECT * FROM admin_otp ORDER BY id DESC LIMIT 1`);
  if (!otp) return res.redirect("/admin/account?err=no_otp");
  if (otp.used_at) return res.redirect("/admin/account?err=otp_used");
  if (new Date() > new Date(otp.expires_at))
    return res.redirect("/admin/account?err=otp_expired");

  const ok = sha256(otpCode) === otp.otp_hash;
  if (!ok) return res.redirect("/admin/account?err=otp_wrong");

  await db.run(`UPDATE admin_otp SET used_at=datetime('now') WHERE id=?`, [
    otp.id,
  ]);

  if (!newUsername && !newPassword)
    return res.redirect("/admin/account?err=nothing");

  const updates = [];
  const params = [];

  if (newUsername) {
    updates.push("username=?");
    params.push(newUsername);
  }

  if (newPassword) {
    if (newPassword.length < 6)
      return res.redirect("/admin/account?err=pw_short");
    const hash = bcrypt.hashSync(newPassword, 10);
    updates.push("password_hash=?");
    params.push(hash);
  }

  updates.push("updated_at=datetime('now')");
  params.push(1);

  try {
    await db.run(`UPDATE admin_users SET ${updates.join(", ")} WHERE id=?`, params);
  } catch (e) {
    return res.redirect("/admin/account?err=duplicate");
  }

  return res.redirect("/admin/account?ok=1");
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

  // 2) 없으면 hero_subtitle/about_text 스키마로 저장
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
  res.render("admin_offers_password", {
    siteName: "SNF SEMI",
    error: null,
    success: null,
  });
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
// 오퍼 폼 파서 (unit = 단가 USD)
// =========================
function buildOfferFromBody(body) {
  const items = [];
  const arr = (v) => (Array.isArray(v) ? v : v != null ? [v] : []);

  const descArr = arr(body["item_desc[]"] ?? body.item_desc);
  const qtyArr = arr(body["item_qty[]"] ?? body.item_qty);

  const unitArr = arr(body["item_unit[]"] ?? body.item_unit);
  const priceArr = arr(body["item_price[]"] ?? body.item_price);

  const len = Math.max(
    descArr.length,
    qtyArr.length,
    unitArr.length,
    priceArr.length
  );

  for (let i = 0; i < len; i++) {
    const desc = (descArr[i] ?? "").toString().trim();
    const qty = (qtyArr[i] ?? "").toString().trim();

    const unit =
      ((unitArr[i] ?? "").toString().trim()) ||
      ((priceArr[i] ?? "").toString().trim());

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
  await db.run(
    `UPDATE posts SET is_published=?, updated_at=datetime('now') WHERE id=?`,
    [next, id]
  );
  res.redirect("/admin");
});

app.post("/admin/delete/:id", requireAdmin, async (req, res) => {
  await ensureDb();

  const id = Number(req.params.id);
  await db.run(`DELETE FROM posts WHERE id=?`, [id]);
  res.redirect("/admin");
});

module.exports = app;