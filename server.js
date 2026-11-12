
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

const app = express();
app.use(express.static(path.join(__dirname, "public")));
const {
  PORT = 3000,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_CALLBACK_URL,
  DISCORD_GUILD_ID,
  FOUNDER_ROLE_ID,
  SESSION_SECRET,
  DATABASE_URL
} = process.env;

const required = [
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_CALLBACK_URL,
  DISCORD_GUILD_ID,
  FOUNDER_ROLE_ID,
  SESSION_SECRET,
  DATABASE_URL
];

if (required.some(value => !value)) {
  console.error("Gerekli ortam değişkenleri eksik. Render Environment ayarlarını kontrol et.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.set("trust proxy", 1);
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: false }));

const uploadDir = path.join(__dirname, "public", "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.mimetype)) {
      return cb(new Error("Yalnızca PNG, JPG veya WEBP yükleyebilirsin."));
    }
    cb(null, true);
  }
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id BIGSERIAL PRIMARY KEY,
      username TEXT,
      content TEXT NOT NULL,
      status TEXT DEFAULT 'Beklemede',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      discord_id TEXT
    );

    CREATE TABLE IF NOT EXISTS bots (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      invite_url TEXT,
      logo TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_applications_discord_status
    ON applications(discord_id, status);
  `);

  const defaults = {
    site_title: "JESTER.GG",
    about_text: "Jester topluluğuna hoş geldin.",
    discord_invite: "https://discord.gg/c5QEquYc4E",
    bots_description: "Jester için geliştirilmiş botlar.",
    announcement: ""
  };

  for (const [key, value] of Object.entries(defaults)) {
    await pool.query(
      `INSERT INTO settings (key, value)
       VALUES ($1, $2)
       ON CONFLICT (key) DO NOTHING`,
      [key, value]
    );
  }

  console.log("Supabase PostgreSQL bağlantısı ve tablolar hazır.");
}

app.use(session({
  name: "jester.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use("/assets", express.static(path.join(__dirname, "public", "assets")));
app.use("/uploads", express.static(uploadDir));

async function getGuildMember(accessToken) {
  try {
    const response = await fetch(
      `https://discord.com/api/v10/users/@me/guilds/${DISCORD_GUILD_ID}/member`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const data = await response.json();

    console.log("Discord rol kontrolü:", {
      status: response.status,
      roles: data.roles,
      error: data.message
    });

    if (!response.ok) return null;
    return data;
  } catch (error) {
    console.error("Discord üye bilgisi alınamadı:", error);
    return null;
  }
}

function loginRequired(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Başvuru göndermek için önce Discord ile giriş yapmalısın."
    });
  }
  next();
}

async function founderOnly(req, res, next) {
  try {
    if (!req.session.user) return res.redirect("/auth/discord");

    const member = await getGuildMember(req.session.user.accessToken);

    if (!member || !member.roles?.includes(FOUNDER_ROLE_ID)) {
      return req.session.destroy(() => {
        res.status(403).send(
          "Bu panele yalnızca Kurucu rolüne sahip kişiler girebilir."
        );
      });
    }

    next();
  } catch (error) {
    console.error("Kurucu kontrol hatası:", error);
    res.status(500).send("Yetki kontrolü yapılamadı.");
  }
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Discord girişini başlat
app.get("/auth/discord", (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_CALLBACK_URL,
    response_type: "code",
    scope: "identify guilds.members.read",
    state
  });

  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});

// Discord giriş dönüşü
app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state || !req.session.oauthState || state !== req.session.oauthState) {
      return res.status(400).send("Giriş doğrulaması başarısız.");
    }

    delete req.session.oauthState;

    const tokenResponse = await fetch(
      "https://discord.com/api/v10/oauth2/token",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_CALLBACK_URL
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.access_token) {
      console.error("Discord token hatası:", tokens);
      return res.status(400).send("Discord giriş işlemi başarısız.");
    }

    const userResponse = await fetch(
      "https://discord.com/api/v10/users/@me",
      { headers: { Authorization: `Bearer ${tokens.access_token}` } }
    );

    const user = await userResponse.json();

    if (!userResponse.ok || !user.id) {
      return res.status(400).send("Discord kullanıcı bilgisi alınamadı.");
    }

    req.session.regenerate(error => {
      if (error) {
        console.error(error);
        return res.status(500).send("Oturum oluşturulamadı.");
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        accessToken: tokens.access_token
      };

      req.session.save(saveError => {
        if (saveError) {
          console.error(saveError);
          return res.status(500).send("Oturum kaydedilemedi.");
        }

        console.log("Discord oturumu başarıyla kaydedildi.");
        res.redirect("/");
      });
    });
  } catch (error) {
    console.error("Discord giriş hatası:", error);
    res.status(500).send("Bir sunucu hatası oluştu.");
  }
});

// Kullanıcı bilgisi
app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });

  res.json({
    loggedIn: true,
    username: req.session.user.username,
    id: req.session.user.id
  });
});

// Yetkili başvurusu
app.post("/api/applications", loginRequired, async (req, res) => {
  try {
    const content = String(req.body.content || "").trim();

    if (content.length < 30 || content.length > 3000) {
      return res.status(400).json({
        error: "Başvuru 30 ile 3000 karakter arasında olmalı."
      });
    }

    const existing = await pool.query(
      `SELECT id FROM applications
       WHERE discord_id = $1 AND status = 'Beklemede'`,
      [req.session.user.id]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        error: "Zaten bekleyen bir yetkili başvurun bulunuyor."
      });
    }

    await pool.query(
      `INSERT INTO applications (username, discord_id, content)
       VALUES ($1, $2, $3)`,
      [req.session.user.username, req.session.user.id, content]
    );

    res.json({
      success: true,
      message: "Yetkili başvurun başarıyla gönderildi."
    });
  } catch (error) {
    console.error("Başvuru kayıt hatası:", error);
    res.status(500).json({ error: "Başvuru kaydedilemedi." });
  }
});

// Admin paneli
app.get("/admin", founderOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/admin.html", founderOnly, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Başvuruları listele
app.get("/api/admin/applications", founderOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, discord_id, content, status, created_at
      FROM applications
      ORDER BY id DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Başvurular alınamadı:", error);
    res.status(500).json({ error: "Başvurular alınamadı." });
  }
});

// Başvuru durumunu değiştir
app.post("/api/admin/applications/:id/status", founderOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const status = req.body.status;
    const allowedStatuses = ["Beklemede", "Kabul Edildi", "Reddedildi"];

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Geçersiz başvuru numarası." });
    }

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ error: "Geçersiz başvuru durumu." });
    }

    const result = await pool.query(
      "UPDATE applications SET status = $1 WHERE id = $2 RETURNING id",
      [status, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Başvuru bulunamadı." });
    }

    res.json({ success: true, message: "Başvuru durumu güncellendi." });
  } catch (error) {
    console.error("Başvuru durumu güncellenemedi:", error);
    res.status(500).json({ error: "Başvuru durumu güncellenemedi." });
  }
});

// Herkese açık bot listesi
app.get("/api/bots", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, invite_url, logo
      FROM bots ORDER BY id DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Botlar alınamadı:", error);
    res.status(500).json({ error: "Botlar alınamadı." });
  }
});

// Admin bot listesi
app.get("/api/admin/bots", founderOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, invite_url, logo
      FROM bots ORDER BY id DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("Admin bot listesi alınamadı:", error);
    res.status(500).json({ error: "Botlar alınamadı." });
  }
});

// Bot ekle
app.post("/api/admin/bots", founderOnly, upload.single("logo"), async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();
    const inviteUrl = String(req.body.invite_url || "").trim();
    const logo = req.file ? `/uploads/${req.file.filename}` : "";

    if (!name || name.length > 80) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: "Bot adı 1-80 karakter arasında olmalı." });
    }

    if (description.length > 500) {
      if (req.file) fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: "Açıklama en fazla 500 karakter olabilir." });
    }

    if (inviteUrl) {
      try {
        const url = new URL(inviteUrl);
        if (!["http:", "https:"].includes(url.protocol)) throw new Error();
      } catch {
        if (req.file) fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: "Geçerli bir HTTP veya HTTPS bağlantısı gir." });
      }
    }

    const result = await pool.query(
      `INSERT INTO bots (name, description, invite_url, logo)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [name, description, inviteUrl, logo]
    );

    res.json({
      success: true,
      id: result.rows[0].id,
      message: "Bot başarıyla eklendi."
    });
  } catch (error) {
    if (req.file) fs.unlink(req.file.path, () => {});
    console.error("Bot ekleme hatası:", error);
    res.status(500).json({ error: "Bot eklenemedi." });
  }
});

// Bot düzenle
app.put("/api/admin/bots/:id", founderOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();
    const inviteUrl = String(req.body.invite_url || "").trim();

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Geçersiz bot numarası." });
    }

    if (!name || name.length > 80 || description.length > 500) {
      return res.status(400).json({ error: "Bot bilgilerini kontrol et." });
    }

    if (inviteUrl) {
      try {
        const url = new URL(inviteUrl);
        if (!["http:", "https:"].includes(url.protocol)) throw new Error();
      } catch {
        return res.status(400).json({ error: "Geçerli bir HTTP veya HTTPS bağlantısı gir." });
      }
    }

    const result = await pool.query(
      `UPDATE bots
       SET name = $1, description = $2, invite_url = $3
       WHERE id = $4 RETURNING id`,
      [name, description, inviteUrl, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Bot bulunamadı." });
    }

    res.json({ success: true, message: "Bot bilgileri güncellendi." });
  } catch (error) {
    console.error("Bot güncelleme hatası:", error);
    res.status(500).json({ error: "Bot güncellenemedi." });
  }
});

// Bot sil
app.delete("/api/admin/bots/:id", founderOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({ error: "Geçersiz bot numarası." });
    }

    const botResult = await pool.query(
      "SELECT logo FROM bots WHERE id = $1",
      [id]
    );

    if (!botResult.rowCount) {
      return res.status(404).json({ error: "Bot bulunamadı." });
    }

    await pool.query("DELETE FROM bots WHERE id = $1", [id]);

    const logo = botResult.rows[0].logo;
    if (logo && logo.startsWith("/uploads/")) {
      fs.unlink(path.join(uploadDir, path.basename(logo)), () => {});
    }

    res.json({ success: true, message: "Bot silindi." });
  } catch (error) {
    console.error("Bot silme hatası:", error);
    res.status(500).json({ error: "Bot silinemedi." });
  }
});

// Site ayarlarını oku
app.get("/api/settings", async (req, res) => {
  try {
    const result = await pool.query("SELECT key, value FROM settings");
    res.json(Object.fromEntries(result.rows.map(row => [row.key, row.value])));
  } catch (error) {
    console.error("Site ayarları alınamadı:", error);
    res.status(500).json({ error: "Site ayarları alınamadı." });
  }
});

// Site ayarlarını kaydet
app.put("/api/admin/settings", founderOnly, async (req, res) => {
  const allowed = [
    "site_title",
    "about_text",
    "discord_invite",
    "bots_description",
    "announcement"
  ];

  let client;

  try {
    client = await pool.connect();
    await client.query("BEGIN");

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        await client.query(
          `INSERT INTO settings (key, value)
           VALUES ($1, $2)
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
          [key, String(req.body[key]).slice(0, 2000)]
        );
      }
    }

    await client.query("COMMIT");
    res.json({ success: true, message: "Site ayarları kaydedildi." });
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    console.error("Site ayarları kaydedilemedi:", error);
    res.status(500).json({ error: "Site ayarları kaydedilemedi." });
  } finally {
    if (client) client.release();
  }
});

// Çıkış
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("jester.sid");
    res.redirect("/");
  });
});

// Hata yakalama
app.use((error, req, res, next) => {
  console.error("İstek hatası:", error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error: "Logo yüklenemedi. Dosya boyutu en fazla 2 MB olabilir."
    });
  }

  if (error.message === "Yalnızca PNG, JPG veya WEBP yükleyebilirsin.") {
    return res.status(400).json({ error: error.message });
  }

  res.status(500).json({ error: "Sunucuda bir hata oluştu." });
});

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`JESTER.GG çalışıyor: http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Sunucu başlatılamadı. DATABASE_URL ve Supabase bağlantısını kontrol et:", error);
    process.exit(1);
  }
}

startServer();
