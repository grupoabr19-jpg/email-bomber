import "dotenv/config";
import cors from "cors";
import crypto from "crypto";
import dns from "node:dns/promises";
import express from "express";
import helmet from "helmet";
import net from "node:net";
import nodemailer from "nodemailer";
import pg from "pg";

const app = express();
const port = Number(process.env.PORT || 3000);
const startedAt = new Date().toISOString();
function configuredAdminAccounts() {
  try {
    const parsed = JSON.parse(process.env.ADMIN_ACCOUNTS_JSON || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.map((account) => {
      const email = String(account?.email || "").trim().toLowerCase();
      return { email, name: String(account?.name || email.split("@")[0] || "Administrador").trim() };
    }).filter((account) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(account.email));
  } catch {
    console.error("ADMIN_ACCOUNTS_JSON está inválida");
    return [];
  }
}
const adminAccounts = configuredAdminAccounts();
const authorizedAdminEmails = new Set(adminAccounts.map((account) => account.email));
const adminEmail = adminAccounts[0]?.email || "";
const adminName = adminAccounts[0]?.name || "Administrador ABR";
const frontendUrl = process.env.FRONTEND_URL || "https://abr-ondas-email.grupoabr.chatgpt.site";
const sessionCookie = "abr_session";
const freeEmailDomains = new Set(["gmail.com","hotmail.com","outlook.com","yahoo.com","icloud.com","live.com","bol.com.br","uol.com.br","terra.com.br"]);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: frontendUrl, credentials: true }));
app.use(express.json({ limit: "5mb" }));

const pool = process.env.DATABASE_URL ? new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 8,
}) : null;

function apiKeyIsValid(value) {
  const expected = process.env.API_ACCESS_KEY;
  if (!expected || !value) return false;
  const left = Buffer.from(value); const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function requireServiceKey(req, res, next) {
  if (apiKeyIsValid(req.get("x-abr-api-key"))) return next();
  return res.status(401).json({ error: "Não autorizado" });
}
function number(value) { return Number(value || 0); }
function cookieValue(req, name) {
  const raw = String(req.headers.cookie || "");
  return raw.split(";").map((part) => part.trim().split("=")).find(([key]) => key === name)?.[1] || "";
}
function tokenHash(value) { return crypto.createHash("sha256").update(String(value)).digest("hex"); }
function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString("base64url"); }
function passwordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 210000;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex");
  return `pbkdf2$${iterations}$${salt}$${hash}`;
}
function passwordMatches(password, stored) {
  const [kind, iterations, salt, expected] = String(stored || "").split("$");
  if (kind !== "pbkdf2" || !iterations || !salt || !expected) return false;
  const actual = crypto.pbkdf2Sync(password, salt, Number(iterations), 32, "sha256").toString("hex");
  const left = Buffer.from(actual); const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function setSessionCookie(res, token, maxAge = 60 * 60 * 24 * 7) {
  res.setHeader("set-cookie", `${sessionCookie}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${process.env.NODE_ENV === "production" ? "; Secure" : ""}`);
}
function encryptionKey() { return crypto.createHash("sha256").update(process.env.SESSION_SECRET || "development-only").digest(); }
function encryptSecret(value) {
  if (!value) return null;
  const iv = crypto.randomBytes(12); const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${encrypted.toString("base64url")}`;
}
function decryptSecret(value) {
  if (!value) return "";
  const [iv, tag, encrypted] = String(value).split(".");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, "base64url")), decipher.final()]).toString("utf8");
}
function cleanHtml(value) { return String(value || "").replace(/<script[\s\S]*?<\/script>/gi, ""); }
function escapeHtmlText(value) {
  return String(value || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}
function unsubscribeToken(contactId, campaignId) {
  const payload = `${contactId}.${campaignId}`;
  const signature = crypto.createHmac("sha256", process.env.SESSION_SECRET || "development-only").update(payload).digest("base64url");
  return `${payload}.${signature}`;
}
function unsubscribeTokenIsValid(token) {
  const [contactId, campaignId, signature] = String(token || "").split(".");
  if (!contactId || !campaignId || !signature) return null;
  const expected = unsubscribeToken(contactId, campaignId).split(".")[2];
  const left = Buffer.from(signature); const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right) ? { contactId, campaignId } : null;
}
function personalizeCampaignHtml(html, contact, campaignId) {
  const unsubscribeUrl = `${frontendUrl.replace(/\/$/,"")}/api/abr/unsubscribe?token=${encodeURIComponent(unsubscribeToken(contact.id, campaignId))}`;
  return cleanHtml(html)
    .replaceAll("{{nome}}", escapeHtmlText(contact.name || contact.company || "Cliente"))
    .replaceAll("{{empresa}}", escapeHtmlText(contact.company || "sua empresa"))
    .replaceAll("{{email}}", escapeHtmlText(contact.email))
    .replaceAll("{{unsubscribe_url}}", unsubscribeUrl);
}
function normalizeContact(item) {
  const email = String(item.email || item.Email || item["E-mail"] || "").trim().toLowerCase();
  return {
    email,
    name: String(item.name || item.nome || item.Nome || "").trim(),
    company: String(item.company || item.empresa || item.Empresa || "").trim(),
    segment: String(item.segment || item.segmento || item.Segmento || "").trim(),
    city: String(item.city || item.cidade || item.Cidade || "").trim(),
    region: String(item.region || item.regiao || item.Região || "").trim(),
    website: String(item.website || item.site || "").trim(),
    sourceUrl: String(item.source_url || item.sourceUrl || item.fonte || "").trim(),
    qualificationScore: Math.max(0, Math.min(100, Number(item.qualification_score || item.qualificationScore || 0))),
    qualificationLabel: String(item.qualification_label || item.qualificationLabel || "a revisar").trim(),
    qualificationReason: String(item.qualification_reason || item.qualificationReason || "").trim(),
    suggestedAngle: String(item.suggested_angle || item.suggestedAngle || "").trim(),
  };
}
function corporateEmailIsValid(email) {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return false;
  return !freeEmailDomains.has(email.split("@")[1]);
}
function emailIsValid(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || "")); }
function wait(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function retryDelayMs(error) {
  if (Number(error?.status) !== 429) return 0;
  const explicit = Number(error?.retryAfterMs || 0);
  if (explicit > 0) return Math.min(30000, Math.max(1000, explicit));
  const match = String(error?.message || "").match(/(?:try again in|tente novamente em)\s*([\d.]+)s/i);
  return Math.min(30000, Math.max(1000, Math.ceil(Number(match?.[1] || 20) * 1000)));
}

let schemaPromise;
let prospectionRecoveryDone = false;
async function initializeDatabase() {
  if (!pool) throw new Error("DATABASE_URL não configurada");
  if (!schemaPromise) schemaPromise = (async () => {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, role TEXT NOT NULL DEFAULT 'user',
      password_hash TEXT, status TEXT NOT NULL DEFAULT 'pending_password_setup', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contacts (
      id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, company TEXT, segment TEXT,
      city TEXT, region TEXT, website TEXT, source_url TEXT, qualification_score INTEGER NOT NULL DEFAULT 0,
      qualification_label TEXT NOT NULL DEFAULT 'a revisar', qualification_reason TEXT, suggested_angle TEXT,
      status TEXT NOT NULL DEFAULT 'valid', subscribed BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    for (const statement of [
      `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS city TEXT`, `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS region TEXT`,
      `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS website TEXT`, `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS source_url TEXT`,
      `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS qualification_score INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS qualification_label TEXT NOT NULL DEFAULT 'a revisar'`,
      `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS qualification_reason TEXT`, `ALTER TABLE contacts ADD COLUMN IF NOT EXISTS suggested_angle TEXT`
    ]) await pool.query(statement);
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_lists (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, niche TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '',
      qualification TEXT NOT NULL DEFAULT 'qualified', source TEXT NOT NULL DEFAULT 'manual', criteria TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'ready', created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`ALTER TABLE contact_lists ADD COLUMN IF NOT EXISTS criteria TEXT NOT NULL DEFAULT ''`);
    await pool.query(`ALTER TABLE contact_lists ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ready'`);
    await pool.query(`ALTER TABLE contact_lists ADD COLUMN IF NOT EXISTS created_by BIGINT REFERENCES users(id) ON DELETE SET NULL`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_list_members (
      list_id BIGINT REFERENCES contact_lists(id) ON DELETE CASCADE,
      contact_id BIGINT REFERENCES contacts(id) ON DELETE CASCADE, PRIMARY KEY(list_id, contact_id)
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS prospections (
      id BIGSERIAL PRIMARY KEY, list_id BIGINT REFERENCES contact_lists(id) ON DELETE SET NULL,
      niche TEXT NOT NULL, region TEXT NOT NULL, criteria TEXT NOT NULL DEFAULT '', requested_list_name TEXT NOT NULL DEFAULT '',
      requested_count INTEGER NOT NULL, found_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'queued', provider TEXT NOT NULL DEFAULT 'groq',
      model TEXT, error TEXT, candidate_count INTEGER NOT NULL DEFAULT 0, rejected_count INTEGER NOT NULL DEFAULT 0,
      created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ
    )`);
    await pool.query(`ALTER TABLE prospections ADD COLUMN IF NOT EXISTS requested_list_name TEXT NOT NULL DEFAULT ''`);
    await pool.query(`ALTER TABLE prospections ADD COLUMN IF NOT EXISTS candidate_count INTEGER NOT NULL DEFAULT 0`);
    await pool.query(`ALTER TABLE prospections ADD COLUMN IF NOT EXISTS rejected_count INTEGER NOT NULL DEFAULT 0`);
    await pool.query(`CREATE TABLE IF NOT EXISTS campaigns (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '', html_content TEXT NOT NULL DEFAULT '',
      brief TEXT NOT NULL DEFAULT '', source_references JSONB NOT NULL DEFAULT '[]'::jsonb,
      sender_name TEXT, sender_email TEXT, audience_label TEXT NOT NULL DEFAULT '',
      contact_list_id BIGINT REFERENCES contact_lists(id) ON DELETE SET NULL,
      owner_id BIGINT REFERENCES users(id) ON DELETE SET NULL, status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    for (const statement of [
      `ALTER TABLE campaigns ALTER COLUMN subject SET DEFAULT ''`,
      `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS brief TEXT NOT NULL DEFAULT ''`,
      `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS source_references JSONB NOT NULL DEFAULT '[]'::jsonb`,
      `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS contact_list_id BIGINT REFERENCES contact_lists(id) ON DELETE SET NULL`,
      `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS owner_id BIGINT REFERENCES users(id) ON DELETE SET NULL`
    ]) await pool.query(statement);
    await pool.query(`CREATE TABLE IF NOT EXISTS campaign_waves (
      id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      wave_order INTEGER NOT NULL, scheduled_at TIMESTAMPTZ, recipient_count INTEGER NOT NULL DEFAULT 0,
      automation_mode TEXT NOT NULL DEFAULT 'dated', delay_days INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'draft', UNIQUE(campaign_id, wave_order)
    )`);
    await pool.query(`ALTER TABLE campaign_waves ADD COLUMN IF NOT EXISTS automation_mode TEXT NOT NULL DEFAULT 'dated'`);
    await pool.query(`ALTER TABLE campaign_waves ADD COLUMN IF NOT EXISTS delay_days INTEGER NOT NULL DEFAULT 0`);
    await pool.query(`CREATE TABLE IF NOT EXISTS campaign_emails (
      id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      wave_id BIGINT NOT NULL REFERENCES campaign_waves(id) ON DELETE CASCADE, subject TEXT NOT NULL,
      html_content TEXT NOT NULL DEFAULT '', preview_text TEXT NOT NULL DEFAULT '', editor_mode TEXT NOT NULL DEFAULT 'visual',
      layout_json JSONB NOT NULL DEFAULT '[]'::jsonb, status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(campaign_id, wave_id)
    )`);
    await pool.query(`ALTER TABLE campaign_emails ADD COLUMN IF NOT EXISTS editor_mode TEXT NOT NULL DEFAULT 'visual'`);
    await pool.query(`ALTER TABLE campaign_emails ADD COLUMN IF NOT EXISTS layout_json JSONB NOT NULL DEFAULT '[]'::jsonb`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_events (
      id BIGSERIAL PRIMARY KEY, campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL,
      contact_id BIGINT REFERENCES contacts(id) ON DELETE SET NULL, event_type TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS campaign_deliveries (
      id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      wave_id BIGINT NOT NULL REFERENCES campaign_waves(id) ON DELETE CASCADE,
      contact_id BIGINT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending', provider_message_id TEXT, error TEXT,
      sent_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(wave_id, contact_id)
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS email_templates (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL, template_type TEXT NOT NULL, html_content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS user_email_settings (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, provider TEXT NOT NULL DEFAULT 'none',
      email TEXT, display_name TEXT, reply_to TEXT, signature_html TEXT NOT NULL DEFAULT '', signature_text TEXT NOT NULL DEFAULT '',
      smtp_host TEXT, smtp_port INTEGER, smtp_secure BOOLEAN NOT NULL DEFAULT TRUE, smtp_user TEXT, smtp_password_enc TEXT,
      microsoft_access_token_enc TEXT, microsoft_refresh_token_enc TEXT, microsoft_expires_at TIMESTAMPTZ,
      connected_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS oauth_states (
      state_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
    const adminUsers = [];
    for (const account of adminAccounts) {
      const user = (await pool.query(`INSERT INTO users(email,name,role,status) VALUES($1,$2,'admin','pending_password_setup')
        ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,role='admin',
          status=CASE WHEN users.password_hash IS NULL THEN 'pending_password_setup' ELSE 'active' END
        RETURNING id`, [account.email, account.name])).rows[0];
      adminUsers.push(user);
    }
    const user = adminUsers[0];
    const defaults = [
      ["Header ABR", "header", `<header style="padding:24px 32px;background:#253575;text-align:center"><strong style="color:#fff;font:700 20px Arial">GRUPO ABR</strong></header>`],
      ["Oferta comercial", "body", `<section style="padding:34px 32px;background:#fff;color:#253575;font-family:Arial"><h1 style="margin:0 0 14px">Uma condição especial para você</h1><p style="line-height:1.6">Apresente aqui a oportunidade e o valor para o cliente.</p></section>`],
      ["Footer institucional", "footer", `<footer style="padding:22px 32px;background:#eef1f7;color:#5d6780;font:12px/1.5 Arial;text-align:center">Grupo ABR · Seu ParceirAço<br><a href="{{unsubscribe_url}}">Descadastrar</a></footer>`]
    ];
    if (user) for (const [name, type, html] of defaults) await pool.query(`INSERT INTO email_templates(user_id,name,template_type,html_content)
      SELECT $1,$2,$3,$4 WHERE NOT EXISTS(SELECT 1 FROM email_templates WHERE user_id=$1 AND name=$2)`, [user.id, name, type, html]);
  })().catch((error) => { schemaPromise = undefined; throw error; });
  await schemaPromise;
  if (!prospectionRecoveryDone) {
    prospectionRecoveryDone = true;
    try {
      await pool.query(`UPDATE prospections SET status='queued',error=NULL,completed_at=NULL WHERE status='researching' AND completed_at IS NULL`);
      setImmediate(scheduleProspectionDrain);
    } catch (error) {
      prospectionRecoveryDone = false;
      throw error;
    }
  }
  return schemaPromise;
}
async function requireDatabase(_req, res, next) {
  try { await initializeDatabase(); next(); }
  catch (error) { res.status(503).json({ error: "Banco de dados indisponível", detail: error.message }); }
}
async function requireUser(req, res, next) {
  try {
    const token = decodeURIComponent(cookieValue(req, sessionCookie));
    if (!token) return res.status(401).json({ error: "Faça login para continuar", code: "AUTH_REQUIRED" });
    const result = await pool.query(`SELECT u.id,u.email,u.name,u.role,u.status FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.status='active'`, [tokenHash(token)]);
    if (!result.rowCount) return res.status(401).json({ error: "Sua sessão expirou", code: "AUTH_REQUIRED" });
    req.user = result.rows[0]; next();
  } catch (error) { next(error); }
}
async function createSession(userId, res) {
  const token = randomToken();
  await pool.query(`DELETE FROM sessions WHERE expires_at<NOW()`);
  await pool.query(`INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')`, [tokenHash(token), userId]);
  setSessionCookie(res, token); return token;
}

app.get("/", (_req, res) => res.json({ service: "Email Bomber API", status: "online", version: "0.5.0" }));
app.get("/health", async (_req, res) => {
  try { await initializeDatabase(); res.json({ status: "ok", database: "connected", startedAt }); }
  catch { res.status(503).json({ status: "degraded", database: pool ? "unavailable" : "not_configured", startedAt }); }
});
app.use("/api", requireServiceKey, requireDatabase);

app.get("/api/unsubscribe", async (req, res, next) => {
  try {
    const decoded = unsubscribeTokenIsValid(req.query.token);
    if (!decoded) return res.status(400).send("Link de descadastro inválido ou expirado.");
    await pool.query(`UPDATE contacts SET subscribed=FALSE,updated_at=NOW() WHERE id=$1`, [decoded.contactId]);
    res.type("html").send(`<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Descadastro confirmado</title><body style="margin:0;background:#f4f6fb;font-family:Arial,sans-serif;color:#253575"><main style="max-width:560px;margin:80px auto;padding:38px;background:#fff;border-radius:16px;text-align:center"><h1 style="margin-top:0">Descadastro confirmado</h1><p>Este endereço não receberá novos e-mails comerciais desta base.</p><p style="color:#7b8498">Grupo ABR · Seu ParceirAço</p></main></body></html>`);
  } catch (error) { next(error); }
});

app.get("/api/auth/status", async (req, res, next) => {
  try {
    const token = decodeURIComponent(cookieValue(req, sessionCookie));
    if (!token) return res.json({ authenticated:false, allowedEmail:adminEmail, needsSetup:false });
    const result = await pool.query(`SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>NOW() AND u.status='active'`, [tokenHash(token)]);
    res.json({ authenticated:Boolean(result.rowCount), user:result.rows[0] || null, allowedEmail:adminEmail, needsSetup:false });
  } catch (error) { next(error); }
});
app.post("/api/auth/setup", async (req, res, next) => {
  const email = String(req.body?.email || "").trim().toLowerCase(); const password = String(req.body?.password || "");
  if (!authorizedAdminEmails.has(email)) return res.status(403).json({ error: "Usuário não autorizado" });
  if (password.length < 8) return res.status(400).json({ error: "A senha deve ter pelo menos 8 caracteres" });
  try {
    const result = await pool.query(`UPDATE users SET password_hash=$1,status='active' WHERE email=$2 AND status='pending_password_setup' RETURNING id,email,name,role`, [passwordHash(password), email]);
    if (!result.rowCount) return res.status(409).json({ error: "A senha inicial já foi criada. Use Entrar." });
    await createSession(result.rows[0].id, res); res.json({ user:result.rows[0] });
  } catch (error) { next(error); }
});
app.post("/api/auth/login", async (req, res, next) => {
  const email = String(req.body?.email || "").trim().toLowerCase(); const password = String(req.body?.password || "");
  try {
    const result = await pool.query(`SELECT id,email,name,role,password_hash,status FROM users WHERE email=$1`, [email]); const user=result.rows[0];
    if (user?.status === "pending_password_setup") return res.status(409).json({ error: "Crie a senha inicial desta conta", code: "PASSWORD_SETUP_REQUIRED" });
    if (!user || user.status !== "active" || !passwordMatches(password, user.password_hash)) return res.status(401).json({ error: "E-mail ou senha incorretos" });
    await createSession(user.id, res); delete user.password_hash; delete user.status; res.json({ user });
  } catch (error) { next(error); }
});
app.post("/api/auth/logout", requireUser, async (req, res, next) => {
  try { const token=decodeURIComponent(cookieValue(req,sessionCookie)); await pool.query(`DELETE FROM sessions WHERE token_hash=$1`,[tokenHash(token)]); setSessionCookie(res,"",0); res.json({ok:true}); } catch(error){next(error);}
});

app.get("/api/config/status", requireUser, async (req, res, next) => {
  try {
    const account=(await pool.query(`SELECT provider,email,connected_at FROM user_email_settings WHERE user_id=$1`,[req.user.id])).rows[0];
    res.json({ database:true, groq:Boolean(process.env.GROQ_API_KEY), groqModel:process.env.GROQ_PROSPECTION_MODEL||"openai/gpt-oss-120b", gemini:Boolean(process.env.GEMINI_API_KEY), geminiModel:process.env.GEMINI_PROSPECTION_MODEL||"gemini-3.6-flash", microsoft:Boolean(process.env.MICROSOFT_TENANT_ID&&process.env.MICROSOFT_CLIENT_ID&&process.env.MICROSOFT_CLIENT_SECRET), account:account||null });
  } catch(error){next(error);}
});
app.get("/api/dashboard", requireUser, async (_req, res, next) => {
  try {
    const [contacts,campaigns,events,recent,lists] = await Promise.all([
      pool.query(`SELECT COUNT(*) FILTER(WHERE status='valid' AND subscribed) valid,COUNT(*) FILTER(WHERE status<>'valid') invalid,COUNT(*) FILTER(WHERE NOT subscribed) unsubscribed,COUNT(*) total FROM contacts`),
      pool.query(`SELECT COUNT(*) FILTER(WHERE status='scheduled') scheduled,COUNT(*) FILTER(WHERE status='sending') sending,COUNT(*) FILTER(WHERE status='completed') completed FROM campaigns`),
      pool.query(`SELECT COUNT(*) FILTER(WHERE event_type='sent') sent,COUNT(*) FILTER(WHERE event_type='delivered') delivered,COUNT(*) FILTER(WHERE event_type='opened') opened,COUNT(*) FILTER(WHERE event_type='clicked') clicked FROM email_events`),
      pool.query(`SELECT c.id,c.name,c.subject,c.status,c.audience_label,c.created_at,COALESCE(SUM(w.recipient_count),0)::int recipients,COUNT(w.id)::int waves FROM campaigns c LEFT JOIN campaign_waves w ON w.campaign_id=c.id GROUP BY c.id ORDER BY c.created_at DESC LIMIT 6`),
      pool.query(`SELECT COUNT(*) total FROM contact_lists`)
    ]);
    const e=events.rows[0]; const sent=number(e.sent), delivered=number(e.delivered), opened=number(e.opened), clicked=number(e.clicked);
    res.json({metrics:{sent,deliveryRate:sent?delivered/sent:0,openRate:delivered?opened/delivered:0,clickRate:opened?clicked/opened:0},health:Object.fromEntries(Object.entries(contacts.rows[0]).map(([k,v])=>[k,number(v)])),campaignCounts:Object.fromEntries(Object.entries(campaigns.rows[0]).map(([k,v])=>[k,number(v)])),listCount:number(lists.rows[0].total),recentCampaigns:recent.rows});
  } catch(error){next(error);}
});

app.get("/api/contacts", requireUser, async (req,res,next)=>{
  try { const term=String(req.query.search||"").trim(); const result=await pool.query(`SELECT id,name,email,company,segment,city,region,website,source_url,qualification_score,qualification_label,qualification_reason,suggested_angle,status,subscribed,created_at FROM contacts WHERE($1='' OR name ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' OR company ILIKE '%'||$1||'%') ORDER BY created_at DESC LIMIT 500`,[term]); res.json({contacts:result.rows}); } catch(error){next(error);}
});
app.post("/api/contacts/import", requireUser, async (req,res,next)=>{
  const items=Array.isArray(req.body?.contacts)?req.body.contacts.map(normalizeContact).filter((item)=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item.email)):[];
  if(!items.length) return res.status(400).json({error:"Nenhum contato válido encontrado"});
  try { let imported=0; for(const item of items.slice(0,10000)){const result=await pool.query(`INSERT INTO contacts(email,name,company,segment,city,region,website,source_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,company=EXCLUDED.company,segment=EXCLUDED.segment,city=EXCLUDED.city,region=EXCLUDED.region,website=EXCLUDED.website,source_url=EXCLUDED.source_url,updated_at=NOW()`,[item.email,item.name,item.company,item.segment,item.city,item.region,item.website,item.sourceUrl]); if(result.rowCount) imported++;} res.status(201).json({imported,received:items.length}); }catch(error){next(error);}
});
app.post("/api/contacts/manual", requireUser, async(req,res,next)=>{
  const item=normalizeContact(req.body?.contact||req.body||{});
  const listId=Number(req.body?.listId)||null;
  const listName=String(req.body?.listName||"").trim();
  const listNiche=String(req.body?.listNiche||item.segment||"").trim();
  const listRegion=String(req.body?.listRegion||item.region||item.city||"").trim();
  if(!emailIsValid(item.email))return res.status(400).json({error:"Informe um e-mail válido"});
  if(!item.company&&!item.name)return res.status(400).json({error:"Informe a empresa ou o nome do contato"});
  if(!listId&&!listName)return res.status(400).json({error:"Escolha uma lista ou informe o nome da nova lista"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    let list;
    if(listId){
      list=(await client.query(`SELECT * FROM contact_lists WHERE id=$1 AND status='ready'`,[listId])).rows[0];
      if(!list){const error=new Error("A lista escolhida não foi encontrada");error.status=404;throw error;}
    }else{
      list=(await client.query(`INSERT INTO contact_lists(name,niche,region,qualification,source,criteria,status,created_by) VALUES($1,$2,$3,'manual','manual','Contato incluído manualmente','ready',$4) RETURNING *`,[listName,listNiche,listRegion,req.user.id])).rows[0];
    }
    const contact=(await client.query(`INSERT INTO contacts(email,name,company,segment,city,region,website,source_url,qualification_score,qualification_label,qualification_reason,suggested_angle,status,subscribed)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'valid',TRUE)
      ON CONFLICT(email) DO UPDATE SET
        name=COALESCE(NULLIF(EXCLUDED.name,''),contacts.name),company=COALESCE(NULLIF(EXCLUDED.company,''),contacts.company),
        segment=COALESCE(NULLIF(EXCLUDED.segment,''),contacts.segment),city=COALESCE(NULLIF(EXCLUDED.city,''),contacts.city),
        region=COALESCE(NULLIF(EXCLUDED.region,''),contacts.region),website=COALESCE(NULLIF(EXCLUDED.website,''),contacts.website),
        source_url=COALESCE(NULLIF(EXCLUDED.source_url,''),contacts.source_url),qualification_score=EXCLUDED.qualification_score,
        qualification_label=EXCLUDED.qualification_label,qualification_reason=COALESCE(NULLIF(EXCLUDED.qualification_reason,''),contacts.qualification_reason),
        suggested_angle=COALESCE(NULLIF(EXCLUDED.suggested_angle,''),contacts.suggested_angle),status='valid',updated_at=NOW()
      RETURNING *`,[item.email,item.name,item.company,item.segment,item.city,item.region,item.website,item.sourceUrl,item.qualificationScore||50,item.qualificationLabel||"manual",item.qualificationReason,item.suggestedAngle])).rows[0];
    await client.query(`INSERT INTO contact_list_members(list_id,contact_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[list.id,contact.id]);
    await client.query("COMMIT");
    res.status(201).json({contact,list});
  }catch(error){
    await client.query("ROLLBACK");
    if(error.status)return res.status(error.status).json({error:error.message});
    next(error);
  }finally{client.release();}
});

app.get("/api/contact-lists", requireUser, async (_req,res,next)=>{
  try { const result=await pool.query(`SELECT l.*,COUNT(m.contact_id)::int contacts,COUNT(m.contact_id) FILTER(WHERE c.status='valid' AND c.subscribed)::int valid_contacts FROM contact_lists l LEFT JOIN contact_list_members m ON m.list_id=l.id LEFT JOIN contacts c ON c.id=m.contact_id GROUP BY l.id ORDER BY l.created_at DESC`); res.json({lists:result.rows}); }catch(error){next(error);}
});
app.get("/api/contact-lists/:id", requireUser, async(req,res,next)=>{
  try { const list=(await pool.query(`SELECT l.*,COUNT(m.contact_id)::int contacts FROM contact_lists l LEFT JOIN contact_list_members m ON m.list_id=l.id WHERE l.id=$1 GROUP BY l.id`,[req.params.id])).rows[0]; if(!list)return res.status(404).json({error:"Lista não encontrada"}); const contacts=(await pool.query(`SELECT c.* FROM contacts c JOIN contact_list_members m ON m.contact_id=c.id WHERE m.list_id=$1 ORDER BY c.qualification_score DESC,c.company`,[req.params.id])).rows; res.json({list,contacts}); }catch(error){next(error);}
});
app.post("/api/contact-lists", requireUser, async(req,res,next)=>{
  const {name,niche="",region="",qualification="qualified",source="manual",criteria="",contactIds=[]}=req.body||{}; if(!name?.trim())return res.status(400).json({error:"O nome da lista é obrigatório"});
  try { const client=await pool.connect(); try{await client.query("BEGIN"); const list=(await client.query(`INSERT INTO contact_lists(name,niche,region,qualification,source,criteria,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[name.trim(),niche,region,qualification,source,criteria,req.user.id])).rows[0]; for(const id of Array.isArray(contactIds)?contactIds:[])await client.query(`INSERT INTO contact_list_members(list_id,contact_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[list.id,id]); await client.query("COMMIT");res.status(201).json({list});}catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();} }catch(error){next(error);}
});
app.delete("/api/contact-lists/:id", requireUser, async(req,res,next)=>{try{const used=await pool.query(`SELECT 1 FROM campaigns WHERE contact_list_id=$1 LIMIT 1`,[req.params.id]);if(used.rowCount)return res.status(409).json({error:"Esta lista está vinculada a uma campanha"});await pool.query(`DELETE FROM contact_lists WHERE id=$1`,[req.params.id]);res.json({ok:true});}catch(error){next(error);}});

function extractResearchJson(text,provider="A IA"){
  const cleaned=String(text||"").replace(/```(?:json)?/gi,"").replace(/```/g,"").trim();
  const objectStart=cleaned.indexOf("{"); const objectEnd=cleaned.lastIndexOf("}");
  const arrayStart=cleaned.indexOf("["); const arrayEnd=cleaned.lastIndexOf("]");
  for(const candidate of [objectStart>=0&&objectEnd>objectStart?cleaned.slice(objectStart,objectEnd+1):"",arrayStart>=0&&arrayEnd>arrayStart?cleaned.slice(arrayStart,arrayEnd+1):""]){if(!candidate)continue;try{return JSON.parse(candidate);}catch{}}
  throw new Error(`${provider} respondeu, mas não retornou uma lista estruturada válida`);
}
function privateNetworkAddress(address){
  if(net.isIPv4(address)){
    const [a,b]=address.split(".").map(Number);
    return a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===198&&(b===18||b===19));
  }
  if(net.isIPv6(address)){
    const normalized=address.toLowerCase();
    if(normalized==="::"||normalized==="::1"||normalized.startsWith("fc")||normalized.startsWith("fd")||normalized.startsWith("fe8")||normalized.startsWith("fe9")||normalized.startsWith("fea")||normalized.startsWith("feb"))return true;
    if(normalized.startsWith("::ffff:")){const mapped=normalized.slice(7);return net.isIPv4(mapped)&&privateNetworkAddress(mapped);}
  }
  return false;
}
async function validatedPublicUrl(raw){
  const url=new URL(raw);
  if(!["http:","https:"].includes(url.protocol)||url.username||url.password)throw new Error("URL pública inválida");
  const hostname=url.hostname.toLowerCase();
  if(hostname==="localhost"||hostname.endsWith(".localhost")||hostname.endsWith(".local"))throw new Error("Host privado não permitido");
  const addresses=await dns.lookup(hostname,{all:true,verbatim:true});
  if(!addresses.length||addresses.some(({address})=>privateNetworkAddress(address)))throw new Error("Host privado não permitido");
  return url;
}
async function limitedResponseText(response,maxBytes=2000000){
  if(!response.body)return "";
  const reader=response.body.getReader();const decoder=new TextDecoder();let received=0,output="";
  while(received<maxBytes){const {done,value}=await reader.read();if(done)break;const remaining=maxBytes-received;const chunk=value.byteLength>remaining?value.subarray(0,remaining):value;received+=chunk.byteLength;output+=decoder.decode(chunk,{stream:received<maxBytes});if(chunk.byteLength<value.byteLength)break;}
  await reader.cancel().catch(()=>{});return output+decoder.decode();
}
async function sourceContainsEmail(sourceUrl,email){
  const controller=new AbortController(); const timeout=setTimeout(()=>controller.abort(),8000);
  try{
    let url=await validatedPublicUrl(sourceUrl);
    for(let redirects=0;redirects<=4;redirects++){
      const response=await fetch(url,{headers:{"user-agent":"Mozilla/5.0 (compatible; ABR-Prospection/1.0)"},signal:controller.signal,redirect:"manual"});
      if(response.status>=300&&response.status<400&&response.headers.get("location")){url=await validatedPublicUrl(new URL(response.headers.get("location"),url).toString());continue;}
      if(!response.ok)return false;
      const contentType=String(response.headers.get("content-type")||"").toLowerCase();if(contentType&&!contentType.includes("text/")&&!contentType.includes("application/xhtml+xml"))return false;
      const text=(await limitedResponseText(response)).toLowerCase()
        .replace(/&#0*64;|&#x0*40;|&commat;|\s+\[at\]\s+|\s+\(at\)\s+/gi,"@")
        .replace(/&#0*46;|&#x0*2e;|&period;|\s+\[dot\]\s+|\s+\(dot\)\s+/gi,".")
        .replace(/&nbsp;|&#0*160;|&#x0*a0;/gi," ");
      return text.includes(email.toLowerCase());
    }
    return false;
  }catch{return false;}finally{clearTimeout(timeout);}
}
const mxCache=new Map();
async function domainHasMail(domain){
  if(mxCache.has(domain))return mxCache.get(domain);
  const check=dns.resolveMx(domain).then((records)=>records.length>0).catch(()=>false);
  mxCache.set(domain,check);return check;
}
function websiteMatchesEmailDomain(website,email){
  try{
    const domain=String(email).split("@")[1]?.toLowerCase();
    const host=new URL(website).hostname.toLowerCase().replace(/^www\./,"");
    return Boolean(domain&&(host===domain||host.endsWith(`.${domain}`)));
  }catch{return false;}
}
async function contactHasPublicEvidence(item){
  if(await sourceContainsEmail(item.sourceUrl,item.email))return true;
  const localPart=item.email.split("@")[0]?.toLowerCase();
  const roleAddress=/^(contato|comercial|vendas|atendimento|orcamento|orçamento|marketing|engenharia|projetos|administrativo|sac)([._-].*)?$/.test(localPart||"");
  if(!roleAddress||!websiteMatchesEmailDomain(item.website,item.email))return false;
  try{await validatedPublicUrl(item.website);}catch{return false;}
  return domainHasMail(item.email.split("@")[1].toLowerCase());
}
function prospectionPrompt({niche,region,quantity,criteria,excludedEmails=[]}){
  const exclusions=excludedEmails.length?` Não repita estes e-mails já encontrados: ${excludedEmails.join(", ")}.`:"";
  return `Você é um pesquisador comercial B2B do Grupo ABR, distribuidor de aço. Pesquise empresas reais do nicho "${niche}" na região "${region}". Encontre até ${quantity} empresas diferentes. Critérios adicionais: ${criteria||"aderência comercial a aços longos, planos, telhas, perfis, chapas ou estruturas metálicas"}.${exclusions}
Use apenas fontes públicas. O e-mail precisa ser corporativo, estar literalmente publicado na URL de origem informada e não pode ser Gmail, Hotmail, Outlook, Yahoo ou outro provedor gratuito. Não invente empresa, site, e-mail ou fonte. Qualifique o potencial de 0 a 100 e sugira um argumento comercial específico.
Responda somente com JSON válido, sem markdown, no formato {"list_name":"...","contacts":[{"company":"...","email":"...","name":"...","segment":"...","city":"...","region":"...","website":"https://...","source_url":"https://pagina-exata-onde-o-email-aparece","qualification_score":0,"qualification_label":"alto|medio|baixo","qualification_reason":"...","suggested_angle":"..."}]}. Se não encontrar um e-mail verificável, não inclua a empresa.`;
}
function parsedResearchPayload(parsed,quantity){
  const raw=Array.isArray(parsed)?parsed:(parsed.contacts||parsed.prospects||[]);
  return {listName:String(parsed.list_name||"").trim(),contacts:raw.map(normalizeContact).filter((item)=>item.company&&corporateEmailIsValid(item.email)&&/^https?:\/\//i.test(item.sourceUrl)).slice(0,quantity)};
}
async function runGroqBatch({niche,region,quantity,criteria,excludedEmails}){
  if(!process.env.GROQ_API_KEY)throw new Error("GROQ_API_KEY não configurada");
  const model=process.env.GROQ_PROSPECTION_MODEL||"openai/gpt-oss-120b";
  const prompt=prospectionPrompt({niche,region,quantity,criteria,excludedEmails});
  const response=await fetch("https://api.groq.com/openai/v1/chat/completions",{method:"POST",headers:{authorization:`Bearer ${process.env.GROQ_API_KEY}`,"content-type":"application/json"},body:JSON.stringify({messages:[{role:"user",content:prompt}],model,temperature:0.2,max_completion_tokens:1800,top_p:1,stream:false,reasoning_effort:"low",tool_choice:"required",tools:[{type:"browser_search"}]}),signal:AbortSignal.timeout(45000)});
  const body=await response.json().catch(()=>({})); if(!response.ok){const error=new Error(body.error?.message||`Falha na Groq (${response.status})`);error.status=response.status;const retryAfter=Number(response.headers.get("retry-after"));error.retryAfterMs=Number.isFinite(retryAfter)&&retryAfter>0?Math.ceil(retryAfter*1000):0;throw error;}
  const parsed=extractResearchJson(body.choices?.[0]?.message?.content,"A Groq");
  return {provider:"groq",model,...parsedResearchPayload(parsed,quantity)};
}
async function runGeminiBatch({niche,region,quantity,criteria,excludedEmails}){
  if(!process.env.GEMINI_API_KEY)throw new Error("GEMINI_API_KEY não configurada");
  const model=process.env.GEMINI_PROSPECTION_MODEL||"gemini-3.6-flash";
  const prompt=prospectionPrompt({niche,region,quantity,criteria,excludedEmails});
  const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,{method:"POST",headers:{"x-goog-api-key":process.env.GEMINI_API_KEY,"content-type":"application/json"},body:JSON.stringify({contents:[{parts:[{text:prompt}]}],tools:[{google_search:{}}],generationConfig:{maxOutputTokens:3000}}),signal:AbortSignal.timeout(45000)});
  const body=await response.json().catch(()=>({})); if(!response.ok){const error=new Error(body.error?.message||`Falha no Gemini (${response.status})`);error.status=response.status;const retryAfter=Number(response.headers.get("retry-after"));error.retryAfterMs=Number.isFinite(retryAfter)&&retryAfter>0?Math.ceil(retryAfter*1000):0;throw error;}
  const text=(body.candidates?.[0]?.content?.parts||[]).map((part)=>part.text||"").join("\n");
  const parsed=extractResearchJson(text,"O Gemini");
  return {provider:"gemini",model,...parsedResearchPayload(parsed,quantity)};
}
async function verifyResearchContacts(items,quantity){
  const unique=[...new Map(items.map((item)=>[item.email,item])).values()].slice(0,quantity);
  const verified=[];
  for(let index=0;index<unique.length;index+=5){
    const group=unique.slice(index,index+5);
    const checks=await Promise.all(group.map(async item=>({item,valid:await contactHasPublicEvidence(item)})));
    verified.push(...checks.filter(check=>check.valid).map(check=>check.item));
  }
  return verified;
}
async function runAiProspection({niche,region,quantity,criteria}){
  const providers=[];
  if(process.env.GROQ_API_KEY)providers.push({name:"groq",run:runGroqBatch});
  if(process.env.GEMINI_API_KEY)providers.push({name:"gemini",run:runGeminiBatch});
  if(!providers.length)throw new Error("Configure GROQ_API_KEY ou GEMINI_API_KEY para executar a Prospecção");
  const candidates=new Map(),contacts=new Map(),models=new Set(),usedProviders=new Set(),failures=[];let listName="";
  const batchSize=5,totalBatches=Math.max(2,Math.ceil(quantity/batchSize)*2);
  for(let batchIndex=0;batchIndex<totalBatches&&contacts.size<quantity;batchIndex++){
    const ordered=providers.map((_,offset)=>providers[(batchIndex+offset)%providers.length]);let result=null;
    for(const provider of ordered){
      const input={niche,region,quantity:batchSize,criteria,excludedEmails:[...candidates.keys()]};
      try{result=await provider.run(input);break;}
      catch(error){
        const delay=retryDelayMs(error);
        failures.push(`${provider.name}: ${error.message}`);
        if(delay&&ordered.length===1){
          await wait(delay+350);
          try{result=await provider.run(input);break;}
          catch(retryError){failures.push(`${provider.name} (nova tentativa): ${retryError.message}`);}
        }
      }
    }
    if(!result){if(!candidates.size)throw new Error(`A pesquisa falhou nos provedores configurados. ${failures.slice(-providers.length).join(" | ")}`);break;}
    if(result.listName&&!listName)listName=result.listName;models.add(result.model);usedProviders.add(result.provider);
    const fresh=[];
    for(const item of result.contacts)if(!candidates.has(item.email)){candidates.set(item.email,item);fresh.push(item);}
    const verified=await verifyResearchContacts(fresh,batchSize);
    for(const item of verified)if(!contacts.has(item.email)&&contacts.size<quantity)contacts.set(item.email,item);
  }
  return {provider:[...usedProviders].join("+"),model:[...models].join(" + "),listName:listName||`${niche} · ${region}`,contacts:[...contacts.values()],candidateCount:candidates.size,rejectedCount:Math.max(0,candidates.size-contacts.size)};
}

let prospectionDrainPromise = null;
let prospectionDrainRequested = false;
function scheduleProspectionDrain() {
  prospectionDrainRequested = true;
  if (prospectionDrainPromise) return prospectionDrainPromise;
  prospectionDrainPromise = new Promise((resolve) => setImmediate(resolve))
    .then(async () => {
      do {
        prospectionDrainRequested = false;
        await drainProspectionQueue();
      } while (prospectionDrainRequested);
    })
    .catch((error) => console.error("Falha na fila de prospecção", error))
    .finally(() => { prospectionDrainPromise = null; });
  return prospectionDrainPromise;
}
async function claimNextProspection() {
  const result = await pool.query(`WITH next_run AS (
    SELECT id FROM prospections WHERE status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1
  ) UPDATE prospections p SET status='researching',error=NULL FROM next_run WHERE p.id=next_run.id RETURNING p.*`);
  return result.rows[0] || null;
}
async function completeProspection(run, research) {
  if (!research.contacts.length) {
    const error = new Error(research.candidateCount
      ? `A IA encontrou ${research.candidateCount} contato(s) candidato(s), mas nenhum passou na validação das fontes públicas. Tente ampliar a região ou ajustar o nicho.`
      : "Os provedores concluíram a pesquisa, mas não sugeriram e-mails corporativos para estes critérios. Tente ampliar a região ou simplificar os filtros.");
    error.status = 422;
    throw error;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const list = (await client.query(`INSERT INTO contact_lists(name,niche,region,qualification,source,criteria,created_by) VALUES($1,$2,$3,'qualified','ai_web_search',$4,$5) RETURNING *`,[run.requested_list_name||research.listName,run.niche,run.region,run.criteria,run.created_by])).rows[0];
    for (const item of research.contacts) {
      const contact = (await client.query(`INSERT INTO contacts(email,name,company,segment,city,region,website,source_url,qualification_score,qualification_label,qualification_reason,suggested_angle,status,subscribed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'valid',TRUE) ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,company=EXCLUDED.company,segment=EXCLUDED.segment,city=EXCLUDED.city,region=EXCLUDED.region,website=EXCLUDED.website,source_url=EXCLUDED.source_url,qualification_score=EXCLUDED.qualification_score,qualification_label=EXCLUDED.qualification_label,qualification_reason=EXCLUDED.qualification_reason,suggested_angle=EXCLUDED.suggested_angle,status='valid',updated_at=NOW() RETURNING id`,[item.email,item.name,item.company,item.segment||run.niche,item.city,item.region||run.region,item.website,item.sourceUrl,item.qualificationScore,item.qualificationLabel,item.qualificationReason,item.suggestedAngle])).rows[0];
      await client.query(`INSERT INTO contact_list_members(list_id,contact_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[list.id,contact.id]);
    }
    await client.query(`UPDATE prospections SET list_id=$1,found_count=$2,candidate_count=$3,rejected_count=$4,status='completed',provider=$5,model=$6,error=NULL,completed_at=NOW() WHERE id=$7`,[list.id,research.contacts.length,research.candidateCount,research.rejectedCount,research.provider,research.model,run.id]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
async function processProspection(run) {
  let research;
  try {
    research = await runAiProspection({niche:run.niche,region:run.region,quantity:number(run.requested_count),criteria:run.criteria});
    await completeProspection(run,research);
  } catch (error) {
    await pool.query(`UPDATE prospections SET status='failed',error=$1,candidate_count=$2,rejected_count=$3,completed_at=NOW() WHERE id=$4`,[String(error.message||error).slice(0,2000),research?.candidateCount||0,research?.rejectedCount||0,run.id]).catch(()=>{});
  }
}
async function drainProspectionQueue() {
  while (true) {
    const run = await claimNextProspection();
    if (!run) return;
    await processProspection(run);
  }
}
async function prospectionPayload(id) {
  const run = (await pool.query(`SELECT p.*,l.name list_name FROM prospections p LEFT JOIN contact_lists l ON l.id=p.list_id WHERE p.id=$1`,[id])).rows[0];
  if (!run) return null;
  let list = null, contacts = [];
  if (run.list_id) {
    list = (await pool.query(`SELECT l.*,COUNT(m.contact_id)::int contacts,COUNT(m.contact_id) FILTER(WHERE c.status='valid' AND c.subscribed)::int valid_contacts FROM contact_lists l LEFT JOIN contact_list_members m ON m.list_id=l.id LEFT JOIN contacts c ON c.id=m.contact_id WHERE l.id=$1 GROUP BY l.id`,[run.list_id])).rows[0] || null;
    contacts = (await pool.query(`SELECT c.* FROM contacts c JOIN contact_list_members m ON m.contact_id=c.id WHERE m.list_id=$1 ORDER BY c.qualification_score DESC,c.company`,[run.list_id])).rows;
  }
  return {prospection:run,list,contacts};
}
app.get("/api/prospections", requireUser, async(_req,res,next)=>{try{const result=await pool.query(`SELECT p.*,l.name list_name FROM prospections p LEFT JOIN contact_lists l ON l.id=p.list_id ORDER BY p.created_at DESC LIMIT 50`);res.json({prospections:result.rows});}catch(error){next(error);}});
app.get("/api/prospections/:id", requireUser, async(req,res,next)=>{try{const payload=await prospectionPayload(req.params.id);if(!payload)return res.status(404).json({error:"Pesquisa não encontrada"});res.json(payload);}catch(error){next(error);}});
app.delete("/api/prospections", requireUser, async(req,res,next)=>{
  const ids=[...new Set((Array.isArray(req.body?.ids)?req.body.ids:[]).map(Number).filter(Number.isInteger))].slice(0,50);
  if(!ids.length)return res.status(400).json({error:"Selecione ao menos uma pesquisa"});
  try{const result=await pool.query(`DELETE FROM prospections WHERE id=ANY($1::bigint[]) AND status NOT IN ('queued','researching') RETURNING id`,[ids]);res.json({deleted:result.rowCount,skipped:ids.length-result.rowCount,ids:result.rows.map((row)=>Number(row.id))});}catch(error){next(error);}
});
app.post("/api/prospections", requireUser, async(req,res,next)=>{
  const niche=String(req.body?.niche||"").trim(),region=String(req.body?.region||"").trim(),criteria=String(req.body?.criteria||"").trim(),requestedName=String(req.body?.listName||"").trim();const quantity=Math.max(1,Math.min(20,Number(req.body?.quantity)||10));
  if(!niche||!region)return res.status(400).json({error:"Informe o nicho e a região"});
  const configuredModel=[process.env.GROQ_API_KEY&&(process.env.GROQ_PROSPECTION_MODEL||"openai/gpt-oss-120b"),process.env.GEMINI_API_KEY&&(process.env.GEMINI_PROSPECTION_MODEL||"gemini-3.6-flash")].filter(Boolean).join(" + ");
  try{const run=(await pool.query(`INSERT INTO prospections(niche,region,criteria,requested_list_name,requested_count,status,provider,model,created_by) VALUES($1,$2,$3,$4,$5,'queued','ai_fallback',$6,$7) RETURNING *`,[niche,region,criteria,requestedName,quantity,configuredModel,req.user.id])).rows[0];res.status(202).json({prospection:run});scheduleProspectionDrain();}
  catch(error){next(error);}
});

async function accountEmailSender(account, user) {
  if (!account || account.provider === "none") throw new Error("Configure uma conta Microsoft ou SMTP antes de enviar a campanha");
  if (account.provider === "microsoft") {
    const ready = await refreshMicrosoftAccount(account);
    return async ({to,subject,html}) => {
      const response = await fetch("https://graph.microsoft.com/v1.0/me/sendMail", {method:"POST",headers:{authorization:`Bearer ${ready.accessToken}`,"content-type":"application/json"},body:JSON.stringify({message:{subject,body:{contentType:"HTML",content:html},toRecipients:[{emailAddress:{address:to}}],replyTo:account.reply_to?[{emailAddress:{address:account.reply_to}}]:undefined},saveToSentItems:true})});
      if (!response.ok) { const body=await response.json().catch(()=>({})); throw new Error(body.error?.message||"Falha no envio Microsoft"); }
      return "microsoft-accepted";
    };
  }
  if (account.provider === "smtp") {
    if (!account.smtp_host || !account.smtp_user || !account.smtp_password_enc) throw new Error("Complete servidor, usuário e senha SMTP antes de enviar");
    const transporter = nodemailer.createTransport({host:account.smtp_host,port:account.smtp_port||587,secure:Boolean(account.smtp_secure),auth:{user:account.smtp_user,pass:decryptSecret(account.smtp_password_enc)}});
    return async ({to,subject,html}) => {
      const result = await transporter.sendMail({from:`${account.display_name||user.name} <${account.email||account.smtp_user}>`,to,replyTo:account.reply_to||undefined,subject,html});
      return result.messageId || "smtp-accepted";
    };
  }
  throw new Error("Provedor de envio não reconhecido");
}

async function sendWaveImmediately({campaignId,waveId,user}) {
  const bundle = (await pool.query(`SELECT w.id,w.wave_order,w.automation_mode,w.status,c.contact_list_id,c.owner_id,e.subject,e.html_content
    FROM campaign_waves w JOIN campaigns c ON c.id=w.campaign_id JOIN campaign_emails e ON e.wave_id=w.id
    WHERE c.id=$1 AND w.id=$2`, [campaignId,waveId])).rows[0];
  if (!bundle) throw new Error("O e-mail da primeira onda não foi encontrado");
  if (Number(bundle.wave_order) !== 1 || bundle.automation_mode !== "now") throw new Error("Enviar agora está disponível somente para a primeira onda");
  const account = (await pool.query(`SELECT * FROM user_email_settings WHERE user_id=$1`, [user.id])).rows[0];
  const sendEmail = await accountEmailSender(account,user);
  const contacts = (await pool.query(`SELECT c.id,c.email,c.name,c.company FROM contact_list_members m JOIN contacts c ON c.id=m.contact_id
    WHERE m.list_id=$1 AND c.status='valid' AND c.subscribed=TRUE ORDER BY c.id`, [bundle.contact_list_id])).rows;
  if (!contacts.length) throw new Error("A lista não possui contatos válidos e autorizados para envio");

  const claimed = [];
  for (const contact of contacts) {
    const delivery = await pool.query(`INSERT INTO campaign_deliveries(campaign_id,wave_id,contact_id,status)
      VALUES($1,$2,$3,'sending') ON CONFLICT(wave_id,contact_id) DO UPDATE SET status='sending',error=NULL,updated_at=NOW()
      WHERE campaign_deliveries.status='failed' OR (campaign_deliveries.status='sending' AND campaign_deliveries.updated_at<NOW()-INTERVAL '15 minutes') RETURNING id`, [campaignId,waveId,contact.id]);
    if (delivery.rowCount) claimed.push({...contact,deliveryId:delivery.rows[0].id});
  }
  await pool.query(`UPDATE campaign_waves SET status='sending' WHERE id=$1 AND status NOT IN ('completed')`, [waveId]);
  await pool.query(`UPDATE campaigns SET status='sending',updated_at=NOW() WHERE id=$1`, [campaignId]);

  for (let index=0; index<claimed.length; index+=3) {
    const batch = claimed.slice(index,index+3);
    await Promise.all(batch.map(async contact => {
      try {
        const html = personalizeCampaignHtml(bundle.html_content,contact,campaignId) + cleanHtml(account.signature_html);
        const messageId = await sendEmail({to:contact.email,subject:bundle.subject,html});
        await pool.query(`UPDATE campaign_deliveries SET status='sent',provider_message_id=$1,error=NULL,sent_at=NOW(),updated_at=NOW() WHERE id=$2`, [messageId,contact.deliveryId]);
        await pool.query(`INSERT INTO email_events(campaign_id,contact_id,event_type) VALUES($1,$2,'sent')`, [campaignId,contact.id]);
      } catch (error) {
        await pool.query(`UPDATE campaign_deliveries SET status='failed',error=$1,updated_at=NOW() WHERE id=$2`, [String(error.message||error).slice(0,1000),contact.deliveryId]);
      }
    }));
  }

  const stats = (await pool.query(`SELECT COUNT(*) FILTER(WHERE status='sent')::int sent,COUNT(*) FILTER(WHERE status='failed')::int failed FROM campaign_deliveries WHERE wave_id=$1`, [waveId])).rows[0];
  const sent=number(stats.sent),failed=number(stats.failed),total=contacts.length;
  const waveStatus=sent>=total?"completed":sent>0?"partial":"failed";
  await pool.query(`UPDATE campaign_waves SET status=$1 WHERE id=$2`, [waveStatus,waveId]);
  await pool.query(`UPDATE campaign_emails SET status=$1,updated_at=NOW() WHERE wave_id=$2`, [waveStatus,waveId]);
  await pool.query(`UPDATE campaigns SET status=$1,updated_at=NOW() WHERE id=$2`, [sent>0?"active":"draft",campaignId]);
  return {sent,failed,total,skipped:Math.max(0,total-claimed.length),status:waveStatus};
}

app.get("/api/campaigns", requireUser, async(_req,res,next)=>{try{const result=await pool.query(`SELECT c.id,c.name,c.subject,c.brief,c.source_references,c.status,c.audience_label,c.contact_list_id,c.sender_name,c.sender_email,c.created_at,COALESCE(SUM(w.recipient_count),0)::int recipients,COUNT(w.id)::int waves,MIN(w.scheduled_at) FILTER(WHERE w.scheduled_at>NOW()) next_send FROM campaigns c LEFT JOIN campaign_waves w ON w.campaign_id=c.id GROUP BY c.id ORDER BY c.created_at DESC`);res.json({campaigns:result.rows});}catch(error){next(error);}});
app.post("/api/campaigns", requireUser, async(req,res,next)=>{
  const {name,brief="",sourceReferences=[],senderName=adminName,senderEmail="",contactListId,waves=1,firstSendAt}=req.body||{};if(!name?.trim())return res.status(400).json({error:"O nome da campanha é obrigatório"});if(!contactListId)return res.status(400).json({error:"Selecione a lista de contatos destinatária"});
  try{const list=await pool.query(`SELECT name FROM contact_lists WHERE id=$1 AND status='ready'`,[contactListId]);if(!list.rowCount)return res.status(400).json({error:"Lista não encontrada ou indisponível"});const contactCount=number((await pool.query(`SELECT COUNT(*) FROM contact_list_members m JOIN contacts c ON c.id=m.contact_id WHERE m.list_id=$1 AND c.status='valid' AND c.subscribed`,[contactListId])).rows[0].count);if(!contactCount)return res.status(400).json({error:"A lista escolhida não possui contatos válidos"});const client=await pool.connect();try{await client.query("BEGIN");const campaign=(await client.query(`INSERT INTO campaigns(name,brief,source_references,sender_name,sender_email,audience_label,contact_list_id,owner_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'draft') RETURNING *`,[name.trim(),String(brief),JSON.stringify(Array.isArray(sourceReferences)?sourceReferences:[]),senderName,senderEmail,list.rows[0].name,contactListId,req.user.id])).rows[0];const total=Math.min(10,Math.max(1,Number(waves)||1));for(let index=0;index<total;index++){const scheduled=firstSendAt?new Date(new Date(firstSendAt).getTime()+index*24*60*60*1000):null;await client.query(`INSERT INTO campaign_waves(campaign_id,wave_order,scheduled_at,recipient_count,status) VALUES($1,$2,$3,$4,'draft')`,[campaign.id,index+1,scheduled,contactCount]);}await client.query("COMMIT");res.status(201).json({campaign});}catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}}catch(error){next(error);}
});
app.put("/api/campaigns/:id/contact-list", requireUser, async(req,res,next)=>{
  const contactListId=Number(req.body?.contactListId);
  if(!contactListId)return res.status(400).json({error:"Selecione a lista de contatos destinatária"});
  try{
    const [campaign,list,deliveries]=await Promise.all([
      pool.query(`SELECT id,contact_list_id FROM campaigns WHERE id=$1`,[req.params.id]),
      pool.query(`SELECT id,name FROM contact_lists WHERE id=$1 AND status='ready'`,[contactListId]),
      pool.query(`SELECT 1 FROM campaign_deliveries WHERE campaign_id=$1 LIMIT 1`,[req.params.id])
    ]);
    if(!campaign.rowCount)return res.status(404).json({error:"Campanha não encontrada"});
    if(!list.rowCount)return res.status(400).json({error:"Lista não encontrada ou indisponível"});
    if(deliveries.rowCount)return res.status(409).json({error:"A lista não pode ser alterada depois que a campanha iniciou os envios"});
    const contactCount=number((await pool.query(`SELECT COUNT(*) FROM contact_list_members m JOIN contacts c ON c.id=m.contact_id WHERE m.list_id=$1 AND c.status='valid' AND c.subscribed`,[contactListId])).rows[0].count);
    if(!contactCount)return res.status(400).json({error:"A lista escolhida não possui contatos válidos"});
    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      const updated=(await client.query(`UPDATE campaigns SET contact_list_id=$1,audience_label=$2,updated_at=NOW() WHERE id=$3 RETURNING *`,[contactListId,list.rows[0].name,req.params.id])).rows[0];
      await client.query(`UPDATE campaign_waves SET recipient_count=$1 WHERE campaign_id=$2`,[contactCount,req.params.id]);
      await client.query("COMMIT");
      res.json({campaign:updated,recipientCount:contactCount});
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }catch(error){next(error);}
});
app.get("/api/campaigns/:id/waves", requireUser, async(req,res,next)=>{try{const result=await pool.query(`SELECT w.id,w.wave_order,w.scheduled_at,w.recipient_count,w.automation_mode,w.delay_days,w.status,e.id email_id,e.subject,e.html_content,e.preview_text,e.editor_mode,e.layout_json,e.status email_status FROM campaign_waves w LEFT JOIN campaign_emails e ON e.wave_id=w.id WHERE w.campaign_id=$1 ORDER BY w.wave_order`,[req.params.id]);res.json({waves:result.rows});}catch(error){next(error);}});
app.post("/api/campaigns/:id/waves/:waveId/email", requireUser, async(req,res,next)=>{const{subject,htmlContent="",previewText="",scheduledAt=null,automationMode="dated",delayDays=0,editorMode="visual",layout=[],sendNow=false}=req.body||{};if(!subject?.trim())return res.status(400).json({error:"O assunto é obrigatório"});if(/<script[\s>]/i.test(htmlContent))return res.status(400).json({error:"JavaScript não é permitido em e-mails"});if(!["now","dated","unopened","opened_no_click","no_reply"].includes(automationMode))return res.status(400).json({error:"Regra de envio inválida"});try{const wave=await pool.query(`SELECT id,wave_order,status FROM campaign_waves WHERE id=$1 AND campaign_id=$2`,[req.params.waveId,req.params.id]);if(!wave.rowCount)return res.status(404).json({error:"Onda não encontrada"});if(automationMode==="now"&&Number(wave.rows[0].wave_order)!==1)return res.status(400).json({error:"Enviar agora está disponível somente para a primeira onda"});if(sendNow&&automationMode!=="now")return res.status(400).json({error:"Confirme a regra Enviar agora antes do disparo"});await pool.query(`UPDATE campaign_waves SET scheduled_at=$1,automation_mode=$2,delay_days=$3 WHERE id=$4`,[automationMode==="dated"?scheduledAt:null,automationMode,Math.max(0,Number(delayDays)||0),req.params.waveId]);const saved=await pool.query(`INSERT INTO campaign_emails(campaign_id,wave_id,subject,html_content,preview_text,editor_mode,layout_json,status) VALUES($1,$2,$3,$4,$5,$6,$7,'ready') ON CONFLICT(campaign_id,wave_id) DO UPDATE SET subject=EXCLUDED.subject,html_content=EXCLUDED.html_content,preview_text=EXCLUDED.preview_text,editor_mode=EXCLUDED.editor_mode,layout_json=EXCLUDED.layout_json,status=CASE WHEN campaign_emails.status IN ('completed','partial') THEN campaign_emails.status ELSE 'ready' END,updated_at=NOW() RETURNING *`,[req.params.id,req.params.waveId,subject.trim(),htmlContent,previewText,editorMode,JSON.stringify(Array.isArray(layout)?layout:[])]);await pool.query(`UPDATE campaigns SET subject=$1,updated_at=NOW() WHERE id=$2`,[subject.trim(),req.params.id]);const delivery=sendNow?await sendWaveImmediately({campaignId:req.params.id,waveId:req.params.waveId,user:req.user}):null;res.status(201).json({email:saved.rows[0],delivery});}catch(error){next(error);}});
app.post("/api/campaigns/:id/duplicate", requireUser, async(req,res,next)=>{try{const original=(await pool.query(`SELECT * FROM campaigns WHERE id=$1`,[req.params.id])).rows[0];if(!original)return res.status(404).json({error:"Campanha não encontrada"});const client=await pool.connect();try{await client.query("BEGIN");const copy=(await client.query(`INSERT INTO campaigns(name,subject,html_content,brief,source_references,sender_name,sender_email,audience_label,contact_list_id,owner_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'draft') RETURNING *`,[`${original.name} — cópia`,original.subject,original.html_content,original.brief,original.source_references,original.sender_name,original.sender_email,original.audience_label,original.contact_list_id,req.user.id])).rows[0];const waves=(await client.query(`SELECT * FROM campaign_waves WHERE campaign_id=$1 ORDER BY wave_order`,[original.id])).rows;for(const wave of waves){const newWave=(await client.query(`INSERT INTO campaign_waves(campaign_id,wave_order,scheduled_at,recipient_count,automation_mode,delay_days,status) VALUES($1,$2,NULL,$3,$4,$5,'draft') RETURNING id`,[copy.id,wave.wave_order,wave.recipient_count,wave.automation_mode,wave.delay_days])).rows[0];const email=(await client.query(`SELECT * FROM campaign_emails WHERE wave_id=$1`,[wave.id])).rows[0];if(email)await client.query(`INSERT INTO campaign_emails(campaign_id,wave_id,subject,html_content,preview_text,editor_mode,layout_json,status) VALUES($1,$2,$3,$4,$5,$6,$7,'draft')`,[copy.id,newWave.id,email.subject,email.html_content,email.preview_text,email.editor_mode,email.layout_json]);}await client.query("COMMIT");res.status(201).json({campaign:copy});}catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}}catch(error){next(error);}});
app.delete("/api/campaigns/:id", requireUser, async(req,res,next)=>{try{await pool.query(`DELETE FROM campaigns WHERE id=$1`,[req.params.id]);res.json({ok:true});}catch(error){next(error);}});

app.get("/api/templates", requireUser, async(req,res,next)=>{try{const result=await pool.query(`SELECT id,name,template_type,html_content,created_at,updated_at FROM email_templates WHERE user_id=$1 ORDER BY template_type,name`,[req.user.id]);res.json({templates:result.rows});}catch(error){next(error);}});
app.post("/api/templates", requireUser, async(req,res,next)=>{const name=String(req.body?.name||"").trim(),type=String(req.body?.templateType||"").trim(),html=cleanHtml(req.body?.htmlContent);if(!name||!["header","body","footer","complete"].includes(type)||!html)return res.status(400).json({error:"Informe nome, tipo e conteúdo do modelo"});try{const result=await pool.query(`INSERT INTO email_templates(user_id,name,template_type,html_content) VALUES($1,$2,$3,$4) RETURNING *`,[req.user.id,name,type,html]);res.status(201).json({template:result.rows[0]});}catch(error){next(error);}});
app.delete("/api/templates/:id", requireUser, async(req,res,next)=>{try{await pool.query(`DELETE FROM email_templates WHERE id=$1 AND user_id=$2`,[req.params.id,req.user.id]);res.json({ok:true});}catch(error){next(error);}});

app.get("/api/settings/email", requireUser, async(req,res,next)=>{try{const result=await pool.query(`SELECT provider,email,display_name,reply_to,signature_html,signature_text,smtp_host,smtp_port,smtp_secure,smtp_user,connected_at,updated_at FROM user_email_settings WHERE user_id=$1`,[req.user.id]);res.json({settings:result.rows[0]||{provider:"none",email:req.user.email,display_name:req.user.name,signature_html:"",signature_text:""}});}catch(error){next(error);}});
app.put("/api/settings/email", requireUser, async(req,res,next)=>{const body=req.body||{};const provider=["none","smtp","microsoft"].includes(body.provider)?body.provider:"none";try{const current=(await pool.query(`SELECT smtp_password_enc FROM user_email_settings WHERE user_id=$1`,[req.user.id])).rows[0];const password=body.smtpPassword?encryptSecret(body.smtpPassword):current?.smtp_password_enc||null;const result=await pool.query(`INSERT INTO user_email_settings(user_id,provider,email,display_name,reply_to,signature_html,signature_text,smtp_host,smtp_port,smtp_secure,smtp_user,smtp_password_enc,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW()) ON CONFLICT(user_id) DO UPDATE SET provider=EXCLUDED.provider,email=EXCLUDED.email,display_name=EXCLUDED.display_name,reply_to=EXCLUDED.reply_to,signature_html=EXCLUDED.signature_html,signature_text=EXCLUDED.signature_text,smtp_host=EXCLUDED.smtp_host,smtp_port=EXCLUDED.smtp_port,smtp_secure=EXCLUDED.smtp_secure,smtp_user=EXCLUDED.smtp_user,smtp_password_enc=EXCLUDED.smtp_password_enc,updated_at=NOW() RETURNING provider,email,display_name,reply_to,signature_html,signature_text,smtp_host,smtp_port,smtp_secure,smtp_user,connected_at,updated_at`,[req.user.id,provider,String(body.email||req.user.email),String(body.displayName||req.user.name),String(body.replyTo||""),cleanHtml(body.signatureHtml),String(body.signatureText||""),String(body.smtpHost||""),Number(body.smtpPort)||587,Boolean(body.smtpSecure),String(body.smtpUser||""),password]);res.json({settings:result.rows[0]});}catch(error){next(error);}});

function microsoftRedirectUri(){return `${frontendUrl.replace(/\/$/,"")}/api/abr/microsoft/callback`;}
async function refreshMicrosoftAccount(account){
  if(account.microsoft_access_token_enc&&account.microsoft_expires_at&&new Date(account.microsoft_expires_at).getTime()>Date.now()+60000)return{...account,accessToken:decryptSecret(account.microsoft_access_token_enc)};
  const refreshToken=decryptSecret(account.microsoft_refresh_token_enc);if(!refreshToken)throw new Error("Reconecte sua conta Microsoft");
  const tenant=process.env.MICROSOFT_TENANT_ID;const response=await fetch(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:process.env.MICROSOFT_CLIENT_ID||"",client_secret:process.env.MICROSOFT_CLIENT_SECRET||"",grant_type:"refresh_token",refresh_token:refreshToken,scope:"offline_access User.Read Mail.Read Mail.Send"})});const token=await response.json();if(!response.ok)throw new Error(token.error_description||"Não foi possível renovar a conta Microsoft");const expires=new Date(Date.now()+Number(token.expires_in||3600)*1000);await pool.query(`UPDATE user_email_settings SET microsoft_access_token_enc=$1,microsoft_refresh_token_enc=COALESCE($2,microsoft_refresh_token_enc),microsoft_expires_at=$3,updated_at=NOW() WHERE user_id=$4`,[encryptSecret(token.access_token),token.refresh_token?encryptSecret(token.refresh_token):null,expires,account.user_id]);return{...account,accessToken:token.access_token,microsoft_expires_at:expires};
}
app.post("/api/microsoft/connect", requireUser, async(req,res,next)=>{try{if(!process.env.MICROSOFT_TENANT_ID||!process.env.MICROSOFT_CLIENT_ID||!process.env.MICROSOFT_CLIENT_SECRET)return res.status(503).json({error:"A integração Microsoft ainda não foi configurada no servidor"});const state=randomToken(24);await pool.query(`INSERT INTO oauth_states(state_hash,user_id,expires_at) VALUES($1,$2,NOW()+INTERVAL '10 minutes')`,[tokenHash(state),req.user.id]);const url=new URL(`https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize`);url.search=new URLSearchParams({client_id:process.env.MICROSOFT_CLIENT_ID,response_type:"code",redirect_uri:microsoftRedirectUri(),response_mode:"query",scope:"offline_access User.Read Mail.Read Mail.Send",state}).toString();res.json({authorizeUrl:url.toString()});}catch(error){next(error);}});
app.get("/api/microsoft/callback", async(req,res)=>{const code=String(req.query.code||""),state=String(req.query.state||"");try{const saved=(await pool.query(`DELETE FROM oauth_states WHERE state_hash=$1 AND expires_at>NOW() RETURNING user_id`,[tokenHash(state)])).rows[0];if(!saved||!code)throw new Error("Autorização expirada ou inválida");const response=await fetch(`https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}/oauth2/v2.0/token`,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:new URLSearchParams({client_id:process.env.MICROSOFT_CLIENT_ID||"",client_secret:process.env.MICROSOFT_CLIENT_SECRET||"",code,redirect_uri:microsoftRedirectUri(),grant_type:"authorization_code",scope:"offline_access User.Read Mail.Read Mail.Send"})});const token=await response.json();if(!response.ok)throw new Error(token.error_description||"Falha ao conectar Microsoft");const profileResponse=await fetch("https://graph.microsoft.com/v1.0/me?$select=displayName,mail,userPrincipalName",{headers:{authorization:`Bearer ${token.access_token}`}});const profile=await profileResponse.json();await pool.query(`INSERT INTO user_email_settings(user_id,provider,email,display_name,microsoft_access_token_enc,microsoft_refresh_token_enc,microsoft_expires_at,connected_at,updated_at) VALUES($1,'microsoft',$2,$3,$4,$5,$6,NOW(),NOW()) ON CONFLICT(user_id) DO UPDATE SET provider='microsoft',email=EXCLUDED.email,display_name=EXCLUDED.display_name,microsoft_access_token_enc=EXCLUDED.microsoft_access_token_enc,microsoft_refresh_token_enc=EXCLUDED.microsoft_refresh_token_enc,microsoft_expires_at=EXCLUDED.microsoft_expires_at,connected_at=NOW(),updated_at=NOW()`,[saved.user_id,profile.mail||profile.userPrincipalName,profile.displayName,encryptSecret(token.access_token),encryptSecret(token.refresh_token),new Date(Date.now()+Number(token.expires_in||3600)*1000)]);res.redirect(`${frontendUrl}/?microsoft=connected`);}catch(error){res.redirect(`${frontendUrl}/?microsoft=error&detail=${encodeURIComponent(error.message)}`);}});
app.post("/api/microsoft/disconnect", requireUser, async(req,res,next)=>{try{await pool.query(`UPDATE user_email_settings SET provider='none',microsoft_access_token_enc=NULL,microsoft_refresh_token_enc=NULL,microsoft_expires_at=NULL,connected_at=NULL WHERE user_id=$1`,[req.user.id]);res.json({ok:true});}catch(error){next(error);}});
app.get("/api/inbox", requireUser, async(req,res,next)=>{try{const account=(await pool.query(`SELECT * FROM user_email_settings WHERE user_id=$1`,[req.user.id])).rows[0];if(!account||account.provider!=="microsoft")return res.status(409).json({error:"Conecte uma conta Microsoft para receber as respostas no sistema"});const ready=await refreshMicrosoftAccount(account);const response=await fetch("https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages?$top=50&$orderby=receivedDateTime%20desc&$select=id,subject,from,receivedDateTime,isRead,bodyPreview,webLink",{headers:{authorization:`Bearer ${ready.accessToken}`}});const body=await response.json();if(!response.ok)throw new Error(body.error?.message||"Não foi possível sincronizar a caixa de entrada");res.json({messages:(body.value||[]).map((item)=>({id:item.id,subject:item.subject,fromName:item.from?.emailAddress?.name,fromEmail:item.from?.emailAddress?.address,receivedAt:item.receivedDateTime,isRead:item.isRead,preview:item.bodyPreview,webLink:item.webLink}))});}catch(error){next(error);}});
app.post("/api/email/test", requireUser, async(req,res,next)=>{try{const account=(await pool.query(`SELECT * FROM user_email_settings WHERE user_id=$1`,[req.user.id])).rows[0];if(!account)return res.status(409).json({error:"Configure sua conta de envio"});const to=String(req.body?.to||account.email||req.user.email),subject=String(req.body?.subject||"Teste do Email Bomber"),content=cleanHtml(req.body?.htmlContent||"<p>Seu e-mail está configurado corretamente.</p>")+cleanHtml(account.signature_html);const sendEmail=await accountEmailSender(account,req.user);await sendEmail({to,subject,html:content});res.json({ok:true,to});}catch(error){next(error);}});

app.get("/api/admins", requireUser, async(_req,res,next)=>{try{const result=await pool.query(`SELECT email,name,role,status,created_at FROM users WHERE role='admin' ORDER BY created_at`);res.json({admins:result.rows});}catch(error){next(error);}});
app.use((error,_req,res,_next)=>{console.error(error);res.status(500).json({error:error.message||"Erro interno"});});
app.use((_req,res)=>res.status(404).json({error:"Rota não encontrada"}));
app.listen(port,"0.0.0.0",()=>console.log(`Email Bomber API ouvindo na porta ${port}`));
