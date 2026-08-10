import "dotenv/config";
import cors from "cors";
import crypto from "crypto";
import express from "express";
import helmet from "helmet";
import pg from "pg";

const app = express();
const port = Number(process.env.PORT || 3000);
const startedAt = new Date().toISOString();
const adminEmail = "thiago.almeida@grupoabr.com.br";

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || true }));
app.use(express.json({ limit: "2mb" }));

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

const pool = process.env.DATABASE_URL
  ? new pg.Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
      max: 5,
    })
  : null;

let schemaPromise;
async function initializeDatabase() {
  if (!pool) throw new Error("DATABASE_URL não configurada");
  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT,
        role TEXT NOT NULL DEFAULT 'admin', password_hash TEXT,
        status TEXT NOT NULL DEFAULT 'pending_password_setup', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS contacts (
        id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT,
        company TEXT, segment TEXT, status TEXT NOT NULL DEFAULT 'valid',
        subscribed BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS campaigns (
        id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, subject TEXT NOT NULL,
        html_content TEXT NOT NULL DEFAULT '', sender_name TEXT, sender_email TEXT,
        audience_label TEXT NOT NULL DEFAULT 'Todos os contatos', status TEXT NOT NULL DEFAULT 'draft',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS campaign_waves (
        id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        wave_order INTEGER NOT NULL, scheduled_at TIMESTAMPTZ, recipient_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'scheduled', UNIQUE(campaign_id, wave_order)
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS email_events (
        id BIGSERIAL PRIMARY KEY, campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL,
        contact_id BIGINT REFERENCES contacts(id) ON DELETE SET NULL, event_type TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await pool.query(
        `INSERT INTO users (email, name, role) VALUES ($1, $2, 'admin') ON CONFLICT (email) DO NOTHING`,
        [adminEmail, "Thiago Almeida"],
      );
    })().catch((error) => { schemaPromise = undefined; throw error; });
  }
  return schemaPromise;
}

async function requireDatabase(_req, res, next) {
  try { await initializeDatabase(); next(); }
  catch (error) { res.status(503).json({ error: "Banco de dados indisponível", detail: error.message }); }
}

function number(value) { return Number(value || 0); }
function normalizeContact(item) {
  const email = String(item.email || item.Email || item["E-mail"] || "").trim().toLowerCase();
  return { email, name: String(item.name || item.nome || item.Nome || "").trim(), company: String(item.company || item.empresa || item.Empresa || "").trim(), segment: String(item.segment || item.segmento || item.Segmento || "").trim() };
}

app.get("/", (_req, res) => res.json({ service: "ABR Ondas API", status: "online", version: "0.2.0" }));
app.get("/health", async (_req, res) => {
  try {
    await initializeDatabase();
    res.json({ status: "ok", database: "connected", startedAt });
  } catch { res.status(503).json({ status: "degraded", database: pool ? "unavailable" : "not_configured", startedAt }); }
});

app.get("/api/config/status", requireServiceKey, (_req, res) => res.json({
  database: Boolean(process.env.DATABASE_URL), microsoftTenant: Boolean(process.env.MICROSOFT_TENANT_ID),
  microsoftClient: Boolean(process.env.MICROSOFT_CLIENT_ID), microsoftSecret: Boolean(process.env.MICROSOFT_CLIENT_SECRET),
  sender: process.env.MICROSOFT_SENDER_EMAIL || null,
}));

app.get("/api/dashboard", requireServiceKey, requireDatabase, async (_req, res, next) => {
  try {
    const [contacts, campaigns, events, recent] = await Promise.all([
      pool.query(`SELECT COUNT(*) FILTER (WHERE status = 'valid' AND subscribed) AS valid, COUNT(*) FILTER (WHERE status <> 'valid') AS invalid, COUNT(*) FILTER (WHERE NOT subscribed) AS unsubscribed, COUNT(*) AS total FROM contacts`),
      pool.query(`SELECT COUNT(*) FILTER (WHERE status = 'scheduled') AS scheduled, COUNT(*) FILTER (WHERE status = 'sending') AS sending, COUNT(*) FILTER (WHERE status = 'completed') AS completed FROM campaigns`),
      pool.query(`SELECT COUNT(*) FILTER (WHERE event_type = 'sent') AS sent, COUNT(*) FILTER (WHERE event_type = 'delivered') AS delivered, COUNT(*) FILTER (WHERE event_type = 'opened') AS opened, COUNT(*) FILTER (WHERE event_type = 'clicked') AS clicked FROM email_events`),
      pool.query(`SELECT c.id, c.name, c.subject, c.status, c.audience_label, c.created_at, COALESCE(SUM(w.recipient_count),0)::int AS recipients, COUNT(w.id)::int AS waves FROM campaigns c LEFT JOIN campaign_waves w ON w.campaign_id=c.id GROUP BY c.id ORDER BY c.created_at DESC LIMIT 6`),
    ]);
    const e = events.rows[0]; const sent = number(e.sent); const delivered = number(e.delivered); const opened = number(e.opened); const clicked = number(e.clicked);
    res.json({ metrics: { sent, deliveryRate: sent ? delivered / sent : 0, openRate: delivered ? opened / delivered : 0, clickRate: opened ? clicked / opened : 0 }, health: { ...Object.fromEntries(Object.entries(contacts.rows[0]).map(([k,v])=>[k,number(v)])) }, campaignCounts: Object.fromEntries(Object.entries(campaigns.rows[0]).map(([k,v])=>[k,number(v)])), recentCampaigns: recent.rows });
  } catch (error) { next(error); }
});

app.get("/api/campaigns", requireServiceKey, requireDatabase, async (_req, res, next) => {
  try { const result = await pool.query(`SELECT c.id,c.name,c.subject,c.status,c.audience_label,c.sender_name,c.sender_email,c.created_at,COALESCE(SUM(w.recipient_count),0)::int AS recipients,COUNT(w.id)::int AS waves,MIN(w.scheduled_at) AS next_send FROM campaigns c LEFT JOIN campaign_waves w ON w.campaign_id=c.id GROUP BY c.id ORDER BY c.created_at DESC`); res.json({ campaigns: result.rows }); } catch (error) { next(error); }
});

app.post("/api/campaigns", requireServiceKey, requireDatabase, async (req, res, next) => {
  const { name, subject, htmlContent = "", senderName = "Grupo ABR", senderEmail = process.env.MICROSOFT_SENDER_EMAIL || "", audienceLabel = "Todos os contatos", waves = 1, firstSendAt } = req.body || {};
  if (!name?.trim() || !subject?.trim()) return res.status(400).json({ error: "Nome e assunto são obrigatórios" });
  try {
    const contactCount = number((await pool.query(`SELECT COUNT(*) FROM contacts WHERE status='valid' AND subscribed`)).rows[0].count);
    const campaign = await pool.query(`INSERT INTO campaigns(name,subject,html_content,sender_name,sender_email,audience_label,status) VALUES($1,$2,$3,$4,$5,$6,'scheduled') RETURNING *`, [name.trim(), subject.trim(), htmlContent, senderName, senderEmail, audienceLabel]);
    const totalWaves = Math.min(10, Math.max(1, Number(waves) || 1));
    for (let index = 0; index < totalWaves; index += 1) {
      const scheduled = firstSendAt ? new Date(new Date(firstSendAt).getTime() + index * 24 * 60 * 60 * 1000) : null;
      await pool.query(`INSERT INTO campaign_waves(campaign_id,wave_order,scheduled_at,recipient_count) VALUES($1,$2,$3,$4)`, [campaign.rows[0].id, index + 1, scheduled, Math.ceil(contactCount / totalWaves)]);
    }
    res.status(201).json({ campaign: campaign.rows[0] });
  } catch (error) { next(error); }
});

app.get("/api/contacts", requireServiceKey, requireDatabase, async (req, res, next) => {
  try { const term = String(req.query.search || "").trim(); const result = await pool.query(`SELECT id,name,email,company,segment,status,subscribed,created_at FROM contacts WHERE ($1='' OR name ILIKE '%' || $1 || '%' OR email ILIKE '%' || $1 || '%' OR company ILIKE '%' || $1 || '%') ORDER BY created_at DESC LIMIT 200`, [term]); res.json({ contacts: result.rows }); } catch (error) { next(error); }
});

app.post("/api/contacts/import", requireServiceKey, requireDatabase, async (req, res, next) => {
  const items = Array.isArray(req.body?.contacts) ? req.body.contacts.map(normalizeContact).filter((item) => item.email.includes("@")) : [];
  if (!items.length) return res.status(400).json({ error: "Nenhum contato válido encontrado" });
  try {
    let imported = 0;
    for (const item of items.slice(0, 10000)) { const result = await pool.query(`INSERT INTO contacts(email,name,company,segment) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO UPDATE SET name=EXCLUDED.name,company=EXCLUDED.company,segment=EXCLUDED.segment,updated_at=NOW()`, [item.email,item.name,item.company,item.segment]); if (result.rowCount) imported += 1; }
    res.status(201).json({ imported, received: items.length });
  } catch (error) { next(error); }
});

app.get("/api/admins", requireServiceKey, requireDatabase, async (_req, res, next) => {
  try { const result = await pool.query(`SELECT email,name,role,status,created_at FROM users WHERE role='admin' ORDER BY created_at`); res.json({ admins: result.rows }); } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => { console.error(error); res.status(500).json({ error: "Erro interno" }); });
app.use((_req, res) => res.status(404).json({ error: "Rota não encontrada" }));
app.listen(port, "0.0.0.0", () => console.log(`ABR Ondas API ouvindo na porta ${port}`));
