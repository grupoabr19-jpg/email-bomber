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
      await pool.query(`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS brief TEXT NOT NULL DEFAULT ''`);
      await pool.query(`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS source_references JSONB NOT NULL DEFAULT '[]'::jsonb`);
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
      await pool.query(`CREATE TABLE IF NOT EXISTS campaign_emails (
        id BIGSERIAL PRIMARY KEY, campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
        wave_id BIGINT NOT NULL REFERENCES campaign_waves(id) ON DELETE CASCADE,
        subject TEXT NOT NULL, html_content TEXT NOT NULL DEFAULT '', preview_text TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(campaign_id, wave_id)
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS contact_lists (
        id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, niche TEXT NOT NULL DEFAULT '',
        region TEXT NOT NULL DEFAULT '', qualification TEXT NOT NULL DEFAULT 'qualified',
        source TEXT NOT NULL DEFAULT 'manual', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
      await pool.query(`CREATE TABLE IF NOT EXISTS contact_list_members (
        list_id BIGINT REFERENCES contact_lists(id) ON DELETE CASCADE,
        contact_id BIGINT REFERENCES contacts(id) ON DELETE CASCADE,
        PRIMARY KEY(list_id,contact_id)
      )`);
      await pool.query(`ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS contact_list_id BIGINT REFERENCES contact_lists(id) ON DELETE SET NULL`);
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
  try { const result = await pool.query(`SELECT c.id,c.name,c.subject,c.brief,c.source_references,c.status,c.audience_label,c.sender_name,c.sender_email,c.created_at,COALESCE(SUM(w.recipient_count),0)::int AS recipients,COUNT(w.id)::int AS waves,MIN(w.scheduled_at) AS next_send FROM campaigns c LEFT JOIN campaign_waves w ON w.campaign_id=c.id GROUP BY c.id ORDER BY c.created_at DESC`); res.json({ campaigns: result.rows }); } catch (error) { next(error); }
});

app.get("/api/contact-lists", requireServiceKey, requireDatabase, async (_req, res, next) => {
  try { const result=await pool.query(`SELECT l.*,COUNT(m.contact_id)::int AS contacts FROM contact_lists l LEFT JOIN contact_list_members m ON m.list_id=l.id GROUP BY l.id ORDER BY l.created_at DESC`); res.json({lists:result.rows}); } catch(error){next(error);}
});
app.post("/api/contact-lists", requireServiceKey, requireDatabase, async (req,res,next)=>{
  const {name,niche="",region="",qualification="qualified",source="manual",contactIds=[]}=req.body||{};
  if(!name?.trim()) return res.status(400).json({error:"O nome da lista é obrigatório"});
  try { const list=(await pool.query(`INSERT INTO contact_lists(name,niche,region,qualification,source) VALUES($1,$2,$3,$4,$5) RETURNING *`,[name.trim(),niche,region,qualification,source])).rows[0];
    for(const id of Array.isArray(contactIds)?contactIds:[]) await pool.query(`INSERT INTO contact_list_members(list_id,contact_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,[list.id,id]);
    res.status(201).json({list}); }catch(error){next(error);}
});

app.post("/api/campaigns", requireServiceKey, requireDatabase, async (req, res, next) => {
  const { name, brief = "", sourceReferences = [], senderName = "Grupo ABR", senderEmail = process.env.MICROSOFT_SENDER_EMAIL || "", contactListId, waves = 1, firstSendAt } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: "O nome da campanha é obrigatório" });
  if (!contactListId) return res.status(400).json({ error: "Selecione a lista de contatos destinatária" });
  try {
    const list=await pool.query(`SELECT name FROM contact_lists WHERE id=$1`,[contactListId]); if(!list.rowCount) return res.status(400).json({error:"Lista não encontrada"});
    const contactCount = number((await pool.query(`SELECT COUNT(*) FROM contact_list_members m JOIN contacts c ON c.id=m.contact_id WHERE m.list_id=$1 AND c.status='valid' AND c.subscribed`,[contactListId])).rows[0].count);
    const campaign = await pool.query(`INSERT INTO campaigns(name,subject,brief,source_references,html_content,sender_name,sender_email,audience_label,contact_list_id,status) VALUES($1,'',$2,$3,'',$4,$5,$6,$7,'draft') RETURNING *`, [name.trim(), String(brief), JSON.stringify(Array.isArray(sourceReferences) ? sourceReferences : []), senderName, senderEmail, list.rows[0].name,contactListId]);
    const totalWaves = Math.min(10, Math.max(1, Number(waves) || 1));
    for (let index = 0; index < totalWaves; index += 1) {
      const scheduled = firstSendAt ? new Date(new Date(firstSendAt).getTime() + index * 24 * 60 * 60 * 1000) : null;
      await pool.query(`INSERT INTO campaign_waves(campaign_id,wave_order,scheduled_at,recipient_count,status) VALUES($1,$2,$3,$4,'draft')`, [campaign.rows[0].id, index + 1, scheduled, Math.ceil(contactCount / totalWaves)]);
    }
    res.status(201).json({ campaign: campaign.rows[0] });
  } catch (error) { next(error); }
});

app.get("/api/campaigns/:id/waves", requireServiceKey, requireDatabase, async (req, res, next) => {
  try {
    const result = await pool.query(`SELECT w.id,w.wave_order,w.scheduled_at,w.recipient_count,w.status,e.id AS email_id,e.subject,e.html_content,e.preview_text,e.status AS email_status FROM campaign_waves w LEFT JOIN campaign_emails e ON e.wave_id=w.id WHERE w.campaign_id=$1 ORDER BY w.wave_order`, [req.params.id]);
    res.json({ waves: result.rows });
  } catch (error) { next(error); }
});

app.post("/api/campaigns/:id/waves/:waveId/email", requireServiceKey, requireDatabase, async (req, res, next) => {
  const { subject, htmlContent = "", previewText = "" } = req.body || {};
  if (!subject?.trim()) return res.status(400).json({ error: "O assunto do e-mail é obrigatório" });
  if (/<script[\s>]/i.test(htmlContent)) return res.status(400).json({ error: "JavaScript não é permitido em e-mails. Use somente HTML e CSS compatíveis." });
  try {
    const wave = await pool.query(`SELECT id FROM campaign_waves WHERE id=$1 AND campaign_id=$2`, [req.params.waveId, req.params.id]);
    if (!wave.rowCount) return res.status(404).json({ error: "Onda não encontrada" });
    const saved = await pool.query(`INSERT INTO campaign_emails(campaign_id,wave_id,subject,html_content,preview_text,status) VALUES($1,$2,$3,$4,$5,'ready') ON CONFLICT(campaign_id,wave_id) DO UPDATE SET subject=EXCLUDED.subject,html_content=EXCLUDED.html_content,preview_text=EXCLUDED.preview_text,status='ready',updated_at=NOW() RETURNING *`, [req.params.id, req.params.waveId, subject.trim(), htmlContent, previewText]);
    res.status(201).json({ email: saved.rows[0] });
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
