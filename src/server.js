import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import pg from "pg";

const app = express();
const port = Number(process.env.PORT || 3000);
const startedAt = new Date().toISOString();

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || true, credentials: true }));
app.use(express.json({ limit: "2mb" }));

const pool = process.env.DATABASE_URL
  ? new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false })
  : null;

app.get("/", (_req, res) => res.json({ service: "ABR Ondas API", status: "online", version: "0.1.0" }));

app.get("/health", async (_req, res) => {
  let database = "not_configured";
  if (pool) {
    try {
      await pool.query("select 1");
      database = "connected";
    } catch {
      database = "unavailable";
    }
  }
  res.status(database === "unavailable" ? 503 : 200).json({ status: "ok", database, startedAt });
});

app.get("/api/config/status", (_req, res) => {
  res.json({
    database: Boolean(process.env.DATABASE_URL),
    microsoftTenant: Boolean(process.env.MICROSOFT_TENANT_ID),
    microsoftClient: Boolean(process.env.MICROSOFT_CLIENT_ID),
    microsoftSecret: Boolean(process.env.MICROSOFT_CLIENT_SECRET),
    sender: process.env.MICROSOFT_SENDER_EMAIL || null,
  });
});

app.use((_req, res) => res.status(404).json({ error: "Rota não encontrada" }));

app.listen(port, "0.0.0.0", () => console.log(`ABR Ondas API ouvindo na porta ${port}`));
