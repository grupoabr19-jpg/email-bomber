# ABR Ondas API

Backend do sistema de campanhas de e-mail em ondas do Grupo ABR.

## Implantação no Render

O arquivo `render.yaml` cria:

- um Web Service Node chamado `abr-ondas-api`;
- um PostgreSQL chamado `abr-ondas-db`;
- a conexão automática entre o serviço e o banco;
- campos protegidos para as credenciais Microsoft 365.

No Render, use **New > Blueprint**, conecte este repositório e confirme os recursos. Os campos `MICROSOFT_TENANT_ID`, `MICROSOFT_CLIENT_ID` e `MICROSOFT_CLIENT_SECRET` serão solicitados durante a criação.

## Rotas iniciais

- `GET /` — identificação do serviço;
- `GET /health` — saúde da API e conexão com o banco;
- `GET /api/config/status` — informa apenas quais integrações estão configuradas, sem revelar segredos.
