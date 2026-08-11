# Email Bomber — API

Backend do sistema de campanhas de e-mail em ondas do Grupo ABR.

## Fluxo principal

1. A Prospecção pesquisa empresas por nicho e região em lotes de até cinco contatos.
2. Somente contatos corporativos com página pública de origem são validados.
3. A pesquisa encerra criando uma lista qualificada permanente.
4. A campanha exige a seleção de uma lista destinatária.
5. Cada onda possui assunto, conteúdo, agenda e regra de automação próprios.

## Integrações

- Neon/Postgres: persistência.
- Groq (`openai/gpt-oss-120b` por padrão): pesquisa e qualificação em lotes com orçamento reduzido.
- Gemini (`gemini-3.6-flash` por padrão): pesquisa com Google Search e continuidade automática quando a Groq atinge o limite.
- Microsoft 365 OAuth/Graph: envio, assinatura e caixa de entrada por usuário.
- SMTP: alternativa individual de envio para outros provedores.

## Variáveis

`DATABASE_URL`, `API_ACCESS_KEY`, `SESSION_SECRET`, `ADMIN_ACCOUNTS_JSON`, `GROQ_API_KEY`,
`GROQ_PROSPECTION_MODEL`, `GEMINI_API_KEY`, `GEMINI_PROSPECTION_MODEL`,
`FRONTEND_URL`, `MICROSOFT_TENANT_ID`,
`MICROSOFT_CLIENT_ID` e `MICROSOFT_CLIENT_SECRET`.
