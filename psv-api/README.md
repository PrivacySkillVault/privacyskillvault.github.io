# Privacy Skill Vault API

This directory is a separate Vercel project root. It does not change the MkDocs/GitHub Pages website deployment.

## Current endpoint

- `GET /api/health` — deployment health and boolean integration-configuration indicators.
- `OPTIONS /api/health` — CORS preflight for the PSV production origins.

The health response never returns credential values. A provider is marked configured only when its server-side environment variable exists.

## Local verification

Requires Node.js 20 or later:

```bash
npm test
```

## Vercel project setup

Create/link the Vercel project to this repository with **Root Directory = `psv-api`**. The project should use the Hobby team's single function region configured in `vercel.json` (`bom1`).

After deployment, verify:

```bash
curl -i https://<deployment-host>/api/health
```

Expected: HTTP 200, `Cache-Control: no-store`, and a JSON payload with `status: "ok"`.

## Integration security requirements

Do not add provider keys to browser JavaScript, MkDocs files, GitHub commits, issue comments, or chat messages. Add them only as encrypted Vercel environment variables after confirming provider account access and terms.

Provider adapters are intentionally not exposed yet. Before enabling public lookup or submission routes, implement distributed rate limiting/abuse controls, strict input validation, provider-specific timeouts and response limits, safe error handling, and audit logging that excludes credentials and sensitive submitted data. CORS is not authentication.

Sandbox submissions (URLScan, ANY.RUN, Hybrid Analysis) must require an explicit user confirmation because submitted URLs/files may be shared with third parties. VirusTotal use must be checked against the account's license and current service terms before activation.

## Secure Share

The earlier prototype credential must be revoked and replaced. Do not restore client-side provider credentials or the previous non-atomic read-then-delete flow. A production one-time share service needs encrypted-payload-only storage, atomic consume/delete semantics, expiry, payload limits, distributed rate limiting, and careful handling of link fragments and logs. It is not enabled by this foundation deployment.
