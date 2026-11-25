# SentinelMesh

**Secure the connection. Contain the compromise.**

A security control-plane foundation for hybrid infrastructure (private
datacenter + AWS + Kubernetes): multi-tenant RBAC, a real policy engine, and
a real AWS discovery integration, all backed by PostgreSQL — no mock data
disguised as live infrastructure.

## What's real vs. what's scaffolded

This is a genuine foundation, not the full 60-section spec built out — that
is realistically weeks of work for a team. Built and working in this pass:

| Area | Status |
|---|---|
| Auth (Argon2id credentials, DB sessions, NextAuth) | ✅ Real |
| Multi-tenant RBAC, enforced server-side on every route | ✅ Real |
| Prisma schema (full data model from the spec) | ✅ Real |
| AWS integration: STS AssumeRole, VPC/Subnet/SecurityGroup discovery | ✅ Real (needs your AWS role) |
| Policy engine: CRUD + deterministic validation rules | ✅ Real |
| Dashboard metrics | ✅ Real (COUNT() against the DB, honest zero-state) |
| Audit logging | ✅ Real, wired into the routes above |
| Secret encryption (AES-256-GCM envelope) | ✅ Real |
| IAM discovery/risk analysis | 🟡 DB model + risk logic done; API route not yet wired — same pattern as `/api/aws/vpcs`, straightforward to add |
| Kubernetes integration | 🟡 DB model only. Needs `@kubernetes/client-node` wiring following the same pattern as `src/server/aws/` |
| Datacenter connector protocol | 🟡 DB model + `NOT_CONNECTED` status only. No agent binary or heartbeat endpoint yet |
| Incident correlation engine | 🟡 DB model only, no rule engine yet |
| Drift detection | 🟡 Dashboard reports it as 0 honestly; no background job yet |
| Topology graph service | ❌ Not built |
| Background job runner (BullMQ/Redis) | ❌ Redis is wired for future use; no workers yet |
| Frontend pages beyond API + login | ❌ Only `/login` scaffolded; dashboard/network/etc. pages not built |
| Test suite | ❌ Not written |

Nothing above pretends to be more than it is: every status in the app comes
from a real DB query or a real external API call, and failures are reported
as failures.

## Architecture

```
Browser
  ↓ HTTPS
Next.js (App Router) — UI + API routes
  ↓
RBAC layer (src/server/rbac) — resolves org membership from the
  authenticated session only, never from client-supplied IDs
  ↓
Service layer (src/server/aws, src/server/policy, src/server/audit)
  ↓
Prisma → PostgreSQL
  ↓
AWS SDK (STS/EC2/IAM) — real calls, real errors
```

## Local setup

```bash
cp .env.example .env
# fill in AUTH_SECRET and ENCRYPTION_KEY (see comments in .env.example)

docker compose up -d postgres redis
npm install
npm run prisma:migrate:dev
SEED_ADMIN_PASSWORD='choose-a-strong-password' npm run seed
npm run dev
```

Log in at `http://localhost:3000/login` with the seeded admin email/password.

## Database

PostgreSQL via Prisma. Schema: `prisma/schema.prisma`. Migrations:

```bash
npm run prisma:migrate         # apply migrations (production)
npm run prisma:migrate:dev     # create + apply a new migration (dev)
```

## Environment variables

See `.env.example` for the full list and generation commands. Never commit
a filled-in `.env`.

## AWS integration

1. In the target AWS account, create two IAM roles SentinelMesh can assume:
   - **Discovery role** — read-only: `ec2:Describe*`, `iam:List*`, `iam:Get*`
   - **Enforcement role** (optional, only if you want SentinelMesh to apply
     security-group changes) — adds `ec2:AuthorizeSecurityGroupIngress`,
     `ec2:RevokeSecurityGroupIngress`, scoped with a condition key to your
     managed VPCs
2. Trust policy: allow the principal SentinelMesh runs as (an AWS-hosted
   task role, or the "trust broker" IAM user whose access key you store) to
   `sts:AssumeRole`.
3. Create a CloudAccount row (via `/integrations` once that UI is built, or
   directly via Prisma Studio for now) with `roleArn` set, and store the
   trust-broker access key through `IntegrationCredential` (encrypted with
   `ENCRYPTION_KEY` — see `src/lib/crypto.ts`).
4. `POST /api/aws/vpcs` with `{ organizationId, cloudAccountId }` to run
   discovery. On failure you get the real AWS error message and the account
   is marked `ERROR`, never `CONNECTED`.

## Kubernetes integration

Not yet wired. To add it: install `@kubernetes/client-node`, mirror
`src/server/aws/client.ts` + `discovery.ts` using a securely-stored
kubeconfig or in-cluster service account token, and never expose that token
to the frontend.

## Datacenter connector

Not yet built. The DB model (`DatacenterConnector`) and status field exist
so the dashboard can honestly report `NOT_CONNECTED` until a real connector
agent and heartbeat/auth endpoint are implemented.

## Production deployment

1. Provision PostgreSQL and Redis (managed services recommended).
2. Set all variables from `.env.example` via your platform's secret
   manager — never bake them into the image.
3. `docker build -t sentinelmesh .`
4. Run `npx prisma migrate deploy` against production DB before first boot.
5. Deploy behind HTTPS (reverse proxy / platform-managed TLS).
6. Run the seed script once, with a strong `SEED_ADMIN_PASSWORD`, then
   rotate that password and disable the seed script in CI.

## Security considerations

- Passwords hashed with Argon2id; never stored or logged in plaintext.
- Integration credentials envelope-encrypted (AES-256-GCM) before storage
  and only decrypted server-side, in-memory, for the duration of an AWS call.
- Every API route resolves org access from the authenticated session's
  `Membership` row — a client-supplied `organizationId` alone grants nothing.
- Every mutating route writes to `AuditLog` with actor, before/after, and
  result.
- API errors never include stack traces; internal failures return a generic
  message while real external errors (AWS, etc.) are surfaced verbatim so
  operators can act on them.

## Troubleshooting

- **`ENCRYPTION_KEY is not configured`** — generate one with
  `openssl rand -base64 32` and set it before creating any integration
  credential.
- **AWS discovery returns `AWS_ASSUME_ROLE_FAILED`** — check the trust
  policy on the target role and that the broker credentials haven't expired.
- **`/api/health` returns 503** — PostgreSQL is unreachable; check
  `DATABASE_URL` and that the container/service is running.
