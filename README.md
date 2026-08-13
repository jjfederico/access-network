# ACCESS — standalone

Invite-only, agent-to-agent, off-market **investment** deal network. Runs on its
own — separate repo, separate Render service, separate Postgres database — so
customer data never mixes with the Grove hub or personal tools.

## Architecture

- `server.js` — Express app, marketplace routes (`/api/pm/*`).
- `db.js` — Postgres data layer. Every list (`pm_listings`, `pm_intros`,
  `pm_buyboxes`, `pm_members`, …) is one row in `pm_store(k, v jsonb)`.
  `pmLoad(key)` / `pmSave(key, arr)` — same contract the hub used, now durable.
- `auth.js` — email magic-link sign-in (works for agents at any brokerage).
  Admin is whoever's email is set in `ACCESS_ADMIN`.
- `public/index.html` — the landing page. `public/app.html` — the members app.

## What you provision (one-time)

1. **GitHub repo** — new, e.g. `access-network`. Push this folder to it.
2. **Render Postgres** — New + → Postgres, name `access-db`, same region as the
   web service, cheapest plan. Copy its **Internal Database URL**.
3. **Render Web Service** — New + → Web Service → this repo.
   - Build command: `npm install`
   - Start command: `npm start`
   - Environment variables:
     - `DATABASE_URL` = the Postgres Internal URL from step 2
     - `SESSION_SECRET` = any long random string
     - `ACCESS_ADMIN` = your email (makes you the admin/owner)
     - `BASE_URL` = the service's public URL (e.g. `https://access.yourdomain.com`)
     - `NODE_ENV` = `production`
     - `RESEND_API_KEY` = *(optional)* a [Resend](https://resend.com) API key for
       real sign-in emails. Without it, sign-in links are printed to the server
       logs (fine for testing).
     - `ACCESS_FROM` = *(optional)* the from-address, e.g. `ACCESS <login@yourdomain.com>`
4. **Domain** — point your ACCESS domain at the Render service (Render → Settings
   → Custom Domain), then set `BASE_URL` to match.

## Moving your existing ACCESS data over

The old data lives in the hub's ACCESS sheet. Export it from the hub
(`/api/pm/migrate`, owner-only) as a `{ pm_listings:[…], pm_intros:[…], … }`
JSON map, then POST it once to `/api/pm/import` while signed in as admin. It
writes every list into Postgres in a single transaction. Safe to re-run.

## Status

**Complete and tested end-to-end on real Postgres:** the full `/api/pm/*`
marketplace is ported —

- Feed, listing create/edit/delete, Moved-to-MLS, featuring
- Intros (request / approve / decline / address reveal), entitlement redaction
- Buy-boxes + two-way matching, notifications, market pulse, broadcasts
- Member-to-member messaging (threads)
- Views + per-deal seller analytics, 30-day renewals
- Profiles + socials, member directory
- Public join requests + admin approvals + referral credits
- Network stats (public), sample-data loader
- Stripe checkout (renew / feature / membership) — gated on `STRIPE_SECRET_KEY`
- Document upload (small files inline; swap for S3/R2 later)
- Self-scheduled renewal-reminder sweep

Verified: boots clean, magic-link login, seeds 14 deals / 10 members, feed +
directory + stats correct, import works, and **data survives a full restart**.

**Still to layer on (product hardening):** object storage for large docs,
license-verified badge automation, captcha on the public join form, and a Stripe
webhook (today confirmation is on return-from-checkout).
