# AXESS

A Massachusetts-only network for licensed real estate agents to share
seller-directed, pre-market property with one another. Flat monthly
subscription. AXESS is not an MLS, not a brokerage, and does not take a
cut of any transaction.

Express serves **only `public/`**. Root HTML outside `public/` is not live.

## Architecture

- `server.js` — Express app, network routes (`/api/pm/*`), static `public/`.
- `db.js` — Postgres data layer. Every list (`pm_listings`, `pm_intros`,
  `pm_buyboxes`, `pm_members`, …) is one row in `pm_store(k, v jsonb)`.
- `auth.js` — email magic-link sign-in. Admin is `ACCESS_ADMIN`.
- `lib/compliance.js` — shared Massachusetts / compensation / membership helpers.
- `public/index.html` — landing. `public/app.html` — members app.
  `public/terms.html` / `public/privacy.html` — live legal pages.

## Membership

Open to every applicant who (a) holds an active Massachusetts salesperson
or broker license in good standing, (b) is affiliated with a licensed
Massachusetts brokerage, (c) agrees to the Terms, and (d) pays the
applicable subscription. Admission is automatic. Termination is only for
stated cause (license lapse, non-payment, or material breach).

Published pricing (honored in code): first 100 members free, then $25/month
for life for those founding members; $50/month after the 100th.

## What you provision

1. GitHub repo → Render web service (`npm install` / `npm start`).
2. Render Postgres → `DATABASE_URL`.
3. Env: `SESSION_SECRET`, `ACCESS_ADMIN`, `BASE_URL`, optional
   `RESEND_API_KEY`, `STRIPE_SECRET_KEY` / price IDs,
   `STRIPE_PRICE_FOUNDING`, `STRIPE_PRICE_STANDARD`.
