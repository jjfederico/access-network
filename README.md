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
applicable subscription. Admission is automatic. Denial or termination is
only for stated cause (license lapse, non-payment, or material breach).
The criteria are published at `/membership` (`public/membership.html`).

Every admission decision is appended to `pm_admissions` (date, applicant,
criteria checked, license verification result, decision, stated cause for
any denial). Admin-only: `GET /api/pm/admin/admissions` and the Admin →
Admissions log tab.

## Seller authorization

A listing is live (feed, detail, intros, alerts, digest, teaser, stats) only
with the seller-signed Non-MLS / delayed-listing form on file
(`compliance.listingAuthorized`). Every path that can set a listing active —
post, edit, relist, renew, undo-MLS, undo-closed, paid renew — enforces it.
Owner-loaded sample data (`sample: true`) is exempt.

Published pricing (honored in code): first 100 members free, then $25/month
for life for those founding members; $50/month after the 100th.

## What you provision

1. GitHub repo → Render web service (`npm install` / `npm start`).
2. Render Postgres → `DATABASE_URL`.
3. Env: `SESSION_SECRET`, `ACCESS_ADMIN`, `BASE_URL`, optional
   `RESEND_API_KEY`, `STRIPE_SECRET_KEY` / price IDs,
   `STRIPE_PRICE_FOUNDING`, `STRIPE_PRICE_STANDARD`.
