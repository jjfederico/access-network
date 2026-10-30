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
any denial). A sign-up that is missing a valid license number or the
certification is logged as `incomplete` (not a denial) with what is missing.
Admin-only: `GET /api/pm/admin/admissions` and the Admin →
Admissions log tab.

## Seller authorization

A listing is live (feed, detail, intros, alerts, digest, teaser, stats) only
with the seller-signed Non-MLS / delayed-listing form on file
(`compliance.listingAuthorized`). Every path that can set a listing active —
post, edit, relist, renew, undo-MLS, undo-closed, paid renew — enforces it.
Owner-loaded sample data (`sample: true`) is exempt. A newly submitted form is
validated after sanitizing (`compliance.cleanSellerForm`): it must be an upload
key issued by `/api/pm/upload` or an inline PDF/image/Word data URL; anything
else is refused with `seller_form_invalid`.

Tests: `npm test` (unit + copy audit in `test/compliance.test.js`; route tests in
`test/routes.test.js` run `server.js` against in-memory stubs — no database,
network, or email; `test/demo.test.js` covers demo gates, seed fixtures,
partition isolation, public counters, and that demo sends no email and makes
no Stripe call). Shared stubs live in `test/server-harness.js`.

Published pricing (honored in code): every membership starts with a 14-day
free trial; then $25/month for life for the first 100 members (founding rate)
and $50/month after the 100th. The trial clock starts at join or when billing
is first switched on (`billingStartedAt`), whichever is later.

## Demo mode (audit/testing workspace)

An isolated copy of the member app with five fake accounts (Demo Agent 1–5),
six DEMO listings and three DEMO client needs. Nothing is linked publicly and
it is `noindex` + excluded in `robots.txt`.

- **Enter:** signed in as an admin, open `/demo-mode`; or anyone with the code
  opens `/demo-mode?code=<DEMO_ACCESS_CODE>`. Without one of those it is a 404.
- **Use:** pick an account; the gold DEMO bar in the app switches accounts,
  signs out (back to the picker) and exits. The seller-form step has a
  "Use DEMO placeholder form" button.
- **Reset:** admins see "Reset demo data" on `/demo-mode`.
- **Off switch:** `DEMO_MODE=off` removes demo mode entirely.

Isolation: demo requests run in an AsyncLocalStorage context and `db.js`
stores every list under `demo:<key>` (`lib/demo.js`). Public counters, the
teaser, real sign-up and real sign-in always use real data. Demo sends no
email, uploads stay inline (never R2), and checkout, portal, resume and
payment confirmation are refused without calling Stripe.

## What you provision

1. GitHub repo → Render web service (`npm install` / `npm start`).
2. Render Postgres → `DATABASE_URL`.
3. Env: `SESSION_SECRET`, `ACCESS_ADMIN`, `BASE_URL`, optional
   `RESEND_API_KEY`, `STRIPE_SECRET_KEY` / price IDs,
   `STRIPE_PRICE_FOUNDING`, `STRIPE_PRICE_STANDARD`, `STRIPE_WEBHOOK_SECRET`,
   optional `DEMO_ACCESS_CODE` (demo link code) and `DEMO_MODE=off`.
