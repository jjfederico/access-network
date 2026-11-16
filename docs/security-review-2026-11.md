# AXESS internal security review — November 2026

Scope: the live app in this repo (server.js, auth.js, db.js, lib/, public/).
Method: code review plus attack tests run against the app in a browser.
This is not a substitute for an independent penetration test (see the end).

## Tested and passing

| Area | What was tested | Result |
|---|---|---|
| Stored XSS | An attacker member filled every text field (profile, listing, address, documents, seller form name, client need, intro note, messages, sign-up fields) with script/HTML payloads; a second member and the admin opened every view (feed, detail, activity tabs, needs board, deal room, notifications, directory, profile, all admin tabs, insights). | 0 of 14 views executed anything; payloads render as text |
| Access control | Every owner-only endpoint (23) called as a normal member and signed out. | All refused (401/403/404, or redirect for /insights) |
| Security policy (CSP) | Enforced CSP across 14 pages at 390px and 1280px, with Google Maps and Google sign-in really loading; a planted off-list script. | 28/28 clean; planted script blocked and reported to Admin → Security |
| Dependencies | `npm audit` | 0 vulnerabilities |
| Error leakage | Server responses | No internal error text reaches the browser (68 sites fixed) |
| Request size | 2 MB anonymous JSON | Rejected (413); 25 MB only on file routes |
| CSV export | Member name `=HYPERLINK(...)` | Neutralized (prefixed with ') |
| Demo isolation | Demo session vs. real data, counters, email, billing | Isolated (see README) |

## Design notes

- Sign-in is an emailed one-time link (30 min, single use) or Google ID token
  (audience + email_verified checked). Admin = addresses in `ACCESS_ADMIN`;
  admin security therefore equals the security of those mailboxes — keep
  two-step verification on.
- Sessions: signed cookie, httpOnly, SameSite=Lax, Secure in production,
  90 days.
- Rate limits are in-memory per instance (sign-up, sign-in email, contact,
  uploads, intros, messages, CSP reports).
- Uploads: allow-listed MIME types, size-capped, stored in private R2 and
  served through permission-checked short-lived signed URLs.
- Stripe webhook verifies signatures; billing endpoints refuse demo sessions.

## Known limits / follow-ups

- `'unsafe-inline'` remains in the CSP (the UI uses inline handlers); the CSP
  still restricts where scripts load from and where data can be sent.
- Rate limits reset on restart and are per instance.
- No account lockout or audit log beyond the admissions log.

## Brief for an independent penetration test (before charging money)

Target: https://axessre.com (production) or a staging copy (`STAGING=1`).
In scope: sign-up/sign-in (magic link, Google), member API `/api/pm/*`,
admin API, file upload/download, demo mode gate (`/demo-mode`), Stripe
webhook. Provide two member test accounts and one admin. Ask for: OWASP Top
10 web testing, authorization (horizontal/vertical) testing, session handling,
upload abuse, and business-logic abuse (fake listings, intro/address unlock,
seller-form bypass). Deliverable: findings with severity and reproduction.
