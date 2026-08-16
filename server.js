import express from "express";
import cookieSession from "cookie-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import * as gdb from "./grove-db.js";   // Postgres data layer (gated on DATABASE_URL; read-through + dual-write)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const {
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL = "http://localhost:3000",
  SESSION_SECRET = "", OWNER_EMAILS = "", AGENT_EMAILS = "", CITICORE_GUEST_EMAILS = "",
  SUMMIT_EMAILS = "", BOOKKEEPER_EMAILS = "",
  SHEET_CSV_URL = "", PROBATE_CSV_URL = "", PORT = 3000,
  GEMINI_API_KEY = "", GEMINI_MODEL = "gemini-2.5-flash",
  // Per-company Gemini keys so each company's AI usage bills its OWN card. Each key
  // lives in its own Google Cloud billing account (its own card). If a company key
  // is unset, it falls back to GEMINI_API_KEY (Grove's), so nothing breaks before
  // the extra keys are added.
  GEMINI_API_KEY_CITICORE = "", GEMINI_API_KEY_SUMMIT = "", GEMINI_API_KEY_GROVE = ""
} = process.env;
// Resolve which Gemini key (and therefore which company's card) a request bills to.
function geminiKeyFor(co) {
  co = String(co || "").toLowerCase();
  if (co === "citicore" && GEMINI_API_KEY_CITICORE) return GEMINI_API_KEY_CITICORE;
  if (co === "summit" && GEMINI_API_KEY_SUMMIT) return GEMINI_API_KEY_SUMMIT;
  if (co === "grove" && GEMINI_API_KEY_GROVE) return GEMINI_API_KEY_GROVE;
  return GEMINI_API_KEY;   // fallback: Grove's shared key
}
function normCo(co) { co = String(co || "").toLowerCase(); return (co === "citicore" || co === "summit" || co === "grove") ? co : "grove"; }
// Session signing key: use the env secret; if unset, generate a strong random key at
// boot (keeps the app up, but logs everyone out on restart — set SESSION_SECRET in the
// environment for persistent sessions). Never fall back to a shipped literal.
const SESSION_KEY = (SESSION_SECRET && SESSION_SECRET !== "dev-secret")
  ? SESSION_SECRET
  : crypto.randomBytes(32).toString("hex");
if (!SESSION_SECRET) console.warn("[boot] SESSION_SECRET not set — using a random per-boot key; set it in env for persistent logins.");

const OWNERS = OWNER_EMAILS.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
const AGENTS = AGENT_EMAILS.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
const GUESTS = CITICORE_GUEST_EMAILS.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
// Summit partners: people outside the brokerage who help with Summit marketing.
// They are NOT agents — no Grove pages, no deals, no money. Set SUMMIT_EMAILS in
// Render. Checked BEFORE the agent list on purpose: if an address ends up on both
// lists by mistake, the person gets the smaller set of tools, not the bigger one.
const PARTNERS = SUMMIT_EMAILS.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
// ── Premarket Hub public product ────────────────────────────────────────────
// When PM_PUBLIC_SIGNUP=1, ANY Google account may log in — but ONLY as a locked
// "member" role scoped to premarket-hub.html + /api/pm/* (blocked from every
// other page, note and endpoint). Kept OFF by default so the hub stays closed
// until a deliberate security check. Members reach content only through the
// /api/pm/* API, which redacts addresses server-side and enforces per-record
// ownership — the raw note store is blocked for members.
const PM_PUBLIC_SIGNUP = process.env.PM_PUBLIC_SIGNUP === '1';
// Bookkeeper: a limited financial login (money read/write, property read-only, no
// Grove/Summit tools). Dormant until BOOKKEEPER_EMAILS is set in the environment.
const BOOKKEEPERS = BOOKKEEPER_EMAILS.split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
// Agents added from the site (Agent Roster page → owner_roster.custom) get an
// agent login WITHOUT a Render change. loadRoster() refreshes this set from that
// owner-only note. Two hard guarantees: it can ONLY ever grant the AGENT role
// (never owner/guest/summit — so a bad note can't escalate anyone), and the four
// env-var lists above are always checked FIRST (so a note can never demote or
// lock out an env-var owner/agent). Only John can write owner_roster, so the
// trust level is the same as the Render list — just editable from the site.
let DYN_AGENTS = new Set();
let DYN_AGENT_NAMES = [];   // display names of roster-added agents (for the agent dropdown)
const roleFor = email => {
  email = (email || "").toLowerCase();
  if (OWNERS.includes(email)) return "owner";
  if (BOOKKEEPERS.includes(email)) return "bookkeeper"; // limited financial login
  if (PARTNERS.includes(email)) return "summit"; // outside Summit-marketing partner
  if (AGENTS.includes(email)) return "agent";
  if (GUESTS.includes(email)) return "guest"; // outside Citicore-only guest
  if (DYN_AGENTS.has(email)) return "agent"; // added on the Agent Roster page
  return null; // not on any list = denied
};

// Maps each agent's login email to the exact name they appear as on a deal split
// (the Deals & Payouts "listing agent" dropdown). Used to scope an agent's Summary to
// only their own deals. Add new agents here as they're onboarded.
const AGENT_DEAL_NAMES = {
  "tyler@gpgboston.com": "TYLER BATES",
  "joe@gpgboston.com": "JOE",
  "rburke@gpgboston.com": "BURKE",
  "ryan@gpgboston.com": "QUINN",
  "marc@gpgboston.com": "WATERFALL",
  "eleni@gpgboston.com": "ELENI",
  "melissa@gpgboston.com": "MELISSA",
  "michelle@gpgboston.com": "MICHELLE",
  "harry@gpgboston.com": "HARRY V.",
  "matt@gpgboston.com": "MATT",
  "guy@gcdinc.us": "GUY",
  "herbert.shaughnessy@gmail.com": "AJ",
  "jfed6745@gmail.com": "COBROKE",
  "bp@linellacapital.com": "BRETT P."
};

// New agents can be added WITHOUT a code change: set AGENT_NAME_MAP in Render to a
// comma-separated list of email:CODE pairs, e.g.
//   dan@gpgboston.com:DAN,corey@gpgboston.com:COREY,zack@gpgboston.com:ZACK
// The CODE must match the spelling used in the Deals & Payouts listing-agent dropdown.
(process.env.AGENT_NAME_MAP || "").split(",").forEach(pair => {
  const i = String(pair).indexOf(":");
  if (i < 1) return;
  const em = pair.slice(0, i).trim().toLowerCase();
  const cd = pair.slice(i + 1).trim().toUpperCase();
  if (em && cd) AGENT_DEAL_NAMES[em] = cd;
});

// The owner isn't on the split-name list above (his deals are booked as "JOHN"). Returning
// "" for him blanked out My Page and made the Pipeline Board think nobody owned any row,
// so owners always resolve to a real name. Override with OWNER_DEAL_NAME in Render.
const OWNER_DEAL_NAME = String(process.env.OWNER_DEAL_NAME || "JOHN").trim().toUpperCase();
const agentDealName = email => {
  const e = (email || "").toLowerCase().trim();
  const hit = AGENT_DEAL_NAMES[e];
  if (hit) return hit;
  if (roleFor(e) === "owner") return OWNER_DEAL_NAME;
  return "";
};

const ACCT_DATA = {
  bank: "JPMorgan Chase",
  accounts: [
    { id:"operating", label:"Grove Operating", mask:"\u20262452", account:"80010922452", routing:"021000021" },
    { id:"escrow", label:"Escrow", mask:"\u20269295", account:"80012299295", routing:"021000021" }
  ],
  citicore: [
    { id:"Citicore", label:"Citicore Properties", mask:"\u20261775", account:"80009201775", routing:"021000021" }
  ],
  summit: [
    { id:"Summit", label:"Summit", mask:"\u20268101", account:"2908318101", routing:"021000021" }
  ]
};
// Account data sent to the browser is scoped by role: owner = all, agent = Grove only, guest = none.
function acctFor(role){
  if (role === "owner") return ACCT_DATA;
  if (role === "agent") return { bank: ACCT_DATA.bank, accounts: ACCT_DATA.accounts, citicore: [], summit: [] };
  if (role === "guest") return { bank: ACCT_DATA.bank, accounts: [], citicore: ACCT_DATA.citicore, summit: [] }; // Citicore user
  if (role === "summit") return { bank: "", accounts: [], citicore: [], summit: [] }; // Summit partner: no account numbers at all
  return { bank: "", accounts: [], citicore: [], summit: [] };
}

passport.serializeUser((u, done) => done(null, u));
passport.deserializeUser((u, done) => done(null, u));
// Google login only registers when both keys are present. If either is missing we
// log a loud warning and boot ANYWAY, so a missing env var can never crash-loop the
// deploy and freeze the whole site on an old build (which looked like "my changes
// won't deploy"). Login stays off until the keys are set in Render → Environment.
// ── Google token refresh ──────────────────────────────────────────────────────
// The bug this fixes: Google hands back BOTH an access token (good for one hour)
// and a refresh token (good until it's revoked). The old code kept only the
// access token — inside a session cookie set to last 30 days. So every Gmail-,
// Sheets- and Tasks-backed page worked for about an hour after a fresh sign-in
// and then answered "could not load" for the next month, because the session
// never expired and nobody was ever forced to log in again. QuickBooks has had a
// full refresh flow for ages (qbRefresh, further down); Google never got one.
//
// Refresh tokens live here, in memory, keyed by email — deliberately NOT on the
// user object, because that object is serialized into the session cookie, and
// cookie-session only SIGNS its payload, it does not encrypt it. A refresh token
// in there would be readable by anyone holding the cookie, and unlike an access
// token it never expires on its own.
//
// A redeploy empties this map. The next Google-backed call then falls back to
// the stale access token, fails, and the page says to sign in again — one click,
// and the map refills. Exactly the trade-off qbTokens already makes.
const googleRefresh = new Map();

// Returns a live access token for the signed-in user, renewing it if the hour is
// up. Never throws: these run inside async express handlers, where a throw is an
// unhandled rejection rather than a clean 500. On failure it returns whatever
// token it has (possibly '') and sets req._reauth, which routes can report.
async function freshToken(req) {
  const u = req.user || {};
  if (u.accessToken && u.tokenExp && Date.now() < u.tokenExp) return u.accessToken;
  const key = String(u.email || '').toLowerCase();
  const rt = googleRefresh.get(key);
  if (!rt) { if (!u.accessToken) req._reauth = true; return u.accessToken || ''; }
  try {
    const r = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=refresh_token'
          + '&refresh_token=' + encodeURIComponent(rt)
          + '&client_id='     + encodeURIComponent(GOOGLE_CLIENT_ID)
          + '&client_secret=' + encodeURIComponent(GOOGLE_CLIENT_SECRET)
    });
    const j = await r.json().catch(() => ({}));
    if (!j.access_token) {
      // Revoked — password change, access removed, or six months idle. Drop it so
      // we stop hammering a dead credential on every single request.
      googleRefresh.delete(key);
      req._reauth = true;
      return u.accessToken || '';
    }
    req.user.accessToken = j.access_token;
    req.user.tokenExp = Date.now() + ((j.expires_in || 3600) - 300) * 1000;
    // Write it back into the session too, so the next request in this session
    // doesn't have to spend another round-trip refreshing.
    if (req.session && req.session.passport && req.session.passport.user) {
      req.session.passport.user.accessToken = req.user.accessToken;
      req.session.passport.user.tokenExp    = req.user.tokenExp;
    }
    return req.user.accessToken;
  } catch (e) { req._reauth = true; return u.accessToken || ''; }
}

// Builds the header object the routes used to write inline as a literal.
// `json` adds the Content-Type the write calls need.
async function gauth(req, json) {
  const h = { Authorization: `Bearer ${await freshToken(req)}` };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

const OAUTH_READY = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
if (OAUTH_READY) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails?.[0]?.value;
    let role = roleFor(email);
    // Not on the env-var lists? They may have just been added on the Agent Roster
    // page. Refresh that owner-only list once and re-check before turning them away,
    // so a newly-added agent can log in immediately without waiting for a redeploy.
    if (!role) { try { await loadRoster(true); } catch (e) {} role = roleFor(email); }
    // Public Premarket sign-up: an unknown Google account becomes a locked "member"
    // (premarket-hub + /api/pm/* only). Everyone else on no list is still denied.
    if (!role && PM_PUBLIC_SIGNUP) role = "member";
    if (!role) return done(null, false);
    // Google only sends a refresh token on a real consent screen (which is why
    // accessType:"offline" + prompt:"consent" are set on the /auth/google route).
    // Stash it server-side; it must never reach the cookie.
    if (refreshToken) googleRefresh.set(String(email || "").toLowerCase(), refreshToken);
    // Access tokens last an hour. Record when this one dies so freshToken() renews
    // it instead of firing a request that's already doomed.
    done(null, { email, name: profile.displayName, role, accessToken, tokenExp: Date.now() + 55 * 60 * 1000 });
  }));
} else {
  console.error("\n*** GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET missing from the environment. ***");
  console.error("*** Server is starting so the deploy succeeds, but Google login is DISABLED  ***");
  console.error("*** until you set both in Render -> Environment -> Save Changes.             ***\n");
}

const app = express();
app.set("trust proxy", 1); // Render terminates HTTPS at a proxy; required for secure session cookies
app.use(cookieSession({
  name: "grove.sid",
  keys: [SESSION_KEY],
  maxAge: 30 * 24 * 3600 * 1000, // 30 days — login persists across server restarts/redeploys
  secure: BASE_URL.startsWith("https"),
  httpOnly: true,
  sameSite: "lax"
}));
// cookie-session has no regenerate()/save(); passport 0.6+ calls them, so provide no-op shims
app.use((req, res, next) => {
  if (req.session && !req.session.regenerate) req.session.regenerate = (cb) => cb();
  if (req.session && !req.session.save) req.session.save = (cb) => cb();
  next();
});
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json({ limit: '25mb' }));   // headroom for For Sale Folder file uploads (base64)

// ── 2026-08-06 · CRITICAL: normalise the URL path before ANY gate reads it ───
// Every gate below (the source-file 404, pageBlockedFor, the .html token
// scrubber) tests req.path with a regex like /\.js$/ or /\.html$/. Express does
// NOT decode req.path — but express.static DOES decode before reading from disk.
// So "/server.j%73" slipped past the source blocker (it doesn't end in ".js")
// and static then happily served server.js — bank account numbers, routing
// number, GROVE_SHEET_TOKEN and all. The same trick opened every owner-only page
// ("/deals-payouts.htm%6C") and skipped stripSheetSecret, handing out the Apps
// Script token that makes the whole permission model moot.
// Decoding once, here, at the very front, closes all of it in one place: from
// this line on every gate sees the same path the filesystem will see.
app.use((req, res, next) => {
  const raw = req.url || '/';
  const q = raw.indexOf('?');
  let p = q >= 0 ? raw.slice(0, q) : raw;
  const rest = q >= 0 ? raw.slice(q) : '';
  // Peel repeatedly: "%256C" decodes to "%6C" decodes to "l". Cap the loop so a
  // hostile path can't spin here.
  for (let i = 0; i < 5 && p.indexOf('%') >= 0; i++) {
    let dec;
    try { dec = decodeURIComponent(p); } catch (e) { return res.status(400).type('txt').send('Bad request'); }
    if (dec === p) break;
    p = dec;
  }
  if (p.indexOf('\0') >= 0 || p.indexOf('\\') >= 0) return res.status(400).type('txt').send('Bad request');
  if (p !== (q >= 0 ? raw.slice(0, q) : raw)) req.url = p + rest;
  next();
});

// Never serve source, config, data, or dotfiles — only pages (.html) and safe web assets
// (images/fonts/css/pdf). Runs FIRST, before auth, so GET /server.js, *.gs, *.json, *.zip,
// *.env, .git/* return a clean 404 for everyone (authed or not) rather than an auth redirect.
app.use((req, res, next) => {
  const p = (req.path || '').toLowerCase();
  const ALLOW = p === '/manifest.json' || p === '/sw.js';   // PWA: these two must be served
  const BLOCKED = /\.(js|mjs|cjs|ts|tsx|jsx|gs|json|lock|zip|tar|gz|env|sh|bash|log|bak|md|yml|yaml|sql|db)$/;
  const dotfile = /(^|\/)\.[^/]+/;               // .git, .env, .DS_Store, etc.
  if (!ALLOW && (BLOCKED.test(p) || dotfile.test(p) || p === '/server.js' || p.includes('grovebackend'))) {
    return res.status(404).type('txt').send('Not found');
  }
  next();
});

const ensureAuth = (req, res, next) => req.isAuthenticated() ? next() : res.redirect("/auth/google");

// Public pages — no login required
app.get("/privacy", (req, res) => res.sendFile(path.join(__dirname, "privacy.html")));
app.get("/privacy.html", (req, res) => res.sendFile(path.join(__dirname, "privacy.html")));
app.get("/terms", (req, res) => res.sendFile(path.join(__dirname, "terms.html")));
app.get("/terms.html", (req, res) => res.sendFile(path.join(__dirname, "terms.html")));
// Reserve — public marketing / membership landing. This is the front door for the
// off-market marketplace: anyone (logged out) can see it, and its CTAs kick off
// Google sign-in. The app itself (premarket-hub.html) stays behind auth + the
// member role gate; only PM_PUBLIC_SIGNUP decides whether a new Google account
// actually becomes a member on the far side of login.
// ACCESS brand assets (logo, favicon, og-image) — public so the marketing page
// renders for logged-out visitors. Static, no secrets.
app.use("/brand", express.static(path.join(__dirname, "brand")));
// ACCESS landing hero video(s) — public, served from the repo root where they were
// uploaded (the root static mount is behind login, so map the public paths straight to
// the files). Supports a playlist: hero.mp4, hero2.mp4, hero3.mp4 … all rotate on the
// landing. Missing numbers just 404 and the player skips them.
app.get(/^\/(?:brand\/)?hero(\d*)\.mp4$/, (req, res) => {
  const n = String(req.params[0] || '');
  const file = 'hero' + (n && n !== '1' ? n : '') + '.mp4';   // /hero.mp4 & /hero1.mp4 → hero.mp4
  res.sendFile(path.join(__dirname, file), err => { if (err && !res.headersSent) res.status(404).end(); });
});
// ACCESS — public marketing / membership landing (was "Reserve"). /reserve kept as an alias.
app.get(["/doors", "/doors.html", "/reserve", "/reserve.html"], (req, res) => res.sendFile(path.join(__dirname, "doors.html")));
app.get("/join", (req, res) => res.redirect("/auth/google"));

// --- auth routes ---
app.get("/auth/google", (req, res, next) => {
  if (!OAUTH_READY) return res.status(503).send("Google login isn't configured yet — GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are missing in Render. Set them in Render → Environment → Save Changes and this will work.");
  next();
}, passport.authenticate("google", {
  scope: ["profile", "email", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/tasks"],
  accessType: "offline", prompt: "consent select_account"
}));
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/denied" }),
  // Public Reserve members can't open the hub home — send them straight into the
  // one page they're allowed. Everyone else lands on the hub as before.
  (req, res) => res.redirect(req.user && req.user.role === "member" ? "/premarket-hub.html" : "/"));
app.get("/denied", (req, res) =>
  res.status(403).send('This Google account isn\'t approved yet. If you\'re joining Reserve, start at <a href="/reserve">/reserve</a> — otherwise ask John to add you.'));
app.get("/logout", (req, res) => req.logout(() => { req.session = null; res.redirect("/auth/google"); }));

// ── Summit partners: what the server lets them near ──────────────────────────
// A Summit partner runs the Summit side: acquisitions, the trackers, the
// underwriters and the Studio — everything except the money. Rather
// than remember to add a role check to forty separate route handlers (and get
// one wrong), this one gate names the only API paths they may touch. Everything
// else under /api/ answers 403 for them, including routes added later — so the
// safe thing happens by default and opening a new tool up to them has to be a
// deliberate edit to this list. Pages are handled separately, by pageBlockedFor.
// Money stays shut: no /api/deals, no /api/deposits, no QuickBooks, no
// bookkeeping sheet, no bank or account numbers — those routes aren't named
// here, so they 403 by default, and so does any route added later.
const SUMMIT_API_OK = [
  /^\/api\/me$/i,                        // who am I
  /^\/api\/grove$/i,                     // sheet proxy — narrowed to notes below
  /^\/api\/summit$/i,                    // Summit sheet — narrowed to crm/queue below
  /^\/api\/lead-list(\/(status|health))?$/i,  // the shared probate / pre-foreclosure list
  /^\/api\/uw(\/item)?$/i,               // the underwriters' saved scenarios
  /^\/api\/ai\/(rewrite|extract)$/i      // the caption + parse helpers
];
app.use((req, res, next) => {
  if (!req.user || req.user.role !== 'summit') return next();
  if (!/^\/api\//i.test(req.path || '')) return next();
  if (SUMMIT_API_OK.some(re => re.test(req.path))) return next();
  return res.status(403).json({ ok: false, error: 'forbidden' });
});

// --- API ---
app.get("/api/me", ensureAuth, (req, res) =>
  res.json({ email: req.user.email, name: req.user.name, role: req.user.role, agentName: agentDealName(req.user.email) }));

// Server-side deal redaction: owner = all; agent = only their own deals with only their
// own split line; guest = none. Used by /api/deals AND the /api/grove dealsLoad proxy so
// an agent can never pull the full unredacted deal set from either path.
function redactDeals(deals, user) {
  deals = Array.isArray(deals) ? deals : [];
  if (user.role === "owner") return deals;
  if (user.role === "agent") {
    const name = agentDealName(user.email).toUpperCase();
    const uname = (user.name || "").toUpperCase().trim();
    const email = (user.email || "").toLowerCase().trim();
    const hit = s => { s = String(s || "").trim(); return (!!name && s.toUpperCase() === name) || (!!uname && s.toUpperCase() === uname) || (!!email && s.toLowerCase() === email); };
    return deals
      .filter(d => hit(d.submittedBy) || (d.lines || []).some(l => hit(l.agent)))
      .map(d => Object.assign({}, d, { lines: (d.lines || []).filter(l => hit(l.agent)) }));
  }
  return []; // guest and Summit partner: no deals, ever
}
// ── Deal file attachments (stored in a separate DealFiles tab, keyed by DealID) ──
// Loaded once and cached briefly so the deal pages don't each trigger a fresh read.
// Fail-safe: on any error we keep the last good map rather than dropping paperclips.
let DEALFILES = {};        // dealId -> [ {name,url,view,id,size,by,at} ]
let DEALFILES_AT = 0;
// Backend actions that back the attachments feature but must NEVER be reachable by a
// client through the /api/grove proxy — otherwise any signed-in agent could call
// dealFilesLoad and pull EVERY deal's file list, or dealUpload junk into Drive. The
// browser only ever calls dealAttach/dealDetach, which are handled server-side (with an
// ownership check) and reach these actions on the backend directly, never via the proxy.
const INTERNAL_GROVE_ACTIONS = new Set(['dealFilesLoad', 'dealFileAdd', 'dealFileDel', 'dealUpload']);
async function loadDealFiles(force) {
  const now = Date.now();
  if (!force && DEALFILES_AT && (now - DEALFILES_AT) < 15000) return DEALFILES;
  try {
    const url = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL)
      + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN) + '&action=dealFilesLoad';
    const j = await fetch(url).then(r => r.json());
    const map = {};
    ((j && j.files) || []).forEach(f => {
      const k = String((f && f.dealId) || '').trim(); if (!k) return;
      (map[k] = map[k] || []).push({
        name: f.name || 'file', url: f.url || '', view: f.view || f.url || '',
        id: f.fileId || f.id || '', size: Number(f.size) || 0, by: f.by || '', at: f.at || ''
      });
    });
    DEALFILES = map; DEALFILES_AT = now;
  } catch (e) { /* keep last good map */ }
  return DEALFILES;
}
// Attach the file list to each deal by its DealID (falls back to the legacy id).
function withAttachments(deals, map) {
  if (!Array.isArray(deals)) return deals;
  map = map || {};
  return deals.map(d => {
    const k = String((d && (d.dealId || d.id)) || '');
    return Object.assign({}, d, { attachments: map[k] || [] });
  });
}
// Deals, filtered server-side so an agent's browser only ever receives THEIR OWN deals.
// The hub loads deals from here instead of hitting the sheet directly. Owner = all; agent =
// only deals where a split line / submittedBy matches their name/email; guest = none.
app.get("/api/deals", ensureAuth, async (req, res) => {
  const SU = process.env.GROVE_SHEET_URL || "https://script.google.com/macros/s/AKfycbxLpHZlNw9yNa68Hu1EngEB0v8TwxgiwCBMTzvIy-zmw7C0ARSHmcucQKQlqIaakY93hA/exec";
  const ST = process.env.GROVE_SHEET_TOKEN || "grove-sheet-2026";
  const year = String(req.query.year || "2026");
  try {
    // Through Postgres when DATABASE_URL is set (sheetGet routes dealsLoad to the
    // ledger); straight to Sheets otherwise. Keeps this in lockstep with deal writes.
    const j = gdb.on
      ? await sheetGet(GROVE_SHEET_URL, 'dealsLoad', '&year=' + encodeURIComponent(year))
      : await fetch(SU + (SU.indexOf("?") < 0 ? "?" : "&") + "action=dealsLoad&token=" + encodeURIComponent(ST) + "&year=" + encodeURIComponent(year)).then(r => r.json());
    const deals = redactDeals((j && j.ok && Array.isArray(j.deals)) ? j.deals : [], req.user);
    const fmap = await loadDealFiles();
    res.json({ ok: true, deals: withAttachments(deals, fmap), year });
  } catch (e) {
    res.json({ ok: false, deals: [], error: String(e) });
  }
});

// ── Deal ledger — migration diagnostic (READ-ONLY, owner only) ────────────────
// Compares the Google Sheets backup (still intact) against what Postgres serves now.
// The one-time Sheets→Postgres seed keyed legacy rows (no dealId) on property||type||date
// only — which is NOT unique for rentals (several units at one property share it), so those
// rows collapsed into one. This endpoint quantifies the gap. It writes nothing.
app.get("/api/deals/diag", ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== "owner") return res.status(403).json({ ok: false, error: "owner only" });
  try {
    const num = x => Number(String(x == null ? '' : x).replace(/[^0-9.\-]/g, '')) || 0;
    const isRent = d => String((d && d.type) || '').toLowerCase().indexOf('rent') === 0;
    const feeOf = d => { const t = d && d.total; if (t != null && String(t).trim() !== '') return num(t); return (Array.isArray(d && d.lines) ? d.lines : []).reduce((a, l) => a + num(l && l.amount), 0); };
    const yearOf = d => { const m = /(\d{4})/.exec(String((d && d.date) || '')); return m ? m[1] : '(no date/year)'; };
    const rentFees = arr => Math.round(arr.filter(isRent).reduce((a, d) => a + feeOf(d), 0));
    const snap = arr => ({ total: arr.length, rentals: arr.filter(isRent).length, rentalFees: rentFees(arr) });

    const sheetAll = await _dealsRaw('');
    const pgAll = gdb.on ? await gdb.dealsBook('', (y) => _dealsRaw(y)) : [];
    const sheet26 = await _dealsRaw('2026');
    const pg26 = gdb.on ? await gdb.dealsBook('2026', (y) => _dealsRaw(y)) : [];

    const byYear = {};
    pgAll.filter(isRent).forEach(d => { const y = yearOf(d); (byYear[y] = byYear[y] || { count: 0, fees: 0 }); byYear[y].count++; byYear[y].fees += feeOf(d); });
    Object.keys(byYear).forEach(y => byYear[y].fees = Math.round(byYear[y].fees));

    res.json({
      ok: true, databaseOn: gdb.on,
      wholeBook: { sheet: snap(sheetAll), pg: snap(pgAll) },   // every year — the "real" totals
      year2026view: { sheet: snap(sheet26), pg: snap(pg26) },  // what the Deals & Payouts page loads
      rentalFeesByYear: byYear                                 // where the rental fees actually sit
    });
  } catch (e) { res.json({ ok: false, error: String(e && e.message || e) }); }
});

// ── Whole-migration audit (READ-ONLY, owner only) ─────────────────────────────
// Confirms Postgres (live) matches the Google Sheets backup for BOTH data types the
// migration moved: the deal book and every note. Flags anything where the live copy
// shows less than the backup. Reads only — never writes or backfills.
app.get("/api/migration/audit", ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== "owner") return res.status(403).json({ ok: false, error: "owner only" });
  try {
    const sheetAll = await _dealsRaw('');
    const pgAll = gdb.on ? await gdb.dealsBook('', (y) => _dealsRaw(y)) : [];
    const audit = gdb.on
      ? await gdb.auditNotesParity(async (k) => noteValue(await _sheetGetRaw(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(k))))
      : { on: false, rows: [] };
    const rows = audit.rows || [];
    const by = (s) => rows.filter(r => r.status === s).map(r => ({ key: r.key, pgLen: r.pgLen, sheetLen: r.sheetLen }));
    res.json({
      ok: true, databaseOn: gdb.on,
      deals: { pg: pgAll.length, sheet: sheetAll.length, match: pgAll.length === sheetAll.length },
      notes: {
        total: audit.total || rows.length, checked: audit.checked || rows.length,
        match: rows.filter(r => r.status === 'match').length,
        // review these:
        pgEmptySheetHas: by('pg-empty-sheet-has'),   // live shows nothing but the backup has data — investigate
        differ: by('differ'),                        // both have data, not identical — usually PG newer, confirm
        pgHasSheetEmpty: by('pg-has-sheet-empty'),   // PG newer than backup — normal after edits
        sheetReadError: by('sheet-read-error')       // couldn't reach Sheets for this key — rerun
      }
    });
  } catch (e) { res.json({ ok: false, error: String(e && e.message || e) }); }
});

// Repair (owner only): refill any Postgres note that is empty from the Sheets backup.
// Fixes the "present-but-empty shadows the real value" case (e.g. the 401k note). Only
// fills blanks — never overwrites a non-empty PG value — so nothing real can be lost.
app.get("/api/migration/repair", ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== "owner") return res.status(403).json({ ok: false, error: "owner only" });
  if (!gdb.on) return res.json({ ok: false, error: "no database (hub still on Sheets — nothing to repair)" });
  try {
    const r = await gdb.repairEmptyFromSheets(async (k) => noteValue(await _sheetGetRaw(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(k))));
    res.json({ ok: true, ...r });
  } catch (e) { res.json({ ok: false, error: String(e && e.message || e) }); }
});

// --- Grove $100M goal thermometer: aggregate-only totals (no per-deal detail) ---
// Owner + Ryan Quinn only. Computes sales-closed volume and rental fees server-side
// from the full unredacted deal set, and returns ONLY the two numbers — so an agent
// can see the brokerage goal bar without ever pulling the deal book.
app.get("/api/grove-goal", ensureAuth, async (req, res) => {
  const email = String(req.user.email || "").toLowerCase().trim();
  if (req.user.role !== "owner" && email !== "ryan@gpgboston.com")
    return res.status(403).json({ ok: false, error: "forbidden" });
  const SU = process.env.GROVE_SHEET_URL || "https://script.google.com/macros/s/AKfycbxLpHZlNw9yNa68Hu1EngEB0v8TwxgiwCBMTzvIy-zmw7C0ARSHmcucQKQlqIaakY93hA/exec";
  const ST = process.env.GROVE_SHEET_TOKEN || "grove-sheet-2026";
  const year = String(req.query.year || "2026");
  try {
    const j = gdb.on
      ? await sheetGet(GROVE_SHEET_URL, 'dealsLoad', '&year=' + encodeURIComponent(year))
      : await fetch(SU + (SU.indexOf("?") < 0 ? "?" : "&") + "action=dealsLoad&token=" + encodeURIComponent(ST) + "&year=" + encodeURIComponent(year)).then(r => r.json());
    const deals = (j && j.ok && Array.isArray(j.deals)) ? j.deals : [];
    const num = x => Number(String(x == null ? "" : x).replace(/[^0-9.\-]/g, "")) || 0;
    const feeOf = d => (d.total != null) ? num(d.total) : (d.lines || []).reduce((a, l) => a + num(l.amount), 0);
    const stageOf = d => d.stage || ((d.lines && d.lines.length > 0 && d.fee === "collected" && d.lines.every(l => l.paid)) ? "Closed" : "Under Agreement");
    let salesClosedVol = 0, rentalFees = 0;
    deals.forEach(d => {
      if (d.type === "Sale") { if (stageOf(d) === "Closed") salesClosedVol += num(d.price); }
      else rentalFees += feeOf(d);
    });
    // For Sale Folder potential — total asking price of everything in the folder.
    let forSaleVol = 0;
    try {
      const nu = SU + (SU.indexOf("?") < 0 ? "?" : "&") + "action=notes&notekey=forsale_folder&token=" + encodeURIComponent(ST);
      const nj = await fetch(nu).then(r => r.json());
      const raw = nj && (nj.value != null ? nj.value : nj.notes);
      const data = raw ? JSON.parse(raw) : null;
      const props = (data && Array.isArray(data.props)) ? data.props : [];
      forSaleVol = props.reduce((a, p) => a + num(p.price), 0);
    } catch (e) { /* folder unreadable — leave forSaleVol at 0 */ }
    res.json({ ok: true, salesClosedVol, rentalFees, forSaleVol, year });
  } catch (e) { res.json({ ok: false, error: String(e) }); }
});

// --- Live mortgage rates (Freddie Mac PMMS via FRED, no key needed) ---
let _rateCache = { at: 0, data: null };
app.get("/api/rates", ensureAuth, async (req, res) => {
  try {
    if (_rateCache.data && Date.now() - _rateCache.at < 6 * 3600 * 1000) return res.json(_rateCache.data);
    // FRED public CSV downloads (no API key). MORTGAGE30US / MORTGAGE15US = weekly avg 30/15-yr fixed.
    async function latest(series) {
      const url = `https://fred.stlouisfed.org/graph/fredgraph.csv?id=${series}`;
      const txt = await fetch(url).then(r => r.text());
      const rows = txt.trim().split(/\r?\n/).slice(1).filter(Boolean);
      for (let i = rows.length - 1; i >= 0; i--) {
        const [date, val] = rows[i].split(",");
        if (val && val !== "." && !isNaN(parseFloat(val))) return { date, value: parseFloat(val) };
      }
      return null;
    }
    const [r30, r15] = await Promise.all([latest("MORTGAGE30US"), latest("MORTGAGE15US")]);
    const data = { ok: true, thirty: r30, fifteen: r15, source: "Freddie Mac PMMS (FRED)" };
    _rateCache = { at: Date.now(), data };
    res.json(data);
  } catch (e) { res.status(502).json({ ok: false, error: "rates_failed" }); }
});

// --- Boston real-estate news ticker (public RSS, parsed server-side) ---
let _newsCache = { at: 0, data: null };
app.get("/api/news", ensureAuth, async (req, res) => {
  try {
    if (_newsCache.data && Date.now() - _newsCache.at < 30 * 60 * 1000) return res.json(_newsCache.data);
    const feeds = [
      "https://www.bostonagentmagazine.com/feed/",
      "https://news.google.com/rss/search?q=Boston+real+estate+when:7d&hl=en-US&gl=US&ceid=US:en",
      "https://www.bisnow.com/rss/boston"
    ];
    const texts = await Promise.all(feeds.map(u =>
      fetch(u, { headers: { "User-Agent": "Mozilla/5.0 GroveHub" } }).then(r => r.text()).catch(() => "")
    ));
    const items = [];
    const strip = s => String(s || "")
      .replace(/<!\[CDATA\[|\]\]>/g, "")
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"')
      .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").trim();
    for (const xml of texts) {
      const blocks = xml.split(/<item[\s>]/i).slice(1);
      for (const b of blocks.slice(0, 12)) {
        const t = (b.match(/<title>([\s\S]*?)<\/title>/i) || [])[1];
        const l = (b.match(/<link>([\s\S]*?)<\/link>/i) || [])[1];
        const title = strip(t);
        if (title && title.length > 8) items.push({ title, link: strip(l) });
      }
    }
    const seen = new Set(), out = [];
    for (const it of items) { const k = it.title.toLowerCase().slice(0, 60); if (!seen.has(k)) { seen.add(k); out.push(it); } }
    const data = { ok: true, items: out.slice(0, 20) };
    _newsCache = { at: Date.now(), data };
    res.json(data);
  } catch (e) { res.status(502).json({ ok: false, error: "news_failed", items: [] }); }
});

// --- Build Feasibility: address -> assessor record + zoning fields (owners only). Background job;
// two grounded calls in parallel, each with a 2-minute cap; client polls.
const zoningLookups = new Map();

async function runZoningLookup(job) {
  const address = job.address;
  const recordPrompt = `You are a property assessor-record analyst. Use Google Search on the municipal GIS / online assessor property record card and the county registry of deeds to research this US property.
Address: ${address}
Return ONLY a JSON object — no markdown, no code fences. Use null when a value cannot be reliably found. Numbers plain (no commas, units, or $; dollars as integers). Keys, exactly:
{"town":string,"parcel_id":string|null,"owner":string|null,"land_use":string|null,"year_built":number|null,"existing_building_sqft":number|null,"existing_units":number|null,"lot_sqft":number|null,"frontage_ft":number|null,"assessed_total":number|null,"assessed_land":number|null,"assessed_building":number|null,"last_sale_price":number|null,"last_sale_date":string|null,"estimated_condition":"Turnkey"|"Cosmetic"|"Gut rehab"|"Teardown"|"Unknown","summary":string,"sources":string[]}
last_sale_date as YYYY-MM or MM/YYYY. Search thoroughly — accuracy beats speed. Never invent numbers — prefer null.`;

  const zoningPrompt = `You are a zoning and land-use analyst. Use Google Search on the town/city government zoning bylaw for the district that governs this parcel.
Address: ${address}
Return ONLY a JSON object — no markdown, no code fences. Use null when a value cannot be reliably found. Numbers plain (no commas or units). Keys, exactly:
{"zoning_district":string,"allowed_uses":string|null,"min_lot_area_per_unit":number|null,"min_lot_sqft":number|null,"far":number|null,"max_lot_coverage_pct":number|null,"max_stories":number|null,"max_height_ft":number|null,"min_lot_to_subdivide_sqft":number|null,"min_frontage_ft":number|null,"front_setback_ft":number|null,"side_setback_ft":number|null,"rear_setback_ft":number|null,"parking_per_unit":number|null,"adu_allowed":"yes"|"no"|"unknown","overlay_districts":string|null,"summary":string,"sources":string[]}
Base every number on the specific zoning DISTRICT that governs THIS parcel; put overlay districts in overlay_districts. Search thoroughly — accuracy beats speed. Never invent numbers — prefer null.`;

  async function runOne(prompt) {
    const gr = await Promise.race([
      geminiFetch({ contents: [{ parts: [{ text: prompt }] }], tools: [{ google_search: {} }], generationConfig: { temperature: 0 } }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 120000))
    ]);
    if (!gr || !gr.ok) throw new Error("http_" + (gr ? gr.status : 0));
    const data = await gr.json();
    const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
    let text = parts.map(p => p.text || "").join("").trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
    const m = text.match(/\{[\s\S]*\}/);
    let obj = null; try { obj = JSON.parse(m ? m[0] : text); } catch (e) { obj = null; }
    const gm = ((data.candidates || [])[0] || {}).groundingMetadata || {};
    const src = (gm.groundingChunks || []).map(c => c.web && c.web.uri).filter(Boolean);
    return { obj, src };
  }

  try {
    const [rec, zon] = await Promise.allSettled([runOne(recordPrompt), runOne(zoningPrompt)]);
    const recOk = rec.status === "fulfilled" && rec.value && rec.value.obj;
    const zonOk = zon.status === "fulfilled" && zon.value && zon.value.obj;
    if (!recOk && !zonOk) {
      const timedOut = /timeout/.test(String(rec.reason || "")) || /timeout/.test(String(zon.reason || ""));
      job.status = "error"; job.error = timedOut ? "timeout" : "lookup_failed"; return;
    }
    const recObj = recOk ? rec.value.obj : {};
    const zonObj = zonOk ? zon.value.obj : {};
    const fields = Object.assign({}, recObj, zonObj);
    fields.summary = [recObj.summary, zonObj.summary].filter(Boolean).join(" ");
    fields.confidence = (recOk && zonOk) ? "medium" : "low";
    const src = [].concat(recOk ? rec.value.src : [], zonOk ? zon.value.src : [], recObj.sources || [], zonObj.sources || []).filter((u, k, a) => u && a.indexOf(u) === k);
    fields.sources = src;
    job.status = "done"; job.fields = fields; job.sources = src; job.partial = !(recOk && zonOk);
  } catch (e) {
    job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 200);
  }
}

app.post("/api/zoning-lookup", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable auto-fill." });
  const address = String((req.body && req.body.address) || "").trim();
  if (!address) return res.status(400).json({ ok: false, error: "no_address" });
  const id = zrNewId();
  const job = { id, status: "running", started: Date.now(), address, fields: null, sources: [], partial: false, error: "" };
  zoningLookups.set(id, job);
  runZoningLookup(job).catch(e => { job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 200); });
  if (zoningLookups.size > 50) { const ks = [...zoningLookups.keys()]; for (let k = 0; k < ks.length - 50; k++) zoningLookups.delete(ks[k]); }
  res.json({ ok: true, id });
});

app.get("/api/zoning-lookup/:id", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const job = zoningLookups.get(String(req.params.id || ""));
  if (!job) return res.status(404).json({ ok: false, error: "not_found", message: "That lookup id is unknown — start a new one." });
  const elapsed = Math.round((Date.now() - job.started) / 1000);
  if (job.status === "running") return res.json({ ok: true, status: "running", elapsed });
  if (job.status === "error") return res.json({ ok: true, status: "error", elapsed, error: job.error });
  return res.json({ ok: true, status: "done", elapsed, fields: job.fields, sources: job.sources, partial: job.partial });
});

/* ===== Spending Intelligence — AI analysis (owner-only). Added 2026-08-12. =====
   Powers the "✦ Run AI analysis" button on spending.html. Receives a PRE-AGGREGATED
   spending summary + a sample of the largest transactions (no raw dump, no credentials)
   and returns {insights, advice, enrich}. Prefers Claude when ANTHROPIC_API_KEY is set;
   otherwise reuses the hub's existing Gemini plumbing (geminiFetch / parseLooseJson).
   Override the model with SPEND_MODEL (Claude) / GEMINI_MODEL (Gemini, already set). */
const SPEND_SYS_PROMPT = `You are a rigorous, plain-spoken personal-finance analyst embedded in the owner's private spending dashboard.
You receive a PRE-AGGREGATED summary of ONE time period plus a sample of that period's largest transactions. The data is already deduped and locally tagged.
Your job:
1) ENRICH: for merchants in the sample that are ambiguous or clearly mis-tagged, give a precise subcategory and necessity.
2) ADVISE: surface concrete, prioritized ways to cut UNNECESSARY spending.
Hard rules:
- Be specific and quantitative. Every piece of advice must reference real dollar amounts and merchants FROM THE INPUT and give an annualized savings estimate.
- Never invent transactions, merchants, or numbers not derivable from the input.
- Easy, high-impact wins first. Fixed necessities (rent, mortgage, insurance, loan, utilities, taxes) are usually NOT cuttable — focus on discretionary spend, subscriptions, dining, small recurring leaks, and category spikes.
- Do not moralize or lecture. Neutral, useful, direct.
- Output ONLY valid minified JSON matching the schema. No markdown, no prose outside the JSON.`;
function spendUserPrompt(p) {
  const schema = `Return ONLY this JSON shape (minified):
{"insights":["<=5 one-sentence observations, most important first"],
 "advice":[{"title":"short","detail":"1-2 sentences with specific $ and merchant names","estSavingsYr":<integer dollars/year>,"effort":"easy|medium|big","category":"string"}],
 "enrich":[{"m":"<merchant exactly as given in sample>","subcat":"refined subcategory","necessity":"necessary|discretionary"}]}
- advice: up to 8, sorted easy+high-impact first.
- enrich: ONLY merchants from the sample that are ambiguous or mis-tagged; omit ones already fine. Keep "m" byte-for-byte as provided.`;
  return `Analyze the spending period "${(p && p.period) || "this period"}".\n\nDATA (JSON):\n${JSON.stringify(p)}\n\n${schema}\nRespond with JSON only.`;
}
async function spendClaude(sys, user) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({ model: process.env.SPEND_MODEL || "claude-sonnet-4-5", max_tokens: 1800, system: sys, messages: [{ role: "user", content: user }] })
  });
  if (!r.ok) throw new Error("anthropic_" + r.status + "_" + (await r.text()).slice(0, 160));
  const d = await r.json();
  return (d.content && d.content[0] && d.content[0].text) || "";
}
async function spendGemini(sys, user) {
  const gr = await geminiFetch({ contents: [{ parts: [{ text: sys + "\n\n" + user }] }], generationConfig: { temperature: 0.4, maxOutputTokens: 2048, responseMimeType: "application/json" } }, 2, geminiKeyFor("grove"));
  if (!gr || !gr.ok) throw new Error("gemini_http_" + (gr ? gr.status : 0));
  const data = await gr.json();
  const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
  return parts.map(p => p.text || "").join("");
}
app.post("/api/spend/ai", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  try {
    const p = req.body || {};
    const sys = SPEND_SYS_PROMPT, user = spendUserPrompt(p);
    let raw;
    if (process.env.ANTHROPIC_API_KEY) raw = await spendClaude(sys, user);
    else if (GEMINI_API_KEY) raw = await spendGemini(sys, user);
    else return res.status(501).json({ ok: false, error: "no_key", message: "Set ANTHROPIC_API_KEY (or rely on GEMINI_API_KEY) to enable AI analysis." });
    const j = parseLooseJson(raw) || {};
    res.json({
      ok: true,
      insights: Array.isArray(j.insights) ? j.insights.slice(0, 5) : [],
      advice: Array.isArray(j.advice) ? j.advice.slice(0, 8) : [],
      enrich: Array.isArray(j.enrich) ? j.enrich.slice(0, 200) : []
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e && e.message || e).slice(0, 200) });
  }
});
/* ===== end Spending Intelligence AI ===== */


// --- Developer Zoning Report: deep grounded analysis as a BACKGROUND JOB (owners only), split into
// two parallel calls (structured fields + narrative) so a slow half never kills the run. Answers are
// CACHED (90 days) so repeat lookups are instant; force:true always runs fresh.
const reportCache = new Map();
const CACHE_FILE = "./zoning-cache.json";
try { const cj = JSON.parse(fs.readFileSync(CACHE_FILE, "utf8")); Object.keys(cj).forEach(k => reportCache.set(k, cj[k])); } catch (e) {}
function cacheSave() { try { const o = {}; reportCache.forEach((v, k) => { o[k] = v; }); fs.writeFileSync(CACHE_FILE, JSON.stringify(o)); } catch (e) {} }

// ---- District rules memory: learned once per town+district, kept forever. ----
// Commit /api/zoning-db output to the repo as zoning-db-seed.json to make it deploy-proof.
const districtDB = new Map();
const DISTRICT_FILE = "./zoning-districts.json";
const DISTRICT_SEED = "./zoning-db-seed.json";
function dkeyOf(town, dist) {
  return String(town || "").trim().toLowerCase().replace(/\s+/g, " ") + "|" + String(dist || "").trim().toUpperCase().replace(/\s+/g, " ");
}
// Load the seed + runtime file at boot. Tries BOTH the cwd-relative path and the
// __dirname-absolute path (Render's start cwd is not guaranteed to be the repo root —
// that mismatch once made a committed seed silently load nothing). Every attempt is
// recorded so /api/zoning-db/meta can show exactly what happened at boot.
const SEED_LOAD_LOG = [];
[DISTRICT_SEED, DISTRICT_FILE,
 path.join(__dirname, "zoning-db-seed.json"),
 path.join(__dirname, "zoning-districts.json")].forEach(f => {
  try {
    if (!fs.existsSync(f)) { SEED_LOAD_LOG.push(f + ": not found"); return; }
    const o = JSON.parse(fs.readFileSync(f, "utf8"));
    let n = 0;
    Object.keys(o || {}).forEach(k => { if (k.indexOf("|") > -1 && !districtDB.has(k)) { districtDB.set(k, o[k]); n++; } });
    SEED_LOAD_LOG.push(f + ": loaded " + n);
  } catch (e) { SEED_LOAD_LOG.push(f + ": ERROR " + String(e && e.message ? e.message : e).slice(0, 80)); }
});
function districtSave() { try { const o = {}; districtDB.forEach((v, k) => { o[k] = v; }); fs.writeFileSync(DISTRICT_FILE, JSON.stringify(o)); } catch (e) {} }
const DISTRICT_KEYS = ["min_lot_sqft","min_lot_area_per_unit","min_frontage_ft","front_setback_ft","side_setback_ft","rear_setback_ft","max_height_ft","max_stories","max_lot_coverage_pct","far","parking_per_unit","adu_allowed","allowed_uses"];
function pickRules(src) {
  const rules = {}; let got = 0;
  DISTRICT_KEYS.forEach(k => { const v = src ? src[k] : null; if (v !== null && v !== undefined && v !== "") { rules[k] = v; got++; } });
  return got >= 3 ? rules : null;
}
function districtLearn(f, tag) {
  try {
    if (!f || !f.municipality || !f.zoning_district) return;
    const rules = pickRules(f); if (!rules) return;
    districtDB.set(dkeyOf(f.municipality, f.zoning_district), { town: f.municipality, district: f.zoning_district, rules, at: Date.now(), src: tag || "report" });
    districtSave();
  } catch (e) {}
}
function parseLooseJson(text) {
  let t = String(text || "").trim();
  const fence = t.match(/\`\`\`json\s*([\s\S]*?)\`\`\`/i) || t.match(/\`\`\`\s*(\{[\s\S]*?\})\s*\`\`\`/);
  if (fence) t = fence[1].trim();
  const m = t.match(/\{[\s\S]*\}/);
  try { return JSON.parse(m ? m[0] : t); } catch (e) { return null; }
}
// Salvage a truncated districts payload: when the response got cut mid-JSON, pull
// every COMPLETE {...} item out of the districts array and keep those. A town with
// 14 districts cut at #12 learns 12 instead of 0.
function salvageDistricts(raw) {
  const t = String(raw || "");
  const at = t.search(/"districts"\s*:/);
  if (at < 0) return null;
  const items = [];
  const re = /\{[^{}]*\}/g; re.lastIndex = at;
  let m;
  while ((m = re.exec(t))) {
    try { const o = JSON.parse(m[0]); if (o && o.zoning_district) items.push(o); } catch (e) {}
  }
  return items.length ? { districts: items, __salvaged: true } : null;
}
async function groundedJson(prompt, ms, maxOut, think) {
  const gr = await Promise.race([
    geminiFetch({ contents: [{ parts: [{ text: prompt }] }], tools: [{ google_search: {} }], generationConfig: { temperature: 0, maxOutputTokens: maxOut || 2048, thinkingConfig: { thinkingBudget: think || 2048 } } }, 3),
    new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))
  ]);
  if (!gr || !gr.ok) throw new Error("http_" + (gr ? gr.status : 0));
  const data = await gr.json();
  const cand = (data.candidates || [])[0] || {};
  const parts = (cand.content || {}).parts || [];
  const raw = parts.map(p => p.text || "").join("");
  let out = parseLooseJson(raw);
  if (!out) out = salvageDistricts(raw);
  if (!out) return { __fail: { fr: cand.finishReason || "?", len: raw.length } };
  return out;
}
// Quick lookup: tiny district resolver + memory; learns the district once on a miss.
const quickJobs = new Map();
app.post("/api/zoning-quick", ensureAuth, (req, res) => {
  if (req.user.role === "guest") return res.status(403).json({ ok: false, error: "forbidden" }); // owners + agents may auto-fill (memory hits are free); deep report & comps stay owner-only
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key" });
  const address = String((req.body && req.body.address) || "").trim();
  if (!address) return res.status(400).json({ ok: false, error: "no_address" });
  const hit = reportCache.get(cacheKey(address));
  if (hit && hit.fields && hit.fields.zoning_district) {
    const id = zrNewId();
    quickJobs.set(id, { id, status: "done", started: Date.now(), address, municipality: hit.fields.municipality || "", district: hit.fields.zoning_district, rules: pickRules(hit.fields) || {}, learned: false, from: "cache" });
    return res.json({ ok: true, id, cached: true });
  }
  const id = zrNewId();
  const job = { id, status: "running", started: Date.now(), address, rules: null, learned: false, error: "" };
  quickJobs.set(id, job);
  runQuick(job).catch(e => { job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 160); });
  if (quickJobs.size > 80) { const ks = [...quickJobs.keys()]; for (let k = 0; k < ks.length - 80; k++) quickJobs.delete(ks[k]); }
  res.json({ ok: true, id });
});
app.get("/api/zoning-quick/:id", ensureAuth, (req, res) => {
  if (req.user.role === "guest") return res.status(403).json({ ok: false, error: "forbidden" });
  const job = quickJobs.get(String(req.params.id || ""));
  if (!job) return res.status(404).json({ ok: false, error: "not_found" });
  const elapsed = Math.round((Date.now() - job.started) / 1000);
  if (job.status === "running" && elapsed > 200) { job.status = "error"; job.error = "Ran out of time — try again."; }
  res.json({ ok: true, status: job.status, elapsed, municipality: job.municipality || "", district: job.district || "", rules: job.rules, learned: !!job.learned, from: job.from || "", error: job.error || "" });
});
async function runQuick(job) {
  const rj = await groundedJson(
    "Property address: " + job.address + ". Identify the MUNICIPALITY and the parcel's ZONING DISTRICT CODE (from the town assessor card, town GIS, or zoning map — Google Search). Respond ONLY JSON: {\"municipality\":\"\",\"zoning_district\":\"\",\"confidence\":\"high|medium|low\"}",
    75000, 256, 1024);
  const mun = rj && rj.municipality ? String(rj.municipality) : "";
  const dist = rj && rj.zoning_district ? String(rj.zoning_district) : "";
  if (!dist) { job.status = "error"; job.error = "couldn't identify the district"; return; }
  job.municipality = mun; job.district = dist;
  const hit = districtDB.get(dkeyOf(mun, dist));
  if (hit && hit.rules) { job.rules = hit.rules; job.learned = false; job.from = "memory"; job.status = "done"; return; }
  const dj = await groundedJson(
    "Zoning district \"" + dist + "\" in " + mun + ". From the municipality's CURRENT zoning bylaw/ordinance dimensional table (Google Search; official sources — ecode360, municode, the town site), give the standards for this district. Use null when the bylaw has no value. Respond ONLY JSON: {\"min_lot_sqft\":null,\"min_lot_area_per_unit\":null,\"min_frontage_ft\":null,\"front_setback_ft\":null,\"side_setback_ft\":null,\"rear_setback_ft\":null,\"max_height_ft\":null,\"max_stories\":null,\"max_lot_coverage_pct\":null,\"far\":null,\"parking_per_unit\":null,\"adu_allowed\":\"yes|no|unknown\",\"allowed_uses\":[]}",
    150000, 4096, 4096);
  const rules = pickRules(dj);
  if (!rules) { job.status = "error"; job.error = "couldn't read the dimensional table"; return; }
  districtDB.set(dkeyOf(mun, dist), { town: mun, district: dist, rules, at: Date.now(), src: "quick" });
  districtSave();
  job.rules = rules; job.learned = true; job.from = "learned"; job.status = "done";
}
// Preload: batch-learn every district in a list of towns.
const preloadJobs = new Map();
app.post("/api/zoning-preload", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key" });
  const towns = Array.isArray(req.body && req.body.towns) ? req.body.towns.map(t => String(t).trim()).filter(Boolean).slice(0, 400) : [];
  if (!towns.length) return res.status(400).json({ ok: false, error: "no_towns" });
  const id = zrNewId();
  const job = { id, status: "running", started: Date.now(), towns, done: 0, total: towns.length, districts: 0, log: [] };
  preloadJobs.set(id, job);
  runPreload(job).catch(e => { job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 160); });
  res.json({ ok: true, id });
});
app.get("/api/zoning-preload/:id", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const job = preloadJobs.get(String(req.params.id || ""));
  if (!job) return res.status(404).json({ ok: false, error: "not_found" });
  res.json({ ok: true, status: job.status, done: job.done, total: job.total, districts: job.districts, log: job.log.slice(-8), error: job.error || "" });
});
async function runPreload(job) {
  for (let i = 0; i < job.towns.length; i++) {
    const town = job.towns[i];
    // resumable: skip towns the memory already knows well
    let known = 0;
    districtDB.forEach(v => { if (String(v.town || "").toLowerCase() === town.toLowerCase()) known++; });
    if (known >= 3) { job.log.push(town + ": already known (" + known + " districts) — skipped"); job.done++; continue; }
    try {
      const tj = await groundedJson(
        "Municipality: " + town + ", Massachusetts. Research its CURRENT zoning bylaw/ordinance via Google Search (official sources) and summarize, in your own words as structured data, EVERY base zoning district with its dimensional standards. Include ALL districts; keep values terse (numbers or null only). Output ONLY this JSON, nothing else: {\"districts\":[{\"zoning_district\":\"\",\"min_lot_sqft\":null,\"min_lot_area_per_unit\":null,\"min_frontage_ft\":null,\"front_setback_ft\":null,\"side_setback_ft\":null,\"rear_setback_ft\":null,\"max_height_ft\":null,\"max_stories\":null,\"max_lot_coverage_pct\":null,\"far\":null,\"parking_per_unit\":null,\"adu_allowed\":\"yes|no|unknown\"}]}",
        200000, 16384, 4096);
      const list = (tj && Array.isArray(tj.districts)) ? tj.districts : [];
      let added = 0;
      list.forEach(d => {
        const rules = pickRules(d);
        if (rules && d.zoning_district) { districtDB.set(dkeyOf(town, d.zoning_district), { town, district: String(d.zoning_district), rules, at: Date.now(), src: "preload" }); added++; }
      });
      districtSave();
      job.districts += added;
      job.log.push(town + ": " + added + " districts"
        + (tj && tj.__salvaged ? " (salvaged from a cut response)" : "")
        + (added === 0 ? (" (raw: " + (tj && tj.__fail ? ("FAIL " + tj.__fail.fr + " len " + tj.__fail.len) : (tj && typeof tj === "object" ? (Array.isArray(tj.districts) ? ("array len " + tj.districts.length) : ("keys " + Object.keys(tj).join(",").slice(0, 40))) : typeof tj)) + ")") : ""));
    } catch (e) {
      const msg = String(e && e.message ? e.message : e);
      if (/429/.test(msg)) {
        job._c429 = (job._c429 || 0) + 1;
        if (job._c429 <= 4) {
          job.log.push(town + ": rate/credit hit — pausing 2 min and retrying (" + job._c429 + "/4)");
          await new Promise(r => setTimeout(r, 120000));
          i--;                                    // retry the same town
          continue;
        }
        job.status = "error";
        job.error = "Stopped at " + town + ": persistent 429s — balance or quota exhausted. Re-fire to resume (learned towns are skipped).";
        return;
      }
      job.log.push(town + ": failed (" + msg.slice(0, 40) + ")");
    }
    job._c429 = 0;
    job.done++;
    await new Promise(r => setTimeout(r, 9000));
  }
  job.status = "done";
}
// Export the learned DB — save the JSON as zoning-db-seed.json in the repo to survive redeploys.
app.get("/api/zoning-db", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const o = {}; districtDB.forEach((v, k) => { o[k] = v; });
  res.setHeader("Content-Disposition", "attachment; filename=zoning-db-seed.json");
  res.json(o);
});
// What happened to the seed at boot (owner) — cwd, every load attempt, live count.
app.get("/api/zoning-db/meta", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const towns = new Set(); districtDB.forEach((v, k) => towns.add(String(k).split("|")[0]));
  res.json({ ok: true, cwd: process.cwd(), dirname: __dirname, boot: SEED_LOAD_LOG, districts: districtDB.size, towns: towns.size });
});
// Manual import (owner): POST a flat {"town|DISTRICT":{...}} map (a saved seed export)
// and it merges straight into the live memory — the rescue path if a boot-load ever
// fails again. Chunk-friendly: post partial maps repeatedly, they merge.
app.post("/api/zoning-db", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const o = (req.body && typeof req.body === "object") ? req.body : {};
  let added = 0, skipped = 0;
  Object.keys(o).forEach(k => {
    if (k.indexOf("|") < 0 || !o[k] || typeof o[k] !== "object") { skipped++; return; }
    if (!districtDB.has(k)) added++;
    districtDB.set(k, o[k]);
  });
  districtSave();
  res.json({ ok: true, added, skipped, total: districtDB.size });
});
function cacheKey(a) { return String(a || "").trim().toLowerCase().replace(/\s+/g, " "); }

const zoningReports = new Map();
function zrNewId() { return "zr_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

async function runZoningReport(job) {
  const address = job.address;

  const SOURCES = `OUT-OF-STATE: if the property is NOT in Massachusetts, use that state's official equivalents instead (statewide GIS/parcel viewer, the municipality's current zoning ordinance, county/city assessor) and that state's nonconforming-lot law.
SOURCES — in priority order: (1) the municipality's official website and its CURRENT zoning bylaw/ordinance PDF (often hosted on ecode360.com, municode.com or generalcode.com) and its Table of Dimensional Requirements; (2) the town's online GIS / assessor property card (AxisGIS, Vision/VGSI, Patriot Properties, MapGeo, CAI); (3) MassGIS. For BOSTON addresses: the Boston Zoning Code neighborhood-district articles (e.g. Article 68 Dorchester, Article 53 East Boston, South Boston Article 68 etc.), the BPDA zoning viewer at maps.bostonplans.org, and assessing.boston.gov for the parcel — Boston districts look like "3F-4000", "MFR", "NS", "R-8". Work IN ORDER and stop researching a fact once an official source confirms it. NEVER invent a number — use null and keep confidence honest.
NONCONFORMING LOTS: if the lot is smaller than the district minimum, check the bylaw's nonconforming-lot section AND the MA G.L. c.40A §6 grandfather protections, and state plainly whether a dwelling is still buildable on it.`;

  const fieldsPrompt = `You are a municipal zoning and assessing analyst for US properties (most requests are Massachusetts). Use Google Search to research the property at: ${address}
${SOURCES}
TASKS: identify the municipality; confirm THIS parcel's zoning district; pull the district's dimensional standards; pull the parcel's ACTUAL lot area, frontage and assessor basics; then COMPUTE the max build-out for THIS lot (units by right = lot area ÷ min lot area per unit, capped by which uses are by right; max building sq ft from FAR or footprint-inside-setbacks × stories, respecting height).
Return ONLY a single JSON object — no markdown, no code fences, no prose. Numbers plain (no commas/units/$). Keys, exactly:
{"municipality":string,"county":string|null,"state":string|null,"zoning_district":string,"overlay_districts":string|null,"allowed_uses":string|null,"min_lot_sqft":number|null,"min_lot_area_per_unit":number|null,"min_frontage_ft":number|null,"front_setback_ft":number|null,"side_setback_ft":number|null,"rear_setback_ft":number|null,"max_height_ft":number|null,"max_stories":number|null,"max_lot_coverage_pct":number|null,"far":number|null,"parking_per_unit":number|null,"adu_allowed":"yes"|"no"|"by special permit"|"unknown","lot_sqft":number|null,"frontage_ft":number|null,"parcel_id":string|null,"owner":string|null,"land_use":string|null,"year_built":number|null,"existing_building_sqft":number|null,"existing_units":number|null,"max_units_by_right":number|null,"max_units_special_permit":number|null,"max_buildable_sqft":number|null,"buildout":string,"path":"by-right"|"special permit"|"variance"|"unbuildable","biggest_opportunity":string,"biggest_constraint":string,"best_use":string,"plays":[string],"confidence":"high"|"medium"|"low"}
buildout = one plain-English sentence stating the maximum units AND maximum building size for THIS parcel. path = the easiest realistic route to that max build-out. biggest_opportunity / biggest_constraint = one short developer-focused sentence each (the value-add angle vs. the thing most likely to kill or shrink the deal). best_use = ONE sentence naming the highest-and-best use for THIS parcel given the zoning and the existing building (e.g. "Tear down and build a by-right 3-family of ~3,600 sf" or "Convert the existing two-family to condos and add an interior ADU"). plays = the top 2-3 development plays RANKED best-first, each ONE line: the play, why it wins, and its approval path (by right / special permit / variance). IMPORTANT: max_buildable_sqft and every building size you state are GROSS floor area (the zoning envelope — exterior walls, stairs, common areas included). Say "gross" when stating sizes; living/sellable area typically runs 10-20% below gross.`;

  const fieldsFastPrompt = fieldsPrompt + `
FAST MODE: you have limited time. At most ~6 targeted searches. Fill what an official source confirms quickly, set everything else to null, set confidence to "low". Returning a mostly-null JSON fast is BETTER than timing out.`;

  const narrativePrompt = `You are an expert Massachusetts real estate development analyst writing a zoning read for a developer deciding what they can build at: ${address}
${SOURCES}
Write the report in MARKDOWN ONLY (no JSON) with these five sections and headings exactly:
## Maximum Build-Out — This Parcel
THE ANSWER FIRST, arithmetic shown with this parcel's ACTUAL lot area from the assessor: max dwelling units BY RIGHT (lot ÷ min lot area per unit, capped by by-right uses — if only single-family is by right, say "1 by right" and what lot size a 2nd/3rd unit needs); max units via SPECIAL PERMIT (multifamily SP, conversion, ADU, 40B/40R); the MAXIMUM BUILDING this lot supports in approximate total GROSS sq ft (FAR, or footprint-inside-setbacks × stories, respecting height) — label it gross and note that living/sellable area typically runs 10-20% less; if the lot is UNDERSIZED for the district say exactly what that means here (grandfathered buildable? variance?); and subdivision — how many CONFORMING lots it can split into (area AND frontage limits).
## A. Zoning District & Overlays
Primary district governing this parcel and every overlay that applies (and what each overlay triggers).
## B. By-Right Development Potential
Uses allowed by right; density; dimensional standards (min lot, frontage, setbacks, height, coverage, FAR); parking; ADU rules; any by-right conversion path (e.g. single-family -> two/three-family).
## C. Special Permit / Variance Path
Uses allowed only by special permit; typical special-permit / variance triggers in this district; the criteria the ZBA or Planning Board weighs; how this town tends to treat them if public sources show it.
## D. Developer Summary
Plain language: what can realistically be built or converted BY RIGHT on THIS parcel; what needs a special permit or variance; the biggest constraints and value-add opportunities; red flags (strict historic district, very large minimum lots, high parking ratios, etc.).
Rules: cite the exact source (town + document name + year) inline where it matters. If information is incomplete or conflicting, SAY SO rather than guessing. End with exactly this line: "This is not legal advice. Always verify with the local Building/Planning Department and current zoning map before underwriting."`;

  async function runOnce(prompt, ms) {
    const gr = await Promise.race([
      geminiFetch({ contents: [{ parts: [{ text: prompt }] }], tools: [{ google_search: {} }], generationConfig: { temperature: 0, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 4096 } } }, 3),
      new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))
    ]);
    if (!gr || !gr.ok) throw new Error("http_" + (gr ? gr.status : 0));
    const data = await gr.json();
    const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
    const text = parts.map(p => p.text || "").join("").trim();
    const gm = ((data.candidates || [])[0] || {}).groundingMetadata || {};
    const src = (gm.groundingChunks || []).map(c => c.web && c.web.uri).filter(Boolean);
    return { text, src };
  }
  function parseFields(text) {
    let t = String(text || "").trim();
    const fence = t.match(/```json\s*([\s\S]*?)```/i) || t.match(/```\s*(\{[\s\S]*?\})\s*```/);
    if (fence) t = fence[1].trim();
    const m = t.match(/\{[\s\S]*\}/);
    try { return JSON.parse(m ? m[0] : t); } catch (e) { return null; }
  }

  function mergeFields(a, b, disputed) {
    const STRICT_MAX = ['min_lot_sqft','min_lot_area_per_unit','min_frontage_ft','front_setback_ft','side_setback_ft','rear_setback_ft','parking_per_unit'];
    const CONSERV_MIN = ['max_height_ft','max_stories','max_lot_coverage_pct','far','max_units_by_right','max_units_special_permit','max_buildable_sqft'];
    const FACTS = ['lot_sqft','frontage_ft','existing_building_sqft','existing_units','year_built'];
    const out = Object.assign({}, a);
    const numeric = v => (v === null || v === undefined || v === '' ? null : Number(v));
    STRICT_MAX.forEach(k => { const x = numeric(a[k]), y = numeric(b[k]);
      if (x != null && y != null) { if (x !== y) { out[k] = Math.max(x, y); disputed.push(k); } }
      else out[k] = (x != null ? x : y); });
    CONSERV_MIN.forEach(k => { const x = numeric(a[k]), y = numeric(b[k]);
      if (x != null && y != null) { if (x !== y) { out[k] = Math.min(x, y); disputed.push(k); } }
      else out[k] = (x != null ? x : y); });
    FACTS.forEach(k => { const x = numeric(a[k]), y = numeric(b[k]);
      if (x != null && y != null && Math.abs(x - y) > 0.05 * Math.max(Math.abs(x), Math.abs(y), 1)) disputed.push(k);
      if (out[k] == null) out[k] = (x != null ? x : y); });
    ['zoning_district','path','municipality','adu_allowed'].forEach(k => {
      const x = String(a[k] || '').trim().toLowerCase(), y = String(b[k] || '').trim().toLowerCase();
      if (x && y && x !== y) disputed.push(k);
      if (!a[k] && b[k]) out[k] = b[k]; });
    if (Array.isArray(a.overlay_districts) || Array.isArray(b.overlay_districts)) {
      const u = [].concat(a.overlay_districts || [], b.overlay_districts || []);
      out.overlay_districts = u.filter((v, i) => u.findIndex(w => String(w).toLowerCase() === String(v).toLowerCase()) === i);
    }
    return out;
  }
  const fieldsWork = (async () => {
    const t1 = runOnce(fieldsPrompt, 230000).then(r => ({ r })).catch(e => ({ e }));
    const t2 = new Promise(res => setTimeout(res, 20000)).then(() => runOnce(fieldsPrompt, 210000)).then(r => ({ r })).catch(e => ({ e }));
    const [ra, rb] = await Promise.all([t1, t2]);
    const fa = ra.r ? parseFields(ra.r.text) : null;
    const fb = rb.r ? parseFields(rb.r.text) : null;
    if (fa && fb) {
      const disputed = [];
      const merged = mergeFields(fa, fb, disputed);
      job.disputed = disputed.filter((v, i, s) => s.indexOf(v) === i);
      return { text: JSON.stringify(merged), src: [].concat(ra.r.src || [], rb.r.src || []), premerged: merged };
    }
    if (fa) return Object.assign({}, ra.r, { premerged: fa });
    if (fb) return Object.assign({}, rb.r, { premerged: fb });
    const fast = await runOnce(fieldsFastPrompt, 110000);
    return fast;
  })();
  const narrWork = runOnce(narrativePrompt, 290000);

  const [fRes, nRes] = await Promise.allSettled([fieldsWork, narrWork]);
  const fOk = fRes.status === "fulfilled";
  const nOk = nRes.status === "fulfilled";
  let fields = fOk ? (fRes.value.premerged || parseFields(fRes.value.text)) : null;
  const fieldsOk = !!fields;
  let report = nOk ? String(nRes.value.text || "").replace(/```json[\s\S]*?```/i, "").trim() : "";

  if (!fieldsOk && !report) {
    const reasons = [String(fRes.reason || ""), String(nRes.reason || "")].join(" ");
    job.status = "error";
    job.error = /timeout/.test(reasons) ? "timeout" : (reasons.match(/http_\d+|fetch failed/) || ["analysis_failed"])[0];
    return;
  }
  const seen = {}, sources = [];
  [].concat(fOk ? fRes.value.src : [], nOk ? nRes.value.src : []).forEach(u => { if (u && !seen[u]) { seen[u] = 1; sources.push({ url: u, name: u.replace(/^https?:\/\//, "").split("/")[0] }); } });
  districtLearn(fields, "report");
  job.status = "done";
  job.fields = fields || {};
  job.report = report || "";
  job.sources = sources;
  job.missing = !fieldsOk ? "fields" : (!report ? "report" : null);
  try {
    reportCache.set(cacheKey(job.address), { fields: job.fields, report: job.report, sources: job.sources, missing: job.missing, disputed: job.disputed || [], at: Date.now() });
    if (reportCache.size > 500) { const ks = [...reportCache.keys()]; for (let k = 0; k < ks.length - 500; k++) reportCache.delete(ks[k]); }
    cacheSave();
  } catch (e) {}
}

// ---------- AI comps (background job) ----------
const compsJobs = new Map();
app.post("/api/comps", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable comps." });
  const address = String((req.body && req.body.address) || "").trim();
  if (!address) return res.status(400).json({ ok: false, error: "no_address" });
  const type = String((req.body && req.body.type) || "").slice(0, 120);
  const sqft = Number((req.body && req.body.sqft) || 0) || null;
  const id = zrNewId();
  const job = { id, status: "running", started: Date.now(), address, comps: [], sources: [], error: "" };
  compsJobs.set(id, job);
  runCompsJob(job, type, sqft).catch(e => { job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 200); });
  if (compsJobs.size > 50) { const ks = [...compsJobs.keys()]; for (let k = 0; k < ks.length - 50; k++) compsJobs.delete(ks[k]); }
  res.json({ ok: true, id });
});
app.get("/api/comps/:id", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const job = compsJobs.get(String(req.params.id || ""));
  if (!job) return res.status(404).json({ ok: false, error: "not_found", message: "That comps id is unknown — start a new pull." });
  const elapsed = Math.round((Date.now() - job.started) / 1000);
  if (job.status === "running" && elapsed > 240) { job.status = "error"; job.error = "Ran out of time — try again."; }
  res.json({ ok: true, id: job.id, status: job.status, elapsed, comps: job.comps, sources: job.sources.slice(0, 8), error: job.error });
});
async function runCompsJob(job, type, sqft) {
  const prompt = `You are a New England residential comps analyst. Use Google Search to find RECENTLY SOLD comparable properties near: ${job.address}
PRODUCT: ${type || "residential"}${sqft ? " around " + sqft + " finished sq ft" : ""}.
RULES: SOLD (closed) sales ONLY — never active or pending listings. Prefer the last 12 months (18 max). Same town, closest first — same street or immediate neighborhood beats distance. Return 4 to 6 comps. Use Zillow / Redfin / Realtor.com sold pages, town assessor sale records, and news of recent sales found via search. sale_price must be the actual closed price. sqft is FINISHED LIVING area. If you cannot verify a number from a source, skip that comp entirely — never invent.
Respond ONLY with JSON, no prose:
{"comps":[{"address":"","sale_price":0,"sqft":0,"sold_date":"YYYY-MM","note":"1-line similarity note"}]}`;
  const gr = await Promise.race([
    geminiFetch({ contents: [{ parts: [{ text: prompt }] }], tools: [{ google_search: {} }], generationConfig: { temperature: 0, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 4096 } } }, 3),
    new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 200000))
  ]);
  if (!gr || !gr.ok) throw new Error("http_" + (gr ? gr.status : 0));
  const data = await gr.json();
  const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
  const text = parts.map(p => p.text || "").join("").trim();
  const gm = ((data.candidates || [])[0] || {}).groundingMetadata || {};
  job.sources = (gm.groundingChunks || []).map(c => c.web && c.web.uri).filter(Boolean);
  let t = text; const fence = t.match(/\`\`\`json\s*([\s\S]*?)\`\`\`/i) || t.match(/\`\`\`\s*(\{[\s\S]*?\})\s*\`\`\`/);
  if (fence) t = fence[1].trim();
  const m = t.match(/\{[\s\S]*\}/);
  let obj = null; try { obj = JSON.parse(m ? m[0] : t); } catch (e) {}
  const rows = (obj && Array.isArray(obj.comps)) ? obj.comps : [];
  job.comps = rows.filter(r => r && r.address && Number(r.sale_price) > 10000 && Number(r.sqft) > 100).slice(0, 8)
    .map(r => ({ address: String(r.address).slice(0, 140), sale_price: Math.round(Number(r.sale_price)), sqft: Math.round(Number(r.sqft)), sold_date: String(r.sold_date || "").slice(0, 10), note: String(r.note || "").slice(0, 160) }));
  job.status = "done";
}

app.post("/api/zoning-report", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable the zoning report." });
  const address = String((req.body && req.body.address) || "").trim();
  if (!address) return res.status(400).json({ ok: false, error: "no_address" });
  const force = !!(req.body && req.body.force);
  const hit = !force && reportCache.get(cacheKey(address));
  if (hit && (Date.now() - hit.at) < 90 * 24 * 3600 * 1000) {
    const cid = zrNewId();
    zoningReports.set(cid, { id: cid, status: "done", started: Date.now(), address, report: hit.report || "", fields: hit.fields || {}, sources: hit.sources || [], error: "", missing: hit.missing || null, disputed: hit.disputed || [], cached: true, cachedAt: hit.at });
    return res.json({ ok: true, id: cid, cached: true });
  }
  const id = zrNewId();
  const job = { id, status: "running", started: Date.now(), address, report: "", fields: {}, sources: [], error: "", missing: null };
  zoningReports.set(id, job);
  runZoningReport(job).catch(e => { job.status = "error"; job.error = String(e && e.message ? e.message : e).slice(0, 200); });
  if (zoningReports.size > 50) { const ks = [...zoningReports.keys()]; for (let k = 0; k < ks.length - 50; k++) zoningReports.delete(ks[k]); }
  res.json({ ok: true, id });
});

app.get("/api/zoning-report/:id", ensureAuth, (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  const job = zoningReports.get(String(req.params.id || ""));
  if (!job) return res.status(404).json({ ok: false, error: "not_found", message: "That report id is unknown — start a new one." });
  const elapsed = Math.round((Date.now() - job.started) / 1000);
  if (job.status === "running") return res.json({ ok: true, status: "running", elapsed });
  if (job.status === "error") return res.json({ ok: true, status: "error", elapsed, error: job.error });
  return res.json({ ok: true, status: "done", elapsed, report: job.report, fields: job.fields, sources: job.sources, missing: job.missing || null, disputed: job.disputed || [], cached: !!job.cached, cachedAt: job.cachedAt || null });
});

// Call Gemini with retry AND model fallback: if the configured model is overloaded (503) or
// rate-limited (429), retry with backoff, then fall back to other flash models so "high demand"
// on the newest model never breaks the AI features. 404 (unknown model) skips straight to the next.
async function geminiFetch(payload, tries, apiKey) {
  tries = tries || 2;
  const key = apiKey || GEMINI_API_KEY;
  const models = [GEMINI_MODEL, "gemini-2.5-flash", "gemini-2.0-flash", "gemini-flash-latest"].filter((m, i, a) => m && a.indexOf(m) === i);
  let last;
  for (let mi = 0; mi < models.length; mi++) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${models[mi]}:generateContent`;
    for (let i = 0; i < tries; i++) {
      let gr;
      try {
        gr = await fetch(url, { method: "POST", headers: { "x-goog-api-key": key, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      } catch (netErr) {
        if (i < tries - 1) { await new Promise(r => setTimeout(r, 900 * (i + 1))); continue; }
        break;
      }
      if (gr.ok) return gr;
      last = gr;
      if (gr.status === 400 && payload && payload.generationConfig && payload.generationConfig.thinkingConfig) {
        payload = JSON.parse(JSON.stringify(payload));
        delete payload.generationConfig.thinkingConfig;
        continue;                                                                    // same model, config stripped
      }
      if (gr.status === 404) break;                                                   // unknown model -> next
      if ((gr.status >= 500 || gr.status === 429) && i < tries - 1) { await new Promise(r => setTimeout(r, gr.status === 429 ? (12000 + Math.floor(Math.random() * 6000)) : 900 * (i + 1))); continue; }
      if (gr.status >= 500 || gr.status === 429) break;                               // busy/erroring -> next model
      return gr;                                                                      // other error -> stop
    }
  }
  return last;
}

// --- AI writing helper: polish any description/notes text via Gemini (signed-in users) ---
app.post("/api/ai/rewrite", ensureAuth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable AI writing." });
  const text = String((req.body && req.body.text) || "").trim();
  if (!text) return res.status(400).json({ ok: false, error: "no_text" });
  if (text.length > 6000) return res.status(400).json({ ok: false, error: "too_long", message: "That text is too long to rewrite (max ~6000 chars)." });
  const kind = String((req.body && req.body.kind) || "").slice(0, 60);
  const prompt = `You are an expert real estate copywriter for a Boston brokerage and property-management firm. Rewrite the text below so it reads clearly, professionally, and persuasively${kind ? (" (context: " + kind + ")") : ""}. Rules: keep it TRUTHFUL — never invent facts, numbers, addresses, amenities, or features that are not in the original; keep roughly the same length unless the original is clearly too terse; no hype or fair-housing-sensitive language. Return ONLY the rewritten text — no preamble, no quotes, no markdown.\n\nTEXT:\n${text}`;
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.6 } });
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", status: gr.status, message: t.slice(0, 200) }); }
    const data = await gr.json();
    const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
    let out = parts.map(p => p.text || "").join("").trim();
    out = out.replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    if (!out) return res.status(502).json({ ok: false, error: "empty", message: "The AI returned nothing — try again." });
    res.json({ ok: true, text: out });
  } catch (e) {
    res.status(502).json({ ok: false, error: "rewrite_failed", message: String(e).slice(0, 200) });
  }
});

// --- Voice note → one-line summary + suggested task title + due date (for the Voice Notes inbox) ---
app.post("/api/ai/voice-summary", ensureAuth, async (req, res) => {
  if (!(req.user.role === 'owner' || req.user.role === 'summit')) return res.status(403).json({ ok: false, error: 'forbidden' });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable AI summaries." });
  const text = String((req.body && req.body.text) || "").trim();
  if (!text) return res.status(400).json({ ok: false, error: "no_text" });
  const today = new Date().toISOString().slice(0, 10);
  const prompt = `You are an assistant for a real-estate wholesaler who dictates quick voice notes while cold-calling. From the note below, return STRICT JSON only (no markdown, no preamble) with exactly these keys:\n"summary": one short sentence capturing the point (max 22 words),\n"title": a short imperative task title if the note implies an action to take, else "" (max 8 words),\n"due": an ISO date YYYY-MM-DD if the note mentions or implies a deadline (today is ${today}), else "".\n\nNOTE:\n${text.slice(0,6000)}`;
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2 } });
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", status: gr.status, message: t.slice(0, 200) }); }
    const data = await gr.json();
    const parts = (((data.candidates || [])[0] || {}).content || {}).parts || [];
    let out = parts.map(p => p.text || "").join("").trim();
    out = out.replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    let obj = {}; try { obj = JSON.parse(out) || {}; } catch (e) { obj = { summary: out.slice(0, 200) }; }
    res.json({ ok: true, summary: String(obj.summary || "").slice(0, 300), title: String(obj.title || "").slice(0, 120), due: String(obj.due || "").slice(0, 20) });
  } catch (e) {
    res.status(502).json({ ok: false, error: "summary_failed", message: String(e).slice(0, 200) });
  }
});

// --- AI underwriting second-opinion: verdict + assumptions/pros/cons/risks from a deal's numbers ---
// Advisory only. The model reasons from the figures the analyst entered; it does NOT recompute
// their math and never invents numbers. Used by the "AI Assist" panel on the underwriter pages.
// ── REsimpli → hub webhook receiver ──────────────────────────────────────────
// REsimpli's servers POST here on the events John ticks in their Add Webhook
// screen (New Lead Created, Lead Status Change, Hot Lead, Qualified, etc.).
// No Google session on their side, so auth is a shared secret in the URL:
// the RESIMPLI_WEBHOOK_KEY env var must match ?key=. Events append to the
// resimpli_events note (newest first, capped) and the Summit dashboard shows
// them as a live activity feed.
const RESIMPLI_WEBHOOK_KEY = process.env.RESIMPLI_WEBHOOK_KEY || '';
const RESIMPLI_EVENTS_KEY = 'resimpli_events';
app.post('/api/resimpli/webhook', async (req, res) => {
  if (!RESIMPLI_WEBHOOK_KEY) return res.status(503).json({ ok: false, error: 'not_configured' });
  if (String(req.query.key || '') !== RESIMPLI_WEBHOOK_KEY) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const body = req.body || {};
    // keep each event small; the sheet note is not a data lake
    let slim; try { slim = JSON.parse(JSON.stringify(body)); } catch (e) { slim = {}; }
    let str = JSON.stringify(slim); if (str.length > 4000) { str = str.slice(0, 4000); }
    const ev = { at: new Date().toISOString(), event: String(body.event || body.type || body.trigger || body.webhookType || 'event').slice(0, 60), raw: str };
    let list = [];
    try {
      const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + RESIMPLI_EVENTS_KEY);
      const v = noteValue(j);
      if (v) list = JSON.parse(typeof v === 'string' ? v : JSON.stringify(v)) || [];
      if (!Array.isArray(list)) list = [];
    } catch (e) { list = []; }
    list.unshift(ev);
    if (list.length > 200) list.length = 200;
    await sheetPost(GROVE_SHEET_URL, noteBody(RESIMPLI_EVENTS_KEY, JSON.stringify(list)));
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 120) }); }
});

// ── Voice Note inbox webhook ─────────────────────────────────────────────────
// John records a voice note on his iPhone (Voicenotes / WhoiceWidget); the app
// (directly, or via a Zapier "Webhooks by Zapier" POST step) hits this URL with
// the transcript. No Google session on their side, so auth is a shared secret:
// SUMMIT_VOICE_KEY env (default below) must match ?key= OR a key/token field in
// the body. Notes append to summit_voicenotes (newest first, capped) and show on
// the Summit dashboard + the Voice Notes page, where John turns them into Tasks
// or Leads. Reads the transcript from any of several common field names so the
// same URL works no matter which app or Zap shape sends it.
const SUMMIT_VOICE_KEY = process.env.SUMMIT_VOICE_KEY || 'summit-voice-2026';
const SUMMIT_VOICE_KEY_NAME = 'summit_voicenotes';
function _voicePick(o, keys){ for (let i=0;i<keys.length;i++){ const v=o&&o[keys[i]]; if (v!=null && String(v).trim()!=='') return String(v); } return ''; }
app.post('/api/summit/voice', async (req, res) => {
  const body = (req.body && typeof req.body === 'object') ? req.body : {};
  const key = String(req.query.key || body.key || body.token || '');
  if (key !== SUMMIT_VOICE_KEY) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    // Voicenotes nests the note under `data` and names the event (e.g. "recording.created",
    // "creation.summary"). WhoiceWidget posts flat {transcription:"..."}. Zapier/direct post
    // flat {transcript:"..."}. Read from body first, then body.data, so one URL fits all three.
    const d = (body.data && typeof body.data === 'object') ? body.data : {};
    const pick = (keys) => { for (let i=0;i<keys.length;i++){ let v=body[keys[i]]; if(v!=null&&String(v).trim()!=='') return String(v); v=d[keys[i]]; if(v!=null&&String(v).trim()!=='') return String(v); } return ''; };
    const event = String(body.event || '').toLowerCase();
    // "content"/"transcription" only: transcript-bearing fields, NOT summary/todo payloads.
    const transcript = pick(['transcript','transcription','text','note','recognizedText','message']);
    if (!transcript) {
      // Voicenotes fires secondary events (summary, to-do, main-points) with no transcript —
      // acknowledge them so the app doesn't flag a failure, but don't add an empty inbox row.
      if (/^creation\.|summary|todo|to-do|main/.test(event)) return res.json({ ok: true, skipped: 'secondary_event' });
      return res.status(400).json({ ok: false, error: 'no_transcript' });
    }
    let source = pick(['source','app','from','provider']);
    if (!source) {
      if (event.startsWith('recording') || event.startsWith('creation') || body.data) source = 'Voicenotes';
      // Whoice Widget's signature: a flat body whose only content is `transcription`.
      else if (body.transcription != null && String(body.transcription).trim() !== '') source = 'Whoice Widget';
      else source = 'other';
    }
    const note = {
      id: 'v' + Date.now().toString(36) + Math.floor(Math.random()*1e4).toString(36),
      at: (function(){ const t = pick(['at','timestamp','created','createdAt','date','time']); const dd = t ? new Date(t) : new Date(); return isNaN(+dd) ? new Date().toISOString() : dd.toISOString(); })(),
      title: pick(['title','subject','name']).slice(0, 140),
      transcript: String(transcript).slice(0, 8000),
      summary: pick(['summary','ai_summary','aiSummary','abstract']).slice(0, 600),
      source: source.slice(0, 40),
      due: pick(['due','dueDate','due_date']).slice(0, 40),
      status: 'New'
    };
    let list = [];
    try {
      const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + SUMMIT_VOICE_KEY_NAME);
      const v = noteValue(j);
      if (v) list = JSON.parse(typeof v === 'string' ? v : JSON.stringify(v)) || [];
      if (!Array.isArray(list)) list = [];
    } catch (e) { list = []; }
    list.unshift(note);
    if (list.length > 300) list.length = 300;
    await sheetPost(GROVE_SHEET_URL, noteBody(SUMMIT_VOICE_KEY_NAME, JSON.stringify(list)));
    res.json({ ok: true, id: note.id });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 120) }); }
});

// Push a lead INTO REsimpli. Their lead-creation API is only exposed through
// Zapier, so this forwards to a "Webhooks by Zapier" catch URL (env
// RESIMPLI_ZAP_URL) whose Zap runs REsimpli "Create Lead". John + Summit only.
const RESIMPLI_ZAP_URL = process.env.RESIMPLI_ZAP_URL || '';
app.post('/api/resimpli/push', ensureAuth, async (req, res) => {
  if (!(req.user.role === 'owner' || req.user.role === 'summit'))
    return res.status(403).json({ ok: false, error: 'forbidden' });
  if (!RESIMPLI_ZAP_URL) return res.status(503).json({ ok: false, error: 'not_configured', message: 'The REsimpli Zap isn\'t set up yet — one-time Zapier step needed.' });
  const b = req.body || {};
  const lead = {
    name: String(b.name || '').slice(0, 120),
    address: String(b.address || '').slice(0, 200),
    phone: String(b.phone || '').slice(0, 40),
    email: String(b.email || '').slice(0, 120),
    source: String(b.source || 'GPG Hub').slice(0, 80),
    notes: String(b.notes || '').slice(0, 800),
    sentBy: req.user.name || req.user.email || ''
  };
  if (!lead.address && !lead.name) return res.status(400).json({ ok: false, error: 'no_lead' });
  try {
    const r = await fetch(RESIMPLI_ZAP_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(lead) });
    if (!r.ok) throw new Error('zap_http_' + r.status);
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: 'push_failed', message: String(e).slice(0, 120) }); }
});

// AI cost estimator for the underwriters: given the deal's known numbers, fill
// in conservative estimates for the soft-cost / expense / carry fields the user
// left blank. Estimates only — the page shows them for review before applying.
app.post("/api/ai/uw-estimate", ensureAuth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable AI estimates." });
  const b = req.body || {};
  const type = String(b.type || "deal").slice(0, 40);
  const ctx = Array.isArray(b.context) ? b.context.slice(0, 60) : [];
  const targets = Array.isArray(b.targets) ? b.targets.slice(0, 30) : [];
  if (!targets.length) return res.status(400).json({ ok: false, error: "no_targets", message: "Nothing to estimate — every cost field already has a number." });
  const ctxLines = ctx.map(f => `- ${String(f.label || "").slice(0, 80)}: ${String(f.value == null ? "" : f.value).slice(0, 60)}`).join("\n");
  const tgtLines = targets.map(t => `- id "${String(t.id || "").slice(0, 40)}": ${String(t.label || "").slice(0, 90)}`).join("\n");
  const prompt = `You are a conservative Massachusetts real-estate underwriter. A Boston-area investor is underwriting a ${type} deal. Known inputs:
${ctxLines || "- (nothing entered yet)"}

Estimate a realistic, CONSERVATIVE value for each field below. Read each label carefully — respect its unit ($ vs %, monthly vs annual, per-unit vs total). Lean slightly high on costs. Use Massachusetts norms (property tax ~1.0-1.3% of value/yr unless the label says otherwise, insurance $1,500-$2,500/unit/yr, water/sewer Boston-area rates, 5-8% management, closing costs 1.5-2.5% of price, holding = taxes+insurance+utilities monthly, etc.).
Return ONLY a JSON object, no markdown:
{
 "values": { "<field id>": <number>, ... },
 "basis": ["one short line per field explaining the number, prefixed by its label"]
}
Every target id must appear in "values". Numbers only — no strings, no symbols.

FIELDS TO ESTIMATE:
${tgtLines}`;
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 2048, thinkingConfig: { thinkingBudget: 0 } } });
    if (!gr.ok) return res.status(502).json({ ok: false, error: "gemini_http", message: "AI service error — try again." });
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let txt = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = txt.match(/\{[\s\S]*\}/);
    let obj = null; try { obj = JSON.parse(mm ? mm[0] : txt); } catch (e) { obj = null; }
    if (!obj || typeof obj.values !== "object" || !obj.values) return res.status(502).json({ ok: false, error: "parse_failed", message: "The AI reply came back incomplete — try again." });
    // numbers only, and only for the ids that were asked about
    const clean = {};
    targets.forEach(t => { const v = Number(obj.values[t.id]); if (isFinite(v) && v >= 0) clean[t.id] = Math.round(v * 100) / 100; });
    res.json({ ok: true, values: clean, basis: Array.isArray(obj.basis) ? obj.basis.slice(0, 30).map(x => String(x).slice(0, 160)) : [] });
  } catch (e) { res.status(502).json({ ok: false, error: "uw_estimate_failed", message: String(e).slice(0, 200) }); }
});

app.post("/api/ai/uw-summary", ensureAuth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable AI underwriting help." });
  const b = req.body || {};
  const type = String(b.type || "deal").slice(0, 40);
  const fields = Array.isArray(b.fields) ? b.fields.slice(0, 120) : [];
  if (!fields.length) return res.status(400).json({ ok: false, error: "no_fields", message: "Enter the deal's numbers first." });
  const lines = fields.map(f => `- ${String(f.label || f.id || "").slice(0, 80)}: ${String(f.value == null ? "" : f.value).slice(0, 60)}`).join("\n");
  const prompt = `You are a conservative real-estate investment underwriter giving a Boston investor a brief second opinion on a ${type} deal. Below are the inputs and figures the analyst entered.
Reason from the numbers AS GIVEN — do not recompute their math, and never invent a figure that isn't implied by the inputs. Flag anything thin, missing, or optimistic.
Return ONLY a JSON object (no markdown, no code fence), exactly this shape:
{
 "verdict": "Strong" | "Proceed" | "Proceed with caution" | "Pass",
 "headline": "one sentence, under 120 chars",
 "assumptions": ["2-4 short items to verify or that are being assumed"],
 "pros": ["2-4 short"],
 "cons": ["1-3 short"],
 "risks": ["2-4 short key risks"]
}
Keep each item under ~90 chars, plain and specific to these numbers.

INPUTS (${type}):
${lines}`;
  try {
    // maxOutputTokens high + thinkingBudget 0: 2.5-flash otherwise spends the budget
    // "thinking" and truncates the JSON, which then fails to parse. This structured
    // task needs no thinking, so send the whole budget to the answer.
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.3, maxOutputTokens: 2048, thinkingConfig: { thinkingBudget: 0 } } });
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", message: "AI service error — try again." }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let txt = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = txt.match(/\{[\s\S]*\}/);
    let obj = null; try { obj = JSON.parse(mm ? mm[0] : txt); } catch (e) { obj = null; }
    if (!obj || typeof obj !== "object") return res.status(502).json({ ok: false, error: "parse_failed", message: "The AI reply came back incomplete — tap Re-run.", raw: txt.slice(0, 300) });
    res.json({ ok: true, summary: obj });
  } catch (e) { res.status(502).json({ ok: false, error: "uw_summary_failed", message: String(e).slice(0, 200) }); }
});

// --- AI document extraction: read an uploaded PDF/photo and pull requested fields (signed-in users) ---
// Voice-memo transcription (owner only): John records audit notes on his phone,
// the hub turns them into a verbatim transcript + action items via Gemini.
app.post("/api/ai/transcribe", ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server." });
  const b = req.body || {};
  const data = String(b.data || "");
  const mime = String(b.mime || "audio/mp4").slice(0, 60).toLowerCase();
  if (!data) return res.status(400).json({ ok: false, error: "no_file" });
  if (data.length > 12000000) return res.status(400).json({ ok: false, error: "too_large", message: "Audio too large — compress it first (max ~8MB)." });
  if (!/^audio\/(mp4|m4a|mpeg|mp3|aac|ogg|opus|wav|flac|webm)$/.test(mime)) return res.status(400).json({ ok: false, error: "bad_type" });
  const prompt = "Transcribe this voice memo VERBATIM (it is a real-estate operator dictating website fixes while walking). Then list every distinct request as a numbered action item, quoting his words where useful. Return ONLY JSON: {\"transcript\": \"...\", \"items\": [\"...\"]}";
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ inlineData: { mimeType: mime, data: data } }, { text: prompt }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 0 } } });
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", message: t.slice(0, 200) }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let text = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = text.match(/\{[\s\S]*\}/);
    let vals = null; try { vals = JSON.parse(mm ? mm[0] : text); } catch (e) { vals = null; }
    if (!vals) return res.status(502).json({ ok: false, error: "parse_failed", raw: text.slice(0, 300) });
    res.json({ ok: true, transcript: String(vals.transcript || '').slice(0, 60000), items: Array.isArray(vals.items) ? vals.items.slice(0, 40) : [] });
  } catch (e) { res.status(502).json({ ok: false, error: "transcribe_failed", message: String(e).slice(0, 200) }); }
});

app.post("/api/ai/extract", ensureAuth, async (req, res) => {
  const b = req.body || {};
  const co = normCo(b.co);                         // which company's key/card to bill
  const apiKey = geminiKeyFor(co);
  if (!apiKey) return res.status(400).json({ ok: false, error: "no_key", message: "No Gemini key set for " + co + ". Add GEMINI_API_KEY_" + co.toUpperCase() + " (or GEMINI_API_KEY) on the server." });
  const data = String(b.data || "");
  const mime = String(b.mime || "application/pdf").slice(0, 80).toLowerCase();
  const fields = Array.isArray(b.fields) ? b.fields.slice(0, 40) : [];
  if (!data) return res.status(400).json({ ok: false, error: "no_file" });
  if (data.length > 9000000) return res.status(400).json({ ok: false, error: "too_large", message: "That file is too large (max ~6MB). Try a single page or a photo." });
  if (!/^(application\/pdf|image\/(png|jpe?g|webp|heic|heif))$/.test(mime)) return res.status(400).json({ ok: false, error: "bad_type", message: "Please upload a PDF or a photo." });
  if (!fields.length) return res.status(400).json({ ok: false, error: "no_fields" });
  const schemaLines = fields.map(f => {
    const key = String(f.key || "").replace(/[^a-zA-Z0-9_]/g, "");
    const t = f.type === "number" ? "number|null" : (f.type === "rows" ? "array of objects (one per row)" : "string|null");
    return `  "${key}": ${t}${(f.label || f.hint) ? ("   // " + [f.label, f.hint].filter(Boolean).join(" — ")) : ""}`;
  }).join("\n");
  const prompt = `You are a real-estate document data-extraction assistant. Read the attached document and extract the fields below into ONE JSON object. Return ONLY the JSON — no markdown, no code fences, no commentary. Rules: numbers must be plain (no $, commas, or units); dates as written; use null when a value is not clearly present; NEVER guess or invent a value that is not in the document.\n\nReturn exactly this shape:\n{\n${schemaLines}\n}`;
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ inlineData: { mimeType: mime, data: data } }, { text: prompt }] }], generationConfig: { temperature: 0.1 } }, 2, apiKey);
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", status: gr.status, message: t.slice(0, 200) }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let text = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = text.match(/\{[\s\S]*\}/);
    let vals = null; try { vals = JSON.parse(mm ? mm[0] : text); } catch (e) { vals = null; }
    if (!vals) return res.status(502).json({ ok: false, error: "parse_failed", raw: text.slice(0, 400) });
    bumpAIUsage('extract', 1, co);
    res.json({ ok: true, values: vals });
  } catch (e) {
    res.status(502).json({ ok: false, error: "extract_failed", message: String(e).slice(0, 200) });
  }
});

// ── AI transaction categorizer ───────────────────────────────────────────────
// Takes a batch of bank/card line items plus THIS company's chart of accounts and
// returns one category id per row (same order). Used by the Books import feed's
// "✨ AI categorize" button and auto-run after a statement upload. Company scope
// (Citicore vs Summit) is decided client-side by which books the user is in — this
// only maps a description+amount to the best-fit account id.
app.post("/api/ai/categorize", ensureAuth, async (req, res) => {
  const b = req.body || {};
  const co = normCo(b.co);
  const apiKey = geminiKeyFor(co);
  if (!apiKey) return res.status(400).json({ ok: false, error: "no_key", message: "No Gemini key set for " + co + ". Add GEMINI_API_KEY_" + co.toUpperCase() + " (or GEMINI_API_KEY) on the server." });
  const rows = Array.isArray(b.rows) ? b.rows.slice(0, 300) : [];
  const cats = Array.isArray(b.cats) ? b.cats.slice(0, 120) : [];
  if (!rows.length) return res.status(400).json({ ok: false, error: "no_rows" });
  if (!cats.length) return res.status(400).json({ ok: false, error: "no_cats" });
  const catLines = cats.map(c => `  "${String(c.id || "").replace(/[^a-zA-Z0-9_]/g, "")}" = ${String(c.name || "").slice(0, 60)}${c.type ? (" (" + String(c.type).slice(0, 20) + ")") : ""}`).join("\n");
  const validIds = new Set(cats.map(c => String(c.id || "").replace(/[^a-zA-Z0-9_]/g, "")));
  const rowLines = rows.map((r, i) => `${i}. ${String(r.desc || "").slice(0, 140)} | amount ${Number(String(r.amt).replace(/[^0-9.\-]/g, "")) || 0}`).join("\n");
  const prompt = `You are a bookkeeper for a real-estate company. Assign the single best-fit account id to each transaction below. Positive amount = money in (income/deposit), negative = money out (expense/payment). Use ONLY these account ids:\n${catLines}\n\nTransactions (index. description | amount):\n${rowLines}\n\nReturn ONLY a JSON array of strings, one per transaction IN ORDER, each an account id from the list above. If none clearly fits a row, use "" (empty string) for that row. No markdown, no commentary. Example: ["rent","util","",...]`;
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1 } }, 2, apiKey);
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", status: gr.status, message: t.slice(0, 200) }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let text = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = text.match(/\[[\s\S]*\]/);
    let arr = null; try { arr = JSON.parse(mm ? mm[0] : text); } catch (e) { arr = null; }
    if (!Array.isArray(arr)) return res.status(502).json({ ok: false, error: "parse_failed", raw: text.slice(0, 400) });
    const out = rows.map((r, i) => { const v = String(arr[i] == null ? "" : arr[i]).replace(/[^a-zA-Z0-9_]/g, ""); return validIds.has(v) ? v : ""; });
    bumpAIUsage('categorize', 1, co);
    res.json({ ok: true, categories: out });
  } catch (e) {
    res.status(502).json({ ok: false, error: "categorize_failed", message: String(e).slice(0, 200) });
  }
});

// AI usage / cost meter — owner-only. Returns today, this month, all-time counts
// and estimated cents (see AI_COST_CENTS). Estimates only; the real bill is on the
// Gemini account tied to GEMINI_API_KEY.
app.get("/api/ai/usage", ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: "owner_only" });
  const u = await _aiUsageLoad();
  const today = _aiDay(), month = today.slice(0, 7);
  const sum = (pred) => {
    const o = { extract: 0, categorize: 0, petition: 0, cents: 0, byco: { citicore: 0, summit: 0, grove: 0 } };
    Object.keys(u.days || {}).forEach(d => {
      if (!pred(d)) return;
      const x = u.days[d];
      o.extract += x.extract || 0; o.categorize += x.categorize || 0; o.petition += x.petition || 0; o.cents += x.cents || 0;
      const bc = x.byco || {}; o.byco.citicore += bc.citicore || 0; o.byco.summit += bc.summit || 0; o.byco.grove += bc.grove || 0;
    });
    o.cents = Math.round(o.cents * 100) / 100;
    o.byco.citicore = Math.round(o.byco.citicore * 100) / 100; o.byco.summit = Math.round(o.byco.summit * 100) / 100; o.byco.grove = Math.round(o.byco.grove * 100) / 100;
    return o;
  };
  const todayRec = u.days[today] || { extract: 0, categorize: 0, petition: 0, cents: 0, byco: { citicore: 0, summit: 0, grove: 0 } };
  if (!todayRec.byco) todayRec.byco = { citicore: 0, summit: 0, grove: 0 };
  res.json({
    ok: true,
    rates: AI_COST_CENTS,
    keys: { citicore: !!GEMINI_API_KEY_CITICORE, summit: !!GEMINI_API_KEY_SUMMIT, grove: !!(GEMINI_API_KEY_GROVE || GEMINI_API_KEY) },
    today: todayRec,
    month: sum(d => d.slice(0, 7) === month),
    total: u.total || { extract: 0, categorize: 0, petition: 0, cents: 0, byco: { citicore: 0, summit: 0, grove: 0 } }
  });
});

// ── Petition auto-extract (token-gated; used by the probate scraper) ──────────
// The scraper on the droplet has no hub login, so it can't call /api/ai/extract
// (which is ensureAuth). This mirror endpoint takes a shared token instead and
// runs the SAME Gemini extraction on the petition PDF the scraper just pulled off
// masscourts. Returns the petitioner/decedent fields; the scraper folds them into
// the lead it already posts to the sheet, so the board auto-fills them — no more
// tapping "Read the filing" by hand. Set PETITION_TOKEN in the environment to
// rotate the shared secret; it defaults to the same token the scraper already uses.
const PETITION_TOKEN = process.env.PETITION_TOKEN || "grove-sheet-2026";
app.post("/api/lead-list/petition-extract", async (req, res) => {
  const b = req.body || {};
  if (String(b.token || "") !== PETITION_TOKEN) return res.status(403).json({ ok: false, error: "bad_token" });
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server." });
  const data = String(b.data || "");
  const mime = String(b.mime || "application/pdf").slice(0, 80).toLowerCase();
  if (!data) return res.status(400).json({ ok: false, error: "no_file" });
  if (data.length > 9000000) return res.status(400).json({ ok: false, error: "too_large" });
  if (!/^(application\/pdf|image\/(png|jpe?g|webp))$/.test(mime)) return res.status(400).json({ ok: false, error: "bad_type" });
  const prompt = [
    "You are a probate-filing data-extraction assistant. Read the attached Massachusetts probate petition PDF and return ONE JSON object with EXACTLY the keys below. Return ONLY the JSON — no markdown, no code fences, no commentary.",
    "Rules: use null when a value is not clearly present; NEVER guess or invent a value that is not in the document; write phone numbers as digits with dashes; write each address as a single line like 'street, city, ST zip'.",
    "",
    "{",
    '  "decedent_address": string|null,   // the deceased person\'s residence at death (usually the subject property)',
    '  "petitioner_name": string|null,    // the person filing the petition (the proposed Personal Representative / fiduciary)',
    '  "petitioner_address": string|null, // the petitioner\'s own mailing/home address',
    '  "petitioner_phone": string|null,',
    '  "petitioner_email": string|null,',
    '  "date_of_death": string|null,      // as written on the filing',
    '  "testate": string|null             // "Will" if a will is filed (testate), "No will" if intestate, else null',
    "}"
  ].join("\n");
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ inlineData: { mimeType: mime, data: data } }, { text: prompt }] }], generationConfig: { temperature: 0.1 } });
    if (!gr || !gr.ok) { const t = gr ? await gr.text() : ""; return res.status(502).json({ ok: false, error: "gemini_http", status: gr ? gr.status : 0, message: t.slice(0, 200) }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let text = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = text.match(/\{[\s\S]*\}/);
    let vals = null; try { vals = JSON.parse(mm ? mm[0] : text); } catch (e) { vals = null; }
    if (!vals) return res.status(502).json({ ok: false, error: "parse_failed", raw: text.slice(0, 400) });
    bumpAIUsage('petition', 1);
    res.json({ ok: true, values: vals });
  } catch (e) {
    res.status(502).json({ ok: false, error: "extract_failed", message: String(e).slice(0, 200) });
  }
});

// --- AI deal parser: a broker's shorthand -> structured deal + split lines ---
app.post("/api/ai/parse-deal", ensureAuth, async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, error: "no_key", message: "Set GEMINI_API_KEY on the server to enable AI deal entry." });
  const b = req.body || {};
  const text = String(b.text || "").trim();
  if (!text) return res.status(400).json({ ok: false, error: "no_text" });
  if (text.length > 2000) return res.status(400).json({ ok: false, error: "too_long", message: "That's too long — keep the deal description short." });
  const roster = (Array.isArray(b.agents) ? b.agents : []).map(a => String(a || "").trim()).filter(Boolean).slice(0, 80);
  const rosterLine = roster.length ? roster.join(", ") : "GROVE";
  const prompt = [
    "You convert a broker's shorthand about ONE real-estate deal into a strict JSON object.",
    "Return ONLY the JSON — no markdown, no code fences, no commentary.",
    "",
    "AGENT ROSTER (map every person to EXACTLY one of these names, matching their case): " + rosterLine + ".",
    "The words grove, house, brokerage, or office all map to GROVE (the house's cut). If a person has no close match on the roster, use their name in UPPERCASE as written.",
    "",
    "HOW TO READ SPLITS:",
    "- \"<amount> split <p1>/<p2> <name1> <name2>\" means name1 gets p1% of amount and name2 gets p2% of amount. Example: \"2000 split 75/25 john grove\" -> JOHN 1500, GROVE 500.",
    "- \"<amount> split <p1> <name1> <p2> <name2>\" is the same idea. Example: \"2000 split 75 joe 25 grove\" -> JOE 1500, GROVE 500.",
    "- A plain \"<amount> <name>\" with no percentages means that whole amount goes to that name.",
    "- COMBINE the same agent across every split into ONE line with the summed amount (e.g. GROVE at 500 in two splits becomes one GROVE line of 1000).",
    "",
    "OTHER RULES:",
    "- fee = the total commission/fee stated for the deal (e.g. \"4000 fee\" -> fee 4000). The split line amounts should add up to fee.",
    "- All numbers plain: no dollar signs, no commas, no percent signs.",
    "- type: \"Rental\" if it mentions rent, lease, tenant, or landlord; otherwise \"Sale\".",
    "- feeStatus: \"collected\" if it says collected/paid/received; \"not\" if it says not collected; otherwise \"pending\".",
    "- property = the street address text. unit = a unit/apt number only if stated, else null.",
    "- stage: one of Prospect, For Sale, Under Agreement, Closed, Dead if clearly implied, else null.",
    "- date: YYYY-MM-DD only if an explicit date is given, else null.",
    "- If anything is unclear, put a short note in \"warning\"; never invent people or amounts.",
    "",
    "Return EXACTLY this shape:",
    "{",
    '  "property": string,',
    '  "unit": string|null,',
    '  "type": "Sale"|"Rental",',
    '  "fee": number,',
    '  "feeStatus": "pending"|"collected"|"not",',
    '  "stage": string|null,',
    '  "date": string|null,',
    '  "lines": [ { "agent": string, "amount": number } ],',
    '  "warning": string|null',
    "}",
    "",
    "DEAL TEXT:",
    text
  ].join("\n");
  try {
    const gr = await geminiFetch({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1 } });
    if (!gr.ok) { const t = await gr.text(); return res.status(502).json({ ok: false, error: "gemini_http", status: gr.status, message: t.slice(0, 200) }); }
    const gd = await gr.json();
    const parts = (((gd.candidates || [])[0] || {}).content || {}).parts || [];
    let out = parts.map(p => p.text || "").join("").trim().replace(/^```[a-z]*\s*/i, "").replace(/```$/, "").trim();
    const mm = out.match(/\{[\s\S]*\}/);
    let deal = null; try { deal = JSON.parse(mm ? mm[0] : out); } catch (e) { deal = null; }
    if (!deal || typeof deal !== "object") return res.status(502).json({ ok: false, error: "parse_failed", raw: out.slice(0, 400) });
    deal.lines = Array.isArray(deal.lines) ? deal.lines.map(l => ({ agent: String((l && l.agent) || "").trim(), amount: Math.round((Number(l && l.amount) || 0) * 100) / 100 })).filter(l => l.agent && l.amount) : [];
    deal.fee = Math.round((Number(deal.fee) || 0) * 100) / 100;
    res.json({ ok: true, deal });
  } catch (e) {
    res.status(502).json({ ok: false, error: "parse_failed", message: String(e).slice(0, 200) });
  }
});

// ── Property lookup: address → assessed value + estimated tax ────────────────
// Type an address on any underwriter; this searches the MassGIS L3 parcel layer
// (the same source the probate scraper uses) and returns the assessed value.
// The parcel layer carries assessed value but NOT the annual tax bill, so tax is
// ESTIMATED = assessed × town residential rate / 1000 (clearly labeled "est.").
const ARC_PARCELS = "https://services1.arcgis.com/hGdibHYSPO59RG1h/arcgis/rest/services/Massachusetts_Property_Tax_Parcels/FeatureServer/0/query";
// Residential $/$1000 (approx, recent FY). Unknown towns fall back to DEFAULT.
const MA_MILL = { "BOSTON":10.9,"SOUTH BOSTON":10.9,"DORCHESTER":10.9,"QUINCY":11.5,"BRAINTREE":9.9,"MILTON":12.2,"WEYMOUTH":11.0,
  "CAMBRIDGE":5.9,"SOMERVILLE":10.3,"BROCKTON":12.5,"PLYMOUTH":13.9,"WORCESTER":13.8,"SPRINGFIELD":17.0,"NEWTON":9.9,"BROOKLINE":9.4,
  "BARNSTABLE":6.9,"HARWICH":7.5,"YARMOUTH":7.9,"DENNIS":5.9,"FALMOUTH":7.6,"BOURNE":8.8,"SANDWICH":11.5,"MASHPEE":7.0,"CHATHAM":4.0,"BREWSTER":7.8 };
const MILL_DEFAULT = 12.0;
function _sqlEsc(s){ return String(s||"").replace(/'/g,"''"); }
app.get("/api/property", ensureAuth, async (req, res) => {
  const raw = String(req.query.q || "").trim();
  if (raw.length < 3) return res.json({ ok: true, matches: [] });
  // street portion = text before the first comma; strip unit words
  let street = raw.split(",")[0].toUpperCase().replace(/[^0-9A-Z .\-]/g, " ").replace(/\s+/g, " ").trim();
  const cityGuess = (raw.split(",")[1] || "").toUpperCase().replace(/[^A-Z ]/g, "").trim();
  if (!street) return res.json({ ok: true, matches: [] });
  const where = "UPPER(SITE_ADDR) LIKE '" + _sqlEsc(street) + "%'" + (cityGuess ? (" AND UPPER(CITY)='" + _sqlEsc(cityGuess) + "'") : "");
  const url = ARC_PARCELS + "?where=" + encodeURIComponent(where)
    + "&outFields=" + encodeURIComponent("SITE_ADDR,CITY,ZIP,TOTAL_VAL,BLDG_VAL,LAND_VAL,YEAR_BUILT,USE_DESC,OWNER1")
    + "&returnGeometry=false&resultRecordCount=10&orderByFields=" + encodeURIComponent("SITE_ADDR") + "&f=json";
  try {
    const r = await fetch(url, { headers: { "User-Agent": "grove-hub/1.0" } });
    const j = await r.json();
    const feats = (j && j.features) || [];
    const seen = new Set();
    const matches = feats.map(f => f.attributes || {}).filter(a => a.SITE_ADDR).map(a => {
      const city = a.CITY || "";
      const assessed = Number(a.TOTAL_VAL) || 0;
      const rate = MA_MILL[String(city).toUpperCase()] || MILL_DEFAULT;
      const taxAnnual = Math.round(assessed * rate / 1000);
      return { addr: a.SITE_ADDR, city, zip: String(a.ZIP || "").slice(0, 5), assessed,
        bldg: Number(a.BLDG_VAL) || 0, land: Number(a.LAND_VAL) || 0, yearBuilt: a.YEAR_BUILT || "",
        use: a.USE_DESC || "", owner: a.OWNER1 || "", taxAnnual, taxRate: rate, taxEstimated: !MA_MILL[String(city).toUpperCase()] ? true : true };
    }).filter(m => { const k = (m.addr + "|" + m.city).toUpperCase(); if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 8);
    res.json({ ok: true, matches });
  } catch (e) { res.status(502).json({ ok: false, error: "lookup_failed", message: String(e).slice(0, 160) }); }
});

// recent Gmail snippets for the signed-in user
app.get("/api/gmail/recent", ensureAuth, async (req, res) => {
  try {
    const h = await gauth(req);
    const list = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=6&q=in:inbox", { headers: h }).then(r => r.json());
    const out = [];
    for (const m of (list.messages || [])) {
      const msg = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject`, { headers: h }).then(r => r.json());
      const hdr = n => (msg.payload?.headers || []).find(x => x.name === n)?.value || "";
      out.push({ from: hdr("From"), subject: hdr("Subject"), snippet: msg.snippet, date: Number(msg.internalDate) });
    }
    res.json(out);
  } catch (e) { res.status(502).json({ error: "gmail_failed" }); }
});


// ── The shared lead list ──────────────────────────────────────────────────────
// Where the leads actually live. Both scrapers on the droplet POST every lead
// they find to the "Pulled Leads" tab (probate and pre-foreclosure both — they
// share the tab and are told apart by the Source column). That has been the
// reliable half of the pipeline all along; nothing was reading it.
//
// This replaces the old /api/lead-feed, which read the SIGNED-IN USER's Gmail
// looking for a CSV attachment. Three things were wrong with that and only one
// of them was fixable:
//   1. it searched from:John@citicoreprops.com — the scraper sends from a
//      different account entirely, so the search never matched;
//   2. it required a .csv attachment — the scraper builds .xlsx;
//   3. it read the requester's own mailbox, so a second person looking at the
//      page would search THEIR inbox and find nothing.
// Reading the sheet instead fixes all three at once: one list, same for
// everyone, no Gmail permission needed, and it survives a cleared browser.
const LEAD_STATUS_KEY = 'lead_status';
const LEAD_STATES = ['new', 'working', 'contacted', 'dead', 'deal'];

// A stable id for a lead, so a status set today still points at the same lead
// after the scrapers append another two hundred rows. Built from the things that
// don't change: source, case number (or title) and the filing date.
function leadId(l) {
  const f = {};
  (l.fields || []).forEach(p => { if (p && p[0]) f[String(p[0]).toLowerCase()] = String(p[1] == null ? '' : p[1]); });
  const parts = [l.source || '', f['case #'] || l.title || '', f['filed'] || ''];
  return parts.join('|').toLowerCase().replace(/[^a-z0-9|]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
}

async function _sheetGetRaw(base, action, extra) {
  let url = base + sheetSep(base) + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN);
  if (action) url += '&action=' + encodeURIComponent(action);
  if (extra)  url += extra;
  return fetch(url).then(r => r.json());
}
async function _sheetPostRaw(base, body) {
  const r = await fetch(base, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: JSON.stringify(Object.assign({}, body, { token: GROVE_SHEET_TOKEN }))
  });
  return r.json();
}
// When DATABASE_URL is set, hub NOTES read/write through Postgres (read-through +
// dual-write to the Grove sheet). Everything else — and every non-Grove sheet —
// still goes straight to Apps Script. Unset DATABASE_URL = original behaviour.
// Pull the deals book straight from Sheets (used as the Postgres fallback/seed).
async function _dealsRaw(year) {
  const j = await _sheetGetRaw(GROVE_SHEET_URL, 'dealsLoad', year ? ('&year=' + encodeURIComponent(year)) : '');
  return (j && Array.isArray(j.deals)) ? j.deals : [];
}
async function sheetGet(base, action, extra) {
  if (gdb.on && action === 'notes' && base === GROVE_SHEET_URL) {
    const m = /[?&]notekey=([^&]+)/.exec(extra || '');
    const key = m ? decodeURIComponent(m[1]) : '';
    if (key) {
      const v = await gdb.noteGet(key, async (k) => noteValue(await _sheetGetRaw(base, 'notes', '&notekey=' + encodeURIComponent(k))));
      return { ok: true, value: v == null ? '' : v, notes: v == null ? '' : v };
    }
  }
  if (gdb.on && action === 'dealsLoad' && base === GROVE_SHEET_URL) {
    const m = /[?&]year=([^&]*)/.exec(extra || '');
    const year = m ? decodeURIComponent(m[1]) : '';
    const deals = await gdb.dealsBook(year, (y) => _dealsRaw(y));
    return { ok: true, deals: Array.isArray(deals) ? deals : [] };
  }
  return _sheetGetRaw(base, action, extra);
}
// Deal WRITE through Postgres (authoritative) + best-effort Sheets mirror. Used by
// the /api/grove POST proxy and by agentEditDeal. Non-deal actions never reach here.
async function dealWriteThrough(action, b) {
  const mirror = async () => { await _sheetPostRaw(GROVE_SHEET_URL, b); };
  if (action === 'updateDeal')   { await gdb.dealUpsert(b.oldKey, b.deal, mirror); return { ok: true }; }
  if (action === 'agentDeal')    { await gdb.dealUpsert(null, b.deal, mirror); return { ok: true, dealId: (b.deal && b.deal.dealId) || null }; }
  if (action === 'deleteDeal')   { await gdb.dealDelete(b.oldKey, (b.dealId != null ? b.dealId : b.id), mirror); return { ok: true }; }
  if (action === 'replaceDeals') { await gdb.dealsReplace(b.deals, mirror); return { ok: true }; }
  return _sheetPostRaw(GROVE_SHEET_URL, b);
}
const DEAL_WRITE_ACTIONS = new Set(['updateDeal', 'agentDeal', 'deleteDeal', 'replaceDeals']);
async function sheetPost(base, body) {
  if (gdb.on && body && body.action === 'notes' && base === GROVE_SHEET_URL && body.notekey != null) {
    const key = String(body.notekey);
    const val = body.value != null ? body.value : (body.notes != null ? body.notes : '');
    await gdb.noteSet(key, val, async () => { await _sheetPostRaw(base, body); });
    return { ok: true };
  }
  return _sheetPostRaw(base, body);
}

// The two scripts disagree about what a note is called: the Grove one answers
// {value:...} and takes `value`; the Summit one answers {notes:...} and takes
// `notes`. Read either, write both. Costs one extra JSON field and removes a
// whole class of silent no-op save.
function noteValue(j) {
  if (!j) return null;
  return j.value != null ? j.value : (j.notes != null ? j.notes : null);
}
function noteBody(key, str) {
  return { action: 'notes', notekey: key, value: str, notes: str };
}

// ── AI usage / cost meter ─────────────────────────────────────────────────────
// Every Gemini call (statement extract, transaction categorize, petition extract)
// is billed per use. We keep a lightweight per-day tally in the note store so the
// owner can see roughly what the AI features are costing. Estimates only — the real
// bill is on the Google/Gemini account tied to GEMINI_API_KEY. Costs are rough
// per-call cents (Gemini Flash class); override with env if pricing changes.
const AI_COST_CENTS = {
  extract:    Number(process.env.AI_COST_EXTRACT_CENTS    || 1.0),   // one PDF/photo statement
  categorize: Number(process.env.AI_COST_CATEGORIZE_CENTS || 0.3),   // one batch of transactions
  petition:   Number(process.env.AI_COST_PETITION_CENTS   || 1.0)    // one probate petition PDF
};
const AI_USAGE_KEY = 'ai_usage';
let _aiUsage = null;          // { days: { 'yyyy-mm-dd': {extract,categorize,petition,cents} }, total:{...} }
let _aiUsageDirty = false, _aiUsageTimer = null;
function _aiBlank() { return { days: {}, total: { extract: 0, categorize: 0, petition: 0, cents: 0, byco: { citicore: 0, summit: 0, grove: 0 } } }; }
function _aiDay() { return new Date().toISOString().slice(0, 10); }
async function _aiUsageLoad() {
  if (_aiUsage) return _aiUsage;
  try {
    const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(AI_USAGE_KEY));
    const v = noteValue(j);
    _aiUsage = v ? (typeof v === 'string' ? JSON.parse(v) : v) : _aiBlank();
  } catch (e) { _aiUsage = _aiBlank(); }
  if (!_aiUsage.days) _aiUsage.days = {};
  if (!_aiUsage.total) _aiUsage.total = { extract: 0, categorize: 0, petition: 0, cents: 0, byco: { citicore: 0, summit: 0, grove: 0 } };
  if (!_aiUsage.total.byco) _aiUsage.total.byco = { citicore: 0, summit: 0, grove: 0 };
  return _aiUsage;
}
function _aiUsageFlushSoon() {
  _aiUsageDirty = true;
  if (_aiUsageTimer) return;
  _aiUsageTimer = setTimeout(async () => {
    _aiUsageTimer = null;
    if (!_aiUsageDirty || !_aiUsage) return;
    _aiUsageDirty = false;
    try { await sheetPost(GROVE_SHEET_URL, noteBody(AI_USAGE_KEY, JSON.stringify(_aiUsage))); }
    catch (e) { _aiUsageDirty = true; }   // retry on next bump
  }, 4000);
}
function _aiCoBlank() { return { citicore: 0, summit: 0, grove: 0 }; }   // cents per company
// Fire-and-forget; never blocks or fails an AI response. `co` attributes the cost to
// the company whose card is billed (citicore|summit|grove).
async function bumpAIUsage(kind, units, co) {
  try {
    if (!AI_COST_CENTS.hasOwnProperty(kind)) return;
    co = normCo(co);
    const u = await _aiUsageLoad();
    const n = Math.max(1, Number(units) || 1);
    const cents = AI_COST_CENTS[kind] * n;
    const d = _aiDay();
    const day = u.days[d] || (u.days[d] = { extract: 0, categorize: 0, petition: 0, cents: 0, byco: _aiCoBlank() });
    if (!day.byco) day.byco = _aiCoBlank();
    day[kind] = (day[kind] || 0) + n; day.cents = Math.round(((day.cents || 0) + cents) * 100) / 100;
    day.byco[co] = Math.round(((day.byco[co] || 0) + cents) * 100) / 100;
    if (!u.total.byco) u.total.byco = _aiCoBlank();
    u.total[kind] = (u.total[kind] || 0) + n; u.total.cents = Math.round(((u.total.cents || 0) + cents) * 100) / 100;
    u.total.byco[co] = Math.round(((u.total.byco[co] || 0) + cents) * 100) / 100;
    // keep the note small: retain the last ~120 days
    const keys = Object.keys(u.days).sort();
    while (keys.length > 120) { delete u.days[keys.shift()]; }
    _aiUsageFlushSoon();
  } catch (e) { /* metering must never break a feature */ }
}

// The filing date of a lead, as yyyy-mm-dd so it sorts as text.
//
// This matters more than it looks. Row order on the sheet is the order the
// spreadsheets happened to be read in — the backfill wrote seventy-odd probate
// files and then fifty-odd pre-foreclosure ones — so sorting by row put spring
// filings above last week's and called it "newest". Sort on what was actually
// filed. Anything with no date sinks to the bottom rather than floating to the
// top on a technicality.
function leadFiledKey(l) {
  const f = {};
  (l && l.fields || []).forEach(p => { if (p && p[0]) f[String(p[0]).toLowerCase()] = String(p[1] == null ? '' : p[1]); });
  const s = String(f['filed'] || '').trim();
  let m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (m) return m[1] + '-' + ('0' + m[2]).slice(-2) + '-' + ('0' + m[3]).slice(-2);
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (m) return m[3] + '-' + ('0' + m[1]).slice(-2) + '-' + ('0' + m[2]).slice(-2);
  return '';
}

// Which script actually holds the pulled leads. Asked once per boot, then
// remembered — it can't change without a redeploy of the scrapers.
let LEAD_BASE = null;
async function leadFetch() {
  const tries = LEAD_BASE
    ? [LEAD_BASE]
    : [['leads', LEADS_SHEET_URL], ['grove', GROVE_SHEET_URL], ['summit', SUMMIT_SHEET_URL]]
        .filter(t => t[1]);
  for (const t of tries) {
    const [who, base] = t;
    try {
      const j = await sheetGet(base, 'probateLeads');
      if (j && Array.isArray(j.leads)) { LEAD_BASE = t; return { where: who, leads: j.leads }; }
    } catch (e) { /* try the other one */ }
  }
  // Neither script recognised the action. Not "no leads" — no handler.
  return { where: 'none', leads: [] };
}

// The sheet now holds a few thousand filings, so one pull is a couple of
// megabytes of Apps Script — and the board asks for it twice every time it
// opens, once for the cards and once for the health strip. Holding the pull for
// two minutes makes the second ask free and a page reload instant.
//
// Deliberately the PULL and nothing else: statuses and notes are read fresh on
// every request underneath this, so a mark somebody just made never sits behind
// the cache. Refresh on the page forces a fresh read for the morning's run.
let _leadPull = { at: 0, data: null };
const LEAD_PULL_MS = 2 * 60 * 1000;
async function leadPull(force) {
  if (!force && _leadPull.data && Date.now() - _leadPull.at < LEAD_PULL_MS) return _leadPull.data;
  const found = await leadFetch();
  // Never cache a failure. A 'none' answer usually means the script was
  // mid-redeploy; holding that for two minutes turns a blip into an outage.
  if (found.where !== 'none') _leadPull = { at: Date.now(), data: found };
  return found;
}

// Lead statuses ride along on whichever script holds the leads, so the list and
// the marks on it can never end up on two different spreadsheets.
function statusBase() { return (LEAD_BASE && LEAD_BASE[1]) || GROVE_SHEET_URL; }
async function readLeadStatus() {
  try {
    const j = await sheetGet(statusBase(), 'notes', '&notekey=' + encodeURIComponent(LEAD_STATUS_KEY));
    const v = noteValue(j);
    if (!v) return {};
    return typeof v === 'string' ? (JSON.parse(v) || {}) : (v || {});
  } catch (e) { return {}; }
}

// Who may see the lead list: John, and the Summit partners. Not Grove agents
// (these are Summit acquisitions, not brokerage), not the Citicore guest.
function canSeeLeads(u) { return u && (u.role === 'owner' || u.role === 'summit'); }

app.get("/api/lead-list", ensureAuth, async (req, res) => {
  if (!canSeeLeads(req.user)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const found = await leadPull(String(req.query.fresh || '') === '1');
    const raw = found.leads;
    const status = await readLeadStatus();
    // The scrapers append on every run, so the same case shows up more than
    // once — and the copies are NOT interchangeable: the original filing row
    // carries the Personal Rep + phone contacts, while the later enrichment
    // row carries the property data (Top guess, Owner of record, Deed…) but
    // NO Personal Rep. Keeping only the newest copy was silently throwing the
    // PR away on every enriched case. So: newest copy wins as the base, and
    // any field an older copy has that the base lacks is merged in — same for
    // contacts. Nothing that was ever on a filing disappears from the card.
    const byId = new Map();
    for (const l of raw) {
      if (!l || typeof l !== 'object') continue;
      const id = leadId(l);
      if (!id) continue;
      if (!byId.has(id)) {
        const st = status[id] || {};
        byId.set(id, {
          id,
          source: l.source || 'Lead',
          title: l.title || '',
          subtitle: l.subtitle || '',
          fields: Array.isArray(l.fields) ? l.fields.slice() : [],
          contacts: Array.isArray(l.contacts) ? l.contacts.slice() : [],
          link: l.link || '',
          row: l._row || null,
          status: LEAD_STATES.indexOf(st.s) >= 0 ? st.s : 'new',
          note: st.n || '',
          by: st.by || '',
          at: st.at || ''
        });
        continue;
      }
      // older duplicate of a case we already kept — fill the gaps
      const kept = byId.get(id);
      const have = new Set(kept.fields.map(p => String((p && p[0]) || '').toLowerCase()).filter(Boolean));
      (Array.isArray(l.fields) ? l.fields : []).forEach(p => {
        const k = String((p && p[0]) || '').toLowerCase();
        if (!k || have.has(k)) return;
        if (p[1] == null || p[1] === '') return;
        kept.fields.push(p); have.add(k);
      });
      if (!kept.contacts.length && Array.isArray(l.contacts) && l.contacts.length)
        kept.contacts = l.contacts.slice();
      if (!kept.link && l.link) kept.link = l.link;
    }
    // fold in anything "Read the filing" extracted from the petition PDF
    byId.forEach((L, id) => {
      const x = (status[id] || {}).x; if (!x) return;
      const have = new Set(L.fields.map(p => String((p && p[0]) || '').toLowerCase()));
      const addF = (label, v) => { if (v && !have.has(label.toLowerCase())) { L.fields.push([label, v]); have.add(label.toLowerCase()); } };
      addF('Petitioner', x.petitioner_name);
      addF('Petitioner address', x.petitioner_address);
      addF('Decedent address', x.decedent_address);
      addF('Date of death', x.date_of_death);
      addF('Will', x.testate);
      if (x.petitioner_name && !(L.contacts || []).some(c => c && String(c.name || '').toLowerCase() === String(x.petitioner_name).toLowerCase())) {
        L.contacts.push({ name: x.petitioner_name, role: 'Petitioner (PR)', phones: x.petitioner_phone ? [x.petitioner_phone] : [], emails: x.petitioner_email ? [x.petitioner_email] : [] });
      }
    });
    const leads = Array.from(byId.values());
    // Newest filing at the top. Sorted here rather than on the spreadsheet so
    // that changing what "newest" means never costs a re-paste of the script.
    leads.forEach(l => { l.filed = leadFiledKey(l); });
    leads.sort((a, b) => (b.filed || '').localeCompare(a.filed || ''));

    const counts = { total: leads.length };
    leads.forEach(l => {
      const k = (l.source || '').toLowerCase().indexOf('fore') >= 0 ? 'preforeclosure'
              : (l.source || '').toLowerCase().indexOf('probate') >= 0 ? 'probate' : 'other';
      counts[k] = (counts[k] || 0) + 1;
      counts[l.status] = (counts[l.status] || 0) + 1;
    });
    res.json({
      ok: true, leads, counts, states: LEAD_STATES,
      where: found.where,
      // The page shows this instead of an empty list, because "the sheet has no
      // lead handler" and "the scrapers found nothing this week" look identical
      // from the browser and need completely different fixes.
      warning: found.where === 'none'
        ? 'Neither spreadsheet answered to the lead handler, so there is nothing to read. The scrapers post their leads to the Grove script; the handler that files them lives on the Summit script. One of the two has to move.'
        : ''
    });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'lead_list_failed', message: String(e).slice(0, 200) });
  }
});

// Mark a lead worked. Everyone on the list sees the same marks, so Nik and John
// never call the same personal rep twice. Stored as one JSON note on the sheet —
// read-modify-write, which is fine at this volume (a few hundred leads).
app.post("/api/lead-list/status", ensureAuth, async (req, res) => {
  if (!canSeeLeads(req.user)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const id = String(b.id || '').slice(0, 120);
  const st = String(b.status || '').toLowerCase();
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  const isEnrich = b.enrich && typeof b.enrich === 'object';
  if (!isEnrich && LEAD_STATES.indexOf(st) < 0) return res.status(400).json({ ok: false, error: 'bad_status' });
  try {
    const map = await readLeadStatus();
    const prev = map[id] || {};
    if (isEnrich) {
      // "Read the filing": petition-PDF fields extracted in the browser get
      // stored alongside the lead's status so every device sees them.
      const en = {};
      ['decedent_address','petitioner_name','petitioner_address','petitioner_phone','petitioner_email','date_of_death','testate'].forEach(k => {
        const v = b.enrich[k]; if (v != null && String(v).trim() !== '') en[k] = String(v).slice(0, 160);
      });
      map[id] = Object.assign({}, prev, { x: en, by: req.user.name || req.user.email || '', at: new Date().toISOString().slice(0, 16).replace('T', ' ') });
      const w0 = await sheetPost(statusBase(), noteBody(LEAD_STATUS_KEY, JSON.stringify(map)));
      if (!w0 || w0.ok === false) throw new Error('status_write_rejected');
      return res.json({ ok: true, id, enriched: Object.keys(en) });
    }
    map[id] = {
      s: st,
      n: String(b.note || '').slice(0, 500),
      by: req.user.name || req.user.email || '',
      at: new Date().toISOString().slice(0, 16).replace('T', ' '),
      x: prev.x || undefined
    };
    const w = await sheetPost(statusBase(), noteBody(LEAD_STATUS_KEY, JSON.stringify(map)));
    if (!w || w.ok === false) throw new Error('status_write_rejected');
    res.json({ ok: true, id, status: st, by: map[id].by, at: map[id].at });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'status_write_failed', message: String(e).slice(0, 200) });
  }
});

// Is the pipeline alive? Answers the question John actually asks — "are the
// pulls running?" — by looking at how fresh the newest lead of each kind is.
app.get("/api/lead-list/health", ensureAuth, async (req, res) => {
  if (!canSeeLeads(req.user)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const found = await leadPull(String(req.query.fresh || '') === '1');
    const raw = found.leads;
    // The newest FILING per source, not the first row of it. Taking the first
    // row had the strip reporting the pre-foreclosure pull as 68 days stale on
    // the morning it ran, because the backfill wrote the old files last.
    const newest = {};
    const seen = new Set();
    for (const l of raw) {
      if (!l || typeof l !== 'object') continue;
      const id = leadId(l);
      if (id) seen.add(id);          // count the same way the board does
      const src = String(l.source || '').toLowerCase().indexOf('fore') >= 0 ? 'preforeclosure' : 'probate';
      const k = leadFiledKey(l);
      if (k && (!newest[src] || k > newest[src])) newest[src] = k;
    }
    res.json({ ok: true, total: seen.size, newest, where: found.where });
  } catch (e) { res.status(502).json({ ok: false, error: 'health_failed' }); }
});

// probate feed — the pipeline appends to a published-to-web sheet; we read the CSV
app.get("/api/probate", ensureAuth, async (req, res) => {
  if (!PROBATE_CSV_URL) return res.json({ rows: [], note: "PROBATE_CSV_URL not set" });
  try {
    const csv = await fetch(PROBATE_CSV_URL).then(r => r.text());
    const [head, ...lines] = csv.trim().split(/\r?\n/);
    const cols = head.split(",");
    const rows = lines.slice(0, 25).map(l => {
      const v = l.split(","); return Object.fromEntries(cols.map((c, i) => [c, v[i]]));
    });
    res.json({ rows });
  } catch (e) { res.status(502).json({ error: "probate_failed" }); }
});

// private bookkeeping read (owners only) via the signed-in user's token
// latest "MA multifamily leads" email -> count + parsed rows for the probate tile (owners only)
function _findAttachment(part) {
  if (!part) return null;
  if (part.filename && /\.xlsx$/i.test(part.filename) && part.body && part.body.attachmentId) return part;
  for (const p of (part.parts || [])) { const f = _findAttachment(p); if (f) return f; }
  return null;
}
// Is this login able to renew itself? Answers in plain English. No token values
// are returned — only whether one is on file.
app.get("/api/google-status", ensureAuth, async (req, res) => {
  const key = String(req.user.email || "").toLowerCase();
  const has = googleRefresh.has(key);
  const mins = req.user.tokenExp ? Math.round((req.user.tokenExp - Date.now()) / 60000) : null;
  res.json({
    ok: true,
    canRenew: has,
    accessMinutesLeft: mins,
    note: has
      ? "This login renews itself. Gmail and Sheets pages will keep working."
      : "No refresh token on file — sign out and sign back in once to fix it. (A redeploy also clears these.)"
  });
});
app.get("/api/diag", ensureAuth, async (req, res) => {
  try {
    const info = await fetch("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=" + (await freshToken(req))).then(r => r.json());
    const scopes = (info.scope || "").split(" ");
    res.json({
      email: req.user.email, role: req.user.role,
      hasSheetsWrite: scopes.includes("https://www.googleapis.com/auth/spreadsheets"),
      hasSheetsReadOnly: scopes.includes("https://www.googleapis.com/auth/spreadsheets.readonly"),
      scopes
    });
  } catch (e) { res.status(502).json({ error: "diag_failed", detail: String(e).slice(0, 200) }); }
});
app.get("/api/leads", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.json({ count: 0 });
  try {
    const h = await gauth(req);
    const q = encodeURIComponent('subject:"MA multifamily leads" has:attachment newer_than:120d');
    const list = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${q}&maxResults=1`, { headers: h }).then(r => r.json());
    const msgs = list.messages || [];
    if (!msgs.length) return res.json({ count: 0 });
    const id = msgs[0].id;
    const full = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`, { headers: h }).then(r => r.json());
    const headers = (full.payload && full.payload.headers) || [];
    const subject = (headers.find(x => x.name === "Subject") || {}).value || "";
    const date = (headers.find(x => x.name === "Date") || {}).value || "";
    const cm = /(\d+)\s+new/.exec(subject);
    let rows = [];
    let XLSX = null;
    try { const mod = await import("xlsx"); XLSX = mod && mod.read ? mod : (mod && mod.default) ? mod.default : null; } catch (e) { XLSX = null; }
    const att = _findAttachment(full.payload);
    if (att && XLSX) {
      const a = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}/attachments/${att.body.attachmentId}`, { headers: h }).then(r => r.json());
      let b64 = (a.data || "").replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      const wb = XLSX.read(b64, { type: "base64" });
      const ws = wb.Sheets["Leads"] || wb.Sheets[wb.SheetNames[0]];
      const json = XLSX.utils.sheet_to_json(ws, { defval: "" });
      rows = json.slice(0, 300).map(r => ({
        town: r["Town"] || "", address: r["Address"] || "", units: r["Units"] || "",
        salePrice: r["Sale Price"] || "", saleDate: r["Sale Date"] || "",
        owner: r["Owner"] || "", contact: r["Contact"] || "", role: r["Role"] || "",
        phone: r["Phone"] || "", flags: r["Flags"] || ""
      }));
    }
    res.json({ count: cm ? +cm[1] : rows.length, subject, date, link: `https://mail.google.com/mail/u/0/#all/${id}`, rows });
  } catch (e) { res.status(502).json({ error: "leads_failed", detail: String(e).slice(0, 200) }); }
});

// ---- server-side key/value store for the underwriting tools (UW Store tab) ----
const UW_TAB = "UW Store";
async function _uwTitleId(h, id) {
  const meta = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}?fields=sheets.properties`, { headers: h }).then(r => r.json());
  const sh = (meta.sheets || []).find(x => x.properties.title === UW_TAB);
  return sh ? sh.properties.sheetId : null;
}
async function _uwRead(h, id) {
  try {
    const d = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(UW_TAB)}!A1`, { headers: h }).then(r => r.json());
    const cell = d.values && d.values[0] && d.values[0][0];
    return cell ? JSON.parse(cell) : {};
  } catch (e) { return {}; }
}
async function _uwWrite(h, id, map) {
  let sid = await _uwTitleId(h, id);
  if (sid == null) {
    await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}:batchUpdate`, { method: "POST", headers: h, body: JSON.stringify({ requests: [{ addSheet: { properties: { title: UW_TAB, hidden: true } } }] }) });
  }
  const _w = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(UW_TAB)}!A1?valueInputOption=RAW`, { method: "PUT", headers: h, body: JSON.stringify({ values: [[JSON.stringify(map)]] }) });
  // Was: the result was thrown away, so an expired token or a lost permission
  // produced a cheerful {ok:true} and no saved scenario. Say so instead.
  if (!_w.ok) throw new Error('uw_write_' + _w.status);
}

// ── The Summit partners' scenario store ──────────────────────────────────────
// Same shape as the owner's (one JSON blob, key -> scenario), but held as a note
// on the Grove sheet instead of the bookkeeping book, and reached with the
// server's own token rather than the user's Google login. Shared between Nik and
// Jose on purpose: one Summit list, the same way the lead board works.
const UW_SUMMIT_KEY = 'uw_store_summit';
function uwIsSummit(req) { return ((req.user || {}).role === 'summit'); }
async function _uwSummitRead() {
  try {
    const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(UW_SUMMIT_KEY));
    const v = noteValue(j);
    if (!v) return {};
    return typeof v === 'string' ? (JSON.parse(v) || {}) : (v || {});
  } catch (e) { return {}; }
}
async function _uwSummitWrite(map) {
  const j = await sheetPost(GROVE_SHEET_URL, noteBody(UW_SUMMIT_KEY, JSON.stringify(map)));
  if (!j || j.ok === false) throw new Error('uw_summit_write_failed');
}

// ── Everyone else's scenario store ───────────────────────────────────────────
// The bookkeeping-book store above needs the *user's* Google token AND access to
// that book. A stale token or a person who was never given access meant every
// Analyzer / Quick Underwriter save came back 502 and the scenario was lost. So
// the same blob is now also kept as a note on the Grove sheet, reached with the
// server's own token — the same mechanism the Summit store has always used.
// Read merges both stores (the note copy wins); save writes the note first and
// treats the bookkeeping copy as best-effort so a save can no longer be lost.
function uwNoteKey(req) {
  const u = req.user || {};
  if (u.role === 'owner') return 'uw_store_owner';
  return 'uw_store_u_' + String(u.email || 'anon').toLowerCase().replace(/[^a-z0-9]+/g, '_');
}
async function _uwNoteRead(key) {
  try {
    const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(key));
    const v = noteValue(j);
    if (!v) return {};
    return typeof v === 'string' ? (JSON.parse(v) || {}) : (v || {});
  } catch (e) { return {}; }
}
async function _uwNoteWrite(key, map) {
  const j = await sheetPost(GROVE_SHEET_URL, noteBody(key, JSON.stringify(map)));
  if (!j || j.ok === false) throw new Error('uw_note_write_failed');
}
// Deleting a scenario that only exists in the bookkeeping copy can't always be
// carried out there (that's the whole reason for this fallback), so the note store
// remembers what was deleted and hides it. Saving the same name again clears it.
const UW_TOMB = '__deleted';
async function uwLoad(req) {
  let sheetMap = {};
  const id = process.env.BOOKKEEPING_SHEET_ID;
  if (id) { try { sheetMap = await _uwRead(await gauth(req, 1), id); } catch (e) { sheetMap = {}; } }
  const noteMap = await _uwNoteRead(uwNoteKey(req));
  (Array.isArray(noteMap[UW_TOMB]) ? noteMap[UW_TOMB] : []).forEach(k => { delete sheetMap[k]; });
  const out = Object.assign({}, sheetMap, noteMap);
  delete out[UW_TOMB];
  return out;
}
async function uwStore(req, map, removedKey) {
  const key = uwNoteKey(req);
  const prev = await _uwNoteRead(key);
  let tomb = Array.isArray(prev[UW_TOMB]) ? prev[UW_TOMB].slice() : [];
  if (removedKey && tomb.indexOf(removedKey) < 0) tomb.push(removedKey);
  tomb = tomb.filter(k => !(k in map));
  const payload = Object.assign({}, map);
  if (tomb.length) payload[UW_TOMB] = tomb;
  await _uwNoteWrite(key, payload);          // this one decides saved / not saved
  const id = process.env.BOOKKEEPING_SHEET_ID;
  if (id) {
    try { await _uwWrite(await gauth(req, 1), id, map); }
    catch (e) { console.warn('[uw] bookkeeping copy skipped:', e && e.message); }
  }
}
app.get("/api/uw", ensureAuth, async (req, res) => {
  if (uwIsSummit(req)) {
    const map = await _uwSummitRead();
    const prefix = req.query.prefix || "";
    return res.json({ keys: Object.keys(map).filter(k => k.startsWith(prefix)) });
  }
  try { const map = await uwLoad(req); const prefix = req.query.prefix || ""; res.json({ keys: Object.keys(map).filter(k => k.startsWith(prefix)) }); }
  catch (e) { res.status(502).json({ keys: [] }); }
});
app.get("/api/uw/item", ensureAuth, async (req, res) => {
  if (uwIsSummit(req)) {
    const map = await _uwSummitRead();
    const k = req.query.key;
    return res.json({ value: k in map ? map[k] : null });
  }
  try { const map = await uwLoad(req); const k = req.query.key; res.json({ value: k in map ? map[k] : null }); }
  catch (e) { res.status(502).json({ value: null }); }
});
app.post("/api/uw/item", ensureAuth, async (req, res) => {
  if (uwIsSummit(req)) {
    try {
      const map = await _uwSummitRead();
      map[req.body.key] = req.body.value;
      await _uwSummitWrite(map);
      return res.json({ ok: true });
    } catch (e) { return res.status(502).json({ error: "uw_write_failed" }); }
  }
  try {
    const map = await uwLoad(req);
    map[req.body.key] = req.body.value;
    await uwStore(req, map);
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: "uw_write_failed" }); }
});
app.delete("/api/uw/item", ensureAuth, async (req, res) => {
  if (uwIsSummit(req)) {
    try {
      const map = await _uwSummitRead();
      delete map[req.query.key];
      await _uwSummitWrite(map);
      return res.json({ ok: true });
    } catch (e) { return res.status(502).json({ error: "uw_del_failed" }); }
  }
  try {
    const map = await uwLoad(req);
    delete map[req.query.key];
    await uwStore(req, map, req.query.key);
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: "uw_del_failed" }); }
});


// Google Tasks (default list): list / add / toggle / delete
const TASKS_BASE = "https://tasks.googleapis.com/tasks/v1/lists/@default/tasks";
app.get("/api/tasks", ensureAuth, async (req, res) => {
  try {
    const h = await gauth(req);
    const d = await fetch(`${TASKS_BASE}?showCompleted=true&showHidden=false&maxResults=100`, { headers: h }).then(r => r.json());
    const items = (d.items || []).map(t => ({ id: t.id, title: t.title || "", done: t.status === "completed" }));
    res.json({ items });
  } catch (e) { res.status(502).json({ items: [] }); }
});
app.post("/api/tasks", ensureAuth, async (req, res) => {
  try {
    const h = await gauth(req, 1);
    const r = await fetch(TASKS_BASE, { method: "POST", headers: h, body: JSON.stringify({ title: (req.body.title || "").slice(0, 1024) }) });
    const t = await r.json(); res.json({ id: t.id, title: t.title, done: false });
  } catch (e) { res.status(502).json({ error: "task_add_failed" }); }
});
app.post("/api/tasks/toggle", ensureAuth, async (req, res) => {
  try {
    const h = await gauth(req, 1);
    const status = req.body.done ? "completed" : "needsAction";
    await fetch(`${TASKS_BASE}/${encodeURIComponent(req.body.id)}`, { method: "PATCH", headers: h, body: JSON.stringify({ status }) });
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: "task_toggle_failed" }); }
});
app.delete("/api/tasks", ensureAuth, async (req, res) => {
  try {
    const h = await gauth(req);
    await fetch(`${TASKS_BASE}/${encodeURIComponent(req.query.id)}`, { method: "DELETE", headers: h });
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: "task_del_failed" }); }
});

// per-agent earnings: read each tab's totals row (row 1) for agent columns, combine Sales + Closed
app.get("/api/agent-totals", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.json({ agents: [] });
  const id = process.env.BOOKKEEPING_SHEET_ID;
  if (!id) return res.json({ agents: [] });
  const h = await gauth(req);
  const NON = new Set(["DATE","PROPERTY","ADDRESS","ESCROWED","CLOSING","SALE","GROSS","HOUSE","FEE","TOTAL","CHECK","DEAL","MONTH","NOTES","LISTING","GROVE","LEASE","LANDLORD","UNIT","COMMISSION","PRICE","CONFIRMATION"]);
  const alias = { QUINN: "RYAN" };
  const norm = x => String(x || "").toUpperCase().replace(/[^A-Z ]/g, "").trim().split(" ")[0];
  const money = v => { const n = parseFloat(String(v).replace(/[^0-9.]/g, "")); return isFinite(n) ? n : 0; };
  const totals = {};
  for (const tab of [SALES_TAB, LEASE_TAB]) {
    try {
      const d = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(tab)}!A1:BZ2`, { headers: h }).then(r => r.json());
      const rows = d.values || [];
      const totRow = rows[0] || [], hdrRow = rows[1] || [];
      hdrRow.forEach((hd, i) => {
        const key = norm(hd);
        if (!key || NON.has(key)) return;
        const agent = alias[key] || key;
        totals[agent] = (totals[agent] || 0) + money(totRow[i]);
      });
    } catch (e) {}
  }
  const agents = Object.entries(totals).filter(([k, v]) => v > 0).map(([agent, total]) => ({ agent, total })).sort((a, b) => b.total - a.total);
  res.json({ agents });
});

app.get("/api/sheet", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ error: "forbidden" });
  const id = process.env.BOOKKEEPING_SHEET_ID, gid = process.env.BOOKKEEPING_GID;
  if (!id) return res.json({ rows: [], note: "BOOKKEEPING_SHEET_ID not set" });
  try {
    const h = await gauth(req);
    const meta = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}?fields=sheets.properties`, { headers: h }).then(r => r.json());
    const sheets = meta.sheets || [];
    let title = null;
    if (gid) { const m = sheets.find(x => String(x.properties.sheetId) === String(gid)); title = m && m.properties.title; }
    if (!title && sheets.length) title = sheets[0].properties.title;
    if (!title) return res.json({ rows: [] });
    const data = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(title)}`, { headers: h }).then(r => r.json());
    res.json({ title, rows: (data.values || []).slice(0, 300) });
  } catch (e) { res.status(502).json({ error: "sheet_failed" }); }
});

const LEASE_TAB = process.env.LEASE_TAB || "Closed Rentals";
const SALES_TAB = process.env.SALES_TAB || "Sales $";
const DATA_START = 3;
async function sheetIdByTitle(h, id, title) {
  const meta = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}?fields=sheets.properties`, { headers: h }).then(r => r.json());
  const sh = (meta.sheets || []).find(x => x.properties.title === title);
  return sh ? sh.properties.sheetId : null;
}
// Closed Rentals: E Month|F Notes|G Address|H Fee|I Lease Signed|J Landlord Paid|K Fee Paid (A-C are formulas)
// Sales $: A Date|B Address|C Escrowed|D Closing|E Sale Price|F Gross Commission|G House| then per-agent split columns
app.post("/api/deal", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ error: "forbidden" });
  const id = process.env.BOOKKEEPING_SHEET_ID;
  if (!id) return res.status(400).json({ error: "no_sheet" });
  const d = req.body || {};
  const h = await gauth(req, 1);
  const COL = i => { let s = ""; i = i + 1; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; };
  const monthOf = x => x ? new Date(x + "T00:00:00").toLocaleString("en-US", { month: "long" }) : "";
  const nextRow = async (tab, keyCol) => {
    const c = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(tab)}!${keyCol}1:${keyCol}`, { headers: h }).then(r => r.json());
    let last = DATA_START - 1; (c.values || []).forEach((r, i) => { if (r && r[0] && String(r[0]).trim()) last = i + 1; });
    return Math.max(last + 1, DATA_START);
  };
  const put = async (range, values) => {
    const r = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`, { method: "PUT", headers: h, body: JSON.stringify({ values }) });
    if (!r.ok) throw new Error(await r.text());
  };
  const normA = x => String(x || "").toUpperCase().replace(/[^A-Z ]/g, "").trim().split(" ")[0];
  const writeSplits = async (headers, tab, row, splits) => {
    const alias = { QUINN: "RYAN" };
    const unmatched = [];
    for (const sp of (splits || [])) {
      if (!sp || !sp.agent) continue;
      let key = normA(sp.agent); key = alias[key] || key;
      let idx = -1; headers.forEach((hn, i) => { if (key && normA(hn) === key) idx = i; });
      if (idx >= 0 && sp.amount) { await put(`${tab}!${COL(idx)}${row}`, [[sp.amount]]); }
      else unmatched.push(sp.agent);
    }
    return unmatched;
  };
  try {
    if (d.type === "Sale") {
      const tab = SALES_TAB;
      const hdrRes = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(tab)}!A2:Z2`, { headers: h }).then(r => r.json());
      const headers = (hdrRes.values && hdrRes.values[0]) || [];
      const row = await nextRow(tab, "B");
      await put(`${tab}!A${row}:G${row}`, [[monthOf(d.date), d.property || "", !!d.escrowed, d.closing || "", d.salePrice || "", d.grossComm || "", d.house || ""]]);
      const unmatched = await writeSplits(headers, tab, row, d.splits);
      return res.json({ ok: true, tab, row, unmatched });
    } else {
      const tab = LEASE_TAB;
      const hdrRes = await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(tab)}!A2:BZ2`, { headers: h }).then(r => r.json());
      const headers = (hdrRes.values && hdrRes.values[0]) || [];
      const row = await nextRow(tab, "G");
      await put(`${tab}!E${row}:K${row}`, [[monthOf(d.date), d.note || "", d.property || "", d.fee || "", !!d.leaseSigned, !!d.landlordPaid, !!d.feePaid]]);
      try {
        const sid = await sheetIdByTitle(h, id, tab);
        if (sid != null) {
          await fetch(`https://sheets.googleapis.com/v4/spreadsheets/${id}:batchUpdate`, { method: "POST", headers: h, body: JSON.stringify({ requests: [{ setDataValidation: { range: { sheetId: sid, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: 8, endColumnIndex: 11 }, rule: { condition: { type: "BOOLEAN" }, showCustomUi: true } } }, { setDataValidation: { range: { sheetId: sid, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: 4, endColumnIndex: 5 } } }] }) });
        }
      } catch (e) { /* checkbox formatting is best-effort */ }
      const norm = x => String(x || "").toUpperCase().replace(/[^A-Z ]/g, "").trim().split(" ")[0];
      const findCol = pred => { let idx = -1; headers.forEach((hn, i) => { if (idx < 0 && pred(hn)) idx = i; }); return idx; };
      const listingIdx = findCol(hn => norm(hn) === "LISTING");
      const groveIdx = findCol(hn => norm(hn) === "GROVE");
      const listingName = d.listing || (d.splits && d.splits[0] && d.splits[0].agent) || "";
      if (listingIdx >= 0 && listingName) await put(`${tab}!${COL(listingIdx)}${row}`, [[listingName]]);
      if (groveIdx >= 0 && d.groveComm) await put(`${tab}!${COL(groveIdx)}${row}`, [[d.groveComm]]);
      const unmatched = await writeSplits(headers, tab, row, d.splits);
      return res.json({ ok: true, tab, row, unmatched });
    }
  } catch (e) { return res.status(502).json({ error: "write_failed", detail: String(e).slice(0, 200) }); }
});

// Probate / SCRA lead feeds — read the latest report email from Gmail and parse its CSV attachment.
function findCsvPart(p) {
  if (!p) return null;
  if (p.filename && /\.csv$/i.test(p.filename) && p.body && p.body.attachmentId) return p;
  if (p.parts) { for (var i = 0; i < p.parts.length; i++) { var f = findCsvPart(p.parts[i]); if (f) return f; } }
  return null;
}
function parseCSV(txt) {
  var lines = txt.split(/\r?\n/).filter(function (l) { return l.trim().length; });
  if (!lines.length) return { headers: [], rows: [] };
  function cells(line) { var out = [], cur = '', q = false; for (var i = 0; i < line.length; i++) { var c = line[i]; if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; } else { if (c === '"') q = true; else if (c === ',') { out.push(cur); cur = ''; } else cur += c; } } out.push(cur); return out; }
  var headers = cells(lines[0]).map(function (h) { return h.trim(); });
  var rows = lines.slice(1).map(function (l) { var v = cells(l); var o = {}; headers.forEach(function (h, i) { o[h] = (v[i] || '').trim(); }); return o; });
  return { headers: headers, rows: rows };
}
app.get("/api/lead-feed", ensureAuth, async (req, res) => {
  if (req.user.role !== "owner") return res.status(403).json({ ok: false, error: "forbidden" });
  var type = (req.query.type === 'scra') ? 'scra' : 'probate';
  var subject = type === 'scra' ? 'SCRA Pre-Foreclosure Leads' : 'Probate Leads';
  var q = 'from:John@citicoreprops.com subject:"' + subject + '"';
  var h = await gauth(req);
  try {
    var list = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=1&q=' + encodeURIComponent(q), { headers: h }).then(r => r.json());
    if (!list.messages || !list.messages.length) return res.json({ ok: true, rows: [], headers: [], count: 0, note: 'No report email found yet.' });
    var msg = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/' + list.messages[0].id + '?format=full', { headers: h }).then(r => r.json());
    var subj = ((msg.payload.headers || []).find(x => x.name === 'Subject') || {}).value || '';
    var att = findCsvPart(msg.payload);
    if (!att) return res.json({ ok: true, rows: [], headers: [], count: 0, subject: subj, note: 'Report found, but no CSV attached.' });
    var a = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/' + msg.id + '/attachments/' + att.body.attachmentId, { headers: h }).then(r => r.json());
    var csv = Buffer.from((a.data || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    var parsed = parseCSV(csv);
    res.json({ ok: true, subject: subj, headers: parsed.headers, rows: parsed.rows, count: parsed.rows.length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// --- shared look: one stylesheet, every page ---
// Loads Inter + Oswald and grove.css last, so it wins over each page's own <style>.
// Uniform blue+Inter override, injected LAST so it wins over each page's own CSS and grove.css.
// Remaps the shared design tokens every tool page uses (--good/--navy/--ink/…) to the blue
// system and forces Inter everywhere, so even pages not hand-restyled match the new home.
// ── ACCESS design system (locked 2026-08-12) ────────────────────────────────
// Bricolage Grotesque (display) · Inter (body) · JetBrains Mono (labels).
// Semantic color: blue = interface · emerald = money/good · red = needs
// attention. Gold removed. Light + dark, per-member toggle (localStorage).
// Injected LAST so it wins over each page's own <style> and grove.css.
const GROVE_ACCESS =
   /* ACCESS design system (tokens_1.css) — cool neutral canvas, single ink-blue
      accent (NO gold, NO green), red for status only. Legacy var names are remapped
      to the ACCESS palette so every existing page reskins from this one block. */
   ':root{--paper:#F1F4F8;--card:#FFFFFF;--card2:#F4F6FA;--panel:#F4F6FA;--sand:#F4F6FA;--line:#E4E8EF;--line2:#D5DBE5;--fieldline:#D5DBE5;--ink:#171A20;--slate:#171A20;--mut:#5C6270;--mut2:#8A909C;--blue:#17418A;--blued:#123365;--bluebg:#EAF0FB;--accent:#17418A;--accent-hover:#123365;--accdim:#EAF0FB;--brand:#17418A;--brandmut:#9DB8DA;--navy:#0E1A2E;--nav:#17418A;--black:#17418A;--headerbg:#FFFFFF;--green:#2E9E6E;--good:#2E9E6E;--goodbg:#E6F5EE;--red:#C0492E;--bad:#C0492E;--badbg:#FCEDE9;--amber:#5C6270;--warn:#5C6270;--warnbg:#F4F6FA;--teal:#0E7C6A;--coral:#E0674B;--sky:#5B8DEF}'
   /* dark tokens */
 + 'html.dark{--paper:#12151B;--card:#1B2029;--card2:#20252F;--panel:#20252F;--sand:#20252F;--line:#272D38;--line2:#333B48;--fieldline:#333B48;--ink:#E6E9EF;--slate:#E6E9EF;--mut:#9AA1AD;--mut2:#6E7682;--blue:#6E9BFF;--blued:#9BBBFF;--bluebg:#1B2740;--accent:#6E9BFF;--accent-hover:#9BBBFF;--accdim:#1B2740;--brand:#0F1319;--brandmut:#3A4150;--navy:#0C0F14;--nav:#0F1319;--black:#0F1319;--headerbg:#171B22;--green:#3FBE86;--good:#3FBE86;--goodbg:#14352A;--red:#E0664A;--bad:#E0664A;--badbg:#3A1E16;--amber:#9AA1AD;--warn:#9AA1AD;--warnbg:#20252F;--teal:#2DD4BF;--coral:#F0785C;--sky:#7FA9F5}'
   /* fonts: body Inter, display Space Grotesk, labels Space Mono */
 + 'body,body *{font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif!important}'
 + 'h1,h2,h3,h4,.hublogo,.ttl,.brandline,.crumb,.tbar .crumb{font-family:"Space Grotesk",Inter,sans-serif!important;font-weight:700!important;letter-spacing:0}'
   /* Every NUMBER on the site renders in one family (Inter, the body font) so digits never
      differ between a big stat tile, a pipeline total, and an inline chip. Space Grotesk is
      kept for heading TEXT only. tabular-nums keeps columns of figures aligned. */
 + '.stat .v,.tile b,.big-stat-value,.stat-tile-value,.snap .v,.pc .v,.kpi b,.tot .s b,.entbig,.mini .v,.entr b,.kpirow b,.big .v,.metric .v,.card .big,.hero .v,.v,.num{font-family:Inter,system-ui,-apple-system,sans-serif!important;font-variant-numeric:tabular-nums}'
 + '.section-label,.eyebrow,.header-eyebrow,th,.k,.lbl,.chip,.badge{font-family:Inter,system-ui,-apple-system,sans-serif!important;font-weight:600!important;letter-spacing:.01em}'
   /* uniform casing: kill all CSS-forced ALL-CAPS site-wide (typed acronyms stay as typed) */
 + '*{text-transform:none!important}'
 + '.seg button,.btn,.save,.ghost,.mini,.reload,.pill{font-family:Inter,system-ui,sans-serif!important;font-weight:600!important;letter-spacing:.01em}'
 + 'body{background:var(--paper)!important;color:var(--ink)!important}'
   /* elevated depth: soft layered shadow so cards sit on the page instead of blending in */
 + '.card,.tile,.stat,.snap,.co,.pcard,.mini{box-shadow:0 1px 2px rgba(16,24,40,.04),0 12px 30px -18px rgba(16,24,40,.16)}'
 + '#hq-bar{background:var(--brand)!important}'
   /* responsive safety: images never force horizontal overflow on narrow windows */
 + 'img,video{max-width:100%;height:auto}'
 + 'header,.site-header{background:var(--headerbg)!important;color:var(--ink)!important;padding-top:14px!important;padding-bottom:14px!important;border-bottom:1px solid var(--line)}'
 + 'header .hublogo,header .ttl,header h1,header h2,.site-header h1{color:var(--ink)!important}'
 + 'header .sub,header .tsub,header p,header .tagline,header .mini{color:var(--mut)!important}'
   /* header buttons: the reskin flips headers to a light surface, so button styles that
      assumed a dark header (white text on translucent-white) would vanish. Normalize them. */
 + 'header .hbtn,header .btn:not(.primary),header button:not(.primary):not(.primary){background:var(--card2)!important;color:var(--ink)!important;border:1px solid var(--line)!important}'
 + 'header .hbtn.primary,header .btn.primary,header .primary,header .save,header button.save{background:var(--blue)!important;color:#fff!important;border:1px solid transparent!important}'
 + '.btn,button.btn{padding:8px 13px!important;font-size:12px!important;font-weight:600!important;border-radius:8px!important;line-height:1.25!important}.btn.sm{padding:6px 10px!important;font-size:11px!important}.btn.lg{padding:10px 16px!important;font-size:13px!important}'
   /* dark: flip the common hardcoded-light surfaces */
 + 'html.dark .card,html.dark .side,html.dark .cbprev,html.dark .tile,html.dark .stat,html.dark .stat .v,html.dark .tot .s,html.dark table,html.dark input,html.dark select,html.dark textarea,html.dark .seg,html.dark .ghost,html.dark .mini,html.dark .reload,html.dark .modal,html.dark .sheet,html.dark .empty-card,html.dark .empty-state,html.dark .modal-overlay>*,html.dark .modal-backdrop>*{background:var(--card)!important;border-color:var(--line)!important;color:var(--ink)!important}'
 + 'html.dark thead th,html.dark th{background:var(--panel)!important;color:var(--mut)!important;border-color:var(--line)!important}'
 + 'html.dark td{border-color:var(--line)!important;color:var(--ink)!important}'
 + 'html.dark tbody tr:hover td{background:var(--panel)!important}'
 + 'html.dark tbody td.fz,html.dark .pay tbody td.fz,html.dark tbody tr:hover td.fz{background:var(--card)!important}'
 + 'html.dark .seg button.active{background:var(--blue)!important;color:#fff!important}'
   /* floating theme toggle */
 + '#axThemeBtn{position:fixed;left:14px;bottom:14px;z-index:99999;display:inline-flex;align-items:center;gap:6px;background:var(--card);color:var(--ink);border:1px solid var(--line2);border-radius:22px;padding:8px 13px;font-family:"IBM Plex Mono",ui-monospace,monospace;font-weight:600;font-size:11px;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;box-shadow:0 10px 30px rgba(20,25,40,.18)}#axThemeBtn:hover{border-color:var(--blue)}';
// Applies the saved theme in <head> (no flash), then drops in the toggle button.
const THEME_SCRIPT = '<script>(function(){try{var t=localStorage.getItem("ax-theme")||"light";if(t==="dark")document.documentElement.classList.add("dark");}catch(e){}if(window.self!==window.top){try{var _hb=document.createElement("style");_hb.textContent="#hq-bar{display:none!important}";(document.head||document.documentElement).appendChild(_hb);}catch(e){}}function mk(){if(window.self!==window.top)return;if(document.getElementById("axThemeBtn"))return;var b=document.createElement("button");b.id="axThemeBtn";b.type="button";function lab(){b.innerHTML=document.documentElement.classList.contains("dark")?"\\u25D0 Dark":"\\u25D1 Light";}lab();b.onclick=function(){var d=document.documentElement.classList.toggle("dark");try{localStorage.setItem("ax-theme",d?"dark":"light");}catch(e){}lab();};document.body.appendChild(b);}if(document.readyState!=="loading")mk();else document.addEventListener("DOMContentLoaded",mk);})();</script>';
const THEME_HEAD = '<link rel="preconnect" href="https://fonts.googleapis.com">'
  + '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
  + '<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">'
  + '<style id="grove-access">' + GROVE_ACCESS + '</style>'
  + THEME_SCRIPT;
const GROVE_CSS_LINK = '<link rel="stylesheet" href="/grove.css?v=20260814-access">';
// Inject the ACCESS theme into every page. grove.css link only added when the
// page doesn't already carry it; the theme head goes in regardless.
function injectSkin(html){
  if (html.includes('id="grove-access"')) return html;   // already themed
  let head = THEME_HEAD;
  if (!html.includes("grove.css")) head = GROVE_CSS_LINK + head;
  return html.includes("</head>") ? html.replace("</head>", head + "</head>") : head + html;
}

// ── C1: keep the shared Sheet secret out of the browser ──────────────────────
// Every page we serve is passed through this. It (a) removes the hard-coded
// Apps Script token from the HTML and (b) repoints any direct Apps Script call
// at our own /api/grove proxy, which adds the real token server-side. So no page
// ever ships the secret, and the backup pill still works (it just goes through us).
const HARDCODED_GROVE_EXEC = "https://script.google.com/macros/s/AKfycbxLpHZlNw9yNa68Hu1EngEB0v8TwxgiwCBMTzvIy-zmw7C0ARSHmcucQKQlqIaakY93hA/exec";
function stripSheetSecret(html){
  let out = String(html)
    .split(HARDCODED_GROVE_EXEC).join("/api/grove")
    .split("grove-sheet-2026").join("");        // the original literal, still in old page copies
  // Also scrub whatever the live password actually is. Before this, the strip was
  // hardcoded to the one 2026 literal — so the day that password gets changed, every
  // page carrying the new one would have shipped it straight to the browser and undone
  // the whole point of the proxy. Reading it from the running value means the scrub
  // follows the password instead of having to be remembered separately.
  // (GROVE_SHEET_TOKEN is declared further down the file; that is fine, because this
  // function only ever runs while serving a request, long after startup.)
  const live = String(GROVE_SHEET_TOKEN || "");
  if (live.length >= 8) out = out.split(live).join("");
  return out;
}

// ── C4: notes that hold owner-only data ──────────────────────────────────────
// A "note" is fetched by key. These key patterns hold private financials
// (condo fees, landlord-check ledger, the owner's own to-dos/payroll), so they
// are blocked for non-owners on both read and write. Agent to-dos use keys like
// "main_<agent>" and are unaffected.
// 2026-08-06: this list was missing most of what it was meant to cover. The rule
// for agents is a DENY-list, so anything not named here was readable AND writable
// by every signed-in agent. Audit found: landlord_ledger (the ledger page's real
// key — the old pattern only named landlord_checks, so it never matched once),
// referrals, deal_units, lead_status, the Summit trackers, and every social_ key
// including social_brand_access, which IS the Summit access list. Now named.
// hub_perms added 2026-08-06: it is the Access Control grid itself. Anyone who
// could read it would learn the whole permission map; anyone who could write it
// could grant themselves every page. Owner-only, both directions.
// (hub_access is a DIFFERENT key and stays readable — home.html needs it to
// decide which menu to draw. It can only hide links, never grant anything.)
const OWNER_NOTE_KEY = /^(condofees|landlord_?(checks|ledger)|owner_|payroll|citicore_pay|citipay|invoice_records|referrals|deal_units|lead_status|offers|investors|rehabs|track_record|social_|pipeline_board|hub_perms)|^main$/i;
// "My to-do" and "Quick note" are labelled personal but were stored under ONE
// global key each — so every agent opened John's list, and each save overwrote
// the last person's. Rewritten per-user below, server-side, so no page changes.
// om_deals added 2026-08-06 (C2): the OM Builder library used to live only in
// localStorage, so an agent lost every OM they had built the moment they cleared
// their browser or switched machines. It now mirrors to a note — and because the
// key is listed here, each person gets their own copy rather than one shared pile.
// tx_checklists added 2026-08-06. The Transaction Checklist page saved every
// agent's checklists into ONE shared key and wrote the whole array back on every
// change — so each agent opened everybody else's transactions, and two people
// editing at once silently overwrote each other. The page's own header promised
// "only you and the office see these", which was not true. Now keyed per person,
// server-side, so the page itself needs no change. John (owner) keeps the
// original key, so anything already saved stays exactly where it is.
const PERSONAL_NOTE_KEY = /^(todos_personal|personal_note|om_deals|tx_checklists|grove_leads|quick_links)$/i;
const userSuffix = email => String(email || 'anon').toLowerCase().replace(/[^a-z0-9]+/g, '_');
function personalKey(key, user) {
  const k = String(key || '');
  if (!PERSONAL_NOTE_KEY.test(k)) return k;
  if (!user || user.role === 'owner') return k;   // owner keeps the original key, so existing content stays put
  return k + '__' + userSuffix(user.email);
}
// Citicore-scoped user (guest): full read+write on Citicore data keys ONLY.
// Summit partner's notes. Read: the hub menu list + anything social_*. Write:
// social_* EXCEPT social_brand_access — that key IS the list of who has Summit
// access, so a partner must never be able to edit it and add themselves or
// anyone else. (Their own profile picture is handled separately, further down.)
// The Summit trackers each keep their whole dataset in one note key. A partner
// needs read+write on those to use the page at all. Everything else — the owner
// keys, the Citicore keys, the payroll and ledger keys — stays blocked, and
// social_brand_access stays read-only so a partner can never add themselves or
// anyone else to the Summit access list.
// om_deals + todos_personal added 2026-08-07: OM Builder opened to Summit partners.
// Both are per-user keys (personalKey suffixes them per email), so a partner only
// ever reads/writes their own copy — nothing shared leaks through this.
const SUMMIT_TOOL_NOTE = /^(offers|investors|rehabs|track_record|_heartbeat|uw_store_summit|lead_status|om_deals|todos_personal|summit_logins|summit_deals|summit_props|summit_voicenotes|summit_tasks|pm_listings|pm_intros|pm_buyboxes)$/i;
const SUMMIT_NOTE_READ_OK  = k => { k = String(k || '').toLowerCase(); return k === 'hub_access' || /^social_/.test(k) || SUMMIT_TOOL_NOTE.test(k); };
const SUMMIT_NOTE_WRITE_OK = k => { k = String(k || '').toLowerCase(); return (/^social_/.test(k) && k !== 'social_brand_access') || SUMMIT_TOOL_NOTE.test(k); };
// `books_citicore` was REMOVED from this allow-list 2026-08-06, alongside
// grove-books.html in CITICORE_PAGES. Blocking only the page would have left the
// data reachable by asking /api/grove for the key directly — the exact page-shut-
// but-API-open shape as the other findings. Both go together. Nothing else the
// guest can open reads a books key, so this breaks none of their pages.
const CITICORE_NOTE_OK = k => { k = String(k || '').toLowerCase(); return k === 'owner_portfolio' || k === 'owner_rentroll' || k === 'owner_loans' || /^condofees_/.test(k) || /^(citicore_pay|citipay)/.test(k) || /^pm_(listings|intros|buyboxes)$/.test(k); };
function ownerOnlyNote(action, notekey, role, write, email){
  if (action !== 'notes') return false;
  if (role === 'owner') return false;
  if (role === 'member') return true;   // public Premarket members: NO raw note access — they use /api/pm/* only
  // REsimpli activity feed: John + Nik only, by name — not the whole Summit role.
  if (/^resimpli_events$/i.test(String(notekey || ''))) {
    return !(role === 'summit' && !write && String(email || '').toLowerCase() === 'nik@shbuyers.com');
  }
  // Vault unlock codes: the right team may CHECK them (read), only John sets them.
  if (/^summit_logins_pin$/i.test(String(notekey || ''))) {
    return write ? true : role !== 'summit';
  }
  if (/^grove_logins_pin$/i.test(String(notekey || ''))) {
    return write ? true : role !== 'agent';
  }
  // Citicore Investments co-investors (e.g. an outside partner like Krug): may READ the
  // properties + statements notes; the GET handler then redacts to only the buildings
  // they're invited to and strips the other investors. Writing stays owner-only.
  {
    const _ck = String(notekey || '').toLowerCase();
    if ((_ck === 'ccp_properties' || _ck === 'ccp_stmts') && (role === 'agent' || role === 'guest'))
      return !!write;   // read allowed (false=not blocked), write blocked (true)
  }
  if (role === 'guest') return !CITICORE_NOTE_OK(notekey);            // Citicore user: Citicore keys only, everything else blocked
  if (role === 'summit') return write ? !SUMMIT_NOTE_WRITE_OK(notekey) : !SUMMIT_NOTE_READ_OK(notekey);
  if (role === 'bookkeeper') {
    const bk = String(notekey || '').toLowerCase();
    // What a bookkeeper may SEE: the financial ledgers + the portfolio/property data.
    const readable = /^(owner_loans|owner_rentroll|owner_portfolio|leases|_heartbeat|hub_access)$/.test(bk)
      || /^condofees_/.test(bk) || /^(citicore_pay|citipay)/.test(bk) || /^expenses_/.test(bk)
      || /^pl_/.test(bk) || /^books/.test(bk) || /^ccp_/.test(bk);
    if (!readable) return true;                       // everything else blocked
    if (!write) return false;                          // read: allowed across the set
    // WRITE: money keys yes; property records (rent roll, loans, properties, insurance,
    // docs, leases) are read-only for the bookkeeper.
    const writable = /^expenses_/.test(bk) || /^pl_/.test(bk) || /^books/.test(bk)
      || /^condofees_/.test(bk) || /^(citicore_pay|citipay)/.test(bk)
      || bk === 'ccp_accounts' || bk === 'ccp_workorders';
    return !writable;
  }
  const k = String(notekey || '').toLowerCase();
  // The saved underwriter scenarios are keyed by email, so any agent could guess
  // a colleague's key (or the owner's) and read or delete their work. An agent
  // may now touch exactly one underwriter key: their own.
  if (/^uw_store_/.test(k)) return k !== 'uw_store_u_' + userSuffix(email);
  // Goals are one shared blob for the whole team. Agents may read them; only
  // John sets them, so a save can never clobber someone else's targets.
  if (/^agent_goals/.test(k)) return !!write;
  // ── Structural hardening 2026-08-06 (A2): allow-list, not deny-list ─────────
  // Previously this was `return OWNER_NOTE_KEY.test(k)` — block eight named
  // families, allow everything else. That meant every NOTE KEY ANYONE ADDS
  // LATER was open to agents by default until someone remembered to block it.
  // Inverted below to match how the Citicore guest and Summit partner roles
  // already work: name the handful of keys an agent legitimately uses, block
  // everything else — today's keys and tomorrow's alike. The two special cases
  // an agent is allowed (their own underwriter scenarios, reading team goals)
  // are handled just above, so they never reach this line. Enumerated 2026-08-06
  // from every agent-reachable page: the only raw keys they touch are the
  // per-person scratch set + the health ping + the read-only menu mirror; the
  // board, deals, deposits and profile pics all go through their own gated
  // actions, not raw notes. OWNER_NOTE_KEY is kept as a second, belt-and-braces
  // deny so the sensitive families stay shut even if this list is ever widened.
  return !AGENT_NOTE_OK(k) || OWNER_NOTE_KEY.test(k);                 // agent: allow-list + sensitive backstop
}
// The complete set of note keys a Grove agent may read or write. Anything not
// matched here is denied — including keys added to the app in the future, which
// is the whole point. `personalKey()` suffixes the scratch keys per-email AFTER
// this gate, so one agent can never reach another's; the base names just have to
// pass here first. `todos_shared` and the old hub's per-user `td_`/`ql_` quick
// stores are kept working for anyone still on the legacy shell.
const AGENT_NOTE_OK = k => {
  if (/^grove_logins$/i.test(String(k||''))) return true;   // shared Grove vault — team read/write
  if (/^pm_(listings|intros|buyboxes)$/i.test(String(k||''))) return true;   // Premarket Hub — shared marketplace, all logged-in users read/write
  k = String(k || '').toLowerCase();
  if (k === '_heartbeat' || k === 'hub_access') return true;
  if (/^(todos_personal|personal_note|om_deals|tx_checklists|todos_shared|grove_leads|quick_links|forsale_folder)$/.test(k)) return true;
  if (/^(todos_|td_|ql_|quicklinks_)/.test(k)) return true;
  return false;
};

// ── Google address autocomplete ──────────────────────────────────────────────
// Injected into every page. If GOOGLE_MAPS_KEY is set in the env, any input with
// class "gaddr" becomes a Google Places address typeahead. If the key is missing
// or Google can't load, the field just stays a normal text box — never breaks a page.
const GOOGLE_MAPS_KEY = process.env.GOOGLE_MAPS_KEY || '';
const MAPS_SNIPPET = `<script>window.__MAPSKEY__=${JSON.stringify(GOOGLE_MAPS_KEY)};(function(){var K=window.__MAPSKEY__||'';if(!K)return;function fields(){return document.querySelector('.gaddr');}function attach(){if(!(window.google&&google.maps&&google.maps.places&&google.maps.places.Autocomplete))return;document.querySelectorAll('.gaddr:not([data-ac])').forEach(function(inp){inp.setAttribute('data-ac','1');try{var ac=new google.maps.places.Autocomplete(inp,{types:['address'],componentRestrictions:{country:'us'},fields:['formatted_address']});ac.addListener('place_changed',function(){var p=ac.getPlace();if(p&&p.formatted_address){inp.value=p.formatted_address;inp.dispatchEvent(new Event('input',{bubbles:true}));inp.dispatchEvent(new Event('change',{bubbles:true}));}});}catch(e){}});}window.__initGAddr=attach;function load(){if(!fields())return;if(window.google&&google.maps&&google.maps.places){attach();return;}if(document.getElementById('gmapsjs'))return;var s=document.createElement('script');s.id='gmapsjs';s.src='https://maps.googleapis.com/maps/api/js?key='+encodeURIComponent(K)+'&libraries=places&callback=__initGAddr&loading=async';s.async=true;s.onerror=function(){};document.head.appendChild(s);}if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();})();</script>`;
// Auto-format money inputs (text fields with inputmode="decimal") with thousands commas as you
// type, site-wide. Every such page's own parser strips commas before doing math, so calcs are
// unaffected. Idempotent + guarded, so it never double-installs or fights a page's own formatter.
const MONEYFMT_SNIPPET = `<script>(function(){if(window.__GMONEYFMT__)return;window.__GMONEYFMT__=1;function f(el){if(!el||el.type==='date')return;var o=String(el.value||'');var c=el.selectionStart==null?o.length:el.selectionStart;var db=o.slice(0,c).replace(/[^0-9]/g,'').length;var cl=o.replace(/[^0-9.]/g,'');var d=cl.indexOf('.');var ip=(d<0?cl:cl.slice(0,d)).replace(/^0+(?=\\d)/,'');var dc=d<0?'':cl.slice(d+1).replace(/[^0-9]/g,'').slice(0,2);var out=ip?Number(ip).toLocaleString('en-US'):(d>=0?'0':'');if(d>=0)out+='.'+dc;if(out===o)return;el.value=out;var i=0,s=0;if(db>0){for(;i<out.length;i++){if(/[0-9]/.test(out.charAt(i))){s++;if(s===db){i++;break;}}}}try{el.setSelectionRange(i,i);}catch(e){}}var __rx=null;document.addEventListener('input',function(e){if(__rx===null){__rx=!!document.querySelector('script[type="text/babel"]');}if(__rx)return;var t=e.target;if(t&&t._valueTracker)return;if(t&&t.tagName==='INPUT'&&t.getAttribute('inputmode')==='decimal')f(t);},true);})();</script>`;
// "✨ Improve" AI writing helper — appears next to description/notes textareas site-wide.
// Skips data-paste boxes (CSV/JSON/code) and anything marked .no-ai. Calls /api/ai/rewrite.
const AI_REWRITE_SNIPPET = `<script>(function(){if(window.__GAIWRITE__)return;window.__GAIWRITE__=1;
function mk(el){if(!el||el.dataset.aiBtn)return;if(el.classList&&el.classList.contains('no-ai'))return;var hint=((el.getAttribute('placeholder')||'')+' '+(el.className||'')+' '+(el.id||''));if(/csv|json|paste|import|rows|sql|code|token/i.test(hint))return;el.dataset.aiBtn='1';
var wrap=document.createElement('div');wrap.style.cssText='margin:3px 0 2px';
var b=document.createElement('button');b.type='button';b.textContent='\\u2728 Improve';b.title='Rewrite this with AI';
b.style.cssText='font:inherit;font-size:11px;font-weight:600;color:#2450DC;background:#EEF2FF;border:1px solid #dbe1f5;border-radius:7px;padding:3px 9px;cursor:pointer';
var st=document.createElement('span');st.style.cssText='font-size:11px;color:#6B6B6B;margin-left:8px';
b.addEventListener('click',function(){var t=(el.value||'').trim();if(!t){st.textContent='Type something first.';return;}var orig=el.value;b.disabled=true;st.textContent='Improving\\u2026';
fetch('/api/ai/rewrite',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({text:t})}).then(function(r){return r.json();}).then(function(j){b.disabled=false;
if(j&&j.ok&&j.text){el.value=j.text;try{el.dispatchEvent(new Event('input',{bubbles:true}));}catch(e){}st.textContent='';var u=document.createElement('a');u.href='#';u.textContent='undo';u.style.cssText='font-size:11px;color:#6B6B6B';u.addEventListener('click',function(ev){ev.preventDefault();el.value=orig;try{el.dispatchEvent(new Event('input',{bubbles:true}));}catch(_){}st.textContent='';});st.appendChild(u);}
else{st.textContent=(j&&j.message)?String(j.message).slice(0,90):'Could not improve.';}}).catch(function(){b.disabled=false;st.textContent='Failed \\u2014 check connection.';});});
wrap.appendChild(b);wrap.appendChild(st);if(el.parentNode)el.parentNode.insertBefore(wrap,el.nextSibling);}
function scan(){try{document.querySelectorAll('textarea:not([data-ai-btn]),input[data-ai]:not([data-ai-btn])').forEach(mk);}catch(e){}}
document.addEventListener('focusin',function(e){var t=e.target;if(t&&(t.tagName==='TEXTAREA'||(t.tagName==='INPUT'&&t.hasAttribute('data-ai'))))mk(t);});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',scan);else scan();setTimeout(scan,1200);})();</script>`;
// Reusable "upload a document -> extract -> review -> fill" widget. A page calls
// window.groveAIExtract({title, fields:[{key,id,label,type,hint}], onApply}). It shows an
// upload modal, POSTs the file to /api/ai/extract, lets the user review/edit, then fills
// each field's input by id (and passes the raw values to onApply for tables/rows).
const AI_EXTRACT_SNIPPET = `<script>(function(){if(window.__GAIEXTRACT__)return;window.__GAIEXTRACT__=1;
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
window.groveAIExtract=function(opts){opts=opts||{};var fields=opts.fields||[];
var bg=document.createElement('div');bg.style.cssText='position:fixed;inset:0;background:rgba(10,10,20,.45);z-index:99999;display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;overflow:auto';
var box=document.createElement('div');box.style.cssText='background:#fff;border-radius:14px;max-width:560px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,.3);font-family:Inter,system-ui,sans-serif;color:#141414';
box.innerHTML='<div style="padding:15px 18px;border-bottom:1px solid #eee;display:flex;justify-content:space-between;align-items:center"><b style="font-size:15px">'+esc(opts.title||'Auto-fill from a document')+'</b><button id="_gx" style="border:0;background:#eef2f8;border-radius:8px;width:30px;height:30px;cursor:pointer;font-size:16px">&times;</button></div><div id="_gb" style="padding:16px 18px"></div>';
bg.appendChild(box);document.body.appendChild(bg);var body=box.querySelector('#_gb');
function close(){bg.remove();}box.querySelector('#_gx').onclick=close;bg.addEventListener('click',function(e){if(e.target===bg)close();});
body.innerHTML='<div style="font-size:13px;color:#555;margin-bottom:10px">Upload one or more PDFs or photos (purchase &amp; sale, rent roll, commission agreement, statements…). You can pick several at once — they’re read together. Nothing changes until you review and apply.</div><input type="file" id="_gf" accept="application/pdf,image/*" multiple style="font:inherit"><div id="_gs" style="font-size:12px;color:#6B6B6B;margin-top:10px"></div>';
var st=body.querySelector('#_gs');
body.querySelector('#_gf').addEventListener('change',function(e){var files=Array.prototype.slice.call(e.target.files||[]);if(!files.length)return;var big=files.filter(function(f){return f.size>6.5*1024*1024;});var queue=files.filter(function(f){return f.size<=6.5*1024*1024;});if(!queue.length){st.textContent='Each file must be under ~6MB — shrink or split and try again.';return;}var rowKey={};fields.forEach(function(x){if((x.type||'')==='rows')rowKey[x.key]=1;});var payloadFields=fields.map(function(x){return {key:x.key,label:x.label,type:x.type||'string',hint:x.hint};});var merged={},okN=0,i=0;(function next(){if(i>=queue.length){if(!okN){st.textContent='Could not read '+(queue.length>1?'those documents.':'that document.');return;}review(merged);return;}var f=queue[i++];st.textContent=(queue.length>1?('Reading '+f.name+' — '+i+' of '+queue.length+'…'):'Reading the document… this can take a few seconds.');var fr=new FileReader();fr.onload=function(){var d=String(fr.result||'');var idx=d.indexOf('base64,');var b64=idx>=0?d.slice(idx+7):'';fetch('/api/ai/extract',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({co:(opts.co||window.__AICO__||'grove'),data:b64,mime:f.type||'application/pdf',fields:payloadFields})}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok){okN++;var vals=j.values||{};Object.keys(vals).forEach(function(k){if(rowKey[k]){merged[k]=(merged[k]||[]).concat(Array.isArray(vals[k])?vals[k]:[]);}else if(merged[k]==null||merged[k]===''){if(vals[k]!=null&&vals[k]!=='')merged[k]=vals[k];}});}next();}).catch(function(){next();});};fr.onerror=function(){next();};fr.readAsDataURL(f);})();});
function review(vals){var rowsF=fields.filter(function(x){return x.type==='rows';});var simple=fields.filter(function(x){return x.type!=='rows';});
var h='<div style="font-size:13px;color:#555;margin-bottom:10px">Review what it found — edit anything, then apply.</div>';
simple.forEach(function(fl){var v=vals[fl.key];if(v==null)v='';h+='<div style="margin-bottom:9px"><label style="display:block;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#6B6B6B;margin-bottom:3px">'+esc(fl.label||fl.key)+'</label><input data-k="'+esc(fl.key)+'" value="'+esc(v)+'" style="width:100%;padding:8px 10px;border:1px solid #ddd;border-radius:8px;font:inherit"></div>';});
rowsF.forEach(function(fl){var arr=Array.isArray(vals[fl.key])?vals[fl.key]:[];h+='<div style="margin-bottom:9px"><label style="display:block;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#6B6B6B;margin-bottom:3px">'+esc(fl.label||fl.key)+' ('+arr.length+' rows found)</label><div style="font-size:12px;color:#6B6B6B;background:#f6f7f9;border:1px solid #eee;border-radius:8px;padding:8px;max-height:140px;overflow:auto">'+(arr.length?arr.map(function(r){return esc(JSON.stringify(r));}).join('<br>'):'None found')+'</div></div>';});
h+='<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:14px"><button id="_gc" style="background:#eee;border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer">Cancel</button><button id="_ga" style="background:#2450DC;color:#fff;border:0;border-radius:8px;padding:9px 18px;font:inherit;font-weight:700;cursor:pointer">Apply to form</button></div>';
body.innerHTML=h;body.querySelector('#_gc').onclick=close;body.querySelector('#_ga').onclick=function(){var out={};body.querySelectorAll('input[data-k]').forEach(function(inp){out[inp.getAttribute('data-k')]=inp.value;});rowsF.forEach(function(fl){out[fl.key]=Array.isArray(vals[fl.key])?vals[fl.key]:[];});apply(out);close();};}
function apply(out){fields.forEach(function(fl){if(!fl.id||fl.type==='rows')return;var el=document.getElementById(fl.id);if(!el)return;var v=out[fl.key];if(v==null||v==='')return;el.value=v;try{el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));}catch(e){}});if(typeof opts.onApply==='function'){try{opts.onApply(out);}catch(e){}}}
};})();</script>`;
// Universal "📎 Auto-fill" — a floating button on any page that has a form. It reads the
// on-screen fields (by their labels) and fills them from an uploaded document via groveAIExtract.
// Skips pages that already have a curated Auto-fill button, and pages without a real form.
const AI_AUTOFILL_SNIPPET = `<script>(function(){if(window.__GAUTOFILL__)return;window.__GAUTOFILL__=1;
function lbl(el){var l=(el.labels&&el.labels[0]);if(l)return (l.textContent||'').trim();if(el.getAttribute('aria-label'))return el.getAttribute('aria-label').trim();var p=el.previousElementSibling;if(p&&p.tagName==='LABEL')return (p.textContent||'').trim();var par=el.closest&&el.closest('label');if(par)return (par.textContent||'').trim();if(el.placeholder)return el.placeholder.trim();return '';}
function collect(){var out=[],seen={},els=document.querySelectorAll('input,select,textarea');for(var i=0;i<els.length;i++){var el=els[i],t=(el.type||'').toLowerCase();if(!el.id)continue;if(t==='hidden'||t==='file'||t==='button'||t==='submit'||t==='checkbox'||t==='radio'||t==='password'||el.disabled||el.readOnly)continue;if(el.offsetParent===null)continue;if(seen[el.id])continue;var L=lbl(el);if(!L||L.length>60)continue;seen[el.id]=1;out.push({key:el.id,id:el.id,label:L,type:(el.getAttribute('inputmode')==='decimal'||t==='number')?'number':'string'});if(out.length>=28)break;}return out;}
function run(){if(typeof window.groveAIExtract!=='function'){alert('Auto-fill is still loading — try again in a moment.');return;}var f=collect();if(f.length<1){alert('No fillable form fields on this screen.');return;}window.groveAIExtract({title:'Auto-fill this form from a document',fields:f});}
function place(){if(document.getElementById('_gautofb'))return;if(document.querySelector('[onclick*="groveAIExtract"]'))return;if(collect().length<2)return;var b=document.createElement('button');b.id='_gautofb';b.type='button';b.textContent='📎 Auto-fill';b.title='Fill this form from an uploaded document';b.style.cssText='position:fixed;left:16px;bottom:16px;z-index:9998;font-family:Inter,system-ui,sans-serif;font-size:13px;font-weight:700;color:#fff;background:#2450DC;border:0;border-radius:22px;padding:10px 16px;box-shadow:0 6px 18px rgba(36,80,220,.35);cursor:pointer';b.onclick=run;document.body.appendChild(b);}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',place);else place();setTimeout(place,1500);setTimeout(place,3500);})();</script>`;
// Deal file attachments — paperclip badge + attach/view modal on the deal lists,
// and attach-at-submission on agent-add-deal. Injected on every page; self-gates by path.
const DEALFILES_SNIPPET = "<scr"+"ipt>" + "(function(){\nif(window.__GDEALFILES__)return;window.__GDEALFILES__=1;\nvar P=(location.pathname||'').toLowerCase();\nvar ON_LIST=/(deals-payouts|my-deals)\\.html?$/.test(P)||/(deals-payouts|my-deals)$/.test(P);\nvar ON_ADD=/agent-add-deal\\.html?$/.test(P)||/agent-add-deal$/.test(P);\nif(!ON_LIST&&!ON_ADD)return;\nvar MAXB=15*1024*1024; // 15MB per file (base64 stays under the 25mb server json cap)\nfunction esc(s){return String(s==null?'':s).replace(/[&<>\"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}\nfunction fmtSize(n){n=+n||0;if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(0)+' KB';return (n/1048576).toFixed(1)+' MB';}\nfunction keyOf(d){return String((d&&(d.dealId||d.id))||'');}\n\n// ── authoritative deal list (with attachments) ────────────────────────────────\n// Prefer the page's own loaded DEALS (already carries .attachments now); fall back\n// to fetching so the widget still works if the global is unavailable.\nvar MAP={}; // key -> deal object (with .attachments)\nfunction readPageDeals(){\n  var arr=null;\n  if(Array.isArray(window.DEALS))arr=window.DEALS;\n  else{try{if(typeof DEALS!=='undefined'&&Array.isArray(DEALS))arr=DEALS;}catch(e){}}\n  return arr;\n}\nfunction indexDeals(arr){\n  if(!Array.isArray(arr))return false;\n  var any=false;MAP={};\n  arr.forEach(function(d){if(!d)return;var k=keyOf(d);if(!k)return;if(!Array.isArray(d.attachments))d.attachments=d.attachments||[];MAP[k]=d;if(d.id)MAP[String(d.id)]=d;if(d.dealId)MAP[String(d.dealId)]=d;any=true;});\n  return any;\n}\nfunction pageHasGlobal(){if(Array.isArray(window.DEALS))return true;try{if(typeof DEALS!=='undefined'&&Array.isArray(DEALS))return true;}catch(e){}return false;}\nfunction refreshDeals(cb){\n  // On the deal pages the page owns DEALS (and it now carries .attachments). Use it —\n  // even while it's still empty mid-load — so the owner always gets the WHOLE book, not\n  // the partial set /api/mydeals would return for them. Re-runs as rows render.\n  if(pageHasGlobal()){indexDeals(readPageDeals()||[]);if(cb)cb();return;}\n  // Fallback only for a page with no DEALS global of its own.\n  fetch('/api/mydeals?_='+Date.now()).then(function(r){return r.ok?r.json():null;}).then(function(j){\n    if(j&&Array.isArray(j.deals)&&j.deals.length){indexDeals(j.deals);if(cb)cb();return;}\n    return fetch('/api/deals?_='+Date.now()).then(function(r){return r.ok?r.json():null;}).then(function(k){if(k&&Array.isArray(k.deals))indexDeals(k.deals);if(cb)cb();});\n  }).catch(function(){if(cb)cb();});\n}\nfunction attsFor(key){var d=MAP[String(key)];return (d&&Array.isArray(d.attachments))?d.attachments:[];}\nfunction setAtts(key,list){var d=MAP[String(key)];if(d)d.attachments=list||[];}\n\n// ── the file modal (self-contained; no page coupling) ─────────────────────────\nvar MODAL=null,MODAL_KEY='';\nfunction closeModal(){if(MODAL){MODAL.remove();MODAL=null;MODAL_KEY='';}}\nfunction openModal(key,label){\n  MODAL_KEY=key;\n  if(MODAL)MODAL.remove();\n  var bg=document.createElement('div');\n  bg.style.cssText='position:fixed;inset:0;background:rgba(10,14,32,.5);z-index:2147482000;display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;overflow:auto;font-family:Inter,system-ui,-apple-system,sans-serif';\n  var box=document.createElement('div');\n  box.style.cssText='background:#fff;border-radius:16px;max-width:520px;width:100%;box-shadow:0 24px 70px rgba(0,0,0,.35);color:#0A0A0B';\n  box.addEventListener('click',function(e){e.stopPropagation();});\n  bg.appendChild(box);bg.addEventListener('click',closeModal);\n  document.body.appendChild(bg);MODAL=bg;\n  drawModal(box,label);\n}\nfunction drawModal(box,label){\n  var list=attsFor(MODAL_KEY);\n  var h='<div style=\"padding:16px 18px;border-bottom:1px solid #eef0f5;display:flex;justify-content:space-between;align-items:center\">'\n    +'<div><div style=\"font-weight:800;font-size:15px;color:#0B1020\">Deal files</div>'\n    +'<div style=\"font-size:12.5px;color:#71717A;margin-top:2px\">'+esc(label||'')+'</div></div>'\n    +'<button id=\"_gfx\" style=\"border:0;background:#eef2f8;border-radius:9px;width:32px;height:32px;cursor:pointer;font-size:18px;line-height:1\">&times;</button></div>'\n    +'<div style=\"padding:14px 18px\">';\n  if(list.length){\n    h+='<div style=\"display:flex;flex-direction:column;gap:8px;margin-bottom:14px\">';\n    list.forEach(function(f,i){\n      var view=f.view||f.url;\n      h+='<div style=\"display:flex;align-items:center;gap:10px;border:1px solid #E4E4E7;border-radius:10px;padding:9px 11px\">'\n        +'<span style=\"font-size:17px\">📄</span>'\n        +'<span style=\"flex:1;min-width:0;font-size:13.5px;font-weight:600;color:#0B1020;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">'+esc(f.name||'file')+(f.size?' <span style=\"color:#9aa0b4;font-weight:500\">· '+fmtSize(f.size)+'</span>':'')+'</span>'\n        +'<a href=\"'+esc(view)+'\" target=\"_blank\" rel=\"noopener\" style=\"font-size:12.5px;font-weight:700;color:#2450DC;text-decoration:none\">View</a>'\n        +'<a href=\"'+esc(f.url||view)+'\" target=\"_blank\" rel=\"noopener\" download style=\"font-size:12.5px;font-weight:700;color:#2450DC;text-decoration:none\">Download</a>'\n        +'<button data-del=\"'+i+'\" title=\"Remove from this deal\" style=\"border:0;background:none;color:#B42318;cursor:pointer;font-weight:800;font-size:15px;line-height:1;padding:0 2px\">✕</button>'\n        +'</div>';\n    });\n    h+='</div>';\n  }else{\n    h+='<div style=\"font-size:13px;color:#71717A;background:#F7F7F8;border:1px solid #eef0f5;border-radius:10px;padding:12px;margin-bottom:14px\">No files on this deal yet — add the commission statement, P&amp;S, lease, photos…</div>';\n  }\n  h+='<label for=\"_gfin\" style=\"display:inline-flex;align-items:center;gap:8px;background:#2450DC;color:#fff;font-weight:700;font-size:13.5px;border-radius:10px;padding:10px 15px;cursor:pointer\">＋ Attach a file</label>'\n    +'<input id=\"_gfin\" type=\"file\" multiple accept=\".pdf,.xls,.xlsx,.csv,.doc,.docx,.png,.jpg,.jpeg,.heic,.txt,.ppt,.pptx\" style=\"display:none\">'\n    +'<div id=\"_gfmsg\" style=\"font-size:12.5px;color:#71717A;margin-top:10px;min-height:16px\"></div>'\n    +'</div>';\n  box.innerHTML=h;\n  box.querySelector('#_gfx').onclick=closeModal;\n  box.querySelector('#_gfin').addEventListener('change',function(){uploadFiles(this.files,box,label);});\n  box.querySelectorAll('[data-del]').forEach(function(b){b.onclick=function(){removeFile(parseInt(b.getAttribute('data-del'),10),box,label);};});\n}\nfunction msg(box,t,c){var m=box.querySelector('#_gfmsg');if(m){m.textContent=t||'';m.style.color=c||'#71717A';}}\nfunction uploadFiles(files,box,label){\n  files=Array.prototype.slice.call(files||[]);if(!files.length)return;\n  var i=0;\n  (function next(){\n    if(i>=files.length){msg(box,'All files attached ✓','#2450DC');setTimeout(function(){drawModal(box,label);decorateSoon();},700);return;}\n    var f=files[i++];\n    if(f.size>MAXB){msg(box,'\"'+f.name+'\" is over 15 MB — too big to attach here.','#B42318');return next();}\n    msg(box,'Uploading '+f.name+'…','#B45309');\n    var fr=new FileReader();\n    fr.onload=function(){\n      var d=String(fr.result||'');var idx=d.indexOf('base64,');var b64=idx>=0?d.slice(idx+7):'';\n      fetch('/api/grove',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',\n        body:JSON.stringify({action:'dealAttach',dealId:MODAL_KEY,name:f.name,mime:f.type||'application/octet-stream',size:f.size,data:b64})})\n        .then(function(r){return r.json();}).then(function(j){\n          if(j&&j.ok){setAtts(MODAL_KEY,j.attachments||attsFor(MODAL_KEY));next();}\n          else{msg(box,'Could not attach \"'+f.name+'\"'+(j&&j.error?(' — '+j.error):'')+'.','#B42318');}\n        }).catch(function(){msg(box,'Upload failed for \"'+f.name+'\" (connection).','#B42318');});\n    };\n    fr.onerror=function(){msg(box,'Could not read \"'+f.name+'\".','#B42318');next();};\n    fr.readAsDataURL(f);\n  })();\n}\nfunction removeFile(idx,box,label){\n  var list=attsFor(MODAL_KEY);var f=list[idx];if(!f)return;\n  msg(box,'Removing…','#B45309');\n  fetch('/api/grove',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',\n    body:JSON.stringify({action:'dealDetach',dealId:MODAL_KEY,fileId:f.id||f.fileId||''})})\n    .then(function(r){return r.json();}).then(function(j){\n      if(j&&j.ok){setAtts(MODAL_KEY,j.attachments||list.filter(function(_,k){return k!==idx;}));drawModal(box,label);decorateSoon();}\n      else{msg(box,'Could not remove'+(j&&j.error?(' — '+j.error):'')+'.','#B42318');}\n    }).catch(function(){msg(box,'Remove failed (connection).','#B42318');});\n}\n\n// ── paperclip badges on the list ──────────────────────────────────────────────\n// Find each deal's row by scanning onclick handlers for a known deal id, then drop\n// a single clip into that row. Subtle when empty (add), accent \"📎 N\" when files exist.\nfunction labelForRow(row,key){\n  var d=MAP[String(key)];\n  if(d&&d.property)return d.property+(d.unit?(' #'+d.unit):'');\n  var tds=row&&row.querySelectorAll?row.querySelectorAll('td'):[];\n  if(tds&&tds.length>1)return (tds[1].textContent||'').trim().slice(0,80);\n  return '';\n}\nfunction clipFor(key,row){\n  var n=attsFor(key).length;\n  var b=document.createElement('button');\n  b.className='gclip';b.type='button';\n  b.setAttribute('data-gk',key);\n  b.title=n?(n+' file'+(n===1?'':'s')+' attached — view or add'):'Attach a file to this deal';\n  b.textContent=n?('📎 '+n):'📎';\n  b.style.cssText='margin-left:8px;border:1px solid '+(n?'#c9d4f7':'#E4E4E7')+';background:'+(n?'#eef3ff':'#fff')+';color:'+(n?'#2450DC':'#9aa0b4')+';border-radius:20px;padding:3px 9px;font:inherit;font-size:12px;font-weight:700;cursor:pointer;vertical-align:middle;line-height:1.4';\n  b.onclick=function(ev){ev.stopPropagation();ev.preventDefault();openModal(key,labelForRow(row,key));};\n  var d=MAP[String(key)];\n  if(d&&d.property){var g=document.createElement('a');g.className='gclip gmailb';g.textContent='\u2709';g.title='Search Gmail for '+d.property;g.href='https://mail.google.com/mail/u/0/#search/'+encodeURIComponent('\"'+d.property+'\"');g.target='_blank';g.rel='noopener';g.style.cssText='margin-left:4px;border:1px solid #E4E4E7;background:#fff;color:#9aa0b4;border-radius:20px;padding:3px 9px;font:inherit;font-size:12px;font-weight:700;cursor:pointer;vertical-align:middle;line-height:1.4;text-decoration:none';g.onclick=function(ev){ev.stopPropagation();};var w=document.createElement('span');w.appendChild(b);w.appendChild(g);return w;}\n  return b;\n}\nvar KEYS=[];\n// Which deal does this row belong to? First try a deal id carried in any onclick on\n// the row (cycleFee('D..') on Deals & Payouts, openEdit('D..') on My Deals); if the\n// row encodes the id some other way, fall back to matching the property-address cell.\nfunction keyForRow(row){\n  var cand=[row];\n  var hits=row.querySelectorAll?row.querySelectorAll('[onclick]'):[];\n  for(var i=0;i<hits.length;i++)cand.push(hits[i]);\n  for(var c=0;c<cand.length;c++){\n    var oc=cand[c].getAttribute&&cand[c].getAttribute('onclick');if(!oc)continue;\n    for(var k=0;k<KEYS.length;k++){var key=KEYS[k];if(oc.indexOf(\"'\"+key+\"'\")>=0||oc.indexOf('\"'+key+'\"')>=0)return key;}\n  }\n  var cells=row.querySelectorAll?row.querySelectorAll('td'):[];\n  for(var t=0;t<cells.length;t++){\n    var txt=(cells[t].textContent||'').trim();if(txt.length<4)continue;\n    // Count DISTINCT deals (a deal is indexed under both id and dealId, so counting raw\n    // KEYS would wrongly read as ambiguous). Only bind by address when exactly one deal\n    // sits at that address — otherwise two units in the same building could mis-bind.\n    var canon={},uniq=[];\n    for(var p=0;p<KEYS.length;p++){var d=MAP[KEYS[p]];if(d&&d.property&&txt.indexOf(d.property)===0){var ck=String((d.dealId||d.id)||KEYS[p]);if(!canon[ck]){canon[ck]=KEYS[p];uniq.push(ck);}}}\n    if(uniq.length===1)return canon[uniq[0]];\n  }\n  return '';\n}\nfunction listRows(){\n  var out=[];\n  var trs=document.querySelectorAll('table tr');\n  for(var i=0;i<trs.length;i++){if(trs[i].querySelector('td'))out.push(trs[i]);}   // data rows, not headers\n  var cards=document.querySelectorAll('.card,.ptile,li.deal,.drow');\n  for(var j=0;j<cards.length;j++)out.push(cards[j]);\n  return out;\n}\n// Pick a guaranteed-visible cell to hang the clip on. Prefer the property cell (matched\n// tolerant of CSS/'…' truncation, either direction); else the cell holding the onclick\n// element that identifies this deal (always on-screen); else the leftmost cell. This\n// avoids the last-<td> trap on wide tables (Deals & Payouts is 18 columns).\nfunction hostCell(row,key){\n  if(row.tagName!=='TR')return row;\n  var tds=row.querySelectorAll('td');if(!tds.length)return row;\n  var d=MAP[key];\n  if(d&&d.property){\n    var p=String(d.property).trim();\n    for(var i=0;i<tds.length;i++){\n      var t=(tds[i].textContent||'').replace(/[\\s.…]+$/,'').trim();\n      if(t.length>=4&&(p.indexOf(t)===0||t.indexOf(p)===0))return tds[i];\n    }\n  }\n  var hits=row.querySelectorAll('[onclick]');\n  for(var j=0;j<hits.length;j++){\n    var oc=hits[j].getAttribute('onclick')||'';\n    if(oc.indexOf(\"'\"+key+\"'\")>=0||oc.indexOf('\"'+key+'\"')>=0){var td=hits[j].closest('td');if(td)return td;}\n  }\n  return tds[0]||row;\n}\nvar DEC_BUSY=false;\nfunction decorate(){\n  if(!ON_LIST)return;\n  KEYS=Object.keys(MAP);if(!KEYS.length)return;\n  DEC_BUSY=true;\n  try{\n    var seen={};\n    var rws=listRows();\n    for(var i=0;i<rws.length;i++){\n      var row=rws[i];\n      var key=keyForRow(row);if(!key||seen[key])continue;\n      seen[key]=1;\n      var want=key+':'+attsFor(key).length;\n      if(row.__gclip===want)continue;\n      var old=row.querySelector&&row.querySelector('.gclip');if(old&&old.parentNode)old.parentNode.removeChild(old);\n      hostCell(row,key).appendChild(clipFor(key,row));row.__gclip=want;\n    }\n  }catch(e){}\n  DEC_BUSY=false;\n}\nvar decT=null;\nfunction decorateSoon(){if(decT)clearTimeout(decT);decT=setTimeout(function(){refreshDeals(decorate);},120);}\n\n// keep badges alive across the page's own re-renders (search/sort/tab switch)\nfunction watch(){\n  var host=document.getElementById('list')||document.querySelector('main')||document.body;\n  try{\n    var mo=new MutationObserver(function(muts){\n      if(DEC_BUSY)return;\n      for(var i=0;i<muts.length;i++){var t=muts[i].target;if(t&&t.classList&&t.classList.contains('gclip'))return;}\n      decorateSoon();\n    });\n    mo.observe(host,{childList:true,subtree:true});\n  }catch(e){}\n  decorateSoon();\n  setTimeout(decorateSoon,1500);setTimeout(decorateSoon,4000);\n}\n\n// ── attach-at-submission (agent-add-deal): stage files, then attach after save ──\nvar STAGED=[];\nfunction fmtStaged(){return STAGED.length?(STAGED.length+' file'+(STAGED.length===1?'':'s')+' ready — they attach when you save the deal'):'';}\nfunction placeAddControl(){\n  if(!ON_ADD||document.getElementById('_gaddwrap'))return;\n  // put the control just before the primary save/submit button\n  var btns=document.querySelectorAll('button');\n  var save=null;\n  for(var i=0;i<btns.length;i++){var t=(btns[i].textContent||'').toLowerCase();if(/save deal|send to john|send for|submit|add deal|save & |save and /.test(t)){save=btns[i];break;}}\n  var wrap=document.createElement('div');wrap.id='_gaddwrap';\n  wrap.style.cssText='margin:10px 0;font-family:Inter,system-ui,sans-serif';\n  wrap.innerHTML='<label for=\"_gaddin\" style=\"display:inline-flex;align-items:center;gap:8px;border:1px dashed #c9d4f7;background:#f6f9ff;color:#2450DC;font-weight:700;font-size:13px;border-radius:10px;padding:9px 13px;cursor:pointer\">📎 Attach files (optional)</label>'\n    +'<input id=\"_gaddin\" type=\"file\" multiple accept=\".pdf,.xls,.xlsx,.csv,.doc,.docx,.png,.jpg,.jpeg,.heic,.txt,.ppt,.pptx\" style=\"display:none\">'\n    +'<span id=\"_gaddmsg\" style=\"font-size:12px;color:#71717A;margin-left:10px\"></span>';\n  if(save&&save.parentNode)save.parentNode.insertBefore(wrap,save);\n  else document.body.appendChild(wrap);\n  document.getElementById('_gaddin').addEventListener('change',function(){\n    var fs=Array.prototype.slice.call(this.files||[]);\n    fs.forEach(function(f){if(f.size<=MAXB)STAGED.push(f);});\n    var m=document.getElementById('_gaddmsg');if(m)m.textContent=fmtStaged();\n  });\n}\nfunction b64(f,cb){var fr=new FileReader();fr.onload=function(){var d=String(fr.result||'');var i=d.indexOf('base64,');cb(i>=0?d.slice(i+7):'');};fr.onerror=function(){cb('');};fr.readAsDataURL(f);}\nfunction attachStagedTo(dealId){\n  if(!STAGED.length||!dealId)return;\n  var files=STAGED.slice();STAGED=[];var m=document.getElementById('_gaddmsg');if(m)m.textContent='Attaching '+files.length+' file'+(files.length===1?'':'s')+'…';\n  var ok=0,fail=0,i=0;(function next(){\n    if(i>=files.length){\n      if(m)m.textContent=fail?((ok?('Attached '+ok+' file'+(ok===1?'':'s')+'; '):'')+fail+' didn’t save — open My Deals to retry.'):'Files attached to the deal ✓';\n      return;\n    }\n    var f=files[i++];\n    b64(f,function(data){\n      if(!data){fail++;return next();}\n      fetch('/api/grove',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',\n        body:JSON.stringify({action:'dealAttach',dealId:dealId,name:f.name,mime:f.type||'application/octet-stream',size:f.size,data:data})})\n        .then(function(r){return r.json();}).then(function(j){if(j&&j.ok)ok++;else fail++;next();}).catch(function(){fail++;next();});\n    });\n  })();\n}\n// Wrap fetch so a new-deal submit carries a known dealId and its staged files attach\n// after the deal is saved. Defensive: only touches agentDeal posts; passes everything\n// else straight through, and never throws.\nfunction wrapFetch(){\n  if(!ON_ADD||window.__GFETCHWRAP__)return;window.__GFETCHWRAP__=1;\n  var of=window.fetch;\n  window.fetch=function(input,init){\n    try{\n      var url=(typeof input==='string')?input:(input&&input.url)||'';\n      var isPost=init&&init.method&&String(init.method).toUpperCase()==='POST';\n      if(isPost&&/\\/api\\/grove(\\?|$)/.test(url)&&init.body&&typeof init.body==='string'&&init.body.indexOf('\"agentDeal\"')>=0&&STAGED.length){\n        // Let the request go untouched; the SERVER assigns the DealID and returns it.\n        // We read it off the (cloned) response and attach the staged files to it.\n        var p=of.call(this,input,init);\n        p.then(function(r){return r.clone().json().catch(function(){return null;});}).then(function(j){\n          if(j&&j.ok&&j.dealId)attachStagedTo(j.dealId);\n          else if(j&&j.ok){var mm=document.getElementById('_gaddmsg');if(mm)mm.textContent='Deal saved — open My Deals to attach your files.';}\n        }).catch(function(){});\n        return p;\n      }\n    }catch(e){}\n    return of.call(this,input,init);\n  };\n}\n\nfunction boot(){if(ON_LIST){refreshDeals(function(){decorate();watch();});}if(ON_ADD){placeAddControl();wrapFetch();setTimeout(placeAddControl,1500);setTimeout(placeAddControl,3500);}}\nif(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();\ndocument.addEventListener('keydown',function(e){if(e.key==='Escape'&&MODAL)closeModal();});\n})();\n" + "</scr"+"ipt>";
// One save indicator for the whole hub (audit fix #7). Every page invented its own
// ("Saved ✓", "Backed up ✓", toasts, pills, all in different corners) — this wraps
// fetch and shows a single bottom-center pill for every write to the data APIs:
// "Saving…" → "✓ Saved" (green) or "✗ Not saved" (red, stays up longer). Pages'
// own inline hints still work; this is the one consistent signal people learn once.
const GSAVE_SNIPPET = `<script>(function(){if(window.__GSAVEPILL__)return;window.__GSAVEPILL__=1;
var WRITE=/^\\/api\\/(grove|summit|uw(\\/item)?|board-deals|access)(\\?|$)/;
var el=null,hideT=null,inflight=0;
function pill(){if(el)return el;el=document.createElement('div');el.id='gsavepill';
el.style.cssText='position:fixed;left:50%;bottom:14px;transform:translateX(-50%) translateY(70px);z-index:2147483000;background:#fff;color:#0A0A0B;border:1.5px solid #E4E4E7;border-radius:30px;padding:8px 16px;font:600 13px Inter,system-ui,sans-serif;box-shadow:0 6px 24px rgba(0,0,0,.16);transition:transform .18s ease;pointer-events:none;white-space:nowrap';
document.body.appendChild(el);return el;}
function show(t,c,ms){var p=pill();p.textContent=t;p.style.color=c||'#0A0A0B';p.style.transform='translateX(-50%) translateY(0)';if(hideT)clearTimeout(hideT);if(ms)hideT=setTimeout(hide,ms);}
function hide(){if(el)el.style.transform='translateX(-50%) translateY(70px)';}
var of=window.fetch;
window.fetch=function(input,init){
  var url='',method='GET';
  try{url=(typeof input==='string')?input:(input&&input.url)||'';method=((init&&init.method)||(input&&input.method)||'GET').toUpperCase();}catch(e){}
  var isWrite=false;
  try{var path=url.replace(/^https?:\\/\\/[^\\/]+/,'');isWrite=(method==='POST'||method==='DELETE')&&WRITE.test(path);}catch(e){}
  if(!isWrite)return of.apply(this,arguments);
  inflight++;show('Saving…','#4E5866');
  var p=of.apply(this,arguments);
  p.then(function(r){
    inflight--;if(inflight>0)return;
    if(!r||!r.ok){show('✗ Not saved — try again','#B4453C',5000);return;}
    r.clone().json().then(function(j){
      if(j&&j.ok===false)show('✗ Not saved'+(j.error?(' — '+String(j.error).slice(0,40)):''),'#B4453C',5000);
      else show('✓ Saved','#3A7A46',1600);
    }).catch(function(){show('✓ Saved','#3A7A46',1600);});
  },function(){inflight--;if(inflight<=0)show('✗ Not saved — check connection','#B4453C',5000);});
  return p;
};})();</script>`;
function withMaps(html){
  // Inject before the LAST </body> — the real page end. Using the first one landed a
  // <script> inside deal-analyzer's document.write() PDF template, whose unescaped
  // </script> then closed the React app early and spilled its code onto the page.
  // Money formatter + AI helpers go on EVERY page; maps only when an API key is set.
  const PROP_LOOKUP_SNIPPET = `<script>(function(){
if(window.__GPROP__)return;window.__GPROP__=1;
function money(n){n=Math.round(Number(n)||0);return '$'+n.toLocaleString('en-US');}
function lblText(el){var t='';try{if(el.id){var l=document.querySelector('label[for="'+el.id+'"]');if(l)t+=' '+l.textContent;}}catch(e){}var p=el.closest&&el.closest('label');if(p)t+=' '+p.textContent;var pe=el.previousElementSibling;if(pe&&pe.tagName==='LABEL')t+=' '+pe.textContent;if(el.parentElement){var lab=el.parentElement.querySelector&&el.parentElement.querySelector('label,span');if(lab)t+=' '+lab.textContent;}return t.toLowerCase();}
function isAddr(el){var s=((el.id||'')+' '+(el.name||'')+' '+(el.placeholder||'')+' '+(el.className||'')+' '+lblText(el)).toLowerCase();return el.tagName==='INPUT'&&(el.type===''||el.type==='text')&&/address|\\bgaddr\\b|street/.test(s)&&!/email|owner\\s*name|seller|buyer|website|url|\\bcomp\\b|landlord\\s*(name|mailing)|mailing/.test(s);}
function findTax(){var els=document.querySelectorAll('input');for(var i=0;i<els.length;i++){var el=els[i];var s=((el.id||'')+' '+(el.name||'')+' '+(el.placeholder||'')+' '+lblText(el)).toLowerCase();if(/tax/.test(s)&&!/after|w-?9|syntax/.test(s))return el;}return null;}
function addMag(el){if(el.__gmag)return;el.__gmag=1;var b=document.createElement('button');b.type='button';b.textContent='🔍';b.title='Owner lookup & research — opens in a new tab';b.style.cssText='margin-left:6px;border:1px solid #d4d4d8;background:#fff;border-radius:8px;padding:3px 7px;cursor:pointer;font-size:13px;vertical-align:middle;line-height:1';b.onclick=function(ev){ev.preventDefault();ev.stopPropagation();var q=(el.value||'').trim();window.open('/owner-lookup.html?q='+encodeURIComponent(q),'_blank','noopener');};try{if(el.parentNode)el.parentNode.insertBefore(b,el.nextSibling);}catch(e){}}
function setVal(el,v){if(!el)return;try{var p=Object.getPrototypeOf(el),d=Object.getOwnPropertyDescriptor(p,'value');d.set.call(el,String(v));}catch(e){el.value=String(v);}el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));}
function chip(addrEl,m){var old=document.getElementById('__propchip');if(old)old.remove();var c=document.createElement('div');c.id='__propchip';c.style.cssText='margin:5px 0 2px;font:600 12px system-ui,sans-serif;color:#0B1020';c.innerHTML='🏛️ Assessed <b>'+money(m.assessed)+'</b> · est. tax <b>'+money(m.taxAnnual)+'</b>/yr'+(m.yearBuilt?(' · built '+m.yearBuilt):'')+(m.city?(' · '+m.city):'')+' <span style="color:#71717A;font-weight:500">(tax estimated from town rate — edit if you have the bill)</span>';try{addrEl.parentNode.insertBefore(c,addrEl.nextSibling);}catch(e){}}
var box=null;function closeBox(){if(box){box.remove();box=null;}}
function openBox(addrEl,matches){closeBox();if(!matches.length)return;box=document.createElement('div');box.style.cssText='position:absolute;z-index:99998;background:#fff;border:1px solid #d4d4d8;border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.14);max-height:280px;overflow:auto;font:13px system-ui,sans-serif';var r=addrEl.getBoundingClientRect();box.style.left=(window.scrollX+r.left)+'px';box.style.top=(window.scrollY+r.bottom+4)+'px';box.style.width=Math.max(r.width,260)+'px';matches.forEach(function(m){var it=document.createElement('div');it.style.cssText='padding:9px 11px;cursor:pointer;border-bottom:1px solid #f1f1f4';it.innerHTML='<div style="font-weight:600">'+m.addr+(m.city?(', '+m.city):'')+'</div><div style="color:#71717A;font-size:12px">assessed '+money(m.assessed)+' · est. tax '+money(m.taxAnnual)+'/yr</div>';it.onmousedown=function(ev){ev.preventDefault();pick(addrEl,m);};box.appendChild(it);});document.body.appendChild(box);}
function pick(addrEl,m){setVal(addrEl,m.addr+(m.city?(', '+m.city):'')+(m.zip?(' '+m.zip):''));var t=findTax();if(t)setVal(t,m.taxAnnual);chip(addrEl,m);closeBox();}
var T=null;function onType(addrEl){clearTimeout(T);var q=addrEl.value.trim();if(q.length<3){closeBox();return;}T=setTimeout(function(){fetch('/api/property?q='+encodeURIComponent(q),{credentials:'include'}).then(function(r){return r.json();}).then(function(j){if(j&&j.ok)openBox(addrEl,j.matches||[]);}).catch(function(){});},350);}
function wire(){var els=document.querySelectorAll('input');for(var i=0;i<els.length;i++){(function(el){if(!isAddr(el))return;if(!el.__gmag)addMag(el);if(el.__gprop)return;el.__gprop=1;el.setAttribute('autocomplete','off');el.addEventListener('input',function(){onType(el);});el.addEventListener('blur',function(){setTimeout(closeBox,200);});})(els[i]);}}
window.addEventListener('scroll',closeBox,true);
if(document.readyState!=='loading')wire();else document.addEventListener('DOMContentLoaded',wire);
setInterval(wire,1500);
})();</script>`;
  // Google's address dropdown (.pac-container) is appended to <body> and left
  // floating when the field blurs, the page scrolls, or a modal opens over it —
  // that's the "stuck autocomplete" seen across the site. This dismisses any
  // orphaned dropdown and lifts its z-index so it shows correctly inside modals.
  const PAC_FIX_SNIPPET = `<script>(function(){
if(window.__PACFIX__)return;window.__PACFIX__=1;
var st=document.createElement('style');st.textContent='.pac-container{z-index:2147483000!important;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif!important;border-radius:10px;box-shadow:0 10px 30px rgba(11,16,32,.18);margin-top:2px}.pac-container:empty{display:none!important}';(document.head||document.documentElement).appendChild(st);
function pacs(){return document.querySelectorAll('.pac-container');}
function hideAll(){var l=pacs();for(var i=0;i<l.length;i++)l[i].style.display='none';}
function addrFocused(){var a=document.activeElement;return !!(a&&a.tagName==='INPUT'&&a.getAttribute('data-ac')==='1');}
document.addEventListener('focusout',function(e){var t=e.target;if(t&&t.getAttribute&&t.getAttribute('data-ac')==='1'){setTimeout(function(){if(!addrFocused())hideAll();},250);}},true);
window.addEventListener('scroll',function(){if(!addrFocused())hideAll();},true);
window.addEventListener('resize',function(){if(!addrFocused())hideAll();});
document.addEventListener('keydown',function(e){if(e.key==='Escape'||e.keyCode===27)hideAll();},true);
document.addEventListener('mousedown',function(e){var t=e.target;if(t&&t.closest){if(t.closest('.pac-container'))return;if(t.getAttribute&&t.getAttribute('data-ac')==='1')return;if(t.tagName==='INPUT'&&t.getAttribute&&t.getAttribute('data-ac')==='1')return;}setTimeout(function(){if(!addrFocused())hideAll();},0);},true);
})();</script>`;
  const inject = MONEYFMT_SNIPPET + PROP_LOOKUP_SNIPPET + AI_REWRITE_SNIPPET + AI_EXTRACT_SNIPPET + AI_AUTOFILL_SNIPPET + DEALFILES_SNIPPET + GSAVE_SNIPPET + PAC_FIX_SNIPPET + (GOOGLE_MAPS_KEY ? MAPS_SNIPPET : '');
  const i = html.lastIndexOf('</body>');
  return i >= 0 ? html.slice(0, i) + inject + html.slice(i) : html + inject;
}

// --- serve the dashboard with the role injected ---
// New app-shell home (home.html) is the front door. The previous hub is still
// reachable at /hub-v3.html and /?legacy=1 as an instant rollback.
app.get("/", ensureAuth, (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  // A public Reserve member has no hub home — the marketplace is their whole world.
  if (req.user.role === 'member') return res.redirect('/premarket-hub.html');
  // ?legacy=1 serves the old hub, which draws its menu client-side and would show
  // a Summit partner links they can't open. Keep them on the new shell.
  const legacy = ('legacy' in (req.query || {})) && req.user.role !== 'summit';
  const file = legacy ? "hub-v3.html" : "home.html";
  let html = fs.readFileSync(path.join(__dirname, file), "utf8");
  const inject = `<script>window.__ROLE__=${JSON.stringify(req.user.role)};window.__USER__=${JSON.stringify(req.user.name)};window.__EMAIL__=${JSON.stringify(req.user.email)};window.__AGENTNAME__=${JSON.stringify(agentDealName(req.user.email))};window.__ACCT__=${JSON.stringify(acctFor(req.user.role))};window.__MAPSKEY__=${JSON.stringify(GOOGLE_MAPS_KEY)};</script>`;
  html = html.replace("</head>", inject + "</head>");
  // Legacy hub needs the shared skin; the new home is self-styled.
  res.send(withMaps(stripSheetSecret(injectSkin(html))));
});
// Deals & Payouts page is owner-only — block everyone else before static serves the file
// (flip-underwriter is now part of the shared Underwrite Deals suite, so it's no longer owner-only)
app.use((req, res, next) => {
  if (/^\/deals-payouts\.html$/i.test(req.path)) {
    if (!req.isAuthenticated()) return res.redirect("/auth/google");
    if (req.user.role !== "owner") return res.status(403).send("Owners only.");
  }
  next();
});
// --- the bar every page gets: back to HQ, a live backup check, and sign out ---
// The backup light is a real round-trip: it writes a stamp to the sheet and reads
// it back. Green means saving genuinely works from this page, right now.
const GROVE_SHEET_URL = process.env.GROVE_SHEET_URL
  || "https://script.google.com/macros/s/AKfycbxLpHZlNw9yNa68Hu1EngEB0v8TwxgiwCBMTzvIy-zmw7C0ARSHmcucQKQlqIaakY93hA/exec";
const GROVE_SHEET_TOKEN = process.env.GROVE_SHEET_TOKEN || "grove-sheet-2026";
const SUMMIT_SHEET_URL = process.env.SUMMIT_SHEET_URL
  || "https://script.google.com/macros/s/AKfycbyRecBPswZ-zU8AWlB-8iI6K8TOFkCghmCQTaEfgGPfmqd5xZrShg5Azrnw9ItaGRyH/exec";
// The pulled leads live on their own little script, bound to their own sheet,
// so nothing that touches a court filing can reach a deal or a bank number.
// Unset = the lead list behaves exactly as it did before this line existed.
const LEADS_SHEET_URL = process.env.LEADS_SHEET_URL || "";

// ── Server-side Sheet Proxy ───────────────────────────────────────────────────
// All direct sheet calls are routed through here so the shared token is never
// sent to the browser. The client posts to /api/grove or /api/summit; the
// server strips any client-supplied token, adds the real server-side one, and
// forwards to Google. Owner-only actions are blocked for non-owners.
const OWNER_ONLY_GET_ACTIONS  = new Set(['owed','probateLeads','dumpAll','depositLinkLoad','depositlink','deposits_link']); // 'deposits' handled below: agents get ONLY their own logged rows
// C3: updateDeal replaces/deletes whole deals and replaceDeals rewrites the sheet —
// destructive, owner-only. agentDeal (self-submit, emails John) and dealPatch
// (in-place date edits on their own pipeline) stay available to agents.
const OWNER_ONLY_POST_ACTIONS = new Set(['owed','probateLeadDelete','updateDeal','deleteDeal','replaceDeals']); // depositSave opened to agents 2026-08-03 (John: agents log deposits)
function sheetSep(u){ return u.indexOf('?') < 0 ? '?' : '&'; }

// ── Pipeline Board shared storage ────────────────────────────────────────────
// The board page asked the sheet for `action=board`, but no such action exists
// on the Apps Script — every load fell through to the error branch and the page
// ran on nothing but that one browser's localStorage. Open it in a second
// browser and the board looked empty; the page then "backed up" that empty
// state over the real one. That is how the $74M board disappeared.
//
// There is no sheet-side change needed to fix it: /api/grove is a proxy, so the
// board request is answered here instead of being forwarded, and the board is
// kept in the ordinary note store under one key. Every signed-in Grove user
// reads and writes the same key, so the board is shared by construction.
const BOARD_NOTE_KEY = 'pipeline_board';
// A Google Sheets cell tops out at 50,000 characters. Refuse to write past that
// rather than storing a truncated board that would read back as corrupt — the
// page keeps its local copy and shows "Not saved", which is recoverable.
const BOARD_MAX_CHARS = 45000;
const boardCount = b => !b ? 0
  : ((b.forsale || []).length + (b.deals || []).length + ((b.closed || b.closedRows) || []).length);

async function boardRead() {
  try {
    const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(BOARD_NOTE_KEY));
    const v = noteValue(j);
    if (!v) return null;
    const b = typeof v === 'string' ? JSON.parse(v) : v;
    return (b && typeof b === 'object' && !Array.isArray(b)) ? b : null;
  } catch (e) { return null; }
}

// Board rows are company-wide, so any Grove person may read and write them.
// Guests (Citicore) and Summit partners are not Grove staff and never see it.
const boardMayUse = role => role === 'owner' || role === 'agent';

// The board page shows a 🔒 Private chip whose tooltip promises "Only you (and
// John) can see this". That promise used to be kept in the BROWSER only — the
// server handed every agent the whole board, so another agent's private deals
// were already sitting in the page, one dev-tools tab away. It is kept here now.
// Closed deals stay visible to everyone: that is the company board, by design.
function boardVisibleTo(board, user) {
  if (!board) return null;
  if (!user || user.role === 'owner') return board;
  const me = [agentDealName(user.email), user.name, user.email]
    .map(s => String(s || '').trim().toLowerCase()).filter(Boolean);
  const mine = r => { const by = String((r && r.by) || '').trim().toLowerCase(); return !!by && me.indexOf(by) >= 0; };
  const keep = rows => (Array.isArray(rows) ? rows : []).filter(r => r && (r.shared === true || mine(r)));
  return Object.assign({}, board, { forsale: keep(board.forsale), deals: keep(board.deals) });
}
// Because an agent is now sent only the rows they may see, their save carries
// only those rows. Storing that verbatim would delete every row that was
// withheld from them. So put the hidden rows back before writing.
function boardMergeHidden(cur, incoming, user) {
  if (!cur || !user || user.role === 'owner') return incoming;
  const vis = boardVisibleTo(cur, user) || {};
  const out = Object.assign({}, cur, incoming);
  ['forsale', 'deals'].forEach(k => {
    const all   = Array.isArray(cur[k]) ? cur[k] : [];
    const shown = new Set((Array.isArray(vis[k]) ? vis[k] : []).map(r => JSON.stringify(r)));
    const hidden = all.filter(r => !shown.has(JSON.stringify(r)));
    out[k] = hidden.concat(Array.isArray(incoming[k]) ? incoming[k] : []);
  });
  return out;
}

async function handleBoardGet(req, res) {
  const board = await boardRead();
  // No stored board yet: answer with no board rather than an empty one, so the
  // page offers up its own copy to seed the store instead of rendering blank.
  return res.json({ ok: true, board: boardVisibleTo(board, req.user) || null });
}

async function handleBoardPost(req, res, incoming) {
  let board = (incoming && typeof incoming === 'object' && !Array.isArray(incoming)) ? incoming : null;
  if (!board) return res.status(400).json({ ok: false, error: 'no_board' });
  // Restore the rows this user was never shown, so their save can't delete them.
  if (req.user && req.user.role !== 'owner') board = boardMergeHidden(await boardRead(), board, req.user);
  // The wipe guard. A save that empties a board which currently has rows is
  // almost always a browser that failed to load before it decided to "back up".
  // Emptying the board on purpose has to say so.
  if (boardCount(board) === 0) {
    const cur = await boardRead();
    if (boardCount(cur) > 0 && !(req.body && req.body.allowEmpty === true)) {
      console.warn('[board] refused empty overwrite of', boardCount(cur), 'rows from', req.user && req.user.email);
      return res.status(409).json({ ok: false, error: 'refused_empty_overwrite', rows: boardCount(cur) });
    }
  }
  const str = JSON.stringify(Object.assign({ _init: true }, board));
  if (str.length > BOARD_MAX_CHARS)
    return res.status(413).json({ ok: false, error: 'board_too_large', chars: str.length });
  const j = await sheetPost(GROVE_SHEET_URL, noteBody(BOARD_NOTE_KEY, str));
  if (!j || j.ok === false) return res.status(502).json({ ok: false, error: 'board_save_failed' });
  return res.json({ ok: true, saved: boardCount(board) });
}

// ── Live pipeline board (auto-pulls the real deal book) ──────────────────────
// The classic board above is a hand-kept note whose prices drift. This newer
// board reads the actual Deals & Payouts book instead, groups deals by stage,
// and is READ-ONLY — editing still happens in Deals & Payouts. The OWNER marks
// individual active deals Public (shown on the company board) or Private (owner
// only); the flag lives in a note here, so an agent's browser can't flip it.
// CRITICAL: the only fields that ever leave this endpoint are address, unit,
// price, stage, submittedBy and the three key dates. Split lines, fees and
// totals are never included, so the board can't leak one agent's commissions.
const BOARD_VIS_KEY = 'board_vis';   // { dealId: true } → true = Public
async function boardVisRead() {
  try {
    const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(BOARD_VIS_KEY));
    const v = noteValue(j);
    const m = v ? (typeof v === 'string' ? JSON.parse(v) : v) : {};
    return (m && typeof m === 'object' && !Array.isArray(m)) ? m : {};
  } catch (e) { return {}; }
}
// Mirror of the client dealStage(): an explicit stage wins; otherwise a fully
// paid, collected deal is Closed and everything else is Under Agreement.
function boardDealStage(d) {
  if (d && d.stage) return String(d.stage);
  const done = d && Array.isArray(d.lines) && d.lines.length > 0 && d.fee === 'collected' && d.lines.every(l => l && l.paid);
  return done ? 'Closed' : 'Under Agreement';
}
const BOARD_SHOWN_STAGES = { 'For Sale': 1, 'Under Agreement': 1, 'Closed': 1 };
function boardCardOf(d, vis) {
  const id = String((d && (d.dealId || d.id)) || '');
  const dd = (d && d.dates) || {};
  return {
    dealId: id,
    property: String((d && d.property) || ''),
    unit: String((d && d.unit) || ''),
    price: Number(d && d.price) || 0,
    stage: boardDealStage(d),
    by: String((d && d.submittedBy) || ''),
    dates: { inspection: dd.inspection || '', finance: dd.finance || '', closing: dd.closing || '' },
    pub: vis[id] === true
  };
}
async function handleBoardDealsGet(req, res) {
  const [book, vis] = await Promise.all([
    sheetGet(GROVE_SHEET_URL, 'dealsLoad', '&year=' + encodeURIComponent(String(req.query.year || '2026'))).catch(() => null),
    boardVisRead()
  ]);
  const all = (book && Array.isArray(book.deals)) ? book.deals : [];
  const role = req.user.role;
  const me    = String(agentDealName(req.user.email) || '').toUpperCase().trim();
  const uname = String(req.user.name || '').toUpperCase().trim();
  const email = String(req.user.email || '').toLowerCase().trim();
  const ownsSelf = d => {
    const sub = String((d && d.submittedBy) || '').trim();
    if (role === 'owner' && sub === '') return true;              // unassigned rolls up to the owner
    const bySub  = !!sub && (sub.toUpperCase() === me || sub.toUpperCase() === uname || sub.toLowerCase() === email);
    const byLine = !!me && Array.isArray(d && d.lines) && d.lines.some(l => String((l && l.agent) || '').toUpperCase() === me);
    return bySub || byLine;
  };
  // Sales pipeline only — rentals carry a fee, not a sale price, so they showed
  // up at $0 and muddied the Closed list (John's Aug 7 board fix). Drop anything
  // whose type reads as a rental/lease.
  const isSale = d => !/rent|lease/i.test(String((d && d.type) || ''));
  const shown = all.filter(d => BOARD_SHOWN_STAGES[boardDealStage(d)] && isSale(d));
  const mine = [], company = [], everything = [];
  shown.forEach(d => {
    const card = boardCardOf(d, vis);
    if (ownsSelf(d)) mine.push(card);
    if (card.stage === 'Closed' || card.pub === true) company.push(card);  // closed = company record; else Public only
    if (role === 'owner') everything.push(card);
  });
  return res.json({ ok: true, role, me, mine, company, everything: role === 'owner' ? everything : undefined });
}
async function handleBoardVisPost(req, res, body) {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const id = String((body && body.dealId) || '').trim();
  if (!id) return res.status(400).json({ ok: false, error: 'no_deal' });
  const vis = await boardVisRead();
  if (body && body.public === true) vis[id] = true; else delete vis[id];
  const j = await sheetPost(GROVE_SHEET_URL, noteBody(BOARD_VIS_KEY, JSON.stringify(vis)));
  if (!j || j.ok === false) return res.status(502).json({ ok: false, error: 'vis_save_failed' });
  return res.json({ ok: true, dealId: id, public: vis[id] === true });
}
app.get("/api/board-deals", ensureAuth, async (req, res) => {
  if (!boardMayUse(req.user.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try { return await handleBoardDealsGet(req, res); }
  catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
});
app.post("/api/board-deals", ensureAuth, async (req, res) => {
  if (!boardMayUse(req.user.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try { return await handleBoardVisPost(req, res, req.body || {}); }
  catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
});

// Hub Postgres status (owner-only). ok:false with "no DATABASE_URL" = still on Sheets.
app.get("/api/grove/health", ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  res.json(await gdb.health());
});
// One-time warm-up: pull every note off the Grove sheet into Postgres now (owner-only).
// Optional — read-through already migrates each note the first time it's touched.
app.post("/api/grove/import", ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  if (!gdb.on) return res.json({ ok: false, error: 'no DATABASE_URL' });
  try {
    const dump = await _sheetGetRaw(GROVE_SHEET_URL, 'notesAll', '');
    let map = {};
    if (dump && dump.notes && typeof dump.notes === 'object' && !Array.isArray(dump.notes)) map = dump.notes;
    else if (dump && Array.isArray(dump.notes)) dump.notes.forEach(n => { if (n && n.notekey != null) map[n.notekey] = (n.value != null ? n.value : n.notes); });
    else if (dump && dump.values && typeof dump.values === 'object') map = dump.values;
    const out = await gdb.importNotes(map);
    // Also pull the whole deals book into Postgres so the ledger is fully seeded now
    // (read-through would migrate it on first touch anyway; this makes it immediate).
    let dealsOut = { deals: 0 };
    try { dealsOut = await gdb.importDeals(await _dealsRaw('')); } catch (e) { dealsOut = { deals: 0, dealsError: String(e && e.message || e) }; }
    res.json(Object.assign({}, out, dealsOut));
  } catch (e) { res.status(500).json({ ok: false, error: String(e && e.message || e) }); }
});

app.get("/api/grove", ensureAuth, async (req, res) => {
  // Coerce query params to scalars FIRST. Express's qs parser turns ?action[]=x into an
  // ARRAY, and Set.has([...]) / (action === 'dealsLoad') silently miss — which would let
  // an array-valued action skip the internal-action block, the owner-only gate AND the
  // dealsLoad redaction, then re-serialize to the exact scalar on the way to the sheet
  // (leaking every deal's files + the full unredacted book). Normalise before any gate.
  const _scalar = v => Array.isArray(v) ? (v[0] == null ? '' : String(v[0])) : v;
  req.query.action = String(_scalar(req.query.action) || '');
  if (req.query.notekey != null) req.query.notekey = String(_scalar(req.query.notekey));
  if (req.query.year != null) req.query.year = String(_scalar(req.query.year));
  const action = req.query.action;
  if (INTERNAL_GROVE_ACTIONS.has(action)) return res.status(403).json({ ok: false, error: 'forbidden' });
  if (OWNER_ONLY_GET_ACTIONS.has(action) && req.user.role !== 'owner')
    return res.status(403).json({ ok: false, error: 'forbidden' });
  // Summit partner: notes only. No deals, no deposits, no sheet actions of any kind.
  if (req.user.role === 'summit' && action !== 'notes')
    return res.status(403).json({ ok: false, error: 'forbidden' });
  if (action === 'board') {
    if (!boardMayUse(req.user.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
    try { return await handleBoardGet(req, res); }
    catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // Profile pictures: any signed-in user may read any profilepic_* key (it's just an avatar).
  if (!(action === 'notes' && /^profilepic_/i.test(String(req.query.notekey || ''))) &&
      ownerOnlyNote(action, req.query.notekey, req.user.role, false, req.user.email))
    return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    let url = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL)
      + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN);
    if (action)            url += '&action='   + encodeURIComponent(action);
    if (req.query.notekey) url += '&notekey='  + encodeURIComponent(personalKey(req.query.notekey, req.user));
    if (req.query.year)    url += '&year='     + encodeURIComponent(req.query.year);
    if (req.query._)       url += '&_='        + encodeURIComponent(req.query._);
    // NOTES read through Postgres when DATABASE_URL is set (read-through: a first
    // miss lazily pulls from the sheet and backfills PG). Deals stay on Sheets for
    // now. Redaction below runs on `j` unchanged, so the note shape must match the
    // sheet's: {ok,value,notes}.
    let j;
    if (gdb.on && action === 'notes' && req.query.notekey) {
      const key = personalKey(req.query.notekey, req.user);
      const v = await gdb.noteGet(key, async (k) => noteValue(await _sheetGetRaw(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(k))));
      j = { ok: true, value: v == null ? '' : v, notes: v == null ? '' : v };
    } else if (gdb.on && action === 'dealsLoad') {
      const deals = await gdb.dealsBook(String(req.query.year || ''), (y) => _dealsRaw(y));
      j = { ok: true, deals: Array.isArray(deals) ? deals : [] };
    } else {
      const r = await fetch(url);
      j = await r.json();
    }
    // Redact dealsLoad for non-owners so the proxy can't leak the full deal set (agent-pay/
    // agent-goals get only their own deals + own split line; guests get none).
    if (action === 'dealsLoad' && j && Array.isArray(j.deals)) {
      // Owner gets the full book (redactDeals is a no-op for owner); agents get only
      // their own deals. Either way we join each deal's file list for the paperclip.
      const fmap = await loadDealFiles();
      const deals = withAttachments(redactDeals(j.deals, req.user), fmap);
      return res.json(Object.assign({}, j, { deals }));
    }
    // Deposits: agents may log deposits, so they may also see the list — but ONLY rows
    // they logged themselves (matched on LoggedBy vs their email/name). Guests get none.
    if (action === 'deposits' && req.user.role !== 'owner' && j) {
      if (req.user.role !== 'agent') return res.status(403).json({ ok: false, error: 'forbidden' });
      const arr = j.deposits || j.data || j.rows || (Array.isArray(j) ? j : []);
      // B5 fix: req.user.agentName was never set on the session — it is computed
      // fresh inside /api/me and thrown away — so this match term was always ''.
      // Resolve it here instead, which also means existing sessions work without
      // anyone having to log out and back in.
      const me = [String(req.user.email || ''), String(req.user.name || ''), String(agentDealName(req.user.email) || '')]
        .map(s => s.trim().toLowerCase()).filter(Boolean);
      // B4 fix: this used to be a two-way substring test — lb.indexOf(m) >= 0 ||
      // m.indexOf(lb) >= 0 — so a short sheet code like "JF" matched any row whose
      // LoggedBy merely CONTAINED those letters, and one agent could be shown
      // another's deposit. Now: exact match on the whole normalised value, or an
      // exact match on an email address embedded in it (covers rows stored as
      // "Tyler Smith <tyler@…>" or "Tyler (tyler@…)"). An email can't collide.
      const mine = (Array.isArray(arr) ? arr : []).filter(d => {
        const lb = String((d && (d.loggedBy != null ? d.loggedBy : d.LoggedBy)) || '').trim().toLowerCase();
        if (!lb) return false;
        if (me.indexOf(lb) >= 0) return true;                       // whole value matches
        const inner = lb.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/g) || [];
        return inner.some(e => me.indexOf(e) >= 0);                 // embedded email matches
      });
      return res.json(Object.assign({}, (Array.isArray(j) ? { ok: true } : j), { deposits: mine, data: undefined, rows: undefined }));
    }
    // Agent Goals are private — John's call, 2026-08-06. The goals page fetches ONE
    // note holding every agent's targets, then draws only the signed-in agent's row.
    // The hiding was cosmetic: the whole team's numbers still arrived in the agent's
    // browser, so anyone who opened the network tab read everybody's targets. Filter
    // it here so an agent only ever receives their own line. Owner is untouched and
    // still manages everyone from one place; writing goals stays owner-only, which is
    // what ownerOnlyNote already enforces, so this changes reading only.
    if (action === 'notes' && /^agent_goals/i.test(String(req.query.notekey || ''))
        && req.user.role !== 'owner' && j) {
      const mineName = String(agentDealName(req.user.email) || '').toUpperCase().trim();
      const raw = (j.value != null ? j.value : j.notes);
      let out = '';
      if (raw) {
        try {
          const all  = JSON.parse(String(raw));
          const one  = {};
          if (mineName && all && typeof all === 'object') {
            // Match the stored key case-insensitively — the note is written from a
            // fixed uppercase roster today, but a rename shouldn't silently blank
            // somebody's own goals.
            const k = Object.keys(all).find(x => String(x).toUpperCase().trim() === mineName);
            if (k) one[k] = all[k];
          }
          out = JSON.stringify(one);
        } catch (e) { out = '{}'; }   // unreadable note → send nothing, never everything
      }
      return res.json(Object.assign({}, j, { value: out, notes: out }));
    }
    // Citicore Investments: a co-investor (agent/guest) only ever receives the buildings
    // they're an investor-with-access on, with co-investors stripped and statements limited
    // to those same buildings. Owner + bookkeeper are untouched (trusted, full view).
    if (action === 'notes' && (req.user.role === 'agent' || req.user.role === 'guest')) {
      const nk = String(req.query.notekey || '').toLowerCase();
      const email = String(req.user.email || '').toLowerCase().trim();
      const invHit = p => !!email && p && !p.invest && Array.isArray(p.investors) && p.investors.some(iv => iv && iv.access && String(iv.email || '').toLowerCase().trim() === email);
      if (nk === 'ccp_properties') {
        const raw = (j.value != null ? j.value : j.notes);
        let out = '[]';
        try {
          const arr = JSON.parse(String(raw || '[]'));
          const mine = (Array.isArray(arr) ? arr : []).filter(invHit)
            .map(p => Object.assign({}, p, { investors: (p.investors || []).filter(iv => String(iv.email || '').toLowerCase().trim() === email) }));
          out = JSON.stringify(mine);
        } catch (e) { out = '[]'; }
        return res.json(Object.assign({}, j, { value: out, notes: out }));
      }
      if (nk === 'ccp_stmts') {
        const allowed = new Set();
        try {
          const pu = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL) + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN) + '&action=notes&notekey=ccp_properties';
          const pj = await fetch(pu).then(r => r.json());
          const praw = pj && (pj.value != null ? pj.value : pj.notes);
          const arr = JSON.parse(String(praw || '[]'));
          (Array.isArray(arr) ? arr : []).forEach(p => { if (invHit(p) && p.propId) allowed.add(p.propId); });
        } catch (e) { /* unreadable → no access */ }
        const raw = (j.value != null ? j.value : j.notes);
        let out = '{}';
        try {
          const all = JSON.parse(String(raw || '{}'));
          const filt = {};
          Object.keys(all || {}).forEach(k => { if (allowed.has(k)) filt[k] = all[k]; });
          out = JSON.stringify(filt);
        } catch (e) { out = '{}'; }
        return res.json(Object.assign({}, j, { value: out, notes: out }));
      }
    }
    res.json(j);
  } catch(e) { res.status(502).json({ ok: false, error: String(e) }); }
});

app.post("/api/grove", ensureAuth, async (req, res) => {
  const b = req.body || {};
  const _scalarP = v => Array.isArray(v) ? (v[0] == null ? '' : String(v[0])) : v;
  const action = String(_scalarP(b.action) || '');
  b.action = action;                                 // forward the coerced scalar, never an array
  if (b.notekey != null) b.notekey = String(_scalarP(b.notekey));
  if (INTERNAL_GROVE_ACTIONS.has(action)) return res.status(403).json({ ok: false, error: 'forbidden' });
  if (OWNER_ONLY_POST_ACTIONS.has(action) && req.user.role !== 'owner')
    return res.status(403).json({ ok: false, error: 'forbidden' });
  // Summit partner: notes only, same as the read side.
  if (req.user.role === 'summit' && action !== 'notes')
    return res.status(403).json({ ok: false, error: 'forbidden' });
  // Board save. The page in the field posts {token, board} with no action at all,
  // so match on the board payload as well as the action name — that way the fix
  // works for the copy already in people's browsers, before the page is updated.
  if (action === 'board' || (!action && b.board && typeof b.board === 'object')) {
    if (!boardMayUse(req.user.role)) return res.status(403).json({ ok: false, error: 'forbidden' });
    try { return await handleBoardPost(req, res, b.board); }
    catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // Profile pictures: a user may write ONLY their own profilepic_<email> key.
  const _pk = String(b.notekey || '');
  if (action === 'notes' && /^profilepic_/i.test(_pk)) {
    if (_pk.toLowerCase() !== 'profilepic_' + String(req.user.email || '').toLowerCase())
      return res.status(403).json({ ok: false, error: 'forbidden' });
  } else if (ownerOnlyNote(action, b.notekey, req.user.role, true, req.user.email)) {
    return res.status(403).json({ ok: false, error: 'forbidden' });
  }
  if (action === 'notes' && b.notekey) b.notekey = personalKey(b.notekey, req.user);
  // John just saved the Access Control grid — drop the cached copy so the very
  // next page load re-reads it instead of waiting out the 30s timer.
  if (action === 'notes' && String(b.notekey || '').toLowerCase() === 'hub_perms') PERMS_AT = 0;
  // NOTE WRITE → Postgres (authoritative) + best-effort mirror to the Grove sheet,
  // when DATABASE_URL is set. Matches the GET-side note read so a value saved here
  // is the value read back. b.notekey already carries personalKey; b.value is the
  // note body. Deals and every other action fall through to the sheet unchanged.
  if (gdb.on && action === 'notes' && b.notekey != null) {
    const key = String(b.notekey);
    const val = b.value != null ? b.value : (b.notes != null ? b.notes : '');
    try { await gdb.noteSet(key, val, async () => { await _sheetPostRaw(GROVE_SHEET_URL, b); }); return res.json({ ok: true }); }
    catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // emailForm sends real mail from John's Google account, and the recipient came
  // straight from the browser — so any signed-in person could have used the hub
  // as a relay to mail anyone in the world, from John. The only page that uses
  // this action is the landlord check request, which always goes to the office
  // anyway. Non-owners now get a fixed recipient no matter what they post, and
  // the subject/body are capped so the mail can't be stuffed.
  if (action === 'emailForm' && req.user.role !== 'owner') {
    b.to      = 'john@gpgboston.com';
    b.cc      = undefined;
    b.bcc     = undefined;
    b.subject = String(b.subject || 'Form submission').slice(0, 200);
    b.body    = String(b.body || '').slice(0, 20000);
  }
  // Save to Drive, from the three underwriter pages. The browser was sending two
  // fields the server should never take its word for: `by` (whose name goes on the
  // saved file) and `owner` (a plain true/false claiming the sender is John). The
  // Apps Script has no reason to trust either, and a saved file signed with someone
  // else's name is a small lie that is hard to spot later. Both are now set here
  // from the signed-in session, so whatever the page sends is discarded.
  if (action === 'driveExport') {
    b.by    = String(req.user.name || req.user.email || '').slice(0, 120);
    b.email = String(req.user.email || '').toLowerCase();
    b.owner = (req.user.role === 'owner');
  }
  // Agents may edit the descriptive fields of THEIR OWN deals (property/unit/date/listing).
  // The server verifies ownership from the full book, then rebuilds a complete updateDeal
  // with the ORIGINAL split lines — agents never see co-agent lines, so the client could
  // never send them back safely. Money fields (total/fee/splits/price) are NOT editable here.
  if (action === 'agentEditDeal') {
    if (req.user.role !== 'agent' && req.user.role !== 'owner')
      return res.status(403).json({ ok: false, error: 'forbidden' });
    try {
      const mine = String(agentDealName(req.user.email) || '').toUpperCase();
      const lookId = String(b.dealId || b.oldKey || '');
      if (!lookId) return res.status(400).json({ ok: false, error: 'no_deal' });
      const all = await sheetGet(GROVE_SHEET_URL, 'dealsLoad', '');
      const deal = ((all && all.deals) || []).find(d => d && (String(d.dealId || '') === lookId || String(d.id || '') === lookId));
      if (!deal) return res.status(404).json({ ok: false, error: 'not_found' });
      const onDeal = (deal.lines || []).some(l => String(l.agent || '').toUpperCase() === mine);
      if (req.user.role !== 'owner' && !onDeal) return res.status(403).json({ ok: false, error: 'not_your_deal' });
      // Lock editing once the agent has been paid out — owner can still edit anytime.
      const myPaid = (deal.lines || []).some(l => String(l.agent || '').toUpperCase() === mine && l.paid);
      if (req.user.role !== 'owner' && myPaid) return res.status(403).json({ ok: false, error: 'paid_locked', message: 'This deal has been paid out — ask John for changes.' });
      const ch = (b.changes && typeof b.changes === 'object') ? b.changes : {};
      const upd = { ...deal };
      // Agents may fix descriptive fields + status/note while the deal is active.
      // Money (total/fee/splits/price) stays owner-only.
      ['property', 'unit', 'date', 'listing', 'stage', 'note'].forEach(k => { if (ch[k] != null && !(k === 'stage' && ch[k] === '')) upd[k] = String(ch[k]).slice(0, k === 'note' ? 1500 : 200); });
      const fwd = { action: 'updateDeal', oldKey: (deal.dealId || deal.id),
        deal: { dealId: deal.dealId || '', date: upd.date || '', property: upd.property, type: deal.type, unit: upd.unit || '',
          price: (deal.price != null ? deal.price : ''), total: (deal.total != null ? deal.total : ''), fee: deal.fee || 'pending',
          seller: deal.seller || '', buyer: deal.buyer || '', listing: upd.listing || '', client: deal.client || '', note: upd.note || '',
          submittedBy: deal.submittedBy || '', stage: upd.stage || '', dates: deal.dates || {}, lines: deal.lines || [] } };
      // Through Postgres (authoritative) + Sheets mirror when DATABASE_URL is set;
      // straight to Sheets otherwise. Same path as the /api/grove updateDeal proxy.
      const jj = gdb.on ? await dealWriteThrough('updateDeal', fwd) : await _sheetPostRaw(GROVE_SHEET_URL, fwd);
      return res.json(jj);
    } catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // Attach / detach a file on a deal. Agents may only touch THEIR OWN deals (verified
  // from the full book, exactly like agentEditDeal); the owner may touch any. The file
  // itself goes to a Drive folder via the backend dealUpload; the association is stored
  // in the DealFiles tab (dealFileAdd/Del) — nothing here rewrites the deal's money rows.
  if (action === 'dealAttach' || action === 'dealDetach') {
    if (req.user.role !== 'agent' && req.user.role !== 'owner')
      return res.status(403).json({ ok: false, error: 'forbidden' });
    try {
      const dealId = String(b.dealId || '').trim();
      if (!dealId) return res.status(400).json({ ok: false, error: 'no_deal' });
      const all = await sheetGet(GROVE_SHEET_URL, 'dealsLoad', '');
      const deal = ((all && all.deals) || []).find(d => d && (String(d.dealId || '') === dealId || String(d.id || '') === dealId));
      if (!deal) return res.status(404).json({ ok: false, error: 'not_found' });
      if (req.user.role !== 'owner') {
        const mine = String(agentDealName(req.user.email) || '').toUpperCase();
        const meNames = [String(req.user.name || '').toUpperCase().trim(), mine, String(req.user.email || '').toLowerCase()].filter(Boolean);
        const sub = String(deal.submittedBy || '').trim();
        // Guard on !!mine: a roster-added agent with no sheet code yet has mine === '',
        // which would otherwise match every deal carrying a blank split line.
        const onDeal = (!!mine && (deal.lines || []).some(l => String(l.agent || '').toUpperCase() === mine))
          || (!!sub && meNames.some(x => sub.toUpperCase() === x || sub.toLowerCase() === x));
        if (!onDeal) return res.status(403).json({ ok: false, error: 'not_your_deal' });
      }
      const key = String(deal.dealId || deal.id || dealId);
      const who = req.user.name || agentDealName(req.user.email) || req.user.email || '';
      if (action === 'dealAttach') {
        const data = String(b.data || '');
        if (!data) return res.status(400).json({ ok: false, error: 'no_file' });
        if (data.length > 21 * 1024 * 1024) return res.status(413).json({ ok: false, error: 'too_big' });
        const up = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          body: JSON.stringify({ action: 'dealUpload', token: GROVE_SHEET_TOKEN, name: String(b.name || 'file').slice(0, 200), mime: String(b.mime || 'application/octet-stream').slice(0, 120), size: Number(b.size) || 0, data }) }).then(r => r.json());
        if (!(up && up.ok && up.fileId)) return res.status(502).json({ ok: false, error: (up && up.error) || 'upload_failed' });
        const rec = { action: 'dealFileAdd', token: GROVE_SHEET_TOKEN, dealId: key, name: up.name || String(b.name || 'file').slice(0, 200),
          url: up.url || '', view: up.view || up.url || '', fileId: up.fileId, size: Number(b.size) || 0, by: who,
          at: new Date().toISOString().slice(0, 16).replace('T', ' ') };
        const add = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(rec) }).then(r => r.json());
        if (!(add && add.ok)) return res.status(502).json({ ok: false, error: (add && add.error) || 'save_failed' });
      } else {
        const fileId = String(b.fileId || '').trim();
        if (!fileId) return res.status(400).json({ ok: false, error: 'no_file' });
        const del = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          body: JSON.stringify({ action: 'dealFileDel', token: GROVE_SHEET_TOKEN, dealId: key, fileId }) }).then(r => r.json());
        if (!(del && del.ok)) return res.status(502).json({ ok: false, error: (del && del.error) || 'delete_failed' });
      }
      DEALFILES_AT = 0;                                   // bust the cache so the next load is fresh
      const fmap = await loadDealFiles(true);
      return res.json({ ok: true, attachments: fmap[key] || [] });
    } catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // New deal from an agent. Two things were going wrong here.
  //
  // The submitter was taken from whatever name the browser happened to have —
  // which was blank on any page that never loaded /api/me, so deals arrived with
  // no submitter and there was no way to tell who had entered them. It is now
  // stamped from the signed-in session, and the client's value is ignored: an
  // agent cannot file a deal under somebody else's name.
  //
  // The apartment number was carried only inside the note text. It is now also
  // sent as its own `unit` field (the sheet's updateDeal already accepts one),
  // and the note keeps its "· Unit 2" suffix so nothing that reads the note
  // today changes.
  if (action === 'agentDeal') {
    // The person's own name, so the sheet column reads like a name. redactDeals
    // matches a submitter on the display name, the sheet code or the email
    // equally, so an agent still sees their own deal whichever form is stored.
    const who = req.user.name || agentDealName(req.user.email) || req.user.email || '';
    const d = (b.deal && typeof b.deal === 'object') ? { ...b.deal } : {};
    d.unit = String(d.unit == null ? '' : d.unit).trim().slice(0, 60);
    d.submittedBy = who;
    // The server owns the DealID — never trust a client-supplied one. Attachments are
    // keyed by DealID, so a reused/forged id would otherwise cross-link one agent's files
    // onto another's deal. A fresh unique id here makes that impossible. It's returned
    // below so the add-deal page can attach any staged files to the deal just created.
    d.dealId = 'D' + Date.now().toString(36) + Math.floor(Math.random() * 1e6).toString(36);
    if (d.unit && d.unit !== '-') {
      const n = String(d.note || '');
      if (!/(^|\W)unit\s/i.test(n)) d.note = (n ? n + ' · ' : '') + 'Unit ' + d.unit;
    }
    b.deal = d;
    b.by = who;
    b.submittedBy = who;
  }
  // DEAL WRITES → Postgres (authoritative) + best-effort Sheets mirror, when
  // DATABASE_URL is set. This is the commission ledger, so the write must be durable
  // even if Sheets is slow/down (which is what caused the "unsaved" saves). The
  // matching read path (sheetGet/GET-proxy dealsLoad) serves from Postgres, so a
  // saved deal is the deal read back. agentDeal already had its server-owned dealId
  // stamped above; the mirror still runs, so John's new-deal email and the Sheet
  // backup are unchanged. Ownership/redaction gates all ran before this point.
  if (gdb.on && DEAL_WRITE_ACTIONS.has(action)) {
    try {
      const out = await dealWriteThrough(action, b);
      if (action === 'agentDeal' && b.deal && b.deal.dealId && out && out.dealId == null) out.dealId = b.deal.dealId;
      return res.json(out);
    } catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
  }
  // Always use the server-side token; ignore whatever the client sent
  const body = { ...b, token: GROVE_SHEET_TOKEN };
  try {
    const r = await fetch(GROVE_SHEET_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify(body)
    });
    const j = await r.json();
    // Hand the add-deal page the server-owned DealID so it can attach staged files to
    // the deal it just created (the backend's agentDeal reply doesn't echo the id).
    if (action === 'agentDeal' && b.deal && b.deal.dealId && j && j.dealId == null) j.dealId = b.deal.dealId;
    res.json(j);
  } catch(e) { res.status(502).json({ ok: false, error: String(e) }); }
});

// ── Agent's own deals (secure) ────────────────────────────────────────────────
// Powers my-deals.html. The FULL deal list is fetched server-side; we return ONLY
// the deals this agent is on, and ONLY their own split amount — other agents'
// amounts never leave the server, so nothing leaks even via dev tools.
app.get("/api/mydeals", ensureAuth, async (req, res) => {
  try {
    const mine = String(agentDealName(req.user.email) || '').toUpperCase();
    if (!mine) return res.json({ ok: true, agent: '', deals: [] });
    const j = await sheetGet(GROVE_SHEET_URL, 'dealsLoad', '');
    const deals = (j && j.deals) || [];
    const out = [];
    deals.forEach(function(d) {
      const myLine = (d.lines || []).find(function(l) { return String(l.agent || '').toUpperCase() === mine; });
      if (!myLine) return;
      out.push({
        id: d.id, dealId: d.dealId || '', date: d.date || '', property: d.property || '', type: d.type || '',
        unit: d.unit || '', listing: d.listing || '',
        stage: d.stage || '', fee: d.fee || '',
        myAmount: (myLine.amount != null ? myLine.amount : 0),
        myPaid: !!myLine.paid
      });
    });
    const fmap = await loadDealFiles();
    out.forEach(o => { o.attachments = fmap[String(o.dealId || o.id || '')] || []; });
    res.json({ ok: true, agent: agentDealName(req.user.email), deals: out });
  } catch (e) { res.status(502).json({ ok: false, error: String(e) }); }
});

// Summit partners get the CRM and the drive-by queue here — the two actions the
// Acquisitions CRM and Quick-Add Lead pages need. Every other action on the
// Summit sheet stays owner-only.
const SUMMIT_SHEET_OK = new Set(['crm', 'queue']);
// Roles allowed to use the crm/queue actions. Grove agents were added 2026-08-07
// on John's instruction so the Acquisitions CRM works for them, not just Summit.
const SUMMIT_SHEET_ROLES = new Set(['summit', 'agent']);
app.get("/api/summit", ensureAuth, async (req, res) => {
  const action = req.query.action || '';
  if (req.user.role !== 'owner' &&
      !(SUMMIT_SHEET_ROLES.has(req.user.role) && SUMMIT_SHEET_OK.has(action)))
    return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    let url = SUMMIT_SHEET_URL + sheetSep(SUMMIT_SHEET_URL)
      + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN);
    if (action)         url += '&action=' + encodeURIComponent(action);
    if (req.query._)    url += '&_='      + encodeURIComponent(req.query._);
    const r = await fetch(url);
    const j = await r.json();
    res.json(j);
  } catch(e) { res.status(502).json({ ok: false, error: String(e) }); }
});

app.post("/api/summit", ensureAuth, async (req, res) => {
  // A partner may save the CRM and the queue. The CRM posts its whole list as
  // {crm:[...]} with no action field, so treat a bare crm/queue body as allowed.
  const _b = req.body || {};
  const _act = _b.action || (_b.crm ? 'crm' : _b.queue ? 'queue' : '');
  if (req.user.role !== 'owner' &&
      !(SUMMIT_SHEET_ROLES.has(req.user.role) && SUMMIT_SHEET_OK.has(_act)))
    return res.status(403).json({ ok: false, error: 'forbidden' });
  const body = { ..._b, token: GROVE_SHEET_TOKEN };
  try {
    const r = await fetch(SUMMIT_SHEET_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify(body)
    });
    const j = await r.json();
    res.json(j);
  } catch(e) { res.status(502).json({ ok: false, error: String(e) }); }
});

// Summit: upload a document to the shared Drive folder and return its link.
// Reuses the Apps Script dealUpload (same Drive plumbing deal attachments use), so
// no .gs change is needed. The client stores the returned link against a property
// or deal in the summit_props / summit_deals notes — docs travel with the address.
app.post("/api/summit-upload", ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner' && !SUMMIT_SHEET_ROLES.has(req.user.role))
    return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const data = String(b.data || '');
  if (!data) return res.status(400).json({ ok: false, error: 'no_file' });
  if (data.length > 21 * 1024 * 1024) return res.status(413).json({ ok: false, error: 'too_big', message: 'File too large (max ~15MB).' });
  try {
    const up = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify({ action: 'dealUpload', token: GROVE_SHEET_TOKEN, name: String(b.name || 'file').slice(0, 200), mime: String(b.mime || 'application/octet-stream').slice(0, 120), size: Number(b.size) || 0, data }) }).then(r => r.json());
    if (!(up && up.ok && up.fileId)) return res.status(502).json({ ok: false, error: (up && up.error) || 'upload_failed' });
    res.json({ ok: true, url: up.url || up.view || '', view: up.view || up.url || '', fileId: up.fileId, name: up.name || String(b.name || 'file').slice(0, 200) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── Premarket Hub API (/api/pm/*) ─────────────────────────────────────────────
// The public, membership-walled off-market multifamily marketplace. EVERY response
// here redacts the street address server-side: the feed and single-listing reads
// return coarse location (city/area) only, and the full address is handed out by
// /api/pm/reveal ONLY to the listing's own owner or a buyer whose intro the seller
// has personally approved. A "member" (public paid signup) can reach these routes
// and NOTHING else — see the role gate in the Google verify + pageBlockedFor.
//
// Storage rides the same note store as everything else, three keys on the Grove
// sheet: pm_listings (array), pm_intros (array), pm_buyboxes (array). Reads/writes
// go through sheetGet/sheetPost + noteValue/noteBody, so there is no .gs change.
const PM_KEYS = { listings: 'pm_listings', intros: 'pm_intros', buyboxes: 'pm_buyboxes' };

// ACCESS data lives in its OWN Google Sheet, separate from the hub, so it can spin out
// as its own business. Set DOORS_SHEET_URL + DOORS_SHEET_TOKEN in Render to point at
// the new sheet's Apps Script web app; until then it falls back to the hub sheet, so
// nothing breaks before the migration. Email + document uploads still use the GPG
// account (that's fine — only the ACCESS *data* moves).
const DOORS_SHEET_URL   = process.env.DOORS_SHEET_URL   || GROVE_SHEET_URL;
const DOORS_SHEET_TOKEN = process.env.DOORS_SHEET_TOKEN || GROVE_SHEET_TOKEN;
async function pmSheetGet(action, extra) {
  let url = DOORS_SHEET_URL + sheetSep(DOORS_SHEET_URL) + 'token=' + encodeURIComponent(DOORS_SHEET_TOKEN);
  if (action) url += '&action=' + encodeURIComponent(action);
  if (extra) url += extra;
  return fetch(url).then(r => r.json());
}
async function pmSheetPost(body) {
  const r = await fetch(DOORS_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    body: JSON.stringify(Object.assign({}, body, { token: DOORS_SHEET_TOKEN })) });
  return r.json();
}
async function pmLoad(key) {
  try {
    const j = await pmSheetGet('notes', '&notekey=' + encodeURIComponent(key));
    const v = noteValue(j);
    if (v == null || v === '') return [];
    const arr = typeof v === 'string' ? JSON.parse(v) : v;
    return Array.isArray(arr) ? arr : [];
  } catch (e) { return []; }
}
async function pmSave(key, arr) {
  return pmSheetPost(noteBody(key, JSON.stringify(Array.isArray(arr) ? arr : [])));
}
function pmId(p) { return p + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
function pmEmail(u) { return String((u && u.email) || '').toLowerCase().trim(); }
// Any signed-in role is a member of the marketplace (ensureAuth already blocked the
// unpaid/denied). The page-level gate decides who can even load premarket-hub.html;
// this is the independent API-level check so a stray fetch can't skip it.
function pmMayUse(u) { return !!(u && u.role); }
// True when this user is allowed to see the full street address of a listing.
function pmEntitled(listing, u, intros) {
  if (!listing) return false;
  if (u.role === 'owner') return true;                                  // hub owner sees all
  if (String(listing.owner || '').toLowerCase() === pmEmail(u)) return true;   // the seller
  const email = pmEmail(u);
  return (intros || []).some(i => i && i.listingId === listing.id
    && String(i.buyer || '').toLowerCase() === email && i.status === 'approved');
}
// Strip the exact address out of a listing before it goes to the wire. Keep only the
// coarse location a buyer needs to gauge the market (city / area / state / zip prefix).
// When `full` is true (caller is entitled) the address rides along too.
function pmPublicView(l, full) {
  if (!l) return null;
  const zip = String(l.zip || '');
  const showAddr = full || !l.hideAddress;          // per-deal choice: the poster can hide the address
  const expired = l.expiresAt ? (new Date(l.expiresAt) < new Date()) : false;
  const out = {
    id: l.id, owner: l.owner, ownerName: l.ownerName || '',
    createdAt: l.createdAt || '', updatedAt: l.updatedAt || '', expiresAt: l.expiresAt || '', expired,
    status: l.status || 'active', mlsAt: l.mlsAt || '', featured: !!l.featured,
    city: l.city || '', area: l.area || '', state: l.state || '',
    zipPrefix: zip ? zip.slice(0, 3) : '',
    propType: l.propType || '', dist: l.dist || 'broad',
    units: l.units || '', sqft: l.sqft || '',
    beds: l.beds || '', baths: l.baths || '', yearBuilt: l.yearBuilt || '',
    price: l.price || '', noi: l.noi || '', capRate: l.capRate || '',
    grossIncome: l.grossIncome || '', expenses: l.expenses || '',
    commissionPct: l.commissionPct || '', commissionNotes: l.commissionNotes || '',
    notes: l.notes || '', docs: Array.isArray(l.docs) ? l.docs : [], views: l.views || 0,
    hideAddress: !!l.hideAddress, addressHidden: !showAddr
  };
  if (showAddr) { out.address = l.address || ''; out.zip = zip; }
  return out;
}
// Best-effort outbound email via the Grove Apps Script (sends from John's Google account).
// Used for match alerts and renewal reminders. Never throws.
async function pmSendEmail(to, subject, body) {
  try { await sheetPost(GROVE_SHEET_URL, { action: 'emailForm', to: String(to || ''), subject: String(subject || 'ACCESS').slice(0, 200), body: String(body || '').slice(0, 20000) }); return true; }
  catch (e) { return false; }
}
// Is this member cleared to post/message? Internal roles are auto-cleared; public
// "member" signups need an approved ACCESS profile (with license + brokerage) first.
async function pmApproved(user) {
  if (!user) return false;
  if (user.role !== 'member') return true;                 // owner/agent/summit/etc are trusted
  try { const profs = await pmLoad('pm_profiles'); const p = profs.find(x => x && _lc(x.email) === pmEmail(user)); return !!(p && p.status === 'approved'); }
  catch (e) { return false; }
}
const pmGate = (req, res, next) => pmMayUse(req.user)
  ? next() : res.status(403).json({ ok: false, error: 'forbidden' });

// The live deal feed. Active listings only (a seller's own off-market ones ride along
// so they can manage them); every address redacted unless the viewer is entitled.
app.get('/api/pm/feed', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const meEmail = pmEmail(req.user);
    const isOwner = req.user.role === 'owner';
    const mine = l => String(l.owner || '').toLowerCase() === meEmail;
    const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
    const rows = listings
      .filter(l => l && (((l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls') || mine(l) || isOwner))
      .filter(l => !isExpired(l) || mine(l) || isOwner)   // expired deals hidden from the market, still visible to owner/lister
      .map(l => pmPublicView(l, mine(l) || isOwner))       // full address only to the lister or the hub owner; per-deal hideAddress otherwise
      .sort((a, b) => (b.featured - a.featured) || String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, listings: rows, me: { email: req.user.email, role: req.user.role } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// One listing by id (redacted unless entitled).
app.get('/api/pm/listing/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    const full = String(l.owner || '').toLowerCase() === pmEmail(req.user) || req.user.role === 'owner';
    res.json({ ok: true, listing: pmPublicView(l, full) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Create or update a listing. Owner of the record is bound to the signed-in email at
// create time and CANNOT be reassigned; an update only proceeds if the caller owns the
// record (or is the hub owner). Numeric-ish fields are stored as given (strings ok).
app.post('/api/pm/listing', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120);
  try {
    // Vetting gate: outside members must be approved before they can post.
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const listings = await pmLoad(PM_KEYS.listings);
    const id = S(b.id, 40);
    const now = new Date().toISOString();
    const docsIn = Array.isArray(b.docs) ? b.docs.slice(0, 20).map(d => ({
      name: S(d && d.name, 160), url: S(d && d.url, 600)
    })).filter(d => d.url) : [];
    const fields = {
      ownerName: S(b.ownerName, 80),
      status: (b.status === 'off' ? 'off' : b.status === 'mls' ? 'mls' : 'active'),
      address: S(b.address, 200), city: S(b.city, 80), area: S(b.area, 80),
      state: S(b.state, 40), zip: S(b.zip, 20),
      hideAddress: !!b.hideAddress,
      propType: S(b.propType, 60),
      dist: (['broad', 'private', 'pocket'].indexOf(b.dist) >= 0 ? b.dist : 'broad'),
      units: S(b.units, 20), sqft: S(b.sqft, 20),
      beds: S(b.beds, 20), baths: S(b.baths, 20), yearBuilt: S(b.yearBuilt, 12),
      price: S(b.price, 24), noi: S(b.noi, 24), capRate: S(b.capRate, 16),
      grossIncome: S(b.grossIncome, 24), expenses: S(b.expenses, 24),
      commissionPct: S(b.commissionPct, 16), commissionNotes: S(b.commissionNotes, 300),
      notes: S(b.notes, 3000), docs: docsIn
    };
    const in30 = new Date(Date.now() + 30 * 864e5).toISOString();
    let rec, isNew = false;
    if (id) {
      const idx = listings.findIndex(x => x && x.id === id);
      if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
      const cur = listings[idx];
      if (req.user.role !== 'owner' && String(cur.owner || '').toLowerCase() !== pmEmail(req.user))
        return res.status(403).json({ ok: false, error: 'not_your_listing' });
      rec = Object.assign({}, cur, fields, { updatedAt: now });
      listings[idx] = rec;
    } else {
      rec = Object.assign({ id: pmId('L'), owner: req.user.email, createdAt: now, updatedAt: now,
        expiresAt: in30, views: 0, featured: false }, fields);
      listings.push(rec); isNew = true;
    }
    await pmSave(PM_KEYS.listings, listings);
    // Alert every buyer whose buy-box matches this brand-new, active deal (notif + best-effort email).
    if (isNew && rec.status !== 'off') {
      try {
        const boxes = await pmLoad(PM_KEYS.buyboxes), ns = await pmLoad('pm_notifs');
        const hits = [];
        boxes.forEach(bx => {
          if (bx && _lc(bx.owner) !== pmEmail(req.user) && pmMatch(rec, bx)) {
            const txt = 'New match — ' + (rec.propType || 'deal') + ' in ' + (rec.area || rec.city || 'your market') + (rec.price ? (' · ' + pmMoneyShort(rec.price)) : '');
            ns.push({ id: pmId('N'), to: _lc(bx.owner), type: 'match', text: txt, listingId: rec.id, at: now, read: false });
            hits.push({ to: _lc(bx.owner), txt });
          }
        });
        await pmSave('pm_notifs', ns.length > 2000 ? ns.slice(-2000) : ns);
        for (const h of hits) {
          await pmSendEmail(h.to, 'ACCESS · new deal matches your buy box',
            h.txt + '\n\nOpen ACCESS to view the deal and message the listing agent.');
        }
      } catch (e) { /* alerts are best-effort */ }
    }
    res.json({ ok: true, listing: pmPublicView(rec, req.user.role === 'owner' || String(rec.owner||'').toLowerCase() === pmEmail(req.user)), id: rec.id });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Delete a listing (its own owner, or the hub owner). Also drops any intros against it.
app.post('/api/pm/listing/delete', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === id);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (req.user.role !== 'owner' && String(l.owner || '').toLowerCase() !== pmEmail(req.user))
      return res.status(403).json({ ok: false, error: 'not_your_listing' });
    await pmSave(PM_KEYS.listings, listings.filter(x => x && x.id !== id));
    const intros = await pmLoad(PM_KEYS.intros);
    if (intros.some(i => i && i.listingId === id))
      await pmSave(PM_KEYS.intros, intros.filter(i => i && i.listingId !== id));
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Mark a deal as moved to the MLS (or relist it back). MLS deals leave the live feed
// entirely — the property is public now, so ACCESS no longer brokers contact for it.
// The poster still sees it in "My activity" and the owner sees it in Admin, both as
// a record. Lister or hub owner only.
app.post('/api/pm/listing/mls', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  const on = (req.body || {}).on !== false;   // default: mark as on MLS
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === id);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (req.user.role !== 'owner' && String(l.owner || '').toLowerCase() !== pmEmail(req.user))
      return res.status(403).json({ ok: false, error: 'not_your_listing' });
    if (on) { l.status = 'mls'; l.mlsAt = new Date().toISOString(); }
    else { l.status = 'active'; delete l.mlsAt; }
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, status: l.status });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// A buyer requests an introduction on a listing. The seller must approve before any
// address is revealed. One live (pending/approved) request per buyer per listing.
app.post('/api/pm/intro', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const listingId = String(b.listingId || '');
  if (!listingId) return res.status(400).json({ ok: false, error: 'no_listing' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === listingId);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (String(l.owner || '').toLowerCase() === pmEmail(req.user))
      return res.status(400).json({ ok: false, error: 'own_listing' });
    const intros = await pmLoad(PM_KEYS.intros);
    const email = pmEmail(req.user);
    const live = intros.find(i => i && i.listingId === listingId
      && String(i.buyer || '').toLowerCase() === email && i.status !== 'declined');
    if (live) return res.json({ ok: true, intro: live, already: true });
    const rec = {
      id: pmId('I'), listingId, seller: l.owner,
      buyer: req.user.email, buyerName: String(b.buyerName || req.user.name || '').slice(0, 80),
      message: String(b.message || '').slice(0, 1000),
      status: 'pending', createdAt: new Date().toISOString(), decidedAt: ''
    };
    intros.push(rec);
    await pmSave(PM_KEYS.intros, intros);
    res.json({ ok: true, intro: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Intros relevant to me: ones I sent (as a buyer) and ones on my listings (as a seller).
// Each is enriched with a redacted listing summary; the seller view carries the buyer's
// contact so an approved intro is actionable, the buyer view carries the address only
// once approved.
app.get('/api/pm/intros', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const email = pmEmail(req.user);
    const byId = {}; listings.forEach(l => { if (l && l.id) byId[l.id] = l; });
    const asBuyer = [], asSeller = [];
    intros.forEach(i => {
      if (!i) return;
      const l = byId[i.listingId];
      const summary = l ? pmPublicView(l, i.status === 'approved' || req.user.role === 'owner') : null;
      if (String(i.buyer || '').toLowerCase() === email)
        asBuyer.push({ id: i.id, listingId: i.listingId, status: i.status, message: i.message,
          createdAt: i.createdAt, decidedAt: i.decidedAt, listing: summary });
      if (String(i.seller || '').toLowerCase() === email || req.user.role === 'owner')
        asSeller.push({ id: i.id, listingId: i.listingId, status: i.status, message: i.message,
          createdAt: i.createdAt, decidedAt: i.decidedAt,
          buyer: i.buyer, buyerName: i.buyerName, listing: summary });
    });
    res.json({ ok: true, asBuyer, asSeller });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Seller approves or declines an intro on their own listing (hub owner may act on any).
app.post('/api/pm/intro/decide', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const introId = String(b.introId || '');
  const decision = b.decision === 'approved' ? 'approved' : b.decision === 'declined' ? 'declined' : '';
  if (!introId || !decision) return res.status(400).json({ ok: false, error: 'bad_request' });
  try {
    const intros = await pmLoad(PM_KEYS.intros);
    const idx = intros.findIndex(i => i && i.id === introId);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    const it = intros[idx];
    if (req.user.role !== 'owner' && String(it.seller || '').toLowerCase() !== pmEmail(req.user))
      return res.status(403).json({ ok: false, error: 'not_your_listing' });
    it.status = decision; it.decidedAt = new Date().toISOString();
    intros[idx] = it;
    await pmSave(PM_KEYS.intros, intros);
    res.json({ ok: true, intro: it });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Reveal the full street address — only to the seller or an approved buyer.
app.get('/api/pm/reveal/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (!pmEntitled(l, req.user, intros)) return res.status(403).json({ ok: false, error: 'not_approved' });
    res.json({ ok: true, id: l.id, address: l.address || '', city: l.city || '', state: l.state || '', zip: l.zip || '' });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// A buyer's "buy box" — what they're hunting for. One record per buyer (keyed by email).
app.get('/api/pm/buybox', ensureAuth, pmGate, async (req, res) => {
  try {
    const [boxes, listings] = await Promise.all([pmLoad(PM_KEYS.buyboxes), pmLoad(PM_KEYS.listings)]);
    const email = pmEmail(req.user);
    const mine = boxes.find(x => x && String(x.owner || '').toLowerCase() === email) || null;
    // Two-way matching, buyer side: live deals (not mine, not expired, not off) that fit the box.
    let matches = [];
    if (mine) {
      const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
      matches = listings
        .filter(l => l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && !isExpired(l)
          && _lc(l.owner) !== email && pmMatch(l, mine))
        .map(l => pmPublicView(l, false))
        .sort((a, b) => (b.featured - a.featured) || String(b.createdAt).localeCompare(String(a.createdAt)));
    }
    res.json({ ok: true, buybox: mine, matches });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/buybox', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120);
  try {
    const boxes = await pmLoad(PM_KEYS.buyboxes);
    const email = pmEmail(req.user);
    const now = new Date().toISOString();
    const fields = {
      markets: S(b.markets, 200), propType: S(b.propType, 80),
      minUnits: S(b.minUnits, 12), maxUnits: S(b.maxUnits, 12),
      minPrice: S(b.minPrice, 24), maxPrice: S(b.maxPrice, 24),
      minCap: S(b.minCap, 12), notes: S(b.notes, 1500),
      contact: S(b.contact || req.user.email, 120)
    };
    const idx = boxes.findIndex(x => x && String(x.owner || '').toLowerCase() === email);
    let rec, isNew = false;
    if (idx >= 0) { rec = Object.assign({}, boxes[idx], fields, { updatedAt: now }); boxes[idx] = rec; }
    else { rec = Object.assign({ owner: req.user.email, ownerName: String(req.user.name || '').slice(0, 80), createdAt: now, updatedAt: now }, fields); boxes.push(rec); isNew = true; }
    await pmSave(PM_KEYS.buyboxes, boxes);
    // Two-way matching, seller side: tell listing agents a new buyer is hunting deals like theirs.
    if (isNew) {
      try {
        const listings = await pmLoad(PM_KEYS.listings), ns = await pmLoad('pm_notifs');
        const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
        const sellers = {};
        listings.forEach(l => {
          if (l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && !isExpired(l) && _lc(l.owner) !== email && pmMatch(l, rec)) {
            const s = _lc(l.owner);
            (sellers[s] = sellers[s] || []).push(l);
            ns.push({ id: pmId('N'), to: s, type: 'buyer',
              text: 'New buyer for your ' + (l.area || l.city || 'deal') + ' listing — their buy box matches',
              listingId: l.id, at: now, read: false });
          }
        });
        await pmSave('pm_notifs', ns.length > 2000 ? ns.slice(-2000) : ns);
        for (const s of Object.keys(sellers)) {
          await pmSendEmail(s, 'ACCESS · a buyer is hunting deals like yours',
            'A new buyer just posted a buy box that matches ' + sellers[s].length + ' of your live deal(s).\n\nOpen ACCESS to see the buyer and start a conversation.');
        }
      } catch (e) { /* reverse alerts are best-effort */ }
    }
    res.json({ ok: true, buybox: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// A compact activity roll-up for the "My activity" panel.
app.get('/api/pm/activity', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const email = pmEmail(req.user);
    const myListings = listings.filter(l => l && String(l.owner || '').toLowerCase() === email);
    const myListingIds = new Set(myListings.map(l => l.id));
    const sentPending = intros.filter(i => i && String(i.buyer || '').toLowerCase() === email && i.status === 'pending').length;
    const sentApproved = intros.filter(i => i && String(i.buyer || '').toLowerCase() === email && i.status === 'approved').length;
    const inbound = intros.filter(i => i && myListingIds.has(i.listingId) && i.status === 'pending').length;
    res.json({ ok: true, activity: {
      listings: myListings.length,
      active: myListings.filter(l => (l.status || 'active') !== 'off').length,
      sentPending, sentApproved, inboundPending: inbound
    } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── ACCESS member messaging (TAN-style Conversations) ──────────────────────────
// Free member-to-member messaging. A thread is keyed by the two emails (sorted) plus
// an optional listingId, so a conversation "about 120 Dorchester Ave" is its own thread
// separate from a general DM. Stored in the pm_messages note (server-token only).
function pmThreadKey(a, b, listingId) {
  const p = [String(a || '').toLowerCase().trim(), String(b || '').toLowerCase().trim()].sort();
  return p[0] + '|' + p[1] + (listingId ? ('|' + listingId) : '');
}
const _lc = s => String(s || '').toLowerCase().trim();
app.post('/api/pm/message', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const to = _lc(b.to), body = String(b.body || '').slice(0, 4000).trim(), listingId = String(b.listingId || '');
  if (!to || !body) return res.status(400).json({ ok: false, error: 'bad_request' });
  if (to === pmEmail(req.user)) return res.status(400).json({ ok: false, error: 'cannot_message_self' });
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const msgs = await pmLoad('pm_messages');
    const rec = { id: pmId('M'), key: pmThreadKey(req.user.email, to, listingId), from: req.user.email,
      fromName: String(req.user.name || '').slice(0, 80), to: to, listingId: listingId,
      body: body, at: new Date().toISOString(), readBy: [pmEmail(req.user)] };
    msgs.push(rec);
    await pmSave('pm_messages', msgs);
    res.json({ ok: true, message: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/threads', ensureAuth, pmGate, async (req, res) => {
  try {
    const [msgs, listings] = await Promise.all([pmLoad('pm_messages'), pmLoad(PM_KEYS.listings)]);
    const email = pmEmail(req.user), byId = {}; listings.forEach(l => { if (l && l.id) byId[l.id] = l; });
    const mine = msgs.filter(m => m && (_lc(m.from) === email || _lc(m.to) === email));
    const threads = {};
    mine.forEach(m => {
      const t = threads[m.key] || (threads[m.key] = { key: m.key, other: '', otherName: '', listingId: m.listingId || '', last: '', at: '', unread: 0 });
      const otherIsFrom = _lc(m.from) !== email;
      if (otherIsFrom && m.fromName) t.otherName = m.fromName;
      if (!t.at || String(m.at) > t.at) { t.at = m.at; t.last = m.body; t.other = otherIsFrom ? m.from : m.to; }
      if (_lc(m.to) === email && !(m.readBy || []).map(_lc).includes(email)) t.unread++;
    });
    const list = Object.values(threads).map(t => {
      const l = t.listingId ? byId[t.listingId] : null;
      t.listing = l ? { id: l.id, area: l.area || l.city || '', price: l.price || '' } : null;
      return t;
    }).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    res.json({ ok: true, threads: list, me: { email: req.user.email, name: req.user.name } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/thread', ensureAuth, pmGate, async (req, res) => {
  const other = _lc(req.query.with), listingId = String(req.query.listingId || '');
  if (!other) return res.status(400).json({ ok: false, error: 'no_party' });
  try {
    const msgs = await pmLoad('pm_messages');
    const key = pmThreadKey(req.user.email, other, listingId), email = pmEmail(req.user);
    let changed = false;
    const thread = msgs.filter(m => m && m.key === key).sort((a, b) => String(a.at).localeCompare(String(b.at)));
    thread.forEach(m => { if (_lc(m.to) === email) { m.readBy = m.readBy || []; if (!m.readBy.map(_lc).includes(email)) { m.readBy.push(req.user.email); changed = true; } } });
    if (changed) { try { await pmSave('pm_messages', msgs); } catch (e) {} }
    res.json({ ok: true, messages: thread.map(m => ({ id: m.id, from: m.from, fromName: m.fromName, mine: _lc(m.from) === email, body: m.body, at: m.at })), me: { email: req.user.email } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── ACCESS matching, alerts, market pulse, broadcast board ─────────────────────
function pmNum(v){ var n = parseFloat(String(v == null ? '' : v).replace(/[^0-9.]/g, '')); return isFinite(n) ? n : 0; }
function pmMoneyShort(v){ var n = Math.round(pmNum(v)); if (!n) return ''; if (n >= 1e6) return '$' + (n / 1e6).toFixed(n % 1e6 ? 1 : 0) + 'M'; if (n >= 1e3) return '$' + Math.round(n / 1e3) + 'K'; return '$' + n; }
// Does a live listing satisfy a buyer's buy-box? Blank criteria = "any". Price/units/cap
// are numeric gates; markets/propType are loose text-overlap so "South Boston, Dorchester"
// matches a deal in "South Boston".
function pmMatch(l, box){
  if (!l || !box) return false;
  var price = pmNum(l.price), minP = pmNum(box.minPrice), maxP = pmNum(box.maxPrice);
  if (minP && price && price < minP) return false;
  if (maxP && price && price > maxP) return false;
  var units = pmNum(l.units), minU = pmNum(box.minUnits), maxU = pmNum(box.maxUnits);
  if (minU && units && units < minU) return false;
  if (maxU && units && units > maxU) return false;
  var cap = pmNum(l.capRate), minC = pmNum(box.minCap);
  if (minC && cap && cap < minC) return false;
  var bm = String(box.markets || '').toLowerCase().trim();
  if (bm) { var loc = (String(l.area || '') + ' ' + String(l.city || '') + ' ' + String(l.state || '')).toLowerCase(); var any = false; bm.split(/[,;/]+/).forEach(function (m) { m = m.trim(); if (m && loc.indexOf(m) >= 0) any = true; }); if (!any) return false; }
  var bt = String(box.propType || '').toLowerCase().trim();
  if (bt) { var lt = String(l.propType || '').toLowerCase(); if (lt) { var any2 = false; bt.split(/[,;/ ]+/).forEach(function (w) { if (w && w.length > 2 && lt.indexOf(w) >= 0) any2 = true; }); if (!any2) return false; } }
  return true;
}
// Notifications (the alert bell). Stored in pm_notifs, capped to the last 2000.
app.get('/api/pm/notifs', ensureAuth, pmGate, async (req, res) => {
  try {
    const ns = await pmLoad('pm_notifs'), email = pmEmail(req.user);
    const mine = ns.filter(n => n && _lc(n.to) === email).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50);
    res.json({ ok: true, notifs: mine, unread: mine.filter(n => !n.read).length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/notifs/read', ensureAuth, pmGate, async (req, res) => {
  try {
    const ns = await pmLoad('pm_notifs'), email = pmEmail(req.user); let ch = false;
    ns.forEach(n => { if (n && _lc(n.to) === email && !n.read) { n.read = true; ch = true; } });
    if (ch) await pmSave('pm_notifs', ns);
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Buy boxes matching one listing (the owner sees who the buyers are).
app.get('/api/pm/matches/:listingId', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes)]);
    const l = listings.find(x => x && x.id === String(req.params.listingId));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    const owner = String(l.owner || '').toLowerCase() === pmEmail(req.user) || req.user.role === 'owner';
    const matches = boxes.filter(b => b && pmMatch(l, b));
    res.json({ ok: true, count: matches.length, buyers: owner ? matches.map(b => ({ owner: b.owner, ownerName: b.ownerName || '', markets: b.markets || '', propType: b.propType || '', contact: b.contact || b.owner })) : [] });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Market pulse (the Chapter-Activity equivalent).
app.get('/api/pm/market', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes)]);
    const live = listings.filter(l => l && (l.status || 'active') !== 'off');
    const off = listings.filter(l => l && (l.status || 'active') === 'off');
    const val = live.reduce((a, l) => a + pmNum(l.price), 0);
    const comms = live.map(l => pmNum(l.commissionPct)).filter(x => x > 0);
    const caps = live.map(l => pmNum(l.capRate)).filter(x => x > 0);
    const areas = {}; live.forEach(l => { const a = l.area || l.city || '—'; areas[a] = (areas[a] || 0) + 1; });
    const recent = live.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 6)
      .map(l => ({ id: l.id, area: l.area || l.city || '', propType: l.propType || '', price: l.price || '', createdAt: l.createdAt || '' }));
    res.json({ ok: true, market: {
      liveDeals: live.length, offMarket: off.length, totalValue: val, buyboxes: boxes.length,
      avgCommission: comms.length ? (comms.reduce((a, b) => a + b, 0) / comms.length) : 0,
      avgCap: caps.length ? (caps.reduce((a, b) => a + b, 0) / caps.length) : 0,
      byArea: areas, recent } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Broadcast board (ISO posts, off-market lists, announcements).
app.get('/api/pm/broadcasts', ensureAuth, pmGate, async (req, res) => {
  try {
    let bs = await pmLoad('pm_broadcasts');
    bs = bs.filter(Boolean).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 60);
    res.json({ ok: true, broadcasts: bs });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/broadcast', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const title = String(b.title || '').slice(0, 160).trim(), body = String(b.body || '').slice(0, 4000).trim();
  const category = String(b.category || 'Misc').slice(0, 40);
  if (!title && !body) return res.status(400).json({ ok: false, error: 'empty' });
  try {
    const bs = await pmLoad('pm_broadcasts');
    const rec = { id: pmId('B'), from: req.user.email, fromName: String(req.user.name || '').slice(0, 80), category, title, body, at: new Date().toISOString() };
    bs.push(rec); await pmSave('pm_broadcasts', bs);
    res.json({ ok: true, broadcast: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── ACCESS: view tracking, seller analytics, renewals, profiles, admin ─────────
// Count a deal view (once-ish per opener; a viewer never inflates their own deal).
app.post('/api/pm/view/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === String(req.params.id));
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    if (_lc(listings[idx].owner) !== pmEmail(req.user)) {
      listings[idx].views = (Number(listings[idx].views) || 0) + 1;
      const vb = listings[idx].viewers = Array.isArray(listings[idx].viewers) ? listings[idx].viewers : [];
      const me = pmEmail(req.user);
      if (!vb.includes(me)) vb.push(me);
      await pmSave(PM_KEYS.listings, listings);
    }
    res.json({ ok: true, views: listings[idx].views || 0 });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Seller analytics for one deal (its lister, or the hub owner): views, unique viewers,
// matching buy boxes, and message threads about the deal.
app.get('/api/pm/analytics/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes, msgs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_messages')]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner')
      return res.status(403).json({ ok: false, error: 'not_your_listing' });
    const matches = boxes.filter(b => b && pmMatch(l, b));
    const threadKeys = new Set(msgs.filter(m => m && m.listingId === l.id).map(m => m.key));
    const daysLeft = l.expiresAt ? Math.max(0, Math.ceil((new Date(l.expiresAt) - new Date()) / 864e5)) : null;
    res.json({ ok: true, analytics: {
      id: l.id, views: Number(l.views) || 0,
      uniqueViewers: Array.isArray(l.viewers) ? l.viewers.length : 0,
      matches: matches.length, messageThreads: threadKeys.size,
      messages: msgs.filter(m => m && m.listingId === l.id).length,
      expiresAt: l.expiresAt || '', daysLeft, featured: !!l.featured,
      expired: l.expiresAt ? (new Date(l.expiresAt) < new Date()) : false } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Renew a deal for another 30 days (the lister, or the hub owner). The $1 charge is
// handled by Stripe in a later phase; PM_PAID_RENEW gates whether payment is enforced.
const PM_PAID_RENEW = process.env.PM_PAID_RENEW === '1';
app.post('/api/pm/renew', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    const l = listings[idx];
    if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner')
      return res.status(403).json({ ok: false, error: 'not_your_listing' });
    if (PM_PAID_RENEW && !(req.body && req.body.paid) && req.user.role !== 'owner')
      return res.status(402).json({ ok: false, error: 'payment_required', message: 'Renewing a deal is $1.' });
    // Extend 30 days from the later of now or the current expiry, so early renewals stack.
    const base = l.expiresAt && new Date(l.expiresAt) > new Date() ? new Date(l.expiresAt) : new Date();
    l.expiresAt = new Date(base.getTime() + 30 * 864e5).toISOString();
    l.renewedAt = new Date().toISOString();
    l.renew5Sent = false; l.renew1Sent = false;   // re-arm the reminder cycle
    if ((l.status || 'active') === 'off') l.status = 'active';
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, expiresAt: l.expiresAt });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Member profile (name, license #, brokerage, phone, bio). License + brokerage are
// required to be approved to post. GET returns my own profile.
app.get('/api/pm/profile', ensureAuth, pmGate, async (req, res) => {
  try {
    const profs = await pmLoad('pm_profiles');
    const me = profs.find(p => p && _lc(p.email) === pmEmail(req.user)) || null;
    res.json({ ok: true, profile: me, approved: await pmApproved(req.user), role: req.user.role });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Normalize a social handle or URL into a safe https link (or '' if blank/bad).
// Members paste either "@handle", "handle", or a full URL — all end up as a clean URL.
function pmSocial(kind, v) {
  v = String(v == null ? '' : v).trim().slice(0, 200);
  if (!v) return '';
  if (/^https?:\/\//i.test(v)) return /^https?:\/\/[^\s"'<>`]+$/i.test(v) ? v : '';
  const handle = v.replace(/^@+/, '').replace(/[^A-Za-z0-9_.\/-]/g, '');
  if (!handle) return '';
  if (kind === 'website') return 'https://' + handle;
  const base = { linkedin: 'https://www.linkedin.com/in/', instagram: 'https://instagram.com/', facebook: 'https://facebook.com/', x: 'https://x.com/' }[kind];
  return base ? base + handle : '';
}
app.post('/api/pm/profile', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  try {
    const profs = await pmLoad('pm_profiles');
    const email = pmEmail(req.user);
    const now = new Date().toISOString();
    const fields = {
      name: S(b.name || req.user.name, 100), license: S(b.license, 60), brokerage: S(b.brokerage, 120),
      phone: S(b.phone, 40), markets: S(b.markets, 200), bio: S(b.bio, 1200),
      linkedin: pmSocial('linkedin', b.linkedin), instagram: pmSocial('instagram', b.instagram),
      facebook: pmSocial('facebook', b.facebook), x: pmSocial('x', b.x), website: pmSocial('website', b.website)
    };
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    let rec, isNew = false;
    if (idx >= 0) { rec = Object.assign({}, profs[idx], fields, { updatedAt: now }); profs[idx] = rec; }
    else {
      // Hub logins (any role but 'member') are auto-approved; outside members await review.
      const status = req.user.role === 'member' ? 'pending' : 'approved';
      rec = Object.assign({ email: req.user.email, status, createdAt: now, updatedAt: now }, fields);
      profs.push(rec); isNew = true;
    }
    await pmSave('pm_profiles', profs);
    // New outside-member profile → ping the hub owner to review it.
    if (isNew && rec.status === 'pending') {
      try { await pmSendEmail('john@gpgboston.com', 'ACCESS · new member awaiting approval',
        (rec.name || rec.email) + ' signed up.\nLicense: ' + (rec.license || '—') + '\nBrokerage: ' + (rec.brokerage || '—') + '\n\nApprove them in the ACCESS admin panel.'); } catch (e) {}
    }
    res.json({ ok: true, profile: rec, approved: await pmApproved(req.user) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// A member's public profile card (shown next to their deals / in messages).
app.get('/api/pm/profile/:email', ensureAuth, pmGate, async (req, res) => {
  try {
    const profs = await pmLoad('pm_profiles');
    const p = profs.find(x => x && _lc(x.email) === _lc(req.params.email));
    if (!p) return res.json({ ok: true, profile: null });
    res.json({ ok: true, profile: { email: p.email, name: p.name || '', brokerage: p.brokerage || '',
      license: p.license || '', markets: p.markets || '', bio: p.bio || '', phone: p.phone || '',
      linkedin: p.linkedin || '', instagram: p.instagram || '', facebook: p.facebook || '', x: p.x || '', website: p.website || '',
      verified: !!p.verified, status: p.status || 'pending' } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Member directory — approved members only (or owner). A vetted roster members can
// browse and connect through; doubles as the hub owner's member list.
app.get('/api/pm/directory', ensureAuth, pmGate, async (req, res) => {
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const isOwner = req.user.role === 'owner';
    const [profs, listings] = await Promise.all([pmLoad('pm_profiles'), pmLoad(PM_KEYS.listings)]);
    const counts = {}; listings.forEach(l => { if (l) counts[_lc(l.owner)] = (counts[_lc(l.owner)] || 0) + 1; });
    const members = profs.filter(p => p && p.status === 'approved').map(p => ({
      email: p.email, name: p.name || '', brokerage: p.brokerage || '', markets: p.markets || '',
      bio: p.bio || '', phone: p.phone || '', license: isOwner ? (p.license || '') : '',
      linkedin: p.linkedin || '', instagram: p.instagram || '', facebook: p.facebook || '', x: p.x || '', website: p.website || '',
      verified: !!p.verified,
      deals: counts[_lc(p.email)] || 0, joined: p.createdAt || ''
    })).sort((a, b) => (b.deals - a.deals) || String(a.name || a.email).localeCompare(String(b.name || b.email)));
    res.json({ ok: true, members, count: members.length, me: { email: req.user.email, role: req.user.role } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// One-time migration: copy the ACCESS data from the OLD hub sheet into the NEW ACCESS
// sheet. Owner only. Run once, AFTER setting DOORS_SHEET_URL/TOKEN in Render. Reads
// from the Grove sheet directly and writes through the ACCESS sheet helpers.
app.post('/api/pm/migrate', ensureAuth, pmGate, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  if (DOORS_SHEET_URL === GROVE_SHEET_URL)
    return res.json({ ok: false, error: 'same_sheet', message: 'Set DOORS_SHEET_URL to the new sheet first — source and destination are currently the same.' });
  const keys = ['pm_listings','pm_intros','pm_buyboxes','pm_messages','pm_notifs','pm_broadcasts','pm_profiles','pm_requests','pm_pays'];
  const copied = {};
  for (const k of keys) {
    try {
      const j = await sheetGet(GROVE_SHEET_URL, 'notes', '&notekey=' + encodeURIComponent(k)); // read OLD hub sheet
      const v = noteValue(j);
      const str = (v == null || v === '') ? '[]' : (typeof v === 'string' ? v : JSON.stringify(v));
      await pmSheetPost(noteBody(k, str));   // write NEW ACCESS sheet
      let n = 0; try { const a = JSON.parse(str); n = Array.isArray(a) ? a.length : 0; } catch (e) {}
      copied[k] = n;
    } catch (e) { copied[k] = 'error'; }
  }
  res.json({ ok: true, copied });
});
// ── ACCESS admin (hub owner only): members + approvals + featuring ─────────────
function pmIsAdmin(req) { return req.user && req.user.role === 'owner'; }
app.get('/api/pm/admin/members', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const [profs, listings] = await Promise.all([pmLoad('pm_profiles'), pmLoad(PM_KEYS.listings)]);
    const counts = {}; listings.forEach(l => { if (l) counts[_lc(l.owner)] = (counts[_lc(l.owner)] || 0) + 1; });
    const members = profs.filter(Boolean).map(p => ({ email: p.email, name: p.name || '', license: p.license || '',
      brokerage: p.brokerage || '', phone: p.phone || '', markets: p.markets || '', status: p.status || 'pending',
      createdAt: p.createdAt || '', deals: counts[_lc(p.email)] || 0 }))
      .sort((a, b) => (a.status === 'pending' ? -1 : 1) - (b.status === 'pending' ? -1 : 1) || String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, members, pending: members.filter(m => m.status === 'pending').length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/approve', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email), decision = b.status === 'rejected' ? 'rejected' : 'approved';
  if (!email) return res.status(400).json({ ok: false, error: 'no_email' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    profs[idx].status = decision; profs[idx].decidedAt = new Date().toISOString();
    await pmSave('pm_profiles', profs);
    try { await pmSendEmail(email, 'ACCESS · your membership was ' + decision,
      decision === 'approved' ? 'You\'re approved. Open ACCESS to post deals and message members.' : 'Your ACCESS application was not approved at this time.'); } catch (e) {}
    res.json({ ok: true, email, status: decision });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/feature', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const id = String(b.id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    listings[idx].featured = !!b.featured;
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, id, featured: listings[idx].featured });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── Public membership requests (from the ACCESS landing — NO auth) ─────────────
// A prospective agent asks to join. Stored in pm_requests; the hub owner reviews in
// the admin panel and approves, which seeds an approved profile so they can sign in
// and (once Stripe is live) pay. Emails the owner on every new request.
// ── Stripe payments: renew a deal ($10), feature a deal ($25), membership ($50/mo) ──
// The Stripe client loads only when STRIPE_SECRET_KEY is set; until then every pay
// route reports "not_configured" and the app quietly falls back to the free flow, so
// nothing breaks before John connects his account.
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try { const S = (await import('stripe')).default; stripe = new S(process.env.STRIPE_SECRET_KEY); }
  catch (e) { console.log('[stripe] load failed — payments disabled:', e && e.message); }
}
const PM_PRICE = {
  renew: Number(process.env.PM_PRICE_RENEW || 1000),      // cents · $10 to renew a deal 30 days
  feature: Number(process.env.PM_PRICE_FEATURE || 2500)   // cents · $25 to feature a deal
};
const STRIPE_PRICE_MEMBERSHIP = process.env.STRIPE_PRICE_MEMBERSHIP || '';  // recurring Price ID (from Stripe dashboard)
const PM_BASE = (process.env.BASE_URL || 'https://hub.gpgboston.com').replace(/\/$/, '');

app.get('/api/pm/pay/status', ensureAuth, pmGate, (req, res) => {
  res.json({ ok: true, enabled: !!stripe, membership: !!(stripe && STRIPE_PRICE_MEMBERSHIP),
    prices: { renew: PM_PRICE.renew / 100, feature: PM_PRICE.feature / 100 } });
});

app.post('/api/pm/checkout', ensureAuth, pmGate, async (req, res) => {
  if (!stripe) return res.status(503).json({ ok: false, error: 'not_configured' });
  const b = req.body || {}, kind = String(b.kind || '');
  try {
    if (kind === 'renew' || kind === 'feature') {
      const id = String(b.listingId || ''); if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
      const listings = await pmLoad(PM_KEYS.listings); const l = listings.find(x => x && x.id === id);
      if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
      if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner')
        return res.status(403).json({ ok: false, error: 'not_your_listing' });
      const amount = PM_PRICE[kind];
      const label = kind === 'renew' ? 'ACCESS — renew deal (30 days)' : 'ACCESS — feature deal';
      const session = await stripe.checkout.sessions.create({
        mode: 'payment', payment_method_types: ['card'],
        line_items: [{ price_data: { currency: 'usd', unit_amount: amount, product_data: { name: label } }, quantity: 1 }],
        metadata: { kind, listingId: id, email: pmEmail(req.user) },
        success_url: PM_BASE + '/premarket-hub.html?paid={CHECKOUT_SESSION_ID}',
        cancel_url: PM_BASE + '/premarket-hub.html'
      });
      return res.json({ ok: true, url: session.url });
    }
    if (kind === 'membership') {
      if (!STRIPE_PRICE_MEMBERSHIP) return res.status(503).json({ ok: false, error: 'no_membership_price' });
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription', payment_method_types: ['card'],
        line_items: [{ price: STRIPE_PRICE_MEMBERSHIP, quantity: 1 }],
        customer_email: pmEmail(req.user), metadata: { kind: 'membership', email: pmEmail(req.user) },
        success_url: PM_BASE + '/premarket-hub.html?paid={CHECKOUT_SESSION_ID}',
        cancel_url: PM_BASE + '/premarket-hub.html'
      });
      return res.json({ ok: true, url: session.url });
    }
    res.status(400).json({ ok: false, error: 'bad_kind' });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});

// After the buyer returns from Stripe, verify the session server-side and apply the
// action. Idempotent via pm_pays so a refresh can't double-apply.
app.get('/api/pm/pay/confirm', ensureAuth, pmGate, async (req, res) => {
  if (!stripe) return res.status(503).json({ ok: false, error: 'not_configured' });
  const sid = String(req.query.session_id || ''); if (!sid) return res.status(400).json({ ok: false, error: 'no_session' });
  try {
    const s = await stripe.checkout.sessions.retrieve(sid);
    if (!s || (s.payment_status !== 'paid' && s.status !== 'complete')) return res.json({ ok: false, error: 'unpaid' });
    const m = s.metadata || {}, kind = m.kind;
    const pays = await pmLoad('pm_pays');
    if (pays.some(p => p && p.sid === sid)) return res.json({ ok: true, already: true, kind });
    if (kind === 'renew' || kind === 'feature') {
      const listings = await pmLoad(PM_KEYS.listings); const idx = listings.findIndex(x => x && x.id === m.listingId);
      if (idx >= 0) {
        if (kind === 'renew') {
          const l = listings[idx];
          const base = l.expiresAt && new Date(l.expiresAt) > new Date() ? new Date(l.expiresAt) : new Date();
          l.expiresAt = new Date(base.getTime() + 30 * 864e5).toISOString();
          l.renew5Sent = false; l.renew1Sent = false; if ((l.status || 'active') === 'off') l.status = 'active';
        } else { listings[idx].featured = true; }
        await pmSave(PM_KEYS.listings, listings);
      }
    } else if (kind === 'membership') {
      const profs = await pmLoad('pm_profiles'); const p = profs.find(x => x && _lc(x.email) === _lc(m.email || pmEmail(req.user)));
      if (p) { p.status = 'approved'; p.paid = true; p.paidAt = new Date().toISOString(); await pmSave('pm_profiles', profs); }
    }
    pays.push({ sid, kind, email: m.email || pmEmail(req.user), at: new Date().toISOString() });
    await pmSave('pm_pays', pays.length > 5000 ? pays.slice(-5000) : pays);
    res.json({ ok: true, kind });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});

// Public marketing stats for the landing ticker — aggregate only, no auth, no addresses.
app.get('/api/pm/stats', async (req, res) => {
  try {
    const [listings, boxes, profs] = await Promise.all([
      pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
    const now = new Date();
    const active = listings.filter(l => l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls'
      && !(l.expiresAt && new Date(l.expiresAt) < now));
    const volume = active.reduce((a, l) => a + pmNum(l.price), 0);
    const commission = active.reduce((a, l) => a + pmNum(l.price) * pmNum(l.commissionPct) / 100, 0);
    const members = profs.filter(p => p && p.status === 'approved').length;
    const foundingCap = Number(process.env.PM_FOUNDING_CAP || 100);   // change the cap via env, no redeploy of logic
    res.json({ ok: true, stats: {
      liveDeals: active.length,
      volume: Math.round(volume),
      commission: Math.round(commission),
      members,
      clientNeeds: boxes.filter(Boolean).length,
      dealsPosted: listings.length,
      foundingCap,
      foundingLeft: Math.max(0, foundingCap - members),
      foundingFull: members >= foundingCap
    } });
  } catch (e) { res.json({ ok: false }); }
});
// Referral code for a member — deterministic 6-char code from their email, so every
// member always has one with no extra storage. Used in ?ref=CODE links on the landing.
function pmRefCode(email) {
  const s = _lc(email); let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h.toString(36).toUpperCase().replace(/[^A-Z0-9]/g, '').padStart(6, 'X').slice(0, 6);
}
app.post('/api/pm/request', async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  const email = S(b.email, 120).toLowerCase();
  const name = S(b.name, 100);
  if (!name || !email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))
    return res.status(400).json({ ok: false, error: 'bad_request', message: 'Name and a valid email are required.' });
  try {
    const reqs = await pmLoad('pm_requests');
    if (reqs.some(r => r && _lc(r.email) === email && r.status !== 'denied'))
      return res.json({ ok: true, already: true });
    const rec = { id: pmId('R'), email, name, license: S(b.license, 60), brokerage: S(b.brokerage, 120),
      phone: S(b.phone, 40), markets: S(b.markets, 200), note: S(b.note, 1000),
      referredBy: S(b.ref, 12).toUpperCase().replace(/[^A-Z0-9]/g, '') || '',
      status: 'pending', at: new Date().toISOString() };
    reqs.push(rec);
    await pmSave('pm_requests', reqs.length > 2000 ? reqs.slice(-2000) : reqs);
    try { await pmSendEmail('john@gpgboston.com', 'ACCESS · new access request',
      name + ' requested access to ACCESS.\n\nEmail: ' + email + '\nLicense: ' + (rec.license || '—') +
      '\nBrokerage: ' + (rec.brokerage || '—') + '\nMarkets: ' + (rec.markets || '—') +
      (rec.note ? ('\n\nNote: ' + rec.note) : '') + '\n\nApprove them in the ACCESS admin panel.'); } catch (e) {}
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/admin/requests', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const reqs = await pmLoad('pm_requests');
    res.json({ ok: true,
      requests: reqs.filter(Boolean).sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || String(b.at).localeCompare(String(a.at))),
      pending: reqs.filter(r => r && r.status === 'pending').length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/request/decide', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const id = String(b.id || ''), decision = b.decision === 'denied' ? 'denied' : 'approved';
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const reqs = await pmLoad('pm_requests');
    const idx = reqs.findIndex(r => r && r.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    reqs[idx].status = decision; reqs[idx].decidedAt = new Date().toISOString();
    await pmSave('pm_requests', reqs);
    const r = reqs[idx];
    if (decision === 'approved') {
      try {
        const profs = await pmLoad('pm_profiles');
        const p = profs.find(x => x && _lc(x.email) === _lc(r.email));
        if (p) { p.status = 'approved'; }
        else profs.push({ email: r.email, name: r.name || '', license: r.license || '', brokerage: r.brokerage || '',
          phone: r.phone || '', markets: r.markets || '', status: 'approved', createdAt: new Date().toISOString() });
        // Credit the referrer: find the member whose ref code matches, count it once,
        // and give them a free-month credit (applied when billing starts).
        if (r.referredBy) {
          const ref = profs.find(x => x && x.email && pmRefCode(x.email) === r.referredBy);
          if (ref) {
            ref.referredEmails = Array.isArray(ref.referredEmails) ? ref.referredEmails : [];
            if (!ref.referredEmails.some(e => _lc(e) === _lc(r.email))) {
              ref.referredEmails.push(r.email);
              ref.referrals = (ref.referrals || 0) + 1;
              ref.referralCredits = (ref.referralCredits || 0) + 1;
              try { await pmSendEmail(ref.email, 'ACCESS · your referral was approved',
                (r.name || r.email) + ' just joined ACCESS through your invite. You\'ve earned 1 free month, credited to your account when membership billing begins. That\'s ' + ref.referralCredits + ' free month(s) so far — thanks for growing the network.'); } catch (e) {}
            }
          }
        }
        await pmSave('pm_profiles', profs);
      } catch (e) {}
      try { await pmSendEmail(r.email, 'ACCESS · you\'re approved to join',
        'Good news — you\'re approved as a founding member of ACCESS.\n\nYour access is free while we build out the network. Membership will be $50/month afterward, and we\'ll always give you notice before anything is ever charged.\n\nSign in at https://hub.gpgboston.com/premarket-hub.html to start posting deals and connecting with members.'); } catch (e) {}
    } else {
      try { await pmSendEmail(r.email, 'ACCESS · membership request',
        'Thanks for your interest in ACCESS. We\'re not able to approve your request at this time.'); } catch (e) {}
    }
    res.json({ ok: true, id, status: decision });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// A member's referral link + stats. Every member has a code; approved referrals
// earn a free month (tracked as referralCredits, applied when billing starts).
app.get('/api/pm/referral', ensureAuth, pmGate, async (req, res) => {
  try {
    const email = pmEmail(req.user);
    const code = pmRefCode(email);
    const origin = (req.headers.origin && /^https?:\/\//.test(req.headers.origin)) ? req.headers.origin
      : ('https://' + (req.headers.host || 'hub.gpgboston.com'));
    const link = origin + '/doors.html?ref=' + code;
    const [profs, reqs] = await Promise.all([pmLoad('pm_profiles'), pmLoad('pm_requests')]);
    const me = profs.find(p => p && _lc(p.email) === email) || {};
    const referred = Array.isArray(me.referredEmails) ? me.referredEmails : [];
    const pending = reqs.filter(r => r && r.referredBy === code && r.status === 'pending').length;
    res.json({ ok: true, code, link,
      approved: referred.length,
      pending,
      credits: me.referralCredits || referred.length,
      referred });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// One-tap SAMPLE DATA for previewing the site (owner only). Loads realistic ACCESS
// deals, members (with socials), and client-needs — all tagged sample:true so 'clear'
// removes exactly them. Re-running 'load' strips old samples first, so it never dupes.
app.all('/api/pm/seed', ensureAuth, pmGate, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const mode = String((req.query && req.query.mode) || (req.body && req.body.mode) || 'load').toLowerCase();
  try {
    let [listings, boxes, profs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
    listings = listings.filter(x => !(x && x.sample));
    boxes = boxes.filter(x => !(x && x.sample));
    profs = profs.filter(x => !(x && x.sample));
    if (mode === 'clear') {
      await Promise.all([pmSave(PM_KEYS.listings, listings), pmSave(PM_KEYS.buyboxes, boxes), pmSave('pm_profiles', profs)]);
      return res.json({ ok: true, cleared: true });
    }
    const now = Date.now(), D = 864e5, iso = ms => new Date(ms).toISOString();
    const PEOPLE = [
      { email: 'marcus.reilly@reillyre.com', name: 'Marcus Reilly', brokerage: 'Reilly Investment Real Estate', license: '9812345', markets: 'South Boston, Dorchester, South End', phone: '(617) 555-0142', bio: 'Multifamily investment sales, 11 years. Southie & Dorchester specialist.', linkedin: 'https://www.linkedin.com/in/marcusreilly', instagram: 'https://instagram.com/reilly.re', verified: true },
      { email: 'priya.shah@coastalcre.com', name: 'Priya Shah', brokerage: 'Coastal Commercial RE', license: '9823456', markets: 'Cambridge, Somerville, Medford', phone: '(617) 555-0173', bio: 'Mixed-use and multifamily across Cambridge/Somerville.', linkedin: 'https://www.linkedin.com/in/priyashah', website: 'https://coastalcre.com', verified: true },
      { email: 'danny.fournier@fournierco.com', name: 'Danny Fournier', brokerage: 'Fournier & Co', license: '9834567', markets: 'Quincy, Weymouth, Braintree', phone: '(617) 555-0119', bio: 'South Shore investment specialist.', facebook: 'https://facebook.com/fournierco' },
      { email: 'alyssa.nguyen@northshorecap.com', name: 'Alyssa Nguyen', brokerage: 'North Shore Capital RE', license: '9845678', markets: 'Lynn, Salem, Peabody', phone: '(781) 555-0188', bio: 'Value-add multifamily on the North Shore.', linkedin: 'https://www.linkedin.com/in/alyssanguyen', instagram: 'https://instagram.com/northshore.deals', verified: true },
      { email: 'tom.bradley@bradleymf.com', name: 'Tom Bradley', brokerage: 'Bradley Multifamily', license: '9856789', markets: 'Worcester, Shrewsbury', phone: '(508) 555-0155', bio: 'Larger multifamily and portfolios in Central MA.', website: 'https://bradleymultifamily.com' },
      { email: 'sofia.marchetti@baystateig.com', name: 'Sofia Marchetti', brokerage: 'Bay State Investment Group', license: '9867890', markets: 'Malden, Medford, Everett', phone: '(617) 555-0166', bio: 'Investment sales north of Boston.', linkedin: 'https://www.linkedin.com/in/sofiamarchetti', instagram: 'https://instagram.com/sofia.cre' },
      { email: 'kevin.odonnell@odra.com', name: "Kevin O'Donnell", brokerage: "O'Donnell Realty Advisors", license: '9878901', markets: 'Brockton, Stoughton', phone: '(508) 555-0177', bio: 'Mixed-use and retail south of Boston.', facebook: 'https://facebook.com/odonnellrealty', website: 'https://odonnelladvisors.com' },
      { email: 'rachel.kim@kimcre.com', name: 'Rachel Kim', brokerage: 'Kim Commercial Partners', license: '9889012', markets: 'Lowell, Lawrence, Haverhill', phone: '(978) 555-0121', bio: 'Merrimack Valley commercial & multifamily.', linkedin: 'https://www.linkedin.com/in/rachelkimcre', verified: true },
      { email: 'andre.dubois@duboispg.com', name: 'Andre Dubois', brokerage: 'Dubois Property Group', license: '9890123', markets: 'Revere, Chelsea, East Boston', phone: '(617) 555-0134', bio: 'Off-market deals in Revere/Chelsea/Eastie.', instagram: 'https://instagram.com/dubois.deals' },
      { email: 'jenna.walsh@walshassoc.com', name: 'Jenna Walsh', brokerage: 'Walsh & Associates', license: '9801234', markets: 'Framingham, Natick, MetroWest', phone: '(508) 555-0198', bio: 'MetroWest investment and development sites.', linkedin: 'https://www.linkedin.com/in/jennawalsh', website: 'https://walshassociates.com' }
    ];
    PEOPLE.forEach(p => profs.push(Object.assign({ status: 'approved', createdAt: iso(now - 20 * D), sample: true }, p)));
    const DEALS = [
      { o: 0, L: { propType: 'Multifamily', area: 'South Boston', city: 'Boston', zip: '02127', address: '42 Telegraph St', price: 1850000, commissionPct: 2.5, units: 6, capRate: 5.2, noi: 96200, sqft: 5400, yearBuilt: 1905, notes: 'Turn-key 6-unit, all 2-beds, separate utilities. Upside on 2 units at lease turn.', featured: true } },
      { o: 0, L: { propType: 'Multifamily', area: 'Dorchester', city: 'Boston', zip: '02122', address: '18 Melville Ave', price: 2950000, commissionPct: 2.0, units: 12, capRate: 5.8, noi: 171100, sqft: 10200, yearBuilt: 1920, notes: '12-unit brick, mostly renovated. Value-add on 4 legacy tenants.' } },
      { o: 1, L: { propType: 'Mixed-use', area: 'Cambridge', city: 'Cambridge', zip: '02139', address: '605 Massachusetts Ave', price: 3400000, commissionPct: 3.0, units: 8, capRate: 4.9, noi: 166600, sqft: 8900, notes: 'Retail + 6 apartments on Mass Ave. Below-market retail lease rolls next year.', featured: true } },
      { o: 1, L: { propType: 'Development', area: 'Somerville', city: 'Somerville', zip: '02143', price: 1200000, commissionPct: 2.5, sqft: 9000, notes: 'Permitted for 14 units near Union Sq. Full plans available.', dist: 'private', hideAddress: true, address: '0 Prospect St (assemblage)' } },
      { o: 2, L: { propType: 'Retail', area: 'Quincy', city: 'Quincy', zip: '02169', address: '380 Hancock St', price: 2100000, commissionPct: 2.5, capRate: 6.1, noi: 128100, sqft: 7200, notes: 'Single-tenant retail, corporate guarantee, 7 years remaining.' } },
      { o: 4, L: { propType: 'Multifamily', area: 'Worcester', city: 'Worcester', zip: '01610', address: '22 Kingsbury St', price: 3600000, commissionPct: 2.0, units: 24, capRate: 6.5, noi: 234000, sqft: 19800, notes: '24-unit garden style. Assumable financing at 4.1%.' } },
      { o: 3, L: { propType: 'Condo', area: 'Lynn', city: 'Lynn', zip: '01902', address: '55 Broad St', price: 1450000, commissionPct: 2.5, units: 5, sqft: 6100, notes: '5 condo-able units, master deed started. Conversion play.' } },
      { o: 5, L: { propType: 'Industrial', area: 'Malden', city: 'Malden', zip: '02148', address: '120 Commercial St', price: 4200000, commissionPct: 2.0, capRate: 6.0, noi: 252000, sqft: 31000, notes: '31k SF flex/industrial, fully leased to 3 tenants.', featured: true } },
      { o: 6, L: { propType: 'Single-family', area: 'Brockton', city: 'Brockton', zip: '02301', address: 'Scattered-site portfolio (7 homes)', price: 1100000, commissionPct: 2.5, units: 7, notes: '7-home SFR rental portfolio, all leased. Clean management.' } },
      { o: 7, L: { propType: 'Mixed-use', area: 'Lowell', city: 'Lowell', zip: '01852', address: '145 Merrimack St', price: 2750000, commissionPct: 2.5, units: 10, capRate: 5.5, noi: 151300, sqft: 12400, notes: 'Downtown mixed-use, 2 retail + 8 residential.' } },
      { o: 8, L: { propType: 'Multifamily', area: 'Revere', city: 'Revere', zip: '02151', price: 2400000, commissionPct: 2.5, units: 9, capRate: 5.6, noi: 134400, sqft: 8600, notes: '9-unit near the beach. Seller wants a quiet sale.', hideAddress: true, address: '(on file — hidden)' } },
      { o: 8, L: { propType: 'Land', area: 'Framingham', city: 'Framingham', zip: '01702', address: '0 Waverley St', price: 900000, commissionPct: 3.0, sqft: 43560, notes: '1 acre, commercial zoning, curb cut in place.' } },
      { o: 5, L: { propType: 'Multifamily', area: 'Medford', city: 'Medford', zip: '02155', address: '31 Salem St', price: 2650000, commissionPct: 2.25, units: 8, capRate: 5.4, noi: 143100, sqft: 7800, notes: '8-unit near Tufts. Consistent student demand.' } },
      { o: 3, L: { propType: 'Retail', area: 'Salem', city: 'Salem', zip: '01970', address: '210 Essex St', price: 1950000, commissionPct: 2.5, capRate: 6.2, noi: 120900, sqft: 5600, notes: 'Downtown Salem retail, strong foot traffic.' } }
    ];
    DEALS.forEach((d, i) => {
      const p = PEOPLE[d.o];
      listings.push(Object.assign({
        id: 'SAMPLE-' + (i + 1), owner: p.email, ownerName: p.name,
        status: 'active', dist: 'broad', state: 'MA', docs: [], views: (7 * i) % 40,
        createdAt: iso(now - (i + 1) * 2 * D), updatedAt: iso(now - i * D), expiresAt: iso(now + (26 - (i % 12)) * D),
        sample: true
      }, d.L));
    });
    const BOXES = [
      { o: 1, B: { markets: 'Cambridge, Somerville, Medford', propType: 'Multifamily', minUnits: '8', maxUnits: '30', minPrice: '2000000', maxPrice: '5000000', minCap: '5', notes: '1031 buyer, needs to close in 60 days. Value-add ok.' } },
      { o: 6, B: { markets: 'Brockton, Quincy, Stoughton', propType: 'Mixed-use', minUnits: '', maxUnits: '', minPrice: '1000000', maxPrice: '3000000', minCap: '6', notes: 'Retail + resi, stabilized preferred.' } },
      { o: 4, B: { markets: 'Worcester, Central MA', propType: 'Multifamily', minUnits: '20', maxUnits: '', minPrice: '3000000', maxPrice: '8000000', minCap: '6', notes: 'Institutional buyer seeking 20+ unit assets.' } },
      { o: 3, B: { markets: 'Lynn, Salem, Peabody', propType: 'Multifamily', minUnits: '4', maxUnits: '20', minPrice: '1000000', maxPrice: '3000000', minCap: '5.5', notes: 'Value-add North Shore, cash buyer.' } },
      { o: 8, B: { markets: 'Revere, Chelsea, East Boston', propType: 'Retail', minUnits: '', maxUnits: '', minPrice: '1000000', maxPrice: '2500000', minCap: '6', notes: 'Looking for retail/mixed near transit.' } }
    ];
    BOXES.forEach((bx, i) => {
      const p = PEOPLE[bx.o];
      boxes.push(Object.assign({ owner: p.email, ownerName: p.name, contact: p.email, createdAt: iso(now - (i + 3) * D), updatedAt: iso(now), sample: true }, bx.B));
    });
    await Promise.all([pmSave(PM_KEYS.listings, listings), pmSave(PM_KEYS.buyboxes, boxes), pmSave('pm_profiles', profs)]);
    res.json({ ok: true, loaded: { listings: DEALS.length, members: PEOPLE.length, clientNeeds: BOXES.length } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Optional document upload on a deal — reuses the same Drive plumbing as Summit/deals.
app.post('/api/pm/upload', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const data = String(b.data || '');
  if (!data) return res.status(400).json({ ok: false, error: 'no_file' });
  if (data.length > 21 * 1024 * 1024) return res.status(413).json({ ok: false, error: 'too_big', message: 'File too large (max ~15MB).' });
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const up = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      body: JSON.stringify({ action: 'dealUpload', token: GROVE_SHEET_TOKEN, name: String(b.name || 'file').slice(0, 200), mime: String(b.mime || 'application/octet-stream').slice(0, 120), size: Number(b.size) || 0, data }) }).then(r => r.json());
    if (!(up && up.ok && up.fileId)) return res.status(502).json({ ok: false, error: (up && up.error) || 'upload_failed' });
    res.json({ ok: true, url: up.view || up.url || '', name: up.name || String(b.name || 'file').slice(0, 200) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Renewal-reminder cron: emails the lister 5 days and 1 day before a deal expires, and
// flips lapsed deals to 'off'. Runs on a schedule (protected by PM_CRON_TOKEN) or by the
// hub owner hitting it manually. Idempotent via per-deal renew5Sent / renew1Sent flags.
const PM_CRON_TOKEN = process.env.PM_CRON_TOKEN || '';
async function pmRunRenewals() {
  const listings = await pmLoad(PM_KEYS.listings);
  const now = new Date(); let changed = false; const sent = { r5: 0, r1: 0, expired: 0 };
  for (const l of listings) {
    if (!l || !l.expiresAt || (l.status || 'active') === 'off') continue;
    const days = (new Date(l.expiresAt) - now) / 864e5;
    const link = 'Open ACCESS and hit Renew to extend this deal another 30 days ($1).';
    const label = (l.area || l.city || 'your deal') + (l.price ? (' · ' + pmMoneyShort(l.price)) : '');
    if (days <= 0) { l.status = 'off'; l.expiredAt = now.toISOString(); changed = true; sent.expired++; continue; }
    if (days <= 5 && days > 1 && !l.renew5Sent) {
      await pmSendEmail(l.owner, 'ACCESS · your deal expires in 5 days', label + ' expires in 5 days.\n\n' + link);
      l.renew5Sent = true; changed = true; sent.r5++;
    }
    if (days <= 1 && !l.renew1Sent) {
      await pmSendEmail(l.owner, 'ACCESS · your deal expires tomorrow', label + ' expires in 1 day.\n\n' + link);
      l.renew1Sent = true; changed = true; sent.r1++;
    }
  }
  if (changed) await pmSave(PM_KEYS.listings, listings);
  return sent;
}
app.all('/api/pm/cron', async (req, res) => {
  const tok = String((req.query && req.query.token) || (req.body && req.body.token) || '');
  const authed = (PM_CRON_TOKEN && tok === PM_CRON_TOKEN) || (req.user && req.user.role === 'owner');
  if (!authed) return res.status(403).json({ ok: false, error: 'forbidden' });
  try { res.json({ ok: true, sent: await pmRunRenewals() }); }
  catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Server-side daily sweep so renewal reminders fire without any external scheduler.
// Runs ~30s after boot, then every 12h; idempotent flags keep repeats harmless.
setTimeout(() => { pmRunRenewals().catch(() => {}); }, 30000);
setInterval(() => { pmRunRenewals().catch(() => {}); }, 12 * 3600 * 1000);

// ── Automated off-Google backup ──────────────────────────────────────────────
// All hub + ACCESS data lives in Google Sheets. This makes a second, INDEPENDENT
// copy on a daily schedule so a lost/corrupted/deleted sheet is never the end of
// the world. Every destination is env-gated and off until you set a credential:
//
//   GitHub  (recommended — versioned history, free, truly off Google):
//     BACKUP_GITHUB_TOKEN    fine-grained PAT, Contents: Read+Write on the repo
//     BACKUP_GITHUB_REPO     "your-user/your-private-repo"
//     BACKUP_GITHUB_BRANCH   optional (default "main")
//   Email heartbeat/summary:
//     BACKUP_EMAIL           address to email a daily summary (+ small snapshots)
//
// With NOTHING configured the daily job just logs, and the owner can still pull a
// full snapshot any time from /api/backup/download (zero setup). Never throws.
const BACKUP_GITHUB_TOKEN  = process.env.BACKUP_GITHUB_TOKEN  || '';
const BACKUP_GITHUB_REPO   = process.env.BACKUP_GITHUB_REPO   || '';
const BACKUP_GITHUB_BRANCH = process.env.BACKUP_GITHUB_BRANCH || 'main';
const BACKUP_EMAIL         = process.env.BACKUP_EMAIL         || '';

// ACCESS keys are fully known; the hub list is a fallback used only when the Apps
// Script doesn't support the whole-tab 'notesAll' dump (added to the .gs). If the
// script has notesAll, EVERY key is captured automatically — this list is a floor.
const DOORS_BACKUP_KEYS = ['pm_listings','pm_intros','pm_buyboxes','pm_messages','pm_notifs','pm_broadcasts','pm_profiles','pm_requests','pm_pays'];
const HUB_BACKUP_KEYS = ['owner_portfolio','owner_loans','owner_rentroll','owner_agents','owner_roster','owner_summit_budget_2026','owner_summit_flips_2026','owner_summit_pf','grove_vendors','grove_leads','agent_goals_2026','landlord_ledger','landlord_checks','deal_units','invoice_records','paid_log','referrals','offers','investors','rehabs','track_record','leases','tx_checklists','forsale_folder','ccp_properties','citicore_payroll_401k','summit_campaigns','todos_shared','todos_personal','owner_condo_fees_2026'];

function _bkParse(v){ if (typeof v !== 'string') return v; try { return JSON.parse(v); } catch (e) { return v; } }
// Pull every note off a sheet. Tries the whole-tab dump first (captures keys we
// don't even know about); falls back to enumerating a known key list per-key.
async function bkDumpNotes(baseUrl, token, fallbackKeys, preferAll) {
  if (preferAll) {
    try {
      const url = baseUrl + sheetSep(baseUrl) + 'token=' + encodeURIComponent(token) + '&action=notesAll';
      const j = await fetch(url).then(r => r.json());
      if (j && j.ok && j.notes && typeof j.notes === 'object' && !Array.isArray(j.notes)) {
        const out = {};
        for (const k of Object.keys(j.notes)) { const v = _bkParse(j.notes[k]); if (v != null && v !== '') out[k] = v; }
        return out;
      }
    } catch (e) {}
  }
  const out = {};
  for (const k of fallbackKeys) {
    try {
      const url = baseUrl + sheetSep(baseUrl) + 'token=' + encodeURIComponent(token) + '&action=notes&notekey=' + encodeURIComponent(k);
      const j = await fetch(url).then(r => r.json());
      const v = noteValue(j);
      if (v != null && v !== '') out[k] = _bkParse(v);
    } catch (e) {}
  }
  return out;
}
async function collectFullBackup() {
  const separated = DOORS_SHEET_URL !== GROVE_SHEET_URL;
  const [hub, doors] = await Promise.all([
    bkDumpNotes(GROVE_SHEET_URL, GROVE_SHEET_TOKEN, HUB_BACKUP_KEYS, true),
    // when ACCESS still shares the hub sheet, don't re-dump the whole tab into
    // `doors` — pull just the ACCESS keys so the two buckets stay clean.
    bkDumpNotes(DOORS_SHEET_URL, DOORS_SHEET_TOKEN, DOORS_BACKUP_KEYS, separated)
  ]);
  return { app: 'grove-doors', createdAt: new Date().toISOString(), doorsSheetSeparated: separated, hub, doors };
}
function backupCounts(snap) {
  const map = {};
  for (const b of ['hub', 'doors']) {
    const o = snap[b] || {};
    for (const k of Object.keys(o)) {
      const v = o[k];
      map[b + '.' + k] = Array.isArray(v) ? v.length : (v && typeof v === 'object' ? Object.keys(v).length : (v ? 1 : 0));
    }
  }
  const dp = snap.doors && snap.doors.pm_profiles, dl = snap.doors && snap.doors.pm_listings;
  const short = ((Array.isArray(dp) ? dp.length : 0) + ' members, ' + (Array.isArray(dl) ? dl.length : 0) + ' deals');
  const text = Object.keys(map).map(k => '  ' + k + ': ' + map[k]).join('\n');
  return { map, text, short };
}
// Create/update a file in the GitHub repo via the Contents API (base64, with sha).
async function bkGithubPut(path, contentStr, message) {
  const api = 'https://api.github.com/repos/' + BACKUP_GITHUB_REPO + '/contents/' + path;
  const headers = { 'Authorization': 'Bearer ' + BACKUP_GITHUB_TOKEN, 'Accept': 'application/vnd.github+json', 'User-Agent': 'doors-backup', 'X-GitHub-Api-Version': '2022-11-28' };
  let sha = null;
  try {
    const g = await fetch(api + '?ref=' + encodeURIComponent(BACKUP_GITHUB_BRANCH), { headers });
    if (g.ok) { const gj = await g.json(); sha = (gj && gj.sha) || null; }
  } catch (e) {}
  const body = { message, content: Buffer.from(contentStr, 'utf8').toString('base64'), branch: BACKUP_GITHUB_BRANCH };
  if (sha) body.sha = sha;
  const r = await fetch(api, { method: 'PUT', headers: Object.assign({ 'Content-Type': 'application/json' }, headers), body: JSON.stringify(body) });
  if (!r.ok) throw new Error('github ' + r.status + ' ' + (await r.text().catch(() => '')).slice(0, 160));
  return true;
}
let _lastBackup = { at: null, ok: false, destinations: {}, error: 'not run yet' };
async function runBackup(reason) {
  let snap;
  try { snap = await collectFullBackup(); }
  catch (e) { _lastBackup = { at: new Date().toISOString(), ok: false, destinations: {}, error: 'collect failed: ' + String(e.message || e).slice(0, 160) }; return _lastBackup; }
  const json = JSON.stringify(snap, null, 2);
  const day = snap.createdAt.slice(0, 10);
  const counts = backupCounts(snap);
  const dest = {};
  if (BACKUP_GITHUB_TOKEN && BACKUP_GITHUB_REPO) {
    try {
      await bkGithubPut('doors-backups/latest.json', json, 'ACCESS backup ' + snap.createdAt);
      await bkGithubPut('doors-backups/' + day + '.json', json, 'ACCESS backup ' + day);
      dest.github = 'ok';
    } catch (e) { dest.github = 'error: ' + String(e.message || e).slice(0, 150); }
  }
  if (BACKUP_EMAIL) {
    try {
      const small = json.length < 18000;
      const body = 'ACCESS / Grove automated backup — ' + snap.createdAt + '\n\nContents:\n' + counts.text +
        (dest.github ? ('\n\nGitHub push: ' + dest.github) : '') +
        (small ? ('\n\n--- full snapshot ---\n' + json)
               : '\n\n(Full snapshot is large — pull it from /api/backup/download or your GitHub backup repo.)');
      await pmSendEmail(BACKUP_EMAIL, 'ACCESS backup ' + day + ' · ' + counts.short, body);
      dest.email = 'ok';
    } catch (e) { dest.email = 'error: ' + String(e.message || e).slice(0, 150); }
  }
  const noDest = !(BACKUP_GITHUB_TOKEN && BACKUP_GITHUB_REPO) && !BACKUP_EMAIL;
  _lastBackup = { at: snap.createdAt, ok: Object.values(dest).some(v => v === 'ok'), destinations: dest, counts: counts.map, error: noDest ? 'no destination configured' : null };
  console.log('[backup] ' + reason + (noDest ? ' — no destination configured (download still works)' : ' → ' + JSON.stringify(dest)));
  return _lastBackup;
}
// Owner pulls a complete snapshot on demand — zero setup, saves anywhere they like.
app.get('/api/backup/download', ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const snap = await collectFullBackup();
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="ACCESS-Grove-backup-' + snap.createdAt.slice(0, 10) + '.json"');
    res.send(JSON.stringify(snap, null, 2));
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/backup/run', ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try { res.json({ ok: true, result: await runBackup('manual') }); }
  catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/backup/status', ensureAuth, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  res.json({ ok: true, configured: { github: !!(BACKUP_GITHUB_TOKEN && BACKUP_GITHUB_REPO), email: !!BACKUP_EMAIL, doorsSheetSeparated: DOORS_SHEET_URL !== GROVE_SHEET_URL }, last: _lastBackup });
});
// Daily automated run: ~2 min after boot, then every 24h.
setTimeout(() => { runBackup('boot').catch(() => {}); }, 120000);
setInterval(() => { runBackup('daily').catch(() => {}); }, 24 * 3600 * 1000);

// ── QuickBooks Online Integration ────────────────────────────────────────────
const QB_CLIENT_ID     = process.env.QB_CLIENT_ID     || '';  // set in env; no secret shipped in source
const QB_CLIENT_SECRET = process.env.QB_CLIENT_SECRET || '';  // set in env; QuickBooks features disabled if unset
const QB_REDIRECT_URI  = process.env.QB_REDIRECT_URI  || 'https://hub.gpgboston.com/api/qbo/callback';
const QB_SCOPES        = 'com.intuit.quickbooks.accounting';
const QB_AUTH_URL      = 'https://appcenter.intuit.com/connect/oauth2';
const QB_TOKEN_URL     = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
const QB_API_BASE      = 'https://quickbooks.api.intuit.com/v3/company';

// In-memory token store (owner-scoped; survives requests, lost on restart — re-auth takes 10 sec)
let qbTokens = { accessToken: null, refreshToken: null, realmId: null, expiresAt: 0 };
// Summit company tokens — same Intuit app, different company
let qbSummitTokens = { accessToken: null, refreshToken: null, realmId: null, expiresAt: 0 };
const QB_SUMMIT_REDIRECT_URI = process.env.QB_SUMMIT_REDIRECT_URI || 'https://hub.gpgboston.com/api/qbo-summit/callback';

// QuickBooks tokens were in-memory only, so EVERY redeploy wiped the connection and
// the page went dead until John reconnected. Persist them to an owner-only Sheet note
// (owner_ prefix → owner-gated) so they survive restarts. Intuit rotates the refresh
// token on each refresh, so we re-save after every refresh too.
async function saveQbTokens() {
  try {
    // sheetPost routes through Postgres (+ sheet mirror) when DATABASE_URL is set,
    // matching how this note is read back — keeps the QBO token consistent.
    await sheetPost(GROVE_SHEET_URL, { action: 'notes', notekey: 'owner_qbo_tok', value: JSON.stringify(qbTokens) });
  } catch (e) { /* best effort — memory copy still works this run */ }
}
async function loadQbTokens() {
  if (qbTokens.refreshToken) return;                       // already hydrated this run
  try {
    const url = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL) + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN) + '&action=notes&notekey=owner_qbo_tok';
    const j = await fetch(url).then(r => r.json());
    const raw = j && (j.value != null ? j.value : j.notes);
    if (raw) { const t = JSON.parse(String(raw)); if (t && t.refreshToken) qbTokens = t; }
  } catch (e) { /* ignore — treated as not connected */ }
}

async function qbRefresh() {
  if (!qbTokens.refreshToken) throw new Error('not_connected');
  const creds = Buffer.from(`${QB_CLIENT_ID}:${QB_CLIENT_SECRET}`).toString('base64');
  const r = await fetch(QB_TOKEN_URL, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(qbTokens.refreshToken)}`
  });
  const j = await r.json();
  if (!j.access_token) throw new Error(j.error || 'refresh_failed');
  qbTokens.accessToken = j.access_token;
  qbTokens.refreshToken = j.refresh_token || qbTokens.refreshToken;
  qbTokens.expiresAt = Date.now() + (j.expires_in - 60) * 1000;
  await saveQbTokens();                                    // persist the rotated refresh token
}

async function qbToken() {
  if (!qbTokens.accessToken && !qbTokens.refreshToken) await loadQbTokens();   // rehydrate after a redeploy
  if (!qbTokens.accessToken && !qbTokens.refreshToken) throw new Error('not_connected');
  if (!qbTokens.accessToken || Date.now() > qbTokens.expiresAt) await qbRefresh();
  return qbTokens.accessToken;
}

async function qbGet(path) {
  const tok = await qbToken();
  const r = await fetch(`${QB_API_BASE}/${qbTokens.realmId}${path}`, {
    headers: { 'Authorization': `Bearer ${tok}`, 'Accept': 'application/json' }
  });
  return r.json();
}

// ── Summit QB helpers (mirrors Grove QB functions above) ─────────────────────
async function qbSummitRefresh() {
  if (!qbSummitTokens.refreshToken) throw new Error('not_connected');
  const creds = Buffer.from(`${QB_CLIENT_ID}:${QB_CLIENT_SECRET}`).toString('base64');
  const r = await fetch(QB_TOKEN_URL, {
    method: 'POST',
    headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: `grant_type=refresh_token&refresh_token=${encodeURIComponent(qbSummitTokens.refreshToken)}`
  });
  const j = await r.json();
  if (!j.access_token) throw new Error(j.error || 'refresh_failed');
  qbSummitTokens.accessToken = j.access_token;
  qbSummitTokens.refreshToken = j.refresh_token || qbSummitTokens.refreshToken;
  qbSummitTokens.expiresAt = Date.now() + (j.expires_in - 60) * 1000;
}
async function qbSummitToken() {
  if (!qbSummitTokens.accessToken) throw new Error('not_connected');
  if (Date.now() > qbSummitTokens.expiresAt) await qbSummitRefresh();
  return qbSummitTokens.accessToken;
}
async function qbSummitGet(path) {
  const tok = await qbSummitToken();
  const r = await fetch(`${QB_API_BASE}/${qbSummitTokens.realmId}${path}`, {
    headers: { 'Authorization': `Bearer ${tok}`, 'Accept': 'application/json' }
  });
  return r.json();
}

// Summit QB OAuth
app.get('/api/qbo-summit/connect', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const state = Math.random().toString(36).slice(2);
  req.session.qbSummitState = state;
  const url = `${QB_AUTH_URL}?client_id=${QB_CLIENT_ID}&redirect_uri=${encodeURIComponent(QB_SUMMIT_REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(QB_SCOPES)}&state=${state}`;
  res.redirect(url);
});
app.get('/api/qbo-summit/callback', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).send('Forbidden');
  const { code, state, realmId } = req.query;
  if (!code || state !== req.session.qbSummitState) return res.status(400).send('Invalid state');
  try {
    const creds = Buffer.from(`${QB_CLIENT_ID}:${QB_CLIENT_SECRET}`).toString('base64');
    const r = await fetch(QB_TOKEN_URL, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(QB_SUMMIT_REDIRECT_URI)}`
    });
    const j = await r.json();
    if (!j.access_token) return res.status(502).send('Token exchange failed: ' + JSON.stringify(j));
    qbSummitTokens = { accessToken: j.access_token, refreshToken: j.refresh_token, realmId, expiresAt: Date.now() + (j.expires_in - 60) * 1000 };
    res.redirect('/qbo-connect-summit.html?connected=1');
  } catch(e) { res.status(502).send('QB Summit auth error: ' + e.message); }
});
app.get('/api/qbo-summit/status', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false });
  res.json({ ok: true, connected: !!qbSummitTokens.accessToken, realmId: qbSummitTokens.realmId });
});
app.post('/api/qbo-summit/disconnect', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false });
  qbSummitTokens = { accessToken: null, refreshToken: null, realmId: null, expiresAt: 0 };
  res.json({ ok: true });
});
app.get('/api/qbo-summit/pl', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const { start_date, end_date } = req.query;
    let path = '/reports/ProfitAndLoss?minorversion=65';
    if (start_date) path += `&start_date=${start_date}`;
    if (end_date)   path += `&end_date=${end_date}`;
    const j = await qbSummitGet(path);
    res.json({ ok: true, report: j });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});
app.get('/api/qbo-summit/expenses', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
    const j = await qbSummitGet(`/query?query=${encodeURIComponent(`SELECT * FROM Purchase ORDERBY TxnDate DESC MAXRESULTS ${limit}`)}&minorversion=65`);
    res.json({ ok: true, expenses: j.QueryResponse?.Purchase || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});
app.get('/api/qbo-summit/vendors', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const j = await qbSummitGet(`/query?query=${encodeURIComponent('SELECT * FROM Vendor MAXRESULTS 1000')}&minorversion=65`);
    res.json({ ok: true, vendors: j.QueryResponse?.Vendor || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});
app.get('/api/qbo-summit/accounts', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const j = await qbSummitGet(`/query?query=${encodeURIComponent('SELECT * FROM Account MAXRESULTS 1000')}&minorversion=65`);
    res.json({ ok: true, accounts: j.QueryResponse?.Account || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

// OAuth: redirect owner to Intuit consent screen
app.get('/api/qbo/connect', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const state = Math.random().toString(36).slice(2);
  req.session.qbState = state;
  const url = `${QB_AUTH_URL}?client_id=${QB_CLIENT_ID}&redirect_uri=${encodeURIComponent(QB_REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(QB_SCOPES)}&state=${state}`;
  res.redirect(url);
});

// OAuth callback: exchange code for tokens
app.get('/api/qbo/callback', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).send('Forbidden');
  const { code, state, realmId } = req.query;
  if (!code || state !== req.session.qbState) return res.status(400).send('Invalid state');
  try {
    const creds = Buffer.from(`${QB_CLIENT_ID}:${QB_CLIENT_SECRET}`).toString('base64');
    const r = await fetch(QB_TOKEN_URL, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(QB_REDIRECT_URI)}`
    });
    const j = await r.json();
    if (!j.access_token) return res.status(502).send('Token exchange failed: ' + JSON.stringify(j));
    qbTokens = { accessToken: j.access_token, refreshToken: j.refresh_token, realmId, expiresAt: Date.now() + (j.expires_in - 60) * 1000 };
    await saveQbTokens();                                  // survive future redeploys
    res.redirect('/qbo-connect.html?connected=1');
  } catch(e) { res.status(502).send('QB auth error: ' + e.message); }
});

// Status
app.get('/api/qbo/status', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false });
  await loadQbTokens();                                    // rehydrate after a redeploy before reporting
  res.json({ ok: true, connected: !!(qbTokens.refreshToken || qbTokens.accessToken), realmId: qbTokens.realmId });
});

// Disconnect
app.post('/api/qbo/disconnect', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false });
  qbTokens = { accessToken: null, refreshToken: null, realmId: null, expiresAt: 0 };
  await saveQbTokens();                                    // clear the persisted copy too
  res.json({ ok: true });
});

// P&L report
app.get('/api/qbo/pl', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const { start_date, end_date } = req.query;
    let path = '/reports/ProfitAndLoss?minorversion=65';
    if (start_date) path += `&start_date=${start_date}`;
    if (end_date)   path += `&end_date=${end_date}`;
    const j = await qbGet(path);
    res.json({ ok: true, report: j });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

// Expenses (purchases)
app.get('/api/qbo/expenses', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
    const j = await qbGet(`/query?query=${encodeURIComponent(`SELECT * FROM Purchase ORDERBY TxnDate DESC MAXRESULTS ${limit}`)}&minorversion=65`);
    res.json({ ok: true, expenses: j.QueryResponse?.Purchase || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

// Vendors
app.get('/api/qbo/vendors', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const j = await qbGet(`/query?query=${encodeURIComponent('SELECT * FROM Vendor MAXRESULTS 1000')}&minorversion=65`);
    res.json({ ok: true, vendors: j.QueryResponse?.Vendor || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

// Income transactions (Deposits + Sales Receipts) — for deal fee matching
app.get('/api/qbo/income', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const since = req.query.since || '2026-01-01';
    const [depRes, srRes] = await Promise.all([
      qbGet(`/query?query=${encodeURIComponent(`SELECT * FROM Deposit WHERE TxnDate >= '${since}' ORDERBY TxnDate DESC MAXRESULTS 200`)}&minorversion=65`),
      qbGet(`/query?query=${encodeURIComponent(`SELECT * FROM SalesReceipt WHERE TxnDate >= '${since}' ORDERBY TxnDate DESC MAXRESULTS 200`)}&minorversion=65`)
    ]);
    const deposits = (depRes.QueryResponse?.Deposit || []).map(d => ({
      id: 'dep-' + d.Id,
      date: d.TxnDate,
      amount: d.TotalAmt || 0,
      memo: d.PrivateNote || '',
      type: 'Deposit',
      account: d.DepositToAccountRef?.name || ''
    }));
    const receipts = (srRes.QueryResponse?.SalesReceipt || []).map(s => ({
      id: 'sr-' + s.Id,
      date: s.TxnDate,
      amount: s.TotalAmt || 0,
      memo: (s.CustomerRef?.name || s.PrivateNote || ''),
      type: 'Receipt',
      account: s.DepositToAccountRef?.name || ''
    }));
    const all = [...deposits, ...receipts].sort((a, b) => b.date.localeCompare(a.date));
    res.json({ ok: true, transactions: all });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

// Accounts (chart of accounts)
app.get('/api/qbo/accounts', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const j = await qbGet(`/query?query=${encodeURIComponent('SELECT * FROM Account MAXRESULTS 1000')}&minorversion=65`);
    res.json({ ok: true, accounts: j.QueryResponse?.Account || [] });
  } catch(e) { res.status(e.message === 'not_connected' ? 401 : 502).json({ ok: false, error: e.message }); }
});

const HQ_BAR = `<div id="hq-bar"><div class="hqwrap">
  <a class="hqhome" href="/" target="_top">&#8592; HQ</a>
  <div class="hqr">
    <button type="button" id="hqBackup" title="Check that saving to the sheet works right now">
      <span class="hqdot"></span><span class="hqtxt">Check backup</span>
    </button>
    <a class="hqout" href="/logout" target="_top">Sign out</a>
  </div>
</div></div>
<script>(function(){
  var b=document.getElementById('hqBackup'); if(!b) return;
  var tx=b.querySelector('.hqtxt');
  function set(s,m){ b.className=s; tx.textContent=m; }
  // quiet read on load: is the backend even reachable?
  fetch('/api/grove?action=notes&notekey=_heartbeat')
    .then(function(r){return r.json();})
    .then(function(j){ if(j&&j.ok) set('ok','Backup on'); else set('bad','Backup problem'); })
    .catch(function(){ set('bad','Backup unreachable'); });
  // click: full write -> read-back proof
  b.addEventListener('click', function(){
    set('busy','Checking\u2026');
    var stamp='hb'+Date.now();
    fetch('/api/grove',{method:'POST',headers:{'Content-Type':'application/json'},
             body:JSON.stringify({action:'notes',value:stamp,notes:stamp,notekey:'_heartbeat'})})
      .then(function(r){return r.text();})
      .then(function(txt){
        var j=null; try{ j=JSON.parse(txt); }catch(e){}
        if(!j||!j.ok) throw new Error('write rejected: '+String(txt).slice(0,60));
        return fetch('/api/grove?action=notes&notekey=_heartbeat&_='+Date.now())
                 .then(function(r){return r.json();});
      })
      .then(function(j){
        if(j&&j.ok&&(j.value===stamp||j.notes===stamp)) set('ok','Backup working');
        else throw new Error('read-back mismatch');
      })
      .catch(function(e){ set('bad','Backup FAILING'); console.error('backup check:',e); });
  });
})();</script>`;
// ── Access Control API (owner only) ──────────────────────────────────────────
// Everything access-control.html needs, and the one place it saves back to.
// Deliberately NOT routed through /api/grove: the page catalogue and the role
// defaults are computed here from the same sets and the same pageBlockedFor the
// real gate uses, so the grid can never drift out of step with what the server
// actually enforces. Add a new .html to the repo and it shows up in the grid on
// the next page load with nobody having to remember anything.
const ACL_HIDE = new Set(['home.html','hub-v3.html','access-control.html','privacy.html','terms.html',
                          'grove-access-matrix.html',
                          // The ACCESS product (own access model) + design mockups / scratch pages —
                          // keep them out of the hub permission grid so it lists only real hub tools.
                          'doors.html','premarket-hub.html','reserve.html',
                          'access-landing-mockup.html','access-logo-ad.html','access-logo-final-preview.html',
                          'access-logo-fresh.html','access-logo-hybrids.html','access-logo-mockups.html','access-logo-techy.html',
                          'doors-app-themes.html','doors-browse-layout.html','doors-landing-copy-mockup.html',
                          'doors-theme-11-compare.html','doors-theme-options-2.html','doors-theme-options.html',
                          'sidebar-colors.html','sidebar-fonts.html','sidebar-headings.html','sidebar-mockups.html',
                          'summit-logo-preview.html','preview-sidebar.html',
                          // Personal finance pages — owner-only + private, keep them out of the agent access grid.
                          'spending.html','ledgerwise.html']);
// Pages that hand over money, bank detail, logins or the whole book. Still fully
// grantable — John is the admin — but the grid paints them red so a stray click
// on the wrong row is obvious.
const ACL_SENSITIVE = new Set(['money.html','grove-books.html','deals-payouts.html','logins.html',
  'citicore-payroll.html','backups.html','portfolio.html','citicore-portfolio.html','summit-portfolio.html',
  'qbo-connect.html','qbo-connect-summit.html','pl-tracker.html','expense-log.html','loan-tracker.html',
  'agent-roster.html','landlord-funds.html','key-dates.html']);
function aclPageList(){
  let files = [];
  try { files = fs.readdirSync(__dirname); } catch (e) { files = []; }
  return files
    .filter(f => /\.html$/i.test(f))
    .map(f => f.toLowerCase())
    .filter(f => !ACL_HIDE.has(f) && !/^src-/.test(f) && !/\.orig\.html$/.test(f))
    .sort()
    .map(f => ({ file: f, sensitive: ACL_SENSITIVE.has(f) }));
}
// Agent roster names for dropdowns (e.g. "Your name" on Request Landlord Funds).
// Any signed-in user may read it — it's just the list of agent display names.
app.get('/api/agents', ensureAuth, async (req, res) => {
  try { await loadRoster(false); } catch (e) {}
  const set = new Set();
  const skip = new Set(['GROVE', 'COBROKE', 'HOUSE', 'OFFICE', '']);
  Object.values(AGENT_DEAL_NAMES).forEach(n => { n = String(n || '').trim(); if (n && !skip.has(n.toUpperCase())) set.add(n); });
  (DYN_AGENT_NAMES || []).forEach(n => { n = String(n || '').trim(); if (n && !skip.has(n.toUpperCase())) set.add(n); });
  const agents = [...set].sort((a, b) => a.localeCompare(b));
  res.json({ ok: true, agents });
});
app.get('/api/access', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try { await loadPerms(true); } catch (e) {}
  try { await loadRoster(true); } catch (e) {}
  const pages = aclPageList();
  // Role defaults, computed by the REAL gate with an email that is deliberately
  // not in the grid — so "normal access" on screen is exactly what the server does.
  const NOBODY = '__default__@nobody.invalid';
  const defaults = {};
  ['agent','guest','summit'].forEach(r => {
    defaults[r] = pages.filter(p => !pageBlockedFor(p.file, r, NOBODY)).map(p => p.file);
  });
  const roster = []; const seen = new Set();
  const add = (e, r) => {
    e = String(e || '').trim().toLowerCase();
    if (!e || seen.has(e)) return;
    seen.add(e);
    roster.push({ email: e, role: r, name: AGENT_DEAL_NAMES[e] || '' });
  };
  OWNERS.forEach(e => add(e, 'owner'));
  AGENTS.forEach(e => add(e, 'agent'));
  GUESTS.forEach(e => add(e, 'guest'));
  PARTNERS.forEach(e => add(e, 'summit'));
  DYN_AGENTS.forEach(e => add(e, 'agent'));   // agents added on the Roster page — appear here automatically
  const perms = {};
  Object.keys(PERMS || {}).forEach(e => { perms[e] = [...PERMS[e]]; add(e, roleFor(e) || 'unknown'); });
  res.json({ ok: true, pages, defaults, people: roster, perms, you: req.user.email });
});
app.post('/api/access', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const src = (req.body && req.body.people && typeof req.body.people === 'object') ? req.body.people : null;
  if (!src) return res.status(400).json({ ok: false, error: 'no_people' });
  const valid = new Set(aclPageList().map(p => p.file));
  // MERGE, don't replace. The access page saves ONE person at a time, so if this
  // handler wrote only the people in `src` it would wipe everyone else's custom
  // list on every save — the board could then never hold more than one custom
  // person. Start from the current stored map and apply just the rows in `src`:
  //   array  → set that person's custom list
  //   null   → remove their override (back to normal role access)
  //   absent → left exactly as it was
  // A full-map POST (every person at once) still works — it just sets them all.
  try { await loadPerms(true); } catch (e) {}
  const people = {};
  Object.keys(PERMS || {}).forEach(e => {
    const em = String(e || '').trim().toLowerCase();
    if (em && roleFor(em) !== 'owner') people[em] = [...PERMS[e]];
  });
  Object.keys(src).forEach(e => {
    const em = String(e || '').trim().toLowerCase();
    if (!em || !em.includes('@')) return;
    if (roleFor(em) === 'owner') { delete people[em]; return; } // owners already have everything
    const raw = src[e];
    if (raw === null) { delete people[em]; return; }            // explicit reset to normal access
    if (!Array.isArray(raw)) return;                            // undefined/other → leave this person untouched
    people[em] = [...new Set(raw.map(p => String(p || '').trim().toLowerCase()).filter(p => valid.has(p)))].sort();
  });
  const payload = JSON.stringify({ v: 1, updated: new Date().toISOString(), by: req.user.email, people });
  if (payload.length > 45000) return res.status(413).json({ ok: false, error: 'too_big' });
  try {
    const fwd = { action: 'notes', token: GROVE_SHEET_TOKEN, notekey: 'hub_perms', value: payload };
    const j = await fetch(GROVE_SHEET_URL, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(fwd) }).then(r => r.json());
    if (!j || j.ok === false) return res.status(502).json({ ok: false, error: 'write_rejected' });
    PERMS_AT = 0;                                        // next page load re-reads it
    await loadPerms(true);
    return res.json({ ok: true, saved: Object.keys(people).length });
  } catch (e) { return res.status(502).json({ ok: false, error: String(e) }); }
});

app.use(ensureAuth, async (req, res, next) => {
  if (!/\.html$/i.test(req.path)) return next();
  // Warm the Access Control grid before either gate reads it. Cached 30s, so
  // this is one call to the sheet every half minute, not one per page view.
  // If it throws, loadPerms swallows it and the role defaults apply.
  if (req.user && req.user.role !== 'owner') { try { await loadPerms(); } catch (e) {} }
  // C2: the REAL owner-only gate. This block serves every .html file, so the
  // check has to happen HERE, before the file is read — otherwise the separate
  // gate further below never runs and owner-only pages get handed to anyone.
  const pg = req.path.replace(/^\//, '').toLowerCase();
  if (pageBlockedFor(pg, req.user.role, req.user.email)) {
    return send403(req, res);
  }
  const isHub = /^\/hub-v3\.html$/i.test(req.path);                 // the hub is home; no back link
  let file;
  try { file = path.join(__dirname, decodeURIComponent(req.path)); } catch (e) { return next(); }
  if (!file.startsWith(__dirname)) return next();                   // no path traversal
  fs.readFile(file, "utf8", (err, html) => {
    if (err) return next();                                         // let static handle 404s
    html = injectSkin(html);                                        // ACCESS theme (fonts + colors + dark toggle), every page
    if (!isHub && !html.includes('id="hq-bar"')) {
      const m = /<body[^>]*>/i.exec(html);
      if (m) { const at = m.index + m[0].length; html = html.slice(0, at) + HQ_BAR + html.slice(at); }
    }
    // No-cache, like the "/" route: this handler serves EVERY page, and without
    // these headers Chrome kept stale copies for hours after a deploy — which is
    // why "it's deployed" never looked deployed until a manual hard refresh.
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.type("html").send(withMaps(stripSheetSecret(html)));        // C1: never ship the token · + address autocomplete
  });
});

// Owner-only pages — agents/guests get a 403 if they hit these directly.
// (Enforced in the .html handler above, before the file is served.)
// NOTE: landlord-funds.html is intentionally NOT here — agents use its request
// form; its owner-only sections are protected by the C4 note gate + /api/dl/recon.
const OWNER_ONLY_PAGES = new Set([
  'spending.html','ledgerwise.html',   // Personal finance (Monarch import / statement upload) — owner-only. Added 2026-08-12.
  'portfolio.html','investor-tracker.html','rehab-tracker.html',
  'pl-tracker.html','expense-log.html','offer-tracker.html',
  'lease-tracker.html','track-record.html',
  'qbo-connect.html','qbo-connect-summit.html','deals-payouts.html','money.html',
  'key-dates.html',
  // lead-feeds.html is DELIBERATELY in this list AND in SUMMIT_PAGES below.
  // It is the shared probate / pre-foreclosure board: Summit partners need it,
  // Grove agents must not have it. pageBlockedFor checks the Summit allow-list
  // first and returns before it ever reaches this set, so both hold at once.
  // Do not "clean this up" by deleting either entry — removing it here opens the
  // board to every agent. (C3)
  'citicore-payroll.html','lead-feeds.html',   // logins.html opened to agents 2026-08-07 — rebuilt as the shared Grove vault (code-gated)
  'citicore-portfolio.html','citicore-condo-fees.html','rent-roll.html','summit-portfolio.html',
  'loan-tracker.html','backups.html','grove-books.html',
  // Added 2026-08-06. Both were reachable by agents but read owner-only notes,
  // so an agent got an empty page that looked broken rather than a clean 403.
  'agent-roster.html','referral-tracker.html','team-access.html',
  // Added 2026-08-07. The new Citicore portfolio-management pages were reachable
  // by any Grove agent (the deny-list simply never listed them) even though they
  // expose Citicore bank balances, properties, insurance, maintenance and docs.
  // Owner-only here; the bookkeeper still reaches them via BOOKKEEPER_PAGES.
  'citicore-dashboard.html','citicore-bank.html','citicore-properties.html',
  'citicore-maintenance.html','citicore-insurance.html','citicore-documents.html',
  // Added 2026-08-08. New per-property Citicore ops pages — utility account
  // numbers and lockbox/alarm/gate codes. Owner-only; sensitive access data.
  'citicore-utilities.html','citicore-keycodes.html',
  // Added 2026-08-09 (pre-release audit, John's call): the standalone Pipeline
  // Board is owner-only now — the totals live on Deals & Payouts. board-deals
  // endpoint still allows agents, but with the page blocked nothing agent-facing
  // reaches it. (To fully wall it, set boardMayUse to owner-only too.)
  'board.html',
  // Added 2026-08-09 (pre-release audit). hub-v3.html is an owner-style "Business
  // Hub — Preview" (payroll/todos/deals widgets) that nothing links to but any
  // agent could reach by URL. Its data calls are individually gated, but the
  // surface itself is owner-shaped; block the page outright.
  'hub-v3.html'
]);
// Summit's own tools. Summit partners are correctly walled out of every Grove
// page by their allow-list — but the wall only stood in ONE direction, because
// the agent rule is a deny-list and nobody added these. A Grove agent could open
// the Social Studio and read (and edit) all of Summit's content. The other two
// simply broke for agents: the page loaded, /api/summit answered 403, and the
// screen sat empty. Named here so the agent rule blocks them too.
const SUMMIT_ONLY_PAGES = new Set([
  // ── Deactivated 2026-08-07 (REsimpli takes these over): blocked for agents
  // here AND removed from SUMMIT_PAGES above, so nobody but John can open them.
  'acquisitions-crm.html','offer-tracker.html','summit-campaigns.html',
  'summit-quickadd.html',
  'nik-task-board.html',      // Nik's private onboarding/daily/weekly board — Grove agents blocked here
  // Added 2026-08-07. Summit's outbound dashboard and campaign tracker were in
  // SUMMIT_PAGES (partner allow-list) but never in this agent deny-list, so a
  // Grove agent could open them. Blocked for agents now, same as the other Summit tools.
  'summit-dashboard.html','summit-campaigns.html',
  // Added 2026-08-09 (pre-release audit). Summit's shared password vault page was
  // reachable by Grove agents (in SUMMIT_PAGES for partners, but never in this agent
  // deny-list). The summit_logins note is already blocked for agents server-side and
  // the page is PIN-gated, but a Grove agent should not see the Summit vault at all.
  'summit-logins.html'
  // NOTE: social-studio.html and acquisitions-crm.html were removed from this set
  // 2026-08-07 on John's instruction — Grove agents now get both. social-studio
  // falls back to the Grove brand for non-Summit users; acquisitions-crm needs the
  // /api/summit crm+queue actions, which now allow the agent role (see /api/summit).
]);
// Citicore-scoped user (guest) may reach ONLY these pages (+ the home shell). Fail-safe allow-list.
// Summit partner may reach ONLY these pages (+ the home shell). Same fail-safe
// allow-list style as the Citicore one: anything not named here is blocked.
// Summit partner (Nik, Jose): the full Summit toolset. Everything on the Summit
// side of the house EXCEPT the money pages — money.html, grove-books.html and
// summit-portfolio.html are deliberately absent, and so is every Grove and
// Citicore page. Anything not named here is blocked.
const SUMMIT_PAGES = new Set([
  'social-studio.html',       // Social Media Studio
  'lead-feeds.html',          // the shared lead board (probate + pre-foreclosure)
  'investor-tracker.html',    // Investor Tracker
  'rehab-tracker.html',       // Rehab Tracker
  'track-record.html',        // Deal Track Record
  'quick-underwrite.html',    // Fast Underwrite
  'flip-underwriter.html',    // Flip / Hard Money
  // Full underwriting suite + OM Builder opened to Summit partners 2026-08-07
  // on John's instruction — same tools Grove agents see.
  'deal-analyzer.html',       // Full Underwrite
  'str-underwriter.html',     // Airbnb / STR
  'multifamily-underwriter.html', // Multifamily pro forma
  'build-feasibility.html',   // Build Feasibility
  'condo-underwriter.html',   // Condo Play Underwriter (sell-out vs comps by SF/bed/bath)
  'om-builder.html',          // OM Builder
  'summit-logins.html',       // Summit shared logins (site/username/password, synced to the sheet)
  'nik-task-board.html',      // Nik's task board (its own page gate shows non-Nik a private screen)
  'summit-dashboard.html',    // Summit outbound dashboard
  'summit-voice.html',        // Voice Note inbox + task list (webhook fed)
  'premarket-hub.html',       // Premarket · Boston off-market deal network (all roles)
]);
// grove-books.html was REMOVED from this list 2026-08-06 on John's instruction.
// Note what it actually did: the books page is multi-company, and the guest's
// note allow-list only ever permitted the `books_citicore` keys — so Michael saw
// the Citicore tab and never Grove's or Summit's numbers. Removing the page (and
// the matching key below) closes it entirely. To reverse, add the filename back
// here, restore the `books_citicore` clause in CITICORE_NOTE_OK, and put the
// Books link back in NAV_CITI in home.html — all three, or the link 403s.
const CITICORE_PAGES = new Set(['citicore-portfolio.html','rent-roll.html','loan-tracker.html','citicore-condo-fees.html','citicore-payroll.html','premarket-hub.html']);
function send403(req, res){
  const role = (req.user && req.user.role) || "agent";
  const links = role === "guest"
    ? '<a href="/citicore-portfolio.html">Citicore Portfolio</a> · <a href="/rent-roll.html">Rent Roll</a> · <a href="/loan-tracker.html">Loans</a> · <a href="/citicore-condo-fees.html">Condo Fees</a> · <a href="/citicore-payroll.html">Payroll</a>'
    : role === "summit"
    ? '<a href="/lead-feeds.html">Lead Board</a> · <a href="/acquisitions-crm.html">Acquisitions CRM</a> · <a href="/offer-tracker.html">Offers</a> · <a href="/quick-underwrite.html">Fast Underwrite</a> · <a href="/social-studio.html">Social Studio</a>'
    : '<a href="/agent-add-deal.html">Submit a Deal</a> · <a href="/transaction-checklist.html">Checklist</a> · <a href="/agent-pay.html">My Pay</a> · <a href="/vendors.html">Vendors</a>';
  return res.status(403).type("html").send('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Owner-only</title><style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#E6EBF3;color:#141A24;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.b{text-align:center;padding:36px;background:#fff;border:1px solid #C7D3E4;border-radius:14px;max-width:460px;box-shadow:0 2px 16px rgba(20,26,36,.06)}h1{font-size:20px;margin:0 0 8px}p{color:#4E5866;margin:0 0 6px;font-size:14.5px;line-height:1.5}.l{margin-top:14px;font-size:13.5px}.l a{color:#1D4F8F;text-decoration:none;font-weight:600}a.hq{display:inline-block;margin-top:18px;background:#0E1626;color:#fff;text-decoration:none;padding:10px 18px;border-radius:9px;font-weight:600}</style></head><body><div class="b"><h1>This one&rsquo;s owner-only</h1><p>Nothing&rsquo;s broken — this page is part of the ownership side of the hub.</p><div class="l">Your tools: '+links+'</div><a class="hq" href="/">&larr; Back to HQ</a></div></body></html>');
}
// ── Per-person access grid ───────────────────────────────────────────────────
// access-control.html is a grid: every person down the left, every page across
// the top, a checkbox between. Ticking a box saves a JSON map to the note
// `hub_perms`; this block reads that map back server-side and lets it override
// the role defaults below. A change takes effect on that person's next page
// load — no deploy, no GitHub, no restart.
//
// Fail-safe in every direction. Any of these falls back to the plain role rules,
// which are exactly today's behaviour:
//   • the note is missing, unreadable, empty, or not valid JSON
//   • the grid has never been saved (cold server)
//   • the person isn't listed in it
// Only a person who IS listed gets the override, and then their list is the
// whole truth for them. That means the grid can never lock the hub down harder
// than it already is by failing — the worst a failure does is nothing.
//
// One page is deliberately NOT overridable: access-control.html itself. If it
// were, one wrong tick would let somebody re-grant themselves everything.
// Pages the grid must never be able to hand out, however many boxes get ticked.
// access-control.html: whoever holds it can grant themselves everything else.
// backups.html: it reads every note in the business and can restore over live
//   data, so it is the same power by another door. It also became a data trap
//   once Agent Goals were filtered per person (2026-08-06) — a backup run by a
//   non-owner would quietly contain only that person's goals while looking
//   complete. Owner-only removes both problems at once. Safe to relax later if
//   John wants a bookkeeper to hold it, but that should be a deliberate choice.
// board.html added 2026-08-09 (John's call: pipeline is owner-only). ALWAYS_OWNER
// means not even the per-person Access Control grid can re-open it — a stray tick
// can never expose the Pipeline Board again.
const ALWAYS_OWNER = new Set(['access-control.html', 'backups.html', 'board.html']);
// The analysis toolkit every agent always keeps — the underwriters (Condo Play
// included), OM Builder, and the calculators. These carry no private data, and
// John's directive (2026-08-13) is that every agent can use all of them. So they
// are granted to ANY agent even when that person has a custom Access Control list
// that happens to omit them — a whitelist can restrict pages, never these tools.
const AGENT_ALWAYS = new Set([
  'quick-underwrite.html','deal-analyzer.html','flip-underwriter.html','str-underwriter.html',
  'multifamily-underwriter.html','build-feasibility.html','condo-underwriter.html','om-builder.html',
  'commission-calc.html','mortgage-calc.html'
]);
let PERMS    = null;   // null = never successfully loaded; {} = loaded, nobody listed
let PERMS_AT = 0;
const PERMS_TTL = 30000;   // 30s — a tick John saves shows up on the next refresh
async function loadPerms(force){
  if (!force && PERMS !== null && Date.now() - PERMS_AT < PERMS_TTL) return PERMS;
  try {
    const url = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL)
              + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN)
              + '&action=notes&notekey=hub_perms&_=' + Date.now();
    const j   = await fetch(url).then(r => r.json());
    const raw = j && (j.value != null ? j.value : j.notes);
    const obj = raw ? JSON.parse(String(raw)) : null;
    const ppl = (obj && obj.people && typeof obj.people === 'object') ? obj.people : {};
    const out = {};
    Object.keys(ppl).forEach(e => {
      const v    = ppl[e];
      const list = Array.isArray(v) ? v : (v && Array.isArray(v.pages) ? v.pages : null);
      if (list) out[String(e).trim().toLowerCase()] = new Set(list.map(p => String(p).trim().toLowerCase()));
    });
    PERMS = out; PERMS_AT = Date.now();
  } catch (e) {
    // Keep the last good copy. Only stamp the clock so we retry on the next tick
    // instead of hammering Apps Script once per request while it's down.
    PERMS_AT = Date.now();
  }
  return PERMS;
}
function personAllow(email){
  if (!PERMS) return null;                                  // never loaded → role defaults
  const e = String(email || '').trim().toLowerCase();
  return (e && PERMS[e]) || null;                           // not listed → role defaults
}
// People John adds on the Agent Roster page land in owner_roster.custom (an
// owner-only note). Read that list — cached the same way the perms grid is — and
// expose the emails as agent logins through DYN_AGENTS. Fail-safe: any read error
// keeps the last-known set, so a flaky sheet call can never revoke everyone at once.
let ROSTER_AT = 0;
const ROSTER_TTL = 30000;   // 30s — a person John adds can sign in on the next tick
async function loadRoster(force){
  if (!force && Date.now() - ROSTER_AT < ROSTER_TTL) return DYN_AGENTS;
  try {
    const url = GROVE_SHEET_URL + sheetSep(GROVE_SHEET_URL)
              + 'token=' + encodeURIComponent(GROVE_SHEET_TOKEN)
              + '&action=notes&notekey=owner_roster&_=' + Date.now();
    const j   = await fetch(url).then(r => r.json());
    const raw = j && (j.value != null ? j.value : j.notes);
    const obj = raw ? JSON.parse(String(raw)) : null;
    const custom = (obj && Array.isArray(obj.custom)) ? obj.custom : [];
    const set = new Set(); const names = [];
    custom.forEach(p => {
      const e = String(p && p.email || '').trim().toLowerCase();
      if (e && e.indexOf('@') > 0) set.add(e);
      const nm = String(p && p.name || '').trim();
      if (nm) names.push(nm);
    });
    DYN_AGENTS = set; DYN_AGENT_NAMES = names; ROSTER_AT = Date.now();
  } catch (e) {
    ROSTER_AT = Date.now();   // keep the last good set; retry on the next tick
  }
  return DYN_AGENTS;
}
// Pages a bookkeeper login may open: the money ledgers + read access to the
// portfolio/property pages they categorise against. No Grove/Summit/brokerage tools.
const BOOKKEEPER_PAGES = new Set([
  'citicore-dashboard.html','grove-books.html','citicore-bank.html','expense-log.html',
  'pl-tracker.html','citicore-payroll.html','citicore-condo-fees.html','citicore-maintenance.html',
  'citicore-properties.html','rent-roll.html','loan-tracker.html','lease-tracker.html',
  'citicore-insurance.html','citicore-documents.html'
]);
function pageBlockedFor(pg, role, email){
  pg = (pg || '').toLowerCase();
  if (!/\.html$/.test(pg)) return false;                                      // only gate .html; assets/api pass
  if (role === 'owner') return false;                                         // owner: everything
  if (role === 'member') return pg !== 'premarket-hub.html';                  // public Reserve member: that ONE page, nothing else
  if (pg === 'premarket-hub.html') return false;                             // Reserve: free for EVERY hub login (outsiders pay via the member role above)
  if (ALWAYS_OWNER.has(pg)) return true;                                      // never grantable, not even by the grid
  // Old copies and working files. aclPageList() deliberately keeps these OUT of the
  // Access Control grid so John isn't asked to make decisions about scratch files —
  // but "not in the grid" was never the same as "blocked", so until now an agent who
  // typed the address got the superseded copy of a page, complete with whatever
  // behaviour that copy had before it was fixed. Nothing links to them; they exist
  // because a file was kept next to the one that replaced it. Owner-only, so they
  // cannot rot into a back door, and so a page can still be kept beside its
  // replacement safely.
  if (/\.orig\.html$/.test(pg) || /^src-/.test(pg)) return true;
  if (pg === 'home.html') return false;                                       // the hub shell, always
  if (role === 'agent' && AGENT_ALWAYS.has(pg)) return false;                 // every agent keeps the underwriter toolkit (Condo Play etc.), even with a custom list
  const mine = personAllow(email);
  if (mine) return !mine.has(pg);                                             // John ticked boxes for this person — his list wins
  if (role === 'guest') return !CITICORE_PAGES.has(pg);                       // Citicore user: Citicore pages only
  if (role === 'summit') return !SUMMIT_PAGES.has(pg);                        // Summit partner: the Studio and the hub shell
  if (role === 'bookkeeper') return !BOOKKEEPER_PAGES.has(pg);                // Bookkeeper: money ledgers + read-only property
  return OWNER_ONLY_PAGES.has(pg) || SUMMIT_ONLY_PAGES.has(pg);               // agent: owner-only + Summit-only pages blocked
}
app.use(ensureAuth, async (req, res, next) => {
  const page = req.path.replace(/^\//, '');
  if (/\.html$/i.test(page) && req.user && req.user.role !== 'owner') {
    try { await loadPerms(); } catch (e) {}
  }
  if (pageBlockedFor(page, req.user.role, req.user.email)) {
    return send403(req, res);
  }
  next();
}, (req, res, next) => {
  if (req.path.endsWith('.html') || req.path === '/') {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
}, express.static(__dirname)); // serves the workbook + assets, gated

// ---- DepositLink reconciliation (owner only) ----
// Registered BEFORE the catch-all 404 below. It used to sit after app.listen(), past the
// 404 handler, so the 404 shadowed it and every /api/dl/recon call returned the branded
// "page isn't available" HTML — which is why Landlord Funds said "Couldn't load escrow".
let DL_TOK=null, DL_TOK_EXP=0;
async function dlToken(){
  if(DL_TOK && Date.now()<DL_TOK_EXP) return DL_TOK;
  const id=(process.env.DEPOSITLINK_CLIENT_ID||'').trim(), sec=(process.env.DEPOSITLINK_SECRET||'').trim();
  if(!id||!sec) throw new Error('DepositLink credentials not configured');
  const body='grant_type=client_credentials&scope='+encodeURIComponent('transactions:read deals:read')+'&client_id='+encodeURIComponent(id)+'&client_secret='+encodeURIComponent(sec);
  const r=await fetch('https://api.depositlink.com/connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
  if(!r.ok) throw new Error('DepositLink token HTTP '+r.status);
  const j=await r.json();
  DL_TOK=j.access_token; DL_TOK_EXP=Date.now()+(((j.expires_in||3600)-120)*1000);
  return DL_TOK;
}
app.get('/api/dl/recon', ensureAuth, async (req,res)=>{
  try{
    if(!req.user || req.user.role!=='owner') return res.status(403).json({ok:false,error:'owner only'});
    const tok=await dlToken();
    let all=[],skip=0,take=200;
    for(let i=0;i<25;i++){
      const r=await fetch('https://api.depositlink.com/transactions?take='+take+'&skip='+skip,{headers:{Authorization:'Bearer '+tok}});
      if(!r.ok) throw new Error('DepositLink transactions HTTP '+r.status);
      const a=await r.json();
      const L=Array.isArray(a)?a:(a.items||a.data||a.results||[]);
      all=all.concat(L);
      if(L.length<take) break;
      skip+=take;
    }
    const tx=all.map(function(x){
      const acct=String(x.receiverFundingSourceName||'');
      let cls='other';
      if(acct.indexOf('9295')>=0)cls='escrow'; else if(acct.indexOf('2452')>=0)cls='fee';
      return {id:x.id,address:x.address||'',city:x.city||'',amount:x.amount||0,type:x.transactionType||'',status:x.transferStatus||'',cls:cls,agent:x.agentName||'',sender:x.sender||'',seller:x.seller||'',date:x.createdDate||'',acct:acct};
    });
    res.json({ok:true,count:tx.length,transactions:tx});
  }catch(e){res.status(500).json({ok:false,error:String((e&&e.message)||e)});}
});

// Branded 404 for any unmatched route (missing tool pages, mistyped links) instead of a raw 404.
app.use((req, res) => {
  res.status(404);
  if (req.accepts('html')) {
    return res.type('html').send('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Not available</title><style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#FAFAFA;color:#141414;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}.b{text-align:center;padding:30px}h1{font-size:22px;margin:0 0 8px}p{color:#8A8A8A;margin:0}a{display:inline-block;margin-top:16px;background:#111;color:#fff;text-decoration:none;padding:10px 18px;border-radius:9px;font-weight:600}</style></head><body><div class="b"><h1>This page isn’t available</h1><p>It may have moved, or isn’t part of your access.</p><a href="/">&larr; Back to HQ</a></div></body></html>');
  }
  res.type('txt').send('Not found');
});

// Bring up the Postgres schema before we start serving (no-op if DATABASE_URL unset).
gdb.ensureSchema()
  .then(ok => console.log(ok ? "Postgres ready (hub data → Postgres, mirrored to Sheets)" : "No DATABASE_URL — hub on Google Sheets"))
  .catch(e => console.error("grove-db schema init failed", e))
  .finally(() => app.listen(PORT, () => console.log(`Grove dashboard on ${BASE_URL}`)));
