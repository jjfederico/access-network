// Shared product-compliance helpers for a Massachusetts-only, flat-subscription
// licensed-agent network. No transaction-money fields. No invented legal copy.

'use strict';

const FOUNDING_CAP = Number(process.env.PM_FOUNDING_CAP || 100);
const FOUNDING_RATE = Number(process.env.PM_PRICE_FOUNDING || 25);
// Flat pricing: everyone pays the same published rate. Founding members (first
// 100 by join order) have it locked for life; the distinction is the lock, not
// the amount.
const STANDARD_RATE = Number(process.env.PM_PRICE_STANDARD || 25);
// Every membership starts with a free trial of this many days.
const TRIAL_DAYS = Number(process.env.PM_TRIAL_DAYS || 14);

const TERMINATION_CAUSES = ['license_lapse', 'non_payment', 'material_breach'];
// The only stated causes for denying, revoking, or terminating a membership.
const CAUSE_LABELS = {
  license_lapse: 'License not active or not in good standing',
  non_payment: 'Non-payment of the published subscription',
  material_breach: 'Material breach of the Terms'
};

const PRICE_BANDS = [
  { id: 'under_500k', label: 'Under $500K', min: 0, max: 500000 },
  { id: '500k_1m', label: '$500K – $1M', min: 500000, max: 1000000 },
  { id: '1m_2m', label: '$1M – $2M', min: 1000000, max: 2000000 },
  { id: '2m_5m', label: '$2M – $5M', min: 2000000, max: 5000000 },
  { id: '5m_plus', label: '$5M+', min: 5000000, max: 0 }
];

const NEED_TIMELINES = ['30_days', '60_days', '90_days', '6_months', 'flexible'];
const NEED_TIMELINE_LABELS = {
  '30_days': 'About 30 days',
  '60_days': 'About 60 days',
  '90_days': 'About 90 days',
  '6_months': 'About 6 months',
  flexible: 'Flexible'
};

// Cape Cod & Islands / Berkshires — posting here may count as public marketing
// under a local MLS's rules. Members must confirm with their broker/MLS.
const MLS_ZONE = {
  cape_islands: [
    'barnstable', 'hyannis', 'falmouth', 'sandwich', 'bourne', 'mashpee', 'yarmouth',
    'dennis', 'harwich', 'chatham', 'orleans', 'brewster', 'eastham', 'wellfleet',
    'truro', 'provincetown', 'cape cod', 'nantucket', 'edgartown', 'oak bluffs',
    'tisbury', 'vineyard haven', 'west tisbury', 'chilmark', 'aquinnah',
    "martha's vineyard", 'marthas vineyard', 'marion', 'wareham', 'gosnold'
  ],
  berkshire: [
    'pittsfield', 'lenox', 'great barrington', 'lee', 'stockbridge', 'williamstown',
    'north adams', 'adams', 'dalton', 'sheffield', 'egremont', 'monterey',
    'new marlborough', 'sandisfield', 'otis', 'becket', 'hinsdale', 'peru',
    'washington', 'becket', 'cheshire', 'lanesborough', 'hancock', 'richmond',
    'west stockbridge', 'alford', 'tyringham', 'monterey', 'new ashford',
    'clarksburg', 'florida', 'savoy', 'windsor', 'cummington', 'middlefield'
  ]
};

const MLS_ZONE_WARNING =
  'Posting a property in the Cape Cod & Islands or Berkshire area on this network may count as public marketing under that area’s MLS rules. Confirm with your broker and your MLS before you post. AXESS does not determine whether a post satisfies or violates any MLS rule.';

// Compensation / BBC language. Reject listing descriptions that advertise
// buyer-broker compensation, referral fees, or finder’s fees.
const COMP_RE = /\b(buyer[-\s]?broker(?:age)?(?:\s+comp(?:ensation)?)?|buyer[-\s]?agent\s+comp(?:ensation)?|\bbbc\b|co-?broke(?:rage|r)?|cooperating\s+broker(?:age)?|referral\s+fee|finder['’]?s\s+fee|commission(?:s)?(?:\s+(?:to|for|of|pct|percent|%))|\d+(\.\d+)?\s*%\s*(commission|bbc|to\s+buyer|buyer\s+agent|buyer[-\s]?broker))\b/i;
const MOTIVATED_RE = /\bmotivated\b/i;

function compensationHit(text) {
  const s = String(text == null ? '' : text);
  if (!s.trim()) return null;
  const m = s.match(COMP_RE);
  return m ? m[0] : null;
}

// Fair housing: listing and client-need text may not state a preference,
// limitation or discrimination based on a protected class (federal Fair
// Housing Act §3604(c); Massachusetts G.L. c.151B, which also protects
// receipt of public assistance / housing subsidies such as Section 8).
// Conservative phrase list — catches common problem wording, not a legal
// review. Returns the matched phrase, or null.
const FAIR_HOUSING_RE = new RegExp('\\b(' + [
  'no (?:kids|children|minors|families|babies|teens?)',
  'adults? only', 'adult (?:community|building|living)(?! center)',
  'not suitable for (?:children|kids|families)', 'no (?:section ?8|vouchers?|housing vouchers?|subsidi[sz]ed tenants?|rental assistance|welfare|public assistance|ssi|ssdi)',
  'section ?8 not (?:accepted|allowed)', 'vouchers? not (?:accepted|allowed)',
  '(?:perfect|ideal|great|best) for (?:an? )?(?:young |single |married |mature |older |retired )?(?:couples?|singles?|bachelors?|retirees|seniors|empty[- ]nesters|young professionals|students|newlyweds)',
  '(?:singles?|couples?|married couples?|seniors|retirees|students) only', 'no students', 'mature (?:person|persons|couple|individual|adults?|tenants?|buyers?)',
  'no (?:wheelchairs?|disabled|handicapped)', 'able[- ]bodied', 'must be able to climb', 'no (?:service|emotional support|support) animals',
  '(?:christian|catholic|jewish|muslim|church[- ]going) (?:home|family|families|buyers?|tenants?|neighborhood|community)',
  '(?:white|black|asian|hispanic|latino|ethnic|exclusive) neighborhood', 'english[- ]speaking only', 'english only', 'must speak english',
  'no (?:immigrants|foreigners)', 'citizens only', 'no unmarried', 'married couples? preferred'
].join('|') + ')\\b', 'i');

function fairHousingHit(text) {
  const s = String(text == null ? '' : text);
  if (!s.trim()) return null;
  const m = s.match(FAIR_HOUSING_RE);
  return m ? m[0] : null;
}
const FAIR_HOUSING_MSG = 'Listings and client needs can’t state a preference or limitation based on a protected class — for example family status or children, age, disability, religion, race, national origin, or receipt of public assistance such as Section 8. Remove';

function motivatedHit(text) {
  const s = String(text == null ? '' : text);
  if (!s.trim()) return null;
  return MOTIVATED_RE.test(s) ? 'motivated' : null;
}

function priceBandById(id) {
  return PRICE_BANDS.find(b => b.id === String(id || '')) || null;
}

function normalizePriceBand(v) {
  const b = priceBandById(v);
  return b ? b.id : '';
}

function normalizeTimeline(v) {
  const t = String(v || '').trim();
  return NEED_TIMELINES.indexOf(t) >= 0 ? t : '';
}

function locBlob() {
  return Array.prototype.slice.call(arguments).map(x => String(x || '').toLowerCase()).join(' ');
}

function mlsZoneFor(city, area, address) {
  const loc = locBlob(city, area, address);
  if (!loc.trim()) return '';
  const inList = list => list.some(c => loc.indexOf(c) >= 0);
  if (inList(MLS_ZONE.cape_islands)) return 'cape_islands';
  if (inList(MLS_ZONE.berkshire)) return 'berkshire';
  return '';
}

function isMassachusettsState(state) {
  const s = String(state || '').trim().toUpperCase();
  return !s || s === 'MA' || s === 'MASS' || s === 'MASSACHUSETTS';
}

function foundingForJoinOrder(priorApprovedCount) {
  const n = Number(priorApprovedCount) || 0;
  const founder = n < FOUNDING_CAP;
  return {
    founder,
    memberNo: n + 1,
    monthly: founder ? FOUNDING_RATE : STANDARD_RATE,
    foundingCap: FOUNDING_CAP,
    foundingRate: FOUNDING_RATE,
    standardRate: STANDARD_RATE
  };
}

// A member's free trial runs TRIAL_DAYS from the later of when they joined and
// when paid billing began, so members who joined before billing still get the
// full trial. Before billing begins there is no trial end (nobody is charged).
function trialEndsAt(joinedAt, billingStartedAt) {
  if (!billingStartedAt) return '';
  const start = Math.max(new Date(joinedAt || 0).getTime() || 0, new Date(billingStartedAt).getTime() || 0);
  return start ? new Date(start + TRIAL_DAYS * 864e5).toISOString() : '';
}

function validTerminationCause(cause) {
  return TERMINATION_CAUSES.indexOf(String(cause || '')) >= 0;
}

function sellerFormOk(form) {
  if (!form || typeof form !== 'object') return false;
  const hasFile = !!(form.key || form.url);
  const name = String(form.name || '');
  return hasFile && !!name;
}

// A newly submitted seller-signed form must point at a real uploaded file:
// either an object-storage key in the shape /api/pm/upload issues, or an inline
// document/image data URL (the no-R2 fallback). Anything else — a bare link,
// junk that sanitizes to nothing, an over-size or truncated payload — is
// rejected rather than stored as "authorized". Returns the cleaned form or null.
const SELLER_FORM_KEY_RE = /^u\/[0-9a-f]{10}\/[a-z0-9]+\.[a-z0-9]+$/;
const SELLER_FORM_DATA_RE = /^data:(application\/pdf|image\/(png|jpe?g|gif|webp|heic)|application\/msword|application\/vnd\.openxmlformats-officedocument\.wordprocessingml\.document);base64,[A-Za-z0-9+/]+={0,2}$/;
const SELLER_FORM_DATA_MAX = 21 * 1024 * 1024; // matches the 15MB upload cap once base64-encoded
function cleanSellerForm(form, nowIso) {
  if (!form || typeof form !== 'object') return null;
  const name = String(form.name == null ? '' : form.name).trim().slice(0, 160);
  if (!name) return null;
  const key = String(form.key == null ? '' : form.key).trim();
  if (key) {
    if (!SELLER_FORM_KEY_RE.test(key)) return null;
    return { name, key, url: '', uploadedAt: String(form.uploadedAt || nowIso || '') };
  }
  const url = String(form.url == null ? '' : form.url).trim();
  if (!url || url.length > SELLER_FORM_DATA_MAX || !SELLER_FORM_DATA_RE.test(url)) return null;
  return { name, key: '', url, uploadedAt: String(form.uploadedAt || nowIso || '') };
}

// Why a sign-up submission falls short of the published criteria, in plain
// words, for the admissions log. Empty when the criteria are met.
function admissionShortfalls(checks) {
  const c = checks || {};
  const out = [];
  if (!c.maLicense) out.push('Massachusetts license number missing or not in a valid format');
  if (!c.maBrokerage) out.push('Licensed Massachusetts brokerage not provided');
  if (!c.termsAccepted) out.push('Licensure certification and Terms not accepted');
  return out;
}

// ── Seller consent recorded in AXESS ─────────────────────────────────────────
// The seller's authorization can be given three ways: an uploaded signed form,
// the owner's own consent recorded in AXESS, or the seller's consent through an
// emailed single-use link. The consent text below is what the seller agrees to;
// its version is stored with every consent record.
const CONSENT_TEXT_VERSION = 'v1-2026-11';
const CONSENT_TEXT = [
  'I authorize AXESS RE LLC to display and market this property on the AXESS agent-to-agent network as a non-MLS (delayed-listing) offering at the asking price shown above.',
  'This property is not currently listed in the MLS, and I direct that it be marketed through AXESS instead at this time.',
  'I understand that AXESS RE LLC is a software platform only. It is not a real estate broker, it is not a party to any sale, and it does not negotiate or hold any money.',
  'I may revoke this consent in writing at any time, and the listing will then be removed.'
];
const CONSENT_LINK_DAYS = 7;
const CONSENT_PATHS = ['owner_in_app', 'seller_link', 'uploaded_form'];
const CONSENT_PATH_LABELS = { owner_in_app: 'Owner consent in AXESS', seller_link: 'Seller consent by emailed link', uploaded_form: 'Uploaded signed form' };

// Material-change comparison: a consent covers one address and one asking price.
function consentAddrKey(a) { return String(a == null ? '' : a).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
function consentPriceKey(p) { const n = parseFloat(String(p == null ? '' : p).replace(/[^0-9.]/g, '')); return isFinite(n) ? String(Math.round(n * 100) / 100) : ''; }
// True when the recorded consent still covers the listing as it stands now.
function consentCovers(l) {
  const c = l && l.consent;
  if (!c || typeof c !== 'object' || c.revokedAt || !c.at || !String(c.name || '').trim()) return false;
  if (CONSENT_PATHS.indexOf(c.path) < 0 || c.path === 'uploaded_form') return false;
  return consentAddrKey(c.address) === consentAddrKey(l.address) && !!consentAddrKey(l.address)
    && consentPriceKey(c.price) === consentPriceKey(l.price) && !!consentPriceKey(l.price);
}
// True when a consent was recorded but the address or price has changed since.
function consentLapsed(l) {
  const c = l && l.consent;
  return !!(c && typeof c === 'object' && !c.revokedAt && c.path !== 'uploaded_form' && !consentCovers(l));
}
// A typed full name: at least two characters with a letter in it.
function consentNameOk(name) {
  const s = String(name == null ? '' : name).trim();
  return s.length >= 2 && s.length <= 120 && /[A-Za-z\u00C0-\u024F]/.test(s);
}

// A listing may be live (visible to other members) only with the seller's
// authorization on file: the seller-signed Non-MLS / delayed-listing form, or a
// consent recorded in AXESS that still covers the listing's address and asking
// price. A seller's revocation takes the listing down whichever path was used.
// Owner-loaded sample data is not a real property and has no seller, so it is
// exempt.
function listingAuthorized(l) {
  if (!l || typeof l !== 'object') return false;
  if (l.sample === true) return true;
  if (l.sellerRevokedAt) return false;
  return sellerFormOk(l.sellerForm) || consentCovers(l);
}

// MA license numbers are 4–12 digits. MA has no public verification API, so this
// is a format check; the registry check is recorded separately by an admin.
function licenseFormatOk(license) {
  const s = String(license == null ? '' : license).trim();
  const digits = s.replace(/\D/g, '');
  return digits.length >= 4 && digits.length <= 12 && !/^(n\/?a|none|test|unknown|pending)$/i.test(s);
}

// The published membership criteria, evaluated identically for every applicant.
// Returns each check plus whether all are met.
function admissionCriteria(a) {
  a = a || {};
  const checks = {
    maLicense: licenseFormatOk(a.license),
    maBrokerage: !!String(a.brokerage || '').trim() && isMassachusettsState(a.state),
    termsAccepted: a.attest === true,
    subscription: 'free_trial_then_published_rate'
  };
  return { checks, met: checks.maLicense && checks.maBrokerage && checks.termsAccepted };
}

module.exports = {
  FOUNDING_CAP,
  FOUNDING_RATE,
  STANDARD_RATE,
  TRIAL_DAYS,
  TERMINATION_CAUSES,
  CAUSE_LABELS,
  PRICE_BANDS,
  NEED_TIMELINES,
  NEED_TIMELINE_LABELS,
  MLS_ZONE_WARNING,
  COMP_RE,
  compensationHit,
  motivatedHit,
  fairHousingHit,
  FAIR_HOUSING_MSG,
  priceBandById,
  normalizePriceBand,
  normalizeTimeline,
  mlsZoneFor,
  isMassachusettsState,
  foundingForJoinOrder,
  trialEndsAt,
  validTerminationCause,
  sellerFormOk,
  cleanSellerForm,
  admissionShortfalls,
  listingAuthorized,
  CONSENT_TEXT_VERSION,
  CONSENT_TEXT,
  CONSENT_LINK_DAYS,
  CONSENT_PATHS,
  CONSENT_PATH_LABELS,
  consentAddrKey,
  consentPriceKey,
  consentCovers,
  consentLapsed,
  consentNameOk,
  licenseFormatOk,
  admissionCriteria
};
