// Shared product-compliance helpers for a Massachusetts-only, flat-subscription
// licensed-agent network. No transaction-money fields. No invented legal copy.

'use strict';

const FOUNDING_CAP = Number(process.env.PM_FOUNDING_CAP || 100);
const FOUNDING_RATE = Number(process.env.PM_PRICE_FOUNDING || 25);
const STANDARD_RATE = Number(process.env.PM_PRICE_STANDARD || 50);
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

// A listing may be live (visible to other members) only with the seller-signed
// Non-MLS / delayed-listing form on file. Owner-loaded sample data is not a real
// property and has no seller, so it is exempt.
function listingAuthorized(l) {
  if (!l || typeof l !== 'object') return false;
  return l.sample === true || sellerFormOk(l.sellerForm);
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
  priceBandById,
  normalizePriceBand,
  normalizeTimeline,
  mlsZoneFor,
  isMassachusettsState,
  foundingForJoinOrder,
  trialEndsAt,
  validTerminationCause,
  sellerFormOk,
  listingAuthorized,
  licenseFormatOk,
  admissionCriteria
};
