require('dotenv').config();
const express = require('express');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const cors = require('cors');
const morgan = require('morgan');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 4242;
const RZP_KEY_ID = process.env.RZP_KEY_ID;
const RZP_KEY_SECRET = process.env.RZP_KEY_SECRET;
const RZP_WEBHOOK_SECRET = process.env.RZP_WEBHOOK_SECRET;
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT;
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const FIREBASE_SERVICE_ACCOUNT_JSON =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 300);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 6);
const OTP_RESEND_COOLDOWN_SECONDS = Number(
  process.env.OTP_RESEND_COOLDOWN_SECONDS || 45
);
const APP_NAME = process.env.APP_NAME || 'FairAdda';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || SMTP_USER || '';
const APP_BASE_URL = process.env.APP_BASE_URL || 'https://fairadda.com';
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 604800);
const SESSION_TOKEN_SECRET =
  process.env.SESSION_TOKEN_SECRET || RZP_KEY_SECRET || 'unsafe-session-secret';
const API_KEY_SECRET =
  process.env.API_KEY_SECRET || RZP_KEY_SECRET || 'unsafe-api-key-secret';
const API_KEY_DEFAULT_TTL_DAYS = Number(
  process.env.API_KEY_DEFAULT_TTL_DAYS || 365
);
const API_KEY_MAX_PER_USER = Number(process.env.API_KEY_MAX_PER_USER || 20);

if (!RZP_KEY_ID || !RZP_KEY_SECRET) {
  console.warn('[WARN] Missing Razorpay keys in .env');
}
if (!FIREBASE_SERVICE_ACCOUNT) {
  console.warn('[WARN] Missing FIREBASE_SERVICE_ACCOUNT path in .env');
}
if (!FIREBASE_SERVICE_ACCOUNT && !FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.warn('[WARN] Missing FIREBASE_SERVICE_ACCOUNT_JSON in .env');
}
if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
  console.warn('[WARN] Missing SMTP config in .env');
}
if (!process.env.SESSION_TOKEN_SECRET) {
  console.warn('[WARN] Missing SESSION_TOKEN_SECRET, using fallback secret');
}
if (!process.env.API_KEY_SECRET) {
  console.warn('[WARN] Missing API_KEY_SECRET, using fallback secret');
}

let serviceAccount = null;
if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  try {
    serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
  } catch (err) {
    console.warn('[WARN] Invalid FIREBASE_SERVICE_ACCOUNT_JSON');
  }
} else if (FIREBASE_SERVICE_ACCOUNT) {
  serviceAccount = require(FIREBASE_SERVICE_ACCOUNT);
}

admin.initializeApp({
  credential: serviceAccount
    ? admin.credential.cert(serviceAccount)
    : admin.credential.applicationDefault(),
});

const db = admin.firestore();
const razorpay = new Razorpay({
  key_id: RZP_KEY_ID,
  key_secret: RZP_KEY_SECRET,
});

const app = express();
app.use(cors());
app.use(morgan('tiny'));

const mailer =
  SMTP_HOST && SMTP_USER && SMTP_PASS
    ? nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
      })
    : null;

function normalizeEmail(value) {
  return (value || '').toString().trim().toLowerCase();
}

function normalizeOtp(value) {
  return (value || '').toString().replace(/\D/g, '').slice(0, 6);
}

function escapeHtml(value) {
  return (value || '')
    .toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildOtpEmailHtml({ otp, ttlMinutes, email }) {
  const safeOtp = escapeHtml(otp);
  const safeEmail = escapeHtml(email);
  const safeAppName = escapeHtml(APP_NAME);
  const safeSupport = escapeHtml(SUPPORT_EMAIL);
  const safeBase = escapeHtml(APP_BASE_URL);
  return `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${safeAppName} OTP</title>
  </head>
  <body style="margin:0;background:#0f1115;font-family:Arial,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:24px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#171a21;border:1px solid #2a3040;border-radius:12px;overflow:hidden;">
            <tr>
              <td style="padding:20px 24px;background:#d32f2f;color:#ffffff;font-size:20px;font-weight:700;">
                ${safeAppName}
              </td>
            </tr>
            <tr>
              <td style="padding:24px;color:#e8ebf1;">
                <p style="margin:0 0 12px;font-size:16px;">Verify your login</p>
                <p style="margin:0 0 16px;color:#bac0cf;font-size:14px;">
                  Use the OTP below to continue. This code is valid for ${ttlMinutes} minutes.
                </p>
                <div style="margin:16px 0;padding:14px 16px;background:#0f1115;border:1px dashed #3b4254;border-radius:8px;text-align:center;">
                  <span style="font-size:30px;letter-spacing:10px;font-weight:700;color:#ffffff;">${safeOtp}</span>
                </div>
                <p style="margin:0 0 16px;color:#98a1b3;font-size:12px;">
                  Requested for: ${safeEmail}
                </p>
                <p style="margin:0 0 16px;color:#98a1b3;font-size:12px;">
                  If you did not request this OTP, you can ignore this email.
                </p>
                <a href="${safeBase}" style="display:inline-block;background:#d32f2f;color:#fff;text-decoration:none;padding:10px 14px;border-radius:6px;font-size:13px;">Open ${safeAppName}</a>
              </td>
            </tr>
            <tr>
              <td style="padding:14px 24px;background:#11141b;color:#7f889a;font-size:12px;">
                Need help? Contact ${safeSupport}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

async function sendEmail({ to, subject, text, html }) {
  if (!mailer || !to) return;
  await mailer.sendMail({
    from: SMTP_FROM,
    replyTo: SUPPORT_EMAIL || undefined,
    to,
    subject,
    text,
    html,
    headers: {
      'X-Auto-Response-Suppress': 'OOF, AutoReply',
    },
  });
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableHash(value, secret) {
  return sha256Hex(`${secret}:${value}`);
}

function randomHex(byteLength = 16) {
  return crypto.randomBytes(byteLength).toString('hex');
}

function normalizePlatform(value, fallback = '') {
  const platform = (value || '').toString().trim().toLowerCase();
  if (platform === 'web' || platform === 'app' || platform === 'both') {
    return platform;
  }
  return fallback;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function otpDocId(email) {
  return crypto.createHash('md5').update(email).digest('hex');
}

function parseSessionToken(rawToken) {
  const token = (rawToken || '').toString().trim();
  const match = /^fa_sess_([a-f0-9]{32})\.([a-f0-9]{48})$/i.exec(token);
  if (!match) return null;
  return { sessionId: match[1], secret: match[2] };
}

function parseApiKey(rawKey) {
  const token = (rawKey || '').toString().trim();
  const match = /^fa_(?:live|test)_([a-f0-9]{12})_([a-f0-9]{48})$/i.exec(token);
  if (!match) return null;
  return { prefix: match[1], secret: match[2] };
}

function extractBearerToken(req) {
  const auth = (req.headers.authorization || '').toString();
  if (!auth.startsWith('Bearer ')) return '';
  return auth.slice('Bearer '.length).trim();
}

function extractApiKey(req) {
  const direct = (req.headers['x-api-key'] || '').toString().trim();
  if (direct) return direct;
  const auth = (req.headers.authorization || '').toString();
  if (auth.toLowerCase().startsWith('apikey ')) {
    return auth.slice('ApiKey '.length).trim();
  }
  return '';
}

function getClientIp(req) {
  const forwarded = (req.headers['x-forwarded-for'] || '').toString();
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return (
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    ''
  );
}

function getClientPlatform(req, fallback = '') {
  const headerPlatform = normalizePlatform(req.headers['x-client-platform']);
  if (headerPlatform) return headerPlatform;
  const bodyPlatform = normalizePlatform(req.body?.platform);
  if (bodyPlatform) return bodyPlatform;
  return normalizePlatform(fallback);
}

function platformMatches(savedPlatform, requestedPlatform) {
  const saved = normalizePlatform(savedPlatform, 'both');
  const requested = normalizePlatform(requestedPlatform);
  if (!requested) return true;
  if (saved === 'both') return true;
  return saved === requested;
}

function buildHttpError(status, message, code) {
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

async function sendOtpToEmail(email) {
  if (!mailer) {
    throw buildHttpError(500, 'SMTP not configured', 'SMTP_NOT_CONFIGURED');
  }

  const nowSec = nowSeconds();
  const docRef = db.collection('email_otps').doc(otpDocId(email));
  const existingSnap = await docRef.get();
  const existing = existingSnap.data() || {};
  const lastSentAt = Number(existing.last_sent_at_epoch || 0);
  if (lastSentAt > 0 && nowSec - lastSentAt < OTP_RESEND_COOLDOWN_SECONDS) {
    const retryAfterSeconds = OTP_RESEND_COOLDOWN_SECONDS - (nowSec - lastSentAt);
    const err = buildHttpError(
      429,
      `Please wait ${retryAfterSeconds}s before requesting OTP again`,
      'OTP_RATE_LIMIT'
    );
    err.retryAfterSeconds = retryAfterSeconds;
    throw err;
  }

  const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
  const otpHash = sha256Hex(otp);
  const expiresAt = nowSec + OTP_TTL_SECONDS;
  const existingHash = (existing.otp_hash || '').toString();
  const existingExpiry = Number(existing.expires_at || 0);
  const shouldKeepPrevious = existingHash.length > 0 && existingExpiry >= nowSec;

  await docRef.set(
    {
      email,
      otp_hash: otpHash,
      expires_at: expiresAt,
      otp_prev_hash: shouldKeepPrevious ? existingHash : '',
      otp_prev_expires_at: shouldKeepPrevious
        ? Math.min(existingExpiry, expiresAt)
        : 0,
      attempts: 0,
      max_attempts: OTP_MAX_ATTEMPTS,
      last_sent_at_epoch: nowSec,
      created_at_epoch: nowSec,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  const ttlMinutes = Math.max(1, Math.floor(OTP_TTL_SECONDS / 60));
  await sendEmail({
    to: email,
    subject: `${APP_NAME} verification code`,
    text:
      `${APP_NAME} OTP: ${otp}\n` +
      `Valid for ${ttlMinutes} minutes.\n` +
      `Requested for: ${email}\n` +
      `If this was not you, ignore this email.`,
    html: buildOtpEmailHtml({ otp, ttlMinutes, email }),
  });

  return { ttlMinutes };
}

async function verifyOtpForEmail(email, otp) {
  const docRef = db.collection('email_otps').doc(otpDocId(email));
  const snap = await docRef.get();
  if (!snap.exists) {
    return {
      ok: false,
      status: 401,
      message: 'OTP not found. Please resend OTP.',
      code: 'OTP_NOT_FOUND',
    };
  }

  const data = snap.data() || {};
  const nowSec = nowSeconds();
  const expiresAt = Number(data.expires_at || 0);
  if (expiresAt < nowSec) {
    await docRef.delete();
    return {
      ok: false,
      status: 401,
      message: 'OTP expired. Please resend OTP.',
      code: 'OTP_EXPIRED',
    };
  }

  const otpHash = sha256Hex(otp);
  const currentHash = (data.otp_hash || '').toString();
  const prevHash = (data.otp_prev_hash || '').toString();
  const prevExpiry = Number(data.otp_prev_expires_at || 0);
  const currentMatch = otpHash === currentHash;
  const previousMatch = otpHash === prevHash && prevExpiry >= nowSec;
  if (!currentMatch && !previousMatch) {
    const attempts = Number(data.attempts || 0) + 1;
    const maxAttempts = Number(data.max_attempts || OTP_MAX_ATTEMPTS);
    if (attempts >= maxAttempts) {
      await docRef.delete();
      return {
        ok: false,
        status: 429,
        message: 'Too many incorrect attempts. Please request a new OTP.',
        code: 'OTP_ATTEMPTS_EXCEEDED',
      };
    }
    await docRef.set(
      {
        attempts,
        last_failed_at_epoch: nowSec,
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return {
      ok: false,
      status: 401,
      message: 'Incorrect OTP. Please try again.',
      code: 'OTP_INVALID',
    };
  }

  await docRef.delete();
  return { ok: true };
}

async function getOrCreateAuthUserByEmail(email) {
  try {
    return await admin.auth().getUserByEmail(email);
  } catch (err) {
    if (err?.code === 'auth/user-not-found') {
      return admin.auth().createUser({ email, emailVerified: true });
    }
    throw err;
  }
}

async function ensureUserProfile(uid, email) {
  const ref = db.collection('users').doc(uid);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.data() || {};
    const update = {
      email,
      emailLower: email,
      authProvider: 'email_otp',
      'authProviders.emailOtp': true,
      lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    if (!data.role) {
      update.role = 'user';
    }
    if (!data.status) {
      update.status = 'active';
    }
    tx.set(ref, update, { merge: true });
  });
}

async function createSessionToken({
  uid,
  email,
  platform = 'app',
  userAgent = '',
  ip = '',
}) {
  const sessionId = randomHex(16);
  const sessionSecret = randomHex(24);
  const token = `fa_sess_${sessionId}.${sessionSecret}`;
  const nowSec = nowSeconds();
  const expiresAtEpoch = nowSec + Math.max(60, SESSION_TTL_SECONDS);

  await db
    .collection('auth_sessions')
    .doc(sessionId)
    .set({
      uid,
      email: email || '',
      platform: normalizePlatform(platform, 'app'),
      session_secret_hash: stableHash(sessionSecret, SESSION_TOKEN_SECRET),
      created_at_epoch: nowSec,
      expires_at_epoch: expiresAtEpoch,
      last_used_at_epoch: nowSec,
      revoked: false,
      revoked_at_epoch: 0,
      user_agent: (userAgent || '').toString().slice(0, 300),
      ip: (ip || '').toString().slice(0, 120),
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    });

  return { token, sessionId, expiresAtEpoch };
}

async function validateSessionToken(rawToken, requiredPlatform = '') {
  const parsed = parseSessionToken(rawToken);
  if (!parsed) {
    throw buildHttpError(401, 'Invalid session token format', 'SESSION_FORMAT');
  }

  const docRef = db.collection('auth_sessions').doc(parsed.sessionId);
  const snap = await docRef.get();
  if (!snap.exists) {
    throw buildHttpError(401, 'Session not found', 'SESSION_NOT_FOUND');
  }

  const data = snap.data() || {};
  const expectedHash = (data.session_secret_hash || '').toString();
  const providedHash = stableHash(parsed.secret, SESSION_TOKEN_SECRET);
  if (!expectedHash || expectedHash !== providedHash) {
    throw buildHttpError(401, 'Invalid session token', 'SESSION_HASH_MISMATCH');
  }

  if (data.revoked === true) {
    throw buildHttpError(401, 'Session revoked', 'SESSION_REVOKED');
  }

  const nowSec = nowSeconds();
  const expiresAtEpoch = Number(data.expires_at_epoch || 0);
  if (!expiresAtEpoch || expiresAtEpoch < nowSec) {
    await docRef.set(
      {
        revoked: true,
        revoked_at_epoch: nowSec,
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    throw buildHttpError(401, 'Session expired', 'SESSION_EXPIRED');
  }

  const savedPlatform = normalizePlatform(data.platform, 'app');
  if (!platformMatches(savedPlatform, requiredPlatform)) {
    throw buildHttpError(
      403,
      `Session is not valid for ${requiredPlatform} client`,
      'SESSION_PLATFORM_MISMATCH'
    );
  }

  await docRef.set(
    {
      last_used_at_epoch: nowSec,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  return {
    sessionId: parsed.sessionId,
    uid: (data.uid || '').toString(),
    email: (data.email || '').toString(),
    platform: savedPlatform,
    expiresAtEpoch,
  };
}

async function revokeSessionToken(rawToken) {
  const parsed = parseSessionToken(rawToken);
  if (!parsed) return;
  await db
    .collection('auth_sessions')
    .doc(parsed.sessionId)
    .set(
      {
        revoked: true,
        revoked_at_epoch: nowSeconds(),
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
}

function buildApiKeyMaterial() {
  const prefix = randomHex(6);
  const secret = randomHex(24);
  const apiKey = `fa_live_${prefix}_${secret}`;
  const keyHash = stableHash(`${prefix}.${secret}`, API_KEY_SECRET);
  return { apiKey, prefix, keyHash };
}

async function createUserApiKey({
  uid,
  name,
  platform = 'both',
  scopes = [],
  expiresInDays = API_KEY_DEFAULT_TTL_DAYS,
}) {
  const safeName = (name || 'API Key').toString().trim().slice(0, 80);
  const safePlatform = normalizePlatform(platform, 'both');
  const safeScopes = Array.isArray(scopes)
    ? scopes
        .map((s) => (s || '').toString().trim().toLowerCase())
        .filter(Boolean)
        .slice(0, 20)
    : [];

  const currentSnap = await db
    .collection('user_api_keys')
    .where('userId', '==', uid)
    .get();
  const activeCount = currentSnap.docs.filter((doc) => {
    const data = doc.data() || {};
    return (data.status || 'active') === 'active';
  }).length;
  if (activeCount >= API_KEY_MAX_PER_USER) {
    throw buildHttpError(
      400,
      `Active API key limit reached (${API_KEY_MAX_PER_USER})`,
      'API_KEY_LIMIT'
    );
  }

  const ttlDays = Math.max(1, Math.min(3650, Number(expiresInDays) || API_KEY_DEFAULT_TTL_DAYS));
  const nowSec = nowSeconds();
  const expiresAtEpoch = nowSec + ttlDays * 24 * 60 * 60;
  const { apiKey, prefix, keyHash } = buildApiKeyMaterial();
  const ref = db.collection('user_api_keys').doc();
  await ref.set({
    userId: uid,
    name: safeName,
    platform: safePlatform,
    scopes: safeScopes,
    status: 'active',
    prefix,
    key_hash: keyHash,
    created_at_epoch: nowSec,
    updated_at_epoch: nowSec,
    expires_at_epoch: expiresAtEpoch,
    last_used_at_epoch: 0,
    revoked_at_epoch: 0,
    created_at: admin.firestore.FieldValue.serverTimestamp(),
    updated_at: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {
    id: ref.id,
    apiKey,
    prefix,
    name: safeName,
    platform: safePlatform,
    scopes: safeScopes,
    expiresAtEpoch,
  };
}

async function listUserApiKeys(uid) {
  const snap = await db.collection('user_api_keys').where('userId', '==', uid).get();
  return snap.docs
    .map((doc) => {
      const data = doc.data() || {};
      return {
        id: doc.id,
        name: (data.name || '').toString(),
        platform: normalizePlatform(data.platform, 'both'),
        scopes: Array.isArray(data.scopes) ? data.scopes : [],
        status: (data.status || 'active').toString(),
        prefix: (data.prefix || '').toString(),
        createdAtEpoch: Number(data.created_at_epoch || 0),
        expiresAtEpoch: Number(data.expires_at_epoch || 0),
        lastUsedAtEpoch: Number(data.last_used_at_epoch || 0),
      };
    })
    .sort((a, b) => b.createdAtEpoch - a.createdAtEpoch);
}

async function verifyUserApiKey(rawKey, requiredPlatform = '') {
  const parsed = parseApiKey(rawKey);
  if (!parsed) {
    throw buildHttpError(401, 'Invalid API key format', 'API_KEY_FORMAT');
  }

  const snap = await db
    .collection('user_api_keys')
    .where('prefix', '==', parsed.prefix)
    .limit(10)
    .get();
  if (snap.empty) {
    throw buildHttpError(401, 'API key not found', 'API_KEY_NOT_FOUND');
  }

  const providedHash = stableHash(`${parsed.prefix}.${parsed.secret}`, API_KEY_SECRET);
  const nowSec = nowSeconds();
  for (const doc of snap.docs) {
    const data = doc.data() || {};
    if ((data.key_hash || '').toString() !== providedHash) continue;
    if ((data.status || 'active') !== 'active') {
      throw buildHttpError(401, 'API key revoked', 'API_KEY_REVOKED');
    }
    const expiresAtEpoch = Number(data.expires_at_epoch || 0);
    if (expiresAtEpoch > 0 && expiresAtEpoch < nowSec) {
      throw buildHttpError(401, 'API key expired', 'API_KEY_EXPIRED');
    }
    const savedPlatform = normalizePlatform(data.platform, 'both');
    if (!platformMatches(savedPlatform, requiredPlatform)) {
      throw buildHttpError(
        403,
        `API key is not valid for ${requiredPlatform} client`,
        'API_KEY_PLATFORM_MISMATCH'
      );
    }

    await doc.ref.set(
      {
        last_used_at_epoch: nowSec,
        updated_at_epoch: nowSec,
        updated_at: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return {
      id: doc.id,
      userId: (data.userId || '').toString(),
      platform: savedPlatform,
      scopes: Array.isArray(data.scopes) ? data.scopes : [],
      prefix: parsed.prefix,
    };
  }

  throw buildHttpError(401, 'Invalid API key', 'API_KEY_INVALID');
}

async function revokeUserApiKey(uid, keyId) {
  const ref = db.collection('user_api_keys').doc(keyId);
  const snap = await ref.get();
  if (!snap.exists) {
    throw buildHttpError(404, 'API key not found', 'API_KEY_NOT_FOUND');
  }
  const data = snap.data() || {};
  if ((data.userId || '').toString() !== uid) {
    throw buildHttpError(403, 'API key does not belong to user', 'API_KEY_OWNERSHIP');
  }
  await ref.set(
    {
      status: 'revoked',
      revoked_at_epoch: nowSeconds(),
      updated_at_epoch: nowSeconds(),
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
}

async function rotateUserApiKey(uid, keyId, expiresInDays = API_KEY_DEFAULT_TTL_DAYS) {
  const ref = db.collection('user_api_keys').doc(keyId);
  const snap = await ref.get();
  if (!snap.exists) {
    throw buildHttpError(404, 'API key not found', 'API_KEY_NOT_FOUND');
  }
  const data = snap.data() || {};
  if ((data.userId || '').toString() !== uid) {
    throw buildHttpError(403, 'API key does not belong to user', 'API_KEY_OWNERSHIP');
  }

  const ttlDays = Math.max(1, Math.min(3650, Number(expiresInDays) || API_KEY_DEFAULT_TTL_DAYS));
  const nowSec = nowSeconds();
  const expiresAtEpoch = nowSec + ttlDays * 24 * 60 * 60;
  const { apiKey, prefix, keyHash } = buildApiKeyMaterial();
  await ref.set(
    {
      status: 'active',
      prefix,
      key_hash: keyHash,
      expires_at_epoch: expiresAtEpoch,
      revoked_at_epoch: 0,
      updated_at_epoch: nowSec,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  return { apiKey, prefix, expiresAtEpoch };
}

function requireAuth({
  allowFirebase = true,
  allowSession = true,
  allowApiKey = false,
  requiredPlatform = '',
} = {}) {
  return async (req, res, next) => {
    try {
      const requestedPlatform = getClientPlatform(req, requiredPlatform);
      const bearer = extractBearerToken(req);
      if (bearer) {
        if (bearer.startsWith('fa_sess_')) {
          if (!allowSession) {
            return res.status(401).json({ error: 'Session auth not allowed' });
          }
          const session = await validateSessionToken(bearer, requestedPlatform);
          req.user = {
            uid: session.uid,
            email: session.email,
            authType: 'session',
            platform: session.platform,
            sessionId: session.sessionId,
          };
          return next();
        }

        if (!allowFirebase) {
          return res.status(401).json({ error: 'Firebase auth not allowed' });
        }
        const decoded = await admin.auth().verifyIdToken(bearer);
        req.user = {
          uid: decoded.uid,
          email: decoded.email || '',
          authType: 'firebase',
          platform: requestedPlatform || 'app',
          claims: decoded,
        };
        return next();
      }

      if (allowApiKey) {
        const rawKey = extractApiKey(req);
        if (rawKey) {
          const keyData = await verifyUserApiKey(rawKey, requestedPlatform);
          req.user = {
            uid: keyData.userId,
            authType: 'api_key',
            platform: keyData.platform,
            keyId: keyData.id,
            scopes: keyData.scopes,
          };
          return next();
        }
      }

      return res.status(401).json({ error: 'Missing auth token or API key' });
    } catch (err) {
      const status = Number(err?.status || 401);
      return res.status(status).json({
        error: err?.message || 'Invalid authentication credentials',
        code: err?.code || 'AUTH_ERROR',
      });
    }
  };
}

// Webhook needs raw body
app.post(
  '/razorpay/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    try {
      const signature = req.headers['x-razorpay-signature'];
      if (!signature || !RZP_WEBHOOK_SECRET) {
        return res.status(400).send('Missing signature/secret');
      }
      const expected = crypto
        .createHmac('sha256', RZP_WEBHOOK_SECRET)
        .update(req.body)
        .digest('hex');
      if (expected !== signature) {
        return res.status(400).send('Invalid signature');
      }

      const payload = JSON.parse(req.body.toString());
      if (payload.event === 'payment.captured') {
        const payment = payload.payload?.payment?.entity;
        const orderId = payment?.order_id;
        const paymentId = payment?.id;
        if (orderId && paymentId) {
          await finalizeOrderPayment({
            orderId,
            paymentId,
            signature: 'webhook',
          });
        }
      }
      return res.json({ ok: true });
    } catch (err) {
      console.error(err);
      return res.status(500).send('Webhook error');
    }
  }
);

app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

async function sendOtpHandler(req, res) {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email' });
    }

    await sendOtpToEmail(email);
    return res.json({
      success: true,
      message: 'OTP sent successfully',
      ttlSeconds: OTP_TTL_SECONDS,
    });
  } catch (err) {
    const status = Number(err?.status || 500);
    const payload = {
      success: false,
      message: err?.message || 'Email send failed',
      code: err?.code || 'OTP_SEND_FAILED',
    };
    if (err?.retryAfterSeconds) {
      payload.retryAfterSeconds = err.retryAfterSeconds;
    }
    return res.status(status).json(payload);
  }
}

async function verifyOtpHandler(req, res, options = {}) {
  try {
    const legacyMode = options.legacyMode === true;
    const email = normalizeEmail(req.body?.email);
    const otp = normalizeOtp(req.body?.otp);
    const platform = getClientPlatform(req, 'app');
    const issueSession = legacyMode
      ? req.body?.issueSession === true
      : req.body?.issueSession !== false;
    const issueCustomToken = legacyMode
      ? req.body?.issueCustomToken === true
      : req.body?.issueCustomToken !== false;

    if (!email || !isValidEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }

    const verifyResult = await verifyOtpForEmail(email, otp);
    if (!verifyResult.ok) {
      return res.status(verifyResult.status).json({
        success: false,
        message: verifyResult.message,
        code: verifyResult.code,
      });
    }

    const user = await getOrCreateAuthUserByEmail(email);
    await ensureUserProfile(user.uid, email);
    const response = {
      success: true,
      message: 'OTP verified',
      uid: user.uid,
      email,
      platform,
    };

    if (issueCustomToken) {
      response.customToken = await admin.auth().createCustomToken(user.uid, {
        auth_method: 'email_otp',
        platform,
      });
    }

    if (issueSession) {
      const session = await createSessionToken({
        uid: user.uid,
        email,
        platform,
        userAgent: req.headers['user-agent'],
        ip: getClientIp(req),
      });
      response.sessionToken = session.token;
      response.sessionExpiresAtEpoch = session.expiresAtEpoch;
      response.sessionTtlSeconds = Math.max(60, SESSION_TTL_SECONDS);
    }

    return res.json(response);
  } catch (err) {
    console.error(err);
    const status = Number(err?.status || 500);
    return res.status(status).json({
      success: false,
      message: err?.message || 'OTP verification failed',
      code: err?.code || 'OTP_VERIFY_FAILED',
    });
  }
}

app.post('/send_otp.php', sendOtpHandler);
app.post('/auth/otp/send', sendOtpHandler);

app.post('/verify_otp.php', (req, res) =>
  verifyOtpHandler(req, res, { legacyMode: true })
);
app.post('/auth/otp/verify', verifyOtpHandler);

const userAuthMiddleware = requireAuth({
  allowFirebase: true,
  allowSession: true,
  allowApiKey: false,
});

const integrationAuthMiddleware = requireAuth({
  allowFirebase: true,
  allowSession: true,
  allowApiKey: true,
});

const firebaseAuthMiddleware = requireAuth({
  allowFirebase: true,
  allowSession: false,
  allowApiKey: false,
});

app.get('/auth/me', integrationAuthMiddleware, async (req, res) => {
  try {
    const userSnap = await db.collection('users').doc(req.user.uid).get();
    const userData = userSnap.data() || {};
    return res.json({
      success: true,
      user: {
        uid: req.user.uid,
        email: req.user.email || (userData.email || '').toString(),
        role: (userData.role || 'user').toString(),
        status: (userData.status || 'active').toString(),
      },
      auth: {
        type: req.user.authType,
        platform: req.user.platform || null,
        sessionId: req.user.sessionId || null,
        keyId: req.user.keyId || null,
        scopes: Array.isArray(req.user.scopes) ? req.user.scopes : [],
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: 'Failed to fetch profile' });
  }
});

app.post(
  '/auth/session/refresh',
  requireAuth({ allowFirebase: false, allowSession: true, allowApiKey: false }),
  async (req, res) => {
    try {
      const currentToken = extractBearerToken(req);
      const activeSession = await validateSessionToken(currentToken);
      await revokeSessionToken(currentToken);
      const newSession = await createSessionToken({
        uid: activeSession.uid,
        email: activeSession.email,
        platform: activeSession.platform,
        userAgent: req.headers['user-agent'],
        ip: getClientIp(req),
      });

      return res.json({
        success: true,
        sessionToken: newSession.token,
        sessionExpiresAtEpoch: newSession.expiresAtEpoch,
        sessionTtlSeconds: Math.max(60, SESSION_TTL_SECONDS),
      });
    } catch (err) {
      const status = Number(err?.status || 401);
      return res.status(status).json({
        success: false,
        error: err?.message || 'Session refresh failed',
      });
    }
  }
);

app.post(
  '/auth/session/logout',
  requireAuth({ allowFirebase: false, allowSession: true, allowApiKey: false }),
  async (req, res) => {
    try {
      await revokeSessionToken(extractBearerToken(req));
      return res.json({ success: true });
    } catch (err) {
      const status = Number(err?.status || 401);
      return res.status(status).json({
        success: false,
        error: err?.message || 'Session logout failed',
      });
    }
  }
);

app.get(['/api-keys', '/v1/api-keys'], userAuthMiddleware, async (req, res) => {
  try {
    const keys = await listUserApiKeys(req.user.uid);
    return res.json({ success: true, keys });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: 'Failed to list API keys' });
  }
});

app.post(['/api-keys', '/v1/api-keys'], userAuthMiddleware, async (req, res) => {
  try {
    const result = await createUserApiKey({
      uid: req.user.uid,
      name: req.body?.name,
      platform: getClientPlatform(req, 'both'),
      scopes: req.body?.scopes,
      expiresInDays: req.body?.expiresInDays,
    });
    return res.status(201).json({
      success: true,
      key: {
        id: result.id,
        name: result.name,
        prefix: result.prefix,
        platform: result.platform,
        scopes: result.scopes,
        expiresAtEpoch: result.expiresAtEpoch,
      },
      apiKey: result.apiKey,
      message: 'Store this API key securely; it will not be shown again.',
    });
  } catch (err) {
    const status = Number(err?.status || 400);
    return res.status(status).json({
      success: false,
      error: err?.message || 'Failed to create API key',
      code: err?.code || 'API_KEY_CREATE_FAILED',
    });
  }
});

app.post('/api-keys/:id/rotate', userAuthMiddleware, async (req, res) => {
  try {
    const rotated = await rotateUserApiKey(
      req.user.uid,
      req.params.id,
      req.body?.expiresInDays
    );
    return res.json({
      success: true,
      keyId: req.params.id,
      prefix: rotated.prefix,
      expiresAtEpoch: rotated.expiresAtEpoch,
      apiKey: rotated.apiKey,
      message: 'Old key secret is invalidated immediately.',
    });
  } catch (err) {
    const status = Number(err?.status || 400);
    return res.status(status).json({
      success: false,
      error: err?.message || 'Failed to rotate API key',
      code: err?.code || 'API_KEY_ROTATE_FAILED',
    });
  }
});

app.post('/api-keys/:id/revoke', userAuthMiddleware, async (req, res) => {
  try {
    await revokeUserApiKey(req.user.uid, req.params.id);
    return res.json({ success: true });
  } catch (err) {
    const status = Number(err?.status || 400);
    return res.status(status).json({
      success: false,
      error: err?.message || 'Failed to revoke API key',
      code: err?.code || 'API_KEY_REVOKE_FAILED',
    });
  }
});

app.delete('/api-keys/:id', userAuthMiddleware, async (req, res) => {
  try {
    await revokeUserApiKey(req.user.uid, req.params.id);
    return res.json({ success: true });
  } catch (err) {
    const status = Number(err?.status || 400);
    return res.status(status).json({
      success: false,
      error: err?.message || 'Failed to delete API key',
      code: err?.code || 'API_KEY_DELETE_FAILED',
    });
  }
});

app.get(
  '/v1/integrations/whoami',
  requireAuth({ allowFirebase: false, allowSession: false, allowApiKey: true }),
  async (req, res) => {
    return res.json({
      success: true,
      integration: {
        uid: req.user.uid,
        keyId: req.user.keyId,
        platform: req.user.platform,
        scopes: req.user.scopes || [],
      },
    });
  }
);

app.post('/razorpay/create-order', firebaseAuthMiddleware, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    const amountPaise = Math.round(amount * 100);

    const receiptSource = `${req.user.uid}_${Date.now()}`;
    const receipt =
      'wa_' +
      crypto.createHash('sha1').update(receiptSource).digest('hex').slice(0, 32);
    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt,
      payment_capture: 1,
      notes: { uid: req.user.uid },
    });

    await db.collection('razorpay_orders').doc(order.id).set({
      userId: req.user.uid,
      amount,
      amountPaise,
      currency: 'INR',
      status: 'created',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({
      orderId: order.id,
      keyId: RZP_KEY_ID,
      amount: amountPaise,
      currency: 'INR',
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to create order' });
  }
});

app.post('/razorpay/verify', firebaseAuthMiddleware, async (req, res) => {
  try {
    const { orderId, paymentId, signature } = req.body || {};
    if (!orderId || !paymentId || !signature) {
      return res.status(400).json({ error: 'Missing payment fields' });
    }
    const expected = crypto
      .createHmac('sha256', RZP_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');
    if (expected !== signature) {
      return res.status(400).json({ error: 'Invalid signature' });
    }

    await finalizeOrderPayment({
      orderId,
      paymentId,
      signature,
      userEmail: req.user.email,
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/wallet/withdraw', firebaseAuthMiddleware, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = (req.body.method || 'upi').toString();
    const upiId = (req.body.upiId || '').toString().trim();
    const accountHolderName = (req.body.accountHolderName || '')
      .toString()
      .trim();
    const bankAccountNumber = (req.body.bankAccountNumber || '')
      .toString()
      .trim();
    const ifsc = (req.body.ifsc || '').toString().trim().toUpperCase();
    const bankName = (req.body.bankName || '').toString().trim();
    const branch = (req.body.branch || '').toString().trim();

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (method === 'upi' && !upiId) {
      return res.status(400).json({ error: 'UPI ID required' });
    }

    const userRef = db.collection('users').doc(req.user.uid);
    const withdrawRef = db.collection('withdraw_requests').doc();
    const txRef = db.collection('wallet_transactions').doc();

    await db.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      const data = userSnap.data() || {};
      const wallet = data.wallet || {};
      const winning = Number(wallet.winning || 0);
      if (amount > winning) {
        throw new Error('INSUFFICIENT_WINNING');
      }

      tx.update(userRef, {
        'wallet.winning': admin.firestore.FieldValue.increment(-amount),
        'wallet.total': admin.firestore.FieldValue.increment(-amount),
      });

      const withdrawPayload = {
        userId: req.user.uid,
        amount,
        method,
        upiId,
        status: 'pending',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      if (accountHolderName) {
        withdrawPayload.accountHolderName = accountHolderName;
      }
      if (method === 'bank') {
        if (bankAccountNumber) {
          withdrawPayload.bankAccountNumber = bankAccountNumber;
        }
        if (ifsc) {
          withdrawPayload.ifsc = ifsc;
        }
        if (bankName) {
          withdrawPayload.bankName = bankName;
        }
        if (branch) {
          withdrawPayload.branch = branch;
        }
      }

      tx.set(withdrawRef, withdrawPayload);

      tx.set(txRef, {
        userId: req.user.uid,
        type: 'debit',
        status: 'pending',
        amount,
        source: 'withdraw',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    await sendEmail({
      to: req.user.email,
      subject: 'Withdraw request received',
      text: `We received your withdraw request of Rs ${amount}. Status: pending.`,
    });

    return res.json({ ok: true });
  } catch (err) {
    if (err.message === 'INSUFFICIENT_WINNING') {
      return res.status(400).json({ error: 'Insufficient winning balance' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Withdraw failed' });
  }
});

async function finalizeOrderPayment({
  orderId,
  paymentId,
  signature,
  userEmail,
}) {
  const orderRef = db.collection('razorpay_orders').doc(orderId);
  const txRef = db.collection('wallet_transactions').doc();
  let creditedAmount = 0;

  await db.runTransaction(async (tx) => {
    const orderSnap = await tx.get(orderRef);
    if (!orderSnap.exists) {
      throw new Error('ORDER_NOT_FOUND');
    }
    const order = orderSnap.data();
    if (order.status === 'paid') {
      return;
    }

    const amount = Number(order.amount || 0);
    const userId = order.userId;
    const userRef = db.collection('users').doc(userId);
    creditedAmount = amount;

    tx.update(orderRef, {
      status: 'paid',
      paymentId,
      signature,
      paidAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    tx.update(userRef, {
      'wallet.deposit': admin.firestore.FieldValue.increment(amount),
      'wallet.total': admin.firestore.FieldValue.increment(amount),
    });

    tx.set(txRef, {
      userId,
      type: 'credit',
      status: 'success',
      amount,
      source: 'razorpay',
      reference: { orderId, paymentId },
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await sendEmail({
    to: userEmail,
    subject: 'Deposit successful',
    text: `Your wallet has been credited with Rs ${creditedAmount}. Order: ${orderId}.`,
  });
}

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Razorpay backend running on port ${PORT}`);
  });
}

module.exports = app;
