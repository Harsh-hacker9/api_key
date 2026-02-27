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
const PUSH_WORKER_INTERVAL_MS = Number(
  process.env.PUSH_WORKER_INTERVAL_MS || 15000
);
const PUSH_WORKER_BATCH_SIZE = Math.max(
  1,
  Number(process.env.PUSH_WORKER_BATCH_SIZE || 60)
);
const CRON_SECRET = (process.env.CRON_SECRET || '').toString().trim();
const NOTIFICATION_TZ_OFFSET_MINUTES = Number(
  process.env.NOTIFICATION_TZ_OFFSET_MINUTES || 330
);

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
if (!process.env.CRON_SECRET) {
  console.warn('[WARN] Missing CRON_SECRET, cron endpoints will reject requests');
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

const TEST_LOGIN_EMAIL = normalizeEmail(
  process.env.TEST_LOGIN_EMAIL || 'test@gmail.com'
);
const TEST_LOGIN_OTP = normalizeOtp(process.env.TEST_LOGIN_OTP || '123456');

function isTestLoginEmail(email) {
  return normalizeEmail(email) === TEST_LOGIN_EMAIL;
}

function isTestLoginOtp(email, otp) {
  return isTestLoginEmail(email) && normalizeOtp(otp) === TEST_LOGIN_OTP;
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

async function getAuthUserByEmail(email) {
  try {
    return await admin.auth().getUserByEmail(email);
  } catch (err) {
    if (err?.code === 'auth/user-not-found') {
      return null;
    }
    throw err;
  }
}

async function findUserProfileByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;

  const byLower = await db
    .collection('users')
    .where('emailLower', '==', normalized)
    .limit(1)
    .get();
  if (!byLower.empty) {
    return byLower.docs[0];
  }

  const byEmail = await db
    .collection('users')
    .where('email', '==', normalized)
    .limit(1)
    .get();
  if (!byEmail.empty) {
    return byEmail.docs[0];
  }

  return null;
}

async function ensureUserProfile(uid, email, options = {}) {
  const createIfMissing = options.createIfMissing !== false;
  const markRegistered = options.markRegistered === true;
  const ref = db.collection('users').doc(uid);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists && !createIfMissing) {
      throw buildHttpError(
        403,
        'User profile not found. Please register first.',
        'PROFILE_NOT_FOUND'
      );
    }
    const data = snap.data() || {};
    const update = {
      email,
      emailLower: email,
      authProvider: 'email_otp',
      'authProviders.emailOtp': true,
      lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    if (markRegistered && !data.registeredAt) {
      update.registeredAt = admin.firestore.FieldValue.serverTimestamp();
    }
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
    const modeInput = (req.body?.mode || '').toString().trim().toLowerCase();
    const mode = modeInput === 'signup' ? 'signup' : modeInput === 'login' ? 'login' : '';
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email' });
    }

    if (mode === 'login' && isTestLoginEmail(email)) {
      return res.json({
        success: true,
        message: 'OTP sent successfully',
        ttlSeconds: OTP_TTL_SECONDS,
        testMode: true,
      });
    }

    if (mode === 'login') {
      const userProfile = await findUserProfileByEmail(email);
      if (!userProfile) {
        return res.status(404).json({
          success: false,
          message: 'Please register first',
          code: 'USER_NOT_REGISTERED',
        });
      }
    } else if (mode === 'signup') {
      const userProfile = await findUserProfileByEmail(email);
      if (userProfile) {
        return res.status(409).json({
          success: false,
          message: 'Email already exists',
          code: 'EMAIL_ALREADY_EXISTS',
        });
      }
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
    const modeInput = (req.body?.mode || '').toString().trim().toLowerCase();
    const mode = modeInput === 'signup' ? 'signup' : 'login';
    const issueSession = legacyMode
      ? req.body?.issueSession === true
      : req.body?.issueSession !== false;
    const issueCustomToken = legacyMode
      ? req.body?.issueCustomToken === true
      : req.body?.issueCustomToken !== false;

    if (!email || !isValidEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }

    const isTestLogin = mode === 'login' && isTestLoginEmail(email);
    if (isTestLogin) {
      if (!isTestLoginOtp(email, otp)) {
        return res.status(401).json({
          success: false,
          message: 'Incorrect OTP. Please try again.',
          code: 'OTP_INVALID',
        });
      }
    } else {
      const verifyResult = await verifyOtpForEmail(email, otp);
      if (!verifyResult.ok) {
        return res.status(verifyResult.status).json({
          success: false,
          message: verifyResult.message,
          code: verifyResult.code,
        });
      }
    }

    let user;
    const profileDoc = await findUserProfileByEmail(email);
    const authUser = await getAuthUserByEmail(email);

    if (mode === 'login') {
      if (isTestLogin) {
        if (profileDoc && authUser && profileDoc.id !== authUser.uid) {
          return res.status(403).json({
            success: false,
            message: 'Account mismatch. Contact support.',
            code: 'ACCOUNT_UID_MISMATCH',
          });
        }

        if (profileDoc) {
          try {
            user = await admin.auth().getUser(profileDoc.id);
          } catch (err) {
            if (err?.code === 'auth/user-not-found') {
              user = await admin.auth().createUser({
                uid: profileDoc.id,
                email,
                emailVerified: true,
              });
            } else {
              throw err;
            }
          }
        } else {
          user = authUser || (await getOrCreateAuthUserByEmail(email));
        }

        await ensureUserProfile(user.uid, email, {
          createIfMissing: true,
          markRegistered: true,
        });
      } else {
        if (!profileDoc || !authUser) {
          return res.status(403).json({
            success: false,
            message: 'Please register first',
            code: 'USER_NOT_REGISTERED',
          });
        }
        if (profileDoc.id !== authUser.uid) {
          return res.status(403).json({
            success: false,
            message: 'Account mismatch. Contact support.',
            code: 'ACCOUNT_UID_MISMATCH',
          });
        }
        user = authUser;
        await ensureUserProfile(user.uid, email, { createIfMissing: false });
      }
    } else {
      if (profileDoc) {
        return res.status(409).json({
          success: false,
          message: 'Email already exists',
          code: 'EMAIL_ALREADY_EXISTS',
        });
      }
      user = authUser || (await getOrCreateAuthUserByEmail(email));
      await ensureUserProfile(user.uid, email, {
        createIfMissing: true,
        markRegistered: true,
      });
    }

    const response = {
      success: true,
      message: 'OTP verified',
      uid: user.uid,
      email,
      platform,
      mode,
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

function isStaffRoleValue(role) {
  const normalized = (role || '').toString().trim().toLowerCase();
  return (
    normalized === 'admin' ||
    normalized === 'owner' ||
    normalized === 'staff' ||
    normalized === 'creator'
  );
}

function toAmount(value) {
  if (value == null) return 0;
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
  const parsed = Number(
    value
      .toString()
      .replace(/[^0-9.\-]/g, '')
      .trim()
  );
  return Number.isFinite(parsed) ? parsed : 0;
}

function dateKeyAtOffset(offsetMinutes = NOTIFICATION_TZ_OFFSET_MINUTES) {
  const offset = Number.isFinite(Number(offsetMinutes))
    ? Number(offsetMinutes)
    : NOTIFICATION_TZ_OFFSET_MINUTES;
  const shifted = new Date(Date.now() + offset * 60 * 1000);
  return shifted.toISOString().slice(0, 10);
}

function requireCronAuth(req, res, next) {
  if (!CRON_SECRET) {
    return res.status(503).json({ error: 'CRON_SECRET not configured' });
  }
  const auth = (req.headers.authorization || '').toString().trim();
  const token = auth.toLowerCase().startsWith('bearer ')
    ? auth.slice('bearer '.length).trim()
    : '';
  if (token !== CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized cron request' });
  }
  return next();
}

async function enqueueUserInAppAndPush({
  userId,
  title,
  body,
  type,
  screen,
  data = {},
  inAppDocId = '',
  pushDocId = '',
  createdById = 'system',
  createdByRole = 'system',
}) {
  const uid = (userId || '').toString().trim();
  if (!uid) return false;

  const userNotifs = db.collection('users').doc(uid).collection('notifications');
  const inAppRef = inAppDocId.trim() ? userNotifs.doc(inAppDocId.trim()) : userNotifs.doc();
  const pushQueue = db.collection('push_notifications_queue');
  const pushRef = pushDocId.trim() ? pushQueue.doc(pushDocId.trim()) : pushQueue.doc();

  const payload = {
    ...data,
    userId: uid,
    title: (title || 'Notification').toString().trim() || 'Notification',
    body: (body || '').toString().trim(),
    type: (type || 'generic').toString().trim() || 'generic',
    createdById,
    createdByRole,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };

  const batch = db.batch();
  batch.set(
    inAppRef,
    {
      ...payload,
      isRead: false,
    },
    { merge: true }
  );
  batch.set(
    pushRef,
    {
      ...payload,
      screen: (screen || 'announcement').toString().trim() || 'announcement',
      status: 'pending',
    },
    { merge: true }
  );
  await batch.commit();
  return true;
}

async function flushPushQueueNow({ maxTicks = 8, batchSize = PUSH_WORKER_BATCH_SIZE } = {}) {
  let ticks = 0;
  const summary = { picked: 0, sent: 0, failed: 0 };
  while (ticks < Math.max(1, Number(maxTicks) || 1)) {
    const result = await processPendingPushQueue(batchSize);
    summary.picked += Number(result.picked || 0);
    summary.sent += Number(result.sent || 0);
    summary.failed += Number(result.failed || 0);
    ticks += 1;
    if (Number(result.picked || 0) <= 0) break;
  }
  return summary;
}

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

app.post('/notifications/push/flush', firebaseAuthMiddleware, async (req, res) => {
  try {
    const meSnap = await db.collection('users').doc(req.user.uid).get();
    const role = (meSnap.data()?.role || '').toString();
    if (!isStaffRoleValue(role)) {
      return res.status(403).json({ error: 'Only staff can process push queue' });
    }
    const size = Math.max(
      1,
      Math.min(200, Number(req.body?.batchSize || PUSH_WORKER_BATCH_SIZE) || PUSH_WORKER_BATCH_SIZE)
    );
    const result = await processPendingPushQueue(size);
    return res.json({ ok: true, ...result });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to process push queue' });
  }
});

app.post('/notifications/scratch-unlock/sync', firebaseAuthMiddleware, async (req, res) => {
  try {
    const uid = (req.user?.uid || '').toString().trim();
    if (!uid) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const leaguesSnap = await db
      .collection('user_leagues')
      .where('userId', '==', uid)
      .get();

    let completedCount = 0;
    for (const doc of leaguesSnap.docs) {
      const data = doc.data() || {};
      const status = (data.resultStatus || data.status || '').toString().trim().toLowerCase();
      if (status === 'completed') {
        completedCount += 1;
      }
    }

    const earnedCards = Math.floor(completedCount / 5);
    const userRef = db.collection('users').doc(uid);
    const txResult = await db.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      const userData = userSnap.data() || {};
      const scratch = userData.scratch && typeof userData.scratch === 'object' ? userData.scratch : {};
      const notifiedCount = Math.max(0, Number(scratch.unlockNotifiedCount || 0) || 0);

      if (earnedCards <= notifiedCount) {
        return {
          sent: false,
          earnedCards,
          notifiedCount,
          newUnlocks: 0,
        };
      }

      const newUnlocks = earnedCards - notifiedCount;
      const title = newUnlocks > 1 ? `${newUnlocks} Scratch Cards Unlocked` : 'Scratch Card Unlocked';
      const body =
        newUnlocks > 1
          ? `Great news! ${newUnlocks} new scratch cards are now available.`
          : 'Great news! A new scratch card is now available.';
      const inAppRef = userRef.collection('notifications').doc(`scratch_unlock_${earnedCards}`);
      const pushRef = db.collection('push_notifications_queue').doc(`scratch_unlock_${uid}_${earnedCards}`);

      tx.set(
        inAppRef,
        {
          userId: uid,
          title,
          body,
          type: 'scratch_unlocked',
          screen: 'scratch',
          isRead: false,
          unlockCount: newUnlocks,
          earnedCards,
          createdById: 'system',
          createdByRole: 'system',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
      tx.set(
        pushRef,
        {
          userId: uid,
          title,
          body,
          type: 'scratch_unlocked',
          screen: 'scratch',
          status: 'pending',
          unlockCount: newUnlocks,
          earnedCards,
          createdById: 'system',
          createdByRole: 'system',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
      tx.set(
        userRef,
        {
          'scratch.unlockNotifiedCount': earnedCards,
          'scratch.lastUnlockNotifiedAt': admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      return {
        sent: true,
        earnedCards,
        notifiedCount,
        newUnlocks,
      };
    });

    let pushResult = { picked: 0, sent: 0, failed: 0 };
    if (txResult.sent) {
      pushResult = await flushPushQueueNow({ maxTicks: 2, batchSize: PUSH_WORKER_BATCH_SIZE });
    }
    return res.json({
      ok: true,
      ...txResult,
      push: pushResult,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to sync scratch unlock notifications' });
  }
});

async function queueDailyCampaignNotifications({ dateKey }) {
  const normalizedDateKey = (dateKey || '').toString().trim();
  if (!normalizedDateKey) throw new Error('Missing date key for daily campaign');

  let scannedUsers = 0;
  let touchedUsers = 0;
  let queuedNotifications = 0;
  let cursor = null;

  for (;;) {
    let query = db
      .collection('users')
      .orderBy(admin.firestore.FieldPath.documentId())
      .limit(300);
    if (cursor) query = query.startAfter(cursor);
    const snap = await query.get();
    if (snap.empty) break;

    let batch = db.batch();
    let opCount = 0;
    const commitBatch = async () => {
      if (opCount === 0) return;
      await batch.commit();
      batch = db.batch();
      opCount = 0;
    };

    for (const doc of snap.docs) {
      scannedUsers += 1;
      const uid = doc.id;
      const data = doc.data() || {};
      const role = (data.role || 'user').toString().trim().toLowerCase();
      if (isStaffRoleValue(role)) continue;
      const status = (data.status || 'active').toString().trim().toLowerCase();
      if (status === 'banned' || data.isBanned === true) continue;

      const wallet = data.wallet && typeof data.wallet === 'object' ? data.wallet : {};
      const hasDeposit = toAmount(wallet.deposit) > 0;
      const notificationsMeta =
        data.notificationsMeta && typeof data.notificationsMeta === 'object'
          ? data.notificationsMeta
          : {};

      const alreadySentJoin =
        (notificationsMeta.dailyJoinPlayDate || '').toString() === normalizedDateKey;
      const alreadySentReferral =
        (notificationsMeta.dailyReferralDate || '').toString() === normalizedDateKey;
      const alreadySentComeback =
        (notificationsMeta.dailyComebackDate || '').toString() === normalizedDateKey;
      if (alreadySentJoin && alreadySentReferral && alreadySentComeback) continue;

      const userRef = db.collection('users').doc(uid);
      const userUpdates = {
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      let userTouched = false;

      const campaigns = [];
      if (!alreadySentJoin) {
        campaigns.push({
          id: hasDeposit ? 'daily_join_play' : 'daily_deposit_play',
          title: hasDeposit ? 'Join & Play Today' : 'Deposit & Join & Play Today',
          body: hasDeposit
            ? 'Fresh matches are waiting. Join now and win rewards.'
            : 'Top up wallet, join today matches, and win rewards.',
          screen: hasDeposit ? 'join_play' : 'wallet',
          metaKey: 'notificationsMeta.dailyJoinPlayDate',
        });
      }
      if (!alreadySentReferral) {
        campaigns.push({
          id: 'daily_referral',
          title: 'Refer & Earn',
          body: 'Invite friends to Fair Adda and earn referral rewards.',
          screen: 'referrals',
          metaKey: 'notificationsMeta.dailyReferralDate',
        });
      }
      if (!alreadySentComeback) {
        campaigns.push({
          id: 'daily_comeback',
          title: 'Come Back & Win',
          body: 'Daily tournaments are live. Come back now and play to win.',
          screen: 'join_play',
          metaKey: 'notificationsMeta.dailyComebackDate',
        });
      }

      for (const campaign of campaigns) {
        batch.set(
          db.collection('push_notifications_queue').doc(`${campaign.id}_${uid}_${normalizedDateKey}`),
          {
            userId: uid,
            title: campaign.title,
            body: campaign.body,
            type: campaign.id,
            screen: campaign.screen,
            status: 'pending',
            createdById: 'system',
            createdByRole: 'system',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
        opCount += 1;
        queuedNotifications += 1;
        userUpdates[campaign.metaKey] = normalizedDateKey;
        userTouched = true;
      }

      if (userTouched) {
        batch.set(userRef, userUpdates, { merge: true });
        opCount += 1;
        touchedUsers += 1;
      }

      if (opCount >= 360) await commitBatch();
    }

    await commitBatch();
    cursor = snap.docs[snap.docs.length - 1];
    if (snap.size < 300) break;
  }

  return {
    dateKey: normalizedDateKey,
    scannedUsers,
    touchedUsers,
    queuedNotifications,
  };
}
app.get('/notifications/push/worker/run', requireCronAuth, async (req, res) => {
  try {
    const batchSize = Math.max(
      1,
      Math.min(200, Number(req.query.batchSize || PUSH_WORKER_BATCH_SIZE) || PUSH_WORKER_BATCH_SIZE)
    );
    const maxTicks = Math.max(1, Math.min(25, Number(req.query.maxTicks || 4) || 4));
    const result = await flushPushQueueNow({ maxTicks, batchSize });
    return res.json({ ok: true, batchSize, maxTicks, ...result });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to run push worker' });
  }
});

app.get('/notifications/campaign/daily/run', requireCronAuth, async (req, res) => {
  try {
    const offset = Number(req.query.tzOffsetMinutes || NOTIFICATION_TZ_OFFSET_MINUTES);
    const dateKey = dateKeyAtOffset(offset);
    const queued = await queueDailyCampaignNotifications({ dateKey });
    const push = await flushPushQueueNow({ maxTicks: 20, batchSize: PUSH_WORKER_BATCH_SIZE });
    return res.json({
      ok: true,
      tzOffsetMinutes: offset,
      queued,
      push,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to run daily campaign notifications' });
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
    let requesterName = '';
    let requesterPhone = '';
    let requesterEmail = req.user.email || '';

    await db.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      const data = userSnap.data() || {};
      const wallet = data.wallet || {};
      const winning = Number(wallet.winning || 0);
      if (amount > winning) {
        throw new Error('INSUFFICIENT_WINNING');
      }
      requesterName = (data.name || data.username || '').toString().trim();
      requesterPhone = (data.phone || data.mobile || '').toString().trim();
      requesterEmail = (data.email || req.user.email || '').toString().trim();

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
        walletTxId: txRef.id,
        userName: requesterName,
        userEmail: requesterEmail,
        userPhone: requesterPhone,
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
        requestId: withdrawRef.id,
        userId: req.user.uid,
        type: 'withdraw_debit',
        status: 'pending',
        amount,
        source: 'withdraw',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    await queueWithdrawRequestAlerts({
      requestId: withdrawRef.id,
      userId: req.user.uid,
      userName: requesterName,
      userEmail: requesterEmail,
      userPhone: requesterPhone,
      amount,
      method,
      upiId,
      accountHolderName,
      bankAccountNumber,
      ifsc,
      bankName,
      branch,
    });

    await sendEmail({
      to: requesterEmail,
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

async function queueWithdrawRequestAlerts({
  requestId,
  userId,
  userName,
  userEmail,
  userPhone,
  amount,
  method,
  upiId,
  accountHolderName,
  bankAccountNumber,
  ifsc,
  bankName,
  branch,
}) {
  const staffSnap = await db
    .collection('users')
    .where('role', 'in', ['admin', 'owner', 'staff', 'creator'])
    .get();
  if (staffSnap.empty) return;

  const displayName = (userName || '').trim() || userId;
  const title = 'New Withdraw Request';
  const body = `${displayName} requested Rs ${Number(amount).toFixed(2)} via ${(
    method || 'upi'
  )
    .toString()
    .toUpperCase()}`;
  const methodLabel = (method || '').toString().trim().toLowerCase();

  let batch = db.batch();
  let count = 0;

  async function commitBatchIfNeeded(force = false) {
    if (!force && count < 380) return;
    if (count === 0) return;
    await batch.commit();
    batch = db.batch();
    count = 0;
  }

  for (const doc of staffSnap.docs) {
    const adminId = doc.id;
    if (!adminId) continue;

    const notifRef = db
      .collection('users')
      .doc(adminId)
      .collection('notifications')
      .doc();
    batch.set(notifRef, {
      userId: adminId,
      title,
      body,
      type: 'withdraw_request_admin',
      isRead: false,
      requestId,
      requestUserId: userId,
      requestUserName: userName || '',
      requestUserEmail: userEmail || '',
      requestUserPhone: userPhone || '',
      amount,
      method: methodLabel,
      upiId: upiId || '',
      accountHolderName: accountHolderName || '',
      bankAccountNumber: bankAccountNumber || '',
      ifsc: ifsc || '',
      bankName: bankName || '',
      branch: branch || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    count += 1;

    const pushRef = db.collection('push_notifications_queue').doc();
    batch.set(pushRef, {
      userId: adminId,
      title,
      body,
      type: 'withdraw_request_admin',
      screen: 'admin_wallet',
      status: 'pending',
      requestId,
      requestUserId: userId,
      requestUserName: userName || '',
      requestUserEmail: userEmail || '',
      requestUserPhone: userPhone || '',
      amount,
      method: methodLabel,
      upiId: upiId || '',
      accountHolderName: accountHolderName || '',
      bankAccountNumber: bankAccountNumber || '',
      ifsc: ifsc || '',
      bankName: bankName || '',
      branch: branch || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    count += 1;

    await commitBatchIfNeeded(false);
  }

  await commitBatchIfNeeded(true);
}

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

function normalizePushDataValue(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value.toString();
  }
  try {
    return JSON.stringify(value);
  } catch (_err) {
    return '';
  }
}

function extractPushData(payload) {
  const allowedKeys = [
    'type',
    'screen',
    'route',
    'matchId',
    'tournamentId',
    'chatId',
    'targetRole',
    'senderId',
    'senderRole',
    'senderName',
    'userId',
    'reason',
    'requestId',
    'requestUserId',
    'requestUserName',
    'requestUserEmail',
    'requestUserPhone',
    'amount',
    'method',
    'upiId',
    'accountHolderName',
    'bankAccountNumber',
    'ifsc',
    'bankName',
    'branch',
  ];
  const data = {};
  for (const key of allowedKeys) {
    if (!(key in payload)) continue;
    const value = normalizePushDataValue(payload[key]);
    if (!value) continue;
    data[key] = value;
  }
  if (!data.type) {
    data.type = 'generic';
  }
  return data;
}

function isInvalidRegistrationToken(errorCode) {
  const code = (errorCode || '').toString().toLowerCase();
  return (
    code.includes('registration-token-not-registered') ||
    code.includes('invalid-registration-token') ||
    code.includes('invalid-argument')
  );
}

async function processPendingPushQueue(batchSize = PUSH_WORKER_BATCH_SIZE) {
  const queueSnap = await db
    .collection('push_notifications_queue')
    .where('status', '==', 'pending')
    .limit(Math.max(1, Number(batchSize) || PUSH_WORKER_BATCH_SIZE))
    .get();

  if (queueSnap.empty) return { picked: 0, sent: 0, failed: 0 };

  let sent = 0;
  let failed = 0;

  for (const doc of queueSnap.docs) {
    const ref = doc.ref;
    const claimed = await db.runTransaction(async (tx) => {
      const fresh = await tx.get(ref);
      if (!fresh.exists) return false;
      const data = fresh.data() || {};
      const status = (data.status || 'pending').toString().toLowerCase();
      if (status !== 'pending') return false;
      tx.set(
        ref,
        {
          status: 'processing',
          processingAt: admin.firestore.FieldValue.serverTimestamp(),
          attempts: admin.firestore.FieldValue.increment(1),
        },
        { merge: true }
      );
      return true;
    });
    if (!claimed) continue;

    try {
      const freshSnap = await ref.get();
      const payload = freshSnap.data() || {};
      const userId = (payload.userId || '').toString().trim();
      const title = (payload.title || 'Notification').toString();
      const body = (payload.body || '').toString();

      const tokens = new Set();
      const directToken = (payload.fcmToken || '').toString().trim();
      if (directToken) tokens.add(directToken);

      let userSnap = null;
      let userData = {};
      if (userId) {
        userSnap = await db.collection('users').doc(userId).get();
        userData = userSnap.data() || {};
        const primary = (userData.fcmToken || '').toString().trim();
        if (primary) tokens.add(primary);
        if (Array.isArray(userData.fcmTokens)) {
          for (const value of userData.fcmTokens) {
            const token = (value || '').toString().trim();
            if (token) tokens.add(token);
          }
        }
      }

      const tokenList = Array.from(tokens);
      if (tokenList.length === 0) {
        await ref.set(
          {
            status: 'failed',
            errorCode: 'NO_FCM_TOKEN',
            errorMessage: 'No device token found for user',
            failedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
        failed += 1;
        continue;
      }

      const messageData = extractPushData(payload);
      const response = await admin.messaging().sendEachForMulticast({
        tokens: tokenList,
        notification: {
          title,
          body,
        },
        data: messageData,
        android: {
          priority: 'high',
          notification: {
            channelId: 'high_importance_channel',
            sound: 'default',
          },
        },
      });

      const invalidTokens = [];
      for (let i = 0; i < response.responses.length; i += 1) {
        const item = response.responses[i];
        if (item.success) continue;
        const code = item.error?.code || '';
        if (isInvalidRegistrationToken(code)) {
          invalidTokens.push(tokenList[i]);
        }
      }

      if (invalidTokens.length > 0 && userId) {
        const userRef = db.collection('users').doc(userId);
        await userRef.set(
          {
            fcmTokens: admin.firestore.FieldValue.arrayRemove(...invalidTokens),
            fcmTokenUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
        const primary = (userData.fcmToken || '').toString().trim();
        if (primary && invalidTokens.includes(primary)) {
          await userRef.set(
            {
              fcmToken: '',
              fcmTokenUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
        }
      }

      if (response.successCount > 0) {
        await ref.set(
          {
            status: 'sent',
            sentAt: admin.firestore.FieldValue.serverTimestamp(),
            sentCount: response.successCount,
            failCount: response.failureCount,
            invalidTokens,
          },
          { merge: true }
        );
        sent += 1;
      } else {
        await ref.set(
          {
            status: 'failed',
            failCount: response.failureCount,
            invalidTokens,
            failedAt: admin.firestore.FieldValue.serverTimestamp(),
            errorCode: response.responses[0]?.error?.code || 'FCM_SEND_FAILED',
            errorMessage:
              response.responses[0]?.error?.message || 'Unable to send notification',
          },
          { merge: true }
        );
        failed += 1;
      }
    } catch (err) {
      await ref.set(
        {
          status: 'failed',
          errorCode: err?.code || 'FCM_SEND_EXCEPTION',
          errorMessage: err?.message || 'Unknown push worker error',
          failedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
      failed += 1;
    }
  }

  return { picked: queueSnap.size, sent, failed };
}

let pushWorkerBusy = false;
let pushWorkerTimer = null;
let dailyCampaignBusy = false;
let dailyCampaignTimer = null;
let lastDailyCampaignDateKey = '';

async function runPushWorkerTick() {
  if (pushWorkerBusy) return;
  pushWorkerBusy = true;
  try {
    const result = await processPendingPushQueue(PUSH_WORKER_BATCH_SIZE);
    if (result.picked > 0) {
      console.log(
        `[push-worker] picked=${result.picked}, sent=${result.sent}, failed=${result.failed}`
      );
    }
  } catch (err) {
    console.error('[push-worker] tick failed', err);
  } finally {
    pushWorkerBusy = false;
  }
}

function startPushWorker() {
  if (pushWorkerTimer) return;
  pushWorkerTimer = setInterval(() => {
    runPushWorkerTick().catch((err) => {
      console.error('[push-worker] uncaught tick error', err);
    });
  }, PUSH_WORKER_INTERVAL_MS);
  runPushWorkerTick().catch((err) => {
    console.error('[push-worker] startup tick error', err);
  });
}

async function runDailyCampaignTick(force = false) {
  if (dailyCampaignBusy) return;
  const dateKey = dateKeyAtOffset(NOTIFICATION_TZ_OFFSET_MINUTES);
  if (!force && lastDailyCampaignDateKey === dateKey) return;

  dailyCampaignBusy = true;
  try {
    const queued = await queueDailyCampaignNotifications({ dateKey });
    const push = await flushPushQueueNow({ maxTicks: 20, batchSize: PUSH_WORKER_BATCH_SIZE });
    lastDailyCampaignDateKey = dateKey;
    if (queued.queuedNotifications > 0 || push.picked > 0) {
      console.log(
        `[daily-campaign] date=${dateKey}, users=${queued.touchedUsers}, queued=${queued.queuedNotifications}, pushSent=${push.sent}, pushFailed=${push.failed}`
      );
    }
  } catch (err) {
    console.error('[daily-campaign] tick failed', err);
  } finally {
    dailyCampaignBusy = false;
  }
}

function startDailyCampaignScheduler() {
  if (dailyCampaignTimer) return;
  dailyCampaignTimer = setInterval(() => {
    runDailyCampaignTick(false).catch((err) => {
      console.error('[daily-campaign] uncaught tick error', err);
    });
  }, 15 * 60 * 1000);
  runDailyCampaignTick(true).catch((err) => {
    console.error('[daily-campaign] startup tick error', err);
  });
}

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Razorpay backend running on port ${PORT}`);
    startPushWorker();
    startDailyCampaignScheduler();
  });
}

module.exports = app;


