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

async function sendEmail({ to, subject, text }) {
  if (!mailer || !to) return;
  await mailer.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    text,
  });
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

app.post('/send_otp.php', async (req, res) => {
  try {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email' });
    }
    if (!mailer) {
      return res
        .status(500)
        .json({ success: false, message: 'SMTP not configured' });
    }

    const otp = String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
    const expiresAt = Math.floor(Date.now() / 1000) + OTP_TTL_SECONDS;
    const docId = crypto.createHash('md5').update(email).digest('hex');

    await db.collection('email_otps').doc(docId).set({
      email,
      otp_hash: otpHash,
      expires_at: expiresAt,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    await sendEmail({
      to: email,
      subject: 'Your FairAdda OTP',
      text: `Your OTP is: ${otp}\nThis OTP will expire in 5 minutes.`,
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ success: false, message: 'Email send failed' });
  }
});

app.post('/verify_otp.php', async (req, res) => {
  try {
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    const otp = (req.body?.otp || '').toString().trim();
    if (
      !email ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !/^\d{6}$/.test(otp)
    ) {
      return res.status(400).json({ success: false, message: 'Invalid input' });
    }

    const docId = crypto.createHash('md5').update(email).digest('hex');
    const docRef = db.collection('email_otps').doc(docId);
    const snap = await docRef.get();
    if (!snap.exists) {
      return res
        .status(401)
        .json({ success: false, message: 'Invalid or expired OTP' });
    }

    const data = snap.data() || {};
    const expiresAt = Number(data.expires_at || 0);
    if (expiresAt < Math.floor(Date.now() / 1000)) {
      await docRef.delete();
      return res
        .status(401)
        .json({ success: false, message: 'Invalid or expired OTP' });
    }

    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
    if (otpHash !== data.otp_hash) {
      return res
        .status(401)
        .json({ success: false, message: 'Invalid or expired OTP' });
    }

    await docRef.delete();
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res
      .status(401)
      .json({ success: false, message: 'Invalid or expired OTP' });
  }
});

async function authMiddleware(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing auth token' });
    }
    const token = auth.replace('Bearer ', '');
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid auth token' });
  }
}

app.post('/razorpay/create-order', authMiddleware, async (req, res) => {
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

app.post('/razorpay/verify', authMiddleware, async (req, res) => {
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

app.post('/wallet/withdraw', authMiddleware, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = (req.body.method || 'upi').toString();
    const upiId = (req.body.upiId || '').toString().trim();

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

      tx.set(withdrawRef, {
        userId: req.user.uid,
        amount,
        method,
        upiId,
        status: 'pending',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

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
