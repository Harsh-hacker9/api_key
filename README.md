<<<<<<< HEAD
# api
=======
# Fair Adda Razorpay Backend

Minimal Node.js backend for Razorpay wallet deposits + withdraw requests.

## Setup
1. `cd backend/razorpay`
2. `npm install`
3. Copy `.env.example` to `.env` and fill:
   - `RZP_KEY_ID`, `RZP_KEY_SECRET`, `RZP_WEBHOOK_SECRET`
   - `FIREBASE_SERVICE_ACCOUNT` path to Firebase service account JSON (local dev)
   - `FIREBASE_SERVICE_ACCOUNT_JSON` for Vercel (paste JSON string)
   - `SMTP_*` values for Gmail SMTP (use App Password)
4. `npm run dev`

## Endpoints
- `POST /razorpay/create-order` (auth required)
  - body: `{ "amount": 100, "userId": "firebase_uid" }`
- `POST /razorpay/verify` (auth required)
  - body: `{ "orderId": "...", "paymentId": "...", "signature": "..." }`
- `POST /razorpay/webhook` (Razorpay webhook)
- `POST /wallet/withdraw` (auth required)
  - body: `{ "amount": 200, "method": "upi", "upiId": "name@bank" }`

## Vercel
1. Deploy `backend/razorpay` as its own project (Root Directory).
2. Add env vars in Vercel:
   - `RZP_KEY_ID`, `RZP_KEY_SECRET`, `RZP_WEBHOOK_SECRET`
   - `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
   - `FIREBASE_SERVICE_ACCOUNT_JSON` (paste the whole JSON content)
3. Update Flutter `PaymentConfig.baseUrl` to your Vercel URL.

## Firestore collections
- `razorpay_orders`
- `wallet_transactions`
- `withdraw_requests`
>>>>>>> 1bca7be (Razorpay backend)
