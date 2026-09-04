# UniMarket, updated

This release was smoke-tested across the public pages and authenticated buyer, seller, admin, and superadmin flows.

- Buyer login routes to `/buyer`, seller login to `/seller`, and admin login to `/admin`.
- Orders support Buy now, payment/delivery status, receipt tracking, and private browser-GPS location tracking at `/order/<id>/track`.
- Make Offer is removed from the listing UI.
- Admin applications collect labelled full name, staff number, university, national ID, cover letter introduction, KRA PIN, and uploads.
- Universities use dropdowns, dashboards use the UniMarket black/gold/warm-paper styling, and authenticated pages use the sidebar shell.
- Reports support date ranges and buyer/transaction exports.
- The server reads Render's `PORT` and binds to `0.0.0.0`; `requirements.txt` is intentionally empty because the app uses Python's standard library.

Run locally with:

```bash
python server/main.py
```

Render commands:

```text
Build: pip install -r requirements.txt
Start: python server/main.py
```

M-Pesa/Daraja still requires the live OAuth, STK Push, and callback implementation plus Render environment variables before real payments can be used.

## Demo seed data

The included `seed_demo_data.py` creates 10 demo accounts and 40 listings, with 10 listings per seller. Every listing includes a description and a category image under `static/images/demo/`. Run `python seed_demo_data.py` after setting up a clean database. Demo accounts use the password `DemoPass123!`; seller emails end in `@demo.unimarket.test` and buyer emails end in `@demo.unimarket.test`.

## Superadmin document review

Superadmins can open the uploaded cover letter, national ID, and KRA PIN documents from each pending admin request in the Admin Console. Document access is routed through a superadmin-only endpoint, and direct upload URLs for admin-request documents are protected from non-superadmin users.

## University admin seller visibility

The Admin Console now includes a Seller Directory. A regular university admin sees seller contact and listing information only for sellers whose `users.university` matches the admin's own university. Superadmins retain the global seller view. Recent listings and the seller count on a regular university admin dashboard use the same university scope.

## Seller approval workflow

Seller signups create a pending seller request instead of granting selling access immediately. The request is routed by university, so a regular admin can approve or reject requests only for that admin's own university; superadmins can review all schools. Buyers only provide their name, phone number, email, and password during signup.

## M-Pesa production configuration

Set these Render environment variables from the same Safaricom Daraja production app and shortcode:

```text
MPESA_ENV=production
MPESA_CONSUMER_KEY=...
MPESA_CONSUMER_SECRET=...
MPESA_SHORTCODE=...
MPESA_PASSKEY=...
MPESA_TRANSACTION_TYPE=CustomerPayBillOnline
MPESA_CALLBACK_URL=https://your-domain.example/payment/mpesa/callback
```

Use `CustomerPayBillOnline` for a PayBill and `CustomerBuyGoodsOnline` for a Till. The callback URL must be public HTTPS and must be the exact URL configured for the production app. Payment is marked paid only after a successful callback or Safaricom status query, duplicate prompts are blocked while a request is in flight, and failed or reversed attempts remain retryable.
