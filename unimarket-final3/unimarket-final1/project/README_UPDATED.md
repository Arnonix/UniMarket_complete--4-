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


## Temporary manual Send Money checkout

Until the marketplace has a PayBill or Business Till, checkout uses M-Pesa Send Money. The buyer sees the seller's registered phone number and order amount, sends the money from the M-Pesa app, and submits the transaction code. The seller must check their own M-Pesa SMS or statement and confirm the payment; buyers cannot mark their own order as paid.

The Daraja STK Push integration remains available for later activation, but its button is not shown in checkout while the marketplace is using manual Send Money.
