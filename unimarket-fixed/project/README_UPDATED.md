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
