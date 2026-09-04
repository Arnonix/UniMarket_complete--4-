# UniMarket

UniMarket is a framework-free marketplace for university students. Students can buy and sell textbooks, gadgets, fashion, tickets, and services across their universities.

## Run

```powershell
python server/main.py
```

Open `http://127.0.0.1:8080`.

## Demo Accounts

- Admin: `admin@unimarket.test` / `admin12345`
- Superadmin: `superadmin@unimarket.test` / `SuperAdmin2026!`
- Seller: `seller@unimarket.test` / `student12345`

## Features

- Buyer and seller registration and login
- University and faculty profiles
- Listings with categories, photos, search, filtering, and editing
- Seller Hub for listings, buyer messages, and offers
- Wishlist, reviews, reports, and admin moderation

## Access and payments

Seller signups now create a pending request routed to the admin for the seller's own university. Buyers only enter their name, phone number, email, and password at signup. For M-Pesa production, configure `MPESA_ENV`, `MPESA_CONSUMER_KEY`, `MPESA_CONSUMER_SECRET`, `MPESA_SHORTCODE`, `MPESA_PASSKEY`, `MPESA_TRANSACTION_TYPE` (`CustomerPayBillOnline` for PayBill or `CustomerBuyGoodsOnline` for Till), and a public HTTPS `MPESA_CALLBACK_URL` from the same Daraja app. Payments are confirmed from Safaricom callbacks or a status query, not from the initial STK response.
