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


## Current payment mode

Because UniMarket does not yet have a PayBill or Business Till, checkout currently uses manual M-Pesa Send Money. Buyers submit the transaction code, and sellers verify and confirm it from their M-Pesa SMS or statement.


## Order confirmation

Buyers are redirected to a waiting page after submitting a Send Money transaction code. Sellers confirm submitted payments from Orders, after which the order is marked paid and the buyer receives an email confirmation when SMTP is configured.
