import base64
import html
import json
import mimetypes
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import defaultdict
from email import policy
from email.mime.text import MIMEText
from email.parser import BytesParser
from hashlib import pbkdf2_hmac
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DATABASE = ROOT / "database"
UPLOADS = ROOT / "uploads"
STATIC = ROOT / "static"
SCHEMA = DATABASE / "schema.sql"
DB = DATABASE / "unimarket.sqlite3"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
CATEGORIES = [
    "Textbooks and Notes",
    "Electronics and Gadgets",
    "Clothes and Accessories",
    "Event Tickets",
    "Services",
]
UNIVERSITIES = [
    "University of Nairobi", "Kenyatta University",
    "Jomo Kenyatta University of Agriculture and Technology", "Strathmore University",
    "Moi University", "Egerton University", "Maseno University",
    "Technical University of Kenya", "United States International University - Africa",
    "Catholic University of Eastern Africa", "Other university",
]

# ---------------------------------------------------------------------------
# Email config — set SMTP_* env vars in production; falls back to console dev mode
# ---------------------------------------------------------------------------
import os
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@unimarket.test")
APP_BASE_URL = os.environ.get("APP_BASE_URL", f"http://127.0.0.1:{PORT}")

# ---------------------------------------------------------------------------
# CSRF — per-session token stored in a signed cookie
# ---------------------------------------------------------------------------
_CSRF_COOKIE = "um_csrf"

def _csrf_token_for(req):
    """Return the CSRF token from the request cookie, creating one if absent."""
    return req.cookies.get(_CSRF_COOKIE) or secrets.token_urlsafe(32)

def _set_csrf_cookie(resp, token):
    """Attach the CSRF cookie to a response (non-HttpOnly so JS can read if needed)."""
    resp.headers["Set-Cookie-CSRF"] = (
        f"{_CSRF_COOKIE}={token}; SameSite=Strict; Path=/; Max-Age={86400 * 14}"
    )
    return resp

def csrf_input(req):
    """Return a hidden <input> carrying the CSRF token for the current request."""
    return f'<input type="hidden" name="_csrf" value="{esc(_csrf_token_for(req))}">'

def validate_csrf(req):
    """Return True if the POST body's _csrf field matches the cookie."""
    # parse_form handles both ordinary and multipart forms, including listing
    # submissions that contain photo uploads.
    fields, _ = parse_form(req)
    submitted = fields.get("_csrf", "")
    cookie_token = req.cookies.get(_CSRF_COOKIE, "")
    if not submitted or not cookie_token:
        return False
    return secrets.compare_digest(submitted, cookie_token)

def csrf_protected(req):
    """Return an error Response if CSRF validation fails, else None."""
    if req.method != "POST":
        return None
    if not validate_csrf(req):
        return Response(
            '<h1>Request Forbidden</h1><p>CSRF token invalid. Please go back and try again.</p>',
            403,
        )
    return None

# ---------------------------------------------------------------------------
# Rate limiter — in-memory sliding-window per IP
# ---------------------------------------------------------------------------
_rl_lock = threading.Lock()
_rl_buckets: dict = defaultdict(list)   # key -> [timestamp, ...]

# (max_requests, window_seconds)
_RL_RULES = {
    "login":    (5, 60),
    "register": (3, 60),
    "message":  (15, 60),
    "offer":    (10, 60),
    "report":   (5, 60),
    "review":   (5, 60),
    "bump":     (3, 60),
}

def _client_ip(req):
    return (
        req.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or req.headers.get("x-real-ip", "")
        or "unknown"
    )

def rate_limited(req, bucket):
    """Return True if this IP has exceeded the limit for the given bucket."""
    max_req, window = _RL_RULES.get(bucket, (30, 60))
    key = f"{bucket}:{_client_ip(req)}"
    cutoff = time.time() - window
    with _rl_lock:
        hits = _rl_buckets[key]
        hits[:] = [t for t in hits if t > cutoff]
        if len(hits) >= max_req:
            return True
        hits.append(time.time())
        return False

def rate_limit_response():
    return Response(
        '<section class="auth-panel"><p class="eyebrow">Slow down</p>'
        '<h1>Too many requests</h1>'
        '<p class="muted">You\'re doing that too fast. Please wait a minute and try again.</p>'
        '<a class="button-link" href="/">Go home</a></section>',
        429,
    )

def ensure_dirs():
    DATABASE.mkdir(exist_ok=True)
    UPLOADS.mkdir(exist_ok=True)
    STATIC.mkdir(exist_ok=True)
    (STATIC / "css").mkdir(exist_ok=True)
    (STATIC / "js").mkdir(exist_ok=True)
    (STATIC / "images").mkdir(exist_ok=True)
    (STATIC / "pages").mkdir(exist_ok=True)


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now():
    return int(time.time())


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)

def university_options(selected=""):
    return "".join(f'<option value="{esc(name)}" {"selected" if name == selected else ""}>{esc(name)}</option>' for name in UNIVERSITIES)

def labelize_fields(markup):
    pattern = re.compile(r"<(input|textarea)\b([^>]*?)\splaceholder=([\"'])(.*?)\3([^>]*)>", re.I | re.S)
    def repl(match):
        tag, attrs, label, tail = match.group(1), match.group(2), match.group(4), match.group(5)
        combined = attrs + tail
        if re.search(r"\btype=[\"']hidden[\"]", combined, re.I):
            return match.group(0)
        field = re.search(r"\b(?:id|name)=[\"']([^\"']+)", combined, re.I)
        if not field:
            return f"<{tag}{attrs}{tail}>"
        ident = field.group(1)
        if not re.search(r"\bid=[\"']", combined, re.I):
            tail = f' id="{esc(ident)}"' + tail
        label_text = re.sub(r"\s*\((?:optional|e.g\.[^)]*)\)", "", label, flags=re.I).strip()
        return f'<label class="field-label" for="{esc(ident)}">{esc(label_text)}</label><{tag}{attrs}{tail}>'
    return pattern.sub(repl, markup)


def clamp(value, max_len):
    """Truncate a string to max_len characters."""
    return str(value)[:max_len]


def money(value):
    return f"KES {float(value):,.0f}"


def stat_card(icon, value, label, accent="amber", href=None):
    """One TailAdmin-style stat card: coloured icon badge + number + label.
    Cycles through a small accent palette; the site's core colour scheme
    (nav/buttons/links) is untouched — only these badges use the accents."""
    inner = f'<span class="stat-icon icon-{accent}">{icon}</span><div class="stat-card-body"><strong>{value}</strong><span>{esc(label)}</span></div>'
    if href:
        return f'<div class="stat-card"><a class="stat-card-link" href="{esc(href)}">{inner}</a></div>'
    return f'<div class="stat-card">{inner}</div>'


# ---------------------------------------------------------------------------
# Lightweight server-rendered SVG charts for the admin console — no
# external JS charting library. The page's CSP only allows scripts from
# 'self', so a CDN-hosted chart library (as this file used to reference)
# would be silently blocked by the browser; these are plain inline SVG,
# so they render unconditionally with no script/network dependency at all.
# ---------------------------------------------------------------------------
_CHART_COLOURS = ["#d6a21e", "#9a6f08", "#b42318", "#6f6a5d", "#4a90d9", "#2f5245"]


def svg_donut_chart(labels, values, width=220, height=220):
    total = sum(values)
    if not total:
        return '<p class="muted">Not enough data yet.</p>'
    cx, cy, r = width / 2, height / 2, min(width, height) / 2 - 14
    circumference = 2 * 3.14159265 * r
    offset = 0
    segs, legend = [], []
    for i, (label, v) in enumerate(zip(labels, values)):
        if v <= 0:
            continue
        frac = v / total
        seg_len = frac * circumference
        colour = _CHART_COLOURS[i % len(_CHART_COLOURS)]
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{colour}" stroke-width="26" '
            f'stroke-dasharray="{seg_len:.1f} {circumference - seg_len:.1f}" '
            f'stroke-dashoffset="{-offset:.1f}" transform="rotate(-90 {cx} {cy})">'
            f'<title>{esc(label)}: {v}</title></circle>'
        )
        offset += seg_len
        legend.append(
            f'<li><span class="chart-swatch" style="background:{colour}"></span>{esc(label)} '
            f'<span class="muted">({v})</span></li>'
        )
    svg = (
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Breakdown chart">'
        + "".join(segs)
        + f'<text x="{cx}" y="{cy}" text-anchor="middle" font-size="20" font-weight="800" fill="var(--ink)">{total}</text>'
        + "</svg>"
    )
    return f'<div class="donut-wrap">{svg}<ul class="chart-legend">{"".join(legend)}</ul></div>'


def svg_line_chart(labels, values, width=520, height=180):
    if not values or len(values) < 2 or not any(values):
        return '<p class="muted">Not enough data yet.</p>'
    pad_l, pad_r, pad_t, pad_b = 8, 8, 16, 24
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    max_v = max(values) or 1
    step = plot_w / (len(values) - 1)
    pts = [(pad_l + i * step, pad_t + plot_h - (v / max_v) * plot_h) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = line + f" {pts[-1][0]:.1f},{pad_t+plot_h:.1f} {pts[0][0]:.1f},{pad_t+plot_h:.1f}"
    stride = max(1, len(labels) // 6)
    label_ticks = "".join(
        f'<text x="{pts[i][0]:.1f}" y="{height-4}" text-anchor="middle" font-size="10" fill="var(--muted)">{esc(labels[i])}</text>'
        for i in range(0, len(labels), stride)
    )
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="var(--gold-dark)"><title>{esc(labels[i])}: {values[i]}</title></circle>'
        for i, (x, y) in enumerate(pts)
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Trend chart">'
        f'<polygon points="{area}" fill="rgba(214,162,30,.14)"></polygon>'
        f'<polyline points="{line}" fill="none" stroke="var(--gold-dark)" stroke-width="2.5"></polyline>'
        f'{dots}{label_ticks}</svg>'
    )


def svg_bar_chart(labels, values, width=520, height=200):
    if not values or not any(values):
        return '<p class="muted">Not enough data yet.</p>'
    pad_l, pad_r, pad_t, pad_b = 8, 8, 20, 24
    plot_w, plot_h = width - pad_l - pad_r, height - pad_t - pad_b
    max_v = max(values) or 1
    n = len(values)
    gap = 10
    bar_w = max(8, (plot_w - gap * (n - 1)) / n)
    bars = []
    stride = max(1, n // 8)
    for i, (label, v) in enumerate(zip(labels, values)):
        x = pad_l + i * (bar_w + gap)
        bh = (v / max_v) * plot_h
        y = pad_t + (plot_h - bh)
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bh:.1f}" rx="2" fill="var(--gold-dark)">'
            f'<title>{esc(label)}: {v}</title></rect>'
        )
        if i % stride == 0:
            bars.append(
                f'<text x="{x + bar_w/2:.1f}" y="{height-4}" text-anchor="middle" font-size="10" fill="var(--muted)">{esc(label)}</text>'
            )
    return f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Bar chart">{"".join(bars)}</svg>'


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return "pbkdf2_sha256$260000$" + salt.hex() + "$" + digest.hex()


def password_ok(password, stored):
    try:
        alg, rounds, salt, digest = stored.split("$")
        if alg != "pbkdf2_sha256":
            return False
        test = pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return secrets.compare_digest(test, digest)
    except Exception:
        return False


def password_error(password):
    """Return a clear policy error, or an empty string for an acceptable password."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    return ""


# ---------------------------------------------------------------------------
# Email sending — prints to console when SMTP is not configured (dev mode)
# ---------------------------------------------------------------------------
def send_email(to_addr, subject, body_text):
    if not SMTP_HOST:
        print(f"\n[DEV EMAIL] To: {to_addr}\nSubject: {subject}\n{body_text}\n")
        return
    msg = MIMEText(body_text, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_FROM, [to_addr], msg.as_bytes())
    except Exception as exc:
        print(f"[EMAIL ERROR] {exc}")



def validate_phone(phone):
    """Validate and normalize a Kenyan phone number.
    Accepts: 07XXXXXXXX, 01XXXXXXXX, +2547XXXXXXXX, +2541XXXXXXXX,
             2547XXXXXXXX, 2541XXXXXXXX.
    Returns (normalized_phone, error_message)."""
    phone = phone.strip().replace(" ", "").replace("-", "")
    if not phone:
        return "", "Phone number is required."
    # Accepted formats:
    #   0[71]XXXXXXXX  (10 digits, local)
    #   +254[71]XXXXXXXX (13 chars)
    #   254[71]XXXXXXXX  (12 digits, no plus)
    if re.match(r"^0[17]\d{8}$", phone):
        phone = "+254" + phone[1:]
    elif re.match(r"^\+254[17]\d{8}$", phone):
        pass  # already correct
    elif re.match(r"^254[17]\d{8}$", phone):
        phone = "+" + phone
    else:
        return "", "Enter a valid Kenyan phone number (e.g. 0712345678 or +254712345678)."
    return phone, ""

OTP_TTL = 600  # 10 minutes
OTP_MAX_ATTEMPTS = 5


def generate_otp():
    """Generate a 6-digit numeric OTP."""
    return f"{secrets.randbelow(900000) + 100000}"


def send_verification_email(to_addr, token):
    link = f"{APP_BASE_URL}/verify/{token}"
    send_email(
        to_addr,
        "Verify your UniMarket email",
        f"Welcome to UniMarket!\n\nClick the link below to verify your email address:\n\n{link}\n\nThis link expires in 24 hours.\n\nIf you did not create an account, ignore this message.",
    )


def send_otp_email(to_addr, otp_code, user_name=""):
    """Send a 6-digit OTP verification code by email."""
    greeting = f"Hi {user_name},\n\n" if user_name else ""
    send_email(
        to_addr,
        f"UniMarket verification code: {otp_code}",
        f"{greeting}Your UniMarket email verification code is:\n\n"
        f"    {otp_code}\n\n"
        f"Enter this code on the verification page to confirm your email.\n"
        f"This code expires in 10 minutes.\n\n"
        f"If you did not create a UniMarket account, please ignore this email.",
    )


def send_message_notification(to_addr, sender_name, listing_title, conv_id):
    link = f"{APP_BASE_URL}/conversation/{conv_id}"
    send_email(
        to_addr,
        f"New message from {sender_name} on UniMarket",
        f"{sender_name} sent you a message about \"{listing_title}\".\n\nReply here: {link}",
    )


def send_payment_confirmation_email(to_addr, buyer_name, order_id, listing_title, amount):
    send_email(
        to_addr,
        f"UniMarket payment confirmed for order #{order_id:05d}",
        f"Hi {buyer_name},\n\n"
        f"The seller has confirmed your payment for {listing_title}.\n"
        f"Amount: {money(amount)}\n"
        f"Order: #UM-{order_id:05d}\n\n"
        f"You can view the order here: {APP_BASE_URL}/orders\n",
    )


def send_alert_email(to_addr, label, listing_title, listing_id, category):
    link = f"{APP_BASE_URL}/listing/{listing_id}"
    send_email(
        to_addr,
        f"New UniMarket listing matches your alert \"{label}\"",
        f"A new listing matching your saved alert \"{label}\" was just posted.\n\n"
        f"{listing_title}\nCategory: {category}\n\nView it here: {link}\n\n"
        f"Manage your alerts: {APP_BASE_URL}/alerts",
    )


# ---------------------------------------------------------------------------
# Database init & migration
# ---------------------------------------------------------------------------
def init_db():
    ensure_dirs()
    with db() as conn:
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))

        # Safe migrations for existing databases
        user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "university" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN university TEXT DEFAULT ''")
        if "email_verified" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
        if "verify_token" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN verify_token TEXT DEFAULT ''")
        if "otp_code" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN otp_code TEXT DEFAULT ''")
        if "otp_expires_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN otp_expires_at INTEGER NOT NULL DEFAULT 0")
        if "otp_attempts" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN otp_attempts INTEGER NOT NULL DEFAULT 0")
        if "failed_logins" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0")
        if "locked_until" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0")
        if "is_superadmin" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_superadmin INTEGER NOT NULL DEFAULT 0")
        if "seller_status" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN seller_status TEXT NOT NULL DEFAULT 'none'")

        msg_cols = {row["name"] for row in conn.execute("PRAGMA table_info(messages)")}
        if "conversation_id" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE")
        if "is_read" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0")

        listing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(listings)")}
        if "bump_count" not in listing_cols:
            conn.execute("ALTER TABLE listings ADD COLUMN bump_count INTEGER NOT NULL DEFAULT 0")
        if "bumped_at" not in listing_cols:
            conn.execute("ALTER TABLE listings ADD COLUMN bumped_at INTEGER NOT NULL DEFAULT 0")
        if "expires_at" not in listing_cols:
            conn.execute("ALTER TABLE listings ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0")
            # Backfill: existing active listings expire 60 days from creation
            conn.execute(
                "UPDATE listings SET expires_at = created_at + 5184000 WHERE status='active' AND expires_at=0"
            )
        if "view_count" not in listing_cols:
            conn.execute("ALTER TABLE listings ADD COLUMN view_count INTEGER NOT NULL DEFAULT 0")

        offer_cols = {row["name"] for row in conn.execute("PRAGMA table_info(offers)")}
        if "expires_at" not in offer_cols:
            conn.execute("ALTER TABLE offers ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                "UPDATE offers SET expires_at = created_at + 604800 WHERE status='pending' AND expires_at=0"
            )
        if "counter_price" not in offer_cols:
            conn.execute("ALTER TABLE offers ADD COLUMN counter_price REAL NOT NULL DEFAULT 0")
        if "counter_note" not in offer_cols:
            conn.execute("ALTER TABLE offers ADD COLUMN counter_note TEXT DEFAULT ''")

        user_cols2 = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "profile_image_path" not in user_cols2:
            conn.execute("ALTER TABLE users ADD COLUMN profile_image_path TEXT DEFAULT ''")
        if "suspended" not in user_cols2:
            conn.execute("ALTER TABLE users ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0")
        if "suspend_reason" not in user_cols2:
            conn.execute("ALTER TABLE users ADD COLUMN suspend_reason TEXT DEFAULT ''")

        conn.execute(
            """CREATE TABLE IF NOT EXISTS listing_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
                image_path TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )"""
        )

        # recently_viewed — safe CREATE (schema handles IF NOT EXISTS)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS recently_viewed (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
                viewed_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, listing_id)
            )"""
        )

        # Admin request documents and marketplace operations migrations.
        admin_req_cols = {row["name"] for row in conn.execute("PRAGMA table_info(admin_requests)")}
        for col, definition in (("university", "TEXT NOT NULL DEFAULT ''"), ("cover_letter_path", "TEXT DEFAULT ''"), ("national_id_path", "TEXT DEFAULT ''"), ("kra_pin", "TEXT DEFAULT ''")):
            if col not in admin_req_cols:
                conn.execute(f"ALTER TABLE admin_requests ADD COLUMN {col} {definition}")
        conn.execute("""CREATE TABLE IF NOT EXISTS seller_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            university TEXT NOT NULL,
            identifier_type TEXT NOT NULL DEFAULT 'admission_number',
            identifier_number TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
            reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            reviewed_at INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        )""")
        seller_req_cols = {row["name"] for row in conn.execute("PRAGMA table_info(seller_requests)")}
        for col, definition in (("identifier_type", "TEXT NOT NULL DEFAULT 'admission_number'"), ("identifier_number", "TEXT NOT NULL DEFAULT ''")):
            if col not in seller_req_cols:
                conn.execute(f"ALTER TABLE seller_requests ADD COLUMN {col} {definition}")
        conn.execute("""CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, listing_id INTEGER NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
            buyer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount REAL NOT NULL, payment_status TEXT NOT NULL DEFAULT 'pending', seller_order_status TEXT NOT NULL DEFAULT 'pending', delivery_status TEXT NOT NULL DEFAULT 'awaiting_payment',
            payment_method TEXT NOT NULL DEFAULT 'manual_send_money', sdk_push_status TEXT NOT NULL DEFAULT 'not_started', tracking_note TEXT DEFAULT '', created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL, received_at INTEGER NOT NULL DEFAULT 0, receipt_code TEXT DEFAULT '', payment_note TEXT DEFAULT '',
            payment_submitted_at INTEGER NOT NULL DEFAULT 0, payment_confirmed_at INTEGER NOT NULL DEFAULT 0, payment_rejected_reason TEXT DEFAULT '')""")
        conn.execute("""CREATE TABLE IF NOT EXISTS report_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, requested_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            report_scope TEXT NOT NULL DEFAULT 'transactions', admin_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            period_from TEXT DEFAULT '', period_to TEXT DEFAULT '', format TEXT NOT NULL DEFAULT 'csv', created_at INTEGER NOT NULL)""")
        order_cols = {row["name"] for row in conn.execute("PRAGMA table_info(orders)")}
        for col, definition in (("seller_order_status", "TEXT NOT NULL DEFAULT 'pending'"), ("payment_method", "TEXT NOT NULL DEFAULT 'manual_send_money'"), ("receipt_code", "TEXT DEFAULT ''"), ("payment_note", "TEXT DEFAULT ''"), ("payment_submitted_at", "INTEGER NOT NULL DEFAULT 0"), ("payment_confirmed_at", "INTEGER NOT NULL DEFAULT 0"), ("payment_rejected_reason", "TEXT DEFAULT ''"), ("latitude", "REAL"), ("longitude", "REAL"), ("location_label", "TEXT DEFAULT ''"), ("location_updated_at", "INTEGER NOT NULL DEFAULT 0"), ("checkout_request_id", "TEXT DEFAULT ''"), ("merchant_request_id", "TEXT DEFAULT ''"), ("mpesa_receipt", "TEXT DEFAULT ''"), ("payment_result", "TEXT DEFAULT ''")):
            if col not in order_cols:
                conn.execute(f"ALTER TABLE orders ADD COLUMN {col} {definition}")

        # Backfill conversation rows for legacy messages that have no conversation_id
        orphans = conn.execute(
            "SELECT DISTINCT listing_id, sender_id, receiver_id FROM messages WHERE conversation_id IS NULL"
        ).fetchall()
        for row in orphans:
            lid, s, r = row["listing_id"], row["sender_id"], row["receiver_id"]
            listing = conn.execute("SELECT user_id FROM listings WHERE id=?", (lid,)).fetchone()
            if not listing:
                continue
            seller_id = listing["user_id"]
            buyer_id = s if s != seller_id else r
            conn.execute(
                "INSERT OR IGNORE INTO conversations(listing_id,buyer_id,seller_id,created_at) VALUES(?,?,?,?)",
                (lid, buyer_id, seller_id, now()),
            )
            conv = conn.execute(
                "SELECT id FROM conversations WHERE listing_id=? AND buyer_id=? AND seller_id=?",
                (lid, buyer_id, seller_id),
            ).fetchone()
            if conv:
                conn.execute(
                    "UPDATE messages SET conversation_id=? WHERE listing_id=? AND conversation_id IS NULL",
                    (conv["id"], lid),
                )


        # admin_requests table
        conn.execute(
            """CREATE TABLE IF NOT EXISTS admin_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                staff_number TEXT NOT NULL,
                kra_certificate_path TEXT DEFAULT '',
                full_name TEXT NOT NULL,
                id_number TEXT NOT NULL,
                phone TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
                created_at INTEGER NOT NULL
            )"""
        )
        # Seed data and preserve legacy sellers as already approved.
        conn.execute("UPDATE users SET role='seller', seller_status='approved' WHERE role='student'")
        conn.execute("UPDATE users SET seller_status='approved' WHERE role='seller' AND seller_status='none'")
        conn.execute("UPDATE orders SET seller_order_status='paid' WHERE seller_order_status='pending' AND payment_status='paid'")
        if not conn.execute("SELECT 1 FROM users WHERE email='admin@unimarket.test'").fetchone():
            conn.execute(
                "INSERT INTO users(name,email,university,role,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,?,?)",
                ("UniMarket Admin", "admin@unimarket.test", "UniMarket", "admin", password_hash("admin12345"), 1, now()),
            )
        if not conn.execute("SELECT 1 FROM users WHERE email='seller@unimarket.test'").fetchone():
            conn.execute(
                "INSERT INTO users(name,email,phone,university,faculty,year,bio,role,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "Sample Seller", "seller@unimarket.test", "+254700000000",
                    "Example University", "Science", "Year 4",
                    "Selling gently used university essentials.",
                    "seller", password_hash("student12345"), 1, now(),
                ),
            )
        if not conn.execute("SELECT 1 FROM users WHERE email='superadmin@unimarket.test'").fetchone():
            conn.execute(
                """INSERT INTO users(name,email,university,role,is_superadmin,password_hash,email_verified,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    "UniMarket Superadmin", "superadmin@unimarket.test", "UniMarket",
                    "admin", 1, password_hash("SuperAdmin2026!"), 1, now(),
                ),
            )
        if not conn.execute("SELECT 1 FROM listings").fetchone():
            sid = conn.execute("SELECT id FROM users WHERE email='seller@unimarket.test'").fetchone()["id"]
            seed = [
                ("Discrete Mathematics Textbook", "Textbooks and Notes", "Clean copy with handwritten revision notes included. Covers graphs, trees, counting, and logic. Great for BCS and BSc students.", 1200, "Used - Good", "Main campus", "/static/images/demo/textbook.jpg"),
                ("Scientific Calculator", "Electronics and Gadgets", "Casio fx-991ES PLUS with 570+ functions. Perfect for computer science, engineering, and commerce units. Batteries included.", 900, "Used - Excellent", "University library", "/static/images/demo/calculator.jpg"),
                ("Event Photography", "Services", "Affordable professional photography for university events, birthdays, and graduation shoots. Includes editing and digital delivery.", 2500, "Service", "University campus", "/static/images/demo/photography.jpg"),
            ]
            for title, category, desc, price, condition, location, img in seed:
                conn.execute(
                    """INSERT INTO listings(user_id,title,category,description,price,condition,location,image_path,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (sid, title, category, desc, price, condition, location, img, now(), now()),
                )


# ---------------------------------------------------------------------------
# Background worker — offer expiry
# ---------------------------------------------------------------------------
OFFER_TTL = 7 * 86400    # 7 days
LISTING_TTL = 60 * 86400  # 60 days


def _expiry_worker():
    """Runs in a daemon thread; auto-expires offers and old listings."""
    while True:
        try:
            with db() as conn:
                conn.execute(
                    "UPDATE offers SET status='expired', updated_at=? "
                    "WHERE status='pending' AND expires_at > 0 AND expires_at <= ?",
                    (now(), now()),
                )
                conn.execute(
                    "UPDATE listings SET status='expired', updated_at=? "
                    "WHERE status='active' AND expires_at > 0 AND expires_at <= ?",
                    (now(), now()),
                )
        except Exception as exc:
            print(f"[EXPIRY WORKER] {exc}")
        time.sleep(300)


# ---------------------------------------------------------------------------
# HTTP primitives
# ---------------------------------------------------------------------------
class Request:
    def __init__(self, raw):
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        method, target, _version = lines[0].split(" ", 2)
        self.method = method
        self.path, _, self.query_string = target.partition("?")
        self.query = urllib.parse.parse_qs(self.query_string)
        self.headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.lower()] = v.strip()
        self.body = body
        self.cookies = {}
        for part in self.headers.get("cookie", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                self.cookies[k] = v


class Response:
    def __init__(self, body="", status=200, ctype="text/html; charset=utf-8", headers=None):
        self.body = body.encode() if isinstance(body, str) else body
        self.status = status
        self.ctype = ctype
        self.headers = headers or {}


STATUS = {200: "OK", 302: "Found", 400: "Bad Request", 401: "Unauthorized",
          403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
          500: "Internal Server Error"}


def redirect(path):
    return Response("", 302, headers={"Location": path})


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_form(req):
    ctype = req.headers.get("content-type", "")
    if ctype.startswith("multipart/form-data"):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + req.body
        )
        fields, files = {}, {}
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            data = part.get_payload(decode=True) or b""
            if filename:
                files[name] = (filename, data)
            else:
                fields[name] = data.decode("utf-8", "replace")
        return fields, files
    return {k: v[0] for k, v in urllib.parse.parse_qs(req.body.decode(), keep_blank_values=True).items()}, {}


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user(req):
    token = req.cookies.get("um_session")
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?",
            (token, now()),
        ).fetchone()
        return row


def require_user(req):
    user = current_user(req)
    if not user:
        return None, redirect("/login")
    return user, None


def require_seller(req):
    user, resp = require_user(req)
    if resp:
        return user, resp
    if user["suspended"]:
        reason = esc((user["suspend_reason"] or "") or "No reason provided.")
        return user, layout(
            req,
            "Account Suspended",
            '<section class="auth-panel"><p class="eyebrow">Selling suspended</p>'
            '<h1>Your selling privileges have been suspended</h1>'
            f'<p class="muted">Reason: {reason}</p>'
            '<p class="muted">Contact the admin team if you believe this is an error.</p>'
            '<a class="button-link" href="/">Go home</a></section>',
            user,
        )
    if user["role"] not in ("seller", "admin"):
        with db() as conn:
            request = conn.execute("SELECT status, university FROM seller_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 1", (user["id"],)).fetchone()
        if request and request["status"] == "pending":
            return user, layout(req, "Seller application pending", '<section class="auth-panel"><p class="eyebrow">Seller access</p><h1>Your seller request is under review</h1>' + f'<p class="muted">The admin team for {esc(request["university"])} must approve your account before you can publish listings.</p>' + '<a class="button-link" href="/buyer">Back to buyer dashboard</a></section>', user)
        intro = '<p class="muted">Your last seller request was declined. Submit a new request below.</p>' if request and request["status"] == "rejected" else '<p class="muted">Seller accounts are approved by an admin from your own school before publishing listings.</p>'
        return user, layout(req, "Seller Account Required", '<section class="auth-panel"><p class="eyebrow">Seller access</p><h1>Request seller access</h1>' + intro + '<form method="post" action="/profile/upgrade-seller" class="form">' + csrf_input(req) + '<label class="field-label" for="seller-university">Your university or school</label><select id="seller-university" name="university" required><option value="">Select university</option>' + university_options(user["university"]) + '</select><label class="field-label" for="seller-identifier-type">Seller identification</label><select id="seller-identifier-type" name="identifier_type" required><option value="admission_number">Admission number</option><option value="staff_number">Staff number</option></select><label class="field-label" for="seller-identifier-number">Admission or staff number</label><input id="seller-identifier-number" name="identifier_number" required maxlength="80" autocomplete="off" placeholder="Enter your number"><button>Submit seller request</button></form></section>', user)
    return user, None


def unread_count(user_id):
    with db() as conn:
        row = conn.execute(
            "SELECT count(*) c FROM messages WHERE receiver_id=? AND is_read=0",
            (user_id,),
        ).fetchone()
        return row["c"] if row else 0


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
def layout(req, title, content, user=None):
    user = user if user is not None else current_user(req)
    csrf_tok = _csrf_token_for(req)
    content = re.sub(r'(<form\b(?=[^>]*\bmethod\s*=\s*(["\'])post\2)[^>]*>)', lambda match: match.group(1) + f'<input type="hidden" name="_csrf" value="{esc(csrf_tok)}">', content, flags=re.IGNORECASE)
    content = labelize_fields(content)
    unread = unread_count(user["id"]) if user else 0
    if user:
        is_admin = user["role"] == "admin"
        is_super = is_admin and bool(user["is_superadmin"])
        dashboard_href = '/admin' if is_admin else ('/seller' if user['role'] == 'seller' else '/buyer')
        nav = f'''
        <aside class="app-sidebar">
          <a class="app-brand" href="/"><span class="app-brand-mark">U</span><span><strong>UniMarket</strong><small>{'Admin dashboard' if is_admin else 'University marketplace'}</small></span></a>
          <p class="app-nav-label">Menu</p>
          <nav class="app-nav" aria-label="Dashboard menu">
            <a class="active" href="{dashboard_href}"><span>▦</span>Dashboard</a>
            <a href="/buyer"><span>♧</span>Buyer dashboard</a>
            {f'<a href="/seller"><span>♧</span>Seller dashboard</a>' if user['role'] in ('seller','admin') else ''}
            {f'<a href="/admin"><span>♙</span>Admin dashboard</a>' if is_admin else ''}
            <a href="/orders"><span>▤</span>Orders &amp; delivery</a>
            <a href="/inbox"><span>◫</span>Chat {f'<b>{unread}</b>' if unread else ''}</a>
            <a href="/reports"><span>▥</span>Reports</a>
            {'<a href="/buyer/reports"><span>📊</span>Purchase reports</a>' if user['role'] == 'buyer' or user['role'] == 'admin' else ''}
            {'<a href="/seller/reports"><span>📈</span>Sales reports</a>' if user['role'] in ('seller','admin') else ''}
            {'<a href="/admin/reports"><span>📉</span>Admin reports</a>' if user['role'] == 'admin' else ''}
          </nav>
          <p class="app-nav-label">Features</p>
          <nav class="app-nav">
            {f'<a href="/admin-request"><span>♙</span>Admin request</a>' if not is_admin else ''}
            {f'<a href="/listing/new"><span>＋</span>Sell an item</a>' if user['role'] in ('seller','admin') else ''}
            <a href="/profile"><span>⚙</span>Profile</a>
          </nav>
          <div class="app-sidebar-footer"><div class="app-user"><span class="app-avatar">{esc(user['name'][:2].upper())}</span><span><strong>{esc(user['name'])}</strong><small>{'Superadmin' if is_super else esc(user['role'].title())}</small></span></div><form method="post" action="/logout"><input type="hidden" name="_csrf" value="{esc(csrf_tok)}"><button class="app-logout" type="submit"><span aria-hidden="true">↪</span> Log out</button></form></div>
        </aside>'''
        page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} | UniMarket</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><link rel="stylesheet" href="/static/css/styles.css"><script defer src="/static/js/app.js"></script></head><body class="dashboard-body"><div class="app-shell">{nav}<div class="app-main"><header class="app-topbar"><button class="app-menu" aria-label="Open menu" type="button">☰</button><div class="app-crumb">Dashboard / <strong>{esc(title)}</strong></div><div class="app-top-actions"><form class="app-search" method="get" action="/" role="search"><span aria-hidden="true">⌕</span><input name="q" aria-label="Search listings" placeholder="Search listings"><button class="app-search-submit" type="submit" aria-label="Submit search">Search</button></form><a class="app-icon" href="/inbox" title="Open chat" aria-label="Open chat">◫{f'<i aria-hidden="true"></i><span class="sr-only">{unread} unread messages</span>' if unread else ''}</a><a class="app-icon" href="/orders" title="Open orders" aria-label="Open orders">♧</a><a class="app-avatar app-avatar-link" href="/profile" title="Open profile" aria-label="Open profile">{esc(user['name'][:2].upper())}</a></div></header><main class="app-content">{content}</main></div></div><script>document.querySelector('.app-menu')?.addEventListener('click',()=>document.querySelector('.app-sidebar')?.classList.toggle('open'));</script></body></html>'''
    else:
        page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} | UniMarket</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet"><link rel="stylesheet" href="/static/css/styles.css"><script defer src="/static/js/app.js"></script></head><body><header class="topbar"><a class="brand" href="/"><img src="/static/images/unimarket-logo.svg" alt="UniMarket logo"><span><strong>UniMarket</strong><small>University Marketplace</small></span></a><nav><a href="/">Browse</a><a href="/categories">Categories</a><a href="/login">Login</a><a class="admin-signup-button" href="/register?admin_intent=1">Sign up as Admin</a><a class="button-link" href="/register">Join</a></nav></header><main>{content}</main></body></html>'''
    resp = Response(page)
    _set_csrf_cookie(resp, csrf_tok)
    return resp

# ---------------------------------------------------------------------------
# Shared components
# ---------------------------------------------------------------------------
def listing_card(row, wished=False):
    img = (
        f'<img src="{esc(row["image_path"])}" alt="">'
        if row["image_path"] else '<div class="image-fallback">UM</div>'
    )
    return f"""
<article class="listing-card">
  <a class="media" href="/listing/{row['id']}">{img}</a>
  <div class="card-body">
    <p class="eyebrow">{esc(row['category'])}{f' &middot; {esc(row["status"])}' if row['status'] != 'active' else ''}</p>
    <h3><a href="/listing/{row['id']}">{esc(row['title'])}</a></h3>
    <p class="muted">{esc(row['location'])} &middot; {esc(row['condition'])}</p>
    {f'<p class="university-label">{esc(row["university"])}</p>' if row['university'] else ''}
    <div class="card-row">
      <strong>{money(row['price'])}</strong>
      <span><a href="/seller/{row['seller_id'] if 'seller_id' in row.keys() else ''}">{esc(row['seller'])}</a></span>
    </div>
  </div>
</article>"""


def stars(avg, count):
    """Render a star rating display."""
    if not count:
        return '<span class="muted">No reviews yet</span>'
    filled = round(avg)
    stars_html = "&#9733;" * filled + "&#9734;" * (5 - filled)
    return f'<span class="stars">{stars_html}</span> <span class="muted">({count} review{"s" if count != 1 else ""})</span>'


# ---------------------------------------------------------------------------
# Saved search / alert helpers
# ---------------------------------------------------------------------------
def _matches_search(listing_title, listing_category, listing_price, query, category, max_price):
    """Return True if a listing matches a saved search's criteria."""
    if category and listing_category != category:
        return False
    if max_price and max_price > 0 and listing_price > max_price:
        return False
    if query:
        return query.lower() in listing_title.lower()
    return True


def fire_alerts(listing_id, listing_title, listing_category, listing_price):
    """Called after a new listing is created. Emails matching saved searches."""
    try:
        with db() as conn:
            searches = conn.execute(
                """SELECT ss.*, u.email FROM saved_searches ss
                   JOIN users u ON u.id=ss.user_id
                   WHERE u.email_verified=1"""
            ).fetchall()
            for s in searches:
                if not _matches_search(
                    listing_title, listing_category, listing_price,
                    s["query"], s["category"], s["max_price"],
                ):
                    continue
                conn.execute(
                    "UPDATE saved_searches SET last_alerted_at=? WHERE id=?",
                    (now(), s["id"]),
                )
                threading.Thread(
                    target=send_alert_email,
                    args=(s["email"], s["label"] or s["query"] or s["category"],
                          listing_title, listing_id, listing_category),
                    daemon=True,
                ).start()
    except Exception as exc:
        print(f"[ALERT FIRE] {exc}")


def alerts_page(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        searches = conn.execute(
            "SELECT * FROM saved_searches WHERE user_id=? ORDER BY created_at DESC",
            (user["id"],),
        ).fetchall()
    rows_html = ""
    for s in searches:
        criteria = []
        if s["query"]:
            criteria.append(f'Keyword: <strong>{esc(s["query"])}</strong>')
        if s["category"]:
            criteria.append(f'Category: <strong>{esc(s["category"])}</strong>')
        if s["max_price"] and s["max_price"] > 0:
            criteria.append(f'Max price: <strong>{money(s["max_price"])}</strong>')
        last = (
            time.strftime("%d %b %Y", time.localtime(s["last_alerted_at"]))
            if s["last_alerted_at"] else "Never"
        )
        rows_html += f"""
<li class="alert-item">
  <div class="alert-info">
    <strong class="alert-label">{esc(s["label"] or "Untitled alert")}</strong>
    <span class="muted">{" &middot; ".join(criteria) or "Any listing"}</span>
    <span class="muted">Last matched: {last}</span>
  </div>
  <form method="post" action="/alerts/delete">
    <input type="hidden" name="search_id" value="{s['id']}">
    <button class="danger-button">Delete</button>
  </form>
</li>"""
    empty = '<p class="empty">No saved alerts yet. Browse a category or search and click "Save as Alert".</p>'
    content = f"""
<section class="toolbar">
  <div><p class="eyebrow">Notifications</p><h1>My Alerts</h1>
  <p class="muted">Get an email when a new listing matches your saved search.</p></div>
  <a class="button-link" href="/categories">Browse Categories</a>
</section>
<section class="narrow alert-create">
  <h2>Create a new alert</h2>
  <form method="post" action="/alerts/save" class="form">
    <input name="label" placeholder="Alert name (e.g. Casio calculator)">
    <input name="query" placeholder="Keyword (optional)">
    <select name="category">
      <option value="">Any category</option>
      {"".join(f'<option>{esc(c)}</option>' for c in CATEGORIES)}
    </select>
    <input name="max_price" type="number" min="0" step="1" placeholder="Max price in KES (optional)">
    <button>Save Alert</button>
  </form>
</section>
<section class="toolbar" style="margin-top:32px"><h2>Active Alerts</h2></section>
{"<ul class='alert-list'>" + rows_html + "</ul>" if searches else empty}"""
    return layout(req, "My Alerts", content, user)


def save_alert(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    query = form.get("query", "").strip()
    category = form.get("category", "").strip()
    if category not in CATEGORIES:
        category = ""
    max_price = as_float(form.get("max_price", "0"))
    label = form.get("label", "").strip() or query or category or "Alert"
    if not query and not category:
        return redirect("/alerts")
    with db() as conn:
        conn.execute(
            "INSERT INTO saved_searches(user_id,query,category,max_price,label,created_at) VALUES(?,?,?,?,?,?)",
            (user["id"], query, category, max_price, label, now()),
        )
    return redirect("/alerts")


def delete_alert(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    with db() as conn:
        conn.execute(
            "DELETE FROM saved_searches WHERE id=? AND user_id=?",
            (as_int(form.get("search_id")), user["id"]),
        )
    return redirect("/alerts")


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------
CATEGORY_ICONS = {
    "Textbooks and Notes": "📚",
    "Electronics and Gadgets": "💻",
    "Clothes and Accessories": "👗",
    "Event Tickets": "🎟️",
    "Services": "🛠️",
}


def categories_page(req):
    with db() as conn:
        counts = {
            row["category"]: row["c"]
            for row in conn.execute(
                "SELECT category, count(*) c FROM listings WHERE status='active' GROUP BY category"
            ).fetchall()
        }
    cards = ""
    for cat in CATEGORIES:
        count = counts.get(cat, 0)
        icon = CATEGORY_ICONS.get(cat, "🏷️")
        cards += f"""
<a class="category-card" href="/category/{urllib.parse.quote(cat)}">
  <span class="category-icon" aria-hidden="true">{icon}</span>
  <span class="category-name">{esc(cat)}</span>
  <span class="category-count muted">{count} listing{"s" if count != 1 else ""}</span>
</a>"""
    content = f"""
<section class="toolbar">
  <div><p class="eyebrow">Browse by topic</p><h1>Categories</h1></div>
</section>
<section class="category-grid">{cards}</section>"""
    return layout(req, "Categories", content)


def category_page(req, cat_name):
    if cat_name not in CATEGORIES:
        return layout(req, "Not Found", '<p class="empty">Category not found.</p>')
    university = req.query.get("university", [""])[0]
    sort = req.query.get("sort", ["newest"])[0]
    order = {
        "newest": "l.bumped_at DESC, l.created_at DESC",
        "price_asc": "l.price ASC",
        "price_desc": "l.price DESC",
    }.get(sort, "l.bumped_at DESC, l.created_at DESC")
    clauses = ["l.status='active'", "l.category=?"]
    args = [cat_name]
    if university:
        clauses.append("u.university=?")
        args.append(university)
    with db() as conn:
        listings = conn.execute(
            f"""SELECT l.*, u.name seller, u.id seller_id, u.university
                FROM listings l JOIN users u ON u.id=l.user_id
                WHERE {' AND '.join(clauses)} ORDER BY {order}""",
            args,
        ).fetchall()
        universities = conn.execute(
            "SELECT DISTINCT university FROM users WHERE university <> '' ORDER BY university COLLATE NOCASE"
        ).fetchall()
    university_options = "".join(
        f'<option value="{esc(r["university"])}" {"selected" if r["university"] == university else ""}>{esc(r["university"])}</option>'
        for r in universities
    )
    sort_options = "".join(
        f'<option value="{v}" {"selected" if sort == v else ""}>{label}</option>'
        for v, label in [("newest", "Newest first"), ("price_asc", "Price: low to high"), ("price_desc", "Price: high to low")]
    )
    cards = (
        "".join(listing_card(x) for x in listings)
        or '<p class="empty">No active listings in this category.</p>'
    )
    icon = CATEGORY_ICONS.get(cat_name, "🏷️")
    user = current_user(req)
    # Show save-search button for logged-in users
    save_search = ""
    if user:
        save_search = f"""
<form method="post" action="/alerts/save" class="save-search-form">
  <input type="hidden" name="category" value="{esc(cat_name)}">
  <input type="hidden" name="query" value="">
  <input type="hidden" name="label" value="{esc(cat_name)}">
  <button class="secondary-button save-alert-btn">&#43; Save as Alert</button>
</form>"""
    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow"><a href="/categories">Categories</a></p>
    <h1><span aria-hidden="true">{icon}</span> {esc(cat_name)}</h1>
    <p class="muted">{len(listings)} active listing{"s" if len(listings) != 1 else ""}</p>
  </div>
  <div class="profile-actions">
    {save_search}
    <a class="button-link" href="/listing/new">Sell in this category</a>
  </div>
</section>
<form class="category-filters" method="get">
  <select name="university" onchange="this.form.submit()">
    <option value="">All universities</option>{university_options}
  </select>
  <select name="sort" onchange="this.form.submit()">
    {sort_options}
  </select>
</form>
<section class="grid">{cards}</section>"""
    return layout(req, cat_name, content)


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------
def home(req):
    q = req.query.get("q", [""])[0]
    cat = req.query.get("category", [""])[0]
    university = req.query.get("university", [""])[0]
    clauses = ["l.status='active'"]
    args = []
    if q:
        clauses.append("(l.title LIKE ? OR l.description LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if cat:
        clauses.append("l.category=?")
        args.append(cat)
    if university:
        clauses.append("u.university=?")
        args.append(university)
    with db() as conn:
        listings = conn.execute(
            f"""SELECT l.*, u.name seller, u.id seller_id, u.university FROM listings l
                JOIN users u ON u.id=l.user_id
                WHERE {' AND '.join(clauses)} ORDER BY l.bumped_at DESC, l.created_at DESC""",
            args,
        ).fetchall()
        universities = conn.execute(
            "SELECT DISTINCT university FROM users WHERE university <> '' ORDER BY university COLLATE NOCASE"
        ).fetchall()
    cats = "".join(
        f'<option {"selected" if c == cat else ""}>{esc(c)}</option>' for c in CATEGORIES
    )
    university_options = "".join(
        f'<option value="{esc(row["university"])}" {"selected" if row["university"] == university else ""}>{esc(row["university"])}</option>'
        for row in universities
    )
    cards = (
        "".join(listing_card(x) for x in listings)
        or '<p class="empty">No listings match that search yet.</p>'
    )
    account_paths = "" if current_user(req) else """
<section class="account-paths" aria-label="Choose how to use UniMarket">
  <div class="account-path buyer-path">
    <p class="eyebrow">Find what you need</p>
    <h2>Login as a buyer</h2>
    <p>Browse listings near your university, save favourites, message sellers, and make offers.</p>
    <a class="button-link" href="/login?role=buyer">Buyer Login</a>
    <a class="text-link" href="/register?role=buyer">New buyer? Create an account</a>
  </div>
  <div class="account-path seller-path">
    <p class="eyebrow">Turn items into value</p>
    <h2>Login as a seller</h2>
    <p>Post listings, speak with interested students, and manage offers in one place.</p>
    <a class="button-link" href="/login?role=seller">Seller Login</a>
    <a class="text-link" href="/register?role=seller">New seller? Create an account</a>
  </div>
  <div class="account-path admin-path">
    <p class="eyebrow">Manage the marketplace</p>
    <h2>Sign up as Admin</h2>
    <p>Create an account, then submit staff and identity documents for approval.</p>
    <a class="button-link" href="/register?admin_intent=1">Sign up as Admin</a>
    <a class="text-link" href="/login?role=admin">Existing admin? Log in</a>
  </div>
</section>"""
    category_pills = "".join(
        f'<a class="category-pill" href="/category/{urllib.parse.quote(c)}">'
        f'{CATEGORY_ICONS.get(c, "🏷️")} {esc(c)}</a>'
        for c in CATEGORIES
    )
    content = f"""
<section class="hero">
  <div class="hero-copy">
    <p class="eyebrow">University Student Marketplace</p>
    <h1>UniMarket</h1>
    <p class="hero-lede">A marketplace for university students to buy and sell textbooks, gadgets, fashion, tickets, and services.</p>
    <div class="hero-actions">
      <a class="button-link" href="/listing/new">Post Listing</a>
      <a class="ghost-link" href="/register?role=buyer">Join UniMarket</a>
    </div>
  </div>
  <div class="hero-panel">
    <img src="/static/images/unimarket-logo.svg" alt="" class="hero-logo">
    <form class="searchbar" method="get">
      <input name="q" value="{esc(q)}" placeholder="Search textbooks, electronics, services">
      <select name="category"><option value="">All categories</option>{cats}</select>
      <select name="university"><option value="">All universities</option>{university_options}</select>
      <button>Search</button>
    </form>
  </div>
</section>
{account_paths}
<nav class="category-pills" aria-label="Browse by category">{category_pills}</nav>
<section class="toolbar"><h2>Latest Listings</h2><a class="button-link" href="/listing/new">Post Listing</a></section>
<section class="grid">{cards}</section>"""
    return layout(req, "Browse", content)


# ---------------------------------------------------------------------------
# Auth — register / login / logout / verify
# ---------------------------------------------------------------------------
def auth_page(req, mode, error="", role=""):
    is_reg = mode == "register"
    admin_intent = req.query.get("admin_intent", [""])[0] == "1"
    allowed_roles = ("buyer", "seller") if is_reg else ("buyer", "seller", "admin")
    role = role if role in allowed_roles else req.query.get("role", ["buyer"])[0]
    if role not in allowed_roles:
        role = "buyer"
    role_options = "".join(
        f'<option value="{value}" {"selected" if role == value else ""}>{label}</option>'
        for value, label in (("buyer", "Buyer"), ("seller", "Seller"), ("admin", "Admin"))
        if value != "admin" or not is_reg
    )
    if is_reg and role == "seller":
        extra = f"""
    <label class="field-label" for="phone">Phone number</label>
    <input id="phone" name="phone" required pattern="^(\\+?254|0)[17]\\d{{8}}$" title="Use 0712345678, 0112345678, or +254712345678" inputmode="tel">
    <label class="field-label" for="university">University or school</label>
    <select id="university" name="university" required><option value="">Select university</option>{university_options()}</select>
    <label class="field-label" for="faculty">Faculty or school department</label><input id="faculty" name="faculty">
    <label class="field-label" for="year">Year of study</label>
    <select id="year" name="year"><option>Year 1</option><option>Year 2</option><option>Year 3</option><option>Year 4</option></select>
    <label class="field-label" for="identifier_type">Seller identification</label>
    <select id="identifier_type" name="identifier_type" required><option value="admission_number">Admission number</option><option value="staff_number">Staff number</option></select>
    <label class="field-label" for="identifier_number">Admission or staff number</label>
    <input id="identifier_number" name="identifier_number" required maxlength="80" autocomplete="off" placeholder="Enter your number">
    """
    elif is_reg and admin_intent:
        extra = f"""
    <label class="field-label" for="phone">Phone number</label>
    <input id="phone" name="phone" required pattern="^(\\+?254|0)[17]\\d{{8}}$" title="Use 0712345678, 0112345678, or +254712345678" inputmode="tel">
    <label class="field-label" for="university">University or school</label>
    <select id="university" name="university" required><option value="">Select university</option>{university_options()}</select>
    <label class="field-label" for="faculty">Faculty or school department</label><input id="faculty" name="faculty">
    <label class="field-label" for="year">Year of study</label>
    <select id="year" name="year"><option>Year 1</option><option>Year 2</option><option>Year 3</option><option>Year 4</option></select>
    """
    elif is_reg:
        extra = """
    <label class="field-label" for="phone">Phone number</label>
    <input id="phone" name="phone" required pattern="^(\\+?254|0)[17]\\d{8}$" title="Use 0712345678, 0112345678, or +254712345678" inputmode="tel">
    """
    else:
        extra = ""
    intent_notice = '<p class="notice">Complete the form below to register and apply for admin access in one step.</p>' if admin_intent else ""
    signup_choices = "" if not is_reg else f"""
  <div class="signup-choices" aria-label="Choose an account type">
    <a class="signup-choice {"selected" if role == "buyer" and not admin_intent else ""}" href="/register?role=buyer"><strong>Buyer sign up</strong><span>Browse and buy from students</span></a>
    <a class="signup-choice {"selected" if role == "seller" and not admin_intent else ""}" href="/register?role=seller"><strong>Seller sign up</strong><span>Request approval from your school admin, then list items</span></a>
    <a class="signup-choice admin-choice {"selected" if admin_intent else ""}" href="/register?admin_intent=1"><strong>Sign up as Admin</strong><span>Apply for verified admin access</span></a>
  </div>"""
    admin_extra = ""
    if is_reg and admin_intent:
        admin_extra = """
    <hr style="margin:18px 0 10px;border:none;border-top:1px solid var(--border,#ddd)">
    <p class="muted" style="margin-bottom:8px"><strong>Admin verification details</strong></p>
    <label class="field-label" for="staff_number">Staff number</label><input id="staff_number" name="staff_number" required>
    <label class="field-label" for="kra_pin">KRA PIN</label><input id="kra_pin" name="kra_pin" required>
    <label class="field-label" for="cover_letter">Cover letter introduction</label><input id="cover_letter" name="cover_letter" type="file" accept="image/png,image/jpeg,application/pdf,.doc,.docx" required>
    <label class="field-label" for="national_id">Copy of national ID</label><input id="national_id" name="national_id" type="file" accept="image/png,image/jpeg,application/pdf" required>
    """
    form_enc = ' enctype="multipart/form-data"' if (is_reg and admin_intent) else ''
    content = f"""
<section class="auth-panel">
  <p class="eyebrow">{'Create your account' if is_reg else 'Welcome back'}</p>
  <h1>{'Apply as Admin' if is_reg and admin_intent else ('Join as a ' + role.title() if is_reg else role.title() + ' Login')}</h1>
  {intent_notice}
  {f'<p class="error">{esc(error)}</p>' if error else ''}
  {signup_choices}
  <form method="post" class="form"{form_enc}>
    {csrf_input(req)}
    {'<input type="hidden" name="admin_intent" value="1">' if admin_intent and is_reg else ''}
    <label class="field-label" for="account-role">Account type</label>
    <select id="account-role" name="role">{role_options}</select>
    {'<label class="field-label" for="name">Full name</label><input id="name" name="name" required>' if is_reg else ''}
    <label class="field-label" for="email">Email address</label><input id="email" name="email" type="email" required>
    {extra}
    <label class="field-label" for="password">Password</label>
    <div class="password-field"><input id="password" name="password" type="password" minlength="8" title="Use at least 8 characters." autocomplete="new-password" required><button class="password-toggle" type="button" aria-label="Show password">Show</button></div>
    {'<p class="password-hint">Use at least 8 characters. Letters, numbers, and special characters are all accepted.</p>' if is_reg else ''}
    {'<label class="field-label" for="password2">Confirm password</label><div class="password-field"><input id="password2" name="password2" type="password" minlength="8" autocomplete="new-password" required><button class="password-toggle" type="button" aria-label="Show confirmation password">Show</button></div>' if is_reg else ''}
    {admin_extra}
    <button>{'Register & Apply' if is_reg and admin_intent else ('Register' if is_reg else 'Login')}</button>
  </form>
  {'' if is_reg else '<p style="margin-top:10px;font-size:14px"><a class="text-link" href="/forgot-password">Forgot password?</a></p>'}
</section>"""
    return layout(req, "Register" if is_reg else "Login", content)


def register(req):
    if req.method == "GET":
        return auth_page(req, "register")
    if err := csrf_protected(req):
        return err
    if rate_limited(req, "register"):
        return rate_limit_response()
    form, files = parse_form(req)
    admin_intent = form.get("admin_intent") == "1"
    role = form.get("role", "buyer")
    if role not in ("buyer", "seller"):
        return auth_page(req, "register", "Choose buyer or seller.")
    email = form.get("email", "").strip().lower()
    if not email or "@" not in email or len(email) > 254:
        return auth_page(req, "register", "Use a valid email address.")
    name = clamp(form.get("name", "").strip(), 120)
    if not name:
        return auth_page(req, "register", "Full name is required.")
    university = clamp(form.get("university", "").strip(), 120)
    if role == "seller" or admin_intent:
        if not university:
            return auth_page(req, "register", "University or school is required for seller and admin applications.", role)
    else:
        university = ""
    phone, phone_err = validate_phone(form.get("phone", ""))
    if phone_err:
        return auth_page(req, "register", phone_err, role)
    identifier_type = form.get("identifier_type", "").strip().lower() if role == "seller" else ""
    identifier_number = clamp(form.get("identifier_number", "").strip(), 80) if role == "seller" else ""
    if role == "seller" and identifier_type not in {"admission_number", "staff_number"}:
        return auth_page(req, "register", "Choose admission number or staff number.", role)
    if role == "seller" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/._ -]{1,79}", identifier_number):
        return auth_page(req, "register", "Enter a valid admission or staff number.", role)
    password = form.get("password", "")
    password2 = form.get("password2", "")
    if error := password_error(password):
        return auth_page(req, "register", error, role)
    if password != password2:
        return auth_page(req, "register", "Passwords do not match.", role)
    # Validate admin-specific fields when applying as admin
    if admin_intent:
        staff_number = clamp(form.get("staff_number", "").strip(), 80)
        kra_pin = clamp(form.get("kra_pin", "").strip(), 80)
        if not staff_number:
            return auth_page(req, "register", "Staff number is required for admin applications.")
        if not kra_pin:
            return auth_page(req, "register", "KRA PIN is required for admin applications.")
        cover_file = files.get("cover_letter")
        natid_file = files.get("national_id")
        if not cover_file or not cover_file[1]:
            return auth_page(req, "register", "Please upload your cover letter introduction.")
        if not natid_file or not natid_file[1]:
            return auth_page(req, "register", "Please upload a copy of your national ID.")
    token = secrets.token_urlsafe(32)
    try:
        with db() as conn:
            account_role = "buyer" if role == "seller" else role
            seller_status = "pending" if role == "seller" else "none"
            conn.execute("INSERT INTO users(name,email,phone,university,faculty,year,role,seller_status,password_hash,email_verified,verify_token,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (name, email, phone, university, clamp(form.get("faculty", ""), 80), form.get("year", ""), account_role, seller_status, password_hash(password), 0, token, now()))
            new_user = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if role == "seller":
                conn.execute("INSERT INTO seller_requests(user_id, university, identifier_type, identifier_number, status, created_at) VALUES(?,?,?,?,?,?)", (new_user["id"], university, identifier_type, identifier_number, "pending", now()))
            # If admin intent, create admin request right away
            if admin_intent:
                cover_path = save_upload(cover_file, allow_docs=True) or ""
                id_path = save_upload(natid_file, allow_docs=True) or ""
                university = clamp(form.get("university", "").strip(), 160)
                conn.execute(
                    """INSERT INTO admin_requests(user_id, staff_number, full_name, university, id_number, phone,
                       cover_letter_path, national_id_path, kra_pin, kra_certificate_path, status, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (new_user["id"], staff_number, name, university, "", phone,
                     cover_path, id_path, kra_pin, "", "pending", now()),
                )
        # Email verification remains available as an optional follow-up, but it is
        # not required before a new account can sign in.
        if admin_intent:
            return redirect("/login?registered=1&admin_applied=1")
        if role == "seller":
            return redirect("/login?registered=1&seller_applied=1")
        return redirect("/login?registered=1")
    except sqlite3.IntegrityError:
        return auth_page(req, "register", "That email is already registered.", role)


def login(req):
    if req.method == "GET":
        registered = req.query.get("registered", [""])[0]
        admin_applied = req.query.get("admin_applied", [""])[0]
        seller_applied = req.query.get("seller_applied", [""])[0]
        notice = ""
        if admin_applied:
            notice = '<p class="notice">Account created and admin application submitted! A superadmin will review your details.</p>'
        elif seller_applied:
            notice = '<p class="notice">Seller request submitted. Log in as a buyer while the admin for your school reviews it.</p>'
        elif registered:
            notice = '<p class="notice">Account created! You can log in now. Email verification is optional.</p>'
        page = auth_page(req, "login")
        if notice:
            page.body = page.body.replace(b"<form method", notice.encode() + b"<form method", 1)
        return page
    if err := csrf_protected(req):
        return err
    if rate_limited(req, "login"):
        return rate_limit_response()
    form, _ = parse_form(req)
    role = form.get("role", "buyer")
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (form.get("email", "").lower(),)).fetchone()
        # Account lockout check
        if user and user["locked_until"] > now():
            wait = max(1, (user["locked_until"] - now()) // 60)
            return auth_page(req, "login",
                f"Account temporarily locked after too many failed attempts. "
                f"Try again in {wait} minute{'s' if wait != 1 else ''}.", role)
        if not user or not password_ok(form.get("password", ""), user["password_hash"]):
            if user:
                new_fails = user["failed_logins"] + 1
                lock_until = (now() + 900) if new_fails >= 5 else user["locked_until"]
                conn.execute(
                    "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                    (new_fails, lock_until, user["id"]),
                )
                if new_fails >= 5:
                    return auth_page(req, "login",
                        "Too many failed attempts. Account locked for 15 minutes.", role)
            return auth_page(req, "login", "Invalid email or password.", role)
        if user["role"] != role:
            return auth_page(req, "login",
                f"This account is registered as a {user['role']}. "
                f"Choose {user['role'].title()} Login instead.", role)
        # Block login if user has a pending admin request
        pending_req = conn.execute(
            "SELECT status FROM admin_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()
        if pending_req and pending_req["status"] == "pending":
            return auth_page(req, "login",
                "Your admin application is still under review. "
                "You will be able to log in once a superadmin approves your request.", role)
        if pending_req and pending_req["status"] == "rejected":
            return auth_page(req, "login",
                "Your admin application was rejected. "
                "Please contact support if you believe this is an error.", role)
        # Successful login — reset lockout counters
        session_token = secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE users SET failed_logins=0, locked_until=0 WHERE id=?", (user["id"],)
        )
        conn.execute(
            "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (session_token, user["id"], now(), now() + 86400 * 14),
        )
    destination = {"buyer": "/buyer", "seller": "/seller", "admin": "/admin"}[user["role"]]
    if req.query.get("admin_intent", [""])[0] == "1" and user["role"] != "admin":
        destination = "/admin-request"
    return Response("", 302, headers={
        "Location": destination,
        "Set-Cookie": f"um_session={session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={86400 * 14}",
    })


def logout(req):
    if err := csrf_protected(req):
        return err
    token = req.cookies.get("um_session", "")
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    return Response("", 302, headers={
        "Location": "/",
        "Set-Cookie": "um_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
    })


# ---------------------------------------------------------------------------
# Email verification routes (OTP + link fallback)
# ---------------------------------------------------------------------------
def verify_email_page(req):
    """GET/POST /verify-email — enter the 6-digit OTP sent to your email."""
    email = req.query.get("email", [""])[0]
    admin_applied = req.query.get("admin_applied", [""])[0]
    error = ""
    success = False

    if req.method == "POST":
        form, _ = parse_form(req)
        email = form.get("email", "").strip().lower()
        otp_input = form.get("otp", "").strip()

        if not email or not otp_input:
            error = "Please enter your email and the 6-digit code."
        elif not re.match(r"^\d{6}$", otp_input):
            error = "The code must be exactly 6 digits."
        else:
            with db() as conn:
                user = conn.execute(
                    "SELECT id, otp_code, otp_expires_at, otp_attempts, email_verified, name FROM users WHERE email=?",
                    (email,),
                ).fetchone()
                if not user:
                    error = "No account found with that email."
                elif user["email_verified"]:
                    return layout(
                        req, "Already Verified",
                        '<section class="auth-panel"><p class="eyebrow">Email verification</p>'
                        '<h1>&#10003; Already verified</h1>'
                        '<p class="muted">Your email is already confirmed.</p>'
                        '<a class="button-link" href="/login">Log in</a></section>',
                    )
                elif user["otp_attempts"] >= OTP_MAX_ATTEMPTS:
                    error = "Too many failed attempts. Please request a new code."
                elif user["otp_expires_at"] < now():
                    error = "That code has expired. Please request a new one."
                elif not secrets.compare_digest(otp_input, user["otp_code"]):
                    conn.execute(
                        "UPDATE users SET otp_attempts = otp_attempts + 1 WHERE id=?",
                        (user["id"],),
                    )
                    remaining = OTP_MAX_ATTEMPTS - user["otp_attempts"] - 1
                    error = f"Incorrect code. {remaining} attempt{'s' if remaining != 1 else ''} remaining."
                else:
                    # OTP matches — verify the email
                    conn.execute(
                        "UPDATE users SET email_verified=1, verify_token=\'\', otp_code=\'\', otp_attempts=0 WHERE id=?",
                        (user["id"],),
                    )
                    success = True

    if success:
        notice = ""
        if admin_applied:
            notice = '<p class="muted">Your admin application is under review. You will be notified once approved.</p>'
        return layout(
            req, "Email Verified",
            '<section class="auth-panel"><p class="eyebrow">Email verification</p>'
            '<h1>&#10003; Email verified!</h1>'
            '<p class="muted">Your university email has been confirmed.</p>'
            + notice +
            '<a class="button-link" href="/login">Log in to your account</a></section>',
        )

    # Calculate time remaining for countdown display
    time_left = 0
    if email:
        with db() as conn:
            u = conn.execute("SELECT otp_expires_at FROM users WHERE email=?", (email,)).fetchone()
            if u and u["otp_expires_at"] > now():
                time_left = u["otp_expires_at"] - now()

    content = f"""
<section class="auth-panel">
  <p class="eyebrow">Email verification</p>
  <h1>Enter your verification code</h1>
  <p class="muted">We sent a 6-digit code to <strong>{esc(email) if email else 'your email'}</strong>. Check your inbox (and spam folder).</p>
  {f'<p class="error">{esc(error)}</p>' if error else ''}
  <form method="post" class="form otp-form">
    {csrf_input(req)}
    <input type="hidden" name="email" value="{esc(email)}">
    {f'<input type="hidden" name="admin_applied" value="1">' if admin_applied else ''}
    <label class="field-label" for="otp">6-digit code</label>
    <input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{{6}}"
           maxlength="6" autocomplete="one-time-code" placeholder="000000"
           class="otp-input" required autofocus>
    {f'<p class="muted otp-timer">Code expires in <strong id="otp-countdown" data-seconds="{time_left}">{time_left // 60}:{time_left % 60:02d}</strong></p>' if time_left > 0 else ''}
    <button>Verify Email</button>
  </form>
  <div class="otp-actions">
    <form method="post" action="/verify-email/resend" class="inline-form">
      {csrf_input(req)}
      <input type="hidden" name="email" value="{esc(email)}">
      <button class="text-link" type="submit">Resend code</button>
    </form>
    <span class="muted">&middot;</span>
    <p class="muted" style="display:inline">Also check for a verification link in your email</p>
  </div>
</section>"""
    return layout(req, "Verify Email", content)


def resend_otp(req):
    """POST /verify-email/resend — generate and send a new OTP."""
    form, _ = parse_form(req)
    email = form.get("email", "").strip().lower()
    if not email:
        return redirect("/verify-email")
    with db() as conn:
        user = conn.execute(
            "SELECT id, name, email_verified FROM users WHERE email=?", (email,)
        ).fetchone()
        if not user or user["email_verified"]:
            return redirect(f"/verify-email?email={urllib.parse.quote(email)}")
        otp = generate_otp()
        token = secrets.token_urlsafe(32)
        conn.execute(
            "UPDATE users SET otp_code=?, otp_expires_at=?, otp_attempts=0, verify_token=? WHERE id=?",
            (otp, now() + OTP_TTL, token, user["id"]),
        )
    threading.Thread(target=send_otp_email, args=(email, otp, user["name"]), daemon=True).start()
    threading.Thread(target=send_verification_email, args=(email, token), daemon=True).start()
    return redirect(f"/verify-email?email={urllib.parse.quote(email)}")


def verify_email(req, token):
    """GET /verify/<token> — link-based fallback verification."""
    with db() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE verify_token=? AND email_verified=0", (token,)
        ).fetchone()
        if not user:
            return layout(
                req, "Verification Failed",
                '<section class="auth-panel"><p class="eyebrow">Email verification</p>'
                '<h1>Link invalid or already used</h1>'
                '<p class="muted">The verification link has expired or your email is already verified.</p>'
                '<a class="button-link" href="/login">Go to login</a></section>',
            )
        conn.execute(
            "UPDATE users SET email_verified=1, verify_token=\'\', otp_code=\'\' WHERE id=?", (user["id"],)
        )
    return layout(
        req, "Email Verified",
        '<section class="auth-panel"><p class="eyebrow">Email verification</p>'
        '<h1>&#10003; Email verified!</h1>'
        '<p class="muted">Your university email has been confirmed. You can now use all UniMarket features.</p>'
        '<a class="button-link" href="/login">Log in</a></section>',
    )


def resend_verification(req):
    """POST /verify/resend — from the dashboard banner, resend both OTP and link."""
    user, resp = require_user(req)
    if resp:
        return resp
    if user["email_verified"]:
        return redirect("/profile")
    otp = generate_otp()
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute(
            "UPDATE users SET verify_token=?, otp_code=?, otp_expires_at=?, otp_attempts=0 WHERE id=?",
            (token, otp, now() + OTP_TTL, user["id"]),
        )
    threading.Thread(target=send_otp_email, args=(user["email"], otp, user["name"]), daemon=True).start()
    threading.Thread(target=send_verification_email, args=(user["email"], token), daemon=True).start()
    return redirect(f"/verify-email?email={urllib.parse.quote(user['email'])}")


# ---------------------------------------------------------------------------
# Password reset  /forgot-password  /reset-password/<token>
# ---------------------------------------------------------------------------
RESET_TTL = 3600  # 1 hour


def send_password_reset_email(to_addr, token):
    link = f"{APP_BASE_URL}/reset-password/{token}"
    send_email(
        to_addr,
        "Reset your UniMarket password",
        f"You requested a password reset for your UniMarket account.\n\n"
        f"Click the link below to choose a new password:\n\n{link}\n\n"
        f"This link expires in 1 hour. If you did not request this, ignore this email.",
    )


def forgot_password(req):
    if req.method == "GET":
        content = f"""
<section class="auth-panel">
  <p class="eyebrow">Account recovery</p>
  <h1>Forgot password?</h1>
  <p class="muted">Enter your university email and we'll send a reset link.</p>
  <form method="post" class="form">
    {csrf_input(req)}
    <input name="email" type="email" placeholder="University email" required>
    <button>Send reset link</button>
  </form>
  <p style="margin-top:14px"><a class="text-link" href="/login">Back to login</a></p>
</section>"""
        return layout(req, "Forgot Password", content)
    if err := csrf_protected(req):
        return err
    if rate_limited(req, "login"):  # reuse login bucket to prevent enumeration
        return rate_limit_response()
    form, _ = parse_form(req)
    email = form.get("email", "").strip().lower()
    # Always show the same message regardless of whether the email exists
    # (prevents account enumeration)
    confirmation = layout(
        req, "Reset Link Sent",
        '<section class="auth-panel"><p class="eyebrow">Account recovery</p>'
        '<h1>Check your email</h1>'
        '<p class="muted">If that address is registered, you\'ll receive a password reset link within a few minutes.</p>'
        '<a class="button-link" href="/login">Back to login</a></section>',
    )
    with db() as conn:
        user = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            return confirmation
        # Invalidate old tokens for this user
        conn.execute("DELETE FROM password_resets WHERE user_id=?", (user["id"],))
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO password_resets(token,user_id,created_at,expires_at,used) VALUES(?,?,?,?,0)",
            (token, user["id"], now(), now() + RESET_TTL),
        )
    threading.Thread(
        target=send_password_reset_email, args=(email, token), daemon=True
    ).start()
    return confirmation


def reset_password(req, token):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM password_resets WHERE token=? AND used=0 AND expires_at>?",
            (token, now()),
        ).fetchone()
    if not row:
        return layout(
            req, "Link Expired",
            '<section class="auth-panel"><p class="eyebrow">Password reset</p>'
            '<h1>Link invalid or expired</h1>'
            '<p class="muted">This reset link has already been used or has expired (1 hour).</p>'
            '<a class="button-link" href="/forgot-password">Request a new link</a></section>',
        )
    if req.method == "GET":
        content = f"""
<section class="auth-panel">
  <p class="eyebrow">Password reset</p>
  <h1>Choose a new password</h1>
  <form method="post" class="form">
    {csrf_input(req)}
    <div class="password-field"><input name="password" type="password" placeholder="New password" minlength="8" title="Use at least 8 characters." required><button class="password-toggle" type="button" aria-label="Show new password">Show</button></div>
    <p class="password-hint">Use at least 8 characters. Letters, numbers, and special characters are all accepted.</p>
    <div class="password-field"><input name="password2" type="password" placeholder="Confirm password" minlength="8" required><button class="password-toggle" type="button" aria-label="Show confirmation password">Show</button></div>
    <button>Set new password</button>
  </form>
</section>"""
        return layout(req, "Reset Password", content)
    if err := csrf_protected(req):
        return err
    form, _ = parse_form(req)
    pw  = form.get("password", "")
    pw2 = form.get("password2", "")
    if error := password_error(pw):
        return layout(req, "Reset Password",
            f'<section class="auth-panel"><p class="error">{esc(error)}</p>'
            f'<a class="button-link" href="/reset-password/{esc(token)}">Try again</a></section>')
    if pw != pw2:
        return layout(req, "Reset Password",
            f'<section class="auth-panel"><p class="error">Passwords do not match.</p>'
            f'<a class="button-link" href="/reset-password/{esc(token)}">Try again</a></section>')
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, failed_logins=0, locked_until=0 WHERE id=?",
            (password_hash(pw), row["user_id"]),
        )
        conn.execute(
            "UPDATE password_resets SET used=1 WHERE token=?", (token,)
        )
        # Invalidate all sessions so the old password can't be used
        conn.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
    return layout(
        req, "Password Reset",
        '<section class="auth-panel"><p class="eyebrow">Password reset</p>'
        '<h1>&#10003; Password updated</h1>'
        '<p class="muted">Your password has been changed. You can now log in with your new password.</p>'
        '<a class="button-link" href="/login">Log in</a></section>',
    )


# ---------------------------------------------------------------------------
# Public seller profile  /seller/<id>
# ---------------------------------------------------------------------------
def public_seller_profile(req, seller_id):
    with db() as conn:
        seller = conn.execute(
            "SELECT id, name, university, faculty, year, bio, role, created_at FROM users WHERE id=?",
            (seller_id,),
        ).fetchone()
        if not seller or seller["role"] == "admin":
            return layout(req, "Not Found", '<p class="empty">Seller not found.</p>')
        listings = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM listings l JOIN users u ON u.id=l.user_id
               WHERE l.user_id=? AND l.status='active' ORDER BY l.created_at DESC""",
            (seller_id,),
        ).fetchall()
        review_stats = conn.execute(
            "SELECT count(*) c, avg(rating) avg FROM reviews WHERE reviewed_id=?",
            (seller_id,),
        ).fetchone()
        reviews = conn.execute(
            """SELECT r.*, u.name reviewer FROM reviews r
               JOIN users u ON u.id=r.reviewer_id
               WHERE reviewed_id=? ORDER BY r.created_at DESC LIMIT 10""",
            (seller_id,),
        ).fetchall()
        sold_count = conn.execute(
            "SELECT count(*) c FROM listings WHERE user_id=? AND status='sold'",
            (seller_id,),
        ).fetchone()["c"]

    avg = review_stats["avg"] or 0
    count = review_stats["c"] or 0
    member_since = time.strftime("%B %Y", time.localtime(seller["created_at"]))
    rating_html = stars(avg, count)
    review_list = "".join(
        f"""<li class="review-item">
              <div class="review-meta">
                <span class="stars-inline">{'&#9733;' * r['rating']}{'&#9734;' * (5 - r['rating'])}</span>
                <strong>{esc(r['reviewer'])}</strong>
              </div>
              <p>{esc(r['body'])}</p>
            </li>"""
        for r in reviews
    ) or "<li>No reviews yet.</li>"
    cards = (
        "".join(listing_card(x) for x in listings)
        or '<p class="empty">No active listings.</p>'
    )
    current = current_user(req)
    message_btn = ""
    if current and current["id"] != seller_id:
        message_btn = f'<a class="button-link" href="/inbox">Message seller</a>'

    content = f"""
<section class="seller-profile-header">
  <div class="seller-avatar" aria-hidden="true">{esc(seller['name'][:2].upper())}</div>
  <div class="seller-profile-info">
    <p class="eyebrow">{esc(seller['university'])}</p>
    <h1>{esc(seller['name'])}</h1>
    <p class="seller-meta muted">{esc(seller['faculty'])} &middot; {esc(seller['year'])} &middot; Member since {member_since}</p>
    <div class="seller-rating">{rating_html}</div>
    {f'<p class="seller-bio">{esc(seller["bio"])}</p>' if seller["bio"] else ''}
    <div class="seller-stats-row">
      <span><strong>{len(listings)}</strong> active listing{"s" if len(listings) != 1 else ""}</span>
      <span><strong>{sold_count}</strong> sold</span>
      <span><strong>{count}</strong> review{"s" if count != 1 else ""}</span>
    </div>
    {message_btn}
  </div>
</section>
<section class="toolbar"><h2>Active Listings</h2></section>
<section class="grid">{cards}</section>
<section class="seller-reviews">
  <h2>Reviews</h2>
  <ul class="review-list">{review_list}</ul>
</section>"""
    return layout(req, esc(seller["name"]), content)


# ---------------------------------------------------------------------------
# Threaded messaging helpers
# ---------------------------------------------------------------------------
def get_or_create_conversation(conn, listing_id, buyer_id, seller_id):
    """Return conversation id, creating a row if needed."""
    row = conn.execute(
        "SELECT id FROM conversations WHERE listing_id=? AND buyer_id=? AND seller_id=?",
        (listing_id, buyer_id, seller_id),
    ).fetchone()
    if row:
        return row["id"]
    conn.execute(
        "INSERT INTO conversations(listing_id,buyer_id,seller_id,created_at) VALUES(?,?,?,?)",
        (listing_id, buyer_id, seller_id, now()),
    )
    return conn.execute(
        "SELECT id FROM conversations WHERE listing_id=? AND buyer_id=? AND seller_id=?",
        (listing_id, buyer_id, seller_id),
    ).fetchone()["id"]


# ---------------------------------------------------------------------------
# Conversation thread view  /conversation/<id>
# ---------------------------------------------------------------------------
def conversation_view(req, conv_id):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        conv = conn.execute(
            """SELECT c.*, l.title listing_title, l.status listing_status,
                      b.name buyer_name, s.name seller_name
               FROM conversations c
               JOIN listings l ON l.id=c.listing_id
               JOIN users b ON b.id=c.buyer_id
               JOIN users s ON s.id=c.seller_id
               WHERE c.id=?""",
            (conv_id,),
        ).fetchone()
        if not conv:
            return layout(req, "Not Found", '<p class="empty">Conversation not found.</p>', user)
        is_participant = user["id"] in (conv["buyer_id"], conv["seller_id"])
        if not is_participant and user["role"] != "admin":
            return layout(req, "Forbidden", '<p class="error">You are not part of this conversation.</p>', user)
        # Mark messages to this user as read
        conn.execute(
            "UPDATE messages SET is_read=1 WHERE conversation_id=? AND receiver_id=?",
            (conv_id, user["id"]),
        )
        messages = conn.execute(
            """SELECT m.*, u.name sender_name FROM messages m
               JOIN users u ON u.id=m.sender_id
               WHERE m.conversation_id=? ORDER BY m.created_at ASC""",
            (conv_id,),
        ).fetchall()

    other_id = conv["seller_id"] if user["id"] == conv["buyer_id"] else conv["buyer_id"]
    other_name = conv["seller_name"] if user["id"] == conv["buyer_id"] else conv["buyer_name"]
    msg_html = "".join(
        f"""<div class="message {'message-mine' if m['sender_id'] == user['id'] else 'message-theirs'}">
              <span class="message-author">{esc(m['sender_name'])}</span>
              <p>{esc(m['body'])}</p>
              <span class="message-time">{time.strftime('%d %b %Y %H:%M', time.localtime(m['created_at']))}</span>
            </div>"""
        for m in messages
    ) or '<p class="muted">No messages yet. Start the conversation below.</p>'

    reply_form = ""
    if conv["listing_status"] == "active" or user["role"] == "admin":
        reply_form = f"""
<form method="post" action="/conversation/{conv_id}/reply" class="reply-form">
  <textarea name="body" placeholder="Type a message..." required></textarea>
  <button>Send</button>
</form>"""

    content = f"""
<section class="conversation-header">
  <div>
    <p class="eyebrow">Conversation</p>
    <h1><a href="/listing/{conv['listing_id']}">{esc(conv['listing_title'])}</a></h1>
    <p class="muted">With <a href="/seller/{other_id}">{esc(other_name)}</a></p>
  </div>
  <a class="button-link" href="/inbox">Back to Inbox</a>
</section>
<section class="thread">{msg_html}</section>
{reply_form}"""
    return layout(req, f"Conversation — {conv['listing_title']}", content, user)


def conversation_reply(req, conv_id):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    body = form.get("body", "").strip()
    if not body:
        return redirect(f"/conversation/{conv_id}")
    with db() as conn:
        conv = conn.execute(
            "SELECT c.*, l.status listing_status FROM conversations c JOIN listings l ON l.id=c.listing_id WHERE c.id=?",
            (conv_id,),
        ).fetchone()
        if not conv:
            return redirect("/inbox")
        is_participant = user["id"] in (conv["buyer_id"], conv["seller_id"])
        if not is_participant:
            return redirect("/inbox")
        receiver_id = conv["seller_id"] if user["id"] == conv["buyer_id"] else conv["buyer_id"]
        conn.execute(
            "INSERT INTO messages(conversation_id,listing_id,sender_id,receiver_id,body,is_read,created_at) VALUES(?,?,?,?,?,?,?)",
            (conv_id, conv["listing_id"], user["id"], receiver_id, body, 0, now()),
        )
        receiver = conn.execute("SELECT email, name FROM users WHERE id=?", (receiver_id,)).fetchone()
        listing = conn.execute("SELECT title FROM listings WHERE id=?", (conv["listing_id"],)).fetchone()

    threading.Thread(
        target=send_message_notification,
        args=(receiver["email"], user["name"], listing["title"], conv_id),
        daemon=True,
    ).start()
    return redirect(f"/conversation/{conv_id}")


# ---------------------------------------------------------------------------
# Inbox — now shows conversations grouped by thread
# ---------------------------------------------------------------------------
def inbox(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        conversations = conn.execute(
            """SELECT c.id, c.listing_id, l.title listing_title,
                      b.name buyer_name, b.id buyer_id,
                      s.name seller_name, s.id seller_id,
                      (SELECT body FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) last_msg,
                      (SELECT created_at FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) last_at,
                      (SELECT count(*) FROM messages WHERE conversation_id=c.id AND receiver_id=? AND is_read=0) unread
               FROM conversations c
               JOIN listings l ON l.id=c.listing_id
               JOIN users b ON b.id=c.buyer_id
               JOIN users s ON s.id=c.seller_id
               WHERE c.buyer_id=? OR c.seller_id=?
               ORDER BY last_at DESC NULLS LAST""",
            (user["id"], user["id"], user["id"]),
        ).fetchall()
        offers = conn.execute(
            """SELECT o.*, l.title, b.name buyer FROM offers o
               JOIN listings l ON l.id=o.listing_id
               JOIN users b ON b.id=o.buyer_id
               WHERE seller_id=? OR buyer_id=?
               ORDER BY o.created_at DESC""",
            (user["id"], user["id"]),
        ).fetchall()

    conv_html = ""
    for c in conversations:
        other_name = c["seller_name"] if user["id"] == c["buyer_id"] else c["buyer_name"]
        other_id = c["seller_id"] if user["id"] == c["buyer_id"] else c["buyer_id"]
        unread_badge = f' <span class="badge">{c["unread"]}</span>' if c["unread"] else ""
        last_time = time.strftime("%d %b", time.localtime(c["last_at"])) if c["last_at"] else ""
        conv_html += f"""
<li class="conv-item">
  <a href="/conversation/{c['id']}" class="conv-link">
    <div class="conv-title">{esc(c['listing_title'])}{unread_badge}</div>
    <div class="conv-meta muted">With <strong><a href="/seller/{other_id}">{esc(other_name)}</a></strong> &middot; {last_time}</div>
    {f'<div class="conv-preview muted">{esc(c["last_msg"][:80])}{"..." if c["last_msg"] and len(c["last_msg"]) > 80 else ""}</div>' if c["last_msg"] else ''}
  </a>
</li>"""

    if not conv_html:
        conv_html = "<li>No conversations yet.</li>"

    off_html = "".join(
        f"<li><a href='/listing/{o['listing_id']}'>{esc(o['title'])}</a>: {esc(o['buyer'])} offered {money(o['amount'])} &middot; {esc(o['status'])}</li>"
        for o in offers
    ) or "<li>No offers yet.</li>"

    content = f"""
<section class="toolbar"><h1>Inbox</h1></section>
<section class="columns">
  <div>
    <h2>Conversations</h2>
    <ul class="conv-list">{conv_html}</ul>
  </div>
  <div>
    <h2>Offers</h2>
    <ul>{off_html}</ul>
  </div>
</section>"""
    return layout(req, "Inbox", content, user)


# ---------------------------------------------------------------------------
# Listing pages
# ---------------------------------------------------------------------------
def save_upload(filetuple, allow_docs=False):
    if not filetuple:
        return ""
    filename, data = filetuple
    if not data:
        return ""
    allowed = [
        (b"\xff\xd8\xff", ".jpg"), (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"GIF87a", ".gif"), (b"GIF89a", ".gif"), (b"RIFF", ".webp"),
    ]
    if allow_docs:
        allowed += [
            (b"%PDF", ".pdf"),
            (b"PK\x03\x04", ".docx"),
            (b"\xd0\xcf\x11\xe0", ".doc"),
        ]
    ext = ""
    for sig, suffix in allowed:
        if data.startswith(sig):
            ext = suffix
            break
    max_size = 5_000_000 if allow_docs else 3_000_000
    if not ext or len(data) > max_size:
        return ""
    name = secrets.token_hex(12) + ext
    (UPLOADS / name).write_bytes(data)
    return "/uploads/" + name


def listing_form(req, row=None, error="", gallery=None):
    user, resp = require_seller(req)
    if resp:
        return resp
    cats = "".join(
        f'<option {"selected" if row and row["category"] == c else ""}>{esc(c)}</option>'
        for c in CATEGORIES
    )
    condition_value = row["condition"] if row else ""
    conditions = ("New", "Used - Like New", "Used - Excellent", "Used - Good", "Used - Fair", "Service")
    condition_options = '<option value="">Select condition</option>' + "".join(
        f'<option {"selected" if condition_value == condition else ""}>{condition}</option>'
        for condition in conditions
    )
    if condition_value and condition_value not in conditions:
        condition_options += f'<option selected>{esc(condition_value)}</option>'
    existing_imgs = ""
    if gallery:
        thumbs = "".join(
            f'<img src="{esc(img["image_path"])}" alt="" class="gallery-thumb-sm">'
            for img in gallery
        )
        existing_imgs = f'<div class="gallery-strip">{thumbs}</div><p class="muted" style="font-size:13px">Upload new photos to replace existing ones.</p>'
    photo_inputs = "".join(
        f'<input name="photo_{i}" type="file" accept="image/png,image/jpeg,image/gif,image/webp" aria-label="Photo {i+1}">'
        for i in range(5)
    )
    expiry_note = ""
    if row and row["expires_at"]:
        days_left = max(0, (row["expires_at"] - now()) // 86400)
        expiry_note = f'<p class="muted" style="font-size:13px">Listing expires in {days_left} day{"s" if days_left != 1 else ""}.</p>'
    content = f"""
<section class="narrow listing-editor">
  <div class="listing-editor-heading"><p class="eyebrow">{('Update your marketplace listing' if row else 'Create a marketplace listing')}</p><h1>{'Edit Listing' if row else 'Post a Listing'}</h1></div>
  {f'<p class="error">{esc(error)}</p>' if error else ''}
  <form method="post" enctype="multipart/form-data" class="form listing-editor-form">
    {csrf_input(req)}
    <input name="title" required placeholder="Title" value="{esc(row['title'] if row else '')}">
    <select name="category">{cats}</select>
    <textarea name="description" required placeholder="Describe the item or service">{esc(row['description'] if row else '')}</textarea>
    <div class="split">
      <input name="price" required type="number" min="0" step="1" placeholder="Price" value="{esc(row['price'] if row else '')}">
      <select name="condition" aria-label="Condition">{condition_options}</select>
    </div>
    <input name="location" placeholder="Pickup location" value="{esc(row['location'] if row else '')}">
    <p style="font-size:13px;font-weight:700;margin:4px 0">Photos (up to 5)</p>
    {existing_imgs}
    {photo_inputs}
    {expiry_note}
    <button>Save Listing</button>
  </form>
</section>"""
    return layout(req, "Listing", content, user)


def create_listing(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    if req.method == "GET":
        return listing_form(req)
    form, files = parse_form(req)
    title = form.get("title", "").strip()
    category = form.get("category", CATEGORIES[0])
    price = as_float(form.get("price"))
    description = form.get("description", "").strip()
    if not title or not description or category not in CATEGORIES or price < 0:
        return listing_form(
            req,
            error="Enter a title, description, valid category, and a price of zero or more.",
        )
    listing_expires = now() + LISTING_TTL
    with db() as conn:
        conn.execute(
            """INSERT INTO listings(user_id,title,category,description,price,condition,
               location,image_path,expires_at,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                user["id"], title, category,
                description,
                price,
                form.get("condition", "").strip(),
                form.get("location", "").strip(),
                "", listing_expires, now(), now(),
            ),
        )
        new_id = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
        # Save up to 5 gallery images
        for i in range(5):
            ft = files.get(f"photo_{i}") or (files.get("photo") if i == 0 else None)
            path = save_upload(ft)
            if path:
                conn.execute(
                    "INSERT INTO listing_images(listing_id,image_path,sort_order,created_at) VALUES(?,?,?,?)",
                    (new_id, path, i, now()),
                )
                if i == 0:  # keep legacy image_path in sync
                    conn.execute("UPDATE listings SET image_path=? WHERE id=?", (path, new_id))
    threading.Thread(target=fire_alerts, args=(new_id, title, category, price), daemon=True).start()
    return redirect("/profile")


def listing_detail(req, listing_id):
    user = current_user(req)
    # Record view for logged-in buyers (not the seller themselves)
    if user:
        threading.Thread(
            target=record_view, args=(user["id"], listing_id), daemon=True
        ).start()
    with db() as conn:
        row = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.email seller_email, u.university
               FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id=?""",
            (listing_id,),
        ).fetchone()
        if not row:
            return layout(req, "Not Found", '<p class="empty">Listing not found.</p>', user)
        offers = conn.execute(
            "SELECT o.*, b.name buyer FROM offers o JOIN users b ON b.id=o.buyer_id WHERE listing_id=? ORDER BY created_at DESC",
            (listing_id,),
        ).fetchall()
        reviews = conn.execute(
            "SELECT r.*, u.name reviewer FROM reviews r JOIN users u ON u.id=r.reviewer_id WHERE reviewed_id=? ORDER BY created_at DESC",
            (row["seller_id"],),
        ).fetchall()
        wished = user and conn.execute(
            "SELECT 1 FROM wishlist WHERE user_id=? AND listing_id=?", (user["id"], listing_id)
        ).fetchone()
        # Find conversation between current user and seller for this listing (if any)
        existing_conv = None
        if user and user["id"] != row["seller_id"]:
            existing_conv = conn.execute(
                "SELECT id FROM conversations WHERE listing_id=? AND buyer_id=? AND seller_id=?",
                (listing_id, user["id"], row["seller_id"]),
            ).fetchone()

    owner = user and user["id"] == row["seller_id"]
    if row["status"] == "removed" and not (user and (owner or user["role"] == "admin")):
        return layout(req, "Not Found", '<p class="empty">Listing not found.</p>', user)

    img = (
        f'<img src="{esc(row["image_path"])}" alt="">'
        if row["image_path"] else '<div class="detail-fallback">UniMarket</div>'
    )
    actions = ""
    if user and not owner and row["status"] == "active":
        conv_link = (
            f'<a class="button-link" href="/conversation/{existing_conv["id"]}">Continue conversation</a>'
            if existing_conv
            else f'<form method="post" action="/message" class="message-start-form"><input type="hidden" name="listing_id" value="{row["id"]}"><input type="hidden" name="receiver_id" value="{row["seller_id"]}"><input name="body" placeholder="Message seller..." required><button>Send Message</button></form>'
        )
        actions = f"""
<form method="post" action="/wishlist/toggle">
  <input type="hidden" name="listing_id" value="{row['id']}">
  <button>{'Remove from Wishlist' if wished else 'Add to Wishlist'}</button>
</form>

{conv_link}
<form method="post" action="/report" class="inline-form">
  <input type="hidden" name="listing_id" value="{row['id']}">
  <input name="reason" placeholder="Report reason">
  <button>Report</button>
</form>"""
    elif row["status"] != "active":
        actions = f'<p class="empty">This listing is {esc(row["status"])}.</p>'
    if owner:
        bump_available = (now() - (row["bumped_at"] or 0)) >= BUMP_COOLDOWN
        bump_btn = (
            f'<form method="post" action="/listing/{row["id"]}/bump">'
            f'<button class="secondary-button bump-btn">&#8679; Bump to Top</button></form>'
            if bump_available else
            '<button class="secondary-button bump-btn bump-disabled" disabled title="Available again in 24 hours">&#8679; Bumped</button>'
        )
        actions = f"""<a class="button-link" href="/listing/{row['id']}/edit">Edit Listing</a>
        {bump_btn}
        {f'<form method="post" action="/listing/sold"><input type="hidden" name="listing_id" value="{row["id"]}"><button class="secondary-button">Mark as Sold</button></form>' if row['status'] == 'active' else ''}"""

    offer_html = "".join(
        f"<li><strong>{esc(o['buyer'])}</strong> offered {money(o['amount'])} &middot; {esc(o['status'])}</li>"
        for o in offers
    ) or "<li>No offers yet.</li>"
    review_html = "".join(
        f"<li><strong>{'&#9733;' * r['rating']}</strong> {esc(r['body'])} <span>{esc(r['reviewer'])}</span></li>"
        for r in reviews
    ) or "<li>No reviews yet.</li>"
    review_form = ""
    if user and not owner:
        review_form = f"""<form method="post" action="/review" class="inline-form">
  <input type="hidden" name="listing_id" value="{row['id']}">
  <input type="hidden" name="reviewed_id" value="{row['seller_id']}">
  <select name="rating"><option>5</option><option>4</option><option>3</option><option>2</option><option>1</option></select>
  <input name="body" placeholder="Review seller">
  <button>Review</button>
</form>"""

    content = f"""
<section class="detail">
  <div class="detail-media">{img}</div>
  <div class="detail-copy">
    <p class="eyebrow">{esc(row['category'])}</p>
    <h1>{esc(row['title'])}</h1>
    <strong class="price">{money(row['price'])}</strong>
    <p>{esc(row['description'])}</p>
    <p class="muted">{esc(row['condition'])} &middot; {esc(row['location'])} &middot; {esc(row['university'])}</p>
    <p class="muted">Seller: <a href="/seller/{row['seller_id']}">{esc(row['seller'])}</a></p>
    {f'<form method="post" action="/order" class="actions"><input type="hidden" name="listing_id" value="{row["id"]}"><button type="submit">Buy now</button></form>' if user and user["id"] != row["seller_id"] and user["role"] != "admin" else ""}
    {f'<p class="muted bump-count">&#8679; Bumped {row["bump_count"]} time{"s" if row["bump_count"] != 1 else ""}</p>' if owner and row["bump_count"] else ''}
    <div class="actions">{actions}</div>
  </div>
</section>
<section class="columns">
  <div><h2>Offers</h2><ul>{offer_html}</ul></div>
  <div><h2>Seller Reviews</h2>{review_form}<ul>{review_html}</ul></div>
</section>"""
    return layout(req, row["title"], content, user)


def edit_listing(req, listing_id):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        row = conn.execute("SELECT * FROM listings WHERE id=?", (listing_id,)).fetchone()
        if not row or (row["user_id"] != user["id"] and user["role"] != "admin"):
            return layout(req, "Forbidden", '<p class="error">You cannot edit this listing.</p>', user)
        gallery = conn.execute(
            "SELECT * FROM listing_images WHERE listing_id=? ORDER BY sort_order", (listing_id,)
        ).fetchall()
        if req.method == "GET":
            return listing_form(req, row, gallery=gallery)
        form, files = parse_form(req)
        new_imgs = [save_upload(files.get(f"photo_{i}")) for i in range(5)]
        new_imgs = [p for p in new_imgs if p]
        if new_imgs:
            conn.execute("DELETE FROM listing_images WHERE listing_id=?", (listing_id,))
            for i, path in enumerate(new_imgs):
                conn.execute(
                    "INSERT INTO listing_images(listing_id,image_path,sort_order,created_at) VALUES(?,?,?,?)",
                    (listing_id, path, i, now()),
                )
            primary = new_imgs[0]
        else:
            primary = row["image_path"]
        conn.execute(
            "UPDATE listings SET title=?,category=?,description=?,price=?,condition=?,"
            "location=?,image_path=?,updated_at=? WHERE id=?",
            (
                form.get("title", "").strip(), form.get("category", ""),
                form.get("description", "").strip(), as_float(form.get("price")),
                form.get("condition", "").strip(), form.get("location", "").strip(),
                primary, now(), listing_id,
            ),
        )
    return redirect(f"/listing/{listing_id}")


def mark_listing_sold(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    with db() as conn:
        conn.execute(
            "UPDATE listings SET status='sold', updated_at=? WHERE id=? AND user_id=? AND status='active'",
            (now(), as_int(form.get("listing_id")), user["id"]),
        )
    return redirect("/profile")


def renew_listing(req, listing_id):
    """Renew an expired listing for another 60 days."""
    user, resp = require_seller(req)
    if resp:
        return resp
    if err := csrf_protected(req):
        return err
    with db() as conn:
        row = conn.execute(
            "SELECT user_id, status FROM listings WHERE id=?", (listing_id,)
        ).fetchone()
        if not row or row["user_id"] != user["id"]:
            return layout(req, "Forbidden", '<p class="error">Not your listing.</p>', user)
        if row["status"] not in ("expired", "active"):
            return redirect(f"/listing/{listing_id}")
        conn.execute(
            "UPDATE listings SET status='active', expires_at=?, updated_at=? WHERE id=?",
            (now() + LISTING_TTL, now(), listing_id),
        )
    return redirect(f"/listing/{listing_id}")


BUMP_COOLDOWN = 86400  # 24 hours


def bump_listing(req, listing_id):
    user, resp = require_seller(req)
    if resp:
        return resp
    with db() as conn:
        row = conn.execute(
            "SELECT user_id, status, bumped_at, bump_count FROM listings WHERE id=?",
            (listing_id,),
        ).fetchone()
        if not row:
            return layout(req, "Not Found", '<p class="empty">Listing not found.</p>', user)
        if row["user_id"] != user["id"]:
            return layout(req, "Forbidden", '<p class="error">Not your listing.</p>', user)
        if row["status"] != "active":
            return redirect(f"/listing/{listing_id}")
        since_last = now() - (row["bumped_at"] or 0)
        if since_last < BUMP_COOLDOWN:
            wait_h = int((BUMP_COOLDOWN - since_last) // 3600) + 1
            return layout(
                req, "Bump unavailable",
                f'<section class="auth-panel"><p class="eyebrow">Bump listing</p>'
                f'<h1>Too soon to bump</h1>'
                f'<p class="muted">You can bump this listing again in about {wait_h} hour{"s" if wait_h != 1 else ""}.</p>'
                f'<a class="button-link" href="/listing/{listing_id}">Back to listing</a></section>',
                user,
            )
        conn.execute(
            "UPDATE listings SET bumped_at=?, bump_count=bump_count+1, updated_at=? WHERE id=?",
            (now(), now(), listing_id),
        )
    return redirect(f"/listing/{listing_id}")


# ---------------------------------------------------------------------------
# Messaging — new conversation start from listing page
# ---------------------------------------------------------------------------
def post_message(req):
    """Create a new conversation + first message from the listing detail page."""
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    lid = as_int(form.get("listing_id"))
    body = form.get("body", "").strip()
    if not body:
        return redirect(f"/listing/{lid}")
    with db() as conn:
        listing = conn.execute(
            "SELECT user_id, status, title FROM listings WHERE id=?", (lid,)
        ).fetchone()
        if not listing or listing["status"] != "active" or listing["user_id"] == user["id"]:
            return redirect(f"/listing/{lid}")
        seller_id = listing["user_id"]
        conv_id = get_or_create_conversation(conn, lid, user["id"], seller_id)
        conn.execute(
            "INSERT INTO messages(conversation_id,listing_id,sender_id,receiver_id,body,is_read,created_at) VALUES(?,?,?,?,?,?,?)",
            (conv_id, lid, user["id"], seller_id, body, 0, now()),
        )
        seller = conn.execute("SELECT email, name FROM users WHERE id=?", (seller_id,)).fetchone()

    threading.Thread(
        target=send_message_notification,
        args=(seller["email"], user["name"], listing["title"], conv_id),
        daemon=True,
    ).start()
    return redirect(f"/conversation/{conv_id}")


# ---------------------------------------------------------------------------
# Offers, Wishlist, Reviews, Reports
# ---------------------------------------------------------------------------
def wishlist_toggle(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    lid = as_int(form.get("listing_id"))
    with db() as conn:
        listing = conn.execute("SELECT 1 FROM listings WHERE id=?", (lid,)).fetchone()
        if not listing:
            return redirect("/")
        exists = conn.execute(
            "SELECT 1 FROM wishlist WHERE user_id=? AND listing_id=?", (user["id"], lid)
        ).fetchone()
        if exists:
            conn.execute("DELETE FROM wishlist WHERE user_id=? AND listing_id=?", (user["id"], lid))
        else:
            conn.execute(
                "INSERT OR IGNORE INTO wishlist(user_id,listing_id,created_at) VALUES(?,?,?)",
                (user["id"], lid, now()),
            )
    return redirect(f"/listing/{lid}")


def post_offer(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    lid = as_int(form.get("listing_id"))
    amount = as_float(form.get("amount"))
    if amount <= 0:
        return redirect(f"/listing/{lid}")
    with db() as conn:
        listing = conn.execute("SELECT user_id, status FROM listings WHERE id=?", (lid,)).fetchone()
        if listing and listing["status"] == "active" and listing["user_id"] != user["id"]:
            conn.execute(
                "INSERT INTO offers(listing_id,buyer_id,seller_id,amount,note,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (lid, user["id"], listing["user_id"], amount,
                 form.get("note", "").strip(), now() + OFFER_TTL, now(), now()),
            )
    return redirect(f"/listing/{lid}")


def update_offer_status(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    status = form.get("status", "")
    if status not in ("accepted", "declined"):
        return redirect("/seller")
    with db() as conn:
        offer = conn.execute(
            "SELECT listing_id FROM offers WHERE id=? AND seller_id=? AND status='pending'",
            (as_int(form.get("offer_id")), user["id"]),
        ).fetchone()
        if not offer:
            return redirect("/seller")
        conn.execute(
            "UPDATE offers SET status=?, updated_at=? WHERE id=? AND seller_id=? AND status='pending'",
            (status, now(), as_int(form.get("offer_id")), user["id"]),
        )
        if status == "accepted":
            conn.execute(
                "UPDATE listings SET status='sold', updated_at=? WHERE id=? AND user_id=?",
                (now(), offer["listing_id"], user["id"]),
            )
            conn.execute(
                "UPDATE offers SET status='declined', updated_at=? WHERE listing_id=? AND id<>? AND status='pending'",
                (now(), offer["listing_id"], as_int(form.get("offer_id"))),
            )
    return redirect("/seller")


def post_review(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    lid = as_int(form.get("listing_id"))
    rating = max(1, min(5, as_int(form.get("rating"), 5)))
    with db() as conn:
        conn.execute(
            "INSERT INTO reviews(listing_id,reviewer_id,reviewed_id,rating,body,created_at) VALUES(?,?,?,?,?,?)",
            (lid, user["id"], as_int(form.get("reviewed_id")), rating, form.get("body", "").strip(), now()),
        )
    return redirect(f"/listing/{lid}")


def post_report(req):
    user, resp = require_user(req)
    if resp:
        return resp
    form, _ = parse_form(req)
    lid = as_int(form.get("listing_id"))
    with db() as conn:
        conn.execute(
            "INSERT INTO reports(listing_id,reporter_id,reason,created_at) VALUES(?,?,?,?)",
            (lid, user["id"], form.get("reason", "").strip(), now()),
        )
    return redirect(f"/listing/{lid}")


# ---------------------------------------------------------------------------
# Profile completeness
# ---------------------------------------------------------------------------
_COMPLETENESS_FIELDS = [
    ("name",       "Full name"),
    ("university", "University"),
    ("faculty",    "Faculty"),
    ("year",       "Year of study"),
    ("phone",      "Phone number"),
    ("bio",        "Bio"),
]

def profile_completeness(user):
    """Return (pct:int, missing:list[str]) for the user's profile."""
    missing = [label for field, label in _COMPLETENESS_FIELDS if not user[field]]
    filled  = len(_COMPLETENESS_FIELDS) - len(missing)
    pct     = round(filled / len(_COMPLETENESS_FIELDS) * 100)
    return pct, missing

def completeness_bar_html(pct, missing):
    colour = "#477567" if pct == 100 else ("#d6a21e" if pct >= 50 else "#b42318")
    tip = (
        "Profile complete!" if pct == 100
        else "Still needed: " + ", ".join(missing)
    )
    return f"""
<div class="completeness-wrap" title="{esc(tip)}">
  <div class="completeness-label">
    <span>Profile completeness</span>
    <span class="completeness-pct">{pct}%</span>
  </div>
  <div class="completeness-track">
    <div class="completeness-fill" style="width:{pct}%;background:{colour}"></div>
  </div>
  {f'<p class="completeness-tip muted">Add: {esc(", ".join(missing))}</p>' if missing else ''}
</div>"""


# ---------------------------------------------------------------------------
# Recently viewed helper
# ---------------------------------------------------------------------------
def record_view(user_id, listing_id):
    """Upsert a recently-viewed row, keeping only the 20 most recent per user."""
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO recently_viewed(user_id,listing_id,viewed_at) VALUES(?,?,?) "
                "ON CONFLICT(user_id,listing_id) DO UPDATE SET viewed_at=excluded.viewed_at",
                (user_id, listing_id, now()),
            )
            # Prune to 20 most recent
            oldest = conn.execute(
                "SELECT viewed_at FROM recently_viewed WHERE user_id=? "
                "ORDER BY viewed_at DESC LIMIT 1 OFFSET 19",
                (user_id,),
            ).fetchone()
            if oldest:
                conn.execute(
                    "DELETE FROM recently_viewed WHERE user_id=? AND viewed_at<?",
                    (user_id, oldest["viewed_at"]),
                )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Buyer dashboard  /buyer
# ---------------------------------------------------------------------------
def dashboard_profile_panel(user):
    photo = f'<img src="{esc(user["profile_image_path"])}" alt="Profile photo of {esc(user["name"])}">' if user["profile_image_path"] else f'<span>{esc(user["name"][:2].upper())}</span>'
    details = " · ".join(x for x in (user["university"], user["faculty"], user["year"]) if x)
    bio = f'<p>{esc(user["bio"][:180])}</p>' if user["bio"] else '<p class="muted">Add a short introduction so other marketplace users know who they are dealing with.</p>'
    return f'<section class="dashboard-profile-panel"><div class="dashboard-profile-photo">{photo}</div><div class="dashboard-profile-copy"><p class="eyebrow">Your profile</p><h2>{esc(user["name"])}</h2><p class="muted">{esc(details or "Add your university and study details")}</p>{bio}</div><a class="text-link" href="/profile/edit">Edit profile</a></section>'

def buyer_dashboard(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        wishlist_count = conn.execute(
            "SELECT count(*) c FROM wishlist WHERE user_id=?", (user["id"],)
        ).fetchone()["c"]
        conv_count = conn.execute(
            "SELECT count(*) c FROM conversations WHERE buyer_id=?", (user["id"],)
        ).fetchone()["c"]
        unread = conn.execute(
            "SELECT count(*) c FROM messages WHERE receiver_id=? AND is_read=0",
            (user["id"],),
        ).fetchone()["c"]
        pending_offers = conn.execute(
            "SELECT count(*) c FROM offers WHERE buyer_id=? AND status='pending'",
            (user["id"],),
        ).fetchone()["c"]
        recent_offers = conn.execute(
            """SELECT o.*, l.title, l.id listing_id FROM offers o
               JOIN listings l ON l.id=o.listing_id
               WHERE o.buyer_id=? ORDER BY o.updated_at DESC LIMIT 5""",
            (user["id"],),
        ).fetchall()
        recent_convs = conn.execute(
            """SELECT c.id, l.title listing_title, s.name seller_name, s.id seller_id,
                      (SELECT body FROM messages WHERE conversation_id=c.id
                       ORDER BY created_at DESC LIMIT 1) last_msg,
                      (SELECT count(*) FROM messages WHERE conversation_id=c.id
                       AND receiver_id=? AND is_read=0) unread
               FROM conversations c
               JOIN listings l ON l.id=c.listing_id
               JOIN users s ON s.id=c.seller_id
               WHERE c.buyer_id=? ORDER BY c.created_at DESC LIMIT 5""",
            (user["id"], user["id"]),
        ).fetchall()
        viewed = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM recently_viewed rv
               JOIN listings l ON l.id=rv.listing_id
               JOIN users u ON u.id=l.user_id
               WHERE rv.user_id=? AND l.status='active'
               ORDER BY rv.viewed_at DESC LIMIT 8""",
            (user["id"],),
        ).fetchall()

    pct, missing = profile_completeness(user)

    offer_status_chip = {
        "pending":  '<span class="chip chip-pending">Pending</span>',
        "accepted": '<span class="chip chip-accepted">Accepted</span>',
        "declined": '<span class="chip chip-declined">Declined</span>',
        "expired":  '<span class="chip chip-expired">Expired</span>',
    }
    offers_html = "".join(
        f"""<li class="activity-list-item">
          <a href="/listing/{o['listing_id']}">{esc(o['title'])}</a>
          {offer_status_chip.get(o['status'], f'<span class="chip">{esc(o["status"])}</span>')}
          <span class="muted">{money(o['amount'])}</span>
        </li>"""
        for o in recent_offers
    ) or "<li>No offers yet.</li>"

    convs_html = "".join(
        f"""<li class="activity-list-item">
          <a href="/conversation/{c['id']}">{esc(c['listing_title'])}</a>
          {f'<span class="badge">{c["unread"]}</span>' if c["unread"] else ""}
          <span class="muted">with <a href="/seller/{c['seller_id']}">{esc(c['seller_name'])}</a></span>
        </li>"""
        for c in recent_convs
    ) or "<li>No conversations yet.</li>"

    viewed_html = (
        "".join(listing_card(x) for x in viewed)
        or '<p class="empty">No recently viewed listings.</p>'
    )

    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow">Buyer hub</p>
    <h1>My Dashboard</h1>
  </div>
  <a class="button-link" href="/">Browse Listings</a>
</section>
{dashboard_profile_panel(user)}
{completeness_bar_html(pct, missing)}
<section class="stat-grid buyer-stats">
  {stat_card("❤️", wishlist_count, "Wishlist items", "coral", href="/wishlist")}
  {stat_card("🤝", pending_offers, "Pending offers", "amber", href="/buyer/offers")}
  {stat_card("💬", conv_count, "Conversations", "blue", href="/inbox")}
  {stat_card("🔔", unread, "Unread messages", "teal" if not unread else "coral", href="/inbox")}
</section>
<section class="columns">
  <div>
    <div class="section-heading">
      <h2>Recent Offers</h2>
      <a class="text-link" href="/buyer/offers">View all</a>
    </div>
    <ul class="activity-list">{offers_html}</ul>
  </div>
  <div>
    <div class="section-heading">
      <h2>Recent Conversations</h2>
      <a class="text-link" href="/inbox">View all</a>
    </div>
    <ul class="activity-list">{convs_html}</ul>
  </div>
</section>
<section class="toolbar" style="margin-top:28px">
  <h2>Recently Viewed</h2>
  <a class="text-link" href="/buyer/history">View all</a>
</section>
<section class="grid">{viewed_html}</section>"""
    return layout(req, "Buyer Dashboard", content, user)


# ---------------------------------------------------------------------------
# Recently viewed history  /buyer/history
# ---------------------------------------------------------------------------
def buyer_history(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        rows = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM recently_viewed rv
               JOIN listings l ON l.id=rv.listing_id
               JOIN users u ON u.id=l.user_id
               WHERE rv.user_id=?
               ORDER BY rv.viewed_at DESC""",
            (user["id"],),
        ).fetchall()
    cards = (
        "".join(listing_card(x) for x in rows)
        or '<p class="empty">You haven\'t viewed any listings yet.</p>'
    )
    content = f"""
<section class="toolbar">
  <div><p class="eyebrow">Your activity</p><h1>Recently Viewed</h1></div>
  <a class="button-link" href="/">Browse Listings</a>
</section>
<section class="grid">{cards}</section>"""
    return layout(req, "Recently Viewed", content, user)



# ---------------------------------------------------------------------------
# Buyer reports  /buyer/reports
# ---------------------------------------------------------------------------
def buyer_reports_page(req):
    user, resp = require_user(req)
    if resp:
        return resp
    start, end, start_ts, end_ts = _date_range(req)
    if not start:
        start = time.strftime('%Y-%m-01')
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d")))
    if not end:
        end = time.strftime('%Y-%m-%d')
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399
    with db() as conn:
        purchases = conn.execute(
            """SELECT o.id, o.amount, o.payment_status, o.delivery_status, o.created_at,
                      l.title, l.category, s.name seller_name
               FROM orders o
               JOIN listings l ON l.id=o.listing_id
               JOIN users s ON s.id=o.seller_id
               WHERE o.buyer_id=? AND o.created_at>=? AND o.created_at<=?
               ORDER BY o.created_at DESC""",
            (user["id"], start_ts, end_ts),
        ).fetchall()
        total_spend = sum(r["amount"] for r in purchases if r["payment_status"] == "paid")
        total_orders = len(purchases)
        paid_count = sum(1 for r in purchases if r["payment_status"] == "paid")
        # Spending by category
        cat_spend = {}
        for r in purchases:
            if r["payment_status"] == "paid":
                cat_spend[r["category"]] = cat_spend.get(r["category"], 0) + r["amount"]
        cat_labels = list(cat_spend.keys())
        cat_values = [int(cat_spend[c]) for c in cat_labels]
        # Monthly spending trend
        month_spend = {}
        for r in purchases:
            if r["payment_status"] == "paid":
                m = time.strftime('%Y-%m', time.gmtime(r["created_at"]))
                month_spend[m] = month_spend.get(m, 0) + r["amount"]
        sorted_months = sorted(month_spend.keys())
        month_labels = sorted_months
        month_values = [int(month_spend[m]) for m in sorted_months]

    cat_chart = svg_donut_chart(cat_labels, cat_values) if cat_labels else '<p class="muted">No purchase data yet.</p>'
    trend_chart = svg_bar_chart(month_labels, month_values) if month_labels else '<p class="muted">No purchase data yet.</p>'

    rows_html = "".join(
        f"""<tr>
            <td>#{r['id']:05d}</td>
            <td>{esc(r['title'])}</td>
            <td>{esc(r['category'])}</td>
            <td>{esc(r['seller_name'])}</td>
            <td><strong>{money(r['amount'])}</strong></td>
            <td><span class="chip chip-{esc(r['payment_status'])}">{esc(r['payment_status'].title())}</span></td>
            <td>{time.strftime('%Y-%m-%d', time.gmtime(r['created_at']))}</td>
        </tr>"""
        for r in purchases
    ) or '<tr><td colspan="7" class="muted">No purchases found in this period.</td></tr>'

    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow">Buyer reports</p>
    <h1>Your Purchase Reports</h1>
    <p class="muted">View and download reports on items you have bought.</p>
  </div>
</section>
<section class="admin-section report-builder">
  <h2>Filter by date range</h2>
  <form method="get" action="/buyer/reports" class="form">
    <div class="split">
      <div><label class="field-label" for="start">From</label><input id="start" type="date" name="start" value="{esc(start)}" required></div>
      <div><label class="field-label" for="end">To</label><input id="end" type="date" name="end" value="{esc(end)}" required></div>
    </div>
    <button>Apply Filter</button>
  </form>
</section>
<section class="stat-grid">
  {stat_card("🛒", total_orders, "Total Orders", "amber")}
  {stat_card("✅", paid_count, "Paid Orders", "teal")}
  {stat_card("💰", money(total_spend), "Total Spend", "blue")}
</section>
<section class="admin-section admin-charts">
  <div class="chart-grid">
    <div class="chart-card"><h3>Spending by Category</h3>{cat_chart}</div>
    <div class="chart-card"><h3>Monthly Spend Trend</h3>{trend_chart}</div>
  </div>
</section>
<section class="admin-section">
  <div class="section-heading">
    <h2>Purchase History</h2>
    <a class="button-link" href="/buyer/reports/download?start={esc(start)}&end={esc(end)}">Download CSV</a>
  </div>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Order</th><th>Item</th><th>Category</th><th>Seller</th><th>Amount</th><th>Payment</th><th>Date</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>
</section>"""
    return layout(req, "Purchase Reports", content, user)


def buyer_reports_download(req):
    user, resp = require_user(req)
    if resp:
        return resp
    import csv as _csv
    from io import StringIO
    start, end, start_ts, end_ts = _date_range(req)
    if not start:
        start = time.strftime('%Y-%m-01')
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d")))
    if not end:
        end = time.strftime('%Y-%m-%d')
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399
    buf = StringIO()
    writer = _csv.writer(buf)
    writer.writerow(["Order ID", "Item", "Category", "Seller", "Amount (KES)", "Payment Status", "Delivery Status", "Date"])
    with db() as conn:
        rows = conn.execute(
            """SELECT o.id, o.amount, o.payment_status, o.delivery_status, o.created_at,
                      l.title, l.category, s.name seller_name
               FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users s ON s.id=o.seller_id
               WHERE o.buyer_id=? AND o.created_at>=? AND o.created_at<=?
               ORDER BY o.created_at DESC""",
            (user["id"], start_ts, end_ts),
        ).fetchall()
    for r in rows:
        writer.writerow([r["id"], r["title"], r["category"], r["seller_name"], r["amount"],
                         r["payment_status"], r["delivery_status"],
                         time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created_at"]))])
    filename = f"unimarket-purchases-{start or 'all'}-to-{end or 'now'}.csv"
    return Response(buf.getvalue(), 200, "text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# My offers  /buyer/offers  +  cancel offer  POST /buyer/offers/cancel
# ---------------------------------------------------------------------------
def buyer_offers(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        offers = conn.execute(
            """SELECT o.*, l.title, l.id listing_id, l.status listing_status,
                      l.price listing_price
               FROM offers o JOIN listings l ON l.id=o.listing_id
               WHERE o.buyer_id=? ORDER BY o.created_at DESC""",
            (user["id"],),
        ).fetchall()

    chip_class = {
        "pending":  "chip-pending",
        "accepted": "chip-accepted",
        "declined": "chip-declined",
        "expired":  "chip-expired",
    }
    rows_html = ""
    for o in offers:
        expires_str = ""
        if o["status"] == "pending" and o["expires_at"]:
            secs = o["expires_at"] - now()
            if secs > 0:
                days = secs // 86400
                hrs  = (secs % 86400) // 3600
                expires_str = f'<span class="muted offer-expiry">Expires in {days}d {hrs}h</span>'
            else:
                expires_str = '<span class="muted offer-expiry">Expiring…</span>'
        cancel_btn = ""
        if o["status"] == "pending":
            cancel_btn = f"""
<form method="post" action="/buyer/offers/cancel">
  {csrf_input(req)}
  <input type="hidden" name="offer_id" value="{o['id']}">
  <button class="danger-button" style="min-height:30px;padding:4px 10px;font-size:13px">Cancel</button>
</form>"""
        rows_html += f"""
<li class="offer-row">
  <div class="offer-row-info">
    <a href="/listing/{o['listing_id']}">{esc(o['title'])}</a>
    <span class="chip {chip_class.get(o['status'], '')}">{esc(o['status'].title())}</span>
    {expires_str}
  </div>
  <div class="offer-row-meta muted">
    Offered: <strong>{money(o['amount'])}</strong>
    &middot; Listed: {money(o['listing_price'])}
    {f'&middot; Note: {esc(o["note"])}' if o['note'] else ''}
  </div>
  {cancel_btn}
</li>"""

    content = f"""
<section class="toolbar">
  <div><p class="eyebrow">Buyer hub</p><h1>My Offers</h1></div>
  <a class="text-link" href="/buyer">Dashboard</a>
</section>
{"<ul class='offer-list'>" + rows_html + "</ul>" if offers else '<p class="empty">You haven\'t made any offers yet.</p>'}"""
    return layout(req, "My Offers", content, user)


def cancel_offer(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if err := csrf_protected(req):
        return err
    form, _ = parse_form(req)
    offer_id = as_int(form.get("offer_id"))
    with db() as conn:
        conn.execute(
            "UPDATE offers SET status='declined', updated_at=? "
            "WHERE id=? AND buyer_id=? AND status='pending'",
            (now(), offer_id, user["id"]),
        )
    return redirect("/buyer/offers")


# ---------------------------------------------------------------------------
# My reviews  /buyer/reviews  +  edit  +  delete
# ---------------------------------------------------------------------------
def buyer_reviews(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        reviews = conn.execute(
            """SELECT r.*, l.title, l.id listing_id, u.name reviewed_name
               FROM reviews r
               JOIN listings l ON l.id=r.listing_id
               JOIN users u ON u.id=r.reviewed_id
               WHERE r.reviewer_id=?
               ORDER BY r.created_at DESC""",
            (user["id"],),
        ).fetchall()

    rows_html = ""
    for r in reviews:
        rows_html += f"""
<li class="review-item review-mine">
  <div class="review-meta">
    <span class="stars-inline">{'&#9733;' * r['rating']}{'&#9734;' * (5 - r['rating'])}</span>
    <a href="/listing/{r['listing_id']}">{esc(r['title'])}</a>
    <span class="muted">for <strong>{esc(r['reviewed_name'])}</strong></span>
  </div>
  <p>{esc(r['body'])}</p>
  <div class="review-actions">
    <a class="text-link" href="/buyer/reviews/{r['id']}/edit">Edit</a>
    <form method="post" action="/buyer/reviews/{r['id']}/delete">
      {csrf_input(req)}
      <button class="danger-button" style="min-height:30px;padding:4px 10px;font-size:13px">Delete</button>
    </form>
  </div>
</li>"""

    content = f"""
<section class="toolbar">
  <div><p class="eyebrow">Buyer hub</p><h1>My Reviews</h1></div>
  <a class="text-link" href="/buyer">Dashboard</a>
</section>
{"<ul class='review-list'>" + rows_html + "</ul>" if reviews else '<p class="empty">You haven\'t written any reviews yet.</p>'}"""
    return layout(req, "My Reviews", content, user)


def edit_review_page(req, review_id):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        review = conn.execute(
            "SELECT * FROM reviews WHERE id=? AND reviewer_id=?",
            (review_id, user["id"]),
        ).fetchone()
    if not review:
        return layout(req, "Not Found", '<p class="empty">Review not found.</p>', user)
    if req.method == "POST" and req.path != "/payment/mpesa/callback":
        if err := csrf_protected(req):
            return err
        form, _ = parse_form(req)
        rating  = max(1, min(5, as_int(form.get("rating"), review["rating"])))
        body    = clamp(form.get("body", "").strip(), 1000)
        with db() as conn:
            conn.execute(
                "UPDATE reviews SET rating=?, body=? WHERE id=? AND reviewer_id=?",
                (rating, body, review_id, user["id"]),
            )
        return redirect("/buyer/reviews")
    star_opts = "".join(
        f'<option value="{v}" {"selected" if v == review["rating"] else ""}>{v} star{"s" if v!=1 else ""}</option>'
        for v in range(5, 0, -1)
    )
    content = f"""
<section class="narrow">
  <p class="eyebrow">Edit review</p>
  <h1>Update your review</h1>
  <form method="post" class="form">
    {csrf_input(req)}
    <select name="rating">{star_opts}</select>
    <textarea name="body" required>{esc(review['body'])}</textarea>
    <button>Save Changes</button>
  </form>
</section>"""
    return layout(req, "Edit Review", content, user)


def delete_review(req, review_id):
    user, resp = require_user(req)
    if resp:
        return resp
    if err := csrf_protected(req):
        return err
    with db() as conn:
        conn.execute(
            "DELETE FROM reviews WHERE id=? AND reviewer_id=?",
            (review_id, user["id"]),
        )
    return redirect("/buyer/reviews")


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
def profile(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        listings = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM listings l JOIN users u ON u.id=l.user_id
               WHERE user_id=? ORDER BY created_at DESC""",
            (user["id"],),
        ).fetchall()
    pct, missing = profile_completeness(user)
    post_listing = (
        '<a class="button-link" href="/listing/new">Post Listing</a>'
        if user["role"] in ("seller", "admin")
        else '<form method="post" action="/profile/upgrade-seller"><button>Become a Seller</button></form>'
    )
    empty_text = (
        "You have not posted listings yet."
        if user["role"] in ("seller", "admin")
        else "Your saved items and conversations are available from the navigation."
    )
    cards = "".join(listing_card(x) for x in listings) or f'<p class="empty">{empty_text}</p>'
    verified_badge = (
        ' <span class="verified-badge" title="Email verified">&#10003; Verified</span>'
        if user["email_verified"] else
        ' <span class="unverified-badge">Unverified</span>'
    )
    buyer_hub_link = (
        '<a class="text-link" href="/buyer">Buyer Dashboard</a>'
        if user["role"] == "buyer" else ""
    )
    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow">{esc(user['role'])} profile</p>
    <h1>{esc(user['name'])}{verified_badge}</h1>
    <p>{esc(user['university'])} &middot; {esc(user['faculty'])} &middot; {esc(user['year'])}</p>
  </div>
  <div class="profile-actions">
    {buyer_hub_link}
    <a class="text-link" href="/seller/{user['id']}">Public Profile</a>
    <a class="text-link" href="/profile/edit">Edit Profile</a>
    {post_listing}
  </div>
</section>
{completeness_bar_html(pct, missing)}
<section class="grid">{cards}</section>"""
    return layout(req, "Profile", content, user)


def profile_form(req, user, error=""):
    years = "".join(
        f'<option {"selected" if user["year"] == year else ""}>{year}</option>'
        for year in ("Year 1", "Year 2", "Year 3", "Year 4", "Postgraduate", "Alumni")
    )
    content = f"""
<section class="narrow">
  <p class="eyebrow">Account settings</p><h1>Edit Profile</h1>
  {f'<p class="error">{esc(error)}</p>' if error else ''}
  <form method="post" class="form" enctype="multipart/form-data">
    <label class="field-label" for="profile-photo">Profile picture</label><input id="profile-photo" name="profile_photo" type="file" accept="image/png,image/jpeg,image/webp">
    <input name="name" value="{esc(user['name'])}" placeholder="Full name" required>
    <select name="university" required><option value="">Select university</option>{university_options(user["university"])}</select>
    <input name="faculty" value="{esc(user['faculty'])}" placeholder="Faculty or school">
    <select name="year">{years}</select>
    <input name="phone" value="{esc(user['phone'])}" placeholder="Phone number (e.g. 0797158775)" pattern="^(\\+?254|0)[17]\\d{{8}}$" title="Use 0712345678, 0112345678, or +254712345678" inputmode="tel">
    <textarea name="bio" placeholder="A short introduction">{esc(user['bio'])}</textarea>
    <button>Save Changes</button>
  </form>
</section>"""
    return layout(req, "Edit Profile", content, user)


def edit_profile(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if req.method == "GET":
        return profile_form(req, user)
    form, files = parse_form(req)
    name = form.get("name", "").strip()
    university = form.get("university", "").strip()
    profile_photo = files.get("profile_photo")
    profile_image_path = user["profile_image_path"] if "profile_image_path" in user.keys() else ""
    if profile_photo and profile_photo[1]:
        profile_image_path = save_upload(profile_photo) or profile_image_path
    if not name or not university:
        updated = dict(user)
        updated.update({
            "name": name, "university": university,
            "faculty": form.get("faculty", "").strip(),
            "year": form.get("year", ""),
            "phone": form.get("phone", "").strip(),
            "bio": form.get("bio", "").strip(),
            "profile_image_path": profile_image_path,
        })
        return profile_form(req, updated, "Name and university are required.")
    phone, phone_err = validate_phone(form.get("phone", ""))
    if phone_err:
        updated = dict(user)
        updated.update({
            "name": name, "university": university,
            "faculty": form.get("faculty", "").strip(),
            "year": form.get("year", ""),
            "phone": form.get("phone", "").strip(),
            "bio": form.get("bio", "").strip(),
            "profile_image_path": profile_image_path,
        })
        return profile_form(req, updated, phone_err)
    with db() as conn:
        conn.execute(
            "UPDATE users SET name=?, university=?, faculty=?, year=?, phone=?, bio=?, profile_image_path=? WHERE id=?",
            (name, university, form.get("faculty", "").strip(), form.get("year", ""),
             phone, form.get("bio", "").strip(), profile_image_path, user["id"]),
        )
    return redirect("/profile")


def upgrade_seller(req):
    user, resp = require_user(req)
    if resp: return resp
    if user["role"] != "buyer": return redirect("/seller")
    form, _ = parse_form(req)
    university = clamp(form.get("university", "").strip(), 120)
    identifier_type = form.get("identifier_type", "").strip().lower()
    identifier_number = clamp(form.get("identifier_number", "").strip(), 80)
    if university not in UNIVERSITIES:
        return layout(req, "Seller request", '<section class="auth-panel"><p class="error">Select your university or school.</p><a class="button-link" href="/seller">Try again</a></section>', user)
    if identifier_type not in {"admission_number", "staff_number"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9/._ -]{1,79}", identifier_number):
        return layout(req, "Seller request", '<section class="auth-panel"><p class="error">Enter a valid admission or staff number.</p><a class="button-link" href="/seller">Try again</a></section>', user)
    with db() as conn:
        existing = conn.execute("SELECT id, status FROM seller_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 1", (user["id"],)).fetchone()
        if existing and existing["status"] == "pending": return redirect("/seller")
        conn.execute("UPDATE users SET university=?, seller_status='pending' WHERE id=?", (university, user["id"]))
        conn.execute("INSERT INTO seller_requests(user_id, university, identifier_type, identifier_number, status, created_at) VALUES(?,?,?,?,?,?)", (user["id"], university, identifier_type, identifier_number, "pending", now()))
    return redirect("/seller")


# ---------------------------------------------------------------------------
# Seller dashboard
# ---------------------------------------------------------------------------
def seller_dashboard(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    with db() as conn:
        listing_count = conn.execute(
            "SELECT count(*) c FROM listings WHERE user_id=? AND status='active'", (user["id"],)
        ).fetchone()["c"]
        pending_offers = conn.execute(
            "SELECT count(*) c FROM offers WHERE seller_id=? AND status='pending'", (user["id"],)
        ).fetchone()["c"]
        buyer_count = conn.execute("SELECT count(DISTINCT buyer_id) c FROM orders WHERE seller_id=?", (user["id"],)).fetchone()["c"]
        order_count = conn.execute("SELECT count(*) c FROM orders WHERE seller_id=?", (user["id"],)).fetchone()["c"]
        unread = unread_count(user["id"])
        listings = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM listings l JOIN users u ON u.id=l.user_id
               WHERE l.user_id=? AND l.status='active' ORDER BY l.updated_at DESC LIMIT 6""",
            (user["id"],),
        ).fetchall()
        offers = conn.execute(
            """SELECT o.*, l.title, b.name buyer FROM offers o
               JOIN listings l ON l.id=o.listing_id JOIN users b ON b.id=o.buyer_id
               WHERE o.seller_id=? ORDER BY o.created_at DESC LIMIT 5""",
            (user["id"],),
        ).fetchall()
        recent_convs = conn.execute(
            """SELECT c.id, l.title listing_title,
                      b.name buyer_name,
                      (SELECT body FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) last_msg,
                      (SELECT count(*) FROM messages WHERE conversation_id=c.id AND receiver_id=? AND is_read=0) unread
               FROM conversations c
               JOIN listings l ON l.id=c.listing_id
               JOIN users b ON b.id=c.buyer_id
               WHERE c.seller_id=?
               ORDER BY c.created_at DESC LIMIT 5""",
            (user["id"], user["id"]),
        ).fetchall()

    offers_html = "".join(
        f"""<li>
          <a href='/listing/{o['listing_id']}'>{esc(o['title'])}</a>
          <span><strong>{esc(o['buyer'])}</strong> offered {money(o['amount'])} &middot; {esc(o['status'])}</span>
          {f'''<form method="post" action="/offer/status" class="activity-actions">
            <input type="hidden" name="offer_id" value="{o['id']}">
            <button name="status" value="accepted">Accept</button>
            <button class="secondary-button" name="status" value="declined">Decline</button>
          </form>''' if o['status'] == 'pending' else ''}
        </li>"""
        for o in offers
    ) or "<li>No offers yet.</li>"

    convs_html = "".join(
        f"""<li>
          <a href='/conversation/{c['id']}'>{esc(c['listing_title'])}</a>
          {f'<span class="badge">{c["unread"]}</span>' if c['unread'] else ''}
          <span>from <strong>{esc(c['buyer_name'])}</strong>{f': {esc(c["last_msg"][:60])}' if c['last_msg'] else ''}</span>
        </li>"""
        for c in recent_convs
    ) or "<li>No messages yet.</li>"

    listing_html = (
        "".join(listing_card(row) for row in listings)
        or '<p class="empty">Your listings will appear here once you publish them.</p>'
    )
    content = f"""
<section class="toolbar seller-heading">
  <div>
    <p class="eyebrow">Seller hub</p>
    <h1>Manage your marketplace</h1>
    <p class="muted">Keep track of listings and interested buyers.</p>
  </div>
  <a class="button-link" href="/listing/new">Post Listing</a>
</section>
{dashboard_profile_panel(user)}
<section class="stat-grid seller-stats">
  {stat_card("📦", listing_count, "Active Listings", "amber")}
  {stat_card("👥", buyer_count, "People who bought", "blue", href="/orders")}
  {stat_card("🛒", order_count, "Orders received", "teal", href="/orders")}
  {stat_card("🤝", pending_offers, "Pending Offers", "coral" if pending_offers else "teal", href="#offers")}
  {stat_card("💬", unread, "Unread Messages", "blue" if unread else "teal", href="/inbox")}
</section>
<section class="columns seller-activity">
  <div id="offers">
    <div class="section-heading"><h2>Latest Offers</h2><a class="text-link" href="/inbox">View inbox</a></div>
    <ul class="activity-list">{offers_html}</ul>
  </div>
  <div>
    <div class="section-heading"><h2>Recent Conversations</h2><a class="text-link" href="/inbox">View all</a></div>
    <ul class="activity-list">{convs_html}</ul>
  </div>
</section>
<section class="toolbar"><h2>Your Active Listings</h2><a class="text-link" href="/profile">View all listings</a></section>
<section class="grid">{listing_html}</section>"""
    return layout(req, "Seller Hub", content, user)



# ---------------------------------------------------------------------------
# Seller reports  /seller/reports
# ---------------------------------------------------------------------------
def seller_reports_page(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    start, end, start_ts, end_ts = _date_range(req)
    if not start:
        start = time.strftime('%Y-%m-01')
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d")))
    if not end:
        end = time.strftime('%Y-%m-%d')
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399
    with db() as conn:
        sales = conn.execute(
            """SELECT o.id, o.amount, o.payment_status, o.delivery_status, o.created_at,
                      l.title, l.category, b.name buyer_name
               FROM orders o
               JOIN listings l ON l.id=o.listing_id
               JOIN users b ON b.id=o.buyer_id
               WHERE o.seller_id=? AND o.created_at>=? AND o.created_at<=?
               ORDER BY o.created_at DESC""",
            (user["id"], start_ts, end_ts),
        ).fetchall()
        total_revenue = sum(r["amount"] for r in sales if r["payment_status"] == "paid")
        total_orders = len(sales)
        paid_count = sum(1 for r in sales if r["payment_status"] == "paid")
        # Revenue by category
        cat_rev = {}
        for r in sales:
            if r["payment_status"] == "paid":
                cat_rev[r["category"]] = cat_rev.get(r["category"], 0) + r["amount"]
        cat_labels = list(cat_rev.keys())
        cat_values = [int(cat_rev[c]) for c in cat_labels]
        # Monthly revenue trend
        month_rev = {}
        for r in sales:
            if r["payment_status"] == "paid":
                m = time.strftime('%Y-%m', time.gmtime(r["created_at"]))
                month_rev[m] = month_rev.get(m, 0) + r["amount"]
        sorted_months = sorted(month_rev.keys())
        month_labels = sorted_months
        month_values = [int(month_rev[m]) for m in sorted_months]

    cat_chart = svg_donut_chart(cat_labels, cat_values) if cat_labels else '<p class="muted">No sales data yet.</p>'
    trend_chart = svg_bar_chart(month_labels, month_values) if month_labels else '<p class="muted">No sales data yet.</p>'

    rows_html = "".join(
        f"""<tr>
            <td>#{r['id']:05d}</td>
            <td>{esc(r['title'])}</td>
            <td>{esc(r['category'])}</td>
            <td>{esc(r['buyer_name'])}</td>
            <td><strong>{money(r['amount'])}</strong></td>
            <td><span class="chip chip-{esc(r['payment_status'])}">{esc(r['payment_status'].title())}</span></td>
            <td>{time.strftime('%Y-%m-%d', time.gmtime(r['created_at']))}</td>
        </tr>"""
        for r in sales
    ) or '<tr><td colspan="7" class="muted">No sales found in this period.</td></tr>'

    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow">Seller reports</p>
    <h1>Your Sales Reports</h1>
    <p class="muted">View and download reports on items you have sold.</p>
  </div>
</section>
<section class="admin-section report-builder">
  <h2>Filter by date range</h2>
  <form method="get" action="/seller/reports" class="form">
    <div class="split">
      <div><label class="field-label" for="start">From</label><input id="start" type="date" name="start" value="{esc(start)}" required></div>
      <div><label class="field-label" for="end">To</label><input id="end" type="date" name="end" value="{esc(end)}" required></div>
    </div>
    <button>Apply Filter</button>
  </form>
</section>
<section class="stat-grid">
  {stat_card("🛒", total_orders, "Total Sales", "amber")}
  {stat_card("✅", paid_count, "Paid Orders", "teal")}
  {stat_card("💰", money(total_revenue), "Total Revenue", "blue")}
</section>
<section class="admin-section admin-charts">
  <div class="chart-grid">
    <div class="chart-card"><h3>Revenue by Category</h3>{cat_chart}</div>
    <div class="chart-card"><h3>Monthly Revenue Trend</h3>{trend_chart}</div>
  </div>
</section>
<section class="admin-section">
  <div class="section-heading">
    <h2>Sales History</h2>
    <a class="button-link" href="/seller/reports/download?start={esc(start)}&end={esc(end)}">Download CSV</a>
  </div>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Order</th><th>Item</th><th>Category</th><th>Buyer</th><th>Amount</th><th>Payment</th><th>Date</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  </div>
</section>"""
    return layout(req, "Sales Reports", content, user)


def seller_reports_download(req):
    user, resp = require_seller(req)
    if resp:
        return resp
    import csv as _csv
    from io import StringIO
    start, end, start_ts, end_ts = _date_range(req)
    if not start:
        start = time.strftime('%Y-%m-01')
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d")))
    if not end:
        end = time.strftime('%Y-%m-%d')
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399
    buf = StringIO()
    writer = _csv.writer(buf)
    writer.writerow(["Order ID", "Item", "Category", "Buyer", "Amount (KES)", "Payment Status", "Delivery Status", "Date"])
    with db() as conn:
        rows = conn.execute(
            """SELECT o.id, o.amount, o.payment_status, o.delivery_status, o.created_at,
                      l.title, l.category, b.name buyer_name
               FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users b ON b.id=o.buyer_id
               WHERE o.seller_id=? AND o.created_at>=? AND o.created_at<=?
               ORDER BY o.created_at DESC""",
            (user["id"], start_ts, end_ts),
        ).fetchall()
    for r in rows:
        writer.writerow([r["id"], r["title"], r["category"], r["buyer_name"], r["amount"],
                         r["payment_status"], r["delivery_status"],
                         time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created_at"]))])
    filename = f"unimarket-sales-{start or 'all'}-to-{end or 'now'}.csv"
    return Response(buf.getvalue(), 200, "text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# Wishlist page
# ---------------------------------------------------------------------------
def wishlist(req):
    user, resp = require_user(req)
    if resp:
        return resp
    with db() as conn:
        rows = conn.execute(
            """SELECT l.*, u.name seller, u.id seller_id, u.university
               FROM wishlist w JOIN listings l ON l.id=w.listing_id
               JOIN users u ON u.id=l.user_id
               WHERE w.user_id=? ORDER BY w.created_at DESC""",
            (user["id"],),
        ).fetchall()
    cards = "".join(listing_card(x) for x in rows) or '<p class="empty">No saved listings yet.</p>'
    return layout(req, "Wishlist", f"<section class='toolbar'><h1>Wishlist</h1></section><section class='grid'>{cards}</section>", user)


# ---------------------------------------------------------------------------
# Orders, seller buyer counts, and reports
# ---------------------------------------------------------------------------
def _date_range(req):
    start, end = req.query.get("start", [""])[0], req.query.get("end", [""])[0]
    try:
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d"))) if start else 0
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399 if end else now()
    except (ValueError, OverflowError): start, end, start_ts, end_ts = "", "", 0, now()
    return start, end, start_ts, end_ts

def place_order(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req); listing_id = as_int(form.get("listing_id"))
    with db() as conn:
        listing = conn.execute("SELECT * FROM listings WHERE id=? AND status='active'", (listing_id,)).fetchone()
        if not listing or listing["user_id"] == user["id"]: return layout(req, "Order unavailable", '<p class="error">That listing is unavailable.</p>', user)
        conn.execute("INSERT INTO orders(listing_id,buyer_id,seller_id,amount,payment_status,seller_order_status,delivery_status,sdk_push_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (listing_id, user["id"], listing["user_id"], listing["price"], "pending", "pending", "awaiting_payment", "not_started", now(), now()))
        order_id = conn.execute("SELECT last_insert_rowid() id").fetchone()["id"]
    return redirect(f"/orders?order={order_id}")

def order_status(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req); order_id = as_int(form.get("order_id")); delivery = form.get("delivery_status", "")
    if delivery not in {"paid", "shipped", "received", "cancelled"}: return redirect("/orders")
    with db() as conn:
        row = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not row or (user["id"] not in (row["buyer_id"], row["seller_id"]) and not user["is_superadmin"]): return redirect("/orders")
        is_seller_or_admin = user["id"] == row["seller_id"] or bool(user["is_superadmin"])
        if delivery in {"paid", "shipped"} and not is_seller_or_admin: return redirect("/orders")
        if delivery in {"paid", "shipped", "received"} and row["payment_status"] != "paid": return redirect("/orders")
        if delivery == "received" and user["id"] != row["buyer_id"] and not user["is_superadmin"]: return redirect("/orders")
        conn.execute("UPDATE orders SET delivery_status=?, received_at=?, updated_at=? WHERE id=?", (delivery, now() if delivery == "received" else row["received_at"], now(), order_id))
    return redirect("/orders")

def orders_page(req):
    user, resp = require_user(req)
    if resp: return resp
    start, end, start_ts, end_ts = _date_range(req)
    with db() as conn:
        orders = conn.execute("""SELECT o.*, l.title, b.name buyer, s.name seller, s.phone seller_phone FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id WHERE o.created_at BETWEEN ? AND ? AND (? IN (o.buyer_id, o.seller_id) OR ?=1) ORDER BY o.created_at DESC""", (start_ts, end_ts, user["id"], int(bool(user["is_superadmin"])),)).fetchall()
    labels = {"awaiting_payment":"Awaiting payment","paid":"Paid","shipped":"Shipped","received":"Received","cancelled":"Cancelled"}
    payment_labels = {"pending":"Payment not submitted", "submitted":"Waiting for seller confirmation", "paid":"Payment confirmed", "failed":"Payment not confirmed"}
    seller_order_labels = {"pending":"Pending", "paid":"Paid", "picked":"Picked", "shipped":"Shipped", "received":"Received", "cancelled":"Cancelled"}
    rows = []
    for o in orders:
        actions = ""
        if user["id"] == o["buyer_id"] and o["payment_status"] == "submitted":
            actions += f"""<div class="payment-instructions"><strong>Payment submitted</strong><span>Wait for {esc(o['seller'])} to check and confirm the payment.</span></div><a class="text-link" href="/payment/waiting/{o['id']}">View payment status</a>"""
        elif user["id"] == o["buyer_id"] and o["payment_status"] != "paid":
            actions += f"""<div class="payment-instructions"><strong>Send {money(o['amount'])} to {esc(o['seller_phone'] or 'seller phone')}</strong><span>Use M-Pesa Send Money, then enter the transaction code.</span></div><form method="post" action="/payment/manual-submit" class="inline-form">{csrf_input(req)}<input type="hidden" name="order_id" value="{o['id']}"><input name="receipt_code" placeholder="M-Pesa transaction code" pattern="[A-Za-z0-9]{{6,32}}" required><input name="payment_note" placeholder="Optional note"><button>Submit payment</button></form>"""
        if user["id"] == o["seller_id"] and o["payment_status"] != "paid":
            actions += f"""<div class="payment-submission"><strong>Buyer submitted: {esc(o['receipt_code'] or 'code not available')}</strong><span>{esc(o['payment_note'] or 'Check your M-Pesa SMS or statement before updating the order.')}</span></div><form method="post" action="/payment/manual-confirm" class="inline-form">{csrf_input(req)}<input type="hidden" name="order_id" value="{o['id']}"><label class="sr-only" for="seller-order-status-{o['id']}">Order status</label><select id="seller-order-status-{o['id']}" name="seller_order_status"><option value="pending" {"selected" if o['seller_order_status'] == 'pending' else ''}>Pending</option><option value="paid">Paid</option><option value="picked">Picked</option></select><button>Update order</button></form>"""
        if o["delivery_status"] not in ("received", "cancelled") and user["id"] in (o["seller_id"], o["buyer_id"]): actions += f"""<form method="post" action="/order/status" class="inline-form">{csrf_input(req)}<input type="hidden" name="order_id" value="{o['id']}"><select name="delivery_status"><option value="paid">Paid</option><option value="shipped">Shipped</option><option value="received">Received</option></select><button>Update</button></form>"""
        rows.append(f"""<tr><td><strong>#UM-{o['id']:05d}</strong><br><span class="muted">{esc(o['title'])}</span></td><td>{esc(o['buyer'])}</td><td>{esc(o['seller'])}</td><td><strong>{money(o['amount'])}</strong></td><td><span class="chip chip-{esc(o['payment_status'])}">{payment_labels.get(o['payment_status'],o['payment_status'].title())}</span><br><span class="muted">Seller status: {seller_order_labels.get(o['seller_order_status'],o['seller_order_status'].title())}</span></td><td>{time.strftime('%Y-%m-%d',time.gmtime(o['updated_at']))}</td><td><a class="text-link" href="/order/{o['id']}/track">Track location</a>{actions}</td></tr>""")
    body = ''.join(rows) or '<tr><td colspan="7"><p class="empty">No orders in this period.</p></td></tr>'
    content = f"""<section class="toolbar"><div><p class="eyebrow">Commerce flow</p><h1>Orders &amp; delivery</h1><p class="muted">Track orders from payment to received.</p></div></section><form class="toolbar filter-bar" method="get"><label>From<input type="date" name="start" value="{esc(start)}"></label><label>To<input type="date" name="end" value="{esc(end)}"></label><button>Filter</button></form><section class="admin-section admin-table-wrap"><table class="admin-table"><thead><tr><th>Order</th><th>Buyer</th><th>Seller</th><th>Amount</th><th>Delivery status</th><th>Updated</th><th>Actions</th></tr></thead><tbody>{body}</tbody></table></section>"""
    return layout(req, "Orders & Delivery", content, user)

def _order_for_user(order_id, user):
    with db() as conn:
        return conn.execute('SELECT o.*, l.title, l.location listing_location, b.name buyer, s.name seller FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id WHERE o.id=? AND (? IN (o.buyer_id, o.seller_id) OR ?=1)', (order_id, user['id'], int(bool(user['is_superadmin'])))).fetchone()


def update_order_location(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req)
    order_id = as_int(form.get('order_id'))
    label = clamp(form.get('location_label', '').strip(), 180)
    try:
        latitude, longitude = float(form.get('latitude', '')), float(form.get('longitude', ''))
    except (TypeError, ValueError):
        return redirect(f'/order/{order_id}/track')
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180): return redirect(f'/order/{order_id}/track')
    order = _order_for_user(order_id, user)
    if not order or (user['id'] != order['seller_id'] and not user['is_superadmin']): return redirect('/orders')
    with db() as conn:
        conn.execute('UPDATE orders SET latitude=?, longitude=?, location_label=?, location_updated_at=?, updated_at=? WHERE id=?', (latitude, longitude, label, now(), now(), order_id))
    return redirect(f'/order/{order_id}/track')


def order_tracker(req, order_id):
    user, resp = require_user(req)
    if resp: return resp
    order = _order_for_user(order_id, user)
    if not order: return layout(req, 'Order not found', '<p class="empty">That order is not available to this account.</p>', user)
    has_location = order['latitude'] is not None and order['longitude'] is not None
    coords = f"{order['latitude']:.6f}, {order['longitude']:.6f}" if has_location else 'Location pending'
    if has_location:
        lat, lon = float(order['latitude']), float(order['longitude'])
        bbox = f'{lon-0.02:.6f},{lat-0.02:.6f},{lon+0.02:.6f},{lat+0.02:.6f}'
        map_html = f'''<div class="order-map"><iframe title="Live order location" src="https://www.openstreetmap.org/export/embed.html?bbox={bbox}&amp;layer=mapnik&amp;marker={lat:.6f}%2C{lon:.6f}"></iframe><a class="map-link" target="_blank" rel="noopener" href="https://www.openstreetmap.org/?mlat={lat:.6f}&amp;mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}">Open full map</a></div>'''
    else:
        map_html = '<div class="order-map empty-map"><strong>Location not shared yet</strong><span>The seller can share the current order location from this page.</span></div>'
    share_form = ''
    if user['id'] == order['seller_id'] or user['is_superadmin']:
        share_form = f'''<section class="location-share"><h2>Share current location</h2><p class="muted">Location is visible only to the buyer, seller, and superadmin on this order.</p><form method="post" action="/order/location" id="location-form" class="form"><input type="hidden" name="order_id" value="{order_id}"><input type="hidden" name="latitude" id="latitude"><input type="hidden" name="longitude" id="longitude"><label class="field-label" for="location-label">Location label</label><input id="location-label" name="location_label"><button type="button" id="use-location">Use my current location</button><button type="submit" id="save-location" disabled>Save order location</button><p id="location-status" class="muted" aria-live="polite">Your browser will ask for location permission.</p></form></section>'''
    updated = time.strftime('%Y-%m-%d %H:%M', time.gmtime(order['location_updated_at'])) if order['location_updated_at'] else 'Not shared yet'
    content = f'''<section class="toolbar"><div><p class="eyebrow">Order tracker</p><h1>#{order_id:05d}, {esc(order['title'])}</h1><p class="muted">Private live location for {esc(order['buyer'])} and {esc(order['seller'])}.</p></div><a class="button-link" href="/orders">Back to orders</a></section><section class="tracker-grid"><div class="tracker-primary"><div class="tracker-meta"><div><span class="field-label">Delivery status</span><span class="chip chip-{esc(order['delivery_status'])}">{esc(order['delivery_status'].replace('_', ' ').title())}</span></div><div><span class="field-label">Last known location</span><strong>{esc(order['location_label'] or order['listing_location'] or 'Not shared yet')}</strong></div><div><span class="field-label">Coordinates</span><strong>{coords}</strong></div><div><span class="field-label">Last update</span><strong>{updated}</strong></div></div>{map_html}</div>{share_form}</section>'''
    return layout(req, 'Order Tracker', content, user)


def reports_page(req):
    user, resp = require_user(req)
    if resp: return resp
    # Redirect to the role-specific reports page
    if user["role"] == "admin":
        return redirect("/admin/reports")
    elif user["role"] == "seller":
        return redirect("/seller/reports")
    else:
        return redirect("/buyer/reports")

# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------
def update_report_status(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin":
        return layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    form, _ = parse_form(req)
    status = form.get("status", "")
    if status in ("resolved", "dismissed"):
        with db() as conn:
            conn.execute("UPDATE reports SET status=? WHERE id=?", (status, as_int(form.get("report_id"))))
    return redirect("/admin")


def hide_reported_listing(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin":
        return layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    form, _ = parse_form(req)
    with db() as conn:
        report = conn.execute(
            "SELECT listing_id FROM reports WHERE id=? AND status='open'",
            (as_int(form.get("report_id")),),
        ).fetchone()
        if report:
            conn.execute("UPDATE listings SET status='removed', updated_at=? WHERE id=?", (now(), report["listing_id"]))
            conn.execute("UPDATE reports SET status='resolved' WHERE id=?", (as_int(form.get("report_id")),))
    return redirect("/admin")


def admin(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin":
        return layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    is_super = user["is_superadmin"]
    with db() as conn:
        users_count = conn.execute("SELECT count(*) c FROM users").fetchone()["c"]
        listings_count = conn.execute("SELECT count(*) c FROM listings").fetchone()["c"]
        seller_count_sql = "SELECT count(*) c FROM users WHERE role='seller'"
        seller_count_args = []
        if not is_super:
            seller_count_sql += " AND university=?"
            seller_count_args.append(user["university"])
        sellers_count = conn.execute(seller_count_sql, seller_count_args).fetchone()["c"]
        admins_count = conn.execute("SELECT count(*) c FROM users WHERE role='admin'").fetchone()["c"]
        # Chart data: sales by category
        cat_data = conn.execute(
            "SELECT category, count(*) c FROM listings WHERE status='sold' GROUP BY category ORDER BY c DESC"
        ).fetchall()
        # Chart data: users over time (last 12 months)
        month_data = conn.execute(
            """SELECT strftime('%Y-%m', created_at, 'unixepoch') month, count(*) c
               FROM users GROUP BY month ORDER BY month DESC LIMIT 12"""
        ).fetchall()
        # Chart data: listings over time (last 12 months)
        listing_month_data = conn.execute(
            """SELECT strftime('%Y-%m', created_at, 'unixepoch') month, count(*) c
               FROM listings GROUP BY month ORDER BY month DESC LIMIT 12"""
        ).fetchall()
        reports = conn.execute(
            """SELECT r.*, l.title, u.name reporter FROM reports r
               JOIN listings l ON l.id=r.listing_id JOIN users u ON u.id=r.reporter_id
               ORDER BY r.created_at DESC"""
        ).fetchall()
        latest_sql = """SELECT l.*, u.name seller, u.id seller_id, u.university
                       FROM listings l JOIN users u ON u.id=l.user_id
                       ORDER BY l.created_at DESC LIMIT 12"""
        latest_args = []
        if not is_super:
            latest_sql = """SELECT l.*, u.name seller, u.id seller_id, u.university
                           FROM listings l JOIN users u ON u.id=l.user_id
                           WHERE u.university=?
                           ORDER BY l.created_at DESC LIMIT 12"""
            latest_args = [user["university"]]
        latest = conn.execute(latest_sql, latest_args).fetchall()
        # Full users table for superadmin
        all_users = conn.execute(
            "SELECT id, name, email, phone, role, university, suspended, suspend_reason, created_at FROM users ORDER BY created_at DESC"
        ).fetchall() if is_super else []
        # Seller directory: university admins are restricted to their own school.
        seller_sql = """SELECT u.id, u.name, u.email, u.phone, u.university, u.suspended, u.created_at,
                              (SELECT count(*) FROM listings l WHERE l.user_id=u.id AND l.status='active') active_listings
                       FROM users u WHERE u.role='seller'"""
        seller_args = []
        if not is_super:
            seller_sql += " AND u.university=?"
            seller_args.append(user["university"])
        seller_sql += " ORDER BY u.created_at DESC"
        school_sellers = conn.execute(seller_sql, seller_args).fetchall()
        # Pending admin requests for superadmin
        admin_reqs = conn.execute(
            """SELECT ar.*, u.name user_name, u.email user_email FROM admin_requests ar
               JOIN users u ON u.id=ar.user_id WHERE ar.status='pending' ORDER BY ar.created_at DESC"""
        ).fetchall() if is_super else []
        seller_req_sql = """SELECT sr.*, u.name user_name, u.email user_email, u.phone FROM seller_requests sr JOIN users u ON u.id=sr.user_id WHERE sr.status='pending'"""
        seller_req_args = []
        if not is_super:
            seller_req_sql += " AND sr.university=?"
            seller_req_args.append(user["university"])
        seller_req_sql += " ORDER BY sr.created_at DESC"
        seller_reqs = conn.execute(seller_req_sql, seller_req_args).fetchall()
    # Build reports HTML
    report_html = "".join(
        f"""<li>
          <a href='/listing/{r['listing_id']}'>{esc(r['title'])}</a>: {esc(r['reason'])} <span>{esc(r['status'])}</span>
          {f'''<form method="post" action="/admin/report/status" class="admin-actions">
            <input type="hidden" name="report_id" value="{r['id']}">
            <button name="status" value="resolved">Resolve</button>
            <button class="secondary-button" name="status" value="dismissed">Dismiss</button>
          </form>
          <form method="post" action="/admin/hide-listing">
            <input type="hidden" name="report_id" value="{r['id']}">
            <button class="danger-button">Hide Listing</button>
          </form>''' if r['status'] == 'open' else ''}
        </li>"""
        for r in reports
    ) or "<li>No reports.</li>"
    # Build users table for superadmin
    users_table = ""
    if is_super and all_users:
        users_table = """
<section class="admin-section">
  <h1>All Users</h1>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Role</th><th>University</th><th>Status</th><th>Joined</th><th>Actions</th></tr></thead>
    <tbody>""" + "".join(
            f"""<tr>
      <td>{esc(u['name'])}</td>
      <td>{esc(u['email'])}</td>
      <td>{esc(u['phone'])}</td>
      <td>{esc(u['role'])}</td>
      <td>{esc(u['university'])}</td>
      <td>{'<span class="suspended-badge">Suspended</span>' if u['suspended'] else '<span class="active-badge">Active</span>'}</td>
      <td>{time.strftime('%Y-%m-%d', time.gmtime(u['created_at']))}</td>
      <td class="admin-actions-cell">
        {'<form method="post" action="/admin/unblock-user"><input type="hidden" name="user_id" value="' + str(u['id']) + '"><input type="hidden" name="_csrf" value="' + esc(_csrf_token_for(req)) + '"><button class="secondary-button" type="submit">Unblock</button></form>' if u['suspended'] else '<form method="post" action="/admin/block-user"><input type="hidden" name="user_id" value="' + str(u['id']) + '"><input type="hidden" name="_csrf" value="' + esc(_csrf_token_for(req)) + '"><button class="danger-button" type="submit">Block Selling</button></form>'}
      </td>
    </tr>"""
            for u in all_users
        ) + """</tbody></table></div></section>"""
    elif is_super:
        users_table = '<section class="admin-section"><h1>All Users</h1><p class="muted">No users found.</p></section>'
    # Build seller directory with strict university scoping for regular admins.
    seller_scope = "All universities" if is_super else (user["university"] or "your university")
    seller_rows = "".join(
        f"""<tr>
      <td><a class="text-link" href="/seller/{seller['id']}">{esc(seller['name'])}</a></td>
      <td>{esc(seller['email'])}</td>
      <td>{esc(seller['phone'])}</td>
      <td>{esc(seller['university'])}</td>
      <td>{seller['active_listings']}</td>
      <td>{'<span class="suspended-badge">Suspended</span>' if seller['suspended'] else '<span class="active-badge">Active</span>'}</td>
      <td>{time.strftime('%Y-%m-%d', time.gmtime(seller['created_at']))}</td>
    </tr>"""
        for seller in school_sellers
    ) or '<tr><td colspan="7" class="muted">No sellers found for this school.</td></tr>'
    seller_table = f"""
<section class="admin-section">
  <div class="section-heading"><div><p class="eyebrow">Seller access</p><h1>Seller Directory</h1></div><span class="muted">Scope: {esc(seller_scope)}</span></div>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>University</th><th>Active listings</th><th>Status</th><th>Joined</th></tr></thead>
    <tbody>{seller_rows}</tbody>
  </table></div>
</section>"""
    # Build admin requests table for superadmin
    admin_reqs_html = ""
    if is_super and admin_reqs:
        admin_reqs_html = """
<section class="admin-section">
  <h1>Pending Admin Requests</h1>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Applicant</th><th>Staff #</th><th>Full name</th><th>University</th><th>ID #</th><th>KRA PIN</th><th>Documents</th><th>Actions</th></tr></thead>
    <tbody>""" + "".join(
            f"""<tr>
      <td>{esc(ar['user_name'])}</td>
      <td>{esc(ar['staff_number'])}</td>
      <td>{esc(ar['full_name'])}</td>
      <td>{esc(ar['university'])}</td>
      <td>{esc(ar['id_number'])}</td>
      <td>{esc(ar['kra_pin'])}</td>
      <td class="document-links">{" · ".join(f'<a href="/admin/request-document?request_id={ar["id"]}&amp;document={key}" target="_blank" rel="noopener">{label}</a>' for label, key, path in (("Intro", "cover_letter", ar["cover_letter_path"]),("National ID", "national_id", ar["national_id_path"]),("KRA PIN", "kra_certificate", ar["kra_certificate_path"])) if path) or "N/A"}</td>
      <td class="admin-actions-cell">
        <form method="post" action="/admin/approve-request" class="inline-form-2">
          <input type="hidden" name="request_id" value="{ar['id']}">
          <input type="hidden" name="_csrf" value="{esc(_csrf_token_for(req))}">
          <button type="submit">Approve</button>
        </form>
        <form method="post" action="/admin/reject-request" class="inline-form-2">
          <input type="hidden" name="request_id" value="{ar['id']}">
          <input type="hidden" name="_csrf" value="{esc(_csrf_token_for(req))}">
          <button class="danger-button" type="submit">Reject</button>
        </form>
      </td>
    </tr>"""
            for ar in admin_reqs
        ) + """</tbody></table></div></section>"""
    elif is_super:
        admin_reqs_html = '<section class="admin-section"><h1>Pending Admin Requests</h1><p class="muted">No pending admin requests.</p></section>'
    seller_req_html = """<section class="admin-section"><div class="section-heading"><div><p class="eyebrow">Seller access</p><h1>Pending Seller Requests</h1></div><span class="muted">Approve only students from your school</span></div><div class="admin-table-wrap"><table class="admin-table"><thead><tr><th>Applicant</th><th>Email</th><th>Phone</th><th>School</th><th>Identification</th><th>Requested</th><th>Actions</th></tr></thead><tbody>""" + ("".join(f"""<tr><td>{esc(sr['user_name'])}</td><td>{esc(sr['user_email'])}</td><td>{esc(sr['phone'])}</td><td>{esc(sr['university'])}</td><td>{esc(sr['identifier_type'].replace('_', ' ').title())}: {esc(sr['identifier_number'])}</td><td>{time.strftime('%Y-%m-%d', time.gmtime(sr['created_at']))}</td><td class="admin-actions-cell"><form method="post" action="/admin/approve-seller" class="inline-form-2"><input type="hidden" name="request_id" value="{sr['id']}"><input type="hidden" name="_csrf" value="{esc(_csrf_token_for(req))}"><button type="submit">Approve</button></form><form method="post" action="/admin/reject-seller" class="inline-form-2"><input type="hidden" name="request_id" value="{sr['id']}"><input type="hidden" name="_csrf" value="{esc(_csrf_token_for(req))}"><button class="danger-button" type="submit">Reject</button></form></td></tr>""" for sr in seller_reqs) or '<tr><td colspan="7" class="muted">No pending seller requests for your school.</td></tr>') + """</tbody></table></div></section>"""
    # Build listings with remove buttons for superadmin
    latest_with_remove = "".join(
        f"""<div class="listing-card admin-listing-card">
      <a class="media" href="/listing/{l['id']}">{'<img src="' + esc(l['image_path']) + '" alt="">' if l['image_path'] else '<div class="image-fallback">UM</div>'}</a>
      <div class="card-body">
        <p class="eyebrow">{esc(l['category'])}</p>
        <h3><a href="/listing/{l['id']}">{esc(l['title'])}</a></h3>
        <p class="muted">{esc(l['seller'])} &middot; {money(l['price'])}</p>
      </div>
      {'<form method="post" action="/admin/remove-listing" class="admin-remove-form"><input type="hidden" name="listing_id" value="' + str(l['id']) + '"><input type="hidden" name="_csrf" value="' + esc(_csrf_token_for(req)) + '"><button class="danger-button" type="submit">Remove</button></form>' if is_super else ''}
    </div>"""
        for l in latest
    )
    # Chart data JSON
    cat_labels = [r['category'] for r in cat_data]
    cat_values = [r['c'] for r in cat_data]
    month_labels = [r['month'] for r in reversed(month_data)]
    month_values = [r['c'] for r in reversed(month_data)]
    listing_month_labels = [r['month'] for r in reversed(listing_month_data)]
    listing_month_values = [r['c'] for r in reversed(listing_month_data)]
    direct_admin_form = """
<section class="admin-section"><h1>Superadmin: Add Admin</h1>
<form method="post" action="/admin/add-admin" class="form"><label class="field-label" for="add-admin-name">Full name</label><input id="add-admin-name" name="name" required><label class="field-label" for="add-admin-email">Email</label><input id="add-admin-email" name="email" type="email" required><label class="field-label" for="add-admin-university">University</label><select id="add-admin-university" name="university" required><option value="">Select university</option>{university_options()}</select><label class="field-label" for="add-admin-password">Temporary password</label><input id="add-admin-password" name="password" type="password" minlength="8" autocomplete="new-password" required><label class="field-label" for="add-admin-password2">Confirm temporary password</label><input id="add-admin-password2" name="password2" type="password" minlength="8" autocomplete="new-password" required><button type="submit">Add Admin</button></form></section>""" if is_super else ""
    # Report generation form
    report_form = """
<section class="admin-section">
  <h1>Generate Report</h1>
  <form method="get" action="/admin/report/download" class="form admin-report-form">
    <input type="hidden" name="_csrf" value=""" + esc(_csrf_token_for(req)) + """>
    <label class="field-label" for="report-type">Report Type</label>
    <select id="report-type" name="type">
      <option value="sales">Sales Report</option>
      <option value="users">Users Report</option>
      <option value="listings">Listings Report</option>
    </select>
    <div class="split">
      <div>
        <label class="field-label" for="start-date">Start Date</label>
        <input type="date" id="start-date" name="start" required>
      </div>
      <div>
        <label class="field-label" for="end-date">End Date</label>
        <input type="date" id="end-date" name="end" required>
      </div>
    </div>
    <button type="submit">Download CSV</button>
  </form>
</section>""" if is_super else ""
    charts_js = ""
    charts_section = ""
    if is_super:
        cat_chart = svg_donut_chart(cat_labels, cat_values)
        users_chart = svg_line_chart(month_labels, month_values)
        listings_chart = svg_bar_chart(listing_month_labels, listing_month_values)
        charts_section = f"""
<section class="admin-section admin-charts">
  <h1>Analytics</h1>
  <div class="chart-grid">
    <div class="chart-card">
      <h3>Sales by Category</h3>
      {cat_chart}
    </div>
    <div class="chart-card">
      <h3>New Users Over Time</h3>
      {users_chart}
    </div>
    <div class="chart-card">
      <h3>New Listings Over Time</h3>
      {listings_chart}
    </div>
  </div>
</section>"""
    content = f"""
<section class="stat-grid admin-stats">
  {stat_card("👥", users_count, "Users", "blue")}
  {stat_card("📦", listings_count, "Listings", "amber")}
  {stat_card("🛍️", sellers_count, "Sellers", "teal")}
  {stat_card("🛡️", admins_count, "Admins", "coral")}
  {stat_card("🚩", len(reports), "Reports", "coral" if len(reports) else "teal")}
</section>
{users_table}
{seller_table}
{seller_req_html}
{admin_reqs_html}
{charts_section}
{charts_js}
{direct_admin_form}
{report_form}
<section class="columns">
  <div><h1>Reports</h1><ul>{report_html}</ul></div>
  <div><h1>Recent Listings</h1><div class="mini-list">{latest_with_remove}</div></div>
</section>"""
    return layout(req, "Admin", content, user)



def admin_add_admin(req):
    user, resp = require_user(req)
    if resp: return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    name = clamp(form.get("name", "").strip(), 160)
    email = clamp(form.get("email", "").strip().lower(), 200)
    university = clamp(form.get("university", "").strip(), 160)
    password = form.get("password", "")
    password2 = form.get("password2", "")
    if not name or not email or not university or len(password) < 8 or "@" not in email or password != password2:
        return redirect("/admin")
    try:
        with db() as conn:
            conn.execute("INSERT INTO users(name,email,university,role,is_superadmin,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,?,?,?)", (name, email, university, "admin", 0, password_hash(password), 1, now()))
    except sqlite3.IntegrityError:
        pass
    return redirect("/admin")


def manual_payment_submit(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req)
    order_id = as_int(form.get("order_id"))
    receipt = clamp(form.get("receipt_code", "").strip().upper(), 32)
    note = clamp(form.get("payment_note", "").strip(), 240)
    if not re.fullmatch(r"[A-Z0-9]{6,32}", receipt):
        return layout(req, "Payment details", '<section class="auth-panel"><p class="error">Enter a valid M-Pesa transaction code.</p><a class="button-link" href="/orders">Back to orders</a></section>', user)
    with db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=? AND buyer_id=?", (order_id, user["id"])).fetchone()
        if not order or order["payment_status"] == "paid": return redirect("/orders")
        conn.execute("UPDATE orders SET payment_method='manual_send_money', receipt_code=?, payment_note=?, payment_status='submitted', seller_order_status='pending', payment_rejected_reason='', payment_submitted_at=?, updated_at=? WHERE id=?", (receipt, note, now(), now(), order_id))
    return redirect(f"/payment/waiting/{order_id}")


def manual_payment_confirm(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req)
    order_id = as_int(form.get("order_id"))
    selected_status = form.get("seller_order_status", "pending").strip().lower()
    if selected_status not in {"pending", "paid", "picked"}:
        return redirect("/orders")
    buyer_email = buyer_name = listing_title = ""
    amount = 0
    confirmed = False
    with db() as conn:
        order = conn.execute("""SELECT o.*, b.email buyer_email, b.name buyer_name, l.title listing_title
                               FROM orders o JOIN users b ON b.id=o.buyer_id JOIN listings l ON l.id=o.listing_id
                               WHERE o.id=? AND o.seller_id=?""", (order_id, user["id"])).fetchone()
        if not order:
            return redirect("/orders")
        if selected_status == "pending":
            conn.execute("UPDATE orders SET seller_order_status='pending', updated_at=? WHERE id=? AND payment_status!='paid'", (now(), order_id))
        else:
            changed = conn.execute("UPDATE orders SET payment_status='paid', seller_order_status=?, delivery_status=?, payment_confirmed_at=CASE WHEN payment_confirmed_at=0 THEN ? ELSE payment_confirmed_at END, payment_rejected_reason='', updated_at=? WHERE id=? AND payment_status!='paid'", (selected_status, "paid" if selected_status == "paid" else "received", now(), now(), order_id))
            confirmed = changed.rowcount == 1
            if confirmed:
                buyer_email = order["buyer_email"] or ""
                buyer_name = order["buyer_name"] or "Buyer"
                listing_title = order["listing_title"] or "your item"
                amount = order["amount"]
    if confirmed and buyer_email:
        threading.Thread(target=send_payment_confirmation_email, args=(buyer_email, buyer_name, order_id, listing_title, amount), daemon=True).start()
    return redirect("/orders")


def payment_waiting_page(req, order_id):
    user, resp = require_user(req)
    if resp: return resp
    with db() as conn:
        order = conn.execute("""SELECT o.*, l.title, s.name seller, s.phone seller_phone
                               FROM orders o JOIN listings l ON l.id=o.listing_id JOIN users s ON s.id=o.seller_id
                               WHERE o.id=? AND o.buyer_id=?""", (order_id, user["id"])).fetchone()
    if not order:
        return layout(req, "Order not found", '<section class="auth-panel"><h1>Order not found</h1><a class="button-link" href="/orders">Back to orders</a></section>', user)
    if order["payment_status"] == "paid":
        heading = "Payment confirmed"
        message = f"{esc(order['seller'])} confirmed your payment for {esc(order['title'])}. Your order is {('picked' if order['seller_order_status'] == 'picked' else 'paid')}."
        eyebrow = "All set"
    elif order["payment_status"] == "submitted":
        heading = "Wait for seller confirmation"
        message = f"Your payment code was submitted. {esc(order['seller'])} needs to check their M-Pesa message or statement and confirm the payment before the order is marked paid."
        eyebrow = "Payment submitted"
    elif order["payment_status"] == "failed":
        heading = "Payment needs attention"
        message = "The seller could not confirm this payment. Check the transaction code and send the payment again if needed."
        eyebrow = "Not confirmed"
    else:
        heading = "Complete your payment"
        message = f"Send {money(order['amount'])} to {esc(order['seller_phone'] or 'the seller phone')}, then submit the M-Pesa transaction code."
        eyebrow = "Payment pending"
    content = f'''<section class="auth-panel payment-state"><p class="eyebrow">{eyebrow}</p><h1>{heading}</h1><p class="muted">{message}</p><p class="order-summary"><strong>Order #UM-{order_id:05d}</strong><span>{esc(order['title'])} · {money(order['amount'])}</span></p><a class="button-link" href="/orders">View orders</a></section>'''
    return layout(req, "Payment status", content, user)


def sdk_push(req):
    user, resp = require_user(req)
    if resp: return resp
    form, _ = parse_form(req)
    order_id = as_int(form.get("order_id"))
    with db() as conn:
        order = conn.execute("SELECT o.*, u.phone FROM orders o JOIN users u ON u.id=o.buyer_id WHERE o.id=? AND o.buyer_id=?", (order_id, user["id"])).fetchone()
    if not order:
        return layout(req, "Payment unavailable", '<p class="error">That order is not available.</p>', user)
    if order["payment_status"] == "paid": return redirect("/orders")
    phone, phone_err = validate_phone(form.get("phone", "").strip() or order["phone"])
    if phone_err:
        return layout(req, "Payment details", f'<p class="error">{esc(phone_err)}</p><a class="button-link" href="/orders">Back to orders</a>', user)
    try:
        consumer_key=os.environ["MPESA_CONSUMER_KEY"]; consumer_secret=os.environ["MPESA_CONSUMER_SECRET"]
        shortcode=os.environ["MPESA_SHORTCODE"]; passkey=os.environ["MPESA_PASSKEY"]
        callback_url=os.environ.get("MPESA_CALLBACK_URL", f"{APP_BASE_URL}/payment/mpesa/callback")
    except KeyError:
        return layout(req, "M-Pesa setup needed", '<p class="error">M-Pesa credentials are not configured yet.</p><a class="button-link" href="/orders">Back to orders</a>', user)
    base_url="https://api.safaricom.co.ke" if os.environ.get("MPESA_ENV", "sandbox").lower()=="production" else "https://sandbox.safaricom.co.ke"
    try:
        auth=base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()
        token_req=urllib.request.Request(f"{base_url}/oauth/v1/generate?grant_type=client_credentials", headers={"Authorization":f"Basic {auth}"})
        with urllib.request.urlopen(token_req, timeout=20) as r: token=json.loads(r.read().decode())["access_token"]
        timestamp=time.strftime("%Y%m%d%H%M%S", time.localtime())
        password=base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()
        normalized=phone.replace("+", "")
        payload={"BusinessShortCode":shortcode,"Password":password,"Timestamp":timestamp,"TransactionType":"CustomerPayBillOnline","Amount":max(1,int(round(float(order["amount"]))),),"PartyA":normalized,"PartyB":shortcode,"PhoneNumber":normalized,"CallBackURL":callback_url,"AccountReference":f"UM{order_id}","TransactionDesc":f"UniMarket order {order_id}"}
        push_req=urllib.request.Request(f"{base_url}/mpesa/stkpush/v1/processrequest", data=json.dumps(payload).encode(), headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"}, method="POST")
        with urllib.request.urlopen(push_req, timeout=30) as r: result=json.loads(r.read().decode())
        accepted=str(result.get("ResponseCode", ""))=="0"
        with db() as conn:
            conn.execute("UPDATE orders SET sdk_push_status=?, checkout_request_id=?, merchant_request_id=?, payment_result=?, updated_at=? WHERE id=?", ("sent" if accepted else "failed", result.get("CheckoutRequestID", ""), result.get("MerchantRequestID", ""), result.get("ResponseDescription", result.get("errorMessage", "")), now(), order_id))
        message="Check your phone and enter your M-Pesa PIN. Your order updates after Safaricom confirms payment." if accepted else "Safaricom did not accept the payment request."
        return layout(req, "M-Pesa payment", f'<section class="auth-panel"><p class="eyebrow">M-Pesa</p><h1>{esc(message)}</h1><p class="muted">Order #{order_id:05d}, {money(order["amount"])}</p><a class="button-link" href="/orders">View orders</a></section>', user)
    except (urllib.error.URLError, TimeoutError, KeyError, ValueError, json.JSONDecodeError) as exc:
        with db() as conn: conn.execute("UPDATE orders SET sdk_push_status='failed', payment_result=?, updated_at=? WHERE id=?", (str(exc)[:240], now(), order_id))
        return layout(req, "Payment error", '<p class="error">Could not start the M-Pesa request. Check Render logs and try again.</p><a class="button-link" href="/orders">Back to orders</a>', user)


def mpesa_callback(req):
    try:
        payload=json.loads(req.body.decode("utf-8")); callback=payload.get("Body", {}).get("stkCallback", {})
        checkout_id=callback.get("CheckoutRequestID", ""); result_code=int(callback.get("ResultCode", -1))
        items={item.get("Name"):item.get("Value") for item in callback.get("CallbackMetadata", {}).get("Item", [])}
        with db() as conn:
            order=conn.execute("SELECT id FROM orders WHERE checkout_request_id=?", (checkout_id,)).fetchone()
            if order and result_code==0:
                conn.execute("UPDATE orders SET payment_status='paid', delivery_status='paid', sdk_push_status='confirmed', mpesa_receipt=?, payment_result=?, updated_at=? WHERE id=?", (str(items.get("MpesaReceiptNumber", "")), str(callback.get("ResultDesc", ""))[:240], now(), order["id"]))
            elif order:
                conn.execute("UPDATE orders SET sdk_push_status='failed', payment_result=?, updated_at=? WHERE id=?", (str(callback.get("ResultDesc", "Payment failed"))[:240], now(), order["id"]))
    except (ValueError, TypeError, json.JSONDecodeError, sqlite3.Error) as exc: print(f"[MPESA CALLBACK ERROR] {exc}")
    return Response("OK", 200, "text/plain")

# ---------------------------------------------------------------------------
# Admin: block/unblock user, remove listing, report download, admin requests
# ---------------------------------------------------------------------------
def admin_block_user(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    target_id = as_int(form.get("user_id"))
    if not target_id:
        return redirect("/admin")
    reason = form.get("reason", "Suspended by admin").strip()
    with db() as conn:
        conn.execute("UPDATE users SET suspended=1, suspend_reason=? WHERE id=?", (reason, target_id))
    return redirect("/admin")


def admin_unblock_user(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    target_id = as_int(form.get("user_id"))
    if not target_id:
        return redirect("/admin")
    with db() as conn:
        conn.execute("UPDATE users SET suspended=0, suspend_reason='' WHERE id=?", (target_id,))
    return redirect("/admin")


def admin_remove_listing(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    listing_id = as_int(form.get("listing_id"))
    if not listing_id:
        return redirect("/admin")
    with db() as conn:
        conn.execute("UPDATE listings SET status='removed', updated_at=? WHERE id=?", (now(), listing_id))
    return redirect("/admin")



# ---------------------------------------------------------------------------
# Admin & superadmin reports  /admin/reports
# ---------------------------------------------------------------------------
def admin_reports_page(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin":
        return layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    is_super = user["is_superadmin"]
    start, end, start_ts, end_ts = _date_range(req)
    if not start:
        start = time.strftime('%Y-%m-01')
        start_ts = int(time.mktime(time.strptime(start, "%Y-%m-%d")))
    if not end:
        end = time.strftime('%Y-%m-%d')
        end_ts = int(time.mktime(time.strptime(end, "%Y-%m-%d"))) + 86399
    # Scope: superadmin sees all, regular admin sees only their university
    uni_filter = ""
    uni_params = []
    if not is_super:
        uni_filter = " AND seller_uni.university=?"
        uni_params = [user["university"]]
    with db() as conn:
        # Total sales data (scoped)
        sales = conn.execute(
            f"""SELECT o.id, o.amount, o.payment_status, o.delivery_status, o.created_at,
                       l.title, l.category, b.name buyer_name, s.name seller_name,
                       s.university seller_university
                FROM orders o
                JOIN listings l ON l.id=o.listing_id
                JOIN users b ON b.id=o.buyer_id
                JOIN users s ON s.id=o.seller_id
                JOIN users seller_uni ON seller_uni.id=o.seller_id
                WHERE o.created_at>=? AND o.created_at<=?{uni_filter}
                ORDER BY o.created_at DESC""",
            [start_ts, end_ts] + uni_params,
        ).fetchall()
        total_revenue = sum(r["amount"] for r in sales if r["payment_status"] == "paid")
        total_orders = len(sales)
        paid_count = sum(1 for r in sales if r["payment_status"] == "paid")
        pending_count = sum(1 for r in sales if r["payment_status"] == "pending")

        # Revenue by category
        cat_rev = {}
        for r in sales:
            if r["payment_status"] == "paid":
                cat_rev[r["category"]] = cat_rev.get(r["category"], 0) + r["amount"]
        cat_labels = list(cat_rev.keys())
        cat_values = [int(cat_rev[c]) for c in cat_labels]

        # Revenue by university (superadmin only)
        uni_rev = {}
        if is_super:
            for r in sales:
                if r["payment_status"] == "paid":
                    uni = r["seller_university"] or "Unknown"
                    uni_rev[uni] = uni_rev.get(uni, 0) + r["amount"]
        uni_labels = list(uni_rev.keys())
        uni_values = [int(uni_rev[u]) for u in uni_labels]

        # Monthly revenue trend
        month_rev = {}
        for r in sales:
            if r["payment_status"] == "paid":
                m = time.strftime('%Y-%m', time.gmtime(r["created_at"]))
                month_rev[m] = month_rev.get(m, 0) + r["amount"]
        sorted_months = sorted(month_rev.keys())
        month_labels = sorted_months
        month_values = [int(month_rev[m]) for m in sorted_months]

        # Orders by status
        status_counts = {}
        for r in sales:
            s = r["payment_status"]
            status_counts[s] = status_counts.get(s, 0) + 1
        status_labels = list(status_counts.keys())
        status_values = [status_counts[s] for s in status_labels]

        # Top sellers
        seller_totals = {}
        for r in sales:
            if r["payment_status"] == "paid":
                key = r["seller_name"]
                if key not in seller_totals:
                    seller_totals[key] = {"count": 0, "revenue": 0}
                seller_totals[key]["count"] += 1
                seller_totals[key]["revenue"] += r["amount"]
        top_sellers = sorted(seller_totals.items(), key=lambda x: x[1]["revenue"], reverse=True)[:10]

    cat_chart = svg_donut_chart(cat_labels, cat_values) if cat_labels else '<p class="muted">No sales data for this period.</p>'
    trend_chart = svg_bar_chart(month_labels, month_values) if month_labels else '<p class="muted">No sales data for this period.</p>'
    status_chart = svg_donut_chart(status_labels, status_values) if status_labels else '<p class="muted">No data.</p>'

    uni_chart_html = ""
    if is_super and uni_labels:
        uni_chart_html = f'<div class="chart-card"><h3>Revenue by University</h3>{svg_donut_chart(uni_labels, uni_values)}</div>'
    elif is_super:
        uni_chart_html = '<div class="chart-card"><h3>Revenue by University</h3><p class="muted">No data yet.</p></div>'

    top_sellers_rows = "".join(
        f'<tr><td>{esc(name)}</td><td>{info["count"]}</td><td><strong>{money(info["revenue"])}</strong></td></tr>'
        for name, info in top_sellers
    ) or '<tr><td colspan="3" class="muted">No sellers with paid orders in this period.</td></tr>'

    sales_rows = "".join(
        f"""<tr>
            <td>#{r['id']:05d}</td>
            <td>{esc(r['title'])}</td>
            <td>{esc(r['category'])}</td>
            <td>{esc(r['buyer_name'])}</td>
            <td>{esc(r['seller_name'])}</td>
            {f'<td>{esc(r["seller_university"])}</td>' if is_super else ''}
            <td><strong>{money(r['amount'])}</strong></td>
            <td><span class="chip chip-{esc(r['payment_status'])}">{esc(r['payment_status'].title())}</span></td>
            <td>{time.strftime('%Y-%m-%d', time.gmtime(r['created_at']))}</td>
        </tr>"""
        for r in sales
    ) or f'<tr><td colspan="{"9" if is_super else "8"}" class="muted">No transactions in this period.</td></tr>'

    scope_label = "All universities" if is_super else esc(user["university"])
    report_opts = ''.join(f'<option value="{v}">{label}</option>' for v, label in (
        ("sales", "Sales Report"), ("users", "Users Report"), ("listings", "Listings Report"),
        ("transactions", "Transaction Report"), ("buyers", "Buyer Activity Report"),
    ))

    content = f"""
<section class="toolbar">
  <div>
    <p class="eyebrow">{"Superadmin" if is_super else "Admin"} reports &middot; {scope_label}</p>
    <h1>Sales &amp; Analytics Reports</h1>
    <p class="muted">Charts and downloadable reports for {"all schools" if is_super else "your university"}.</p>
  </div>
</section>
<section class="admin-section report-builder">
  <h2>Date range</h2>
  <form method="get" action="/admin/reports" class="form">
    <div class="split">
      <div><label class="field-label" for="start">From</label><input id="start" type="date" name="start" value="{esc(start)}" required></div>
      <div><label class="field-label" for="end">To</label><input id="end" type="date" name="end" value="{esc(end)}" required></div>
    </div>
    <button>Apply Filter</button>
  </form>
</section>
<section class="stat-grid">
  {stat_card("🛒", total_orders, "Total Orders", "amber")}
  {stat_card("✅", paid_count, "Paid", "teal")}
  {stat_card("⏳", pending_count, "Pending", "coral")}
  {stat_card("💰", money(total_revenue), "Total Revenue", "blue")}
</section>
<section class="admin-section admin-charts">
  <h2>Visual Analytics</h2>
  <div class="chart-grid">
    <div class="chart-card"><h3>Revenue by Category</h3>{cat_chart}</div>
    <div class="chart-card"><h3>Monthly Revenue</h3>{trend_chart}</div>
    <div class="chart-card"><h3>Order Status Breakdown</h3>{status_chart}</div>
    {uni_chart_html}
  </div>
</section>
<section class="admin-section">
  <h2>Top Sellers</h2>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Seller</th><th>Orders</th><th>Revenue</th></tr></thead>
    <tbody>{top_sellers_rows}</tbody>
  </table>
  </div>
</section>
<section class="admin-section">
  <div class="section-heading">
    <h2>All Transactions</h2>
    <a class="button-link" href="/admin/report/download?type=transactions&start={esc(start)}&end={esc(end)}">Download CSV</a>
  </div>
  <div class="admin-table-wrap">
  <table class="admin-table">
    <thead><tr><th>Order</th><th>Item</th><th>Category</th><th>Buyer</th><th>Seller</th>{"<th>University</th>" if is_super else ""}<th>Amount</th><th>Payment</th><th>Date</th></tr></thead>
    <tbody>{sales_rows}</tbody>
  </table>
  </div>
</section>
<section class="admin-section report-builder">
  <h2>Download a Report</h2>
  <form method="get" action="/admin/report/download" class="form">
    <label class="field-label" for="report-type">Report type</label>
    <select id="report-type" name="type">{report_opts}</select>
    <div class="split">
      <div><label class="field-label" for="dl-start">From</label><input id="dl-start" type="date" name="start" value="{esc(start)}" required></div>
      <div><label class="field-label" for="dl-end">To</label><input id="dl-end" type="date" name="end" value="{esc(end)}" required></div>
    </div>
    <button>Download CSV</button>
  </form>
</section>"""
    return layout(req, "Admin Reports", content, user)


def admin_report_download(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin":
        return layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    import csv as _csv
    from io import StringIO
    report_type = req.query.get("type", ["sales"])[0]
    start_str = req.query.get("start", [""])[0]
    end_str = req.query.get("end", [""])[0]
    try:
        start_ts = int(time.mktime(time.strptime(start_str, "%Y-%m-%d"))) if start_str else 0
        end_ts = int(time.mktime(time.strptime(end_str, "%Y-%m-%d"))) + 86399 if end_str else now()
    except (ValueError, OverflowError):
        start_ts, end_ts = 0, now()
    buf = StringIO()
    writer = _csv.writer(buf)
    with db() as conn:
        if report_type == "sales":
            writer.writerow(["Listing ID", "Title", "Category", "Price", "Condition", "Location", "Seller", "Sold At"])
            rows = conn.execute(
                """SELECT l.id, l.title, l.category, l.price, l.condition, l.location, u.name seller, l.updated_at
                   FROM listings l JOIN users u ON u.id=l.user_id
                   WHERE l.status='sold' AND l.updated_at>=? AND l.updated_at<=?
                   ORDER BY l.updated_at DESC""",
                (start_ts, end_ts),
            ).fetchall()
            for r in rows:
                writer.writerow([r["id"], r["title"], r["category"], r["price"], r["condition"], r["location"], r["seller"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["updated_at"]))])
        elif report_type == "users":
            writer.writerow(["User ID", "Name", "Email", "Phone", "Role", "University", "Joined"])
            rows = conn.execute(
                "SELECT id, name, email, phone, role, university, created_at FROM users WHERE created_at>=? AND created_at<=? ORDER BY created_at DESC",
                (start_ts, end_ts),
            ).fetchall()
            for r in rows:
                writer.writerow([r["id"], r["name"], r["email"], r["phone"], r["role"], r["university"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created_at"]))])
        elif report_type == "listings":
            writer.writerow(["Listing ID", "Title", "Category", "Price", "Status", "Seller", "Created At"])
            rows = conn.execute(
                """SELECT l.id, l.title, l.category, l.price, l.status, u.name seller, l.created_at
                   FROM listings l JOIN users u ON u.id=l.user_id
                   WHERE l.created_at>=? AND l.created_at<=?
                   ORDER BY l.created_at DESC""",
                (start_ts, end_ts),
            ).fetchall()
            for r in rows:
                writer.writerow([r["id"], r["title"], r["category"], r["price"], r["status"], r["seller"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created_at"]))])
        elif report_type == "buyers":
            writer.writerow(["Buyer", "Email", "Orders", "Total Spend", "Last Order"])
            rows = conn.execute("""SELECT u.name, u.email, count(o.id) orders, coalesce(sum(o.amount),0) total_spend, max(o.updated_at) last_order FROM orders o JOIN users u ON u.id=o.buyer_id WHERE o.created_at>=? AND o.created_at<=? GROUP BY o.buyer_id ORDER BY total_spend DESC""", (start_ts, end_ts)).fetchall()
            for r in rows: writer.writerow([r["name"], r["email"], r["orders"], r["total_spend"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["last_order"])) if r["last_order"] else ""])
        elif report_type == "transactions":
            writer.writerow(["Order ID", "Buyer", "Seller", "Item", "Amount", "Payment Status", "Delivery Status", "Transaction Date"])
            rows = conn.execute("""SELECT o.id, b.name buyer, s.name seller, l.title, o.amount, o.payment_status, o.delivery_status, o.created_at FROM orders o JOIN users b ON b.id=o.buyer_id JOIN users s ON s.id=o.seller_id JOIN listings l ON l.id=o.listing_id WHERE o.created_at>=? AND o.created_at<=? ORDER BY o.created_at DESC""", (start_ts, end_ts)).fetchall()
            for r in rows: writer.writerow([r["id"], r["buyer"], r["seller"], r["title"], r["amount"], r["payment_status"], r["delivery_status"], time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["created_at"]))])
    csv_data = buf.getvalue()
    filename = f"unimarket-{report_type}-{start_str or 'all'}-to-{end_str or 'now'}.csv"
    return Response(
        csv_data,
        200,
        "text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def _seller_request_reviewer(req):
    user, resp = require_user(req)
    if resp: return None, resp
    if user["role"] != "admin": return None, layout(req, "Forbidden", '<p class="error">Admin access required.</p>', user)
    return user, None


def admin_approve_seller(req):
    user, resp = _seller_request_reviewer(req)
    if resp: return resp
    form, _ = parse_form(req); req_id = as_int(form.get("request_id"))
    with db() as conn:
        sr = conn.execute("SELECT * FROM seller_requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
        if not sr or (not user["is_superadmin"] and sr["university"] != user["university"]): return layout(req, "Forbidden", '<p class="error">That seller request is outside your school or no longer pending.</p>', user)
        conn.execute("UPDATE seller_requests SET status='approved', reviewed_by=?, reviewed_at=? WHERE id=?", (user["id"], now(), req_id))
        conn.execute("UPDATE users SET role='seller', seller_status='approved', university=? WHERE id=?", (sr["university"], sr["user_id"]))
    return redirect("/admin")


def admin_reject_seller(req):
    user, resp = _seller_request_reviewer(req)
    if resp: return resp
    form, _ = parse_form(req); req_id = as_int(form.get("request_id"))
    with db() as conn:
        sr = conn.execute("SELECT * FROM seller_requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
        if not sr or (not user["is_superadmin"] and sr["university"] != user["university"]): return layout(req, "Forbidden", '<p class="error">That seller request is outside your school or no longer pending.</p>', user)
        conn.execute("UPDATE seller_requests SET status='rejected', reviewed_by=?, reviewed_at=? WHERE id=?", (user["id"], now(), req_id))
        conn.execute("UPDATE users SET seller_status='rejected' WHERE id=? AND role='buyer'", (sr["user_id"],))
    return redirect("/admin")


def admin_approve_request(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    req_id = as_int(form.get("request_id"))
    if not req_id:
        return redirect("/admin")
    with db() as conn:
        ar = conn.execute("SELECT * FROM admin_requests WHERE id=? AND status='pending'", (req_id,)).fetchone()
        if ar:
            conn.execute("UPDATE admin_requests SET status='approved' WHERE id=?", (req_id,))
            conn.execute("UPDATE users SET role='admin' WHERE id=?", (ar["user_id"],))
    return redirect("/admin")


def admin_reject_request(req):
    user, resp = require_user(req)
    if resp:
        return resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    form, _ = parse_form(req)
    req_id = as_int(form.get("request_id"))
    if not req_id:
        return redirect("/admin")
    with db() as conn:
        conn.execute("UPDATE admin_requests SET status='rejected' WHERE id=? AND status='pending'", (req_id,))
    return redirect("/admin")


def admin_request_page(req):
    user, resp = require_user(req)
    if resp: return resp
    if user["role"] == "admin":
        return layout(req, "Already Admin", '<section class="auth-panel"><p class="eyebrow">Admin account</p><h1>You are already an admin</h1><p class="muted">You already have admin privileges.</p><a class="button-link" href="/admin">Go to Admin Console</a></section>', user)
    with db() as conn:
        existing = conn.execute("SELECT * FROM admin_requests WHERE user_id=? AND status='pending'", (user["id"],)).fetchone()
    if existing:
        return layout(req, "Request Pending", '<section class="auth-panel"><p class="eyebrow">Application pending</p><h1>Your admin request is being reviewed</h1><p class="muted">You will be notified once a decision is made. Check back later.</p><a class="button-link" href="/">Go home</a></section>', user)
    content = f"""
<section class="auth-panel admin-application"><p class="eyebrow">Apply for admin access</p><h1>Become a UniMarket Admin</h1><p class="muted">Complete the identity trail. All fields are labelled so nothing gets missed.</p>
<form method="post" action="/admin-request/submit" enctype="multipart/form-data" class="form">{csrf_input(req)}
<label class="field-label" for="full_name">Full name</label><input id="full_name" name="full_name" required>
<label class="field-label" for="staff_number">Staff number</label><input id="staff_number" name="staff_number" required>
<label class="field-label" for="university">University</label><select id="university" name="university" required><option value="">Select university</option>{university_options()}</select>
<label class="field-label" for="id_number">National ID number</label><input id="id_number" name="id_number" required>
<label class="field-label" for="phone">Phone number</label><input id="phone" name="phone" required pattern="^(\\+?254|0)[17]\\d{{8}}$" title="Use 0712345678, 0112345678, or +254712345678" inputmode="tel">
<label class="field-label" for="kra_pin">KRA PIN</label><input id="kra_pin" name="kra_pin" required>
<label class="field-label" for="cover_letter">Cover letter introduction</label><input id="cover_letter" name="cover_letter" type="file" accept="image/png,image/jpeg,application/pdf,.doc,.docx" required>
<label class="field-label" for="national_id">Copy of national ID</label><input id="national_id" name="national_id" type="file" accept="image/png,image/jpeg,application/pdf" required>
<label class="field-label" for="kra_certificate">KRA PIN document</label><input id="kra_certificate" name="kra_certificate" type="file" accept="image/png,image/jpeg,application/pdf" required>
<button type="submit">Submit Request</button></form></section>"""
    return layout(req, "Apply as Admin", content, user)


def admin_request_submit(req):
    user, resp = require_user(req)
    if resp: return resp
    if user["role"] == "admin": return redirect("/admin")
    with db() as conn:
        existing = conn.execute("SELECT * FROM admin_requests WHERE user_id=? AND status='pending'", (user["id"],)).fetchone()
    if existing: return redirect("/admin-request")
    form, files = parse_form(req)
    staff_number = clamp(form.get("staff_number", "").strip(), 80)
    full_name = clamp(form.get("full_name", "").strip(), 160)
    university = clamp(form.get("university", "").strip(), 160)
    id_number = clamp(form.get("id_number", "").strip(), 80)
    kra_pin = clamp(form.get("kra_pin", "").strip(), 80)
    phone, phone_err = validate_phone(form.get("phone", ""))
    required_files = (files.get("cover_letter"), files.get("national_id"), files.get("kra_certificate"))
    if phone_err or not all((staff_number, full_name, university, id_number, kra_pin)) or not all(required_files): return admin_request_page(req)
    cover_path, id_path, kra_path = (save_upload(files.get(k), allow_docs=True) or "" for k in ("cover_letter", "national_id", "kra_certificate"))
    if not all((cover_path, id_path, kra_path)): return admin_request_page(req)
    with db() as conn:
        conn.execute("""INSERT INTO admin_requests(user_id, staff_number, full_name, university, id_number, phone, cover_letter_path, national_id_path, kra_pin, kra_certificate_path, status, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (user["id"], staff_number, full_name, university, id_number, phone, cover_path, id_path, kra_pin, kra_path, "pending", now()))
    return layout(req, "Request Submitted", '<section class="auth-panel"><p class="eyebrow">Application submitted</p><h1>Your admin request has been submitted</h1><p class="muted">A superadmin will review your full name, staff number, university, cover letter introduction, national ID, and KRA PIN.</p><a class="button-link" href="/">Go home</a></section>', user)

# ---------------------------------------------------------------------------
# Protected admin-application document access
# ---------------------------------------------------------------------------
def _require_superadmin(req):
    user, resp = require_user(req)
    if resp:
        return None, resp
    if user["role"] != "admin" or not user["is_superadmin"]:
        return None, layout(req, "Forbidden", '<p class="error">Superadmin access required.</p>', user)
    return user, None

def admin_request_document(req):
    user, resp = _require_superadmin(req)
    if resp:
        return resp
    request_id = as_int(req.query.get("request_id", [""])[0])
    document_key = req.query.get("document", [""])[0]
    document_columns = {
        "cover_letter": "cover_letter_path",
        "national_id": "national_id_path",
        "kra_certificate": "kra_certificate_path",
    }
    column = document_columns.get(document_key)
    if not request_id or not column:
        return Response("Document not found", 404, "text/plain")
    with db() as conn:
        row = conn.execute(f"SELECT {column} document_path FROM admin_requests WHERE id=?", (request_id,)).fetchone()
    if not row or not row["document_path"]:
        return Response("Document not found", 404, "text/plain")
    return serve_file(row["document_path"], req=req)

# ---------------------------------------------------------------------------
# Static / uploads file serving
# ---------------------------------------------------------------------------
def serve_file(path, req=None):
    if path.startswith("/uploads/"):
        with db() as conn:
            protected_doc = conn.execute(
                "SELECT 1 FROM admin_requests WHERE cover_letter_path=? OR national_id_path=? OR kra_certificate_path=? LIMIT 1",
                (path, path, path),
            ).fetchone()
        if protected_doc:
            user, resp = _require_superadmin(req)
            if resp:
                return resp
    root = STATIC if path.startswith("/static/") else UPLOADS
    name = urllib.parse.unquote(path.split("/", 2)[2])
    file = (root / name).resolve()
    if root.resolve() not in file.parents or not file.exists():
        return Response("Not found", 404, "text/plain")
    return Response(
        file.read_bytes(), 200,
        mimetypes.guess_type(file.name)[0] or "application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
def route(req):
    # Every state-changing request must carry the token emitted with its form.
    # Individual handlers may retain their local checks, but this central guard
    # protects newer handlers from accidentally being added without one.
    if req.path == "/payment/mpesa/callback" and req.method == "POST":
        return mpesa_callback(req)
    if req.method == "POST":
        if err := csrf_protected(req):
            return err
    if req.path == "/admin/request-document":
        return admin_request_document(req)
    if req.path.startswith("/static/") or req.path.startswith("/uploads/"):
        return serve_file(req.path, req=req)
    if req.path == "/":
        return home(req)
    if req.path == "/register":
        return register(req)
    if req.path == "/login":
        return login(req)
    if req.path == "/logout" and req.method == "POST":
        return logout(req)
    if req.path == "/verify-email":
        return verify_email_page(req)
    if req.path == "/verify-email/resend" and req.method == "POST":
        return resend_otp(req)
    if req.path == "/verify/resend" and req.method == "POST":
        return resend_verification(req)
    if req.path == "/listing/new":
        return create_listing(req)
    if req.path == "/listing/sold" and req.method == "POST":
        return mark_listing_sold(req)
    if req.path == "/profile":
        return profile(req)
    if req.path == "/profile/edit":
        return edit_profile(req)
    if req.path == "/profile/upgrade-seller" and req.method == "POST":
        return upgrade_seller(req)
    if req.path == "/seller":
        return seller_dashboard(req)
    if req.path == "/orders":
        return orders_page(req)
    if req.path == "/reports":
        return reports_page(req)
    if req.path == "/order" and req.method == "POST":
        return place_order(req)
    if req.path == "/order/status" and req.method == "POST":
        return order_status(req)
    if req.path == "/order/location" and req.method == "POST":
        return update_order_location(req)
    if req.path == "/admin/add-admin" and req.method == "POST":
        return admin_add_admin(req)
    if req.path == "/payment/manual-submit" and req.method == "POST":
        return manual_payment_submit(req)
    if req.path == "/payment/manual-confirm" and req.method == "POST":
        return manual_payment_confirm(req)
    if req.path == "/payment/sdk-push" and req.method == "POST":
        return sdk_push(req)
    if req.path == "/wishlist":
        return wishlist(req)
    if req.path == "/inbox":
        return inbox(req)
    if req.path == "/admin":
        return admin(req)
    if req.path == "/admin/report/status" and req.method == "POST":
        return update_report_status(req)
    if req.path == "/admin/hide-listing" and req.method == "POST":
        return hide_reported_listing(req)
    if req.path == "/admin/block-user" and req.method == "POST":
        return admin_block_user(req)
    if req.path == "/admin/unblock-user" and req.method == "POST":
        return admin_unblock_user(req)
    if req.path == "/admin/remove-listing" and req.method == "POST":
        return admin_remove_listing(req)
    if req.path == "/admin/reports":
        return admin_reports_page(req)
    if req.path == "/admin/report/download" and req.method == "GET":
        return admin_report_download(req)
    if req.path == "/admin/approve-seller" and req.method == "POST":
        return admin_approve_seller(req)
    if req.path == "/admin/reject-seller" and req.method == "POST":
        return admin_reject_seller(req)
    if req.path == "/admin/approve-request" and req.method == "POST":
        return admin_approve_request(req)
    if req.path == "/admin/reject-request" and req.method == "POST":
        return admin_reject_request(req)
    if req.path == "/admin-request":
        return admin_request_page(req)
    if req.path == "/admin-request/submit" and req.method == "POST":
        return admin_request_submit(req)
    if req.path == "/wishlist/toggle" and req.method == "POST":
        return wishlist_toggle(req)
    if req.path == "/message" and req.method == "POST":
        return post_message(req)
    if req.path == "/offer" and req.method == "POST":
        return post_offer(req)
    if req.path == "/offer/status" and req.method == "POST":
        return update_offer_status(req)
    if req.path == "/review" and req.method == "POST":
        return post_review(req)
    if req.path == "/report" and req.method == "POST":
        return post_report(req)
    if req.path == "/categories":
        return categories_page(req)
    if req.path == "/alerts":
        return alerts_page(req)
    if req.path == "/alerts/save" and req.method == "POST":
        return save_alert(req)
    if req.path == "/alerts/delete" and req.method == "POST":
        return delete_alert(req)
    if req.path == "/buyer":
        return buyer_dashboard(req)
    if req.path == "/buyer/offers":
        return buyer_offers(req)
    if req.path == "/buyer/offers/cancel" and req.method == "POST":
        return cancel_offer(req)
    if req.path == "/buyer/reviews":
        return buyer_reviews(req)
    if req.path == "/buyer/history":
        return buyer_history(req)
    if req.path == "/buyer/reports":
        return buyer_reports_page(req)
    if req.path == "/buyer/reports/download":
        return buyer_reports_download(req)
    if req.path == "/seller/reports":
        return seller_reports_page(req)
    if req.path == "/seller/reports/download":
        return seller_reports_download(req)
    if req.path == "/forgot-password":
        return forgot_password(req)

    parts = req.path.strip("/").split("/")

    # /verify/<token>
    if len(parts) == 2 and parts[0] == "verify":
        return verify_email(req, parts[1])
    # /forgot-password handled above; /reset-password/<token>
    if len(parts) == 2 and parts[0] == "reset-password":
        return reset_password(req, parts[1])
    # /payment/waiting/<id>
    if len(parts) == 3 and parts[0] == "payment" and parts[1] == "waiting" and parts[2].isdigit():
        return payment_waiting_page(req, int(parts[2]))
    # /seller/<id>
    if len(parts) == 2 and parts[0] == "seller" and parts[1].isdigit():
        return public_seller_profile(req, int(parts[1]))
    # /category/<name>
    if len(parts) == 2 and parts[0] == "category":
        return category_page(req, urllib.parse.unquote(parts[1]))
    # /conversation/<id>
    if len(parts) == 2 and parts[0] == "conversation" and parts[1].isdigit():
        return conversation_view(req, int(parts[1]))
    # /conversation/<id>/reply
    if len(parts) == 3 and parts[0] == "conversation" and parts[1].isdigit() and parts[2] == "reply" and req.method == "POST":
        return conversation_reply(req, int(parts[1]))
    # /buyer/reviews/<id>/edit   /buyer/reviews/<id>/delete
    if len(parts) == 4 and parts[0] == "buyer" and parts[1] == "reviews" and parts[2].isdigit():
        if parts[3] == "edit":
            return edit_review_page(req, int(parts[2]))
        if parts[3] == "delete" and req.method == "POST":
            return delete_review(req, int(parts[2]))
    # /order/<id>/track
    if len(parts) == 3 and parts[0] == "order" and parts[1].isdigit() and parts[2] == "track":
        return order_tracker(req, int(parts[1]))
    # /listing/<id>
    if len(parts) == 2 and parts[0] == "listing" and parts[1].isdigit():
        return listing_detail(req, int(parts[1]))
    # /listing/<id>/edit
    if len(parts) == 3 and parts[0] == "listing" and parts[1].isdigit() and parts[2] == "edit":
        return edit_listing(req, int(parts[1]))
    # /listing/<id>/bump
    if len(parts) == 3 and parts[0] == "listing" and parts[1].isdigit() and parts[2] == "bump" and req.method == "POST":
        return bump_listing(req, int(parts[1]))

    response = layout(req, "Not Found", '<p class="empty">Page not found.</p>')
    response.status = 404
    return response


# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------
def send(conn, resp):
    headers = {
        "Content-Type": resp.ctype,
        "Content-Length": str(len(resp.body)),
        "Connection": "close",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'none'; "
            "frame-ancestors 'none';"
        ),
    }
    headers.update(resp.headers)
    # Flatten the CSRF cookie alias into the real Set-Cookie header
    if "Set-Cookie-CSRF" in headers:
        csrf_cookie = headers.pop("Set-Cookie-CSRF")
        existing = headers.get("Set-Cookie", "")
        # We need to send two Set-Cookie headers; abuse a list trick via the raw bytes
        # Instead, append as a second header in the head string directly
        head = (
            f"HTTP/1.1 {resp.status} {STATUS.get(resp.status, 'OK')}\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            + f"Set-Cookie: {csrf_cookie}\r\n"
            + "\r\n"
        )
        conn.sendall(head.encode() + resp.body)
        return
    head = (
        f"HTTP/1.1 {resp.status} {STATUS.get(resp.status, 'OK')}\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        + "\r\n"
    )
    conn.sendall(head.encode() + resp.body)


def handle(conn):
    try:
        conn.settimeout(3)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        headers_raw = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        length = 0
        for line in headers_raw.split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
        body_have = len(data.split(b"\r\n\r\n", 1)[1])
        while body_have < length:
            chunk = conn.recv(min(65536, length - body_have))
            if not chunk:
                break
            data += chunk
            body_have += len(chunk)
        req = Request(data)
        send(conn, route(req))
    except Exception as exc:
        send(conn, Response(f"<h1>Server error</h1><pre>{esc(exc)}</pre>", 500))
    finally:
        conn.close()


def run():
    init_db()
    threading.Thread(target=_expiry_worker, daemon=True).start()
    print(f"UniMarket running at http://{HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)
        while True:
            conn, _addr = s.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    run()
