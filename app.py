"""
Accommodation Link — v2 final single-file app
Run: python app.py  ->  http://127.0.0.1:5000
Admin: admin@accommodationlink.co.zw / Admin@123
"""
import os, sqlite3, secrets, string, re, time, json
from functools import wraps
from datetime import datetime, timedelta
from flask import (Flask, request, session, redirect, url_for, render_template_string,
                   flash, g, send_from_directory, abort, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageDraw, ImageFont

# ---------- FACE MATCH (optional, graceful fallback) ----------
try:
    import numpy as np
    import cv2
    _CV_OK = True
except Exception:
    _CV_OK = False

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "accommodation_link.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp", "pdf"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-on-render-to-a-long-random-key-12345")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


# =============================================================
# DB LAYER
# =============================================================
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, args=(), one=False):
    cur = db().execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def ex(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur.lastrowid

def _schema_version(d):
    try:
        row = d.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
        return int(row["value"]) if row and row["value"] else 1
    except Exception:
        return 1


def init_db():
    with app.app_context():
        d = db()
        d.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,
          admin_id INTEGER, action TEXT, target_table TEXT, target_id INTEGER,
          meta TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,
          listing_id INTEGER, reason TEXT NOT NULL, note TEXT, reporter_ip TEXT,
          status TEXT DEFAULT 'open', actioned_by INTEGER,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT UNIQUE NOT NULL, listing_id INTEGER, agent_id INTEGER,
          tenant_name TEXT, tenant_phone TEXT, tenant_email TEXT,
          status TEXT DEFAULT 'open',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          last_activity TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_id INTEGER,
          sender TEXT NOT NULL CHECK(sender IN ('tenant','agent')),
          body TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP, read_at TEXT);
        CREATE TABLE IF NOT EXISTS pricing_tiers(id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, type TEXT NOT NULL CHECK(type IN ('per_listing','subscription')),
          duration_days INTEGER NOT NULL, listing_limit INTEGER,
          price_usd REAL NOT NULL, price_zwg REAL, active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER, tier_id INTEGER, payment_id INTEGER,
          starts_at TEXT DEFAULT CURRENT_TIMESTAMP, ends_at TEXT NOT NULL);
        """)
        defaults = {
            "ecocash_number": "0777037403",
            "ecocash_receiver_name": "Tinotenda Tarsh Makuchete",
            "whatsapp_support_number": "263771234567",
            "whatsapp_support_display_name": "Accommodation Link Support",
            "site_email": "info@accommodationlink.co.zw",
            "default_currency": "USD",
            "watermark_text": "Accommodation Link",
            "site_credit": "Powered by Tinotenda Tarsh Makuchete",
            "developer_name": "Tinotenda Tarsh Makuchete",
            "developer_whatsapp": "263771234567",
            "developer_email": "info@accommodationlink.co.zw",
            "auto_face_match_enabled": "1",
            "face_match_threshold": "0.75",
        }
        for k, v in defaults.items():
            if not d.execute("SELECT 1 FROM settings WHERE key=?", (k,)).fetchone():
                d.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k, v))
        if not d.execute("SELECT 1 FROM pricing_tiers").fetchone():
            d.execute("INSERT INTO pricing_tiers(name,type,duration_days,price_usd) VALUES('Per-listing','per_listing',30,5.0)")
            d.execute("INSERT INTO pricing_tiers(name,type,duration_days,listing_limit,price_usd) VALUES('Monthly Unlimited','subscription',30,50,20.0)")
        d.commit()
        if _schema_version(d) < 2:
            try:
                migrate_v2(d)
                d.execute("INSERT INTO settings(key,value) VALUES('schema_version','2') "
                          "ON CONFLICT(key) DO UPDATE SET value='2'")
                d.commit()
                print("[init_db] migrate_v2 complete — schema_version = 2")
            except Exception as e:
                try:
                    d.rollback()
                    d.execute("INSERT INTO settings(key,value) VALUES('schema_version','1') "
                              "ON CONFLICT(key) DO UPDATE SET value='1'")
                    d.commit()
                except Exception:
                    pass
                print(f"[init_db] migrate_v2 FAILED — schema_version stays 1: {e}")
                raise


def migrate_v2(d):
    print("[migrate_v2] rebuilding core tables…")
    d.execute("PRAGMA foreign_keys = OFF")
    for t in ("users","verifications","listings","listing_photos","payments"):
        d.execute(f"DROP TABLE IF EXISTS {t}")
    d.execute("""
    CREATE TABLE users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL CHECK(role IN ('admin','landlord','agent','lodge','transport')),
      full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL,
      national_id_number TEXT, password_hash TEXT NOT NULL,
      verification_status TEXT DEFAULT 'unverified',
      verified_badge INTEGER DEFAULT 0, face_verified INTEGER DEFAULT 0,
      blacklisted INTEGER DEFAULT 0, bio TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    d.execute("""
    CREATE TABLE verifications(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      role_snapshot TEXT, id_doc_url TEXT, selfie_url TEXT,
      face_match_score REAL, face_match_status TEXT,
      title_deed_url TEXT, agent_license_url TEXT, lodge_license_url TEXT,
      vehicle_reg_url TEXT, vehicle_licence_url TEXT,
      vehicle_make TEXT, vehicle_model TEXT, vehicle_plate TEXT, vehicle_capacity TEXT,
      status TEXT DEFAULT 'pending', admin_note TEXT, reviewed_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    d.execute("""
    CREATE TABLE listings(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      category TEXT NOT NULL CHECK(category IN (
        'house_rent','house_sale','shop_rent','shop_sale','stand_sale','lodge')),
      title TEXT NOT NULL, description TEXT,
      price REAL NOT NULL, currency TEXT DEFAULT 'USD',
      rooms INTEGER, amenities TEXT,
      city TEXT NOT NULL, suburb TEXT, lat REAL, lng REAL,
      contact_name TEXT, contact_phone TEXT,
      status TEXT DEFAULT 'draft', views INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP, expires_at TEXT,
      is_featured INTEGER DEFAULT 0,
      lodging_kind TEXT, star_rating INTEGER,
      checkin_time TEXT, checkout_time TEXT,
      rate_per_night REAL, rate_per_week REAL, rate_per_month REAL,
      max_guests INTEGER, bedrooms INTEGER, bathrooms INTEGER, beds INTEGER,
      has_wifi INTEGER DEFAULT 0, has_pool INTEGER DEFAULT 0,
      has_restaurant INTEGER DEFAULT 0, has_parking INTEGER DEFAULT 0,
      has_ac INTEGER DEFAULT 0, has_dstv INTEGER DEFAULT 0,
      has_breakfast INTEGER DEFAULT 0, has_gym INTEGER DEFAULT 0,
      has_laundry INTEGER DEFAULT 0, policies TEXT, nearby_attractions TEXT,
      area_sqm REAL, title_deed_status TEXT, zoning TEXT, road_access TEXT,
      services_available TEXT, price_per_sqm REAL);
    """)
    d.execute("""
    CREATE TABLE listing_photos(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      listing_id INTEGER REFERENCES listings(id) ON DELETE CASCADE,
      url TEXT NOT NULL, watermarked INTEGER DEFAULT 0, sort_order INTEGER DEFAULT 0);
    """)
    d.execute("""
    CREATE TABLE payments(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      listing_id INTEGER REFERENCES listings(id),
      tier_id INTEGER REFERENCES pricing_tiers(id),
      duration_id INTEGER,
      type TEXT NOT NULL CHECK(type IN ('listing_fee','subscription')),
      amount REAL NOT NULL, currency TEXT DEFAULT 'USD',
      ref_code TEXT UNIQUE NOT NULL, proof_url TEXT, txn_id TEXT,
      status TEXT DEFAULT 'awaiting_verification', admin_note TEXT,
      verified_by INTEGER, verified_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    d.execute("""
    CREATE TABLE listing_durations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      label TEXT NOT NULL, days INTEGER NOT NULL, price_usd REAL NOT NULL,
      active INTEGER DEFAULT 1);
    """)
    if not d.execute("SELECT 1 FROM listing_durations").fetchone():
        for label, days, price in [("7 days",7,3.0),("30 days",30,8.0),("90 days",90,15.0)]:
            d.execute("INSERT INTO listing_durations(label,days,price_usd) VALUES(?,?,?)", (label,days,price))
    d.execute("""
    CREATE TABLE transport_providers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      business_name TEXT NOT NULL,
      provider_type TEXT NOT NULL CHECK(provider_type IN ('taxi','shuttle','truck','mover','bus','mixed')),
      city TEXT NOT NULL, service_areas TEXT, description TEXT,
      phone TEXT, whatsapp TEXT, email TEXT, logo_url TEXT, vehicle_summary TEXT,
      verified INTEGER DEFAULT 0, blacklisted INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    d.execute("""
    CREATE TABLE transport_requests(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      requester_user_id INTEGER REFERENCES users(id),
      requester_name TEXT, requester_phone TEXT,
      request_type TEXT NOT NULL CHECK(request_type IN ('moving','taxi','shuttle','truck','bus','other')),
      from_location TEXT, to_location TEXT,
      when_date TEXT, when_time TEXT,
      description TEXT, budget TEXT, city TEXT,
      linked_listing_id INTEGER REFERENCES listings(id),
      status TEXT DEFAULT 'open' CHECK(status IN ('open','matched','closed')),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    d.execute("""
    CREATE TABLE transport_quotes(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER REFERENCES transport_requests(id) ON DELETE CASCADE,
      provider_id INTEGER REFERENCES transport_providers(id) ON DELETE CASCADE,
      price REAL, message TEXT,
      status TEXT DEFAULT 'sent' CHECK(status IN ('sent','accepted','declined')),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    if not d.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        d.execute("INSERT INTO users(role,full_name,email,phone,password_hash,verification_status,verified_badge,face_verified) "
                  "VALUES('admin','Administrator','admin@accommodationlink.co.zw','0770000000',?,'verified',1,1)",
                  (generate_password_hash("Admin@123"),))
    d.execute("PRAGMA foreign_keys = ON")
    print("[migrate_v2] done.")


# =============================================================
# HELPERS
# =============================================================
def get_setting(key, default=""):
    r = q("SELECT value FROM settings WHERE key=?", (key,), one=True)
    return r["value"] if r else default

def set_setting(key, value):
    ex("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

def current_user():
    uid = session.get("uid")
    return q("SELECT * FROM users WHERE id=?", (uid,), one=True) if uid else None

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            u = current_user()
            if not u: return redirect(url_for("login"))
            if role and u["role"] != role: abort(403)
            return fn(*a, **k)
        return wrapper
    return deco

def admin_required(fn): return login_required("admin")(fn)

def gen_ref():
    while True:
        code = "AL-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        if not q("SELECT 1 FROM payments WHERE ref_code=?", (code,), one=True): return code

def gen_token():
    while True:
        t = "CONV-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        if not q("SELECT 1 FROM conversations WHERE token=?", (t,), one=True): return t

def allowed_file(fn): return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def watermark_image(filepath, text):
    try:
        if filepath.lower().endswith(".pdf"): return
        img = Image.open(filepath).convert("RGBA")
        txt = Image.new("RGBA", img.size, (0,0,0,0))
        draw = ImageDraw.Draw(txt)
        try: font = ImageFont.truetype("arial.ttf", max(20, img.size[0] // 30))
        except Exception: font = ImageFont.load_default()
        try:
            bbox = draw.textbbox((0,0), text, font=font)
            w, h = bbox[2]-bbox[0], bbox[3]-bbox[1]
        except Exception: w, h = len(text)*12, 20
        pos = (img.size[0] - w - 20, img.size[1] - h - 20)
        for dx in (-1,0,1):
            for dy in (-1,0,1): draw.text((pos[0]+dx, pos[1]+dy), text, fill=(0,0,0,120), font=font)
        draw.text(pos, text, fill=(255,255,255,180), font=font)
        Image.alpha_composite(img, txt).convert("RGB").save(filepath)
    except Exception as e: print("Watermark failed:", e)

def save_upload(file, prefix):
    if not file or not file.filename or not allowed_file(file.filename): return None
    ext = file.filename.rsplit(".", 1)[1].lower()
    name = f"{prefix}_{secrets.token_hex(8)}.{ext}"
    path = os.path.join(UPLOAD_DIR, name)
    file.save(path)
    if ext in {"png","jpg","jpeg","webp"}: watermark_image(path, get_setting("watermark_text", "Accommodation Link"))
    return name

@app.route("/uploads/<path:name>")
def uploaded(name): return send_from_directory(UPLOAD_DIR, name)

def active_subscription(uid):
    return q("SELECT * FROM subscriptions WHERE user_id=? AND ends_at > datetime('now') ORDER BY ends_at DESC LIMIT 1", (uid,), one=True)

_rl = {}
def rate_limit(key, max_hits, window_sec):
    now = time.time()
    hits = [t for t in _rl.get(key, []) if now - t < window_sec]
    if len(hits) >= max_hits: return False
    hits.append(now); _rl[key] = hits
    return True

def sanitize_text(s, max_len=2000):
    if not s: return ""
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"https?://\S+", "[link removed]", s)
    return s.strip()[:max_len]

def wa_number(phone):
    if not phone: return ""
    p = re.sub(r"\D", "", phone)
    if p.startswith("0"): p = "263" + p[1:]
    return p

def tel_number(phone):
    if not phone: return ""
    p = re.sub(r"\D", "", phone)
    if p.startswith("0"): p = "+263" + p[1:]
    elif not p.startswith("+"): p = "+" + p
    return p

def expire_old_listings():
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ex("UPDATE listings SET status='expired' WHERE expires_at IS NOT NULL AND expires_at != '' AND expires_at < ? AND status NOT IN ('expired','draft')", (now,))
    except Exception as e:
        print("Expire error:", e)

# ---------- price & WhatsApp helpers ----------
PERIOD_MAP = {
    "house_rent": "/ month",
    "house_sale": "total",
    "shop_rent": "/ month",
    "shop_sale": "total",
    "stand_sale": "total",
    "lodge": "/ night (from)",
}

def price_label(listing, short=False):
    if not listing: return ""
    cur = listing["currency"] or "USD"
    cat = listing["category"]
    try: amt = float(listing["price"])
    except Exception: amt = 0.0
    if short:
        prefix = "$" if cur == "USD" else f"{cur} "
        return f"{prefix}{amt:,.0f}"
    suffix = PERIOD_MAP.get(cat, "")
    if cat == "lodge" and listing["rate_per_night"]:
        try:
            return f"{cur} {float(listing['rate_per_night']):,.2f} / night (from)"
        except Exception: pass
    return f"{cur} {amt:,.2f} {suffix}".strip()

def wa_listing_link(listing):
    if not listing: return "#"
    phone = wa_number(listing["contact_phone"] or "")
    title = listing["title"] or ""
    suburb = listing["suburb"] or ""
    city = listing["city"] or ""
    price = price_label(listing)
    msg = (f"Hi, I saw your listing '{title}' in {suburb}, {city} on Accommodation Link. "
           f"Price: {price}. Is it still available? Can I view?")
    import urllib.parse
    return f"https://wa.me/{phone}?text={urllib.parse.quote(msg)}"

# ---------- KYC helpers ----------
def validate_zw_id(s):
    if not s: return False
    s = s.strip().upper().replace(" ", "")
    return bool(re.match(r"^\d{2}-?\d{6,7}-?[A-Z]-?\d{2}$", s))

def face_verify(selfie_path, id_doc_path, threshold=0.75):
    if not _CV_OK:
        return (None, "manual_only")
    try:
        def faces_in(path):
            img = cv2.imread(path)
            if img is None: return 0, None
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            casc = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
            f = casc.detectMultiScale(gray, 1.1, 4)
            return len(f), f
        n1, f1 = faces_in(selfie_path)
        n2, f2 = faces_in(id_doc_path)
        if n1 != 1 or n2 < 1:
            return (0.0, "manual_needed")
        x1,y1,w1,h1 = f1[0]
        ar_selfie = w1 / h1
        ar_id = (f2[0][2] / f2[0][3]) if len(f2) else 0
        diff = abs(ar_selfie - ar_id)
        score = max(0.0, min(1.0, 1.0 - diff*2))
        status = "auto_pass" if score >= threshold else "manual_needed"
        return (round(score, 3), status)
    except Exception as e:
        print("face_verify error:", e)
        return (None, "manual_only")


# =============================================================
# BASE TEMPLATE (with back button)
# =============================================================
BASE_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Accommodation Link</title>
<style>
:root{--navy:#0a1f44;--navy2:#122a5c;--gold:#d4af37;--gold2:#e8c860;--bg:#f7f6f2;--line:#e3dfd2;--muted:#6b7280;}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:#111;display:flex;flex-direction:column;min-height:100vh}
a{color:var(--navy);text-decoration:none}a:hover{color:var(--gold)}
header{background:linear-gradient(135deg,var(--navy) 0%,var(--navy2) 100%);color:#fff;padding:14px 22px;display:flex;align-items:center;gap:18px;flex-wrap:wrap;border-bottom:3px solid var(--gold)}
header .logo{font-family:Georgia,serif;font-weight:700;font-size:22px;color:var(--gold)}
header nav{margin-left:auto;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
header nav a{color:#eae6da;padding:7px 12px;border-radius:6px;font-size:14px}
header nav a:hover{background:rgba(212,175,55,.18);color:var(--gold)}
main{max-width:1150px;margin:20px auto;padding:0 14px;flex:1;width:100%}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.listing{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#fff;transition:.15s}
.listing:hover{box-shadow:0 6px 20px rgba(10,31,68,.12);transform:translateY(-2px)}
.listing img{width:100%;height:170px;object-fit:cover;background:#ddd}
.listing .body{padding:10px}
.price{color:var(--navy);font-weight:800;font-size:17px}
.btn{display:inline-block;background:var(--gold);color:var(--navy);padding:9px 14px;border-radius:8px;border:0;cursor:pointer;font-weight:700}
.btn:hover{background:var(--gold2)}
.btn.sec{background:#eee7d3}.btn.danger{background:#c0392b;color:#fff}
.btn.wa{background:#25D366;color:#fff}.btn.call{background:var(--navy);color:#fff}
.btn.sm{padding:6px 10px;font-size:13px}
input,select,textarea{padding:9px;border:1px solid var(--line);border-radius:8px;width:100%;font:inherit}
label{display:block;margin:8px 0 4px;font-weight:600;font-size:13px;color:var(--navy)}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:160px}
.flash{background:#f4ecd0;border:1px solid var(--gold);color:var(--navy);padding:10px;border-radius:8px;margin-bottom:12px}
.flash.err{background:#fde8e8;border-color:#f5b5b5;color:#7a1f1f}
.badge{display:inline-block;background:var(--navy);color:var(--gold);font-size:11px;padding:3px 9px;border-radius:99px;font-weight:700}
.badge.pending{background:#fff4d6;color:#8a6200}.badge.rej{background:#fde8e8;color:#c0392b}
.badge.ok{background:#d1f0d9;color:#166534}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:#faf7ee;color:var(--navy);font-weight:700}
.muted{color:var(--muted);font-size:13px}
h1,h2{margin:0 0 12px;color:var(--navy)}
.hero{background:linear-gradient(135deg,var(--navy) 0%,var(--navy2) 55%,#3a2a00 100%);color:#fff;padding:36px 22px;border-radius:12px;margin-bottom:16px;border-bottom:3px solid var(--gold)}
.hero h1{font-size:26px;margin-bottom:6px;color:#fff}
.hero h1 em{color:var(--gold);font-style:normal}
.searchbar{background:#fff;padding:14px;border-radius:10px;margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}
.searchbar>*{flex:1;min-width:140px}
.chat-box{background:#fafbfc;border:1px solid var(--line);border-radius:10px;padding:14px;max-height:60vh;overflow:auto}
.msg{padding:8px 12px;border-radius:8px;margin-bottom:8px;max-width:80%}
.msg.tenant{background:#e7f0ff;margin-right:auto}.msg.agent{background:#f4ecd0;margin-left:auto}
.msg .t{font-size:11px;color:var(--muted);display:block;margin-top:4px}
.tabs{display:flex;gap:6px;border-bottom:2px solid var(--gold);margin-bottom:16px;flex-wrap:wrap}
.tabs a{padding:8px 14px;background:#eee7d3;color:var(--navy);border-radius:8px 8px 0 0;font-weight:700;font-size:13px}
.tabs a.active{background:var(--gold);color:var(--navy)}
footer{text-align:center;padding:20px 14px;margin-top:28px;background:var(--navy);color:#d6d1c2;font-size:12px;border-top:3px solid var(--gold)}
footer em{color:var(--gold)}
</style></head><body>
<header>
  <a href="/" class="logo">Accommodation&nbsp;Link</a>
  <nav>
    <a href="/">Browse</a>
    <a href="/transport">Transport</a>
    <a href="/saved">Saved</a>
    {% if current_user %}
      {% if current_user.role == 'admin' %}<a href="/admin">Admin</a>
      {% else %}<a href="/dashboard">Dashboard</a>{% endif %}
      <a href="/logout">Logout ({{ current_user.full_name }})</a>
    {% else %}
      <a href="/login">Login</a><a href="/register">Register</a>
    {% endif %}
    <a href="https://wa.me/{{ get_setting('whatsapp_support_number') }}" target="_blank" class="btn wa sm">💬 Support</a>
  </nav>
</header>
<main>
<div style="margin-bottom:10px">
  <button onclick="if(history.length>1 && document.referrer.startsWith(location.origin)){history.back()}else{location.href='/'}"
          class="btn sec sm">← Back</button>
</div>
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, m in msgs %}<div class="flash {{ 'err' if cat=='error' }}">{{ m }}</div>{% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</main>
<footer><em>{{ get_setting('site_credit') }}</em> &nbsp;·&nbsp; <a href="/about-developer" style="color:#d6d1c2">About the developer</a><br>
<small>DISCLAIMER: Advertising only. We do NOT collect rent. VIEW Before You Pay. · <a href="/terms" style="color:#d6d1c2">Terms</a> · <a href="/privacy" style="color:#d6d1c2">Privacy</a></small>
</footer>
</body></html>
"""


def render_page(html, **kwargs):
    return render_template_string(BASE_HTML.replace("{% block content %}{% endblock %}", html), **kwargs)


@app.context_processor
def inject():
    u = current_user()
    uc = 0
    if u and u["role"] in ("agent","landlord","lodge"):
        uc = q("SELECT COUNT(*) c FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.agent_id=? AND m.sender='tenant' AND m.read_at IS NULL", (u["id"],), one=True)["c"]
    return dict(current_user=u, get_setting=get_setting, unread_count=uc,
                wa_number=wa_number, tel_number=tel_number,
                price_label=price_label, wa_listing_link=wa_listing_link,
                PERIOD_MAP=PERIOD_MAP)


def tab_bar(role, active):
    tabs = {
        "admin": [("/admin","Dashboard"),("/admin/verifications","Verifications"),
                  ("/admin/payments","Payments"),("/admin/listings","Listings"),
                  ("/admin/users","Users"),("/admin/transport","Transport"),
                  ("/admin/durations","Durations"),("/admin/settings","Settings")],
        "landlord": [("/dashboard/listings","My Listings"),
                     ("/listing/new","New Listing"),("/dashboard/messages","Messages"),
                     ("/subscription","Subscription"),("/verify","Verification")],
        "agent": [("/dashboard/listings","My Listings"),
                  ("/listing/new","New Listing"),("/dashboard/messages","Messages"),
                  ("/subscription","Subscription"),("/verify","Verification")],
        "lodge": [("/dashboard/listings","My Lodges"),
                  ("/listing/new","New Lodge"),("/dashboard/messages","Messages"),
                  ("/verify","Verification")],
        "transport": [("/transport/my","My Vehicle"),
                      ("/transport/requests","Requests"),("/dashboard/messages","Messages"),
                      ("/verify","Verification")],
    }.get(role, [])
    out = '<div class="tabs">'
    for url, label in tabs:
        cls = "active" if url == active else ""
        out += f'<a class="{cls}" href="{url}">{label}</a>'
    out += "</div>"
    return out


# =============================================================
# PUBLIC
# =============================================================
@app.route("/")
def home():
    expire_old_listings()
    a = request.args
    sql = ("SELECT l.*, u.verified_badge FROM listings l JOIN users u ON u.id=l.user_id "
           "WHERE l.status='active' AND u.blacklisted=0")
    args = []
    if a.get("city"): sql += " AND lower(l.city)=?"; args.append(a["city"].lower())
    if a.get("suburb"): sql += " AND lower(l.suburb) LIKE ?"; args.append(f"%{a['suburb'].lower()}%")
    if a.get("category"): sql += " AND l.category=?"; args.append(a["category"])
    if a.get("min_price", type=float) is not None: sql += " AND l.price>=?"; args.append(a["min_price"])
    if a.get("max_price", type=float) is not None: sql += " AND l.price<=?"; args.append(a["max_price"])
    if a.get("rooms", type=int) is not None: sql += " AND l.rooms>=?"; args.append(a["rooms"])
    sql += " ORDER BY l.is_featured DESC, (l.views + l.clicks*2) DESC, l.created_at DESC"
    listings = q(sql, args)
    cities = [r["city"] for r in q("SELECT DISTINCT city FROM listings WHERE status='active' ORDER BY city")]
    return render_page("""
    <div class="hero">
      <h1>Accommodation <em>Link</em> — Find your next home in Zimbabwe</h1>
      <form class="searchbar" method="get">
        <input name="city" placeholder="City" value="{{ request.args.city or '' }}" list="cl">
        <datalist id="cl">{% for c in cities %}<option value="{{ c }}">{% endfor %}</datalist>
        <input name="suburb" placeholder="Suburb" value="{{ request.args.suburb or '' }}">
        <select name="category">
          <option value="">Any category</option>
          <option value="house_rent" {{ 'selected' if request.args.category=='house_rent' }}>House — Rent</option>
          <option value="house_sale" {{ 'selected' if request.args.category=='house_sale' }}>House — Sale</option>
          <option value="shop_rent" {{ 'selected' if request.args.category=='shop_rent' }}>Shop — Rent</option>
          <option value="shop_sale" {{ 'selected' if request.args.category=='shop_sale' }}>Shop — Sale</option>
          <option value="stand_sale" {{ 'selected' if request.args.category=='stand_sale' }}>Stand — Sale</option>
          <option value="lodge" {{ 'selected' if request.args.category=='lodge' }}>Lodge</option>
        </select>
        <input name="min_price" type="number" placeholder="Min price" value="{{ request.args.min_price or '' }}">
        <input name="max_price" type="number" placeholder="Max price" value="{{ request.args.max_price or '' }}">
        <input name="rooms" type="number" placeholder="Min rooms" value="{{ request.args.rooms or '' }}">
        <button class="btn">Search</button>
      </form>
    </div>
    <h2>🔥 Trending / Latest</h2>
    <div class="grid">
      {% for l in listings %}
      <div class="listing">
        <a href="/listing/{{ l.id }}"><img src="/photo_of/{{ l.id }}"></a>
        <div class="body">
          <div class="price">{{ price_label(l) }}</div>
          <div style="font-weight:700;margin:4px 0">{{ l.title }}</div>
          <div class="muted">📍 {{ l.suburb }}{% if l.suburb %}, {% endif %}{{ l.city }}</div>
          {% if l.verified_badge %}<span class="badge">✅ Verified</span>{% endif %}
          {% if l.is_featured %}<span class="badge ok">★ Featured</span>{% endif %}
          <div style="margin-top:8px">
            <a class="btn wa sm" target="_blank" href="{{ wa_listing_link(l) }}">💬 WhatsApp</a>
          </div>
        </div>
      </div>
      {% else %}<p class="muted">No listings yet.</p>{% endfor %}
    </div>
    """, listings=listings, cities=cities)


@app.route("/photo_of/<int:lid>")
def photo_of(lid):
    r = q("SELECT url FROM listing_photos WHERE listing_id=? ORDER BY sort_order LIMIT 1", (lid,), one=True)
    if not r: abort(404)
    return redirect(f"/uploads/{r['url']}")


@app.route("/listing/<int:lid>")
def listing_detail(lid):
    l = q("SELECT l.*, u.verified_badge, u.full_name AS agent_name, u.role AS agent_role, u.id AS aid "
          "FROM listings l JOIN users u ON u.id=l.user_id WHERE l.id=?", (lid,), one=True)
    u = current_user()
    if not l: abort(404)
    if l["status"] not in ("active","expired") and not (u and u["role"] == "admin"): abort(404)
    photos = q("SELECT * FROM listing_photos WHERE listing_id=? ORDER BY sort_order", (lid,))
    ex("UPDATE listings SET views=views+1 WHERE id=?", (lid,))
    transports = []
    if l["category"] in ("house_rent","house_sale","shop_rent","shop_sale","stand_sale"):
        transports = q("SELECT * FROM transport_providers WHERE city=? AND blacklisted=0 "
                       "AND provider_type IN ('truck','mover','taxi','mixed') LIMIT 4",
                       (l["city"],))
    return render_page("""
    <div class="card">
      <h1>{{ l.title }}</h1>
      <div class="muted">📍 {{ l.suburb }}{% if l.suburb %}, {% endif %}{{ l.city }} · {{ l.category|replace('_',' ')|title }} · {{ l.rooms or '-' }} rooms · by <a href="/agent/{{ l.aid }}">{{ l.agent_name }}</a></div>
      <div class="price" style="font-size:24px;margin:8px 0">{{ price_label(l) }}</div>
      {% if l.category=='stand_sale' %}
        <p class="muted">Area: {{ l.area_sqm or '—' }} m² · Zoning: {{ l.zoning or '—' }} · Title: {{ l.title_deed_status or '—' }} · Access: {{ l.road_access or '—' }}</p>
        {% if l.price_per_sqm %}<p class="muted">≈ USD {{ '%.2f'|format(l.price_per_sqm) }} / m²</p>{% endif %}
      {% endif %}
      {% if l.category=='lodge' %}
        <p class="muted">Type: {{ l.lodging_kind or '—' }} · ★ {{ l.star_rating or '—' }} · Guests: {{ l.max_guests or '—' }} · Beds: {{ l.beds or '—' }} · Bedrooms: {{ l.bedrooms or '—' }} · Bathrooms: {{ l.bathrooms or '—' }}</p>
        <p class="muted">Check-in {{ l.checkin_time or '—' }} · Check-out {{ l.checkout_time or '—' }}</p>
        {% if l.rate_per_week or l.rate_per_month %}<p class="muted">Rates: {% if l.rate_per_night %}USD {{ l.rate_per_night }}/night · {% endif %}{% if l.rate_per_week %}USD {{ l.rate_per_week }}/week · {% endif %}{% if l.rate_per_month %}USD {{ l.rate_per_month }}/month{% endif %}</p>{% endif %}
        <p class="muted">Amenities:
          {% for k in ['wifi','pool','restaurant','parking','ac','dstv','breakfast','gym','laundry'] %}
            {% if l['has_' + k] %}✅ {{ k }} {% endif %}
          {% endfor %}
        </p>
        {% if l.policies %}<p><b>Policies:</b> {{ l.policies }}</p>{% endif %}
        {% if l.nearby_attractions %}<p><b>Nearby:</b> {{ l.nearby_attractions }}</p>{% endif %}
      {% endif %}
      {% if l.verified_badge %}<span class="badge">✅ Verified</span>{% endif %}
      <div class="grid" style="margin-top:14px">{% for p in photos %}<img src="/uploads/{{ p.url }}" style="width:100%;border-radius:8px;max-height:340px;object-fit:cover">{% endfor %}</div>
      <p style="margin-top:14px;white-space:pre-wrap">{{ l.description or '' }}</p>
      {% if l.amenities %}<p><b>Amenities:</b> {{ l.amenities }}</p>{% endif %}
      <div class="row" style="margin-top:14px">
        <a class="btn wa" target="_blank" href="{{ wa_listing_link(l) }}">💬 WhatsApp</a>
        <a class="btn call" href="tel:{{ tel_number(l.contact_phone) }}">📞 Call</a>
        <button class="btn sec" onclick="saveFav({{ l.id }})">❤ Save</button>
        {% if l.category in ['house_rent','house_sale','shop_rent','shop_sale','stand_sale'] %}
          <a class="btn sec" href="/transport/request?city={{ l.city }}&linked={{ l.id }}">🚚 Need a truck?</a>
        {% endif %}
      </div>
      {% if l.category == 'lodge' %}
        <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:14px">
          <h3>Booking enquiry</h3>
          <form method="post" action="/listing/{{ l.id }}/enquiry">
            <div class="row">
              <div><label>Check-in date</label><input type="date" name="check_in"></div>
              <div><label>Check-out date</label><input type="date" name="check_out"></div>
              <div><label>Guests</label><input type="number" name="guests" min="1"></div>
            </div>
            <label>Message</label><textarea name="body" rows="3" required></textarea>
            <div style="margin-top:8px"><button class="btn">Send enquiry</button></div>
          </form>
        </div>
      {% endif %}
      {% if transports %}
        <div style="margin-top:14px;border-top:1px solid var(--line);padding-top:14px">
          <h3>🚚 Transport near {{ l.city }}</h3>
          {% for t in transports %}
            <div class="card" style="padding:10px;margin-bottom:8px">
              <b>{{ t.business_name }}</b> <span class="muted">· {{ t.provider_type }}</span>
              {% if t.vehicle_summary %}<div class="muted">{{ t.vehicle_summary }}</div>{% endif %}
              <a class="btn wa sm" target="_blank" href="https://wa.me/{{ wa_number(t.whatsapp or t.phone) }}">💬 WhatsApp</a>
            </div>
          {% endfor %}
          <a href="/transport?city={{ l.city }}" class="muted">See all transport providers →</a>
        </div>
      {% endif %}
    </div>
    <script>
      function saveFav(id){ let s = JSON.parse(localStorage.getItem('al_saved')||'[]'); if(!s.includes(id)) s.push(id); localStorage.setItem('al_saved', JSON.stringify(s)); alert('Saved!'); }
    </script>
    """, l=l, photos=photos, transports=transports)


@app.route("/listing/<int:lid>/enquiry", methods=["POST"])
def listing_enquiry(lid):
    l = q("SELECT * FROM listings WHERE id=? AND status='active'", (lid,), one=True)
    if not l: abort(404)
    if not rate_limit(f"enq:{request.remote_addr}", 5, 3600):
        flash("Too many enquiries — try later.", "error"); return redirect(f"/listing/{lid}")
    token = gen_token()
    cid = ex("INSERT INTO conversations(token,listing_id,agent_id,tenant_name,tenant_phone,tenant_email) VALUES(?,?,?,?,?,?)",
             (token, lid, l["user_id"], "", "", ""))
    body = sanitize_text(request.form.get("body",""))
    extras = []
    if request.form.get("check_in"): extras.append(f"Check-in: {request.form['check_in']}")
    if request.form.get("check_out"): extras.append(f"Check-out: {request.form['check_out']}")
    if request.form.get("guests"): extras.append(f"Guests: {request.form['guests']}")
    if extras: body = " | ".join(extras) + "\n\n" + body
    ex("INSERT INTO messages(conversation_id,sender,body) VALUES(?,?,?)", (cid, "tenant", body))
    flash("Enquiry sent!"); return redirect(f"/chat/{token}")


@app.route("/chat/<token>", methods=["GET","POST"])
def chat_guest(token):
    c = q("SELECT * FROM conversations WHERE token=?", (token,), one=True)
    if not c: abort(404)
    l = q("SELECT * FROM listings WHERE id=?", (c["listing_id"],), one=True)
    if not l: abort(404)
    agent = q("SELECT * FROM users WHERE id=?", (c["agent_id"],), one=True)
    if not agent: abort(404)
    if request.method == "POST":
        if not rate_limit(f"chat:{request.remote_addr}", 30, 3600): flash("Slow down.", "error"); return redirect(f"/chat/{token}")
        body = sanitize_text(request.form.get("body",""))
        if body:
            ex("INSERT INTO messages(conversation_id,sender,body) VALUES(?,?,?)", (c["id"], "tenant", body))
            ex("UPDATE conversations SET last_activity=datetime('now') WHERE id=?", (c["id"],))
        return redirect(f"/chat/{token}")
    msgs = q("SELECT * FROM messages WHERE conversation_id=? ORDER BY id", (c["id"],))
    ex("UPDATE messages SET read_at=datetime('now') WHERE conversation_id=? AND sender='agent' AND read_at IS NULL", (c["id"],))
    return render_page("""
    <div class="card">
      <h1>Conversation with {{ agent.full_name }}</h1>
      <div class="muted">About: <a href="/listing/{{ l.id }}">{{ l.title }}</a></div>
      <div class="chat-box" style="margin-top:10px">
        {% for m in msgs %}<div class="msg {{ m.sender }}">{{ m.body }}<span class="t">{{ m.sender|capitalize }} · {{ m.created_at }}</span></div>{% endfor %}
      </div>
      <form method="post" style="margin-top:10px"><textarea name="body" rows="3" required></textarea><div style="margin-top:8px"><button class="btn">Reply</button></div></form>
    </div>
    """, c=c, l=l, agent=agent, msgs=msgs)


@app.route("/agent/<int:aid>")
def agent_profile(aid):
    u = q("SELECT * FROM users WHERE id=? AND role!='admin' AND blacklisted=0", (aid,), one=True)
    if not u: abort(404)
    listings = q("SELECT * FROM listings WHERE user_id=? AND status='active' ORDER BY id DESC", (aid,))
    return render_page("""
    <div class="card">
      <h1>{{ u.full_name }} {% if u.verified_badge %}<span class="badge">✅ Verified</span>{% endif %}</h1>
      <div class="muted">{{ u.role|capitalize }}{% if u.bio %} · {{ u.bio }}{% endif %}</div>
      <div class="row" style="margin-top:10px">
        <a class="btn wa" target="_blank" href="https://wa.me/{{ wa_number(u.phone) }}">💬 WhatsApp</a>
        <a class="btn call" href="tel:{{ tel_number(u.phone) }}">📞 Call</a>
      </div>
    </div>
    <h2>Active listings ({{ listings|length }})</h2>
    <div class="grid">
      {% for l in listings %}
        <div class="listing"><a href="/listing/{{ l.id }}"><img src="/photo_of/{{ l.id }}"></a>
          <div class="body"><div class="price">{{ price_label(l) }}</div>
            <div style="font-weight:700">{{ l.title }}</div>
            <div class="muted">📍 {{ l.suburb }}, {{ l.city }}</div>
            <a class="btn wa sm" target="_blank" href="{{ wa_listing_link(l) }}">💬 WhatsApp</a>
          </div></div>
      {% else %}<p class="muted">No listings.</p>{% endfor %}
    </div>
    """, u=u, listings=listings)


@app.route("/about-developer")
def about_developer():
    return render_page("""
    <div class="card">
      <h1>About the developer</h1>
      <p><b>{{ get_setting('developer_name') }}</b></p>
      <div class="row" style="margin-top:10px">
        <a class="btn wa" target="_blank" href="https://wa.me/{{ get_setting('developer_whatsapp') }}">💬 WhatsApp</a>
        <a class="btn call" href="tel:{{ tel_number(get_setting('developer_whatsapp')) }}">📞 Call</a>
        <a class="btn sec" href="mailto:{{ get_setting('developer_email') }}">✉️ Email</a>
      </div>
    </div>
    """)


@app.route("/terms")
def terms():
    content = """
    <h2>Terms & Conditions</h2>
    <p><b>Advertising only.</b> Accommodation Link does not own properties, does not collect rent, and is not a party to any rental agreement.</p>
    <p style="color:red;font-weight:bold">VIEW BEFORE YOU PAY. Never send money before viewing.</p>
    <h3>Verification & selfie</h3>
    <p>Landlords, agents, lodges and transport providers upload a National ID and a selfie so we can confirm that the account matches the ID document. Facial images are used <b>only</b> for this verification. They are never shown to other users, never sold, and can be deleted on request within 7 days.</p>
    <p>Admin may also manually review every submission. Auto-match is advisory only — it never overrides human review.</p>
    <h3>Documents</h3>
    <p>Title deeds, agent licences, lodge registrations and vehicle papers are private — visible only to Admin/Verification Team.</p>
    <p><a href="/">Back to Home</a></p>
    """
    return render_page(content)

@app.route("/privacy")
def privacy():
    return terms()


@app.route("/saved")
def saved():
    return render_page("""
    <h1>Saved listings</h1><p class="muted">Saved on this device.</p>
    <div id="out" class="grid"></div>
    <script>
    (async()=>{
      let ids = JSON.parse(localStorage.getItem('al_saved')||'[]');
      let out = document.getElementById('out');
      if(!ids.length){ out.innerHTML='<p class="muted">Nothing saved.</p>'; return; }
      for(const id of ids){
        try{ const r = await fetch('/api/listing/'+id); if(!r.ok) continue; const l = await r.json();
          out.innerHTML += `<div class="listing"><a href="/listing/${l.id}"><img src="/photo_of/${l.id}"></a><div class="body"><div class="price">${l.price_label}</div><div style="font-weight:700">${l.title}</div><div class="muted">📍 ${l.suburb||''}, ${l.city}</div><a class="btn wa sm" target="_blank" href="${l.wa_link}">💬 WhatsApp</a></div></div>`;
        }catch(e){}
      }
    })();
    </script>
    """)


@app.route("/api/listing/<int:lid>")
def api_listing(lid):
    l = q("SELECT * FROM listings WHERE id=? AND status IN ('active','expired')", (lid,), one=True)
    if not l: abort(404)
    d = dict(l)
    d["price_label"] = price_label(l)
    d["wa_link"] = wa_listing_link(l)
    return jsonify(d)


@app.route("/report/<int:lid>", methods=["POST"])
def report_listing(lid):
    if not q("SELECT 1 FROM listings WHERE id=?", (lid,), one=True): abort(404)
    ip = request.remote_addr or ""
    if q("SELECT 1 FROM reports WHERE listing_id=? AND reporter_ip=? AND status='open'", (lid, ip), one=True):
        flash("Already reported.", "error"); return redirect(f"/listing/{lid}")
    ex("INSERT INTO reports(listing_id,reason,note,reporter_ip) VALUES(?,?,?,?)",
       (lid, request.form.get("reason","Other"), request.form.get("note",""), ip))
    flash("Thanks — our team will review."); return redirect(f"/listing/{lid}")


# =============================================================
# AUTH + KYC
# =============================================================
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        role = request.form.get("role")
        if role not in ("landlord","agent","lodge","transport"):
            flash("Choose a role.", "error"); return redirect("/register")
        name = request.form.get("full_name","").strip()
        email = request.form.get("email","").strip().lower()
        phone = request.form.get("phone","").strip()
        nid = request.form.get("national_id_number","").strip().upper()
        pw = request.form.get("password","")
        if not (name and email and phone and pw):
            flash("All fields required.", "error"); return redirect("/register")
        if not validate_zw_id(nid):
            flash("National ID must be in ZW format (e.g. 63-1234567-A-00).", "error"); return redirect("/register")
        if q("SELECT 1 FROM users WHERE email=? OR phone=?", (email, phone), one=True):
            flash("Email or phone already registered.", "error"); return redirect("/register")
        uid = ex("INSERT INTO users(role,full_name,email,phone,national_id_number,password_hash,verification_status) "
                 "VALUES(?,?,?,?,?,?,'pending')",
                 (role, name, email, phone, nid, generate_password_hash(pw)))
        session["uid"] = uid
        flash("Registered. Now upload your verification documents.")
        return redirect("/verify")
    return render_page("""
    <div class="card" style="max-width:560px;margin:0 auto">
      <h1>Create account</h1>
      <form method="post">
        <label>I am a</label>
        <select name="role" required>
          <option value="landlord">Landlord</option>
          <option value="agent">Agent</option>
          <option value="lodge">Lodge / Guesthouse</option>
          <option value="transport">Transport provider</option>
        </select>
        <label>Full name</label><input name="full_name" required>
        <label>Email</label><input name="email" type="email" required>
        <label>Phone</label><input name="phone" required>
        <label>National ID number (ZW)</label>
        <input name="national_id_number" placeholder="63-1234567-A-00" required>
        <label>Password</label><input name="password" type="password" required>
        <div style="margin-top:12px"><button class="btn">Register</button></div>
      </form>
      <p class="muted" style="margin-top:10px">Have an account? <a href="/login">Login</a></p>
    </div>
    """)


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pw = request.form.get("password","")
        u = q("SELECT * FROM users WHERE email=?", (email,), one=True)
        if u and check_password_hash(u["password_hash"], pw):
            if u["blacklisted"]: flash("Account suspended.", "error"); return redirect("/login")
            session["uid"] = u["id"]
            return redirect("/admin" if u["role"] == "admin" else "/dashboard")
        flash("Invalid credentials.", "error")
    return render_page("""
    <div class="card" style="max-width:420px;margin:0 auto">
      <h1>Login</h1>
      <form method="post">
        <label>Email</label><input name="email" type="email" required>
        <label>Password</label><input name="password" type="password" required>
        <div style="margin-top:12px"><button class="btn">Login</button></div>
      </form>
    </div>
    """)


@app.route("/logout")
def logout(): session.clear(); return redirect("/")


@app.route("/verify", methods=["GET","POST"])
@login_required()
def verify():
    u = current_user()
    if u["role"] == "admin": return redirect("/admin")
    if request.method == "POST":
        id_doc = save_upload(request.files.get("id_doc"), "id")
        selfie = save_upload(request.files.get("selfie"), "selfie")
        if not id_doc or not selfie:
            flash("National ID and selfie are required.", "error"); return redirect("/verify")
        role = u["role"]
        td = lic = lodge_lic = vreg = vlic = None
        vmake = vmodel = vplate = vcap = None
        if role == "landlord":
            td = save_upload(request.files.get("title_deed"), "td")
            if not td: flash("Title deed required for landlords.", "error"); return redirect("/verify")
        elif role == "agent":
            lic = save_upload(request.files.get("license"), "lic")
            if not lic: flash("Agent license required.", "error"); return redirect("/verify")
        elif role == "lodge":
            lodge_lic = save_upload(request.files.get("lodge_license"), "lodge")
            if not lodge_lic: flash("Lodge / business registration required.", "error"); return redirect("/verify")
        elif role == "transport":
            vreg = save_upload(request.files.get("vehicle_reg"), "vreg")
            vlic = save_upload(request.files.get("vehicle_licence"), "vlic")
            if not vreg or not vlic: flash("Vehicle registration & licence required.", "error"); return redirect("/verify")
            vmake = request.form.get("vehicle_make","")
            vmodel = request.form.get("vehicle_model","")
            vplate = request.form.get("vehicle_plate","")
            vcap = request.form.get("vehicle_capacity","")
        score, status = face_verify(
            os.path.join(UPLOAD_DIR, selfie),
            os.path.join(UPLOAD_DIR, id_doc),
            float(get_setting("face_match_threshold","0.75"))
        )
        ex("""INSERT INTO verifications(
              user_id, role_snapshot, id_doc_url, selfie_url,
              face_match_score, face_match_status,
              title_deed_url, agent_license_url, lodge_license_url,
              vehicle_reg_url, vehicle_licence_url,
              vehicle_make, vehicle_model, vehicle_plate, vehicle_capacity,
              status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')""",
           (u["id"], role, id_doc, selfie, score, status, td, lic, lodge_lic, vreg, vlic,
            vmake, vmodel, vplate, vcap))
        ex("UPDATE users SET verification_status='pending' WHERE id=?", (u["id"],))
        flash("Submitted for review. You'll be notified once verified.")
        return redirect("/dashboard")
    return render_page(tab_bar(u["role"], "/verify") + """
    <div class="card">
      <h1>Verify your account</h1>
      <p class="muted">Status: <b>{{ u.verification_status }}</b></p>
      <p class="muted">Your ID, selfie and documents are <b>private</b> — only Admin reviews them.</p>
      <form method="post" enctype="multipart/form-data">
        <label>National ID document (photo/PDF)</label><input type="file" name="id_doc" required accept="image/*,application/pdf">
        <label>Selfie (clear face photo)</label><input type="file" name="selfie" required accept="image/*" capture="user">
        {% if u.role == 'landlord' %}
          <label>Title deed</label><input type="file" name="title_deed" required>
        {% elif u.role == 'agent' %}
          <label>Agent license</label><input type="file" name="license" required>
        {% elif u.role == 'lodge' %}
          <label>Lodge / business registration</label><input type="file" name="lodge_license" required>
        {% elif u.role == 'transport' %}
          <label>Vehicle registration</label><input type="file" name="vehicle_reg" required>
          <label>Vehicle licence</label><input type="file" name="vehicle_licence" required>
          <div class="row">
            <div><label>Make</label><input name="vehicle_make"></div>
            <div><label>Model</label><input name="vehicle_model"></div>
            <div><label>Plate</label><input name="vehicle_plate"></div>
            <div><label>Capacity</label><input name="vehicle_capacity" placeholder="e.g. 1.5t / 14 seats"></div>
          </div>
        {% endif %}
        <div style="margin-top:12px"><button class="btn">Submit</button></div>
      </form>
    </div>
    """, u=u)


# =============================================================
# DASHBOARD
# =============================================================
@app.route("/dashboard")
@login_required()
def dashboard():
    u = current_user()
    if u["role"] == "admin": return redirect("/admin")
    if u["role"] == "transport": return redirect("/transport/my")
    return redirect("/dashboard/listings")


@app.route("/dashboard/listings")
@login_required()
def dashboard_listings():
    u = current_user()
    if u["role"] not in ("landlord","agent","lodge"): abort(403)
    listings = q("SELECT * FROM listings WHERE user_id=? ORDER BY id DESC", (u["id"],))
    return render_page(tab_bar(u["role"], "/dashboard/listings") + """
    <div class="card">
      <h1>My listings ({{ listings|length }})</h1>
      <p class="muted">Verification: <b>{{ u.verification_status }}</b></p>
      {% if u.verification_status != 'verified' %}<p><a class="btn" href="/verify">Complete verification</a></p>{% endif %}
      <p><a class="btn" href="/listing/new">+ New listing</a></p>
    </div>
    <div class="card">
      <table>
        <tr><th>Title</th><th>Category</th><th>Price</th><th>Status</th><th>Views/Clicks</th><th>Expires</th><th></th></tr>
        {% for l in listings %}
        <tr>
          <td>{{ l.title }}</td>
          <td>{{ l.category|replace('_',' ')|title }}</td>
          <td>{{ price_label(l) }}</td>
          <td>{{ l.status }}</td>
          <td>{{ l.views }} / {{ l.clicks }}</td>
          <td>{{ l.expires_at or '-' }}</td>
          <td>
            <a class="btn sm sec" href="/listing/{{ l.id }}/edit">Edit</a>
            <a class="btn sm sec" href="/listing/{{ l.id }}/delete" onclick="return confirm('Delete?')">Delete</a>
          </td>
        </tr>
        {% else %}<tr><td colspan="7" class="muted">No listings yet.</td></tr>{% endfor %}
      </table>
    </div>
    """, u=u, listings=listings)


@app.route("/dashboard/messages")
@login_required()
def dashboard_messages():
    u = current_user()
    if u["role"] == "admin": return redirect("/admin")
    convs = q("""SELECT c.*, l.title,
      (SELECT COUNT(*) FROM messages WHERE conversation_id=c.id AND sender='tenant' AND read_at IS NULL) unread,
      (SELECT body FROM messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) last_msg
      FROM conversations c JOIN listings l ON l.id=c.listing_id
      WHERE c.agent_id=? ORDER BY c.last_activity DESC""", (u["id"],))
    return render_page(tab_bar(u["role"], "/dashboard/messages") + """
    <div class="card"><h1>Messages</h1>
      <table>
        <tr><th>Listing</th><th>Tenant</th><th>Last message</th><th>Unread</th><th></th></tr>
        {% for c in convs %}
        <tr><td>{{ c.title }}</td><td>{{ c.tenant_name or 'Anonymous' }}</td>
        <td class="muted">{{ c.last_msg or '' }}</td>
        <td>{% if c.unread %}<span class="badge rej">{{ c.unread }}</span>{% endif %}</td>
        <td><a href="/dashboard/messages/{{ c.id }}">Open</a></td></tr>
        {% else %}<tr><td colspan="5" class="muted">No conversations yet.</td></tr>{% endfor %}
      </table>
    </div>
    """, u=u, convs=convs)


@app.route("/dashboard/messages/<int:cid>", methods=["GET","POST"])
@login_required()
def dashboard_thread(cid):
    u = current_user()
    c = q("SELECT * FROM conversations WHERE id=? AND agent_id=?", (cid, u["id"]), one=True)
    if not c: abort(404)
    l = q("SELECT * FROM listings WHERE id=?", (c["listing_id"],), one=True)
    if not l: abort(404)
    if request.method == "POST":
        body = sanitize_text(request.form.get("body",""), 2000)
        if body:
            ex("INSERT INTO messages(conversation_id,sender,body) VALUES(?,?,?)", (cid, "agent", body))
            ex("UPDATE conversations SET last_activity=datetime('now') WHERE id=?", (cid,))
        return redirect(f"/dashboard/messages/{cid}")
    msgs = q("SELECT * FROM messages WHERE conversation_id=? ORDER BY id", (cid,))
    ex("UPDATE messages SET read_at=datetime('now') WHERE conversation_id=? AND sender='tenant' AND read_at IS NULL", (cid,))
    return render_page(tab_bar(u["role"], "/dashboard/messages") + """
    <div class="card">
      <h1>Conversation · {{ l.title }}</h1>
      <div class="muted">Tenant: {{ c.tenant_name or 'Anonymous' }}{% if c.tenant_phone %} · {{ c.tenant_phone }}{% endif %}</div>
      <div class="chat-box" style="margin-top:10px">
        {% for m in msgs %}<div class="msg {{ m.sender }}">{{ m.body }}<span class="t">{{ m.sender|capitalize }} · {{ m.created_at }}</span></div>{% endfor %}
      </div>
      <form method="post" style="margin-top:10px">
        <textarea name="body" rows="3" required></textarea>
        <div style="margin-top:8px">
          <button class="btn">Send</button>
          {% if c.tenant_phone %}<a class="btn wa" target="_blank" href="https://wa.me/{{ wa_number(c.tenant_phone) }}">💬 Notify on WhatsApp</a>{% endif %}
        </div>
      </form>
    </div>
    """, c=c, l=l, msgs=msgs, u=u)


# =============================================================
# LISTING CREATE / EDIT / DELETE
# =============================================================
@app.route("/listing/new", methods=["GET","POST"])
@login_required()
def listing_new():
    u = current_user()
    if u["role"] == "admin": abort(403)
    if u["verification_status"] != "verified":
        flash("Verify your account before listing.", "error"); return redirect("/verify")
    allowed_cats = {
        "landlord": ["house_rent","house_sale","shop_rent","shop_sale","stand_sale"],
        "agent": ["house_rent","house_sale","shop_rent","shop_sale","stand_sale"],
        "lodge": ["lodge"],
        "transport": [],
    }.get(u["role"], [])
    if not allowed_cats:
        flash("Your role cannot create listings.", "error"); return redirect("/dashboard")
    durations = q("SELECT * FROM listing_durations WHERE active=1 ORDER BY days")
    if request.method == "POST":
        f = request.form
        cat = f.get("category")
        if cat not in allowed_cats: flash("Invalid category.", "error"); return redirect("/listing/new")
        duration_id = f.get("duration_id", type=int)
        d = q("SELECT * FROM listing_durations WHERE id=? AND active=1", (duration_id,), one=True)
        if not d: flash("Choose a duration.", "error"); return redirect("/listing/new")
        if not f.get("title") or not f.get("price") or not f.get("city"):
            flash("Title, price and city are required.", "error"); return redirect("/listing/new")
        fields = {
            "user_id": u["id"], "category": cat,
            "title": f["title"], "description": f.get("description",""),
            "price": float(f["price"]), "currency": f.get("currency","USD"),
            "rooms": int(f["rooms"]) if f.get("rooms") else None,
            "amenities": f.get("amenities",""),
            "city": f["city"], "suburb": f.get("suburb",""),
            "lat": float(f["lat"]) if f.get("lat") else None,
            "lng": float(f["lng"]) if f.get("lng") else None,
            "contact_name": f.get("contact_name", u["full_name"]),
            "contact_phone": f.get("contact_phone", u["phone"]),
            "status": "pending_payment",
        }
        if cat == "lodge":
            fields.update({
                "lodging_kind": f.get("lodging_kind",""),
                "star_rating": int(f["star_rating"]) if f.get("star_rating") else None,
                "checkin_time": f.get("checkin_time",""), "checkout_time": f.get("checkout_time",""),
                "rate_per_night": float(f["rate_per_night"]) if f.get("rate_per_night") else None,
                "rate_per_week": float(f["rate_per_week"]) if f.get("rate_per_week") else None,
                "rate_per_month": float(f["rate_per_month"]) if f.get("rate_per_month") else None,
                "max_guests": int(f["max_guests"]) if f.get("max_guests") else None,
                "bedrooms": int(f["bedrooms"]) if f.get("bedrooms") else None,
                "bathrooms": int(f["bathrooms"]) if f.get("bathrooms") else None,
                "beds": int(f["beds"]) if f.get("beds") else None,
                "has_wifi": 1 if f.get("has_wifi") else 0,
                "has_pool": 1 if f.get("has_pool") else 0,
                "has_restaurant": 1 if f.get("has_restaurant") else 0,
                "has_parking": 1 if f.get("has_parking") else 0,
                "has_ac": 1 if f.get("has_ac") else 0,
                "has_dstv": 1 if f.get("has_dstv") else 0,
                "has_breakfast": 1 if f.get("has_breakfast") else 0,
                "has_gym": 1 if f.get("has_gym") else 0,
                "has_laundry": 1 if f.get("has_laundry") else 0,
                "policies": f.get("policies",""),
                "nearby_attractions": f.get("nearby_attractions",""),
            })
        if cat == "stand_sale":
            fields.update({
                "area_sqm": float(f["area_sqm"]) if f.get("area_sqm") else None,
                "title_deed_status": f.get("title_deed_status",""),
                "zoning": f.get("zoning",""),
                "road_access": f.get("road_access",""),
                "services_available": f.get("services_available",""),
                "price_per_sqm": (float(f["price"])/float(f["area_sqm"])) if f.get("area_sqm") and float(f["area_sqm"])>0 else None,
            })
        cols = ",".join(fields.keys())
        placeholders = ",".join(["?"]*len(fields))
        lid = ex(f"INSERT INTO listings({cols}) VALUES({placeholders})", tuple(fields.values()))
        for i, fph in enumerate(request.files.getlist("photos")):
            name = save_upload(fph, f"l{lid}_{i}")
            if name: ex("INSERT INTO listing_photos(listing_id,url,watermarked,sort_order) VALUES(?,?,?,?)",
                        (lid, name, 1, i))
        ref = gen_ref()
        pid = ex("""INSERT INTO payments(user_id, listing_id, duration_id, type, amount, currency, ref_code, status)
                    VALUES(?,?,?,'listing_fee',?,?,?,'awaiting_verification')""",
                 (u["id"], lid, d["id"], d["price_usd"], "USD", ref))
        return redirect(f"/checkout/{pid}")
    return render_page(tab_bar(u["role"], "/listing/new") + """
    <div class="card">
      <h1>New listing</h1>
      <form method="post" enctype="multipart/form-data" id="nlForm">
        <label>Category</label>
        <select name="category" required onchange="toggleCat(this.value)">
          {% for c in allowed_cats %}<option value="{{ c }}">{{ c|replace('_',' ')|title }}</option>{% endfor %}
        </select>
        <div class="row">
          <div><label>Title</label><input name="title" required></div>
          <div><label>Price ({{ get_setting('default_currency','USD') }})</label><input name="price" type="number" step="0.01" required></div>
        </div>
        <div class="row">
          <div><label>Currency</label><select name="currency"><option>USD</option><option>ZWG</option></select></div>
          <div><label>Rooms</label><input name="rooms" type="number"></div>
        </div>
        <div class="row">
          <div><label>City</label><input name="city" required></div>
          <div><label>Suburb</label><input name="suburb"></div>
        </div>
        <div class="row">
          <div><label>Latitude</label><input name="lat" step="0.000001"></div>
          <div><label>Longitude</label><input name="lng" step="0.000001"></div>
        </div>

        <div id="lodgeFields" style="display:none;border-top:1px dashed var(--line);margin-top:10px;padding-top:10px">
          <h3>Lodge details</h3>
          <div class="row">
            <div><label>Lodging kind</label>
              <select name="lodging_kind">
                <option value="hotel">Hotel</option><option value="lodge">Lodge</option>
                <option value="guesthouse">Guesthouse</option><option value="bnb">B&B</option>
                <option value="backpackers">Backpackers</option><option value="self_catering">Self-catering</option>
                <option value="safari_camp">Safari camp</option><option value="cottage">Cottage</option>
              </select>
            </div>
            <div><label>Star rating</label><input name="star_rating" type="number" min="1" max="5"></div>
          </div>
          <div class="row">
            <div><label>Check-in</label><input name="checkin_time" placeholder="14:00"></div>
            <div><label>Check-out</label><input name="checkout_time" placeholder="10:00"></div>
          </div>
          <div class="row">
            <div><label>Rate/night</label><input name="rate_per_night" type="number" step="0.01"></div>
            <div><label>Rate/week</label><input name="rate_per_week" type="number" step="0.01"></div>
            <div><label>Rate/month</label><input name="rate_per_month" type="number" step="0.01"></div>
          </div>
          <div class="row">
            <div><label>Max guests</label><input name="max_guests" type="number"></div>
            <div><label>Bedrooms</label><input name="bedrooms" type="number"></div>
            <div><label>Bathrooms</label><input name="bathrooms" type="number"></div>
            <div><label>Beds</label><input name="beds" type="number"></div>
          </div>
          <div class="row">
            <label><input type="checkbox" name="has_wifi"> WiFi</label>
            <label><input type="checkbox" name="has_pool"> Pool</label>
            <label><input type="checkbox" name="has_restaurant"> Restaurant</label>
            <label><input type="checkbox" name="has_parking"> Parking</label>
            <label><input type="checkbox" name="has_ac"> A/C</label>
            <label><input type="checkbox" name="has_dstv"> DSTV</label>
            <label><input type="checkbox" name="has_breakfast"> Breakfast</label>
            <label><input type="checkbox" name="has_gym"> Gym</label>
            <label><input type="checkbox" name="has_laundry"> Laundry</label>
          </div>
          <label>Policies</label><textarea name="policies" rows="2"></textarea>
          <label>Nearby attractions</label><textarea name="nearby_attractions" rows="2"></textarea>
        </div>

        <div id="standFields" style="display:none;border-top:1px dashed var(--line);margin-top:10px;padding-top:10px">
          <h3>Stand details</h3>
          <div class="row">
            <div><label>Area (m²)</label><input name="area_sqm" type="number" step="0.01"></div>
            <div><label>Title deed status</label>
              <select name="title_deed_status">
                <option value="titled">Titled</option>
                <option value="offer_letter">Offer letter</option>
                <option value="gazetted">Gazetted</option>
                <option value="not_gazetted">Not gazetted</option>
              </select>
            </div>
          </div>
          <div class="row">
            <div><label>Zoning</label>
              <select name="zoning">
                <option value="residential">Residential</option>
                <option value="commercial">Commercial</option>
                <option value="industrial">Industrial</option>
                <option value="agricultural">Agricultural</option>
              </select>
            </div>
            <div><label>Road access</label>
              <select name="road_access">
                <option value="tarred">Tarred</option>
                <option value="gravel">Gravel</option>
                <option value="earth">Earth</option>
                <option value="none">None</option>
              </select>
            </div>
          </div>
          <label>Services available (water, electricity, sewer…)</label>
          <input name="services_available">
        </div>

        <label>Amenities (comma-separated)</label><input name="amenities">
        <label>Description</label><textarea name="description" rows="4"></textarea>
        <label>Contact name</label><input name="contact_name" value="{{ u.full_name }}">
        <label>Contact phone (WhatsApp)</label><input name="contact_phone" value="{{ u.phone }}">
        <label>Photos</label><input type="file" name="photos" multiple accept="image/*">
        <label>Listing duration (price)</label>
        <select name="duration_id" required>
          {% for d in durations %}
            <option value="{{ d.id }}">{{ d.label }} — USD {{ '%.2f'|format(d.price_usd) }}</option>
          {% endfor %}
        </select>
        <div style="margin-top:14px"><button class="btn">Submit & continue to payment</button></div>
      </form>
    </div>
    <script>
      function toggleCat(c){
        document.getElementById('lodgeFields').style.display = (c==='lodge')?'block':'none';
        document.getElementById('standFields').style.display = (c==='stand_sale')?'block':'none';
      }
      toggleCat(document.querySelector('[name=category]').value);
    </script>
    """, u=u, allowed_cats=allowed_cats, durations=durations)


@app.route("/listing/<int:lid>/edit", methods=["GET","POST"])
@login_required()
def listing_edit(lid):
    u = current_user()
    if u["role"] not in ("landlord","agent","lodge"): abort(403)
    l = q("SELECT * FROM listings WHERE id=? AND user_id=?", (lid, u["id"]), one=True)
    if not l: abort(404)
    if request.method == "POST":
        ex("""UPDATE listings SET title=?, description=?, price=?, currency=?, rooms=?, amenities=?,
              city=?, suburb=?, contact_name=?, contact_phone=? WHERE id=?""",
           (request.form["title"], request.form.get("description",""),
            float(request.form["price"]), request.form.get("currency","USD"),
            int(request.form["rooms"]) if request.form.get("rooms") else None,
            request.form.get("amenities",""), request.form["city"],
            request.form.get("suburb",""), request.form.get("contact_name",""),
            request.form.get("contact_phone",""), lid))
        flash("Updated."); return redirect("/dashboard/listings")
    return render_page(tab_bar(u["role"], "/dashboard/listings") + """
    <div class="card">
      <h1>Edit listing</h1>
      <form method="post">
        <label>Title</label><input name="title" value="{{ l.title }}" required>
        <label>Price</label><input name="price" type="number" step="0.01" value="{{ l.price }}" required>
        <div class="row"><div><label>Currency</label><input name="currency" value="{{ l.currency }}"></div>
        <div><label>Rooms</label><input name="rooms" type="number" value="{{ l.rooms or '' }}"></div></div>
        <div class="row"><div><label>City</label><input name="city" value="{{ l.city }}" required></div>
        <div><label>Suburb</label><input name="suburb" value="{{ l.suburb or '' }}"></div></div>
        <label>Amenities</label><input name="amenities" value="{{ l.amenities or '' }}">
        <label>Description</label><textarea name="description" rows="4">{{ l.description or '' }}</textarea>
        <label>Contact name</label><input name="contact_name" value="{{ l.contact_name or '' }}">
        <label>Contact phone</label><input name="contact_phone" value="{{ l.contact_phone or '' }}">
        <div style="margin-top:12px"><button class="btn">Save</button></div>
      </form>
    </div>
    """, l=l, u=u)


@app.route("/listing/<int:lid>/delete")
@login_required()
def listing_delete_own(lid):
    u = current_user()
    l = q("SELECT * FROM listings WHERE id=? AND user_id=?", (lid, u["id"]), one=True)
    if not l: abort(404)
    ex("DELETE FROM listings WHERE id=?", (lid,))
    flash("Listing deleted."); return redirect("/dashboard/listings")


# =============================================================
# CHECKOUT / SUBSCRIPTION
# =============================================================
@app.route("/checkout/<int:pid>", methods=["GET","POST"])
@login_required()
def checkout(pid):
    u = current_user()
    p = q("SELECT * FROM payments WHERE id=? AND user_id=?", (pid, u["id"]), one=True)
    if not p: abort(404)

    if p["status"] == "verified":
        return render_page("""
        <div class="card" style="max-width:600px;margin:0 auto">
          <h1>Payment already verified</h1>
          <p>Ref: <b>{{ p.ref_code }}</b> · Amount: <b>{{ p.currency }} {{ '%.2f'|format(p.amount) }}</b></p>
          <p>This payment has been verified. <a href="/dashboard">Go to dashboard</a>.</p>
        </div>
        """, p=p)

    if p["status"] == "rejected":
        return render_page("""
        <div class="card" style="max-width:600px;margin:0 auto">
          <h1>Payment rejected</h1>
          <p>Ref: <b>{{ p.ref_code }}</b> · Reason: {{ p.admin_note or '—' }}</p>
          <p>Please contact support via WhatsApp.</p>
        </div>
        """, p=p)

    if request.method == "POST":
        proof = save_upload(request.files.get("proof"), f"pay{pid}")
        txn = request.form.get("txn_id","").strip()
        if not proof or not txn:
            flash("Proof and Txn ID required.", "error"); return redirect(f"/checkout/{pid}")
        ex("UPDATE payments SET proof_url=?, txn_id=?, status='awaiting_verification' WHERE id=?",
           (proof, txn, pid))
        flash("Submitted for verification."); return redirect("/dashboard")

    return render_page("""
    <div class="card" style="max-width:600px;margin:0 auto">
      <h1>Complete EcoCash payment</h1>
      <p>Amount: <b>{{ p.currency }} {{ '%.2f'|format(p.amount) }}</b></p>
      <p>Send to EcoCash:<br><b>{{ get_setting('ecocash_number') }}</b><br>
         Name: <b>{{ get_setting('ecocash_receiver_name') }}</b><br>
         Reference: <b>{{ p.ref_code }}</b></p>
      <hr>
      <form method="post" enctype="multipart/form-data">
        <label>Proof screenshot</label><input type="file" name="proof" accept="image/*" required>
        <label>EcoCash transaction ID</label><input name="txn_id" required>
        <div style="margin-top:12px"><button class="btn">I have paid</button></div>
      </form>
    </div>
    """, p=p)


@app.route("/subscription")
@login_required()
def subscription():
    tiers = q("SELECT * FROM pricing_tiers WHERE type='subscription' AND active=1")
    return render_page(tab_bar(current_user()["role"], "/subscription") + """
    <div class="card"><h1>Buy subscription</h1>
      <form method="post" action="/subscription/buy">
        <select name="tier_id">
          {% for t in tiers %}<option value="{{ t.id }}">{{ t.name }} — {{ t.duration_days }} days — ${{ '%.2f'|format(t.price_usd) }}</option>{% endfor %}
        </select>
        <div style="margin-top:12px"><button class="btn">Continue</button></div>
      </form>
    </div>
    """, tiers=tiers)


@app.route("/subscription/buy", methods=["POST"])
@login_required()
def subscription_buy():
    u = current_user()
    t = q("SELECT * FROM pricing_tiers WHERE id=? AND type='subscription'", (request.form["tier_id"],), one=True)
    if not t: abort(404)
    ref = gen_ref()
    pid = ex("INSERT INTO payments(user_id,tier_id,type,amount,currency,ref_code,status) VALUES(?,?,'subscription',?,'USD',?,'awaiting_verification')",
             (u["id"], t["id"], t["price_usd"], ref))
    return redirect(f"/checkout/{pid}")


# =============================================================
# TRANSPORT
# =============================================================
@app.route("/transport")
def transport_home():
    city = request.args.get("city","").strip()
    ptype = request.args.get("type","").strip()
    sql = "SELECT * FROM transport_providers WHERE blacklisted=0"
    args = []
    if city: sql += " AND lower(city)=?"; args.append(city.lower())
    if ptype: sql += " AND provider_type=?"; args.append(ptype)
    sql += " ORDER BY verified DESC, id DESC"
    providers = q(sql, args)
    open_requests = q("SELECT * FROM transport_requests WHERE status='open' ORDER BY id DESC LIMIT 20")
    return render_page("""
    <h1>🚚 Transport</h1>
    <div class="card">
      <h2>Find a provider</h2>
      <form method="get" class="row">
        <div><label>City</label><input name="city" value="{{ request.args.city or '' }}"></div>
        <div><label>Type</label>
          <select name="type">
            <option value="">Any</option>
            <option value="taxi">Taxi</option><option value="shuttle">Shuttle</option>
            <option value="truck">Truck</option><option value="mover">Mover</option>
            <option value="bus">Bus</option><option value="mixed">Mixed</option>
          </select>
        </div>
        <div style="align-self:flex-end"><button class="btn">Search</button></div>
      </form>
    </div>
    <div class="grid">
      {% for t in providers %}
      <div class="card">
        <b>{{ t.business_name }}</b> <span class="muted">· {{ t.provider_type }}</span>
        {% if t.verified %}<span class="badge ok">✅ Verified</span>{% endif %}
        <div class="muted">📍 {{ t.city }}</div>
        {% if t.vehicle_summary %}<div class="muted">{{ t.vehicle_summary }}</div>{% endif %}
        {% if t.description %}<p class="muted">{{ t.description }}</p>{% endif %}
        <a class="btn wa sm" target="_blank" href="https://wa.me/{{ wa_number(t.whatsapp or t.phone) }}">💬 WhatsApp</a>
        <a class="btn call sm" href="tel:{{ tel_number(t.phone) }}">📞 Call</a>
      </div>
      {% else %}<p class="muted">No providers.</p>{% endfor %}
    </div>
    <h2>Open requests</h2>
    <div class="card">
      <table>
        <tr><th>Type</th><th>From</th><th>To</th><th>When</th><th>City</th></tr>
        {% for r in open_requests %}
        <tr><td>{{ r.request_type }}</td><td>{{ r.from_location }}</td><td>{{ r.to_location }}</td>
        <td>{{ r.when_date or '' }} {{ r.when_time or '' }}</td><td>{{ r.city or '' }}</td></tr>
        {% else %}<tr><td colspan="5" class="muted">No open requests.</td></tr>{% endfor %}
      </table>
      <p><a class="btn" href="/transport/request">+ Post a transport request</a></p>
    </div>
    """)


@app.route("/transport/request", methods=["GET","POST"])
def transport_request():
    u = current_user()
    if request.method == "POST":
        f = request.form
        if not f.get("request_type"):
            flash("Request type required.", "error"); return redirect("/transport/request")
        ex("""INSERT INTO transport_requests(
            requester_user_id, requester_name, requester_phone,
            request_type, from_location, to_location, when_date, when_time,
            description, budget, city, linked_listing_id)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (u["id"] if u else None, f.get("requester_name",""), f.get("requester_phone",""),
           f["request_type"], f.get("from_location",""), f.get("to_location",""),
           f.get("when_date",""), f.get("when_time",""),
           f.get("description",""), f.get("budget",""), f.get("city",""),
           int(f["linked"]) if f.get("linked") else None))
        flash("Request posted! Providers will contact you.")
        return redirect("/transport")
    return render_page("""
    <div class="card" style="max-width:600px;margin:0 auto">
      <h1>Post a transport request</h1>
      <form method="post">
        <label>Request type</label>
        <select name="request_type" required>
          <option value="moving">Moving house</option>
          <option value="taxi">Taxi</option>
          <option value="shuttle">Shuttle</option>
          <option value="truck">Truck</option>
          <option value="bus">Bus</option>
          <option value="other">Other</option>
        </select>
        {% if not current_user %}
          <label>Your name</label><input name="requester_name">
          <label>Your phone (WhatsApp)</label><input name="requester_phone">
        {% endif %}
        <div class="row">
          <div><label>From</label><input name="from_location"></div>
          <div><label>To</label><input name="to_location"></div>
        </div>
        <div class="row">
          <div><label>Date</label><input type="date" name="when_date"></div>
          <div><label>Time</label><input type="time" name="when_time"></div>
        </div>
        <label>City</label><input name="city" value="{{ request.args.city or '' }}">
        <label>Description</label><textarea name="description" rows="3"></textarea>
        <label>Budget (optional)</label><input name="budget">
        <input type="hidden" name="linked" value="{{ request.args.linked or '' }}">
        <div style="margin-top:12px"><button class="btn">Post request</button></div>
      </form>
    </div>
    """)


@app.route("/transport/my")
@login_required()
def transport_my():
    u = current_user()
    if u["role"] != "transport": return redirect("/dashboard")
    p = q("SELECT * FROM transport_providers WHERE user_id=?", (u["id"],), one=True)
    return render_page(tab_bar("transport", "/transport/my") + """
    <div class="card">
      <h1>My transport profile</h1>
      {% if p %}
        <b>{{ p.business_name }}</b> · {{ p.provider_type }} · {{ p.city }}
        {% if p.verified %}<span class="badge ok">✅ Verified</span>{% endif %}
        <p class="muted">{{ p.vehicle_summary or '' }}</p>
        <p class="muted">WhatsApp: {{ p.whatsapp or p.phone }}</p>
        <a class="btn" href="/transport/my/edit">Edit</a>
      {% else %}
        <p>You haven't created your provider profile yet.</p>
        <a class="btn" href="/transport/my/edit">Create profile</a>
      {% endif %}
    </div>
    """, u=u, p=p)


@app.route("/transport/my/edit", methods=["GET","POST"])
@login_required()
def transport_my_edit():
    u = current_user()
    if u["role"] != "transport": abort(403)
    p = q("SELECT * FROM transport_providers WHERE user_id=?", (u["id"],), one=True)
    if request.method == "POST":
        f = request.form
        if p:
            ex("""UPDATE transport_providers SET business_name=?, provider_type=?, city=?,
                  service_areas=?, description=?, phone=?, whatsapp=?, email=?, vehicle_summary=?
                  WHERE id=?""",
               (f["business_name"], f["provider_type"], f["city"],
                f.get("service_areas",""), f.get("description",""),
                f.get("phone",""), f.get("whatsapp",""), f.get("email",""),
                f.get("vehicle_summary",""), p["id"]))
        else:
            ex("""INSERT INTO transport_providers(user_id,business_name,provider_type,city,
                  service_areas,description,phone,whatsapp,email,vehicle_summary)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (u["id"], f["business_name"], f["provider_type"], f["city"],
                f.get("service_areas",""), f.get("description",""),
                f.get("phone", u["phone"]), f.get("whatsapp", u["phone"]),
                f.get("email", u["email"]), f.get("vehicle_summary","")))
        flash("Saved."); return redirect("/transport/my")
    return render_page(tab_bar("transport", "/transport/my") + """
    <div class="card">
      <h1>Transport profile</h1>
      <form method="post">
        <label>Business name</label><input name="business_name" value="{{ p.business_name if p else '' }}" required>
        <label>Provider type</label>
        <select name="provider_type">
          {% for t in ['taxi','shuttle','truck','mover','bus','mixed'] %}
          <option value="{{ t }}" {{ 'selected' if p and p.provider_type==t }}>{{ t }}</option>
          {% endfor %}
        </select>
        <label>City</label><input name="city" value="{{ p.city if p else '' }}" required>
        <label>Service areas</label><input name="service_areas" value="{{ p.service_areas if p else '' }}">
        <label>Description</label><textarea name="description" rows="3">{{ p.description if p else '' }}</textarea>
        <div class="row">
          <div><label>Phone</label><input name="phone" value="{{ p.phone if p else '' }}"></div>
          <div><label>WhatsApp</label><input name="whatsapp" value="{{ p.whatsapp if p else '' }}"></div>
        </div>
        <label>Email</label><input name="email" value="{{ p.email if p else '' }}">
        <label>Vehicle summary</label><input name="vehicle_summary" value="{{ p.vehicle_summary if p else '' }}" placeholder="e.g. Toyota Hiace (14 seats), 1.5t truck">
        <div style="margin-top:12px"><button class="btn">Save</button></div>
      </form>
    </div>
    """, p=p, u=u)


@app.route("/transport/requests")
@login_required()
def transport_requests_list():
    u = current_user()
    if u["role"] != "transport": abort(403)
    p = q("SELECT * FROM transport_providers WHERE user_id=?", (u["id"],), one=True)
    reqs = q("SELECT * FROM transport_requests WHERE status='open' ORDER BY id DESC")
    quotes = {}
    if p:
        for r in q("SELECT * FROM transport_quotes WHERE provider_id=?", (p["id"],)):
            quotes[r["request_id"]] = r
    else:
        flash("Create your transport provider profile first to send quotes.", "error")
    return render_page(tab_bar("transport", "/transport/requests") + """
    <h1>Open requests</h1>
    <div class="card">
      <table>
        <tr><th>Type</th><th>From → To</th><th>When</th><th>City</th><th>Budget</th><th>Action</th></tr>
        {% for r in reqs %}
        <tr>
          <td>{{ r.request_type }}</td>
          <td>{{ r.from_location }} → {{ r.to_location }}</td>
          <td>{{ r.when_date or '' }} {{ r.when_time or '' }}</td>
          <td>{{ r.city or '' }}</td>
          <td>{{ r.budget or '—' }}</td>
          <td>
            {% if not has_provider %}
              <a href="/transport/my/edit" class="btn sm">Create profile</a>
            {% elif r.id in quotes %}
              Quoted: ${{ quotes[r.id].price }}
            {% else %}
              <form method="post" action="/transport/quote/{{ r.id }}">
                <input name="price" type="number" step="0.01" placeholder="Price" style="width:90px;display:inline">
                <input name="message" placeholder="Message" style="width:140px;display:inline">
                <button class="btn sm">Send quote</button>
              </form>
            {% endif %}
          </td>
        </tr>
        {% else %}<tr><td colspan="6" class="muted">No open requests.</td></tr>{% endfor %}
      </table>
    </div>
    """, u=u, reqs=reqs, quotes=quotes, has_provider=bool(p))


@app.route("/transport/quote/<int:rid>", methods=["POST"])
@login_required()
def transport_quote(rid):
    u = current_user()
    if u["role"] != "transport": abort(403)
    p = q("SELECT * FROM transport_providers WHERE user_id=?", (u["id"],), one=True)
    if not p: abort(403)
    ex("INSERT INTO transport_quotes(request_id,provider_id,price,message) VALUES(?,?,?,?)",
       (rid, p["id"], float(request.form.get("price",0)), request.form.get("message","")))
    flash("Quote sent."); return redirect("/transport/requests")


# =============================================================
# ADMIN
# =============================================================
@app.route("/admin")
@admin_required
def admin_home():
    pending_listings = q("SELECT l.*, u.full_name FROM listings l JOIN users u ON u.id=l.user_id WHERE l.status='pending_review' ORDER BY l.id DESC")
    pending_payments = q("SELECT p.*, u.full_name FROM payments p JOIN users u ON u.id=p.user_id WHERE p.status='awaiting_verification' ORDER BY p.id DESC")
    pending_verifs = q("SELECT v.*, u.full_name, u.role, u.email, u.phone, u.national_id_number FROM verifications v JOIN users u ON u.id=v.user_id WHERE v.status='pending' ORDER BY v.id DESC")
    open_reports = q("SELECT r.*, l.title FROM reports r JOIN listings l ON l.id=r.listing_id WHERE r.status='open' ORDER BY r.id DESC")
    stats = {
        "active_listings": q("SELECT COUNT(*) c FROM listings WHERE status='active'", one=True)["c"],
        "revenue": q("SELECT COALESCE(SUM(amount),0) s FROM payments WHERE status='verified'", one=True)["s"],
        "users": q("SELECT COUNT(*) c FROM users WHERE role!='admin'", one=True)["c"],
    }
    return render_page(tab_bar("admin", "/admin") + """
    <h1>Admin Dashboard</h1>
    <div class="grid">
      <div class="card"><div class="muted">Active listings</div><h2>{{ stats.active_listings }}</h2></div>
      <div class="card"><div class="muted">Revenue</div><h2>${{ '%.2f'|format(stats.revenue) }}</h2></div>
      <div class="card"><div class="muted">Users</div><h2>{{ stats.users }}</h2></div>
    </div>

    <div class="card"><h2>Pending verifications ({{ pending_verifs|length }})</h2>
      <table>
        <tr><th>User</th><th>ID number</th><th>Docs</th><th>Auto-match</th><th>Action</th></tr>
        {% for v in pending_verifs %}
        <tr>
          <td>{{ v.full_name }}<br><span class="muted">{{ v.role }} · {{ v.phone }}</span></td>
          <td>{{ v.national_id_number or '—' }}</td>
          <td>
            {% if v.id_doc_url %}<a target="_blank" href="/uploads/{{ v.id_doc_url }}">ID</a>{% endif %}
            {% if v.selfie_url %} · <a target="_blank" href="/uploads/{{ v.selfie_url }}">Selfie</a>{% endif %}
            {% if v.title_deed_url %} · <a target="_blank" href="/uploads/{{ v.title_deed_url }}">Deed</a>{% endif %}
            {% if v.agent_license_url %} · <a target="_blank" href="/uploads/{{ v.agent_license_url }}">Licence</a>{% endif %}
            {% if v.lodge_license_url %} · <a target="_blank" href="/uploads/{{ v.lodge_license_url }}">Lodge</a>{% endif %}
            {% if v.vehicle_reg_url %} · <a target="_blank" href="/uploads/{{ v.vehicle_reg_url }}">VReg</a>{% endif %}
            {% if v.vehicle_licence_url %} · <a target="_blank" href="/uploads/{{ v.vehicle_licence_url }}">VLic</a>{% endif %}
          </td>
          <td>
            {% if v.face_match_status == 'auto_pass' %}<span class="badge ok">auto {{ v.face_match_score }}</span>
            {% elif v.face_match_status == 'manual_only' %}<span class="badge pending">manual only</span>
            {% else %}<span class="badge pending">{{ v.face_match_score }}</span>{% endif %}
          </td>
          <td>
            <form method="post" action="/admin/verify/{{ v.id }}" style="display:inline"><button class="btn sm" name="act" value="approve">Approve</button></form>
            <form method="post" action="/admin/verify/{{ v.id }}" style="display:inline">
              <input name="reason" placeholder="reason" style="width:90px;display:inline">
              <button class="btn sm danger" name="act" value="reject">Reject</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="card"><h2>Pending payments ({{ pending_payments|length }})</h2>
      <table>
        <tr><th>Ref</th><th>User</th><th>Type</th><th>Amount</th><th>Proof</th><th>Action</th></tr>
        {% for p in pending_payments %}
        <tr>
          <td>{{ p.ref_code }}</td><td>{{ p.full_name }}</td><td>{{ p.type }}</td>
          <td>${{ '%.2f'|format(p.amount) }}</td>
          <td>{% if p.proof_url %}<a target="_blank" href="/uploads/{{ p.proof_url }}">view</a>{% endif %}</td>
          <td>
            <form method="post" action="/admin/payment/{{ p.id }}" style="display:inline"><button class="btn sm" name="act" value="approve">Verify</button></form>
            <form method="post" action="/admin/payment/{{ p.id }}" style="display:inline">
              <input name="reason" placeholder="reason" style="width:90px;display:inline">
              <button class="btn sm danger" name="act" value="reject">Reject</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="card"><h2>Pending listings ({{ pending_listings|length }})</h2>
      <table>
        <tr><th>Title</th><th>Agent</th><th>Category</th><th>Preview</th><th>Action</th></tr>
        {% for l in pending_listings %}
        <tr>
          <td>{{ l.title }}<br><span class="muted">{{ l.suburb }}, {{ l.city }} — {{ price_label(l) }}</span></td>
          <td>{{ l.full_name }}</td><td>{{ l.category }}</td>
          <td><a target="_blank" href="/listing/{{ l.id }}">Open</a></td>
          <td>
            <form method="post" action="/admin/listing/{{ l.id }}" style="display:inline"><button class="btn sm" name="act" value="approve">Approve</button></form>
            <form method="post" action="/admin/listing/{{ l.id }}" style="display:inline">
              <input name="reason" placeholder="reason" style="width:90px;display:inline">
              <button class="btn sm danger" name="act" value="reject">Reject</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>

    <div class="card"><h2>Open reports ({{ open_reports|length }})</h2>
      <table>
        <tr><th>Listing</th><th>Reason</th><th>Action</th></tr>
        {% for r in open_reports %}
        <tr><td><a href="/listing/{{ r.listing_id }}">{{ r.title }}</a></td><td>{{ r.reason }}</td>
        <td>
          <form method="post" action="/admin/report/{{ r.id }}" style="display:inline"><button class="btn sm sec" name="act" value="dismiss">Dismiss</button></form>
          <form method="post" action="/admin/report/{{ r.id }}" style="display:inline"><button class="btn sm" name="act" value="hide">Hide</button></form>
          <form method="post" action="/admin/report/{{ r.id }}" style="display:inline"><button class="btn sm danger" name="act" value="remove">Remove</button></form>
        </td></tr>
        {% endfor %}
      </table>
    </div>
    """, pending_listings=pending_listings, pending_payments=pending_payments,
         pending_verifs=pending_verifs, open_reports=open_reports, stats=stats)


@app.route("/admin/verifications")
@admin_required
def admin_verifications():
    pending = q("SELECT v.*, u.full_name, u.role, u.email, u.phone, u.national_id_number FROM verifications v JOIN users u ON u.id=v.user_id WHERE v.status='pending' ORDER BY v.id DESC")
    return render_page(tab_bar("admin","/admin/verifications") + """
    <h1>Verifications</h1>
    {% for v in pending %}
    <div class="card">
      <b>{{ v.full_name }}</b> <span class="muted">· {{ v.role }} · {{ v.phone }} · ID: {{ v.national_id_number or '—' }}</span>
      <div class="row" style="margin-top:10px">
        <div><div class="muted">ID document</div>{% if v.id_doc_url %}<a target="_blank" href="/uploads/{{ v.id_doc_url }}"><img src="/uploads/{{ v.id_doc_url }}" style="max-width:100%;border-radius:6px"></a>{% endif %}</div>
        <div><div class="muted">Selfie</div>{% if v.selfie_url %}<a target="_blank" href="/uploads/{{ v.selfie_url }}"><img src="/uploads/{{ v.selfie_url }}" style="max-width:100%;border-radius:6px"></a>{% endif %}</div>
      </div>
      <p>Auto-match: <b>{{ v.face_match_status or '—' }}</b> ({{ v.face_match_score or '—' }})</p>
      <form method="post" action="/admin/verify/{{ v.id }}" style="display:inline"><button class="btn" name="act" value="approve">Approve</button></form>
      <form method="post" action="/admin/verify/{{ v.id }}" style="display:inline">
        <input name="reason" placeholder="reason" style="width:150px;display:inline">
        <button class="btn danger" name="act" value="reject">Reject</button>
      </form>
    </div>
    {% else %}<p class="muted">No pending verifications.</p>{% endfor %}
    """, pending=pending)


@app.route("/admin/payments")
@admin_required
def admin_payments_page():
    ps = q("SELECT p.*, u.full_name FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100")
    return render_page(tab_bar("admin","/admin/payments") + """
    <h1>Payments</h1>
    <div class="card"><table>
      <tr><th>Date</th><th>User</th><th>Type</th><th>Amount</th><th>Ref</th><th>Status</th></tr>
      {% for p in ps %}<tr><td>{{ p.created_at }}</td><td>{{ p.full_name }}</td><td>{{ p.type }}</td>
      <td><b>${{ '%.2f'|format(p.amount) }}</b></td><td>{{ p.ref_code }}</td><td>{{ p.status }}</td></tr>{% endfor %}
    </table></div>
    """, ps=ps)


@app.route("/admin/listings")
@admin_required
def admin_listings_page():
    ls = q("SELECT l.*, u.full_name FROM listings l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200")
    return render_page(tab_bar("admin","/admin/listings") + """
    <h1>All listings</h1>
    <div class="card"><table>
      <tr><th>Title</th><th>Agent</th><th>Category</th><th>Price</th><th>Status</th><th>Featured</th><th>Action</th></tr>
      {% for l in ls %}
      <tr>
        <td>{{ l.title }}<br><span class="muted">{{ l.suburb }}, {{ l.city }}</span></td>
        <td>{{ l.full_name }}</td><td>{{ l.category }}</td><td>{{ price_label(l) }}</td>
        <td>{{ l.status }}</td>
        <td>{% if l.is_featured %}<span class="badge ok">★</span>{% else %}—{% endif %}</td>
        <td>
          <form method="post" action="/admin/listing_feature/{{ l.id }}" style="display:inline"><button class="btn sm">{% if l.is_featured %}Unfeature{% else %}Feature{% endif %}</button></form>
          <form method="post" action="/admin/listing_delete/{{ l.id }}" style="display:inline" onsubmit="return confirm('Delete?')"><button class="btn sm danger">Delete</button></form>
        </td>
      </tr>
      {% endfor %}
    </table></div>
    """, ls=ls)


@app.route("/admin/users")
@admin_required
def admin_users_page():
    us = q("SELECT *, (SELECT COUNT(*) FROM listings WHERE user_id=users.id) listing_count FROM users WHERE role!='admin' ORDER BY id DESC LIMIT 200")
    return render_page(tab_bar("admin","/admin/users") + """
    <h1>Users</h1>
    <div class="card"><table>
      <tr><th>Name</th><th>Role</th><th>Phone / Email</th><th>Listings</th><th>Verified</th><th>Blocked</th><th>Action</th></tr>
      {% for u in us %}
      <tr>
        <td>{{ u.full_name }}</td><td>{{ u.role }}</td>
        <td>{{ u.phone }}<br><span class="muted">{{ u.email }}</span></td>
        <td>{{ u.listing_count }}</td>
        <td>{% if u.verified_badge %}<span class="badge ok">✅</span>{% else %}—{% endif %}</td>
        <td>{% if u.blacklisted %}<span class="badge rej">Blocked</span>{% else %}—{% endif %}</td>
        <td>
          <form method="post" action="/admin/user_toggle/{{ u.id }}" style="display:inline">
            <button class="btn sm">{% if u.blacklisted %}Unblock{% else %}Block{% endif %}</button>
          </form>
          <form method="post" action="/admin/user_delete/{{ u.id }}" style="display:inline" onsubmit="return confirm('Delete user + listings?')">
            <button class="btn sm danger">Delete</button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </table></div>
    """, us=us)


@app.route("/admin/transport")
@admin_required
def admin_transport():
    ps = q("SELECT p.*, u.full_name FROM transport_providers p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC")
    return render_page(tab_bar("admin","/admin/transport") + """
    <h1>Transport providers</h1>
    <div class="card"><table>
      <tr><th>Business</th><th>Owner</th><th>Type</th><th>City</th><th>Verified</th><th>Blocked</th><th>Action</th></tr>
      {% for p in ps %}
      <tr>
        <td>{{ p.business_name }}</td><td>{{ p.full_name }}</td><td>{{ p.provider_type }}</td><td>{{ p.city }}</td>
        <td>{% if p.verified %}<span class="badge ok">✅</span>{% else %}—{% endif %}</td>
        <td>{% if p.blacklisted %}<span class="badge rej">Blocked</span>{% else %}—{% endif %}</td>
        <td>
          <form method="post" action="/admin/transport_toggle/{{ p.id }}" style="display:inline"><button class="btn sm">{% if p.blacklisted %}Unblock{% else %}Block{% endif %}</button></form>
        </td>
      </tr>
      {% endfor %}
    </table></div>
    """, ps=ps)


@app.route("/admin/durations", methods=["GET","POST"])
@admin_required
def admin_durations():
    if request.method == "POST":
        label = request.form.get("label","").strip()
        try:
            days = int(request.form["days"])
            price = float(request.form["price_usd"])
        except Exception:
            flash("Invalid numbers.", "error"); return redirect("/admin/durations")
        if not label: flash("Label required.", "error"); return redirect("/admin/durations")
        ex("INSERT INTO listing_durations(label,days,price_usd) VALUES(?,?,?)", (label, days, price))
        flash("Added."); return redirect("/admin/durations")
    durs = q("SELECT * FROM listing_durations ORDER BY days")
    return render_page(tab_bar("admin","/admin/durations") + """
    <h1>Listing durations & prices</h1>
    <div class="card">
      <table>
        <tr><th>Label</th><th>Days</th><th>Price (USD)</th><th>Active</th><th>Action</th></tr>
        {% for d in durs %}
        <tr><td>{{ d.label }}</td><td>{{ d.days }}</td><td>{{ '%.2f'|format(d.price_usd) }}</td>
        <td>{{ 'Yes' if d.active else 'No' }}</td>
        <td>
          <form method="post" action="/admin/durations/{{ d.id }}/delete" style="display:inline" onsubmit="return confirm('Delete?')"><button class="btn sm danger">Delete</button></form>
        </td></tr>
        {% endfor %}
      </table>
    </div>
    <div class="card">
      <h2>Add duration</h2>
      <form method="post" class="row">
        <div><label>Label</label><input name="label" required></div>
        <div><label>Days</label><input name="days" type="number" required></div>
        <div><label>Price (USD)</label><input name="price_usd" type="number" step="0.01" required></div>
        <div style="align-self:flex-end"><button class="btn">Add</button></div>
      </form>
    </div>
    """, durs=durs)


@app.route("/admin/durations/<int:did>/delete", methods=["POST"])
@admin_required
def admin_duration_delete(did):
    used = q("SELECT COUNT(*) c FROM payments WHERE duration_id=?", (did,), one=True)["c"]
    if used:
        flash(f"Warning: {used} payment(s) reference this duration. Deleted anyway; "
              f"those payments will fall back to 30 days on approval.", "error")
    ex("DELETE FROM listing_durations WHERE id=?", (did,))
    flash("Deleted."); return redirect("/admin/durations")


@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings():
    keys = ["ecocash_number","ecocash_receiver_name","whatsapp_support_number",
            "whatsapp_support_display_name","site_email","default_currency",
            "watermark_text","site_credit","developer_name","developer_whatsapp",
            "developer_email","auto_face_match_enabled","face_match_threshold"]
    if request.method == "POST":
        for k in keys:
            if k in request.form: set_setting(k, request.form[k])
        flash("Saved."); return redirect("/admin/settings")
    return render_page(tab_bar("admin","/admin/settings") + """
    <h1>Settings</h1>
    <div class="card">
      <form method="post">
        {% for k in keys %}
          <label>{{ k }}</label><input name="{{ k }}" value="{{ get_setting(k) }}">
        {% endfor %}
        <div style="margin-top:12px"><button class="btn">Save</button></div>
      </form>
    </div>
    """, keys=keys)


# ---------- Admin action routes ----------
@app.route("/admin/listing_feature/<int:lid>", methods=["POST"])
@admin_required
def admin_listing_feature(lid):
    l = q("SELECT is_featured FROM listings WHERE id=?", (lid,), one=True)
    if not l: abort(404)
    ex("UPDATE listings SET is_featured=? WHERE id=?", (0 if l["is_featured"] else 1, lid))
    flash("Toggled featured."); return redirect("/admin/listings")


@app.route("/admin/listing_delete/<int:lid>", methods=["POST"])
@admin_required
def admin_listing_delete(lid):
    ex("DELETE FROM listings WHERE id=?", (lid,))
    flash("Listing deleted."); return redirect("/admin/listings")


@app.route("/admin/user_toggle/<int:uid>", methods=["POST"])
@admin_required
def admin_user_toggle(uid):
    u = q("SELECT blacklisted FROM users WHERE id=?", (uid,), one=True)
    if not u: abort(404)
    ex("UPDATE users SET blacklisted=? WHERE id=?", (0 if u["blacklisted"] else 1, uid))
    flash("User toggled."); return redirect("/admin/users")


@app.route("/admin/user_delete/<int:uid>", methods=["POST"])
@admin_required
def admin_user_delete(uid):
    ex("DELETE FROM users WHERE id=? AND role!='admin'", (uid,))
    flash("User deleted."); return redirect("/admin/users")


@app.route("/admin/transport_toggle/<int:tid>", methods=["POST"])
@admin_required
def admin_transport_toggle(tid):
    p = q("SELECT blacklisted FROM transport_providers WHERE id=?", (tid,), one=True)
    if not p: abort(404)
    ex("UPDATE transport_providers SET blacklisted=? WHERE id=?", (0 if p["blacklisted"] else 1, tid))
    flash("Toggled."); return redirect("/admin/transport")


@app.route("/admin/verify/<int:vid>", methods=["POST"])
@admin_required
def admin_verify(vid):
    v = q("SELECT * FROM verifications WHERE id=?", (vid,), one=True)
    if not v: abort(404)
    if request.form.get("act") == "approve":
        ex("UPDATE verifications SET status='verified', reviewed_by=? WHERE id=?", (current_user()["id"], vid))
        ex("UPDATE users SET verification_status='verified', verified_badge=1, face_verified=1 WHERE id=?", (v["user_id"],))
        if v["role_snapshot"] == "transport":
            ex("UPDATE transport_providers SET verified=1 WHERE user_id=?", (v["user_id"],))
        flash("User verified.")
    else:
        ex("UPDATE verifications SET status='rejected', admin_note=?, reviewed_by=? WHERE id=?",
           (request.form.get("reason",""), current_user()["id"], vid))
        ex("UPDATE users SET verification_status='rejected' WHERE id=?", (v["user_id"],))
        flash("Rejected.")
    return redirect("/admin/verifications")


@app.route("/admin/payment/<int:pid>", methods=["POST"])
@admin_required
def admin_payment(pid):
    p = q("SELECT * FROM payments WHERE id=?", (pid,), one=True)
    if not p: abort(404)
    if request.form.get("act") == "approve":
        ex("UPDATE payments SET status='verified', verified_by=?, verified_at=datetime('now') WHERE id=?",
           (current_user()["id"], pid))
        if p["type"] == "listing_fee" and p["listing_id"]:
            d = q("SELECT * FROM listing_durations WHERE id=?", (p["duration_id"],), one=True)
            days = d["days"] if d else 30
            ex("UPDATE listings SET status='pending_review', expires_at=datetime('now', ?) WHERE id=?",
               (f"+{days} days", p["listing_id"]))
        elif p["type"] == "subscription":
            t = q("SELECT * FROM pricing_tiers WHERE id=?", (p["tier_id"],), one=True)
            days = t["duration_days"] if t else 30
            ex("INSERT INTO subscriptions(user_id,tier_id,payment_id,starts_at,ends_at) VALUES(?,?,?,datetime('now'),datetime('now',?))",
               (p["user_id"], p["tier_id"], pid, f"+{days} days"))
        flash("Payment verified.")
    else:
        ex("UPDATE payments SET status='rejected', admin_note=? WHERE id=?",
           (request.form.get("reason",""), pid))
        flash("Rejected.")
    return redirect("/admin/payments")


@app.route("/admin/listing/<int:lid>", methods=["POST"])
@admin_required
def admin_listing(lid):
    if request.form.get("act") == "approve":
        ex("UPDATE listings SET status='active' WHERE id=?", (lid,))
        flash("Live.")
    else:
        ex("UPDATE listings SET status='rejected' WHERE id=?", (lid,))
        flash("Rejected.")
    return redirect("/admin")


@app.route("/admin/report/<int:rid>", methods=["POST"])
@admin_required
def admin_report(rid):
    r = q("SELECT * FROM reports WHERE id=?", (rid,), one=True)
    if not r: abort(404)
    act = request.form.get("act")
    if act == "dismiss":
        ex("UPDATE reports SET status='dismissed', actioned_by=? WHERE id=?", (current_user()["id"], rid))
    elif act == "hide":
        ex("UPDATE reports SET status='actioned', actioned_by=? WHERE id=?", (current_user()["id"], rid))
        ex("UPDATE listings SET status='hidden' WHERE id=?", (r["listing_id"],))
    elif act == "remove":
        ex("UPDATE reports SET status='actioned', actioned_by=? WHERE id=?", (current_user()["id"], rid))
        ex("UPDATE listings SET status='rejected' WHERE id=?", (r["listing_id"],))
    flash("Updated."); return redirect("/admin")


# =============================================================
# BOOT
# =============================================================
if os.environ.get("SECRET_KEY") is None and not app.debug:
    print("[WARN] SECRET_KEY not set in env. Using insecure default. "
          "Set it on Render before going live.")

try:
    init_db()
except Exception as e:
    print(f"[init_db] error: {e}")

if __name__ == "__main__":
    print("\n▶  http://127.0.0.1:5000")
    print("   Admin: admin@accommodationlink.co.zw / Admin@123\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)