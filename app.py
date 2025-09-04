# app.py - EVOSGPT WebCore (Day33)
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
import time
import hmac
import hashlib
import re
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, jsonify, has_request_context
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# Optional: Coinbase Commerce python client (if installed)
try:
    from coinbase_commerce.client import Client as CoinbaseClient
    from coinbase_commerce.webhook import Webhook, SignatureVerificationError
    COINBASE_AVAILABLE = True
except Exception:
    COINBASE_AVAILABLE = False


# ---------- ENVIRONMENT ----------
from dotenv import load_dotenv
load_dotenv()

FLASK_SECRET = os.getenv("FLASK_SECRET", "fallback_secret")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET")
COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
MTN_API_KEY = os.getenv("MTN_API_KEY")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "fallback-secret")

# Security config (set SECURE=True in prod only if HTTPS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(int(os.getenv("SESSION_COOKIE_SECURE", "0"))),  # 1 in prod over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "0"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https://api.commerce.coinbase.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.openai.com https://api.commerce.coinbase.com https://api.paystack.co http://localhost:11434; "
        "frame-ancestors 'none';"
    )
    return resp

# ---------- GLOBAL LOGGER ----------
def log_action(user_id, action, details="N/A"):
    """Logs actions into the activity_log table with optional details"""
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
            (user_id, action, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        # Do not crash the app for logging failures; print for dev visibility
        print(f"[LOGGER ERROR] {e}")


def log_suspicious(activity_type, details="N/A"):
    """Logs suspicious activity into a separate JSONL file"""
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": request.remote_addr if has_request_context() else "unknown",
        "user_agent": str(request.user_agent) if has_request_context() else "unknown",
        "activity": activity_type,
        "details": details
    }
    os.makedirs("logs", exist_ok=True)
    path = os.path.join("logs", "suspicious.jsonl")
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        # best-effort: avoid crashing the request on logging error
        print(f"[SUSPICIOUS LOG ERROR] {e}")


# Only import Postgres driver if needed (guarded)
if os.getenv("DB_MODE") == "postgres" or os.getenv("DB_MODE") == "supabase":
    try:
        import psycopg2  # needed only if using Supabase/Postgres
        from psycopg2 import sql
    except Exception:
        psycopg2 = None


# ---------- small helper for SQLite ALTERs (idempotent) ----------
def safe_alters_sqlite(cursor):
    """
    Run the ALTER TABLE statements you used previously but safely.
    This keeps init_db() simpler and idempotent for SQLite.
    """
    alters = [
        "ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'Basic'",
        "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN referral_code TEXT",
        "ALTER TABLE users ADD COLUMN referrals_used INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN upgrade_expiry DATETIME"
    ]
    for stmt in alters:
        try:
            cursor.execute(stmt)
        except sqlite3.OperationalError:
            # already exists or not applicable — ignore
            pass

    # ensure a unique index for referral_code (idempotent)
    try:
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)")
    except sqlite3.OperationalError:
        pass

    # backfill defaults (if older rows exist)
    try:
        cursor.execute("UPDATE users SET tier = 'Basic' WHERE tier IS NULL")
        cursor.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
        cursor.execute("UPDATE users SET referrals_used = 0 WHERE referrals_used IS NULL")
    except Exception:
        pass


# ---------- DB ADAPTER + INIT ----------
import os, sqlite3, re
try:
    import psycopg2
except ImportError:
    psycopg2 = None

# --- DB Compatibility Layer ---
_real_sqlite_connect = sqlite3.connect

class CompatCursor:
    def __init__(self, cursor, db_mode):
        self.cursor = cursor
        self.db_mode = db_mode

    def execute(self, sql, params=None):
        if self.db_mode in ("supabase", "postgres"):
            # Convert SQLite-style "?" to Postgres-style "%s"
            sql = re.sub(r"\?", "%s", sql)
        return self.cursor.execute(sql, params or ())

    def executemany(self, sql, seq_of_params):
        if self.db_mode in ("supabase", "postgres"):
            sql = re.sub(r"\?", "%s", sql)
        return self.cursor.executemany(sql, seq_of_params)

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class CompatConnection:
    def __init__(self, conn, db_mode):
        self.conn = conn
        self.db_mode = db_mode

    def cursor(self):
        return CompatCursor(self.conn.cursor(), self.db_mode)

    def __getattr__(self, name):
        return getattr(self.conn, name)


def supabase_connect(_=None):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is required for Supabase/Postgres mode")
    conn = psycopg2.connect(os.getenv("SUPABASE_DB_URL"))
    return CompatConnection(conn, "supabase")


# Monkey-patch sqlite3.connect → supabase or real sqlite
if os.getenv("DB_MODE", "sqlite").lower() in ("supabase", "postgres"):
    sqlite3.connect = supabase_connect
else:
    def sqlite_connect_wrapper(path, *args, **kwargs):
        return CompatConnection(_real_sqlite_connect(path, *args, **kwargs), "sqlite")
    sqlite3.connect = sqlite_connect_wrapper


# ---------- DB INIT ----------
def init_db():
    db_mode = os.getenv("DB_MODE", "sqlite").lower()  # "sqlite" or "supabase"/"postgres"

    if db_mode == "sqlite":
        os.makedirs("database", exist_ok=True)
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        # ✅ users table
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password TEXT NOT NULL,
                tier TEXT DEFAULT 'Basic',
                status TEXT DEFAULT 'active',
                referral_code TEXT UNIQUE,
                referrals_used INTEGER DEFAULT 0,
                upgrade_expiry DATETIME,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ✅ chat logs
        c.execute("""
            CREATE TABLE IF NOT EXISTS chat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                message TEXT,
                response TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # ✅ system logs
        c.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # ✅ memory (reset optional)
        if os.getenv("RESET_MEMORY", "true").lower() == "true":
            c.execute("DROP TABLE IF EXISTS memory")
        c.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                user_input TEXT,
                bot_response TEXT,
                system_msg INTEGER DEFAULT 0,
                time_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # ✅ analytics
        c.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tier TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ✅ purchases
        c.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                tier TEXT,
                payment_method TEXT,
                reference TEXT UNIQUE,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # ✅ coupons
        c.execute("""
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY,
                tier TEXT,
                used INTEGER DEFAULT 0
            )
        """)

        # ✅ activity log
        c.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # ✅ seed coupons
        c.execute("SELECT COUNT(*) FROM coupons")
        if c.fetchone()[0] == 0:
            c.executemany("INSERT INTO coupons (code, tier) VALUES (?, ?)", [
                ("FREECORE", "Core"),
                ("KINGME", "King"),
                ("BOOSTPRO", "Pro")
            ])

        conn.commit()
        conn.close()

    elif db_mode in ("supabase", "postgres"):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for Postgres/Supabase mode but not installed.")
        conn = psycopg2.connect(os.getenv("SUPABASE_DB_URL"))
        cur = conn.cursor()

        # ✅ users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password TEXT NOT NULL,
            tier TEXT DEFAULT 'Basic',
            status TEXT DEFAULT 'active',
            referral_code TEXT UNIQUE,
            referrals_used INTEGER DEFAULT 0,
            upgrade_expiry TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ chat logs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            message TEXT,
            response TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ system logs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ memory
        cur.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            user_input TEXT,
            bot_response TEXT,
            system_msg INTEGER DEFAULT 0,
            time_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ analytics
        cur.execute("""
        CREATE TABLE IF NOT EXISTS analytics (
            id SERIAL PRIMARY KEY,
            tier TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ purchases
        cur.execute("""
        CREATE TABLE IF NOT EXISTS purchases (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            tier TEXT,
            payment_method TEXT,
            reference TEXT UNIQUE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ coupons
        cur.execute("""
        CREATE TABLE IF NOT EXISTS coupons (
            code TEXT PRIMARY KEY,
            tier TEXT,
            used INTEGER DEFAULT 0
        )
        """)

        # ✅ activity log
        cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_log (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # ✅ seed coupons
        cur.execute("SELECT COUNT(*) FROM coupons")
        if cur.fetchone()[0] == 0:
            cur.executemany("INSERT INTO coupons (code, tier) VALUES (%s, %s)", [
                ("FREECORE", "Core"),
                ("KINGME", "King"),
                ("BOOSTPRO", "Pro")
            ])

        conn.commit()
        cur.close()
        conn.close()


# helper for SQLite alters (safe + idempotent)
def safe_alters_sqlite(c):
    alters = [
        "ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'Basic'",
        "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'",
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN referral_code TEXT",
        "ALTER TABLE users ADD COLUMN referrals_used INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN upgrade_expiry DATETIME",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)"
    ]
    for stmt in alters:
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # backfills
    try:
        c.execute("UPDATE users SET tier = 'Basic' WHERE tier IS NULL")
        c.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
        c.execute("UPDATE users SET referrals_used = 0 WHERE referrals_used IS NULL")
    except Exception:
        pass


    # backfills
    try:
        c.execute("UPDATE users SET tier = 'Basic' WHERE tier IS NULL")
        c.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
        c.execute("UPDATE users SET referrals_used = 0 WHERE referrals_used IS NULL")
    except Exception:
        pass



def enforce_memory_limit(user_id, tier):
    """Trim per-user memory entries based on tier limits (safe, idempotent)."""
    conn = None
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM memory WHERE user_id = ?", (user_id,))
        row = c.fetchone()
        total = row[0] if row else 0

        if tier == "Basic":
            limit = 30
        elif tier == "Core":
            limit = 100
        else:
            return

        if total > limit:
            to_delete = total - limit
            c.execute("""
                DELETE FROM memory 
                WHERE id IN (
                    SELECT id FROM memory WHERE user_id = ? ORDER BY id ASC LIMIT ?
                )
            """, (user_id, to_delete))
            conn.commit()
    except Exception as e:
        # don't raise; just log suspicious for debug
        try:
            log_suspicious("EnforceMemoryError", str(e))
        except Exception:
            pass
    finally:
        if conn:
            conn.close()


# ---------- AI HELPERS ----------
def local_llm(prompt: str) -> str:
    return f"[Local LLM] You said: {prompt}"


def _openai_chat(prompt: str, model: str) -> Optional[str]:
    try:
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post("https://api.openai.com/v1/chat/completions",
                             headers=headers, json=data, timeout=20)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return None
    except Exception as e:
        # safe logging but avoid exposing secret info
        try:
            log_suspicious("OpenAIRequestError", str(e)[:300])
        except Exception:
            pass
        return None


def gpt4o_mini(prompt: str) -> str:
    return _openai_chat(prompt, "gpt-4o-mini") or f"[Mini-Fallback] {prompt}"


def gpt4o(prompt: str) -> str:
    return _openai_chat(prompt, "gpt-4o") or f"[4o-Fallback] {prompt}"


# ---------------- ROUTES CONTINUE (chat, login, register, etc) ----------------
# (keep all your existing routes unchanged here)


# ---------- Basic firewall & rate limiting ----------
failed_logins = {}
blocked_ips = {}
last_message_time = {}

@app.before_request
def basic_firewall():
    # defensive: some requests (static) may not have endpoint set
    endpoint = request.endpoint or ""
    ip = request.remote_addr or "unknown"
    uid = session.get("user_id", f"ip:{ip}")  # fallback to IP if not logged in

    # temporary block window (per IP)
    if ip in blocked_ips and time.time() - blocked_ips[ip] < 300:
        try:
            log_suspicious("Blocked IP", f"Temporary blocked IP {ip}")
        except Exception:
            pass
        return redirect(url_for("index"))

    # Only scan POSTs on risky endpoints (use explicit list)
    risky_endpoints = {"login", "register", "index", "upgrade", "paystack_init", "create_crypto_charge", "paystack_upgrade", "webhook_paystack", "webhook_coinbase"}
    if request.method == "POST" and (endpoint in risky_endpoints or endpoint.endswith(".post") if isinstance(endpoint, str) else False):
        post_data = request.get_data().decode(errors="ignore") if request.get_data() else ""
        query_data = " ".join(request.args.values()) if request.args else ""
        bad_patterns = ["drop table", "union select", "--", ";--", "' or '1'='1"]
        lowered = post_data.lower() + " " + query_data.lower()
        for p in bad_patterns:
            if p in lowered:
                try:
                    log_suspicious("SQL Injection Attempt", (post_data or query_data)[:500])
                except Exception:
                    pass
                return redirect(url_for("index"))
        # XSS
        if re.search(r"<script.*?>", post_data, re.IGNORECASE):
            try:
                log_suspicious("XSS Attempt", post_data[:500])
            except Exception:
                pass
            return redirect(url_for("index"))

    # ✅ Rate limit chat messages to 2s per user (or IP if guest)
    # only apply to index POST (chat submit) to avoid interfering with webhooks
    if endpoint == "index" and request.method == "POST":
        now = time.time()
        last = last_message_time.get(uid)
        if last and (now - last) < 2:
            try:
                log_suspicious("Rate Limit", f"Too many messages from {uid}")
            except Exception:
                pass
            flash("You're sending messages too fast! Slow down.")
            return redirect(url_for("index"))
        last_message_time[uid] = now


#................ stealth self test ....................
@app.before_request
def stealth_selftest():
    # heartbeat log every ~10 minutes (non-blocking)
    try:
        if int(time.time()) % 600 < 2:
            log_suspicious("StealthTest", "DarkEvo logger heartbeat check")
    except Exception:
        pass


# ---------- helper: idempotent purchase mark ----------
def mark_purchase_if_not_exists(user_id, tier, method, reference=None):
    conn = None
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        if reference:
            c.execute("SELECT COUNT(*) FROM purchases WHERE reference = ?", (reference,))
            if c.fetchone()[0] > 0:
                return False
        # insert
        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                  (user_id, tier, method, reference))
        c.execute("INSERT INTO analytics (tier) VALUES (?)", (tier,))
        conn.commit()
        return True
    except Exception as e:
        try:
            log_suspicious("MarkPurchaseError", str(e))
        except Exception:
            pass
        return False
    finally:
        if conn:
            conn.close()


# --- new helper function ---
def update_user_tier(user_id, new_tier):
    conn = None
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, user_id))
        conn.commit()
    except Exception as e:
        try:
            log_suspicious("UpdateTierError", str(e))
        except Exception:
            pass
    finally:
        if conn:
            conn.close()


def update_user_status(user_id, new_status):
    conn = None
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
    except Exception as e:
        try:
            log_suspicious("UpdateStatusError", str(e))
        except Exception:
            pass
    finally:
        if conn:
            conn.close()

# ---------- HOME / CHAT ----------
@app.route("/", methods=["GET", "POST"])
def index():
    # Guests → default Basic tier
    if "user_id" not in session and "tier" not in session:
        session["tier"] = "Basic"

    tier = session.get("tier", "Basic")
    tier_icon = {"Basic": "🧊", "Core": "⚛", "Pro": "⚡", "King": "👑", "Founder": "🔑"}.get(tier, "")
    show_memory = tier in ["Core", "Pro", "King", "Founder"]
    show_analytics = tier in ["Pro", "King", "Founder"]
    show_admin = tier in ["King", "Founder"]

    # --- Manual tier change (dropdown upgrade) ---
    if request.method == "POST" and "tier" in request.form and "user_id" in session:
        selected_tier = request.form.get("tier")
        session["tier"] = selected_tier
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("INSERT INTO analytics (tier) VALUES (?)", (selected_tier,))
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    # --- Show chat history & notices ---
    chat_history, system_notices = [], []
    if show_memory and session.get("user_id"):
        try:
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            uid_param = session["user_id"]

            # User chat history (last 10)
            c.execute("""
                SELECT user_input, bot_response
                FROM memory
                WHERE system_msg = 0 AND user_id = ?
                ORDER BY id DESC
                LIMIT 10
            """, (uid_param,))
            chat_history = c.fetchall()

            # System notices
            c.execute("""
                SELECT bot_response, time_added
                FROM memory
                WHERE system_msg = 1 AND user_id = ?
                ORDER BY id DESC
                LIMIT 5
            """, (uid_param,))
            system_notices = c.fetchall()
        except Exception as e:
            log_suspicious("HistoryFetchError", str(e))
        finally:
            conn.close()

    return render_template(
        "index.html",
        chat_history=chat_history,
        system_notices=system_notices,
        tier=tier,
        icon=tier_icon,
        show_memory=show_memory,
        show_analytics=show_analytics,
        show_admin=show_admin,
        logged_in=("user_id" in session)
    )


# ---------- CHAT (API ONLY) ----------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    user_msg = (data.get("message") or "").strip()
    ui = user_msg.lower()

    tier = session.get("tier", "Basic")
    reply = None

    # --- Founder unlock sequence (chat phrase path) ---
    if "user_id" in session:
        seq = session.get("founder_seq", 0)
        if seq == 0 and ui == "evosgpt where you created":
            reply = "lab"
            session["founder_seq"] = 1
        elif seq == 1 and ui == "ghanaherewecome":
            reply = "are you coming to Ghana?"
            session["founder_seq"] = 2
        elif seq == 2 and ui == "nameless":
            reply = "[SYSTEM] Founder tier unlocked. Welcome, hidden user."
            session["founder_seq"] = 0
            session["tier"] = "Founder"
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("UPDATE users SET tier = ? WHERE id = ?", ("Founder", session["user_id"]))
                conn.commit()
            except Exception as e:
                log_suspicious("FounderUnlockFail", str(e))
            finally:
                conn.close()
            log_action(session["user_id"], "Founder Unlock", "Secret phrase sequence completed")
        else:
            if seq > 0 and ui not in ["evosgpt where you created", "ghanaherewecome", "nameless"]:
                session["founder_seq"] = 0  # reset if wrong message

    # --- Tier-based replies ---
    if reply is None:
        try:
            if tier == "Basic":
                reply = local_llm(user_msg)
            elif tier == "Core":
                reply = local_llm(user_msg) if len(user_msg) < 50 else gpt4o_mini(user_msg)
            elif tier in ["Pro", "King"]:
                reply = gpt4o_mini(user_msg)
            elif tier == "Founder":
                reply = gpt4o(user_msg)
            else:
                reply = f"I heard you say: {user_msg}"
        except Exception as e:
            log_suspicious("LLMError", str(e))
            reply = f"(fallback) I heard: {user_msg}"

    # --- Save chat ---
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        uid_param = session.get("user_id")
        c.execute(
            "INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, 0)",
            (uid_param, user_msg, reply)
        )
        conn.commit()

        if session.get("user_id"):
            c.execute("INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
                      (session["user_id"], "chat", f"User: {user_msg} | Bot: {reply}"))
            conn.commit()
            enforce_memory_limit(session["user_id"], tier)

    except Exception as e:
        log_suspicious("ChatInsertFail", str(e))
    finally:
        conn.close()

    return jsonify({"reply": reply})



# ---------- FOUNDER DIRECT LOGIN ----------
@app.route("/founder-login", methods=["GET", "POST"])
def founder_login():
    if request.method == "POST":
        key = request.form.get("founder_key", "").strip()
        founder_key = os.getenv("FOUNDER_KEY", "default-secret")

        if hmac.compare_digest(key, founder_key):
            session["tier"] = "Founder"
            session["username"] = "Founder"
            session["user_id"] = -999  # ghost ID (not in DB)
            flash("🔑 Founder access granted.")
            return redirect(url_for("index"))
        else:
            flash("Invalid Founder key.")
            return redirect(url_for("founder_login"))

    # Minimal hidden HTML
    return """
    <h2>Founder Access</h2>
    <form method="POST">
        <input type="password" name="founder_key" placeholder="Enter Founder Key" required>
        <button type="submit">Unlock</button>
    </form>
    """


# ---------- CLEAR MEMORY ----------
@app.route("/clear")
def clear_memory():
    if "user_id" not in session:
        flash("⚠️ Please log in to clear memory.")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    tier = session.get("tier", "Basic")

    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        if tier == "Founder":
            c.execute("DELETE FROM memory WHERE system_msg = 0")
            flash("🜲 Founder override: All user memory cleared! (System logs preserved)")
        else:
            c.execute("DELETE FROM memory WHERE user_id = ? AND system_msg = 0", (user_id,))
            flash("✅ Your memory cleared! (System logs preserved)")

        conn.commit()
    except Exception as e:
        log_suspicious("ClearMemoryFail", str(e))
        flash("⚠️ Error clearing memory.")
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return redirect(url_for("index"))



    # ---------- BEFORE REQUEST HOOKS ----------
    @app.before_request
    def refresh_user_session():
        """Refresh tier + enforce suspension before each request"""
        if "user_id" in session:
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("SELECT tier, status, upgrade_expiry FROM users WHERE id = ?", (session["user_id"],))
                row = c.fetchone()
            except Exception as e:
                log_suspicious("SessionRefreshFail", str(e))
                row = None
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if row:
                tier, status, expiry = row
                session["tier"] = tier
                if status != "active":
                    flash("Your account is suspended. Contact support.")
                    session.clear()
                    return redirect(url_for("login"))

    @app.before_request
    def check_expiry():
        """Downgrade expired users automatically"""
        if "user_id" in session:
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("SELECT tier, upgrade_expiry FROM users WHERE id = ?", (session["user_id"],))
                row = c.fetchone()
                if row and row[1]:
                    try:
                        expiry = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                        if datetime.now() > expiry:
                            c.execute("UPDATE users SET tier = 'Basic', upgrade_expiry = NULL WHERE id = ?",
                                      (session["user_id"],))
                            conn.commit()
                            session["tier"] = "Basic"
                            flash("Your upgrade expired. Downgraded to Basic.")
                    except Exception as e:
                        log_suspicious("ExpiryCheckFail", str(e))
            except Exception as e:
                log_suspicious("ExpiryFetchFail", str(e))
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    @app.before_request
    def firewall_check():
        """Block suspicious IPs / user-agents (stub for now)"""
        blocked = ["sqlmap", "curl"]
        if has_request_context():
            try:
                ua = str(request.user_agent).lower()
                if any(b in ua for b in blocked):
                    log_suspicious("Blocked UA", ua)
                    abort(403)
            except Exception as e:
                log_suspicious("FirewallFail", str(e))

    @app.before_request
    def stealth_founder_protection():
        """Pretend nothing exists if probing Founder unlock"""
        if request.endpoint == "chat" and "founder_seq" in session:
            pass  # silently ignored

    # ---------- COUPON REDEEM ----------
    @app.route("/redeem", methods=["GET", "POST"])
    def redeem():
        msg = None
        if request.method == "POST":
            code = request.form.get("code", "").strip().upper()
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("SELECT tier, used FROM coupons WHERE code = ?", (code,))
                coupon = c.fetchone()

                if not coupon:
                    msg = "❌ Invalid coupon code."
                    if "user_id" in session:
                        log_action(session["user_id"], "Coupon Attempt", f"Invalid code: {code}")
                elif coupon[1] == 1:
                    msg = "⚠️ This coupon has already been used."
                    if "user_id" in session:
                        log_action(session["user_id"], "Coupon Attempt", f"Already used: {code}")
                else:
                    new_tier = coupon[0]
                    c.execute("UPDATE coupons SET used = 1 WHERE code = ?", (code,))
                    if "user_id" in session:
                        c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, session["user_id"]))
                        session["tier"] = new_tier
                        log_action(session["user_id"], "Coupon Redeemed", f"Code: {code}, New Tier: {new_tier}")
                    msg = f"✅ Successfully upgraded to {new_tier}!"
                    conn.commit()
            except Exception as e:
                log_suspicious("RedeemFail", str(e))
                msg = "❌ An error occurred."
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
                    return render_template("redeem.html", msg=msg)


# ---------- ADMIN DASHBOARD ----------
@app.route("/admin")
def admin():
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    # Only King & Founder tiers can access
    if session.get("tier") not in ["King", "Founder"]:
        flash("🚫 Access denied. Admins only.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    # Fetch stats
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM chat_logs")
    total_chats = c.fetchone()[0]

    c.execute("SELECT username, tier, status, created_at FROM users ORDER BY created_at DESC LIMIT 20")
    recent_users = c.fetchall()

    c.execute("SELECT action, details, timestamp FROM system_logs ORDER BY timestamp DESC LIMIT 20")
    logs = c.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_chats=total_chats,
        recent_users=recent_users,
        logs=logs
    )

# ---------- ADMIN STATS SUMMARY ----------
@app.route("/admin/summary")
def admin_summary():
    if session.get("tier") != "Founder":
        flash("⛔ Unauthorized access.")
        return redirect(url_for("index"))

    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM memory")
        total_memory = c.fetchone()[0]

        c.execute("SELECT user_input, bot_response FROM memory ORDER BY id DESC LIMIT 5")
        recent_memory = c.fetchall()
    finally:
        conn.close()

    return render_template("admin_summary.html", total_memory=total_memory, recent_memory=recent_memory)


# ---------- ADMIN COUPONS ----------
@app.route("/admin/coupons", methods=["GET", "POST"])
def admin_coupons():
    if session.get("tier") != "Founder":
        flash("⛔ Only Founder-tier can access the coupon panel.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        code = request.form.get("code")
        tier = request.form.get("tier")
        if code and tier:
            try:
                c.execute("INSERT INTO coupons (code, tier, used) VALUES (?, ?, 0)", (code, tier))
                conn.commit()
                flash(f"✅ Coupon '{code}' for {tier} created!")
            except sqlite3.IntegrityError:
                flash("⚠️ Coupon already exists.")

    c.execute("SELECT code, tier, used FROM coupons ORDER BY tier")
    coupons = c.fetchall()
    conn.close()

    return render_template("admin_coupons.html", coupons=coupons)


@app.route("/admin/coupons/delete/<code>")
def delete_coupon(code):
    if session.get("tier") != "Founder":
        flash("⛔ Unauthorized.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("DELETE FROM coupons WHERE code = ?", (code,))
    conn.commit()
    conn.close()

    flash(f"🗑️ Coupon '{code}' deleted.")
    return redirect(url_for("admin_coupons"))


# --- Admin: Manage Users ---
@app.route("/admin/users")
def admin_users():
    if session.get("tier") != "Founder":
        flash("Only Founder-tier can access user management.")
        return redirect(url_for("index"))
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("SELECT id, username, tier, status FROM users ORDER BY id ASC")
    users = c.fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/user/<int:user_id>/suspend")
def admin_suspend_user(user_id):
    if session.get("tier") != "Founder":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    if user_id == session["user_id"]:
        flash("You cannot suspend yourself.")
        return redirect(url_for("admin_users"))
    update_user_status(user_id, "suspended")
    flash(f"User {user_id} suspended.")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/restore")
def admin_restore_user(user_id):
    if session.get("tier") != "Founder":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    update_user_status(user_id, "active")
    flash(f"User {user_id} restored.")
    return redirect(url_for("admin_users"))


@app.route("/admin/user/<int:user_id>/tier/<new_tier>")
def admin_change_tier(user_id, new_tier):
    if session.get("tier") != "Founder":
        flash("Unauthorized.")
        return redirect(url_for("index"))
    if user_id == session["user_id"]:
        flash("You cannot change your own tier here.")
        return redirect(url_for("admin_users"))
    valid_tiers = ["Basic", "Core", "Pro", "King", "Founder"]
    if new_tier not in valid_tiers:
        flash("Invalid tier.")
        return redirect(url_for("admin_users"))
    update_user_tier(user_id, new_tier)
    flash(f"User {user_id} tier changed to {new_tier}.")
    return redirect(url_for("admin_users"))


# ---------- ACTIVITY LOG VIEWER ----------
@app.route("/activity-log")
def activity_log():
    if session.get("tier") != "Founder":
        flash("Access denied.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("""
        SELECT users.username, activity_log.action, activity_log.details, activity_log.timestamp
        FROM activity_log
        JOIN users ON activity_log.user_id = users.id
        ORDER BY activity_log.id DESC LIMIT 50
    """)
    logs = c.fetchall()
    conn.close()

    return render_template("activity_log.html", logs=logs)


# ---------- Admin: Insert System Messages ----------
@app.route("/admin/system-message", methods=["GET", "POST"])
def admin_system_message():
    if session.get("tier") != "Founder":
        flash("Unauthorized.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        message = request.form.get("message")
        if message:
            c.execute("INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, ?)",
                      (session["user_id"], "[SYSTEM]", message, 1))
            conn.commit()
            flash("System message added to memory.")

    # Show recent system messages
    c.execute("SELECT id, bot_response, time_added FROM memory WHERE system_msg = 1 ORDER BY id DESC LIMIT 10")
    system_messages = c.fetchall()

    conn.close()
    return render_template("admin_system_message.html", system_messages=system_messages)


# ---------- Analytics ----------
@app.route("/analytics")
def analytics_dashboard():
    if session.get("tier") != "Founder":
        flash("Unauthorized access.")
        return redirect(url_for("index"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    # Count tiers (like before)
    c.execute("SELECT tier, COUNT(*) FROM analytics GROUP BY tier")
    tier_counts = c.fetchall()

    # Count system vs. user messages
    c.execute("SELECT COUNT(*) FROM memory WHERE system_msg = 1")
    system_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM memory WHERE system_msg = 0 OR system_msg IS NULL")
    user_count = c.fetchone()[0]

    # Recent analytics logs
    c.execute("SELECT tier, timestamp FROM analytics ORDER BY timestamp DESC LIMIT 10")
    recent_logs = c.fetchall()

    # Recent system messages
    c.execute("SELECT bot_response, time_added FROM memory WHERE system_msg = 1 ORDER BY id DESC LIMIT 5")
    system_messages = c.fetchall()

    conn.close()

    return render_template("analytics.html",
                           tier_counts=tier_counts,
                           system_count=system_count,
                           user_count=user_count,
                           recent_logs=recent_logs,
                           system_messages=system_messages)

# ---------- AUTH ROUTES ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT id, password, tier, status FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[1], password):
            if row[3] != "active":
                flash("⚠️ Your account is suspended.")
                return render_template("login.html")

            # ✅ set full session data
            session["user_id"] = row[0]
            session["username"] = username
            session["tier"] = row[2]

            log_action(row[0], "login", f"User {username} logged in")
            return redirect(url_for("index"))
        else:
            flash("❌ Invalid username or password.")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        password = request.form["password"]

        if not username or not password:
            return render_template("register.html", msg="Username and password required.")

        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_pw))
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            return render_template("register.html", msg="Username already exists.")
        except Exception as e:
            return render_template("register.html", msg=f"Error: {e}")

    return render_template("register.html")



@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "logout", f"User {session.get('username','')} logged out")
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

# ---------- UPGRADE ROUTE ----------
@app.route("/upgrade", methods=["GET", "POST"])
def upgrade():
    if "user_id" not in session:
        flash("⚠️ You must be logged in to upgrade.")
        return redirect(url_for("login"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        user_id = session["user_id"]
        tier = request.form.get("tier")
        payment_method = request.form.get("payment_method")
        coupon = request.form.get("coupon", "").strip().upper()

        # ✅ Handle coupon first
        if coupon:
            c.execute("SELECT tier, used FROM coupons WHERE code = ?", (coupon,))
            row = c.fetchone()
            if row and row[1] == 0:
                new_tier = row[0]
                c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, user_id))
                c.execute("UPDATE coupons SET used = 1 WHERE code = ?", (coupon,))
                conn.commit()
                log_action(user_id, "upgrade", f"Coupon applied: {coupon} → {new_tier}")
                flash(f"🎉 Success! Coupon applied. You are now {new_tier} tier.")
                conn.close()
                return redirect(url_for("index"))
            else:
                flash("⚠️ Invalid or already used coupon.")
                conn.close()
                return redirect(url_for("upgrade"))

        # ✅ Handle normal upgrade
        if tier in ["Core", "Pro", "King", "Founder"]:
            ref = f"EVOS-{user_id}-{int(time.time())}"
            c.execute("""
                INSERT INTO purchases (user_id, tier, payment_method, reference)
                VALUES (?, ?, ?, ?)
            """, (user_id, tier, payment_method, ref))
            c.execute("UPDATE users SET tier = ? WHERE id = ?", (tier, user_id))
            conn.commit()
            log_action(user_id, "upgrade", f"Upgraded to {tier} via {payment_method}")
            flash(f"✅ Upgrade successful! You are now on {tier} tier.")
            conn.close()
            return redirect(url_for("index"))

        flash("⚠️ Invalid tier selected.")
        conn.close()

    # ✅ Display available tiers
    return render_template("upgrade.html", tiers=["Core", "Pro", "King", "Founder"])


# ---------- PAYMENTS & WEBHOOKS (HARDENED) ----------
from hmac import compare_digest

# Prices (source of truth)
TIER_PRICE_USD = {"Core": 1, "Pro": 5, "King": 9}
VALID_TIERS = set(TIER_PRICE_USD.keys())

def _safe_parse_json(raw: bytes):
    try:
        return json.loads(raw)
    except Exception:
        return None

def _purchases_ref_exists(reference: str) -> bool:
    if not reference:
        return False
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute("SELECT 1 FROM purchases WHERE reference = ? LIMIT 1", (reference,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def _upgrade_user(user_id: int, tier: str, days: int = 30):
    expiry = datetime.utcnow() + timedelta(days=days)
    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()
    c.execute(
        "UPDATE users SET tier = ?, upgrade_expiry = ? WHERE id = ?",
        (tier, expiry.strftime("%Y-%m-%d %H:%M:%S"), user_id)
    )
    conn.commit()
    conn.close()

# --- PAYSTACK: verify signature + idempotent insert ---
@app.route("/webhook/paystack", methods=["POST"])
def webhook_paystack():
    raw = request.get_data() or b""
    sent_sig = request.headers.get("X-Paystack-Signature", "")
    secret = os.getenv("PAYSTACK_WEBHOOK_SECRET", "")

    # Signature check (sha512) - only if secret present
    if not sent_sig or not secret:
        log_suspicious("PaystackWebhookMissingSigOrSecret", sent_sig or "no-sig")
        return jsonify({"status": "invalid-signature"}), 400

    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not compare_digest(sent_sig, expected):
        log_suspicious("PaystackWebhookInvalidSig", sent_sig[:64])
        return jsonify({"status": "invalid-signature"}), 400

    payload = _safe_parse_json(raw)
    if not payload:
        log_suspicious("PaystackWebhookBadJSON", raw[:256].decode(errors="ignore"))
        return jsonify({"status": "bad-json"}), 400

    # Only process successful charge events
    if payload.get("event") != "charge.success":
        return jsonify({"status": "ignored"}), 200

    data = payload.get("data", {}) or {}
    reference = data.get("reference") or ""
    meta = data.get("metadata") or {}

    # Extract user_id safely (metadata may store it as str)
    user_id_raw = meta.get("user_id")
    try:
        user_id = int(user_id_raw) if user_id_raw is not None else None
    except Exception:
        user_id = None

    tier = meta.get("tier", "Core")

    # Validate inputs
    if not isinstance(user_id, int) or tier not in VALID_TIERS:
        log_suspicious("PaystackWebhookBadMeta", str(meta))
        return jsonify({"status": "bad-metadata"}), 400

    # Idempotency guard
    if _purchases_ref_exists(reference):
        return jsonify({"status": "ok"}), 200

    # Persist purchase + upgrade user
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
            (user_id, tier, "Paystack", reference)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_suspicious("PaystackWebhookDBError", str(e))
        return jsonify({"status": "db-error"}), 500

    _upgrade_user(user_id, tier, days=30)
    log_action(user_id, "upgrade", f"Upgraded via Paystack → {tier}")
    return jsonify({"status": "ok"}), 200


# --- COINBASE: verify signature + idempotent insert ---
@app.route("/webhook/coinbase", methods=["POST"])
def webhook_coinbase():
    sig = request.headers.get("X-CC-Webhook-Signature", "")
    secret = os.getenv("COINBASE_WEBHOOK_SECRET", "")
    raw = request.get_data() or b""

    if not sig or not secret:
        log_suspicious("CoinbaseWebhookMissingSigOrSecret", "missing header or secret")
        return jsonify({"status": "invalid"}), 400

    # Coinbase webhook signature is HMAC-SHA256 (hex)
    mac = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not compare_digest(sig, mac):
        log_suspicious("CoinbaseWebhookInvalidSig", sig[:64])
        return jsonify({"status": "invalid-signature"}), 400

    payload = _safe_parse_json(raw)
    if not payload:
        log_suspicious("CoinbaseWebhookBadJSON", raw[:256].decode(errors="ignore"))
        return jsonify({"status": "bad-json"}), 400

    event = payload.get("event", {}) or {}
    event_type = event.get("type", "")

    # Accept confirmed/resolved charges only
    if event_type not in {"charge:confirmed", "charge:resolved"}:
        return jsonify({"status": "ignored"}), 200

    data = event.get("data", {}) or {}
    meta = data.get("metadata", {}) or {}
    reference = data.get("code") or ""

    # Extract user_id safely
    user_id_raw = meta.get("user_id")
    try:
        user_id = int(user_id_raw) if user_id_raw is not None else None
    except Exception:
        user_id = None

    tier = meta.get("tier", "Pro")

    if not isinstance(user_id, int) or tier not in VALID_TIERS:
        log_suspicious("CoinbaseWebhookBadMeta", str(meta))
        return jsonify({"status": "bad-metadata"}), 400

    # Idempotency guard
    if _purchases_ref_exists(reference):
        return jsonify({"status": "ok"}), 200

    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
            (user_id, tier, "Coinbase", reference)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_suspicious("CoinbaseWebhookDBError", str(e))
        return jsonify({"status": "db-error"}), 500

    _upgrade_user(user_id, tier, days=30)
    log_action(user_id, "upgrade", f"Upgraded via Coinbase → {tier}")
    return jsonify({"status": "ok"}), 200

@app.errorhandler(404)
def not_found_error(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


@app.route("/db-check")
def db_check():
    try:
        db_mode = os.getenv("DB_MODE", "sqlite").lower()
        if db_mode == "sqlite":
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in c.fetchall()]
            conn.close()
            return {"status": "ok", "db": "sqlite", "tables": tables}
        elif db_mode in ("supabase", "postgres"):
            conn = psycopg2.connect(os.getenv("SUPABASE_DB_URL"))
            cur = conn.cursor()
            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
            tables = [row[0] for row in cur.fetchall()]
            cur.close()
            conn.close()
            return {"status": "ok", "db": "postgres", "tables": tables}
        else:
            return {"status": "error", "msg": "Unknown DB mode"}
    except Exception as e:
        return {"status": "error", "msg": str(e)}



# ---------- Run app ----------
if __name__ == "__main__":
    # Initialize DB (safe to call repeatedly)
    init_db()
    # Do not run in debug on production. Use env var PORT or default 5000.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)


