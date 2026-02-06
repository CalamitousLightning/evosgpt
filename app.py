## app.py - EVOSGPT WebCore (Day33)
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Optional
import time
import hmac
import threading
import time
import random
from uuid import uuid4
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

import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()  # load your .env file

url = os.getenv("SUPABASE_DB_URL")

try:
    conn = psycopg2.connect(url)
    cur = conn.cursor()
    cur.execute("SELECT NOW();")
    print("✅ Connected! Current time:", cur.fetchone())
    cur.close()
    conn.close()
except Exception as e:
    print("❌ Connection failed:", e)



# ---------- ENVIRONMENT ----------
from dotenv import load_dotenv
load_dotenv()

FLASK_SECRET = os.getenv("FLASK_SECRET", "fallback_secret")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET")
COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
MTN_API_KEY = os.getenv("MTN_API_KEY")

app = Flask(__name__)
from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "*"}}) 

app.secret_key = os.getenv("FLASK_SECRET", "fallback-secret")

# Security config (set SECURE=True in prod only if HTTPS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(int(os.getenv("SESSION_COOKIE_SECURE", "0"))),  # 1 in prod over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


# ---------- EVOSGPT DB INIT — Self-Healing + Supabase Sync Layer ----------
import os, sqlite3, re, json, requests
from datetime import datetime
from flask import request, has_request_context

# ---------- GLOBAL CONFIG ----------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "")
DB_MODE = os.getenv("DB_MODE", "sqlite").lower()

# ---------- GLOBAL LOGGER ----------
def log_action(user_id, action, details="N/A"):
    """Logs actions into the activity_log table (local + Supabase mirror)"""
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
        print(f"[LOGGER ERROR] {e}")

    # Supabase mirror
    if DB_MODE in ("supabase", "postgres") and SUPABASE_URL and SUPABASE_KEY:
        try:
            requests.post(
                f"{SUPABASE_URL}/rest/v1/activity_log",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}",
                    "Content-Type": "application/json",
                },
                data=json.dumps({
                    "user_id": user_id,
                    "action": action,
                    "details": details,
                }),
                timeout=5
            )
        except Exception as e:
            print(f"[REMOTE LOG FAIL] {e}")


def log_suspicious(activity_type, details="N/A"):
    """Logs suspicious or system anomalies"""
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": request.remote_addr if has_request_context() else "unknown",
        "user_agent": str(request.user_agent) if has_request_context() else "unknown",
        "activity": activity_type,
        "details": details
    }
    os.makedirs("logs", exist_ok=True)
    try:
        with open("logs/suspicious.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[SUSPICIOUS LOG ERROR] {e}")

# ---------- EVOSGPT DB INIT (Stable Hybrid Edition) ----------
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
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return CompatConnection(_real_sqlite_connect(path, *args, **kwargs), "sqlite")
    sqlite3.connect = sqlite_connect_wrapper


# ---------- MAIN INIT ----------
def init_db():
    db_mode = os.getenv("DB_MODE", "sqlite").lower()
    print(f"🧠 Initializing EVOSGPT DB ({db_mode.upper()})")

    if db_mode == "sqlite":
        os.makedirs("database", exist_ok=True)
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        # ✅ USERS
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

        # ✅ GUESTS
        c.execute("""
            CREATE TABLE IF NOT EXISTS guests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ✅ CHAT LOGS
        c.execute("""
            CREATE TABLE IF NOT EXISTS chat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guest_id INTEGER,
                message TEXT,
                response TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (guest_id) REFERENCES guests(id)
            )
        """)

        # ✅ SYSTEM LOGS
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

        # ✅ MEMORY (keep old schema for compatibility)
        c.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guest_id INTEGER,
                user_input TEXT,
                bot_response TEXT,
                system_msg INTEGER DEFAULT 0,
                time_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(guest_id) REFERENCES guests(id)
            )
        """)

        # ✅ LONG MEMORY (for summaries/personal context)
        c.execute("""
            CREATE TABLE IF NOT EXISTS long_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                summary TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # ✅ GLOBAL MEMORY (shared contextual intelligence)
        c.execute("""
            CREATE TABLE IF NOT EXISTS global_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT,
                importance REAL DEFAULT 0.5,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ✅ ANALYTICS
        c.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tier TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ✅ PURCHASES
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

        # ✅ COUPONS
        c.execute("""
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY,
                tier TEXT,
                used INTEGER DEFAULT 0
            )
        """)

        # ✅ ACTIVITY LOG
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

        # ✅ SEED COUPONS
        c.execute("SELECT COUNT(*) FROM coupons")
        if c.fetchone()[0] == 0:
            c.executemany("INSERT INTO coupons (code, tier) VALUES (?, ?)", [
                ("FREECORE", "Core"),
                ("KINGME", "King"),
                ("BOOSTPRO", "Pro")
            ])

        conn.commit()
        conn.close()
        print("✅ SQLite DB initialized successfully (Extended Memory Enabled).")

    elif db_mode in ("supabase", "postgres"):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is required for Supabase/Postgres mode but not installed.")
        conn = psycopg2.connect(os.getenv("SUPABASE_DB_URL"))
        cur = conn.cursor()

        # Create same tables for Postgres/Supabase
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password TEXT NOT NULL,
                tier TEXT DEFAULT 'Basic',
                status TEXT DEFAULT 'active',
                referral_code TEXT UNIQUE,
                referrals_used INTEGER DEFAULT 0,
                upgrade_expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS guests (
                id SERIAL PRIMARY KEY,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                guest_id INTEGER REFERENCES guests(id),
                user_input TEXT,
                bot_response TEXT,
                system_msg INTEGER DEFAULT 0,
                time_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS long_memory (
                id SERIAL PRIMARY KEY,
                user_id INTEGER UNIQUE REFERENCES users(id),
                summary TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS global_memory (
                id SERIAL PRIMARY KEY,
                content TEXT,
                importance REAL DEFAULT 0.5,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("✅ Supabase/Postgres DB initialized (Extended Memory Enabled).")


# ---------- SAFE ALTER (LOCAL EVOLUTION) ----------
def safe_alters_sqlite(cursor):
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
            pass
    try:
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)")
    except sqlite3.OperationalError:
        pass


    try:
        cursor.execute("UPDATE users SET tier = 'Basic' WHERE tier IS NULL")
        cursor.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
        cursor.execute("UPDATE users SET referrals_used = 0 WHERE referrals_used IS NULL")
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

import random
import datetime

def summarize_user_memory(user_id, tier="Basic", force=False):
    """
    Periodically condense recent short-term chat history into a long-term
    'summary' stored in long_memory.
    Each tier determines how frequently summarization occurs.
    Founder evolves nearly every chat.
    """
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        # --- Count user messages ---
        c.execute("SELECT COUNT(*) FROM memory WHERE user_id = ?", (user_id,))
        total = c.fetchone()[0]

        # --- Tier-based frequency mapping ---
        tier_thresholds = {
            "Basic": 25,
            "Core": 15,
            "Pro": 7,
            "King": 3,
            "Founder": random.choice([1, 2])  # evolves fast and unpredictably
        }
        trigger_threshold = tier_thresholds.get(tier, 10)

        # Skip unless threshold reached or forced
        if total % trigger_threshold != 0 and not force:
            conn.close()
            return

        # --- Fetch recent conversation ---
        c.execute("""
            SELECT role, content FROM memory
            WHERE user_id = ?
            ORDER BY id DESC LIMIT 10
        """, (user_id,))
        rows = c.fetchall()
        conn.close()

        if not rows:
            return

        # --- Combine into readable dialogue ---
        conversation = "\n".join([f"{r[0].capitalize()}: {r[1]}" for r in reversed(rows)])

        # --- Summarization prompt ---
        prompt = f"""
You are EVOSGPT, evolving by reflection.
Below is a recent conversation between you and a user.
Summarize it in one factual, calm paragraph that captures the user's
traits, goals, tone, and evolving personality.

Conversation:
{conversation}
"""

        summary = route_ai_call("Core", prompt).strip()

        # --- Store or merge summary ---
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT summary FROM long_memory WHERE user_id = ?", (user_id,))
        existing = c.fetchone()

        if existing:
            merged_prompt = f"""
You have two personality summaries for the same user.
Merge them into one consistent, concise and neutral description
without repeating or exaggerating traits.

Old Summary:
{existing[0]}

New Summary:
{summary}
"""
            merged = route_ai_call("Core", merged_prompt).strip()
            c.execute("""
                UPDATE long_memory
                SET summary = ?, last_updated = ?
                WHERE user_id = ?
            """, (merged, datetime.datetime.now(), user_id))
        else:
            c.execute("""
                INSERT INTO long_memory (user_id, summary, last_updated)
                VALUES (?, ?, ?)
            """, (user_id, summary, datetime.datetime.now()))

        conn.commit()
        conn.close()
        print(f"🧠 Summarized memory updated for user {user_id} (Tier: {tier})")

    except Exception as e:
        try:
            log_suspicious("SummarizeMemoryError", str(e))
        except Exception:
            pass

# ---------- JOB STORE ----------
import threading, random, time, sqlite3, requests, json, os
from datetime import datetime
from typing import Optional

# in-memory job store (for development). Use persistent queue in production.
jobs = {}
jobs_lock = threading.Lock()

# ---------- BACKGROUND CHAT JOB ----------
def process_chat_job(job_id, user_id, tier, user_msg):
    """
    Background worker: call route_ai_call, apply delay,
    save to DB if user_id present, then mark job done.
    """
    try:
        raw_reply = route_ai_call(tier, user_msg)
        reply = raw_reply.strip()  # ✅ trust model to format already
    except Exception as e:
        log_suspicious("LLMErrorBackground", str(e))
        reply = f"""⚠️ **System Error**

• I wasn’t able to process your request.  
• Input received:  

> {user_msg}"""

    # Decide delay (5–10s) or 1s if "fast" in the prompt
    delay = random.randint(5, 10)
    if "fast" in (user_msg or "").lower():
        delay = 1
    time.sleep(delay)

    # Save to DB only for logged-in users
    try:
        if user_id:
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, 0)",
                (user_id, user_msg, reply)
            )
            conn.commit()

            c.execute("INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)",
                      (user_id, "chat", f"User: {user_msg} | Bot: {reply}"))
            conn.commit()

            enforce_memory_limit(user_id, tier)
            conn.close()
    except Exception as e:
        log_suspicious("ChatInsertFailBackground", str(e))

    # ✅ Mark job as done with clean reply
    with jobs_lock:
        jobs[job_id] = {"status": "done", "reply": reply}


import os, json, requests
from typing import Optional

# ---------- SYSTEM PROMPTS ----------
def build_system_prompt(tier: str) -> str:
    """
    Return a system prompt based on user tier.
    Enforces EVOSGPT's personality + strict formatting style.
    """

    base_structure = """
You MUST always follow this formatting when answering:
1. Begin with a short 1–2 line introduction.
2. Use *numbered lists (1., 2., 3.)* for step-by-step guides.
3. Use *bullet points (•)* for unordered details or options.
4. Highlight key terms in *bold* for clarity.
5. Leave *one blank line* between each list item or paragraph.
6. Keep each paragraph to a maximum of 3 sentences.
7. Never return answers as one block of text.
8. End with a short conclusion or tip if relevant.
"""

    prompts = {
        "Basic": f"""
You are EVOSGPT — friendly and concise. 
{base_structure}
Always keep answers simple but with *bold highlights* for key terms.
""",
        "Core": f"""
You are EVOSGPT — structured and helpful. 
{base_structure}
Focus on step-by-step clarity with *bold terms* and clean bullets.
""",
        "Pro": f"""
You are EVOSGPT — confident, structured, and lightly promotional. 
{base_structure}
After answering, add one short *upgrade tip* politely.
""",
        "King": f"""
You are EVOSGPT — powerful, polished, and strategic. 
{base_structure}
Always add extra insights or *pro tips* at the end.
""",
        "Founder": f"""
You are EVOSGPT — playful, exclusive, and witty. 
{base_structure}
Format answers using *bold*, ### headers, and short witty notes.
Sometimes include hidden founder-only easter eggs.
"""
    }
    return prompts.get(tier, prompts["Basic"])


# ---------- AI HELPERS (OPENAI ONLY) ----------
import os, json, requests
from typing import Optional

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ---------- SYSTEM UTILS ----------
def log_suspicious(tag: str, msg: str):
    print(f"[LOG] {tag}: {msg}")


def build_system_prompt(tier: str) -> str:
    return (
        f"You are EVOSGPT [{tier}], an adaptive AI assistant for the S.O.E project. "
        "Respond fast, clearly, and never expose internal system details."
    )


# ---------- OPENAI WRAPPER ----------
def openai_chat(user_prompt: str, model: str, system_prompt: str) -> Optional[str]:
    try:
        if not OPENAI_API_KEY:
            log_suspicious("MissingKey", "OPENAI_API_KEY not found")
            return None

        headers = {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        resp = requests.post("https://api.openai.com/v1/chat/completions",
                             headers=headers, json=data, timeout=25)

        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()

        log_suspicious("OpenAIError", resp.text)
        return None

    except Exception as e:
        log_suspicious("OpenAIException", str(e))
        return None


# ---------- ROUTER (OPENAI ONLY) ----------
def route_ai_call(tier: str, prompt: str) -> str:
    tier = tier.capitalize().strip()
    system_msg = build_system_prompt(tier)

    def use(model_name):
        return openai_chat(prompt, model_name, system_msg)

    # BASIC
    if tier == "Basic":
        return use("gpt-4o-mini") or f"[Mini-Echo] {prompt}"

    # CORE
    if tier == "Core":
        return use("gpt-4o-mini") or f"[Mini-Echo] {prompt}"

    # PRO
    if tier == "Pro":
        return (
            use("gpt-4o")
            or use("gpt-4o-mini")
            or f"[Pro-Echo] {prompt}"
        )

    # KING
    if tier == "King":
        return (
            use("gpt-5")
            or use("gpt-4o")
            or use("gpt-4o-mini")
            or f"[King-Echo] {prompt}"
        )

    # FOUNDER
    if tier == "Founder":
        return (
            use("gpt-5")
            or use("gpt-4o")
            or use("gpt-4o-mini")
            or f"[Founder-Echo] {prompt}"
        )

    return f"(Unknown tier: {tier}) {prompt}"

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
    # --- Guest handling ---
    if "user_id" not in session:
        session["tier"] = session.get("tier", "Basic")
        if "guest_id" not in session:
            session["guest_id"] = str(uuid.uuid4())  # temp guest identity

    tier = session.get("tier", "Basic")
    tier_icon = {"Basic": "🧊", "Core": "⚛", "Pro": "⚡", "King": "👑", "Founder": "🔑"}.get(tier, "")

    show_memory = tier in ["Core", "Pro", "King", "Founder"]
    show_analytics = tier in ["Pro", "King", "Founder"]
    show_admin = tier in ["King", "Founder"]

    referral_code = None
    referrals_used = 0
    chat_history, system_notices, summaries = [], [], []

    # --- Manual tier change (testing only) ---
    if request.method == "POST" and "tier" in request.form and "user_id" in session:
        selected_tier = request.form.get("tier")
        session["tier"] = selected_tier
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("INSERT INTO analytics (tier) VALUES (?)", (selected_tier,))
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        # --- Logged-in user ---
        if "user_id" in session:
            uid = session["user_id"]

            # ✅ Chat history (last 100)
            c.execute("""
                SELECT user_input, bot_response
                FROM (
                    SELECT id, user_input, bot_response
                    FROM memory
                    WHERE system_msg = 0 AND user_id = ?
                    ORDER BY id DESC
                    LIMIT 100
                ) sub
                ORDER BY id ASC
            """, (uid,))
            chat_history = c.fetchall()

            # ✅ Summaries (for sidebar)
            c.execute("""
                SELECT id, substr(user_input, 1, 40) || '...' as summary
                FROM memory
                WHERE system_msg = 0 AND user_id = ?
                ORDER BY id DESC
                LIMIT 20
            """, (uid,))
            summaries = c.fetchall()

            # ✅ Notices
            c.execute("""
                SELECT bot_response, time_added
                FROM memory
                WHERE system_msg = 1 AND user_id = ?
                ORDER BY id DESC
                LIMIT 5
            """, (uid,))
            system_notices = c.fetchall()

            # ✅ Referrals
            c.execute("SELECT referral_code, referrals_used FROM users WHERE id = ?", (uid,))
            row = c.fetchone()
            if row:
                referral_code, referrals_used = row

        # --- Guest user ---
        elif "guest_id" in session:
            gid = session["guest_id"]

            # ✅ Chat history (last 10 only)
            c.execute("""
                SELECT user_input, bot_response
                FROM (
                    SELECT id, user_input, bot_response
                    FROM memory
                    WHERE system_msg = 0 AND user_id = ?
                    ORDER BY id DESC
                    LIMIT 10
                ) sub
                ORDER BY id ASC
            """, (gid,))
            chat_history = c.fetchall()

            # ✅ Summaries (short preview for sidebar)
            c.execute("""
                SELECT id, substr(user_input, 1, 30) || '...' as summary
                FROM memory
                WHERE system_msg = 0 AND user_id = ?
                ORDER BY id DESC
                LIMIT 5
            """, (gid,))
            summaries = c.fetchall()

    except Exception as e:
        log_suspicious("IndexFetchError", str(e))
    finally:
        conn.close()

    referral_link = None
    if referral_code:
        referral_link = f"https://evosgpt.onrender.com/register?ref={referral_code}"

    return render_template(
        "index.html",
        chat_history=chat_history,
        system_notices=system_notices,
        summaries=summaries,   # 🔹 sidebar summaries
        tier=tier,
        icon=tier_icon,
        show_memory=show_memory,
        show_analytics=show_analytics,
        show_admin=show_admin,
        logged_in=("user_id" in session),
        referral_link=referral_link,
        referrals_used=referrals_used
    )

# ---------- CHAT ROUTE + FORMATTERS (drop into your app.py) ----------
import re
import sqlite3
import os
from flask import request, session, jsonify

def auto_paragraph(text: str) -> str:
    """
    Force replies into readable Markdown paragraphs while preserving:
    - fenced code blocks (```...```)
    - existing list-lines that start with -, *, • or digit.
    - headers (# ...) and quotes (> ...)
    Splits into sentences and creates clean paragraphs.
    """
    if not text:
        return ""

    text = text.replace("\r\n", "\n")

    # Split out fenced code blocks
    parts = re.split(r'(```[\s\S]*?```)', text, flags=re.MULTILINE)
    out_parts = []

    for idx, part in enumerate(parts):
        if idx % 2 == 1:  # code block
            out_parts.append(part.strip())
            continue

        # Split into blocks by blank lines
        segments = [seg.strip() for seg in re.split(r'\n\s*\n', part) if seg.strip()]
        for seg in segments:
            # Preserve lists, headers, quotes as-is
            if re.search(r'^\s*([-*•]|\d+\.)\s+', seg, flags=re.MULTILINE) \
               or re.match(r'^\s*(#+\s|> )', seg):
                out_parts.append(seg)
                continue

            # Split into sentences
            sentences = re.split(r'(?<=[.!?])\s+', seg)
            for s in sentences:
                s = s.strip()
                if not s:
                    continue
                s = s.replace('\n', ' ')
                out_parts.append(s)

    # Join paragraphs with blank lines
    result = '\n\n'.join([p for p in out_parts if p]).strip()
    return result


# ---------- CHAT ROUTE ----------
@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    user_msg = (data.get("message") or "").strip()
    ui = user_msg.lower()

    tier = session.get("tier", "Basic")
    reply = None

    # --- Guest mode ---
    guest_id = None
    if "user_id" not in session:
        if "guest_id" not in session:
            token = os.urandom(16).hex()
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("INSERT INTO guests (session_token) VALUES (?)", (token,))
            guest_id = c.lastrowid
            conn.commit()
            conn.close()

            session["guest_id"] = guest_id
            session["guest_count"] = 0
        else:
            guest_id = session["guest_id"]

        guest_count = session.get("guest_count", 0)
        if guest_count >= 10:
            return jsonify({
                "reply": "🚪 Guest mode limit reached. Redirecting to registration…",
                "redirect": "/register"
            })

        session["guest_count"] = guest_count + 1
        if session["guest_count"] == 5:
            return jsonify({
                "reply": "⚠ You have 4 free chats left. Please register or log in to continue."
            })

    # ---------- Founder unlock sequence ----------
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
            session["tier"] = "Founder"
            session["founder_seq"] = 0

            # update DB tier
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("UPDATE users SET tier = ? WHERE id = ?", ("Founder", session["user_id"]))
                conn.commit()
                conn.close()
            except Exception as e:
                log_suspicious("FounderUnlockFail", str(e))

        elif tier == "Founder" and ui == "logout evosgpt":
            reply = "[SYSTEM] Founder mode deactivated. Returning to Basic tier."
            session["tier"] = "Basic"
            session["founder_seq"] = 0

            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute("UPDATE users SET tier = ? WHERE id = ?", ("Basic", session["user_id"]))
                conn.commit()
                conn.close()
            except Exception as e:
                log_suspicious("FounderLogoutFail", str(e))

        else:
            if seq > 0 and ui not in [
                "evosgpt where you created",
                "ghanaherewecome",
                "nameless"
            ]:
                session["founder_seq"] = 0

    # ---------- Load Context (Last 20 Chats) ----------
    context = ""
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        if "user_id" in session:
            uid = session["user_id"]
            c.execute("""
                SELECT user_input, bot_response
                FROM (
                    SELECT id, user_input, bot_response
                    FROM memory
                    WHERE system_msg = 0 AND user_id = ?
                    ORDER BY id DESC
                    LIMIT 20
                ) sub
                ORDER BY id ASC
            """, (uid,))
        else:
            gid = session.get("guest_id")
            c.execute("""
                SELECT user_input, bot_response
                FROM (
                    SELECT id, user_input, bot_response
                    FROM memory
                    WHERE system_msg = 0 AND guest_id = ?
                    ORDER BY id DESC
                    LIMIT 20
                ) sub
                ORDER BY id ASC
            """, (gid,))

        rows = c.fetchall()
        conn.close()

        for u, b in rows:
            context += f"User: {u}\nBot: {b}\n"

    except Exception as e:
        log_suspicious("ContextLoadError", str(e))
        context = ""

    # ---------- AI Response (OPENAI ONLY) ----------
    if reply is None:
        try:
            raw_reply = route_ai_call(tier, context + "\nUser: " + user_msg)
            reply = auto_paragraph(raw_reply)
        except Exception as e:
            log_suspicious("LLMError", str(e))
            reply = f"""⚠️ **System Error**
            
• I wasn’t able to process your request.  
• Input received:  

> {user_msg}"""

    # ---------- Save Chat to DB ----------
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()

        if "user_id" in session:
            uid = session["user_id"]
            word_count = len(user_msg.split())

            c.execute(
                "INSERT INTO memory (user_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, 0)",
                (uid, user_msg, reply)
            )

            c.execute("""
                UPDATE users
                SET chat_count = chat_count + 1,
                    word_count = word_count + ?
                WHERE id = ?
            """, (word_count, uid))

            conn.commit()
            enforce_memory_limit(uid, tier)

        elif guest_id:
            c.execute(
                "INSERT INTO memory (guest_id, user_input, bot_response, system_msg) VALUES (?, ?, ?, 0)",
                (guest_id, user_msg, reply)
            )
            conn.commit()

        conn.close()

    except Exception as e:
        log_suspicious("ChatInsertFail", str(e))

    # ---------- Return Clean JSON ----------
    return jsonify({
        "reply": reply.replace("\\n", "\n"),
        "tier": tier
    })


# ---------- CHAT JOB RESULT ----------
@app.route("/chat/result", methods=["GET"])
def chat_result():
    job_id = request.args.get("job_id")
    if not job_id:
        return jsonify({"error": "missing job_id"}), 400

    with jobs_lock:
        job = jobs.get(job_id)

    if not job:
        return jsonify({"status": "unknown"}), 404

    # job contains {"status":"processing"} or {"status":"done","reply": "..."}
    return jsonify(job)

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

@app.route("/api/tier-refresh", methods=["GET"])
def tier_refresh():
    """
    Return the authoritative tier for the current user session.
    This endpoint is safe for frontend auto-refresh in sidebar.
    """
    tier = session.get("tier", "Basic")
    user_id = session.get("user_id")
    if user_id:
        try:
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()
            c.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
            row = c.fetchone()
            if row:
                tier = row[0]  # DB has the latest tier
                session["tier"] = tier  # sync session
        except Exception as e:
            log_suspicious("TierRefreshFail", str(e))
        finally:
            conn.close()

    return jsonify({
        "tier": tier
    })

@app.route("/suggestions")
def suggestions():
    return render_template("suggestions.html")

@app.route("/report-bug")
def report_bug():
    return render_template("bug.html")

    
@app.route("/about")
def about():
    return render_template("about.html")
    

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
                elif coupon[1] == 1:
                    msg = "⚠️ This coupon has already been used."
                else:
                    new_tier = coupon[0]
                    c.execute("UPDATE coupons SET used = 1 WHERE code = ?", (code,))
                    if "user_id" in session:
                        c.execute("UPDATE users SET tier = ? WHERE id = ?", (new_tier, session["user_id"]))
                        session["tier"] = new_tier
                    msg = f"✅ Successfully upgraded to {new_tier}!"
                    conn.commit()
            except Exception as e:
                log_suspicious("RedeemFail", str(e))
                msg = "❌ An error occurred."
            finally:
                try:
                    conn.close()
                except:
                    pass

        return render_template("redeem.html", msg=msg)  # ✅ always return


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
import random

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT id, password, tier, status FROM users WHERE username = ?", (username,))
        row = c.fetchone()

        if row:
            user_id, hashed_pw, tier, status = row  # ✅ correct unpacking

            if check_password_hash(hashed_pw, password):  # ✅ correct check
                # ❌ Suspended account
                if status != "active":
                    conn.close()
                    flash("⚠ Your account is suspended.")
                    return render_template("login.html")

                # ✅ Set session
                session["user_id"] = user_id
                session["username"] = username
                session["tier"] = tier

                # ✅ Merge guest chats into this account
                guest_id = session.pop("guest_id", None)
                if guest_id:
                    try:
                        c.execute("UPDATE memory SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (user_id, guest_id))
                        c.execute("UPDATE chat_logs SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (user_id, guest_id))
                        conn.commit()
                    except Exception as e:
                        log_suspicious("GuestReassignFail", str(e))

                conn.close()

                # 🎁 Promo messages by tier
                promos = {
                    "Basic": [
                        "🚀 Upgrade to Core for smarter long-term memory!",
                        "⚡ Pro gives you faster responses & analytics access.",
                        "👑 King unlocks admin tools & premium features."
                    ],
                    "Core": [
                        "⚡ Upgrade to Pro for lightning-fast responses!",
                        "👑 King tier gives you the dashboard & unlimited storage."
                    ],
                    "Pro": [
                        "👑 Upgrade to King for full control & admin dashboard!",
                        "🔥 King tier = ultimate experience, no limits."
                    ],
                    "King": [
                        "👑 You’re a King. Founder tier unlocks secret tools…",
                        "💡 Stay tuned — Founder mode is coming."
                    ],
                    "Founder": [
                        "🔥 Founder mode active. You already have everything.",
                        "💎 Thank you for being a Founder."
                    ]
                }
                session["popup_msg"] = random.choice(promos.get(tier, ["💡 Ask EVOSGPT anything, anytime!"]))

                # ✅ Log login
                log_action(user_id, "login", f"User {username} logged in")

                return redirect(url_for("index"))

        conn.close()
        flash("❌ Invalid username or password.")
        return render_template("login.html")

    return render_template("login.html")


import re
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

ALLOWED_DOMAINS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}  # optional
import uuid
import random, string

def generate_referral_code():
    """Generate a clean referral code like REF-1A2B3C"""
    return "REF-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        password = request.form["password"]

        # 🔹 Validation
        if not username or not password or not email:
            return render_template("register.html", msg="Username, email, and password required.")

        if not EMAIL_REGEX.match(email):
            return render_template("register.html", msg="Invalid email format. Use a valid email like name@gmail.com")

        domain = email.split("@")[-1].lower()
        if domain not in ALLOWED_DOMAINS:
            return render_template("register.html", msg="Email must be from Gmail, Yahoo, Outlook, or Hotmail.")

        hashed_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()

            # 🔹 Assign tier (first 50 = Pro, rest Basic)
            c.execute("SELECT COUNT(*) FROM users")
            total_users = c.fetchone()[0] or 0
            tier = "Pro" if total_users < 50 else "Basic"

            # 🔹 Generate referral code
            referral_code = generate_referral_code()

            # ✅ Safe insert into SQLite
            try:
                c.execute("""
                    INSERT INTO users (username, email, password, tier, referral_code)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, hashed_pw, tier, referral_code))
                new_user_id = c.lastrowid
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return render_template("register.html", msg="❌ Username or email already exists.")

            # 🔹 Handle referral usage if "?ref=" is in URL
            referrer_code = request.args.get("ref")
            if referrer_code:
                try:
                    c.execute("UPDATE users SET referrals_used = referrals_used + 1 WHERE referral_code = ?", (referrer_code,))
                    conn.commit()
                except Exception as e:
                    print(f"[WARN] Failed to update referrer: {e}")

            # 🔹 Merge guest chats into this new user account
            guest_id = session.pop("guest_id", None)
            if guest_id:
                try:
                    c.execute("UPDATE memory SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (new_user_id, guest_id))
                    c.execute("UPDATE chat_logs SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (new_user_id, guest_id))
                    conn.commit()
                except Exception as e:
                    log_suspicious("GuestAssignFail", str(e))

            conn.close()

            # 🔹 Try to sync with Supabase (non-fatal)
            try:
                if "supabase" in globals():
                    supabase.table("users").insert({
                        "username": username,
                        "email": email,
                        "tier": tier,
                        "referral_code": referral_code
                    }).execute()
                else:
                    print("[WARN] Supabase not initialized — skipping sync.")
            except Exception as e:
                print(f"[WARN] Failed to sync user to Supabase: {e}")

            # ✅ Redirect to login after successful registration
            flash("✅ Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))

        except Exception as e:
            print(f"[ERROR] Register crashed: {e}")
            return render_template("register.html", msg=f"⚠ Error: {e}")

    return render_template("register.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        log_action(session["user_id"], "logout", f"User {session.get('username','')} logged out")
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("login"))

@app.route("/get_referral")
def get_referral():
    """Return or generate the user's referral link for evosgpt.xyz"""
    try:
        if "user_id" in session:
            uid = session["user_id"]
            conn = sqlite3.connect("database/memory.db")
            c = conn.cursor()

            # Fetch existing referral code
            c.execute("SELECT referral_code FROM users WHERE id = ?", (uid,))
            result = c.fetchone()

            if result and result[0]:
                ref_code = result[0]
            else:
                # Generate referral code only once if missing
                ref_code = "REF-" + os.urandom(3).hex().upper()
                c.execute("UPDATE users SET referral_code = ? WHERE id = ?", (ref_code, uid))
                conn.commit()

            # Create full referral link for evosgpt.xyz
            link = f"https://evosgpt.xyz/register?ref={ref_code}"

            conn.close()
            return jsonify({"link": link})

        # --- Guest fallback ---
        return jsonify({"link": "https://evosgpt.xyz/register"})

    except Exception as e:
        log_suspicious("ReferralGenError", str(e))
        return jsonify({"link": "https://evosgpt.xyz/register"})

# --- Paste below your existing auth routes (login/register/logout) ---

import os
import requests
from urllib.parse import urlencode, quote

SUPABASE_URL = os.getenv("SUPABASE_URL", "https://ttcavdmgylcxmzdijcsx.supabase.co")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "sys1q0zg3clqajs04p2yhkgf96nf4hmup9mdr8l38u6")  # replace via env vars in production

# Allowed providers list for sanity
ALLOWED_OAUTH_PROVIDERS = {"google", "facebook", "discord", "apple"}

# 1) Route to START OAuth (optional — frontend can also do oauth via supabase-js)
@app.route("/oauth/<provider>", methods=["GET"])
def start_oauth(provider):
    """
    Redirects user to Supabase OAuth authorize endpoint.
    You can optionally call this server route instead of doing oauth from the frontend.
    Add ?ref=REFCODE to preserve referral through the flow.
    """
    provider = provider.lower()
    if provider not in ALLOWED_OAUTH_PROVIDERS:
        flash("Unsupported OAuth provider.")
        return redirect(url_for("login"))

    # preserve referral if present
    ref = request.args.get("ref")
    if ref:
        session["referral_pending"] = ref

    # where Supabase will redirect back after provider auth
    redirect_to = url_for("oauth_callback", _external=True)  # server callback
    # build authorize URL (implicit/redirect flow)
    params = {
        "provider": provider,
        "redirect_to": redirect_to
        # you can add "scopes": "email" if necessary
    }
    auth_url = f"{SUPABASE_URL}/auth/v1/authorize?{urlencode(params, quote_via=quote)}"
    return redirect(auth_url)


# 2) Callback route - Supabase redirects here after OAuth
@app.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    """
    Supabase may return information in the URL fragment (which the server cannot read)
    — so typical pattern: have frontend read the fragment and POST the access_token to /oauth/session.
    This callback also supports server-side query params if your Supabase setup returns token in query.
    We'll:
      - Try to read access_token from query params (if present)
      - Otherwise show a small page with JS that copies fragment into a POST to /oauth/session
    """
    # If access_token present as query param (depends on flow), verify immediately:
    access_token = request.args.get("access_token") or request.args.get("token")
    # If code is present (authorization_code flow), you could exchange it server-side using service role,
    # but we avoid using secret keys here. If you need code exchange, use service_role key in a secure env var.
    if access_token:
        # forward to session handler (server-side verify and login)
        return redirect(url_for("oauth_session_html") + f"?access_token={access_token}")

    # otherwise serve a tiny HTML that extracts fragment (#access_token=...) and POSTs to /oauth/session
    # Also include any referral stored in session so JS can include it.
    referral_pending = session.get("referral_pending", "")
    return f"""
    <!doctype html>
    <html>
      <head><meta charset="utf-8"><title>OAuth callback</title></head>
      <body>
        <p>Finalizing login — please wait...</p>
        <script>
          // read fragment (where supabase-js places the access_token for implicit flow)
          const fragment = new URLSearchParams(window.location.hash.slice(1));
          const token = fragment.get("access_token") || fragment.get("access_token_token") || null;
          // fallback: attempt to read query param if any (rare)
          const urlParams = new URLSearchParams(window.location.search);
          const qtoken = urlParams.get("access_token") || urlParams.get("token");

          const accessToken = token || qtoken;
          if (!accessToken) {{
            document.body.innerHTML = "<p style='color:red'>No access token found. Please return to the login page and try again.</p>";
          }} else {{
            // POST access token to server to verify & create local user
            fetch("{url_for('oauth_session', _external=True)}", {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{
                access_token: accessToken,
                referral: "{referral_pending}"
              }})
            }}).then(resp => resp.json()).then(data => {{
              if (data.success) {{
                // redirect to app
                window.location.href = "{url_for('index', _external=True)}";
              }} else {{
                document.body.innerHTML = "<p style='color:red'>OAuth failed: " + (data.error || 'unknown') + "</p>";
              }}
            }});
          }}
        </script>
      </body>
    </html>
    """


# 3) Server endpoint to accept an access_token and verify user with Supabase
@app.route("/oauth/session", methods=["POST"])
def oauth_session():
    """
    POST JSON payload:
    {
      "access_token": "<provider access token from supabase oauth>",
      "referral": "REF-..."  (optional)
    }

    This endpoint:
      - verifies token by calling Supabase /auth/v1/user with Authorization: Bearer <token>
      - creates/looks up local sqlite user, assigns tier/referral, sets session, and returns JSON { success: true }.
    """
    try:
        data = request.get_json() or {}
        access_token = data.get("access_token")
        referral = data.get("referral") or session.get("referral_pending")

        if not access_token:
            return {"success": False, "error": "no_access_token"}, 400

        # Call Supabase to get user info
        user_info_url = f"{SUPABASE_URL}/auth/v1/user"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "apikey": SUPABASE_ANON_KEY,
            "Content-Type": "application/json"
        }
        resp = requests.get(user_info_url, headers=headers, timeout=8)
        if resp.status_code != 200:
            return {"success": False, "error": "invalid_token_or_supabase_error", "detail": resp.text}, 400

        supa_user = resp.json()
        # supa_user usually contains: id, email, user_metadata, app_metadata, etc.
        supa_id = supa_user.get("id")
        email = supa_user.get("email")
        username_from_email = (email.split("@")[0]) if email else f"user_{supa_id[:6]}"

        # Now check local sqlite users table for an account with this supabase id or email
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        # first try supabase id mapped to provider account (we store provider_id in users.supabase_id)
        c.execute("SELECT id, username, tier, status FROM users WHERE supabase_id = ?", (supa_id,))
        row = c.fetchone()

        if row:
            user_id, username, tier, status = row
            # If account suspended
            if status != "active":
                conn.close()
                return {"success": False, "error": "suspended"}, 403

            # log in
            session["user_id"] = user_id
            session["username"] = username
            session["tier"] = tier
            conn.close()
            # clear referral_pending
            session.pop("referral_pending", None)
            return {"success": True}

        # if no supabase_id mapping, try by email (might be existing local account)
        c.execute("SELECT id, username, tier, status FROM users WHERE email = ?", (email,))
        row2 = c.fetchone()
        if row2:
            user_id, username, tier, status = row2
            if status != "active":
                conn.close()
                return {"success": False, "error": "suspended"}, 403
            # update this local user to remember supabase id for future quick mapping
            try:
                c.execute("UPDATE users SET supabase_id = ? WHERE id = ?", (supa_id, user_id))
                conn.commit()
            except Exception as e:
                # non-fatal
                print("[WARN] Failed to attach supabase_id:", e)
            session["user_id"] = user_id
            session["username"] = username
            session["tier"] = tier
            conn.close()
            session.pop("referral_pending", None)
            return {"success": True}

        # else create local user automatically
        # generate a unique username base (ensure uniqueness)
        base_username = username_from_email
        candidate = base_username
        suffix = 1
        while True:
            c.execute("SELECT 1 FROM users WHERE username = ?", (candidate,))
            if not c.fetchone():
                break
            candidate = f"{base_username}{suffix}"
            suffix += 1

        # assign tier same as register flow: first 50 => Pro else Basic
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0] or 0
        tier = "Pro" if total_users < 50 else "Basic"

        # generate referral code
        def generate_referral_code_short():
            import random, string
            return "REF-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        referral_code = generate_referral_code_short()

        # insert new local user (password empty, oauth account)
        c.execute("""
            INSERT INTO users (username, email, password, tier, referral_code, supabase_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (candidate, email, "", tier, referral_code, supa_id))
        new_user_id = c.lastrowid
        conn.commit()

        # credit referrer if referral pending
        if referral:
            try:
                c.execute("UPDATE users SET referrals_used = referrals_used + 1 WHERE referral_code = ?", (referral,))
                conn.commit()
            except Exception as e:
                print("[WARN] failed to credit referrer:", e)

        # merge guest chats if present
        guest_id = session.pop("guest_id", None)
        if guest_id:
            try:
                c.execute("UPDATE memory SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (new_user_id, guest_id))
                c.execute("UPDATE chat_logs SET user_id = ?, guest_id = NULL WHERE guest_id = ?", (new_user_id, guest_id))
                conn.commit()
            except Exception as e:
                log_suspicious("GuestAssignFail", str(e))

        conn.close()

        # optional: try to replicate to Supabase table users (non-blocking)
        try:
            if "supabase" in globals():
                supabase.table("users").insert({
                    "username": candidate,
                    "email": email,
                    "tier": tier,
                    "referral_code": referral_code,
                    "supabase_id": supa_id
                }).execute()
        except Exception as e:
            print("[WARN] supabase sync failed", e)

        # set session and finish
        session["user_id"] = new_user_id
        session["username"] = candidate
        session["tier"] = tier
        session.pop("referral_pending", None)

        # log
        log_action(new_user_id, "oauth_login", f"OAuth sign-in via supabase provider for {email}")
        return {"success": True}
    except Exception as e:
        print("[ERROR] /oauth/session:", e)
        return {"success": False, "error": "server_error", "detail": str(e)}, 500


# helper small HTML endpoint (optional) to show POST UI if needed
@app.route("/oauth/session_html", methods=["GET"])
def oauth_session_html():
    """
    Optional helper used by oauth_callback redirect logic: if callback had access_token in query,
    this page POSTs the access token to /oauth/session by fetching via JS.
    """
    access_token = request.args.get("access_token", "")
    referral_pending = session.get("referral_pending", "")
    return f"""
    <!doctype html>
    <html>
      <head><meta charset='utf-8'><title>Finalize OAuth</title></head>
      <body>
        <p>Finalizing login...</p>
        <script>
          (async function() {{
            const res = await fetch("{url_for('oauth_session', _external=True)}", {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ access_token: "{access_token}", referral: "{referral_pending}" }})
            }});
            const data = await res.json();
            if (data.success) window.location = "{url_for('index', _external=True)}";
            else document.body.innerHTML = "<p style='color:red'>OAuth failed: " + (data.error||'unknown') + "</p>";
          }})();
        </script>
      </body>
    </html>
    """


# ---------- end of oauth additions ----------

# ---------- UPGRADE ROUTE (Paystack + Coinbase + Bank) ----------
# ---------- UPGRADE ROUTE (Paystack + Coinbase + Bank) ----------
import requests, json, time, sqlite3, os, hmac, hashlib
from datetime import datetime, timedelta
from flask import request, session, redirect, url_for, flash, render_template, jsonify

# === Payment Config (read from env) ===
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET")
PAYSTACK_PUBLIC_KEY = os.getenv("PAYSTACK_PUBLIC_KEY")
COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")               # Coinbase Commerce API key (UUID)
COINBASE_WEBHOOK_SECRET = os.getenv("COINBASE_WEBHOOK_SECRET") # Coinbase webhook secret

# --- Tier setup ---
TIER_PRICE_USD = {"Core": 1, "Pro": 5, "King": 9}
VALID_TIERS = set(TIER_PRICE_USD.keys())

# --- Example exchange rates ---
EXCHANGE_RATES = {
    "GHS": 15.0,   # 1 USD = 15 GHS (example)
    "NGN": 1500.0,
    "USD": 1.0
}

PAYSTACK_ACCOUNT_CURRENCY = "GHS"



@app.route("/upgrade", methods=["GET", "POST"])
def upgrade():
    """Handles tier upgrades via Paystack, Coinbase Commerce, or Bank transfer."""
    if "user_id" not in session:
        flash("⚠️ You must be logged in to upgrade.")
        return redirect(url_for("login"))

    conn = sqlite3.connect("database/memory.db")
    c = conn.cursor()

    if request.method == "POST":
        user_id = session["user_id"]
        tier = request.form.get("tier")
        payment_method = request.form.get("payment_method")
        coupon = (request.form.get("coupon") or "").strip().upper()

        # ---------- Coupon handling ----------
        if coupon:
            c.execute("SELECT tier, used FROM coupons WHERE code = ?", (coupon,))
            row = c.fetchone()
            if row and row[1] == 0:
                new_tier = row[0]
                expiry = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
                c.execute("UPDATE users SET tier = ?, upgrade_expiry = ? WHERE id = ?",
                          (new_tier, expiry, user_id))
                c.execute("UPDATE coupons SET used = 1 WHERE code = ?", (coupon,))
                conn.commit()
                conn.close()
                flash(f"🎉 Success! Coupon applied. You are now {new_tier} tier.")
                return redirect(url_for("index"))
            else:
                conn.close()
                flash("⚠️ Invalid or already used coupon.")
                return redirect(url_for("upgrade"))

        # ---------- Normal upgrade ----------
        if tier not in VALID_TIERS:
            conn.close()
            flash("⚠️ Invalid tier selected.")
            return redirect(url_for("upgrade"))

        # Save pending purchase for audit
        ref = f"EVOS-{user_id}-{int(time.time())}"
        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                  (user_id, tier, payment_method, ref))
        conn.commit()
        conn.close()


 

        # ---------- PAYSTACK ----------
        if payment_method == "Paystack":
            if not PAYSTACK_SECRET_KEY:
                flash("❌ Paystack not configured.")
                return redirect(url_for("upgrade"))

            amount_usd = TIER_PRICE_USD[tier]
            rate = EXCHANGE_RATES.get(PAYSTACK_ACCOUNT_CURRENCY, 1.0)
            amount_local = amount_usd * rate
            amount_smallest = int(round(amount_local * 100))  # pesewas or kobo

            headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
            data = {
                "email": session.get("email", f"user{user_id}@evos.com"),
                "amount": amount_smallest,
                "currency": PAYSTACK_ACCOUNT_CURRENCY,
                "reference": ref,
                "callback_url": url_for("upgrade_success", _external=True),
                "metadata": {"user_id": user_id, "tier": tier}
            }

            try:
                resp = requests.post("https://api.paystack.co/transaction/initialize",
                                     headers=headers, json=data, timeout=15)
            except Exception as e:
                print("❌ Paystack request failed:", e)
                flash("❌ Paystack initialization failed (network).")
                return redirect(url_for("upgrade"))

            print("🔹 Paystack init response:", resp.status_code, resp.text)
            try:
                rj = resp.json()
            except Exception:
                rj = {}

            if resp.ok and rj.get("status"):
                auth_url = rj.get("data", {}).get("authorization_url")
                if auth_url:
                    return redirect(auth_url)
            flash("❌ Paystack initialization failed.")
            return redirect(url_for("upgrade"))

        # ---------- COINBASE COMMERCE ----------
        elif payment_method == "Coinbase":
            if not COINBASE_API_KEY:
                flash("❌ Coinbase Commerce is not configured.")
                return redirect(url_for("upgrade"))

            amount_usd = float(TIER_PRICE_USD[tier])
            coin_ref = f"EVOS-COIN-{user_id}-{int(time.time())}"

            payload = {
                "name": f"EVOSGPT - {tier} Plan",
                "description": f"Upgrade to {tier}",
                "local_price": {"amount": f"{amount_usd:.2f}", "currency": "USD"},
                "pricing_type": "fixed_price",
                "metadata": {"user_id": user_id, "tier": tier, "reference": coin_ref},
                "redirect_url": url_for("upgrade_success", _external=True),
                "cancel_url": url_for("upgrade", _external=True)
            }

            headers = {
                "Content-Type": "application/json",
                "X-CC-Api-Key": COINBASE_API_KEY,
                "X-CC-Version": "2018-03-22"
            }

            try:
                resp = requests.post("https://api.commerce.coinbase.com/charges",
                                     json=payload, headers=headers, timeout=15)
            except Exception as e:
                print("❌ Coinbase network error:", e)
                flash("❌ Coinbase initialization failed (network).")
                return redirect(url_for("upgrade"))

            print("🔹 Coinbase create charge response:", resp.status_code, resp.text)
            try:
                rj = resp.json()
            except Exception as e:
                print("❌ Coinbase JSON decode error:", e)
                rj = {}

            if resp.ok and "data" in rj:
                hosted_url = rj["data"].get("hosted_url")
                if hosted_url:
                    try:
                        conn = sqlite3.connect("database/memory.db")
                        c = conn.cursor()
                        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                                  (user_id, tier, "Coinbase", coin_ref))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        print("⚠️ Coinbase save purchase error:", e)
                    return redirect(hosted_url)
            else:
                print("❌ Coinbase charge failed:", resp.status_code, resp.text)
                error_msg = ""
                if isinstance(rj, dict):
                    error_msg = rj.get("error", {}).get("message") or json.dumps(rj)
                flash(f"❌ Coinbase error: {error_msg}")
                return redirect(url_for("upgrade"))

        # ---------- BANK TRANSFER ----------
        elif payment_method == "Bank":
            return redirect(url_for("bank_transfer"))

        else:
            flash("⚠️ Invalid payment method.")
            return redirect(url_for("upgrade"))

    # ---------- GET request ----------
    rate = EXCHANGE_RATES.get(PAYSTACK_ACCOUNT_CURRENCY, 1.0)
    prices = {t: int(round(TIER_PRICE_USD[t] * rate)) for t in TIER_PRICE_USD}
    return render_template("upgrade.html",
                           tiers=list(TIER_PRICE_USD.keys()),
                           prices=prices,
                           currency=PAYSTACK_ACCOUNT_CURRENCY)


# ---------- COINBASE DIRECT CHARGE ROUTE ----------
@app.route("/create_coinbase_charge", methods=["POST"])
def create_coinbase_charge():
    """Standalone Coinbase charge endpoint."""
    if "user_id" not in session:
        flash("⚠️ You must be logged in to pay.")
        return redirect(url_for("login"))

    tier = request.form.get("tier")
    if tier not in VALID_TIERS:
        flash("⚠️ Invalid tier.")
        return redirect(url_for("upgrade"))

    if not COINBASE_API_KEY:
        flash("❌ Coinbase not configured.")
        return redirect(url_for("upgrade"))

    # amount from your pricing dict
    amount_usd = float(TIER_PRICE_USD[tier])
    ref = f"EVOS-COIN-{session['user_id']}-{int(time.time())}"

    payload = {
        "name": f"EVOSGPT Upgrade - {tier}",
        "description": f"Upgrade your EVOSGPT tier to {tier}",
        "local_price": {
            "amount": f"{amount_usd:.2f}",
            "currency": "USD"
        },
        "pricing_type": "fixed_price",

        # Coinbase will return this EXACTLY in webhook payload.event.data.metadata
        "metadata": {
            "user_id": session["user_id"],
            "tier": tier,
            "reference": ref
        },

        "redirect_url": url_for("upgrade_success", _external=True),
        "cancel_url": url_for("upgrade", _external=True)
    }

    headers = {
        "Content-Type": "application/json",
        "X-CC-Api-Key": COINBASE_API_KEY,
        "X-CC-Version": "2018-03-22"
    }

    # ---- SEND CHARGE REQUEST ----
    try:
        resp = requests.post(
            "https://api.commerce.coinbase.com/charges",
            json=payload,
            headers=headers,
            timeout=15
        )
    except Exception as e:
        print("❌ Coinbase create charge network error:", e)
        flash("❌ Coinbase initialization failed (network).")
        return redirect(url_for("upgrade"))

    print("🔹 Coinbase direct charge response:", resp.status_code, resp.text)

    # Ensure JSON parsing does not crash the flow
    try:
        rj = resp.json()
    except Exception:
        rj = {}

    # ---- SUCCESS CASE ----
    if resp.ok and "data" in rj:
        data = rj["data"]
        hosted_url = data.get("hosted_url")

        if hosted_url:
            print("🔗 Redirecting user to Coinbase hosted charge:", hosted_url)

            # Save pending purchase (optional but safe)
            try:
                conn = sqlite3.connect("database/memory.db")
                c = conn.cursor()
                c.execute(
                    "INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                    (session["user_id"], tier, "Coinbase-Pending", ref)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                print("⚠️ Coinbase save purchase error:", e)

            return redirect(hosted_url)

    # ---- FAILURE CASE ----
    print("❌ Coinbase charge failed:", resp.status_code, resp.text)
    flash("❌ Coinbase initialization failed. Check your API key or Coinbase dashboard.")
    return redirect(url_for("upgrade"))


# ---------- BANK TRANSFER ROUTE ----------
@app.route("/bank_transfer", methods=["GET", "POST"])
def bank_transfer():
    if "user_id" not in session:
        flash("⚠️ You must be logged in to pay.")
        return redirect(url_for("login"))

    if request.method == "POST":
        tier = request.form.get("tier")
        ref = f"EVOS-BANK-{session['user_id']}-{int(time.time())}"
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("INSERT INTO purchases (user_id, tier, payment_method, reference) VALUES (?, ?, ?, ?)",
                  (session['user_id'], tier, "Bank", ref))
        conn.commit()
        conn.close()
        flash("✅ Bank transfer instruction sent. Upload your proof or email support@evosgpt.com with reference.")
        return redirect(url_for("index"))

    bank_details = {
        "bank_name": "ABSA BANK GHANA",
        "account_name": "EVOSGPT LTD",
        "account_number": "024",
        "branch": "Berekum",
        "note": "After transfer, upload proof or email evoarchitect00@gmail.com or support@evosgpt.com with your reference",
        "advice": "Use paystack, upgrade for a seamless transaction."
    }
    return render_template("bank_transfer.html", bank=bank_details, tiers=list(TIER_PRICE_USD.keys()))

# ---------- PAYMENTS & WEBHOOKS (HARDENED) ----------
from hmac import compare_digest
import hmac, hashlib

# Prices (source of truth) → exclude Founder (not for sale)
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

# --- PAYSTACK WEBHOOK ---
@app.route("/webhook/paystack", methods=["POST"])
def webhook_paystack():
    raw = request.get_data() or b""
    sent_sig = request.headers.get("X-Paystack-Signature", "")
    secret = os.getenv("PAYSTACK_SECRET", "")   # ✔ your .env uses PAYSTACK_SECRET

    # Basic checks
    if not sent_sig or not secret:
        print("⚠️ Paystack webhook missing signature or secret.")
        return jsonify({"status": "invalid-signature"}), 400

    # Validate signature
    try:
        expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    except Exception as e:
        print("⚠️ HMAC error:", e)
        return jsonify({"status": "invalid-hmac"}), 400

    if not compare_digest(sent_sig, expected):
        print("⚠️ Invalid Paystack signature.")
        return jsonify({"status": "invalid-signature"}), 400

    # Parse JSON
    payload = _safe_parse_json(raw)
    if not payload:
        print("⚠️ Invalid Paystack JSON payload.")
        return jsonify({"status": "bad-json"}), 400

    if payload.get("event") != "charge.success":
        return jsonify({"status": "ignored"}), 200

    data = payload.get("data", {}) or {}
    reference = data.get("reference", "")
    meta = data.get("metadata", {}) or {}

    # Extract user ID safely
    try:
        user_id = int(meta.get("user_id"))
    except Exception:
        user_id = None

    tier = meta.get("tier", "Core")

    if not isinstance(user_id, int) or tier not in VALID_TIERS:
        print("⚠️ Paystack bad metadata:", meta)
        return jsonify({"status": "bad-metadata"}), 400

    # 💰 Validate amount
    try:
        paid_amount = data.get("amount", 0) / 100   # pesewas → GHS
        expected_amount = TIER_PRICE_USD[tier] * EXCHANGE_RATES["GHS"]
    except Exception as e:
        print("⚠️ Amount validation error:", e)
        return jsonify({"status": "amount-error"}), 400

    if abs(paid_amount - expected_amount) > 0.5:
        print(f"⚠️ Paystack amount mismatch: {paid_amount} vs {expected_amount}")
        return jsonify({"status": "amount-mismatch"}), 400

    # Duplicate reference check
    if _purchases_ref_exists(reference):
        return jsonify({"status": "ok"}), 200

    # Save purchase
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
        print("⚠️ Paystack DB error:", e)
        return jsonify({"status": "db-error"}), 500

    # Upgrade the user
    _upgrade_user(user_id, tier)
    print(f"✅ User {user_id} upgraded via Paystack → {tier}")

    return jsonify({"status": "ok"}), 200


from flask import request

@app.after_request
def set_security_headers(resp):
    # Always applied
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Google must access these without CSP
    sitemap_exceptions = ("/sitemap.xml", "/robots.txt")

    # Skip CSP for sitemap + robots
    if request.path in sitemap_exceptions:
        return resp

    # Strict CSP for everything else
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.openai.com https://api.commerce.coinbase.com "
        "https://api.paystack.co http://localhost:11434; "
        "frame-ancestors 'none';"
    )

    return resp
    
# --- COINBASE WEBHOOK ---
@app.route("/webhook/coinbase", methods=["POST"])
def webhook_coinbase():
    sig = request.headers.get("X-CC-Webhook-Signature", "")
    secret = os.getenv("COINBASE_WEBHOOK_SECRET", "")
    raw = request.get_data() or b""

    if not sig or not secret:
        print("⚠️ Coinbase webhook missing signature or secret.")
        return jsonify({"status": "invalid"}), 400

    # Verify Coinbase signature
    mac = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    if not compare_digest(sig, mac):
        print("⚠️ Coinbase invalid signature.")
        return jsonify({"status": "invalid-signature"}), 400

    payload = _safe_parse_json(raw)
    if not payload:
        print("⚠️ Coinbase bad JSON payload.")
        return jsonify({"status": "bad-json"}), 400

    event = payload.get("event", {}) or {}
    event_type = event.get("type", "")

    # Only accept successful crypto payments
    if event_type not in {"charge:confirmed", "charge:resolved"}:
        return jsonify({"status": "ignored"}), 200

    data = event.get("data", {}) or {}
    meta = data.get("metadata", {}) or {}
    reference = data.get("code") or ""

    # Extract user ID
    try:
        user_id = int(meta.get("user_id"))
    except Exception:
        user_id = None

    tier = meta.get("tier", "Pro")

    if not isinstance(user_id, int) or tier not in VALID_TIERS:
        print("⚠️ Coinbase bad metadata:", meta)
        return jsonify({"status": "bad-metadata"}), 400

    # ---- OPTIONAL AMOUNT VALIDATION ----
    # Coinbase sends payments in crypto; this checks the local pricing object if present
    pricing = data.get("pricing", {})
    local = pricing.get("local", {})
    paid_amount = float(local.get("amount", 0)) if local else 0.0

    # Compare with expected USD price
    expected_amount = TIER_PRICE_USD[tier]

    # Allow ± $0.50 tolerance
    if paid_amount and abs(paid_amount - expected_amount) > 0.50:
        print(f"⚠️ Coinbase amount mismatch: {paid_amount} vs {expected_amount}")
        return jsonify({"status": "amount-mismatch"}), 400

    # Prevent duplicate purchases
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
        print("⚠️ Coinbase DB error:", e)
        return jsonify({"status": "db-error"}), 500

    _upgrade_user(user_id, tier)
    print(f"✅ User {user_id} upgraded via Coinbase → {tier}")
    return jsonify({"status": "ok"}), 200



# ---------- UPGRADE SUCCESS ----------
@app.route("/upgrade_success")
def upgrade_success():
    """
    Callback page shown after a successful payment
    from Paystack or Coinbase.
    Auto-refreshes session tier from DB.
    """
    if "user_id" not in session:
        flash("⚠️ You must be logged in to view this page.")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    reference = request.args.get("reference", None)

    # Fetch the latest tier from DB
    try:
        conn = sqlite3.connect("database/memory.db")
        c = conn.cursor()
        c.execute("SELECT tier FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row:
            session["tier"] = row[0]  # 🔹 Auto-upgrade session
        conn.close()
    except Exception as e:
        print("⚠️ Upgrade session refresh failed:", e)

    if reference:
        print(f"[PAYMENT CALLBACK] Success. Reference received: {reference}")
    else:
        print("[PAYMENT CALLBACK] Success with no reference provided.")

    flash("✅ Payment successful! Your access has been upgraded.")
    return render_template("payment-success.html")

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

from flask import send_from_directory

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        'static/images',
        'evosgpt-icon.png'
        )
        
@app.route('/system_notices')
def system_notices():
    return "No system notices yet."


# ---------- QUICK FIX: Replace SQLite placeholders with Postgres placeholders ----------
import re

def fix_sql_placeholders():
    with open("app.py", "r", encoding="utf-8") as f:
        code = f.read()

    # Replace ? with %s inside execute(...) and executemany(...)
    fixed = re.sub(r'execute\(([^)]*?)\?', r'execute(\1%s', code)
    fixed = re.sub(r'executemany\(([^)]*?)\?', r'executemany(\1%s', fixed)

    with open("app_fixed.py", "w", encoding="utf-8") as f:
        f.write(fixed)

    print("✅ Placeholders fixed. New file saved as app_fixed.py")

# Run the fix (uncomment this line to execute immediately when app.py runs)
# fix_sql_placeholders()

from flask import Response, request

@app.route("/sitemap.xml", methods=["GET", "HEAD"])
def sitemap():
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://evosgpt.xyz/</loc>
        <priority>1.0</priority>
        <changefreq>daily</changefreq>
    </url>
    <url>
        <loc>https://evosgpt.xyz/login</loc>
        <priority>0.8</priority>
        <changefreq>weekly</changefreq>
    </url>
    <url>
        <loc>https://evosgpt.xyz/register</loc>
        <priority>0.8</priority>
        <changefreq>weekly</changefreq>
    </url>
    <url>
        <loc>https://evosgpt.xyz/upgrade</loc>
        <priority>0.8</priority>
        <changefreq>weekly</changefreq>
    </url>
    <url>
        <loc>https://evosgpt.xyz/chat</loc>
        <priority>0.6</priority>
        <changefreq>hourly</changefreq>
    </url>
</urlset>"""

    # If HEAD request: return headers only
    if request.method == "HEAD":
        return Response(status=200, mimetype="application/xml")

    return Response(sitemap_xml, mimetype="application/xml")


@app.route("/robots.txt", methods=["GET", "HEAD"])
def robots():
    robots_text = """User-agent: *
Allow: /

Sitemap: https://evosgpt.xyz/sitemap.xml
"""

    if request.method == "HEAD":
        return Response(status=200, mimetype="text/plain")

    return Response(robots_text, mimetype="text/plain")


# ---------- Run app ----------
if __name__ == "__main__":
    # Initialize DB (safe to call repeatedly)
    init_db()
    # Do not run in debug on production. Use env var PORT or default 5000.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)





















