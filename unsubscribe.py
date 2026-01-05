from flask import Flask, request, abort
import sqlite3
import os
import hmac
import hashlib
import html
import configparser
from pathlib import Path

app = Flask(__name__)

# -------------------------------------------------
# Paths & config
# -------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent

# Where to read config from (override with env var if you want)
CONFIG_PATH = Path(os.environ.get("UNSUBSCRIBE_CONFIG", str(BASE_DIR / "config.ini")))

config = configparser.ConfigParser()
config.read(CONFIG_PATH)

# Standardised paths (can be overridden by env vars, then config.ini, then defaults)
DB_PATH = os.environ.get(
    "UNSUBSCRIBE_DB_PATH",
    config.get("paths", "db_path", fallback=str(BASE_DIR / "stations.db")),
)

# Public base URL used in the "keep me subscribed" link
PUBLIC_BASE_URL = os.environ.get(
    "UNSUBSCRIBE_PUBLIC_BASE_URL",
    config.get("app", "public_base_url", fallback=""),
).rstrip("/")

# Secret stays in environment by default (recommended). Optional fallback to config.ini.
SECRET = os.environ.get(
    "UNSUBSCRIBE_SECRET",
    config.get("security", "unsubscribe_secret", fallback=""),
)


# -------------------------------------------------
# Sanity checks (fail fast on misconfig)
# -------------------------------------------------
def sanity_check():
    problems = []

    if not CONFIG_PATH.exists():
        problems.append(f"Config file not found: {CONFIG_PATH}")

    if not PUBLIC_BASE_URL:
        problems.append("public_base_url is not set (config [app] public_base_url or env UNSUBSCRIBE_PUBLIC_BASE_URL)")

    if not SECRET:
        problems.append("UNSUBSCRIBE_SECRET not set (env UNSUBSCRIBE_SECRET or config [security] unsubscribe_secret)")

    if not DB_PATH:
        problems.append("db_path is empty (config [paths] db_path or env UNSUBSCRIBE_DB_PATH)")
    elif not Path(DB_PATH).exists():
        problems.append(f"Database not found: {DB_PATH}")

    # DB structure check (only if the file exists)
    if DB_PATH and Path(DB_PATH).exists():
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='stations'"
            )
            if not cur.fetchone():
                problems.append("Database is missing required table: stations")

            # Optional: verify required columns exist
            cur.execute("PRAGMA table_info(stations)")
            cols = {row[1] for row in cur.fetchall()}  # row[1] = column name
            required = {"station", "email", "unsubscribed"}
            missing = required - cols
            if missing:
                problems.append(f"Database table 'stations' missing columns: {', '.join(sorted(missing))}")
            conn.close()
        except Exception as e:
            problems.append(f"Database check failed: {e!r}")

    if problems:
        msg = "Unsubscribe service configuration errors:\n- " + "\n- ".join(problems)
        raise RuntimeError(msg)

    # Helpful startup info (no secrets)
    print(f"[unsubscribe] CONFIG_PATH={CONFIG_PATH}")
    print(f"[unsubscribe] DB_PATH={DB_PATH}")
    print(f"[unsubscribe] PUBLIC_BASE_URL={PUBLIC_BASE_URL}")


sanity_check()


# -------------------------------------------------
# HMAC signing (USES UPPERCASE STATION)
# -------------------------------------------------
def make_sig(station_upper: str, email: str) -> str:
    if not SECRET:
        raise RuntimeError("UNSUBSCRIBE_SECRET not set")
    msg = f"{station_upper}|{email}".encode("utf-8")
    return hmac.new(SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_sig(station_upper: str, email: str, sig: str) -> bool:
    if not SECRET:
        return False
    expected = make_sig(station_upper, email)
    return hmac.compare_digest(expected, sig or "")


# -------------------------------------------------
# Database helpers (USE LOWERCASE STATION)
# -------------------------------------------------
def db_get_unsubscribed(station_db: str, email: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT unsubscribed FROM stations WHERE station = ? AND email = ?",
        (station_db, email),
    )
    row = cur.fetchone()
    conn.close()
    return row


def db_set_unsubscribed(station_db: str, email: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "UPDATE stations SET unsubscribed = 1 WHERE station = ? AND email = ?",
        (station_db, email),
    )
    conn.commit()
    conn.close()


# -------------------------------------------------
# GET: confirmation page
# -------------------------------------------------
@app.route("/unsubscribe", methods=["GET"])
def unsubscribe_confirm():
    station = (request.args.get("station") or "").strip()
    email = (request.args.get("email") or "").strip()
    sig = (request.args.get("sig") or "").strip()

    if not station or not email or not sig:
        return """
        <h2>Unsubscribe link required</h2>
        <p>This page must be opened using the unsubscribe link from an alert email.</p>
        <p>If you need help, contact the support team.</p>
        """, 200


    station_upper = station.upper()
    station_db = station_upper.lower()

    # Signature must match UPPERCASE station
    if not verify_sig(station_upper, email, sig):
        abort(403)

    # DB lookup must use lowercase station
    row = db_get_unsubscribed(station_db, email)
    if not row:
        abort(404)

    already = int(row[0] or 0) == 1

    station_html = html.escape(station_upper)
    email_html = html.escape(email)
    sig_html = html.escape(sig)

    if already:
        return f"""
        <h2>Already unsubscribed</h2>
        <p><b>{email_html}</b> is already unsubscribed for station <b>{station_html}</b>.</p>
        """

    return f"""
    <h2>Unsubscribe?</h2>
    <p>Are you sure you want to stop alerts for station <b>{station_html}</b> to <b>{email_html}</b>?</p>

    <form method="POST" action="/unsubscribe/confirm">
        <input type="hidden" name="station" value="{station_html}">
        <input type="hidden" name="email" value="{email_html}">
        <input type="hidden" name="sig" value="{sig_html}">
        <button type="submit">Yes, unsubscribe</button>
    </form>

    <p><a href="{PUBLIC_BASE_URL}/">No, keep me subscribed</a></p>
    """


# -------------------------------------------------
# POST: perform unsubscribe
# -------------------------------------------------
@app.route("/unsubscribe/confirm", methods=["POST"])
def unsubscribe_do():
    station = (request.form.get("station") or "").strip()
    email = (request.form.get("email") or "").strip()
    sig = (request.form.get("sig") or "").strip()

    if not station or not email or not sig:
        abort(400)

    station_upper = station.upper()
    station_db = station_upper.lower()

    # Signature check (UPPERCASE)
    if not verify_sig(station_upper, email, sig):
        abort(403)

    # DB lookup/update (lowercase)
    row = db_get_unsubscribed(station_db, email)
    if not row:
        abort(404)

    db_set_unsubscribed(station_db, email)

    return f"""
    <h2>Unsubscribed</h2>
    <p>You will no longer receive alerts for station <b>{html.escape(station_upper)}</b>.</p>
    """


# -------------------------------------------------
# Run locally only (Cloudflare Tunnel exposes it)
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081)
