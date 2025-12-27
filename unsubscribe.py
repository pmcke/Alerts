from flask import Flask, request, abort
import sqlite3
import os
import hmac
import hashlib
import html

app = Flask(__name__)

DB_PATH = "/home/pmcke/Alerts/stations.db"
SECRET = os.environ.get("UNSUBSCRIBE_SECRET", "")


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
        abort(400)

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

    <p><a href="https://alerts.mckellar.nz/">No, keep me subscribed</a></p>
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
