from flask import Flask, request, abort
import sqlite3
import os
import hmac
import hashlib
import html

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "stations.db")

# Put this in an env var on the Pi (recommended)
# export UNSUBSCRIBE_SECRET='some-long-random-string'
UNSUBSCRIBE_SECRET = os.environ.get("UNSUBSCRIBE_SECRET", "")

def make_sig(station: str, email: str) -> str:
    if not UNSUBSCRIBE_SECRET:
        # Fail closed if you forgot to set it
        raise RuntimeError("UNSUBSCRIBE_SECRET is not set")
    msg = f"{station}|{email}".encode("utf-8")
    return hmac.new(UNSUBSCRIBE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()

def verify_sig(station: str, email: str, sig: str) -> bool:
    try:
        expected = make_sig(station, email)
    except RuntimeError:
        return False
    return hmac.compare_digest(expected, sig or "")

@app.route("/unsubscribe", methods=["GET"])
def unsubscribe_confirm_page():
    station = (request.args.get("station") or "").strip()
    email = (request.args.get("email") or "").strip()
    sig = (request.args.get("sig") or "").strip()

    if not station or not email or not sig:
        abort(400)

    station_u = station.upper()

    # Verify signature before showing anything
    if not verify_sig(station_u, email, sig):
        abort(403)

    # Optional: check the record exists before showing confirm
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT unsubscribed FROM stations
        WHERE station = ? AND email = ?
    """, (station_u, email))
    row = cur.fetchone()
    conn.close()

    if not row:
        abort(404)

    already_unsub = int(row[0] or 0) == 1

    station_html = html.escape(station_u)
    email_html = html.escape(email)

    if already_unsub:
        return f"""
        <h2>Already unsubscribed</h2>
        <p><b>{email_html}</b> is already unsubscribed for station <b>{station_html}</b>.</p>
        """

    # Confirmation page (POST does the update)
    return f"""
    <h2>Unsubscribe?</h2>
    <p>Are you sure you want to stop alerts for station <b>{station_html}</b> to <b>{email_html}</b>?</p>

    <form method="POST" action="/unsubscribe/confirm">
        <input type="hidden" name="station" value="{station_html}">
        <input type="hidden" name="email" value="{email_html}">
        <input type="hidden" name="sig" value="{html.escape(sig)}">
        <button type="submit">Yes, unsubscribe</button>
    </form>

    <p><a href="https://www.google.com">No, take me back</a></p>
    """

@app.route("/unsubscribe/confirm", methods=["POST"])
def unsubscribe_do():
    station = (request.form.get("station") or "").strip()
    email = (request.form.get("email") or "").strip()
    sig = (request.form.get("sig") or "").strip()

    if not station or not email or not sig:
        abort(400)

    station_u = station.upper()

    if not verify_sig(station_u, email, sig):
        abort(403)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT email FROM stations
        WHERE station = ? AND email = ?
    """, (station_u, email))
    row = cur.fetchone()

    if not row:
        conn.close()
        abort(404)

    cur.execute("""
        UPDATE stations
        SET unsubscribed = 1
        WHERE station = ? AND email = ?
    """, (station_u, email))

    conn.commit()
    conn.close()

    return f"""
    <h2>Unsubscribed</h2>
    <p>You will no longer receive alerts for station <b>{html.escape(station_u)}</b>.</p>
    """

if __name__ == "__main__":
    # Keep as-is for local, but when you publish (tunnel) you typically run via systemd/gunicorn
    app.run(host="0.0.0.0", port=8080)

