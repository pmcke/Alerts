from flask import Flask, request, abort
import sqlite3
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "stations.db")

@app.route("/unsubscribe")
def unsubscribe():
    station = request.args.get("station")
    station = station.upper()

    email = request.args.get("email")

    if not station or not email:
        abort(400)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT email FROM stations
        WHERE station = ? AND email = ?
    """, (station, email))

    row = cur.fetchone()

    if not row:
        conn.close()
        abort(404)

    cur.execute("""
        UPDATE stations
        SET unsubscribed = 1
        WHERE station = ? AND email = ?
    """, (station, email))

    conn.commit()
    conn.close()

    return f"""
    <h2>Unsubscribed</h2>
    <p>You will no longer receive alerts for station <b>{station}</b>.</p>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
