#!/usr/bin/env python3
"""
send_welcome.py

Send a welcome/test email to a new subscriber without modifying camera_monitor.py.

Usage:
  ./send_welcome.py NZ002K

The email address is looked up from stations.db. The database path is taken from
camera_monitor.py if it exposes DB_PATH, otherwise from config.ini:
  [paths] db_path = ...
then:
  [unsubscribe] db_path = ...
and finally falls back to ./stations.db.
"""

import os
import sys
import html
import sqlite3
import configparser
from datetime import datetime, timezone

def load_env_file(path):
    if not os.path.isfile(path):
        return

    with open(path) as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)

            # Don't overwrite existing environment vars
            os.environ.setdefault(key.strip(), value.strip())


# Load optional secrets file
load_env_file("/etc/fireballsalerts/secrets.env")


def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def load_config(base_dir: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config_path = os.path.join(base_dir, "config.ini")
    config.read(config_path)
    return config


def get_db_path(base_dir: str, cm) -> str:
    """
    Prefer DB_PATH from camera_monitor.py if present, because that is what the
    alert system itself is using. Otherwise read config.ini.
    """
    cm_db_path = getattr(cm, "DB_PATH", "")
    if cm_db_path:
        return str(cm_db_path)

    config = load_config(base_dir)

    if config.has_option("paths", "db_path"):
        return config.get("paths", "db_path")

    if config.has_option("unsubscribe", "db_path"):
        return config.get("unsubscribe", "db_path")

    return os.path.join(base_dir, "stations.db")


def get_station_email(db_path: str, station_lower: str) -> str:
    if not os.path.isfile(db_path):
        die(f"Database not found: {db_path}")

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            """
            SELECT station, email, unsubscribed
            FROM stations
            WHERE lower(trim(station)) = ?
            """,
            (station_lower,),
        )
        row = cur.fetchone()
    except sqlite3.Error as e:
        die(f"Database lookup failed: {e}", code=1)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not row:
        die(f"Station {station_lower.upper()} was not found in {db_path}")

    unsubscribed = str(row["unsubscribed"] if row["unsubscribed"] is not None else "0").strip()
    if unsubscribed in ("1", "true", "True", "yes", "YES"):
        die(f"Station {station_lower.upper()} is marked as unsubscribed in {db_path}")

    email = (row["email"] or "").strip()
    if "@" not in email or "." not in email:
        die(f"Email address for station {station_lower.upper()} does not look valid: {email!r}")

    return email


def main():
    # Must be in same folder as camera_monitor.py
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cm_path = os.path.join(base_dir, "camera_monitor.py")
    if not os.path.isfile(cm_path):
        die(f"camera_monitor.py not found in {base_dir} (this script must live next to it)")

    if len(sys.argv) != 2:
        die(
            "Expected 1 argument: <camera_number>\n"
            "Example: ./send_welcome.py NZ002K",
            code=2,
        )

    station_in = (sys.argv[1] or "").strip()
    if not station_in:
        die("camera_number is blank")

    station_upper = station_in.upper()
    station_lower = station_in.lower()

    # Import camera_monitor AFTER checks, so it can read config.ini etc.
    try:
        import camera_monitor as cm
    except Exception as e:
        die(f"Failed to import camera_monitor.py: {e}")

    # Basic checks using the loaded config from camera_monitor.py
    if not getattr(cm, "FROM_EMAIL", ""):
        die("Missing [mailjet] from_email in config.ini (camera_monitor.py also warns about this)")
    if not getattr(cm, "MAILJET_API_KEY", "") or not getattr(cm, "MAILJET_SECRET", ""):
        die("Missing [mailjet] api_key/api_secret in config.ini (emails will fail)")

    db_path = get_db_path(base_dir, cm)
    email_in = get_station_email(db_path, station_lower)

    # Template name (place in templates/ folder)
    template_filename = "welcome_new_subscriber.html"

    # Load template using camera_monitor's loader (supports templates/ and fallback path)
    tpl = cm.load_template(template_filename)
    if not tpl:
        die(
            f"Template not found: {template_filename}\n"
            f"Create it in: {os.path.join(base_dir, 'templates', template_filename)}"
        )

    # Support contacts HTML (from config.ini)
    try:
        support_html = cm.build_support_contacts_html(getattr(cm, "SUPPORT_EMAILS", []))
    except Exception:
        support_html = ""

    now_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    unsubscribe_url = ""

    if hasattr(cm, "build_unsubscribe_link"):
	    unsubscribe_url = cm.build_unsubscribe_link(
         	   cm.UNSUB_BASE_URL,
                   station_upper,
                   email_in,
)
    elif hasattr(cm, "build_unsubscribe_url"):
            unsubscribe_url = cm.build_unsubscribe_url(station_lower, email_in)
    elif hasattr(cm, "make_unsubscribe_url"):
            unsubscribe_url = cm.make_unsubscribe_url(station_lower, email_in) 

    if not unsubscribe_url:
        die(
            "Unsubscribe link was blank. Check that UNSUBSCRIBE_SECRET is loaded "
            "and that mailjet.unsubscribe_url is set in config.ini."
        )

    merged = {
        "station": html.escape(station_upper),
        "station_lower": html.escape(station_lower),
        "email": html.escape(email_in),
        "sent_utc": html.escape(now_utc),
        "support_contacts": support_html or "",
        "unsubscribe_url": html.escape(unsubscribe_url),
    }

    try:
        body_html = tpl.format(**merged)
    except Exception as e:
        die(f"Template formatting failed: {e}")

    subject = f"Welcome to Camera Alerts ({station_upper}) — delivery test"

    # Build Mailjet message (reuse camera_monitor's mailjet Client + optional BCC list)
    message = {
        "From": {"Email": cm.FROM_EMAIL, "Name": getattr(cm, "FROM_NAME", "Camera Alerts")},
        "To": [{"Email": email_in}],
        "Subject": subject,
        "HTMLPart": body_html,
    }

    bcc_list = getattr(cm, "MAILJET_BCC", []) or []
    if bcc_list:
        message["Bcc"] = [{"Email": addr} for addr in bcc_list]

    data = {"Messages": [message]}

    try:
        result = cm.mailjet.send.create(data=data)
        if result.status_code >= 300:
            die(f"Mailjet error {result.status_code}: {result.json()}", code=1)
        print(f"OK: welcome email sent to {email_in} for station {station_upper}")
        print(f"DB: {db_path}")
    except Exception as e:
        die(f"Mailjet send failed: {e}", code=1)


if __name__ == "__main__":
    main()
