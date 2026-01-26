#!/usr/bin/env python3
"""
send_welcome.py

Send a welcome/test email to a new subscriber without modifying camera_monitor.py.

Usage:
  ./send_welcome.py NZ002K someone@example.com
"""

import os
import sys
import html
from datetime import datetime, timezone

def die(msg: str, code: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def main():
    # Must be in same folder as camera_monitor.py
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cm_path = os.path.join(base_dir, "camera_monitor.py")
    if not os.path.isfile(cm_path):
        die(f"camera_monitor.py not found in {base_dir} (this script must live next to it)")

    if len(sys.argv) != 3:
        die("Expected 2 arguments: <camera_number> <email_address>\n"
            "Example: ./send_welcome.py NZ002K gmn@example.com", code=2)

    station_in = (sys.argv[1] or "").strip()
    email_in = (sys.argv[2] or "").strip()

    if not station_in:
        die("camera_number is blank")
    if "@" not in email_in or "." not in email_in:
        die("email_address does not look valid")

    station_upper = station_in.strip().upper()
    station_lower = station_in.strip().lower()

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

    # Template name (place in templates/ folder)
    template_filename = "welcome_new_subscriber.html"

    # Load template using camera_monitor's loader (supports templates/ and fallback path)
    tpl = cm.load_template(template_filename)
    if not tpl:
        die(
            f"Template not found: {template_filename}\n"
            f"Create it in: {os.path.join(base_dir, 'templates', template_filename)}"
        )

    # Build unsubscribe link (will be empty if unsubscribe_url or UNSUBSCRIBE_SECRET missing)
    unsub_link = ""
    try:
        unsub_link = cm.build_unsubscribe_link(getattr(cm, "UNSUB_BASE_URL", ""), station_upper, email_in)
    except Exception:
        # Keep going; welcome email should still send
        unsub_link = ""

    # Support contacts HTML (from config.ini)
    try:
        support_html = cm.build_support_contacts_html(getattr(cm, "SUPPORT_EMAILS", []))
    except Exception:
        support_html = ""

    now_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    # Merge template vars (escape anything user-controlled)
    merged = {
        "station": html.escape(station_upper),
        "station_lower": html.escape(station_lower),
        "email": html.escape(email_in),
        "sent_utc": html.escape(now_utc),
        "unsubscribe_link": html.escape(unsub_link) if unsub_link else "",
        "unsubscribe_url": html.escape(unsub_link) if unsub_link else "",
        "support_contacts": support_html or "",
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
    except Exception as e:
        die(f"Mailjet send failed: {e}", code=1)


if __name__ == "__main__":
    main()
