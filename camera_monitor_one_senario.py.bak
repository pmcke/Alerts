#!/usr/bin/env python3

import time
import sqlite3
import logging
import configparser
import os
import sys
import hmac
import hashlib
import urllib.parse
import html as htmlmod
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt
from mailjet_rest import Client

# ----------------------------
# Paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "stations.db")
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")

# Template location:
# Prefer /home/pmcke/Alerts/templates/camera_only_down.txt but fallback to /home/pmcke/Alerts/camera_only_down.txt
MESSAGE_FILE_PRIMARY = os.path.join(BASE_DIR, "templates", "camera_only_down.txt")
MESSAGE_FILE_FALLBACK = os.path.join(BASE_DIR, "camera_only_down.txt")

# ----------------------------
# Logging (file + stdout for journalctl)
# ----------------------------
logger = logging.getLogger("camera_monitor")
logger.setLevel(logging.WARNING)

log_fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# File log
file_handler = logging.FileHandler(os.path.join(BASE_DIR, "camera_monitor.log"))
file_handler.setFormatter(log_fmt)
logger.addHandler(file_handler)

# Stdout log (captured by systemd journal)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(log_fmt)
logger.addHandler(stream_handler)

# ----------------------------
# Load config
# ----------------------------
config = configparser.ConfigParser()
read_ok = config.read(CONFIG_FILE)
if not read_ok:
    logger.error(f"Could not read config file: {CONFIG_FILE}")
    sys.exit(1)

# MQTT
MQTT_HOST = config.get("mqtt", "host", fallback="")
MQTT_PORT = config.getint("mqtt", "port", fallback=8883)
MQTT_USER = config.get("mqtt", "username", fallback="")
MQTT_PASS = config.get("mqtt", "password", fallback="")

# Monitor
CHECK_INTERVAL = config.getint("monitor", "check_interval_seconds", fallback=60)
TIMEOUT_MINUTES = config.getint("monitor", "timeout_minutes", fallback=15)

# Mailjet
MAILJET_API_KEY = config.get("mailjet", "api_key", fallback="")
MAILJET_SECRET = config.get("mailjet", "api_secret", fallback="")
FROM_EMAIL = config.get("mailjet", "from_email", fallback="")
FROM_NAME = config.get("mailjet", "from_name", fallback="Meteor Camera Alerts")
UNSUB_BASE_URL = config.get("mailjet", "unsubscribe_url", fallback="").strip()

# Unsubscribe signing secret (must match what unsubscribe.py expects)
UNSUBSCRIBE_SECRET = os.environ.get("UNSUBSCRIBE_SECRET", "").strip()

# Basic config sanity checks (don’t print secrets)
if not MQTT_HOST:
    logger.error("Missing [mqtt] host in config.ini")
    sys.exit(1)
if not MQTT_USER:
    logger.warning("Missing [mqtt] username in config.ini (broker may refuse connection)")
if not MAILJET_API_KEY or not MAILJET_SECRET:
    logger.warning("Missing Mailjet credentials (emails will fail)")
if not FROM_EMAIL:
    logger.warning("Missing Mailjet from_email (emails will fail)")
if not UNSUB_BASE_URL:
    logger.warning("Missing mailjet.unsubscribe_url in config.ini (unsubscribe links will be omitted)")
if not UNSUBSCRIBE_SECRET:
    logger.warning("UNSUBSCRIBE_SECRET env var not set (signed unsubscribe links will be omitted)")

# ----------------------------
# Mailjet setup
# ----------------------------
mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_SECRET), version="v3.1")

# ----------------------------
# State
# ----------------------------
last_seen = {}        # station -> datetime (UTC)  (still useful for debug/health)
camera_status = {}    # station -> "0" or "1"
offline_since = {}    # station -> datetime of FIRST seen camerastatus=0
alert_sent = set()    # stations already alerted for current offline period

# ----------------------------
# Database helpers
# ----------------------------
def get_recipient(station: str):
    """Return (email, unsubscribed) for station, or None."""
    station = (station or "").strip().lower()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT email, unsubscribed
        FROM stations
        WHERE station = ?
        """,
        (station,),
    )
    row = cur.fetchone()
    conn.close()
    return row


# ----------------------------
# Unsubscribe link helpers (signed)
# ----------------------------
def _hmac_sig(station_upper: str, email: str) -> str:
    msg = f"{station_upper}|{email}".encode("utf-8")
    return hmac.new(UNSUBSCRIBE_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def build_unsubscribe_link(base_url: str, station_upper: str, email: str) -> str:
    """
    Build a signed unsubscribe URL:
      <base_url>?station=STATION&email=EMAIL&sig=HMAC
    Returns "" if base_url or secret missing.
    """
    if not base_url or not UNSUBSCRIBE_SECRET:
        return ""

    sig = _hmac_sig(station_upper, email)

    parsed = urllib.parse.urlparse(base_url)
    q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    q.update({"station": station_upper, "email": email, "sig": sig})
    new_query = urllib.parse.urlencode(q)

    rebuilt = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(rebuilt)


# ----------------------------
# Template loading
# ----------------------------
def load_message_template() -> str:
    """
    Loads the email body template text.
    Supports either:
      BASE_DIR/templates/camera_only_down.txt
      BASE_DIR/camera_only_down.txt
    """
    for path in (MESSAGE_FILE_PRIMARY, MESSAGE_FILE_FALLBACK):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            continue
        except Exception:
            logger.exception(f"Could not read message template: {path}")
            return ""
    logger.error(f"Message template not found in {MESSAGE_FILE_PRIMARY} or {MESSAGE_FILE_FALLBACK}")
    return ""


# ----------------------------
# Email sending
# ----------------------------
def send_alert_email(station: str):
    station = (station or "").strip().lower()
    record = get_recipient(station)

    if not record:
        logger.warning(f"No DB record for {station}")
        return

    email, unsubscribed = record

    if unsubscribed:
        logger.info(f"{station}: user unsubscribed, no email sent")
        return

    template = load_message_template()
    if not template:
        return

    # Use first-offline time if available, otherwise "now"
    first_offline = offline_since.get(station) or datetime.now(timezone.utc)

    station_upper = station.upper()
    time_str = first_offline.strftime("%Y-%m-%d %H:%M:%S UTC")

    unsubscribe_link = build_unsubscribe_link(UNSUB_BASE_URL, station_upper, email)

    # Fill placeholders in template: {station}, {time}, {unsubscribe_link}
    try:
        body_text = template.format(
            station=station_upper,
            time=time_str,
            unsubscribe_link=unsubscribe_link or "(unsubscribe link unavailable)",
        )
    except Exception:
        logger.exception("Template format error (check {station}, {time}, {unsubscribe_link})")
        return

    # Convert text -> safe HTML with line breaks
    lines = [htmlmod.escape(line) for line in body_text.splitlines()]
    body_html = "<br>".join(lines)

    # If we have an unsubscribe link, make it a clickable anchor
    if unsubscribe_link:
        safe_url_text = htmlmod.escape(unsubscribe_link)
        safe_url_href = htmlmod.escape(unsubscribe_link, quote=True)

        # Replace the plain URL occurrence with a clickable link
        body_html = body_html.replace(
            safe_url_text,
            f'<a href="{safe_url_href}">{safe_url_text}</a>'
        )

        body_html += (
            "<hr>"
            '<p style="font-size: small;">'
            "Unsubscribe link (opens a confirmation page): "
            f'<a href="{safe_url_href}">{safe_url_text}</a>'
            "</p>"
        )


    data = {
        "Messages": [{
            "From": {"Email": FROM_EMAIL, "Name": FROM_NAME},
            "To": [{"Email": email}],
            "Subject": f"Camera offline alert: {station_upper}",
            "HTMLPart": f"<p>{body_html}</p>",
        }]
    }

    logger.info(f"Sending email alert for {station_upper} to {email}")
    try:
        result = mailjet.send.create(data=data)
        logger.info(f"Mailjet response: {result.status_code} {result.json()}")
        if result.status_code == 200:
            logger.info(f"Alert email sent for {station_upper}")
        else:
            logger.error(f"Mailjet error for {station_upper}")
    except Exception:
        logger.exception(f"Mailjet exception for {station_upper}")


# ----------------------------
# MQTT callbacks
# ----------------------------
def on_connect(client, userdata, flags, rc, properties=None):
    logger.info(f"MQTT on_connect rc={rc}")
    if rc == 0:
        logger.info("Connected to MQTT broker, subscribing to meteorcams/+/+")
        client.subscribe("meteorcams/+/+")
    else:
        logger.error("MQTT connect failed (check host/port/TLS/username/password)")


def on_disconnect(client, userdata, rc, properties=None):
    logger.warning(f"MQTT disconnected rc={rc}")


def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode(errors="ignore").strip()

        # Log EVERY message so you can confirm receipt
        logger.info(f"MQTT RX topic={msg.topic} payload={payload}")

        parts = msg.topic.split("/")
        if len(parts) < 3:
            return

        station = (parts[1] or "").strip().lower()
        metric = (parts[2] or "").strip().lower()
        now = datetime.now(timezone.utc)

        # Track activity (debug/health)
        last_seen[station] = now

        # --- Alert logic based on camerastatus ---
        if metric == "camerastatus":
            camera_status[station] = payload

            if payload == "0":
                # Start timer only the FIRST time we see 0 during this offline period
                if station not in offline_since:
                    offline_since[station] = now
                    logger.warning(f"{station} camerastatus=0 (first seen at {now.isoformat()})")

            elif payload == "1":
                # Recovery: clear timer + allow future alerts if it goes down again
                if station in offline_since:
                    started = offline_since.get(station)
                    duration = (now - started) if started else None
                    if duration:
                        mins = duration.total_seconds() / 60.0
                        logger.info(f"{station} recovered (camerastatus=1) after {mins:.1f} min offline")
                    else:
                        logger.info(f"{station} recovered (camerastatus=1)")
                offline_since.pop(station, None)
                alert_sent.discard(station)

    except Exception:
        logger.exception("Error processing MQTT message")


# ----------------------------
# Monitor loop
# ----------------------------
def monitor_loop():
    while True:
        now = datetime.now(timezone.utc)

        # Alert if camerastatus has been 0 continuously for > TIMEOUT_MINUTES
        for station, first_offline in list(offline_since.items()):
            if (now - first_offline) > timedelta(minutes=TIMEOUT_MINUTES):
                if station not in alert_sent:
                    logger.warning(f"{station} camerastatus still 0 for > {TIMEOUT_MINUTES} min")
                    logger.info(f"Looking up recipients for station {station}")
                    send_alert_email(station)
                    alert_sent.add(station)

        time.sleep(CHECK_INTERVAL)


# ----------------------------
# Main
# ----------------------------
def main():
    logger.debug(f"Starting camera monitor. MQTT host={MQTT_HOST} port={MQTT_PORT}")
    logger.info(f"Timeout minutes={TIMEOUT_MINUTES}, check interval seconds={CHECK_INTERVAL}")

    client = mqtt.Client()

    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS)

    # --- TLS: REQUIRED for HiveMQ Cloud on 8883 ---
    try:
        client.tls_set()
        client.tls_insecure_set(False)
        logger.info("MQTT TLS enabled")
    except Exception:
        logger.exception("Failed to enable MQTT TLS (required for port 8883)")
        raise

    client.reconnect_delay_set(min_delay=1, max_delay=30)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    try:
        client.connect(MQTT_HOST, MQTT_PORT, 60)
    except Exception:
        logger.exception("MQTT connect() threw an exception")
        raise

    client.loop_start()

    logger.info("Camera monitor started (MQTT loop running)")
    monitor_loop()


if __name__ == "__main__":
    main()
