#!/usr/bin/env python3

import time
import sqlite3
import logging
import configparser
import os
import sys
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt
from mailjet_rest import Client

# ----------------------------
# Paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "stations.db")
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")
MESSAGE_FILE = os.path.join(BASE_DIR, "templates", "camera_only_down.txt")

# ----------------------------
# Logging (file + stdout for journalctl)
# ----------------------------
logger = logging.getLogger("camera_monitor")
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.INFO)

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
UNSUB_BASE_URL = config.get("mailjet", "unsubscribe_url", fallback="")

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

# ----------------------------
# Mailjet setup
# ----------------------------
mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_SECRET), version="v3.1")

# ----------------------------
# State
# ----------------------------
last_seen = {}        # station -> datetime (UTC)   (still useful for "is it alive" info)
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

    try:
        with open(MESSAGE_FILE, encoding="utf-8") as f:
            body = f.read()
    except Exception:
        logger.exception(f"Could not read message template: {MESSAGE_FILE}")
        return

    unsubscribe_link = ""
    if UNSUB_BASE_URL:
        unsubscribe_link = f"{UNSUB_BASE_URL}?station={station}&email={email}"

    html = f"""
    <p>{body}</p>
    <hr>
    <p style="font-size: small;">
      To stop receiving these alerts,
      <a href="{unsubscribe_link}">unsubscribe here</a>.
    </p>
    """ if unsubscribe_link else f"<p>{body}</p>"

    data = {
        "Messages": [{
            "From": {
                "Email": FROM_EMAIL,
                "Name": FROM_NAME
            },
            "To": [{
                "Email": email
            }],
            "Subject": f"Camera offline alert: {station}",
            "HTMLPart": html
        }]
    }

    logger.info(f"Sending email alert for {station} to {email}")
    try:
        result = mailjet.send.create(data=data)
        logger.info(f"Mailjet response: {result.status_code} {result.json()}")
        if result.status_code == 200:
            logger.info(f"Alert email sent for {station}")
        else:
            logger.error(f"Mailjet error for {station}")
    except Exception:
        logger.exception(f"Mailjet exception for {station}")


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

        # Track activity (not used for alerting anymore, but handy for debugging/health)
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
