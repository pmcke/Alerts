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

# Templates:
# Prefer <working directory>/templates/<template>.txt but fallback to /<working directory>/<template>.txt
TEMPLATE_DIR_PRIMARY = os.path.join(BASE_DIR, "templates")
TEMPLATE_DIR_FALLBACK = BASE_DIR

TEMPLATE_CAMERA_ONLY_DOWN = "camera_only_down.txt"
TEMPLATE_PI_AND_CAMERA_DOWN = "pi_and_camera_down.txt"
TEMPLATE_HASNT_REBOOTED = "hasnt_rebooted.txt"

# ----------------------------
# Logging (file + stdout for journalctl)
# ----------------------------
logger = logging.getLogger("camera_monitor")
# Default WARNING; change to INFO if you want per-message logs in journalctl
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

# Optional: separate "silence" timeout (no MQTT messages at all)
SILENCE_TIMEOUT_MINUTES = config.getint("monitor", "silence_timeout_minutes", fallback=TIMEOUT_MINUTES)

# Scenario C: "hasn't rebooted"
REBOOT_THRESHOLD_HOURS = config.getint("monitor", "reboot_threshold_hours", fallback=30)

# Reminder/escalation (repeat alerts, then auto-unsubscribe)
REMINDER_INTERVAL_HOURS = config.getint("monitor", "reminder_interval_hours", fallback=24)
REMINDER_MAX_REPEATS = config.getint("monitor", "reminder_max_repeats", fallback=3)

# Optional: enable/disable each scenario independently
ENABLE_SCENARIO_CAMERA_STATUS = config.getboolean("monitor", "enable_camera_status_scenario", fallback=True)
ENABLE_SCENARIO_SILENCE = config.getboolean("monitor", "enable_silence_scenario", fallback=True)
ENABLE_SCENARIO_REBOOT = config.getboolean("monitor", "enable_reboot_scenario", fallback=True)

# Mailjet
MAILJET_API_KEY = config.get("mailjet", "api_key", fallback="")
MAILJET_SECRET = config.get("mailjet", "api_secret", fallback="")
FROM_EMAIL = config.get("mailjet", "from_email", fallback="")
FROM_NAME = config.get("mailjet", "from_name", fallback="Meteor Camera Alerts")
UNSUB_BASE_URL = config.get("mailjet", "unsubscribe_url", fallback="").strip()

# Mailjet BCC (optional)
MAILJET_BCC = [
    e.strip()
    for e in config.get("mailjet", "bcc_emails", fallback="").split(",")
    if e.strip()
]

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
# Shared state
# ----------------------------
last_seen = {}  # station -> datetime (UTC), updated on ANY received MQTT message

# ----------------------------
# Database helpers
# ----------------------------
def db_connect():
    return sqlite3.connect(DB_PATH)


def get_recipient(station: str):
    """Return (email, unsubscribed) for station, or None."""
    station = (station or "").strip().lower()
    conn = db_connect()
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


def get_active_stations():
    """
    Return list of stations (lowercase) that should receive alerts:
    - Must exist in DB
    - unsubscribed = 0
    """
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT station
        FROM stations
        WHERE COALESCE(unsubscribed, 0) = 0
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [str(r[0]).strip().lower() for r in rows if r and r[0]]


def get_reboot_watch_stations():
    """
    Return list of stations (lowercase) that should receive "hasn't rebooted" alerts:
    - reboot = 1
    - unsubscribed = 0
    """
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT station
        FROM stations
        WHERE COALESCE(reboot, 0) = 1
          AND COALESCE(unsubscribed, 0) = 0
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [str(r[0]).strip().lower() for r in rows if r and r[0]]



# ----------------------------
# Alert reminder state helpers (persisted in SQLite)
# ----------------------------
def ensure_alert_state_table():
    """Create alert_state table if it doesn't exist."""
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_state (
          station TEXT NOT NULL,
          scenario TEXT NOT NULL,
          first_sent_utc TEXT NOT NULL,
          last_sent_utc  TEXT NOT NULL,
          send_count INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (station, scenario)
        )
        """
    )
    conn.commit()
    conn.close()


def clear_alert_state(station: str, scenario: str):
    station = (station or "").strip().lower()
    scenario = (scenario or "").strip()
    if not station or not scenario:
        return
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM alert_state WHERE station=? AND scenario=?",
        (station, scenario),
    )
    conn.commit()
    conn.close()


def mark_station_unsubscribed(station: str, reason: str = ""):
    station = (station or "").strip().lower()
    if not station:
        return
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "UPDATE stations SET unsubscribed=1 WHERE station=?",
        (station,),
    )
    conn.commit()
    conn.close()
    logger.warning(f"{station}: auto-unsubscribed. reason={reason}")


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def should_send_alert_now(station: str, scenario: str, now: datetime) -> str:
    """Return: 'send', 'skip', or 'auto_unsub'.

    Total allowed emails = 1 initial + REMINDER_MAX_REPEATS reminders.
    """
    station = (station or "").strip().lower()
    scenario = (scenario or "").strip()
    if not station or not scenario:
        return "skip"

    interval = timedelta(hours=REMINDER_INTERVAL_HOURS)
    max_total_sends = 1 + max(0, int(REMINDER_MAX_REPEATS))

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT last_sent_utc, send_count
        FROM alert_state
        WHERE station=? AND scenario=?
        """,
        (station, scenario),
    )
    row = cur.fetchone()

    if not row:
        # First send: create state row (send_count will become 1 after record_alert_sent)
        now_iso = _utc_iso(now)
        cur.execute(
            """
            INSERT INTO alert_state (station, scenario, first_sent_utc, last_sent_utc, send_count)
            VALUES (?, ?, ?, ?, 0)
            """,
            (station, scenario, now_iso, now_iso),
        )
        conn.commit()
        conn.close()
        return "send"

    last_sent_utc, send_count = row

    if int(send_count) >= max_total_sends:
        conn.close()
        return "auto_unsub"

    # Parse last_sent
    try:
        s = str(last_sent_utc).replace("Z", "+00:00")
        last_sent = datetime.fromisoformat(s)
        if last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=timezone.utc)
        else:
            last_sent = last_sent.astimezone(timezone.utc)
    except Exception:
        last_sent = now - interval  # fail-safe: allow send

    if (now - last_sent) < interval:
        conn.close()
        return "skip"

    conn.close()
    return "send"


def record_alert_sent(station: str, scenario: str, now: datetime):
    station = (station or "").strip().lower()
    scenario = (scenario or "").strip()
    if not station or not scenario:
        return
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE alert_state
        SET last_sent_utc=?, send_count=send_count+1
        WHERE station=? AND scenario=?
        """,
        (_utc_iso(now), station, scenario),
    )
    conn.commit()
    conn.close()


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
def load_template(template_filename: str) -> str:
    """
    Loads the email body template text.
    Supports either:
      BASE_DIR/templates/<template_filename>
      BASE_DIR/<template_filename>
    """
    for folder in (TEMPLATE_DIR_PRIMARY, TEMPLATE_DIR_FALLBACK):
        path = os.path.join(folder, template_filename)
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            continue
        except Exception:
            logger.exception(f"Could not read message template: {path}")
            return ""
    logger.error(
        f"Message template not found in "
        f"{os.path.join(TEMPLATE_DIR_PRIMARY, template_filename)} or {os.path.join(TEMPLATE_DIR_FALLBACK, template_filename)}"
    )
    return ""


# ----------------------------
# Email sending
# ----------------------------
def send_email(station: str, subject: str, template_filename: str, template_vars: dict):
    """
    Common email sender.
    - station: lowercase id (db key)
    - subject: email subject line
    - template_filename: which template file to load
    - template_vars: dict used with template.format(...)
    """
    station = (station or "").strip().lower()
    record = get_recipient(station)

    if not record:
        logger.warning(f"No DB record for {station}")
        return

    email, unsubscribed = record

    if unsubscribed:
        logger.info(f"{station}: user unsubscribed, no email sent")
        return

    template = load_template(template_filename)
    if not template:
        return

    station_upper = station.upper()
    unsubscribe_link = build_unsubscribe_link(UNSUB_BASE_URL, station_upper, email)

    # Always include station + unsubscribe_link in the template vars
    vars_full = dict(template_vars or {})
    vars_full.setdefault("station", station_upper)
    vars_full.setdefault("unsubscribe_link", unsubscribe_link or "(unsubscribe link unavailable)")

    try:
        body_text = template.format(**vars_full)
    except Exception:
        logger.exception(
            f"Template format error for {template_filename} "
            f"(check placeholders match keys: {sorted(vars_full.keys())})"
        )
        return

    # Convert text -> safe HTML with line breaks
    lines = [htmlmod.escape(line) for line in body_text.splitlines()]
    body_html = "<br>".join(lines)

    # If we have an unsubscribe link, make it a clickable anchor and append footer
    if unsubscribe_link:
        safe_url_text = htmlmod.escape(unsubscribe_link)
        safe_url_href = htmlmod.escape(unsubscribe_link, quote=True)

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
            "Subject": subject,
            "HTMLPart": f"<p>{body_html}</p>",
        }]
    }

    logger.info(f"Sending email alert for {station_upper} to {email} (template={template_filename})")
    try:
        result = mailjet.send.create(data=data)
        logger.info(f"Mailjet response: {result.status_code} {result.json()}")
        if result.status_code == 200:
            logger.info(f"Alert email sent for {station_upper}")
        else:
            logger.error(f"Mailjet error for {station_upper}")
    except Exception:
        logger.exception(f"Mailjet exception for {station_upper}")


# ======================================================================
# Scenarios (modular)
# ======================================================================

class ScenarioCameraStatusDown:
    """
    Scenario A: camera publishes meteorcams/<station>/camerastatus = 0 continuously for > TIMEOUT_MINUTES.

    - Sends initial email once the timeout is exceeded
    - If still down, re-sends every REMINDER_INTERVAL_HOURS for up to REMINDER_MAX_REPEATS reminders
    - After that, marks station unsubscribed in DB
    """
    def __init__(self, timeout_minutes: int):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.offline_since = {}  # station -> datetime when camerastatus first became 0

    def handle_mqtt(self, station: str, metric: str, payload: str, now: datetime):
        if metric != "camerastatus":
            return

        if payload == "0":
            if station not in self.offline_since:
                self.offline_since[station] = now
                logger.warning(f"{station} camerastatus=0 (first seen at {now.isoformat()})")

        elif payload == "1":
            # Condition cleared: reset reminder state
            self.offline_since.pop(station, None)
            clear_alert_state(station, "camera_status_down")

    def check_and_alert(self, now: datetime):
        for station, first_offline in list(self.offline_since.items()):
            if (now - first_offline) <= self.timeout:
                continue

            action = should_send_alert_now(station, "camera_status_down", now)

            if action == "auto_unsub":
                mark_station_unsubscribed(station, reason="camera_status_down not resolved after repeats")
                clear_alert_state(station, "camera_status_down")
                self.offline_since.pop(station, None)
                continue

            if action == "skip":
                continue

            time_str = first_offline.strftime("%Y-%m-%d %H:%M:%S UTC")
            logger.warning(
                f"{station} camerastatus still 0 for > {int(self.timeout.total_seconds()/60)} min"
            )
            send_email(
                station=station,
                subject=f"Camera offline alert: {station.upper()}",
                template_filename=TEMPLATE_CAMERA_ONLY_DOWN,
                template_vars={"time": time_str},
            )
            record_alert_sent(station, "camera_status_down", now)



class ScenarioPiAndCameraDown:
    """
    Scenario B: no MQTT messages received from a DB-listed station (unsubscribed=0)
    for > SILENCE_TIMEOUT_MINUTES.

    - Sends initial email once the silence timeout is exceeded
    - If still silent, re-sends every REMINDER_INTERVAL_HOURS for up to REMINDER_MAX_REPEATS reminders
    - After that, marks station unsubscribed in DB

    Uses TEMPLATE_PI_AND_CAMERA_DOWN
    """
    def __init__(self, timeout_minutes: int):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.silent_since = {}    # station -> datetime when silence began (approx)

    def check_and_alert(self, now: datetime):
        active = get_active_stations()

        for station in active:
            seen = last_seen.get(station)

            # If we've seen a message within the silence timeout, clear state
            if seen and (now - seen) <= self.timeout:
                self.silent_since.pop(station, None)
                clear_alert_state(station, "silence_down")
                continue

            # Start silence window (if not started yet)
            if station not in self.silent_since:
                # If we have never seen the station since service start, use "now" as best estimate
                self.silent_since[station] = seen or now
                continue

            silent_start = self.silent_since[station]

            if (now - silent_start) <= self.timeout:
                continue

            action = should_send_alert_now(station, "silence_down", now)

            if action == "auto_unsub":
                mark_station_unsubscribed(station, reason="silence_down not resolved after repeats")
                clear_alert_state(station, "silence_down")
                self.silent_since.pop(station, None)
                continue

            if action == "skip":
                continue

            last_seen_str = seen.strftime("%Y-%m-%d %H:%M:%S UTC") if seen else "unknown"
            minutes = str(int((now - seen).total_seconds() // 60)) if seen else "unknown"

            logger.warning(
                f"{station} has had no MQTT messages for > {int(self.timeout.total_seconds()/60)} min "
                f"(last seen {last_seen_str})"
            )
            send_email(
                station=station,
                subject=f"Pi/camera offline alert: {station.upper()}",
                template_filename=TEMPLATE_PI_AND_CAMERA_DOWN,
                template_vars={
                    "last_seen": last_seen_str,
                    "minutes": minutes,
                    "time": last_seen_str,  # alias for older templates that used {time}
                },
            )
            record_alert_sent(station, "silence_down", now)



class ScenarioHasntRebooted:
    """
    Scenario C: station is flagged reboot=1 in DB and unsubscribed=0,
    and the station's 'meteorcams/<station>/lastboot' timestamp is older than
    REBOOT_THRESHOLD_HOURS before now (UTC).

    - Sends initial email once threshold exceeded
    - If still stale, re-sends every REMINDER_INTERVAL_HOURS for up to REMINDER_MAX_REPEATS reminders
    - After that, marks station unsubscribed in DB

    Uses TEMPLATE_HASNT_REBOOTED.
    """
    def __init__(self, threshold_hours: int):
        self.threshold = timedelta(hours=threshold_hours)
        self.lastboot = {}  # station -> datetime (UTC) parsed from payload

    def _parse_lastboot_utc(self, s: str):
        """Parse lastboot string as UTC."""
        if not s:
            return None
        s = str(s).strip()

        # Common GMN/RMS format: "YYYY-MM-DD HH:MM:SS"
        try:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

        # Try ISO-ish variants
        try:
            s2 = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s2)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except Exception:
            return None

    def handle_mqtt(self, station: str, metric: str, payload: str, now: datetime):
        if metric != "lastboot":
            return

        parsed = self._parse_lastboot_utc(payload)
        if not parsed:
            logger.warning(f"{station} lastboot payload could not be parsed: {payload!r}")
            return

        prev = self.lastboot.get(station)
        self.lastboot[station] = parsed

        # If lastboot moved forward, the issue is likely resolved; reset reminder state
        if prev and parsed > prev:
            clear_alert_state(station, "hasnt_rebooted")

    def check_and_alert(self, now: datetime):
        watch = get_reboot_watch_stations()

        for station in watch:
            lb = self.lastboot.get(station)
            if not lb:
                # We haven't seen a lastboot for this station since service start.
                continue

            age = now - lb
            if age <= self.threshold:
                clear_alert_state(station, "hasnt_rebooted")
                continue

            hours = age.total_seconds() / 3600.0
            lb_str = lb.strftime("%Y-%m-%d %H:%M:%S UTC")

            action = should_send_alert_now(station, "hasnt_rebooted", now)

            if action == "auto_unsub":
                mark_station_unsubscribed(station, reason="hasnt_rebooted not resolved after repeats")
                clear_alert_state(station, "hasnt_rebooted")
                continue

            if action == "skip":
                continue

            logger.warning(
                f"{station} has not rebooted for {hours:.2f} hours (lastboot {lb_str})"
            )
            send_email(
                station=station,
                subject=f"Reboot failure alert: {station.upper()}",
                template_filename=TEMPLATE_HASNT_REBOOTED,
                template_vars={
                    "lastboot": lb_str,
                    "hours": f"{hours:.2f}",
                },
            )
            record_alert_sent(station, "hasnt_rebooted", now)



# ----------------------------
# MQTT callbacks
# ----------------------------
scenario_a = ScenarioCameraStatusDown(timeout_minutes=TIMEOUT_MINUTES) if ENABLE_SCENARIO_CAMERA_STATUS else None
scenario_b = ScenarioPiAndCameraDown(timeout_minutes=SILENCE_TIMEOUT_MINUTES) if ENABLE_SCENARIO_SILENCE else None
scenario_c = ScenarioHasntRebooted(threshold_hours=REBOOT_THRESHOLD_HOURS) if ENABLE_SCENARIO_REBOOT else None


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

        # Log every message only if INFO enabled
        logger.info(f"MQTT RX topic={msg.topic} payload={payload}")

        parts = msg.topic.split("/")
        if len(parts) < 3:
            return

        station = (parts[1] or "").strip().lower()
        metric = (parts[2] or "").strip().lower()
        now = datetime.now(timezone.utc)

        # Track activity (for silence scenario + debug/health)
        last_seen[station] = now

        # Feed scenario modules
        if scenario_a:
            scenario_a.handle_mqtt(station, metric, payload, now)

        if scenario_c:
            scenario_c.handle_mqtt(station, metric, payload, now)

        # (Scenario B is time-based; no per-message handling required)

    except Exception:
        logger.exception("Error processing MQTT message")


# ----------------------------
# Monitor loop
# ----------------------------
def monitor_loop():
    while True:
        now = datetime.now(timezone.utc)

        if scenario_a:
            scenario_a.check_and_alert(now)

        if scenario_b:
            scenario_b.check_and_alert(now)

        if scenario_c:
            scenario_c.check_and_alert(now)

        time.sleep(CHECK_INTERVAL)


# ----------------------------
# Main
# ----------------------------
def main():
    logger.info(
        f"Timeout minutes={TIMEOUT_MINUTES}, silence timeout minutes={SILENCE_TIMEOUT_MINUTES}, "
        f"reboot threshold hours={REBOOT_THRESHOLD_HOURS}, check interval seconds={CHECK_INTERVAL}"
    )
    logger.info(
        f"Scenarios enabled: camera_status={ENABLE_SCENARIO_CAMERA_STATUS} "
        f"silence={ENABLE_SCENARIO_SILENCE} reboot={ENABLE_SCENARIO_REBOOT}"
    )

    # Ensure DB schema exists (including alert reminder state)
    ensure_alert_state_table()

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
