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
# Logging
# ----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("camera_monitor")

# ----------------------------
# Paths
# ----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Default DB + config paths (can be overridden in config.ini if you add entries later)
DB_PATH = os.path.join(BASE_DIR, "stations.db")
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")

# Templates: primary (your working dir) + fallback (system path)
TEMPLATE_DIR_PRIMARY = os.path.join(BASE_DIR, "templates")
TEMPLATE_DIR_FALLBACK = "/etc/camera-monitor/templates"

TEMPLATE_CAMERA_ONLY_DOWN = "camera_only_down.html"
TEMPLATE_PI_AND_CAMERA_DOWN = "pi_and_camera_down.html"
TEMPLATE_HASNT_REBOOTED = "hasnt_rebooted.html"

# ----------------------------
# Load config
# ----------------------------
config = configparser.ConfigParser()
read_ok = config.read(CONFIG_FILE)
if not read_ok:
    logger.error(f"Could not read config file: {CONFIG_FILE}")
    sys.exit(1)

# ----------------------------
# Apply logging level from config.ini (after config is loaded)
# ----------------------------
LOG_LEVEL_STR = config.get("logging", "level", fallback="INFO").upper().strip()
LOG_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}
LOG_LEVEL = LOG_LEVEL_MAP.get(LOG_LEVEL_STR, logging.INFO)

# Update root logger + any existing handlers (journald)
root_logger = logging.getLogger()
root_logger.setLevel(LOG_LEVEL)
for h in root_logger.handlers:
    try:
        h.setLevel(LOG_LEVEL)
    except Exception:
        pass

logger.setLevel(LOG_LEVEL)
logger.info(f"Logging level set to {LOG_LEVEL_STR}")

# MQTT
MQTT_HOST = config.get("mqtt", "host", fallback="")
MQTT_PORT = config.getint("mqtt", "port", fallback=8883)
MQTT_USER = config.get("mqtt", "username", fallback="")
MQTT_PASS = config.get("mqtt", "password", fallback="")
MQTT_TOPIC = config.get("mqtt", "topic", fallback="meteorcams/#")

MQTT_TLS = config.getboolean("mqtt", "tls", fallback=(MQTT_PORT == 8883))
# Optional: allow insecure TLS (NOT recommended) if you are debugging cert issues
MQTT_TLS_INSECURE = config.getboolean("mqtt", "tls_insecure", fallback=False)

# Monitor
CHECK_INTERVAL = config.getint("monitor", "check_interval_seconds", fallback=60)
TIMEOUT_MINUTES = config.getint("monitor", "timeout_minutes", fallback=15)

# Optional: separate "silence" timeout (no MQTT messages at all)
SILENCE_TIMEOUT_MINUTES = config.getint("monitor", "silence_timeout_minutes", fallback=25)

# If NOTHING arrives from MQTT at all for this long, treat it as a local/server outage
# and suppress Scenario PiAndCameraDown emails (prevents “email burst” when MQTT returns).
GLOBAL_OUTAGE_MINUTES = config.getint("monitor", "global_outage_minutes", fallback=10)

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
FROM_NAME = config.get("mailjet", "from_name", fallback="Camera Alerts")

# Unsubscribe URL base (points to your unsubscribe web service)
UNSUB_BASE_URL = config.get("mailjet", "unsubscribe_url", fallback="").strip()

# Optional Mailjet BCC list (comma-separated in config.ini)
MAILJET_BCC = [
    e.strip() for e in config.get("mailjet", "bcc_emails", fallback="").split(",") if e.strip()
]

# Support contacts shown inside email templates (comma-separated)
SUPPORT_EMAILS = [
    e.strip()
    for e in config.get("mailjet", "support_emails", fallback="").split(",")
    if e.strip()
]

def build_support_contacts_html(emails):
    """
    Returns HTML like:
      x@y (<a href="mailto:x@y">x@y</a>)<br>...
    Currently shows email only; names can be added later.
    """
    if not emails:
        return ""

    lines = []
    for e in emails:
        esc = htmlmod.escape(e)
        lines.append(f'{esc} (<a href="mailto:{esc}">{esc}</a>)')

    return "<br>".join(lines)


# Secret used to HMAC-sign unsubscribe links (recommended in env var)
UNSUBSCRIBE_SECRET = os.environ.get("UNSUBSCRIBE_SECRET", "")

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
if not SUPPORT_EMAILS:
    logger.warning("No mailjet.support_emails configured (support_contacts placeholder will be empty)")
if not UNSUBSCRIBE_SECRET:
    logger.warning("UNSUBSCRIBE_SECRET env var not set (signed unsubscribe links will be omitted)")

# ----------------------------
# Mailjet setup
# ----------------------------
mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_SECRET), version="v3.1")

# ----------------------------
# Shared state
# ----------------------------
last_seen = {}        # station -> datetime (UTC), updated on ANY received MQTT message
last_any_mqtt = None  # datetime (UTC) of last MQTT message from ANY station


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
        WHERE LOWER(station) = ?
        LIMIT 1
        """,
        (station,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    email = (row[0] or "").strip()
    unsubscribed = int(row[1] or 0)
    return email, unsubscribed


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
    Return list of stations (lowercase) that should be checked for reboot issues:
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
    candidates = [
        os.path.join(TEMPLATE_DIR_PRIMARY, template_filename),
        os.path.join(TEMPLATE_DIR_FALLBACK, template_filename),
    ]
    for path in candidates:
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

    station_upper = station.upper()
    unsub_link = build_unsubscribe_link(UNSUB_BASE_URL, station_upper, email)

    tpl = load_template(template_filename)
    if not tpl:
        logger.error(f"{station}: template missing {template_filename}, cannot send email")
        return

    merged = dict(template_vars or {})
    merged.setdefault("station", htmlmod.escape(station_upper))
    merged.setdefault("unsubscribe_link", htmlmod.escape(unsub_link) if unsub_link else "")
    merged.setdefault("unsubscribe_url", htmlmod.escape(unsub_link) if unsub_link else "")
    merged.setdefault("support_contacts", build_support_contacts_html(SUPPORT_EMAILS))

    try:
        body_html = tpl.format(**merged)
    except Exception:
        logger.exception(f"{station}: template formatting failed for {template_filename}")
        return

    message = {
        "From": {"Email": FROM_EMAIL, "Name": FROM_NAME},
        "To": [{"Email": email}],
        "Subject": subject,
        "HTMLPart": body_html,
    }

    # Optional BCC
    if MAILJET_BCC:
        message["Bcc"] = [{"Email": addr} for addr in MAILJET_BCC]

    data = {"Messages": [message]}

    try:
        result = mailjet.send.create(data=data)
        if result.status_code >= 300:
            logger.error(f"{station}: Mailjet error {result.status_code}: {result.json()}")
        else:
            logger.info(f"{station}: email sent: {subject}")
    except Exception:
        logger.exception(f"{station}: Mailjet send failed")


# ----------------------------
# Scenarios
# ----------------------------
class ScenarioCameraStatusDown:
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
            send_email(
                station=station,
                subject=f"Camera offline alert: {station.upper()}",
                template_filename=TEMPLATE_CAMERA_ONLY_DOWN,
                template_vars={"time": time_str},
            )
            record_alert_sent(station, "camera_status_down", now)


class ScenarioPiAndCameraDown:
    def __init__(self, timeout_minutes: int):
        self.timeout = timedelta(minutes=timeout_minutes)
        self.silent_since = {}

    def check_and_alert(self, now: datetime):
        active = get_active_stations()

        # -------- Global outage suppression --------
        outage_threshold = timedelta(minutes=GLOBAL_OUTAGE_MINUTES)

        # On startup (last_any_mqtt is None), suppress but DO NOT clear DB state.
        if last_any_mqtt is None:
            logger.warning(
                "Global MQTT silence: no messages received yet (startup). "
                "Suppressing PiAndCameraDown only."
            )
            self.silent_since.clear()  # in-memory only
            return

        # After startup, treat extended silence as local/server outage and clear state to avoid bursts
        if (now - last_any_mqtt) > outage_threshold:
            mins = (now - last_any_mqtt).total_seconds() / 60.0
            logger.warning(
                f"Global MQTT silence: no messages for {mins:.1f} minutes "
                f"(threshold {GLOBAL_OUTAGE_MINUTES}m). "
                "Suppressing PiAndCameraDown and clearing silence state."
            )
            self.silent_since.clear()
            for station in active:
                clear_alert_state(station, "silence_down")
            return
        # ------------------------------------------

        for station in active:
            seen = last_seen.get(station)

            if seen and (now - seen) <= self.timeout:
                self.silent_since.pop(station, None)
                clear_alert_state(station, "silence_down")
                continue

            if station not in self.silent_since:
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

            since_dt = seen or silent_start
            last_seen_str = since_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            minutes = str(int((now - since_dt).total_seconds() // 60))

            send_email(
                station=station,
                subject=f"Pi/camera offline alert: {station.upper()}",
                template_filename=TEMPLATE_PI_AND_CAMERA_DOWN,
                template_vars={
                    "last_seen": last_seen_str,
                    "minutes": minutes,
                    "time": last_seen_str,
                },
            )
            record_alert_sent(station, "silence_down", now)


class ScenarioHasntRebooted:
    def __init__(self, threshold_hours: int):
        self.threshold = timedelta(hours=threshold_hours)
        self.lastboot = {}

    def _parse_lastboot_utc(self, s: str):
        if not s:
            return None
        s = str(s).strip()

        try:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

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

        if prev and parsed > prev:
            clear_alert_state(station, "hasnt_rebooted")

    def check_and_alert(self, now: datetime):
        if (last_any_mqtt is None) or ((now - last_any_mqtt) > timedelta(minutes=GLOBAL_OUTAGE_MINUTES)):
            logger.warning("Global MQTT silence — suppressing HasntRebooted checks")
            return

        watch = get_reboot_watch_stations()

        for station in watch:
            lb = self.lastboot.get(station)
            if not lb:
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


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("MQTT connected OK")
        client.subscribe(MQTT_TOPIC)
        logger.info(f"Subscribed to {MQTT_TOPIC}")
    else:
        logger.error(f"MQTT connection failed rc={rc}")


def on_disconnect(client, userdata, rc):
    # rc == 0 means clean disconnect
    logger.warning(f"MQTT disconnected rc={rc}")


def on_message(client, userdata, msg):
    try:
        topic = (msg.topic or "").strip()
        payload = msg.payload.decode("utf-8", errors="ignore").strip()

        logger.debug("MQTT RX topic=%s payload=%s", topic, payload[:200])

        parts = topic.split("/")
        if len(parts) < 3:
            return

        if parts[0].lower() != "meteorcams":
            return

        station = (parts[1] or "").strip().lower()
        metric = (parts[2] or "").strip().lower()
        now = datetime.now(timezone.utc)

        global last_any_mqtt
        last_any_mqtt = now

        last_seen[station] = now

        if scenario_a:
            scenario_a.handle_mqtt(station, metric, payload, now)

        if scenario_c:
            scenario_c.handle_mqtt(station, metric, payload, now)

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
    # --- Hardening / debug: log resolved paths ---
    logger.info(f"BASE_DIR={BASE_DIR}")
    logger.info(f"CONFIG_FILE={CONFIG_FILE}")
    logger.info(f"DB_PATH={DB_PATH}")
    logger.info(f"TEMPLATE_DIR_PRIMARY={TEMPLATE_DIR_PRIMARY}")
    logger.info(f"TEMPLATE_DIR_FALLBACK={TEMPLATE_DIR_FALLBACK}")
    # --------------------------------------------

    logger.info(
        f"Timeout minutes={TIMEOUT_MINUTES}, silence timeout minutes={SILENCE_TIMEOUT_MINUTES}, "
        f"global outage minutes={GLOBAL_OUTAGE_MINUTES}, reboot threshold hours={REBOOT_THRESHOLD_HOURS}, "
        f"check interval seconds={CHECK_INTERVAL}"
    )
    logger.info(
        f"Scenarios enabled: camera_status={ENABLE_SCENARIO_CAMERA_STATUS} "
        f"silence={ENABLE_SCENARIO_SILENCE} reboot={ENABLE_SCENARIO_REBOOT}"
    )

    if MAILJET_BCC:
        logger.info(f"Mailjet BCC enabled ({len(MAILJET_BCC)} recipient(s))")
    else:
        logger.info("Mailjet BCC not configured")

    ensure_alert_state_table()

    client = mqtt.Client()

    # Route paho-mqtt internal logging through our logger (respects config.ini log level)
    client.enable_logger(logger)

    # TLS: HiveMQ Cloud on port 8883 requires TLS
    if MQTT_TLS:
        try:
            client.tls_set()  # uses system CA certs
            client.tls_insecure_set(MQTT_TLS_INSECURE)
            logger.info(f"MQTT TLS enabled (insecure={MQTT_TLS_INSECURE})")
        except Exception:
            logger.exception("Failed to configure MQTT TLS")
            raise

    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    logger.info(f"Connecting to MQTT host={MQTT_HOST} port={MQTT_PORT} topic={MQTT_TOPIC}")

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
