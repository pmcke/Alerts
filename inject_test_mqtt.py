#!/usr/bin/env python3
"""
Inject test MQTT messages into the camera-monitor system.

Examples:
  # Trigger reboot scenario (31 hours ago)
  ./inject_test_mqtt.py --station nz002k --lastboot-hours-ago 31

  # Send a fresh lastboot (should NOT trigger)
  ./inject_test_mqtt.py --station nz002k --lastboot-hours-ago 1

  # Also send a cameraStatus=1 message (optional)
  ./inject_test_mqtt.py --station nz002k --lastboot-hours-ago 31 --also-camerastatus 1
"""

import argparse
import configparser
import os
import sys
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(BASE_DIR, "config.ini")


def load_mqtt_config(config_path: str):
    cfg = configparser.ConfigParser()
    if not cfg.read(config_path):
        raise RuntimeError(f"Could not read config file: {config_path}")

    host = cfg.get("mqtt", "host", fallback="").strip()
    port = cfg.getint("mqtt", "port", fallback=8883)
    user = cfg.get("mqtt", "username", fallback="").strip()
    pw = cfg.get("mqtt", "password", fallback="").strip()

    if not host:
        raise RuntimeError("Missing [mqtt] host in config.ini")

    return host, port, user, pw


def fmt_lastboot_utc(dt: datetime) -> str:
    # Matches what your stations send: "YYYY-MM-DD HH:MM:SS" (UTC)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="Path to config.ini (default: ./config.ini)")
    ap.add_argument("--station", required=True, help="Station name, e.g. nz002k")
    ap.add_argument("--lastboot-hours-ago", type=float, default=31.0,
                    help="How many hours ago to set lastboot (default: 31 = should trigger 30h threshold)")
    ap.add_argument("--topic-prefix", default="meteorcams", help="Topic prefix (default: meteorcams)")
    ap.add_argument("--retain", action="store_true", help="Publish retained messages")
    ap.add_argument("--qos", type=int, default=1, choices=[0, 1, 2], help="MQTT QoS (default: 1)")

    ap.add_argument("--also-camerastatus", choices=["0", "1"], help="Also publish meteorcams/<station>/camerastatus")
    ap.add_argument("--also-heartbeat", action="store_true",
                    help="Also publish meteorcams/<station>/heartbeat with current UTC ISO timestamp")

    args = ap.parse_args()

    station = args.station.strip().lower()
    now = datetime.now(timezone.utc)
    lastboot_dt = now - timedelta(hours=args.lastboot_hours_ago)
    lastboot_str = fmt_lastboot_utc(lastboot_dt)

    host, port, user, pw = load_mqtt_config(args.config)

    client = mqtt.Client()
    if user:
        client.username_pw_set(user, pw)

    # TLS on 8883 (matches your camera-monitor approach)
    client.tls_set()
    client.tls_insecure_set(False)

    # Connect
    client.connect(host, port, 60)
    client.loop_start()

    # Publish lastboot
    topic_lastboot = f"{args.topic_prefix}/{station}/lastboot"
    print(f"Publishing {topic_lastboot} = {lastboot_str} (UTC), retain={args.retain}, qos={args.qos}")
    client.publish(topic_lastboot, payload=lastboot_str, qos=args.qos, retain=args.retain)

    # Optional extra topics
    if args.also_camerastatus is not None:
        topic_cs = f"{args.topic_prefix}/{station}/camerastatus"
        print(f"Publishing {topic_cs} = {args.also_camerastatus}")
        client.publish(topic_cs, payload=args.also_camerastatus, qos=args.qos, retain=args.retain)

    if args.also_heartbeat:
        topic_hb = f"{args.topic_prefix}/{station}/heartbeat"
        hb_payload = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"Publishing {topic_hb} = {hb_payload}")
        client.publish(topic_hb, payload=hb_payload, qos=args.qos, retain=args.retain)

    # Give the network a moment to send
    client.loop_stop()
    client.disconnect()
    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
