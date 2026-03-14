#!/usr/bin/env python3
"""
Email the last 20 lines of camera_monitor.log.

This script reuses Mailjet/config/logging helpers from camera_monitor.py.
It is intended to be run daily at 08:00 by cron or a systemd timer.
"""

from __future__ import annotations

import argparse
import html
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import the existing camera_monitor module from the same directory
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import camera_monitor as cm


DEFAULT_LOG_PATH = Path(cm.REPORT_LOG_PATH)
DEFAULT_LINE_COUNT = 20


def tail_lines(path: Path, line_count: int = DEFAULT_LINE_COUNT) -> list[str]:
    """Return the last `line_count` lines from a text file."""
    if line_count <= 0:
        return []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [line.rstrip("\n") for line in lines[-line_count:]]



def build_subject(now_utc: datetime) -> str:
    return now_utc.strftime("Alerts log as at %Y-%m-%d %H:%M UTC")



def build_html_body(lines: list[str]) -> str:
    if lines:
        escaped_lines = "\n".join(html.escape(line) for line in lines)
    else:
        escaped_lines = "(camera_monitor.log is empty)"

    return (
        "<p>Last 20 lines in camera_monitor.log</p>"
        f"<pre style=\"font-family: monospace; white-space: pre-wrap;\">{escaped_lines}</pre>"
    )



def send_log_email(recipients: list[str], log_path: Path, line_count: int = DEFAULT_LINE_COUNT) -> None:
    recipients = [r.strip() for r in recipients if r and r.strip()]
    if not recipients:
        raise ValueError("No recipients specified")

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    now_utc = datetime.now(timezone.utc)
    subject = build_subject(now_utc)
    lines = tail_lines(log_path, line_count)
    body_html = build_html_body(lines)

    message = {
        "From": {"Email": cm.FROM_EMAIL, "Name": cm.FROM_NAME},
        "To": [{"Email": email} for email in recipients],
        "Subject": subject,
        "HTMLPart": body_html,
    }

    if cm.MAILJET_BCC:
        message["Bcc"] = [{"Email": addr} for addr in cm.MAILJET_BCC]

    data = {"Messages": [message]}
    result = cm.mailjet.send.create(data=data)

    if result.status_code >= 300:
        raise RuntimeError(f"Mailjet error {result.status_code}: {result.json()}")

    # Reuse the existing report logger so the email send is recorded in camera_monitor.log.
    cm.report_log_line(
        "system",
        "daily_log_email",
        "SENT",
        extra=f'to={";".join(recipients)} subject="{subject}"',
        when_utc=now_utc,
    )
    for bcc in cm.MAILJET_BCC:
        cm.report_log_line(
            "system",
            "daily_log_email",
            "SENT",
            extra=f'bcc={bcc} subject="{subject}"',
            when_utc=now_utc,
        )



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Email the last 20 lines of camera_monitor.log using Mailjet settings from camera_monitor.py"
    )
    parser.add_argument(
        "--to",
        required=True,
        help="Comma-separated recipient email addresses",
    )
    parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG_PATH),
        help=f"Path to the log file (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--lines",
        type=int,
        default=DEFAULT_LINE_COUNT,
        help=f"How many trailing lines to send (default: {DEFAULT_LINE_COUNT})",
    )
    return parser.parse_args()



def main() -> int:
    args = parse_args()

    recipients = [addr.strip() for addr in args.to.split(",") if addr.strip()]
    log_path = Path(args.log_file).expanduser().resolve()

    try:
        send_log_email(recipients=recipients, log_path=log_path, line_count=args.lines)
        print(f"Daily alerts log email sent to: {', '.join(recipients)}")
        return 0
    except Exception as exc:
        cm.logger.exception("Failed to send daily alerts log email")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
