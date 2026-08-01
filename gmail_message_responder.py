#!/usr/bin/env python3
"""
gmail_message_responder.py

Monitors a Gmail inbox using IMAP. When it finds an unread email from the
configured sender with the configured subject, it extracts a recipient email
address from the message body and sends a templated reply through Mailjet.

Designed to sit in the same folder as:
    camera_monitor.py
    config.ini
    gmail_responder.ini
    templates/

The script deliberately does not import camera_monitor.py because importing it
would also load its MQTT configuration and initialise its global state. Instead,
it uses the same Mailjet v3.1 API and HTML-template approach.
"""

from __future__ import annotations

import configparser
import email
import html
import imaplib
import logging
import os
import re
import signal
import sys
import time
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path
from typing import Iterable

from mailjet_rest import Client


BASE_DIR = Path(__file__).resolve().parent
RESPONDER_CONFIG_FILE = BASE_DIR / "gmail_responder.ini"
CAMERA_CONFIG_FILE = BASE_DIR / "config.ini"
TEMPLATE_DIR_PRIMARY = BASE_DIR / "templates"
TEMPLATE_DIR_FALLBACK = Path("/etc/camera-monitor/templates")

logger = logging.getLogger("gmail_message_responder")
running = True


def stop_requested(signum, frame):
    global running
    logger.info("Stop requested; exiting after the current check")
    running = False


def load_ini(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None)
    if not cfg.read(path):
        raise FileNotFoundError(f"Could not read configuration file: {path}")
    return cfg


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return str(value).strip()


def normalise_subject(value: str) -> str:
    """Collapse whitespace and compare subjects case-insensitively."""
    return " ".join((value or "").split()).casefold()


def extract_text_parts(message: Message) -> tuple[str, str]:
    """
    Return (plain_text, html_text).

    Attachments are ignored. Plain text is preferred when extracting the
    recipient address.
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []

    parts: Iterable[Message]
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.is_multipart():
            continue

        disposition = (part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue

        content_type = part.get_content_type().lower()
        if content_type not in {"text/plain", "text/html"}:
            continue

        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                text = str(part.get_payload() or "")
            else:
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
        except Exception:
            logger.exception("Could not decode one message body part")
            continue

        if content_type == "text/plain":
            plain_parts.append(text)
        else:
            html_parts.append(text)

    return "\n".join(plain_parts), "\n".join(html_parts)


def html_to_text(value: str) -> str:
    """Simple HTML-to-text conversion sufficient for locating an email address."""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value or "")
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return html.unescape(text)


def extract_recipient_email(
    body_text: str,
    extraction_regex: str,
    allowed_domains: list[str],
) -> str | None:
    """
    Extract the destination email address.

    The regular expression may either:
      * contain a named group called 'email', or
      * contain a first capturing group, or
      * match the address directly.
    """
    try:
        match = re.search(extraction_regex, body_text, flags=re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise ValueError(f"Invalid recipient_regex in gmail_responder.ini: {exc}") from exc

    if not match:
        return None

    if "email" in match.groupdict():
        candidate = match.group("email")
    elif match.lastindex:
        candidate = match.group(1)
    else:
        candidate = match.group(0)

    candidate = (candidate or "").strip().strip("<>()[]{}'\".,;:")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
        return None

    if allowed_domains:
        domain = candidate.rsplit("@", 1)[1].casefold()
        if domain not in allowed_domains:
            logger.warning("Extracted address domain is not permitted: %s", domain)
            return None

    return candidate


def load_template(filename: str) -> str:
    for directory in (TEMPLATE_DIR_PRIMARY, TEMPLATE_DIR_FALLBACK):
        path = directory / filename
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except Exception:
            logger.exception("Could not read template: %s", path)
            return ""

    logger.error(
        "Template %s was not found in %s or %s",
        filename,
        TEMPLATE_DIR_PRIMARY,
        TEMPLATE_DIR_FALLBACK,
    )
    return ""


def send_mailjet_email(
    mailjet: Client,
    from_email: str,
    from_name: str,
    recipient: str,
    subject: str,
    template_filename: str,
    template_vars: dict[str, str],
    bcc_addresses: list[str],
) -> bool:
    template = load_template(template_filename)
    if not template:
        return False

    safe_vars = {
        "recipient_email": html.escape(recipient),
        **template_vars,
    }

    try:
        body_html = template.format(**safe_vars)
    except Exception:
        logger.exception("Template formatting failed for %s", template_filename)
        return False

    message = {
        "From": {"Email": from_email, "Name": from_name},
        "To": [{"Email": recipient}],
        "Subject": subject,
        "HTMLPart": body_html,
    }

    if bcc_addresses:
        message["Bcc"] = [{"Email": address} for address in bcc_addresses]

    try:
        result = mailjet.send.create(data={"Messages": [message]})
        if result.status_code >= 300:
            logger.error("Mailjet error %s: %s", result.status_code, result.json())
            return False
    except Exception:
        logger.exception("Mailjet send failed")
        return False

    logger.info("Mailjet email sent to %s with subject %r", recipient, subject)
    return True


def mark_processed(
    mailbox: imaplib.IMAP4_SSL,
    message_id: bytes,
    processed_keyword: str,
    mark_as_read: bool,
) -> None:
    flags = []
    if mark_as_read:
        flags.append(r"\Seen")
    if processed_keyword:
        flags.append(processed_keyword)

    if flags:
        mailbox.store(message_id, "+FLAGS", f"({' '.join(flags)})")


def process_mailbox() -> int:
    responder_cfg = load_ini(RESPONDER_CONFIG_FILE)
    camera_cfg = load_ini(CAMERA_CONFIG_FILE)

    gmail_user = responder_cfg.get("gmail", "username").strip()
    gmail_password = responder_cfg.get("gmail", "password").strip()
    imap_host = responder_cfg.get("gmail", "imap_host", fallback="imap.gmail.com").strip()
    mailbox_name = responder_cfg.get("gmail", "mailbox", fallback="INBOX").strip()

    required_sender = responder_cfg.get("filter", "from_address").strip().casefold()
    required_subject = responder_cfg.get("filter", "subject").strip()
    exact_subject = responder_cfg.getboolean("filter", "exact_subject", fallback=True)
    only_unseen = responder_cfg.getboolean("filter", "only_unseen", fallback=True)

    recipient_regex = responder_cfg.get(
        "extraction",
        "recipient_regex",
        fallback=r"(?P<email>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})",
    )
    allowed_domains = [
        item.strip().casefold()
        for item in responder_cfg.get("extraction", "allowed_domains", fallback="").split(",")
        if item.strip()
    ]

    outgoing_subject = responder_cfg.get(
        "response",
        "subject",
        fallback="Thank you for your message",
    ).strip()
    template_filename = responder_cfg.get(
        "response",
        "template",
        fallback="gmail_thank_you.html",
    ).strip()
    poll_seconds = max(10, responder_cfg.getint("monitor", "poll_seconds", fallback=60))
    processed_keyword = responder_cfg.get(
        "monitor",
        "processed_keyword",
        fallback="GmailResponderProcessed",
    ).strip()
    mark_as_read = responder_cfg.getboolean("monitor", "mark_as_read", fallback=True)

    mailjet_api_key = camera_cfg.get("mailjet", "api_key", fallback="").strip()
    mailjet_secret = camera_cfg.get("mailjet", "api_secret", fallback="").strip()
    from_email = camera_cfg.get("mailjet", "from_email", fallback="").strip()
    from_name = camera_cfg.get("mailjet", "from_name", fallback="Camera Alerts").strip()
    bcc_addresses = [
        item.strip()
        for item in camera_cfg.get("mailjet", "bcc_emails", fallback="").split(",")
        if item.strip()
    ]

    missing = [
        name
        for name, value in (
            ("gmail.username", gmail_user),
            ("gmail.password", gmail_password),
            ("filter.from_address", required_sender),
            ("filter.subject", required_subject),
            ("mailjet.api_key", mailjet_api_key),
            ("mailjet.api_secret", mailjet_secret),
            ("mailjet.from_email", from_email),
        )
        if not value
    ]
    if missing:
        raise ValueError("Missing configuration value(s): " + ", ".join(missing))

    mailjet = Client(auth=(mailjet_api_key, mailjet_secret), version="v3.1")

    logger.info(
        "Monitoring %s/%s for sender=%s subject=%r every %s seconds",
        imap_host,
        mailbox_name,
        required_sender,
        required_subject,
        poll_seconds,
    )

    while running:
        mailbox = None
        try:
            mailbox = imaplib.IMAP4_SSL(imap_host)
            mailbox.login(gmail_user, gmail_password)
            status, _ = mailbox.select(mailbox_name)
            if status != "OK":
                raise RuntimeError(f"Could not select mailbox {mailbox_name!r}")

            criteria = ["UNSEEN"] if only_unseen else ["ALL"]
            if processed_keyword:
                criteria.extend(["UNKEYWORD", processed_keyword])

            status, data = mailbox.search(None, *criteria)
            if status != "OK":
                raise RuntimeError("Gmail IMAP search failed")

            message_ids = data[0].split()
            if message_ids:
                logger.info("Found %d candidate message(s)", len(message_ids))

            for message_id in message_ids:
                status, fetched = mailbox.fetch(message_id, "(RFC822)")
                if status != "OK" or not fetched or not fetched[0]:
                    logger.warning("Could not fetch Gmail message %r", message_id)
                    continue

                raw_message = fetched[0][1]
                message = email.message_from_bytes(raw_message)

                sender_header = decode_mime_header(message.get("From"))
                sender_address_match = re.search(
                    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
                    sender_header,
                    flags=re.IGNORECASE,
                )
                sender_address = (
                    sender_address_match.group(0).casefold()
                    if sender_address_match
                    else ""
                )

                actual_subject = decode_mime_header(message.get("Subject"))
                if sender_address != required_sender:
                    continue

                if exact_subject:
                    subject_matches = (
                        normalise_subject(actual_subject)
                        == normalise_subject(required_subject)
                    )
                else:
                    subject_matches = (
                        normalise_subject(required_subject)
                        in normalise_subject(actual_subject)
                    )

                if not subject_matches:
                    continue

                plain_text, html_text = extract_text_parts(message)
                body_text = plain_text.strip() or html_to_text(html_text)

                recipient = extract_recipient_email(
                    body_text,
                    recipient_regex,
                    allowed_domains,
                )
                if not recipient:
                    logger.warning(
                        "Matching Gmail message %r contained no permitted recipient address",
                        decode_mime_header(message.get("Message-ID")),
                    )
                    continue

                template_vars = {
                    "original_sender": html.escape(sender_address),
                    "original_subject": html.escape(actual_subject),
                }

                sent = send_mailjet_email(
                    mailjet=mailjet,
                    from_email=from_email,
                    from_name=from_name,
                    recipient=recipient,
                    subject=outgoing_subject,
                    template_filename=template_filename,
                    template_vars=template_vars,
                    bcc_addresses=bcc_addresses,
                )

                if sent:
                    mark_processed(
                        mailbox,
                        message_id,
                        processed_keyword,
                        mark_as_read,
                    )

            try:
                mailbox.close()
            except Exception:
                pass
            mailbox.logout()

        except imaplib.IMAP4.error:
            logger.exception(
                "Gmail IMAP login or mailbox error. For Gmail, use an app password "
                "rather than the normal account password."
            )
        except Exception:
            logger.exception("Error while checking Gmail")
        finally:
            if mailbox is not None:
                try:
                    mailbox.logout()
                except Exception:
                    pass

        for _ in range(poll_seconds):
            if not running:
                break
            time.sleep(1)

    return 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    signal.signal(signal.SIGTERM, stop_requested)
    signal.signal(signal.SIGINT, stop_requested)

    try:
        return process_mailbox()
    except Exception:
        logger.exception("Fatal configuration or startup error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
