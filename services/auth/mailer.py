"""Outbound account email over SMTP (any provider: Resend, SES, Mailgun, ...).

Configured by ``PSAT_SMTP_HOST``/``PORT``/``USERNAME``/``PASSWORD`` and ``PSAT_MAIL_FROM``. Port 465 uses implicit TLS;
any other port must offer STARTTLS. Unconfigured, local dev-login setups log the message instead, so the flows can be
exercised without a provider.
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

logger = logging.getLogger(__name__)

_TIMEOUT_S = 15


def smtp_configured() -> bool:
    return bool(os.environ.get("PSAT_SMTP_HOST") and os.environ.get("PSAT_MAIL_FROM"))


def _log_instead() -> bool:
    return os.environ.get("PSAT_AUTH_DEV_LOGIN") == "1" and not os.environ.get("FLY_APP_NAME")


def can_send() -> bool:
    return smtp_configured() or _log_instead()


def send_email(to: str, subject: str, body: str) -> None:
    """Best effort: failures are logged (never the body, which carries a token) and swallowed, since callers answer
    identically whether or not mail went out.
    """
    if not smtp_configured():
        if _log_instead():
            # WARNING so the link shows whatever the local log level; never reached on Fly.
            logger.warning("dev mail (SMTP not configured)\nTo: %s\nSubject: %s\n\n%s", to, subject, body)
        return
    msg = EmailMessage()
    msg["From"] = os.environ["PSAT_MAIL_FROM"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    host = os.environ["PSAT_SMTP_HOST"]
    port = int(os.environ.get("PSAT_SMTP_PORT", "587"))
    username = os.environ.get("PSAT_SMTP_USERNAME")
    password = os.environ.get("PSAT_SMTP_PASSWORD")
    context = ssl.create_default_context()
    try:
        if port == 465:
            client = smtplib.SMTP_SSL(host, port, timeout=_TIMEOUT_S, context=context)
        else:
            client = smtplib.SMTP(host, port, timeout=_TIMEOUT_S)
            client.starttls(context=context)
        with client:
            if username:
                client.login(username, password or "")
            client.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("account email failed", extra={"exc_type": type(exc).__name__, "smtp_host": host})
