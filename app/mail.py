"""Optional SMTP notifications. Never log passwords or reset tokens."""
import logging
import os
import smtplib
from email.message import EmailMessage

log = logging.getLogger(__name__)

def send_mail(to: str, subject: str, body: str):
    host = os.getenv("SMTP_HOST", "")
    sender = os.getenv("SMTP_FROM", "")
    if not host or not sender:
        return  # Not configured; omit notifications in local development.
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    port = int(os.getenv("SMTP_PORT", "587"))
    try:
        if port == 465:
            client = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            client = smtplib.SMTP(host, port, timeout=15)
        with client:
            if port != 465:
                client.starttls()
            username = os.getenv("SMTP_USER", "")
            password = os.getenv("SMTP_PASSWORD", "")
            if username and password:
                client.login(username, password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException):
        log.exception("SMTP delivery failed")
