import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from samokoder.core.config import get_config

def send_email(to: str, subject: str, body: str) -> bool:
    """
    Sends an email using the configured SMTP server.

    :param to: Recipient email address.
    :param subject: Email subject.
    :param body: Email body (can be HTML).
    :return: True if the email was sent successfully, False otherwise.
    """
    config = get_config()

    if not all([config.smtp_host, config.smtp_port, config.smtp_user, config.smtp_password, config.smtp_sender_email]):
        log.warning("SMTP settings are not fully configured. Skipping email notification.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender_email
        msg['To'] = to
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(config.smtp_user, config.smtp_password)
            server.send_message(msg)
            log.info(f"Email notification sent to {to}")
            return True
    except Exception as e:
        log.error(f"Failed to send email notification to {to}: {e}", exc_info=True)
        return False
