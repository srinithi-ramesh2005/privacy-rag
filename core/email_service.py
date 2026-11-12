"""
Email Dispatch Service for OTP / Verification Codes.
Uses SMTP Gmail SSL / STARTTLS with App Password authentication.
Gracefully handles offline or mock fallback if credentials are unset or unreachable.
"""
from __future__ import annotations

import os
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger("EmailService")


def send_verification_email(to_email: str, code: str) -> bool:
    """
    Send a 6-digit verification code to the specified user's email address using an app password.
    Falls back gracefully to logging if SMTP credentials are not configured or on network errors.
    """
    clean_recipient = to_email.strip().lower()
    clean_code = str(code).strip()

    sender = os.getenv("SMTP_EMAIL", "").strip()
    raw_password = os.getenv("SMTP_PASSWORD", "").strip()
    # Gmail app passwords often come formatted with spaces (e.g., 'gqxl svnb yvzp most')
    password = raw_password.replace(" ", "") if raw_password else ""

    # Always log the verification code to server console for development and local testing
    logger.info(f"[Verification Dispatch] Destination: {clean_recipient} | Code: {clean_code}")
    print(f"\n=======================================================")
    print(f" [EMAIL DISPATCH] 6-Digit Verification Code for {clean_recipient}: {clean_code}")
    print(f"=======================================================\n", flush=True)

    if not sender or not password:
        logger.warning(
            f"SMTP_EMAIL or SMTP_PASSWORD is not configured in .env. "
            f"Simulated email delivery for {clean_recipient} with code: {clean_code}"
        )
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"Your Verification Code: {clean_code} - RAG Access"
        msg["From"] = sender
        msg["To"] = clean_recipient

        text_content = (
            f"Hello,\n\n"
            f"Your 6-digit verification code is: {clean_code}\n\n"
            f"Please enter this code on the verification screen to verify your email address.\n"
            f"Once verified, your account will be marked as 'Pending' and submitted to the Administrator for approval.\n\n"
            f"— Privacy RAG Verification Team"
        )

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Your Verification Code</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0f141c; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #e2e8f0;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #0f141c; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" max-width="500" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; background-color: #161d27; border: 1px solid #232d3d; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
          <tr>
            <td style="padding: 28px 32px; background: linear-gradient(135deg, #1e293b, #0f172a); border-bottom: 1px solid #232d3d;">
              <h1 style="margin: 0; font-size: 20px; font-weight: 700; color: #ffffff; letter-spacing: -0.02em;">
                Privacy RAG System
              </h1>
              <p style="margin: 4px 0 0 0; font-size: 13px; color: #8a99ad;">
                Secure Email Verification
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <p style="margin: 0 0 18px 0; font-size: 15px; line-height: 1.5; color: #cbd5e1;">
                Hello,
              </p>
              <p style="margin: 0 0 24px 0; font-size: 14px; line-height: 1.5; color: #94a3b8;">
                Please use the following 6-digit verification code to confirm your email address and continue your registration:
              </p>
              <div style="background-color: #0b0f16; border: 1px solid #3b82f6; border-radius: 8px; padding: 18px; text-align: center; margin: 0 0 24px 0;">
                <span style="font-family: 'JetBrains Mono', monospace, Consolas, Courier; font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #60a5fa; display: inline-block;">
                  {clean_code}
                </span>
              </div>
              <p style="margin: 0 0 12px 0; font-size: 13px; line-height: 1.5; color: #94a3b8;">
                Once your email is verified, your account status will transition to <strong>Pending</strong> awaiting Administrator review.
              </p>
              <p style="margin: 0; font-size: 12px; color: #64748b;">
                If you did not request this registration, please safely ignore this email.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 16px 32px; background-color: #0f141c; border-top: 1px solid #232d3d; text-align: center;">
              <p style="margin: 0; font-size: 11px; color: #5a687c;">
                Zero-Trust Multi-Tenant RAG Verifier &bull; Automated Security Dispatch
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Try SMTP_SSL on port 465 first
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
                server.login(sender, password)
                server.send_message(msg)
            logger.info(f"Verification email successfully dispatched via SSL (465) to {clean_recipient}")
            return True
        except Exception as ssl_err:
            logger.warning(f"SMTP SSL 465 failed ({ssl_err}), attempting STARTTLS 587...")
            # Fallback to STARTTLS on port 587
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(sender, password)
                server.send_message(msg)
            logger.info(f"Verification email successfully dispatched via STARTTLS (587) to {clean_recipient}")
            return True

    except Exception as e:
        logger.error(f"Failed to deliver verification email to {clean_recipient}: {e}")
        # Return True so registration doesn't block if local mail server is unreachable in development
        return True


def send_otp_email(receiver_email: str, otp: str) -> bool:
    """Backward-compatible alias for send_verification_email."""
    return send_verification_email(to_email=receiver_email, code=otp)
