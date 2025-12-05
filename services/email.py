"""Email service for sending verification emails"""
import os
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

# Email configuration - lazy initialization to avoid errors if env vars not set
_conf: Optional[ConnectionConfig] = None
_fastmail: Optional[FastMail] = None


def get_email_config() -> ConnectionConfig:
    """Get email configuration, creating it if needed"""
    global _conf
    if _conf is None:
        MAIL_USERNAME = os.getenv("MAIL_USERNAME")
        MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
        MAIL_FROM = os.getenv("MAIL_FROM")
        MAIL_PORT = int(os.getenv("MAIL_PORT", "465"))  # Default to 465 (SSL) instead of 587 (STARTTLS)
        MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
        MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "ATS Backend")
        
        if not MAIL_USERNAME or not MAIL_PASSWORD or not MAIL_FROM:
            raise ValueError(
                "Email configuration missing. Please set MAIL_USERNAME, MAIL_PASSWORD, and MAIL_FROM in .env"
            )
        
        # Determine if we should validate certificates (disable in development if needed)
        ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
        validate_certs = ENVIRONMENT == "production"
        
        # Use SSL/TLS (port 465) instead of STARTTLS (port 587) for better cloud compatibility
        # Port 465 uses SSL from the start, which is more reliable on cloud platforms like Render
        use_ssl = MAIL_PORT == 465
        use_starttls = MAIL_PORT == 587
        
        _conf = ConnectionConfig(
            MAIL_USERNAME=MAIL_USERNAME,
            MAIL_PASSWORD=MAIL_PASSWORD,
            MAIL_FROM=MAIL_FROM,
            MAIL_PORT=MAIL_PORT,
            MAIL_SERVER=MAIL_SERVER,
            MAIL_FROM_NAME=MAIL_FROM_NAME,
            MAIL_STARTTLS=use_starttls,
            MAIL_SSL_TLS=use_ssl,
            USE_CREDENTIALS=True,
            VALIDATE_CERTS=validate_certs
        )
    return _conf


def get_fastmail() -> FastMail:
    """Get FastMail instance, creating it if needed"""
    global _fastmail
    if _fastmail is None:
        _fastmail = FastMail(get_email_config())
    return _fastmail


async def send_verification_email(email: str, username: str, verification_token: str, frontend_url: str):
    """Send email verification email"""
    verification_url = f"{frontend_url}/email-verify?token={verification_token}"
    
    html_content = f"""
    <html>
    <body>
        <h2>Welcome to ATS Backend, {username}!</h2>
        <p>Thank you for registering. Please verify your email address by clicking the link below:</p>
        <p><a href="{verification_url}">Verify Email Address</a></p>
        <p>Or copy and paste this link into your browser:</p>
        <p>{verification_url}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't create an account, please ignore this email.</p>
    </body>
    </html>
    """
    
    message = MessageSchema(
        subject="Verify Your Email Address",
        recipients=[email],
        body=html_content,
        subtype="html"
    )
    
    fastmail = get_fastmail()
    await fastmail.send_message(message)


async def send_password_reset_email(email: str, username: str, reset_token: str, frontend_url: str):
    """Send password reset email"""
    reset_url = f"{frontend_url}/reset-pwd?token={reset_token}"
    
    html_content = f"""
    <html>
    <body>
        <h2>Password Reset Request</h2>
        <p>Hello {username},</p>
        <p>You requested to reset your password. Click the link below to reset it:</p>
        <p><a href="{reset_url}">Reset Password</a></p>
        <p>Or copy and paste this link into your browser:</p>
        <p>{reset_url}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email.</p>
    </body>
    </html>
    """
    
    message = MessageSchema(
        subject="Reset Your Password",
        recipients=[email],
        body=html_content,
        subtype="html"
    )
    
    fastmail = get_fastmail()
    await fastmail.send_message(message)

