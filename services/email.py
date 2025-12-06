"""Email service for sending verification emails using Resend"""
import os
import asyncio
import resend
from resend.exceptions import ResendError
from dotenv import load_dotenv

load_dotenv()

# Resend configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")

# Initialize Resend API key (lazy initialization)
_resend_initialized = False


def _ensure_resend_initialized():
    """Ensure Resend API key is set"""
    global _resend_initialized
    if not _resend_initialized:
        if not RESEND_API_KEY:
            raise ValueError(
                "RESEND_API_KEY not configured. Please set RESEND_API_KEY in .env"
            )
        if not EMAIL_FROM:
            raise ValueError(
                "EMAIL_FROM not configured. Please set EMAIL_FROM in .env (e.g., 'onboarding@resend.dev' or 'noreply@yourdomain.com')"
            )
        resend.api_key = RESEND_API_KEY
        _resend_initialized = True


async def send_verification_email(email: str, username: str, verification_token: str, frontend_url: str):
    """Send email verification email using Resend"""
    _ensure_resend_initialized()
    
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
    
    params = {
        "from": EMAIL_FROM,
        "to": [email],
        "subject": "Verify Your Email Address",
        "html": html_content,
    }
    
    # Resend API is synchronous, so we run it in a thread pool to avoid blocking
    try:
        await asyncio.to_thread(resend.Emails.send, params)
    except ResendError as e:
        # Re-raise Resend errors with original message for better error handling
        raise Exception(f"Failed to send verification email via Resend: {str(e)}")
    except Exception as e:
        # Catch any other unexpected errors
        raise Exception(f"Failed to send verification email via Resend: {str(e)}")


async def send_password_reset_email(email: str, username: str, reset_token: str, frontend_url: str):
    """Send password reset email using Resend"""
    _ensure_resend_initialized()
    
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
    
    params = {
        "from": EMAIL_FROM,
        "to": [email],
        "subject": "Reset Your Password",
        "html": html_content,
    }
    
    # Resend API is synchronous, so we run it in a thread pool to avoid blocking
    try:
        await asyncio.to_thread(resend.Emails.send, params)
    except ResendError as e:
        # Re-raise Resend errors with original message for better error handling
        raise Exception(f"Failed to send password reset email via Resend: {str(e)}")
    except Exception as e:
        # Catch any other unexpected errors
        raise Exception(f"Failed to send password reset email via Resend: {str(e)}")
