"""Email-based user registration and authentication routes"""
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from sqlalchemy.orm import selectinload
from jose import JWTError, jwt
import bcrypt
from database import get_db
from models import User, EmailVerification, PasswordReset
from schemas.user import UserRegister, UserResponse, UserLogin, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest
from services.email import send_verification_email, send_password_reset_email
from services.cloudinary import upload_image, delete_image

# Load environment variables
load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
EMAIL_VERIFICATION_EXPIRATION_HOURS = 1
PASSWORD_RESET_EXPIRATION_HOURS = 1


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    # Ensure password is bytes
    password_bytes = plain_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    # Ensure password is bytes
    password_bytes = password.encode('utf-8')
    # Generate salt and hash password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    # Return as string
    return hashed.decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    if not JWT_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET_KEY not configured"
        )
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """Verify and decode JWT token"""
    if not JWT_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET_KEY not configured"
        )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user with email and password"""
    # Clean up unverified accounts older than 5 minutes (for testing - change to 24 hours in production)
    # Use database time for consistency - ensures timezone and clock synchronization
    # Use direct SQL DELETE to avoid loading relationships that may not exist in the database
    await db.execute(
        text("""
            DELETE FROM users 
            WHERE email_verified = false 
            AND created_at < NOW() - INTERVAL '5 minutes'
        """)
    )
    await db.flush()
    
    # Check if email already exists
    existing_user_result = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    existing_user = existing_user_result.scalar_one_or_none()
    
    if existing_user:
        # If email exists (verified or not), reject registration
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Check if username already exists (only for new registrations)
    # Username is reserved even if email is not verified
    existing_username = await db.execute(
        select(User).where(User.username == user_data.username)
    )
    if existing_username.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )
    
    # Hash password
    password_hash = get_password_hash(user_data.password)
    
    # Create new user
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        email_verified=False,
        is_active=True
    )
    db.add(user)
    await db.flush()  # Get user ID
    
    # Generate verification token
    verification_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_EXPIRATION_HOURS)
    
    # Create email verification record
    email_verification = EmailVerification(
        user_id=user.id,
        token=verification_token,
        expires_at=expires_at
    )
    db.add(email_verification)
    await db.commit()
    
    # Refresh user to ensure all attributes are loaded
    await db.refresh(user)
    
    # Send verification email
    try:
        await send_verification_email(
            email=user.email,
            username=user.username,
            verification_token=verification_token,
            frontend_url=FRONTEND_URL
        )
        print(f"Verification email sent successfully to {user.email}")
    except Exception as e:
        # Log error but don't fail registration
        print(f"Failed to send verification email to {user.email}: {e}")
        import traceback
        traceback.print_exc()
        # User is still created, they can request a new verification email
    
    return user


@router.get("/verify-email")
async def verify_email(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db)
):
    """Verify user email with token"""
    if not token:
        raise HTTPException(status_code=400, detail="Verification token is required")
    
    # Find verification record with user relationship loaded
    result = await db.execute(
        select(EmailVerification)
        .options(selectinload(EmailVerification.user))
        .where(EmailVerification.token == token)
    )
    email_verification = result.scalar_one_or_none()
    
    if not email_verification:
        print(f"Verification token not found: {token[:20]}...")
        raise HTTPException(status_code=400, detail="Invalid verification token")
    
    # Check if already verified
    if email_verification.verified_at:
        print(f"Token already verified: {token[:20]}...")
        raise HTTPException(status_code=400, detail="Email already verified")
    
    # Check if expired
    if datetime.now(timezone.utc) > email_verification.expires_at:
        print(f"Token expired: {token[:20]}... (expired at {email_verification.expires_at})")
        raise HTTPException(status_code=400, detail="Verification token has expired")
    
    # Get user (should be loaded via selectinload)
    user = email_verification.user
    
    if not user:
        print(f"User not found for token: {token[:20]}...")
        raise HTTPException(status_code=404, detail="User not found")
    
    # Mark email as verified
    user.email_verified = True
    email_verification.verified_at = datetime.now(timezone.utc)
    
    await db.commit()
    # Refresh user to ensure all attributes (including updated_at) are loaded
    await db.refresh(user)
    print(f"Email verified successfully for user: {user.email}")
    
    # Create JWT token to automatically log the user in
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username
    }
    jwt_token = create_access_token(token_data)
    
    # Determine secure setting based on request protocol (HTTPS detection)
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
    
    # Check if request is over HTTPS
    # 1. Check X-Forwarded-Proto header (set by proxies like Render)
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
    # 2. Check request URL scheme
    url_scheme = request.url.scheme
    # 3. Check if FRONTEND_URL is HTTPS (indicates production)
    frontend_is_https = FRONTEND_URL.startswith("https://")
    
    # Determine if we should use secure cookies
    is_https = (
        forwarded_proto == "https" or 
        url_scheme == "https" or 
        frontend_is_https or 
        ENVIRONMENT == "production"
    )
    is_secure = is_https  # Use HTTPS detection
    
    # Create JSON response with user data and set JWT token in HttpOnly cookie
    # Frontend will handle the redirect
    user_response = UserResponse.model_validate(user)
    response_content = {
        "message": "Email verified successfully",
        "user": user_response.model_dump(mode='json'),
        "auto_login": True  # Signal to frontend to redirect to home
    }
    
    response = JSONResponse(content=response_content, status_code=200)
    
    # Set HttpOnly cookie with JWT token
    # For cross-origin requests, don't set domain - let browser handle it
    # For cross-origin requests, use samesite="none" with secure=True
    samesite_value = "none" if is_secure else "lax"
    
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        path="/",
        httponly=True,
        secure=is_secure,
        samesite=samesite_value,  # "none" for cross-origin, "lax" for same-origin
        max_age=JWT_EXPIRATION_HOURS * 3600
        # Don't set domain - let browser handle it (cookie will be sent to backend domain)
    )
    
    return response


@router.post("/resend-verification")
async def resend_verification(
    request: ResendVerificationRequest,
    db: AsyncSession = Depends(get_db)
):
    """Resend verification email - can be called if user didn't receive the email"""
    # Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if email exists or not (security)
        return {"message": "If the email exists, a verification email has been sent"}
    
    # If email is already verified, act normal and don't send email
    if user.email_verified:
        return {"message": "If the email exists, a verification email has been sent"}
    
    # Invalidate old verification tokens (delete unverified ones)
    old_verifications_result = await db.execute(
        select(EmailVerification).where(
            EmailVerification.user_id == user.id,
            EmailVerification.verified_at.is_(None)
        )
    )
    old_verifications = old_verifications_result.scalars().all()
    for old_verification in old_verifications:
        await db.delete(old_verification)
    await db.flush()  # Flush deletions before adding new one
    
    # Generate new verification token
    verification_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_EXPIRATION_HOURS)
    
    # Create new email verification record
    email_verification = EmailVerification(
        user_id=user.id,
        token=verification_token,
        expires_at=expires_at
    )
    db.add(email_verification)
    await db.commit()
    
    # Send verification email
    try:
        await send_verification_email(
            email=user.email,
            username=user.username,
            verification_token=verification_token,
            frontend_url=FRONTEND_URL
        )
        print(f"Verification email resent to {user.email}")
    except Exception as e:
        # Log error but don't fail the request - token is already created
        # User can request another email if needed
        error_msg = str(e)
        print(f"Failed to send verification email to {user.email}: {error_msg}")
        # Still return success - the token was created, user can try again if email wasn't sent
        # This prevents revealing email sending issues to potential attackers
        return {"message": "If the email exists, a verification email has been sent"}
    
    return {"message": "Verification email sent"}


@router.post("/login", response_model=dict)
async def login(
    request: Request,
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """Login with email and password"""
    # Find user by email
    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalar_one_or_none()
    
    if not user:
        # Don't reveal if user exists (security)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check password
    if not user.password_hash or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive")
    
    # If email is not verified, send verification email automatically
    if not user.email_verified:
        # Invalidate old verification tokens
        old_verifications_result = await db.execute(
            select(EmailVerification).where(
                EmailVerification.user_id == user.id,
                EmailVerification.verified_at.is_(None)
            )
        )
        old_verifications = old_verifications_result.scalars().all()
        for old_verification in old_verifications:
            await db.delete(old_verification)
        await db.flush()
        
        # Generate new verification token
        verification_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_EXPIRATION_HOURS)
        
        # Create new email verification record
        email_verification = EmailVerification(
            user_id=user.id,
            token=verification_token,
            expires_at=expires_at
        )
        db.add(email_verification)
        await db.commit()
        
        # Send verification email
        try:
            await send_verification_email(
                email=user.email,
                username=user.username,
                verification_token=verification_token,
                frontend_url=FRONTEND_URL
            )
            print(f"Verification email sent to {user.email} during login")
        except Exception as e:
            print(f"Failed to send verification email during login: {e}")
            # Don't fail login, just log the error
    
    # Create JWT token
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username
    }
    jwt_token = create_access_token(token_data)
    
    # Determine secure setting based on request protocol (HTTPS detection)
    # Check X-Forwarded-Proto header (set by proxies like Render) or request URL scheme
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
    
    # Check if request is over HTTPS
    # 1. Check X-Forwarded-Proto header (set by proxies like Render)
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "").lower()
    # 2. Check request URL scheme
    url_scheme = request.url.scheme
    # 3. Check if FRONTEND_URL is HTTPS (indicates production)
    frontend_is_https = FRONTEND_URL.startswith("https://")
    
    # Determine if we should use secure cookies
    is_https = (
        forwarded_proto == "https" or 
        url_scheme == "https" or 
        frontend_is_https or 
        ENVIRONMENT == "production"
    )
    is_secure = is_https  # Use HTTPS detection
    
    # Create response with token in HttpOnly cookie
    user_response = UserResponse.model_validate(user)
    response_content = {
        "message": "Login successful",
        "user": user_response.model_dump(mode='json')
    }
    
    # Add warning if email is not verified
    if not user.email_verified:
        response_content["warning"] = "Email not verified. A verification email has been sent to your email address."
    
    response = JSONResponse(content=response_content)
    
    # Set HttpOnly cookie with JWT token
    # For cross-origin requests (different domains), cookies work when:
    # 1. CORS allows credentials (allow_credentials=True)
    # 2. Frontend uses credentials: "include" in fetch
    # 3. SameSite must be "none" for cross-origin POST requests (requires secure=True)
    # 4. Don't set domain - browser will send cookie to backend domain automatically
    # Note: "lax" only works for same-site or top-level navigation, not for cross-origin POST
    samesite_value = "none" if is_secure else "lax"  # "none" requires secure=True (HTTPS)
    
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        path="/",
        httponly=True,
        secure=is_secure,  # True when HTTPS (required for samesite="none")
        samesite=samesite_value,  # "none" for cross-origin, "lax" for same-origin
        max_age=JWT_EXPIRATION_HOURS * 3600
        # Don't set domain - let browser handle it (cookie will be sent to backend domain)
    )
    
    return response


@router.post("/upload-icon", response_model=UserResponse)
async def upload_user_icon(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    """Upload user profile icon/avatar"""
    # Get token from HttpOnly cookie (preferred) or Authorization header (fallback)
    token = None
    
    # Try to get from cookie first
    token = request.cookies.get("access_token")
    
    # Fallback to Authorization header if no cookie
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = verify_token(token)
        user_id = int(payload.get("sub"))
    except (ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Get user from database
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")
    
    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Validate file size (max 5MB)
    file_content = await file.read()
    if len(file_content) > 5 * 1024 * 1024:  # 5MB
        raise HTTPException(status_code=400, detail="File size must be less than 5MB")
    
    # Delete old avatar from Cloudinary if it exists
    if user.avatar_url and "cloudinary.com" in user.avatar_url:
        try:
            # Extract public_id from Cloudinary URL
            # Cloudinary URLs format: https://res.cloudinary.com/{cloud_name}/image/upload/{transformations}/{public_id}.{format}
            # We need to extract the public_id which is: avatars/user_{user.id}
            # The public_id we use is relative to folder, so it's just "user_{user.id}"
            old_public_id = f"avatars/user_{user.id}"
            await delete_image(old_public_id)
        except Exception as e:
            # Log error but don't fail the upload if deletion fails
            print(f"Failed to delete old avatar from Cloudinary: {e}")
    
    try:
        # Upload to Cloudinary with user-specific public_id
        # public_id is relative to the folder, so just use user_{user.id}
        public_id = f"user_{user.id}"
        cloudinary_result = await upload_image(
            file_content=file_content,
            folder="avatars",
            public_id=public_id
        )
        
        # Get secure URL from Cloudinary response
        secure_url = cloudinary_result.get("secure_url")
        
        if not secure_url:
            raise HTTPException(status_code=500, detail="Failed to get image URL from Cloudinary")
        
        # Update user's avatar_url in database
        user.avatar_url = secure_url
        await db.commit()
        await db.refresh(user)
        
        return user
        
    except ValueError as e:
        # Cloudinary configuration error
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        # Other upload errors
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")


@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Request password reset - sends reset link to email"""
    # Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()
    
    # Don't reveal if email exists (security)
    # Always return success message
    if not user:
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # Only allow password reset for email-based users (not OAuth-only)
    if not user.password_hash:
        # User doesn't have a password (OAuth-only account)
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # Invalidate old unused password reset tokens
    old_resets_result = await db.execute(
        select(PasswordReset).where(
            PasswordReset.user_id == user.id,
            PasswordReset.used_at.is_(None)
        )
    )
    old_resets = old_resets_result.scalars().all()
    for old_reset in old_resets:
        await db.delete(old_reset)
    await db.flush()
    
    # Generate new reset token
    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_EXPIRATION_HOURS)
    
    # Create password reset record
    password_reset = PasswordReset(
        user_id=user.id,
        token=reset_token,
        expires_at=expires_at
    )
    db.add(password_reset)
    await db.commit()
    
    # Send password reset email
    try:
        await send_password_reset_email(
            email=user.email,
            username=user.username,
            reset_token=reset_token,
            frontend_url=FRONTEND_URL
        )
        print(f"Password reset email sent to {user.email}")
    except Exception as e:
        # Log error but don't fail the request - token is already created
        # User can request another email if needed
        error_msg = str(e)
        print(f"Failed to send password reset email to {user.email}: {error_msg}")
        # Still return success - the token was created, user can try again if email wasn't sent
        # This prevents revealing email sending issues to potential attackers
        return {"message": "If the email exists, a password reset link has been sent"}
    
    return {"message": "If the email exists, a password reset link has been sent"}


@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """Reset password with token"""
    # Find password reset record with user relationship loaded
    result = await db.execute(
        select(PasswordReset)
        .options(selectinload(PasswordReset.user))
        .where(PasswordReset.token == request.token)
    )
    password_reset = result.scalar_one_or_none()
    
    if not password_reset:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Check if already used
    if password_reset.used_at:
        raise HTTPException(status_code=400, detail="Reset token has already been used")
    
    # Check if expired
    if datetime.now(timezone.utc) > password_reset.expires_at:
        raise HTTPException(status_code=400, detail="Reset token has expired")
    
    # Get user (should be loaded via selectinload)
    user = password_reset.user
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Only allow password reset for email-based users
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="This account does not use password authentication")
    
    # Update password
    user.password_hash = get_password_hash(request.new_password)
    password_reset.used_at = datetime.now(timezone.utc)
    
    await db.commit()
    print(f"Password reset successfully for user: {user.email}")
    
    return {"message": "Password reset successfully"}

