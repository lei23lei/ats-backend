"""Email-based user registration and authentication routes"""
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from sqlalchemy.orm import selectinload
from jose import JWTError, jwt
import bcrypt
from database import get_db
from models import User, EmailVerification
from schemas.user import UserRegister, UserResponse, UserLogin, ResendVerificationRequest
from services.email import send_verification_email

# Load environment variables
load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
EMAIL_VERIFICATION_EXPIRATION_HOURS = 1


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


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user with email and password"""
    # Clean up unverified accounts older than 5 minutes (for testing - change to 24 hours in production)
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
    
    # Check if username already exists
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
    
    # Check if expired (use timezone-aware datetime for comparison)
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
    print(f"Email verified successfully for user: {user.email}")
    
    # Refresh user to ensure all attributes are loaded (especially updated_at)
    await db.refresh(user)
    
    # Create JWT token to automatically log the user in
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username
    }
    jwt_token = create_access_token(token_data)
    
    # Determine secure setting based on environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
    is_secure = ENVIRONMENT == "production"
    
    # Create JSON response with user data and set JWT token in HttpOnly cookie
    # Use model_dump with mode='json' to ensure datetime serialization
    user_response = UserResponse.model_validate(user)
    response_content = {
        "message": "Email verified successfully",
        "user": user_response.model_dump(mode='json'),
        "auto_login": True  # Signal to frontend to redirect to home
    }
    
    response = JSONResponse(content=response_content, status_code=200)
    
    # Set HttpOnly cookie with JWT token
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        path="/",
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600
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
    
    if user.email_verified:
        raise HTTPException(status_code=400, detail="Email already verified")
    
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
        print(f"Failed to send verification email: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Failed to send verification email")
    
    return {"message": "Verification email sent"}


@router.post("/login", response_model=dict)
async def login(
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
    
    # SECURITY: Block login if email is not verified
    if not user.email_verified:
        # Send verification email to help user verify their account
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
            print(f"Verification email sent to {user.email} - login rejected due to unverified email")
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            # Still reject login even if email sending fails
        
        # Reject login with helpful error message
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please check your email and verify your account before logging in. A new verification email has been sent."
        )
    
    # Create JWT token
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username
    }
    jwt_token = create_access_token(token_data)
    
    # Determine secure setting based on environment
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
    is_secure = ENVIRONMENT == "production"
    
    # Create response with token in HttpOnly cookie
    # Use model_dump with mode='json' to ensure datetime serialization
    user_response = UserResponse.model_validate(user)
    response_content = {
        "message": "Login successful",
        "user": user_response.model_dump(mode='json')
    }
    
    response = JSONResponse(content=response_content)
    
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        path="/",
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600
    )
    
    return response

