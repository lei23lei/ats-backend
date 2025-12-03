"""User authentication routes including OAuth"""
import os
import secrets
import uuid
import httpx
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from jose import JWTError, jwt
from database import get_db
from models import User, OAuthAccount, OAuthProvider
from schemas.user import UserResponse, TokenResponse, GoogleUserInfo

# Load environment variables
load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["auth"])

# OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")  # Required - no default fallback
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()

# SECURITY: Validate critical configuration at startup
if not JWT_SECRET_KEY:
    raise ValueError(
        "JWT_SECRET_KEY must be set in environment variables. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
    )

# Google OAuth endpoints
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/google/callback")

# Store state temporarily (in production, use Redis or database)
# State expires after 10 minutes
oauth_states = {}
STATE_EXPIRATION_MINUTES = 10


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    if not JWT_SECRET_KEY:
        raise HTTPException(
            status_code=500,
            detail="JWT_SECRET_KEY not configured. Please set it in your .env file."
        )
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
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


def cleanup_expired_states():
    """Remove expired OAuth states to prevent memory leak"""
    now = datetime.utcnow()
    expired_states = [
        state for state, data in oauth_states.items()
        if (now - data["created_at"]).total_seconds() > STATE_EXPIRATION_MINUTES * 60
    ]
    for state in expired_states:
        oauth_states.pop(state, None)


@router.get("/google/login")
async def google_login():
    """Initiate Google OAuth login flow"""
    # Reload env vars in case they weren't loaded at import time
    load_dotenv()
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    
    if not google_client_id or not google_client_secret:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Please check your .env file."
        )
    
    # Cleanup expired states
    cleanup_expired_states()
    
    # Generate secure state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {
        "created_at": datetime.utcnow(),
        "used": False
    }
    
    # Build Google authorization URL
    params = {
        "client_id": google_client_id,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",  # Request refresh token
        "prompt": "consent"
    }
    
    # Construct URL
    auth_url = f"{GOOGLE_AUTHORIZATION_URL}?" + "&".join([f"{k}={v}" for k, v in params.items()])
    
    # Determine secure setting based on environment
    is_secure = ENVIRONMENT == "production"
    
    # Set state in secure cookie
    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=is_secure,  # True in production with HTTPS
        samesite="lax",
        max_age=STATE_EXPIRATION_MINUTES * 60  # 10 minutes
    )
    
    return response


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Handle Google OAuth callback"""
    if error:
        # SECURITY: Don't expose OAuth error details to prevent information leakage
        raise HTTPException(status_code=400, detail="OAuth authentication failed")
    
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing authorization code or state")
    
    # Verify state from cookie
    cookie_state = request.cookies.get("oauth_state")
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Cleanup expired states first
    cleanup_expired_states()
    
    # Check if state exists and hasn't been used
    if state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    
    # Check if state has expired
    state_data = oauth_states[state]
    if (datetime.utcnow() - state_data["created_at"]).total_seconds() > STATE_EXPIRATION_MINUTES * 60:
        oauth_states.pop(state, None)  # Remove expired state
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    
    if state_data["used"]:
        raise HTTPException(status_code=400, detail="State already used")
    
    # Mark state as used
    oauth_states[state]["used"] = True
    
    # Reload env vars to ensure they're available
    load_dotenv()
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    
    if not google_client_id or not google_client_secret:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Please check your .env file."
        )
    
    # Exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": google_client_id,
                "client_secret": google_client_secret,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            }
        )
        
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to exchange authorization code for token"
            )
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token received")
        
        # Fetch user info from Google
        userinfo_response = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if userinfo_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail="Failed to fetch user information from OAuth provider"
            )
        
        google_user = userinfo_response.json()
        google_user_info = GoogleUserInfo(**google_user)
    
    # Check if OAuth account exists (eagerly load user relationship)
    oauth_account_query = select(OAuthAccount).options(
        selectinload(OAuthAccount.user)
    ).where(
        OAuthAccount.provider == OAuthProvider.GOOGLE,
        OAuthAccount.provider_user_id == google_user_info.id
    )
    result = await db.execute(oauth_account_query)
    oauth_account = result.scalar_one_or_none()
    
    if oauth_account:
        # Update existing OAuth account tokens
        oauth_account.access_token = access_token
        oauth_account.refresh_token = refresh_token
        user = oauth_account.user  # Now safely accessible since we eagerly loaded it
        
        # Update user info if changed
        if google_user_info.picture and google_user_info.picture != user.avatar_url:
            user.avatar_url = google_user_info.picture
        if google_user_info.verified_email:
            user.email_verified = True
    else:
        # Check if user exists by email
        user_query = select(User).where(User.email == google_user_info.email)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()
        
        if user:
            # Link OAuth account to existing user
            oauth_account = OAuthAccount(
                user_id=user.id,
                provider=OAuthProvider.GOOGLE,
                provider_user_id=google_user_info.id,
                access_token=access_token,
                refresh_token=refresh_token
            )
            db.add(oauth_account)
            
            # Update user info
            if google_user_info.picture:
                user.avatar_url = google_user_info.picture
            if google_user_info.verified_email:
                user.email_verified = True
        else:
            # Create new user
            # Generate username from email if name not available
            username_base = google_user_info.email.split("@")[0]
            username = username_base
            
            # Ensure username is unique (max 100 attempts to prevent DoS)
            counter = 1
            max_attempts = 100
            while counter <= max_attempts:
                existing_user = await db.execute(
                    select(User).where(User.username == username)
                )
                if existing_user.scalar_one_or_none() is None:
                    break
                username = f"{username_base}{counter}"
                counter += 1
            
            # If still not unique after max attempts, use UUID fallback
            if counter > max_attempts:
                username = f"{username_base}_{uuid.uuid4().hex[:8]}"
            
            user = User(
                username=username,
                email=google_user_info.email,
                email_verified=google_user_info.verified_email,
                avatar_url=google_user_info.picture,
                password_hash=None  # OAuth-only user
            )
            db.add(user)
            await db.flush()  # Get user ID
            
            # Create OAuth account
            oauth_account = OAuthAccount(
                user_id=user.id,
                provider=OAuthProvider.GOOGLE,
                provider_user_id=google_user_info.id,
                access_token=access_token,
                refresh_token=refresh_token
            )
            db.add(oauth_account)
    
    await db.commit()
    
    # Create JWT token
    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "username": user.username
    }
    jwt_token = create_access_token(token_data)
    
    # Determine secure setting based on environment
    is_secure = ENVIRONMENT == "production"
    
    # Redirect to frontend (NO token in URL - security risk)
    response = RedirectResponse(url=f"{FRONTEND_URL}/auth/callback")
    
    # Set JWT in secure HttpOnly cookie
    # Note: path defaults to "/" if not specified, but we'll be explicit
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        path="/",  # Explicitly set path to match deletion
        httponly=True,
        secure=is_secure,  # True in production with HTTPS
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600
    )
    
    # Clear OAuth state cookie (must match secure setting)
    response.delete_cookie(
        key="oauth_state",
        path="/",
        httponly=True,
        secure=is_secure,  # Must match the setting when cookie was set
        samesite="lax"
    )
    
    return response


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Get current authenticated user"""
    # Get token from HttpOnly cookie (preferred) or Authorization header (fallback)
    token = None
    
    # Try to get from cookie first
    token = request.cookies.get("access_token")
    
    # Fallback to Authorization header if no cookie
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    
    # No query parameter fallback - security risk
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = verify_token(token)
        user_id = int(payload.get("sub"))
    except (ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")
    
    return user


@router.post("/logout")
async def logout(request: Request):
    """Logout user by clearing cookies"""
    # Determine secure setting based on environment
    is_secure = ENVIRONMENT == "production"
    
    # Create JSONResponse (subclass of Response) so we can return JSON
    # This is crucial - we must return the Response object, not a dict!
    response = JSONResponse(content={"message": "Logged out successfully"})
    
    # Method 1: Use delete_cookie with matching settings
    response.delete_cookie(
        key="access_token",
        path="/",  # Must match the path when cookie was set
        httponly=True,
        secure=is_secure,  # Must match the setting when cookie was set
        samesite="lax"  # Must match the setting when cookie was set
    )
    
    # Method 2: Also set cookie to empty with max_age=0 as backup
    # This ensures the cookie is deleted even if delete_cookie doesn't work
    response.set_cookie(
        key="access_token",
        value="",
        path="/",
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=0  # Expire immediately
    )
    
    # Return the Response object (not a dict!) so cookie headers are sent
    return response

