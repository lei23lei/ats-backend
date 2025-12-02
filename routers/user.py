"""User authentication routes including OAuth"""
import os
import secrets
import httpx
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import JWTError, jwt
from database import get_db
from models import User, OAuthAccount, OAuthProvider
from schemas.user import UserResponse, TokenResponse, GoogleUserInfo

router = APIRouter(prefix="/api/auth", tags=["auth"])

# OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Google OAuth endpoints
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_REDIRECT_URI = "http://localhost:8000/api/auth/google/callback"

# Store state temporarily (in production, use Redis or database)
oauth_states = {}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
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
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")


@router.get("/google/login")
async def google_login():
    """Initiate Google OAuth login flow"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET"
        )
    
    # Generate secure state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {
        "created_at": datetime.utcnow(),
        "used": False
    }
    
    # Build Google authorization URL
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",  # Request refresh token
        "prompt": "consent"
    }
    
    # Construct URL
    auth_url = f"{GOOGLE_AUTHORIZATION_URL}?" + "&".join([f"{k}={v}" for k, v in params.items()])
    
    # Set state in secure cookie
    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=600  # 10 minutes
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
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing authorization code or state")
    
    # Verify state from cookie
    cookie_state = request.cookies.get("oauth_state")
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Check if state exists and hasn't been used
    if state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid or expired state")
    
    if oauth_states[state]["used"]:
        raise HTTPException(status_code=400, detail="State already used")
    
    # Mark state as used
    oauth_states[state]["used"] = True
    
    # Exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            }
        )
        
        if token_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to exchange code for token: {token_response.text}"
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
                detail=f"Failed to fetch user info: {userinfo_response.text}"
            )
        
        google_user = userinfo_response.json()
        google_user_info = GoogleUserInfo(**google_user)
    
    # Check if OAuth account exists
    oauth_account_query = select(OAuthAccount).where(
        OAuthAccount.provider == OAuthProvider.GOOGLE,
        OAuthAccount.provider_user_id == google_user_info.id
    )
    result = await db.execute(oauth_account_query)
    oauth_account = result.scalar_one_or_none()
    
    if oauth_account:
        # Update existing OAuth account tokens
        oauth_account.access_token = access_token
        oauth_account.refresh_token = refresh_token
        user = oauth_account.user
        
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
            
            # Ensure username is unique
            counter = 1
            while True:
                existing_user = await db.execute(
                    select(User).where(User.username == username)
                )
                if existing_user.scalar_one_or_none() is None:
                    break
                username = f"{username_base}{counter}"
                counter += 1
            
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
    
    # Redirect to frontend with token in cookie
    response = RedirectResponse(url=f"{FRONTEND_URL}/auth/callback?token={jwt_token}")
    
    # Set JWT in secure HttpOnly cookie
    response.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600
    )
    
    # Clear OAuth state cookie
    response.delete_cookie(key="oauth_state")
    
    return response


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    token: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get current authenticated user"""
    # Try to get token from cookie first, then from query param
    # In production, you'd get this from the Authorization header
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
async def logout():
    """Logout user by clearing cookies"""
    response = Response()
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully"}

