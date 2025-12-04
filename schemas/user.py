"""Pydantic schemas for user-related requests and responses"""
from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from typing import Optional
import re


class UserBase(BaseModel):
    """Base user schema"""
    username: str
    email: EmailStr
    avatar_url: Optional[str] = None


class UserRegister(BaseModel):
    """Schema for user registration"""
    username: str
    email: EmailStr
    password: str
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password: 8-16 chars, must have number, letter, lowercase, and uppercase"""
        if len(v) < 8 or len(v) > 16:
            raise ValueError('Password must be between 8 and 16 characters')
        
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one number')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-zA-Z]', v):
            raise ValueError('Password must contain at least one letter')
        
        return v
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username"""
        if len(v) < 3 or len(v) > 50:
            raise ValueError('Username must be between 3 and 50 characters')
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v


class UserCreate(UserBase):
    """Schema for creating a new user"""
    password: Optional[str] = None  # Optional for OAuth users


class UserResponse(UserBase):
    """Schema for user response"""
    id: int
    email_verified: bool
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Schema for authentication token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserLogin(BaseModel):
    """Schema for user login"""
    email: EmailStr
    password: str


class ResendVerificationRequest(BaseModel):
    """Schema for resend verification email request"""
    email: EmailStr


class GoogleUserInfo(BaseModel):
    """Schema for Google user info from OAuth"""
    id: str
    email: str
    verified_email: bool
    name: str
    picture: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

