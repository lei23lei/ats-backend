"""Pydantic schemas for user-related requests and responses"""
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional


class UserBase(BaseModel):
    """Base user schema"""
    username: str
    email: EmailStr
    avatar_url: Optional[str] = None


class UserCreate(UserBase):
    """Schema for creating a new user"""
    password: Optional[str] = None  # Optional for OAuth users


class UserResponse(UserBase):
    """Schema for user response"""
    id: int
    email_verified: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Schema for authentication token response"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class GoogleUserInfo(BaseModel):
    """Schema for Google user info from OAuth"""
    id: str
    email: str
    verified_email: bool
    name: str
    picture: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

