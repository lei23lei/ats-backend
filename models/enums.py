"""Enums used across models"""
import enum


class OAuthProvider(str, enum.Enum):
    """OAuth provider types"""
    FACEBOOK = "facebook"
    GOOGLE = "google"


class ContentType(str, enum.Enum):
    """Types of content that can be liked/commented on"""
    NEWS = "news"
    POST = "post"
    COMMENT = "comment"

