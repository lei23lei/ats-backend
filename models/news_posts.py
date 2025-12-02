from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
from .enums import ContentType


class News(Base):
    """News articles - can be generated or created by users"""
    __tablename__ = "news"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False, index=True)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    is_published = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    author = relationship("User", back_populates="news_articles", foreign_keys=[author_id])
    comments = relationship("Comment", back_populates="news", cascade="all, delete-orphan")
    reactions = relationship("Reaction", back_populates="news", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<News(id={self.id}, title='{self.title[:50]}...')>"


class Post(Base):
    """User-created posts with optional images"""
    __tablename__ = "posts"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    image_url = Column(String(500), nullable=True)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post", cascade="all, delete-orphan")
    reactions = relationship("Reaction", back_populates="post", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Post(id={self.id}, author_id={self.author_id}, content='{self.content[:50]}...')>"


class Comment(Base):
    """Comments on news, posts, or other comments (nested comments)"""
    __tablename__ = "comments"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Polymorphic relationships - comment can be on news, post, or another comment
    news_id = Column(Integer, ForeignKey("news.id", ondelete="CASCADE"), nullable=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"), nullable=True, index=True)
    parent_comment_id = Column(Integer, ForeignKey("comments.id", ondelete="CASCADE"), nullable=True, index=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    author = relationship("User", back_populates="comments")
    news = relationship("News", back_populates="comments")
    post = relationship("Post", back_populates="comments")
    parent_comment = relationship("Comment", remote_side=[id], backref="replies")
    reactions = relationship("Reaction", back_populates="comment", cascade="all, delete-orphan")
    
    # Ensure comment is on exactly one of: news, post, or parent_comment
    __table_args__ = (
        Index('ix_comment_target', 'news_id', 'post_id', 'parent_comment_id'),
    )
    
    def __repr__(self):
        return f"<Comment(id={self.id}, author_id={self.author_id}, content='{self.content[:50]}...')>"


class Reaction(Base):
    """Like/Dislike reactions on news, posts, or comments"""
    __tablename__ = "reactions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    is_like = Column(Boolean, nullable=False)  # True for like, False for dislike
    
    # Polymorphic relationships - reaction can be on news, post, or comment
    news_id = Column(Integer, ForeignKey("news.id", ondelete="CASCADE"), nullable=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id", ondelete="CASCADE"), nullable=True, index=True)
    comment_id = Column(Integer, ForeignKey("comments.id", ondelete="CASCADE"), nullable=True, index=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="reactions")
    news = relationship("News", back_populates="reactions")
    post = relationship("Post", back_populates="reactions")
    comment = relationship("Comment", back_populates="reactions")
    
    # Ensure one reaction per user per content item (user can change like to dislike)
    # Ensure reaction is on exactly one of: news, post, or comment
    __table_args__ = (
        Index('ix_reaction_user_news', 'user_id', 'news_id', unique=True),
        Index('ix_reaction_user_post', 'user_id', 'post_id', unique=True),
        Index('ix_reaction_user_comment', 'user_id', 'comment_id', unique=True),
    )
    
    def __repr__(self):
        reaction_type = "like" if self.is_like else "dislike"
        return f"<Reaction(id={self.id}, user_id={self.user_id}, type='{reaction_type}')>"

