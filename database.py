from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from urllib.parse import quote_plus
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variable (for production/Render)
# Fallback to local database or NeonDB URL if DATABASE_URL is not set
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Use DATABASE_URL from environment (Render/Production)
    # Remove channel_binding if present (not supported by asyncpg)
    URL_DATABASE = DATABASE_URL.replace("&channel_binding=require", "").replace("?channel_binding=require", "")
else:
    # Fallback: Use local database or NeonDB
    # Database connection parameters for local development
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "ats-backend")
    
    # Build connection URL with proper encoding
    URL_DATABASE = f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Convert to async PostgreSQL URL
ASYNC_DATABASE_URL = URL_DATABASE.replace("postgresql://", "postgresql+asyncpg://")

# Create async engine with connection pool settings for production
# These settings help prevent "connection is closed" errors on Render
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=os.getenv("DEBUG", "false").lower() == "true",  # Only echo SQL in debug mode
    future=True,
    # Connection pool settings for production stability
    pool_size=5,  # Number of connections to maintain in the pool
    max_overflow=10,  # Additional connections beyond pool_size
    pool_pre_ping=True,  # Test connections before using them (prevents "connection is closed" errors)
    pool_recycle=3600,  # Recycle connections after 1 hour (prevents stale connections)
    pool_timeout=30,  # Timeout when getting connection from pool
    # Connection arguments for asyncpg
    connect_args={
        "server_settings": {
            "application_name": "ats-backend",
        },
        "command_timeout": 60,  # Timeout for individual commands
    }
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Base class for models
Base = declarative_base()


# Dependency to get database session
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()