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

# Create async engine
# Set echo=False in production (controlled by environment variable)
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=os.getenv("DEBUG", "false").lower() == "true",  # Only echo SQL in debug mode
    future=True,
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