from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from urllib.parse import quote_plus

# Database connection parameters
DB_USER = "postgres"
DB_PASSWORD = "postgres"  # Update this if your password is different
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = "ats-backend"  # Database names with hyphens work fine in connection strings

# Build connection URL with proper encoding
# For database names with special characters, we can use the name directly in the URL
URL_DATABASE = f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
# Convert to async PostgreSQL URL
ASYNC_DATABASE_URL = URL_DATABASE.replace("postgresql://", "postgresql+asyncpg://")

# Create async engine
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=True,  # Set to False in production
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