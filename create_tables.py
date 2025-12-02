"""Script to create all database tables"""
import asyncio
from database import engine, Base
import models  # Import models to register them with SQLAlchemy


async def create_tables():
    """Create all tables defined in models"""
    print("Creating database tables...")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("✅ All tables created successfully!")
        print("\nCreated tables:")
        for table_name in Base.metadata.tables.keys():
            print(f"  - {table_name}")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(create_tables())

