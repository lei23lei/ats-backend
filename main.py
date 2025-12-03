from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import uvicorn
import os
from dotenv import load_dotenv
from database import get_db, engine, Base

# Import routers
from routers import user_oauth as user_oauth_router
from routers import user_email as user_email_router

# Load environment variables from .env file
load_dotenv()

app = FastAPI(title="ATS Backend", version="0.1.0")

# Get frontend URL from environment variable, default to localhost:3000
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],  # Allow requests from frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)


@app.on_event("startup")
async def startup():
    # Create database tables (if they don't exist)
    # Gracefully handle if database doesn't exist yet
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        print(f"Warning: Could not connect to database on startup: {e}")
        print("The app will start, but database operations will fail until the database is created.")


@app.on_event("shutdown")
async def shutdown():
    await engine.dispose()


@app.get("/")
async def root():
    return {"message": "Hello from atsbackend!"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/db-test")
async def db_test(db: AsyncSession = Depends(get_db)):
    """Test endpoint to verify database connection"""
    try:
        # Simple query to test connection
        result = await db.execute(text("SELECT 1"))
        await db.commit()
        return {"status": "connected", "message": "Database connection successful"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# Include routers
app.include_router(user_oauth_router.router)
app.include_router(user_email_router.router)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
