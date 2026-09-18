"""
PhishGuard — Explainable Email Phishing & Threat Detection Platform
FastAPI Application Entry Point
"""

import sys
import os

# Add project root to Python path so we can import detection package
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .ai.routes import router as ai_router

from .config import settings
from .database.connection import init_db
from .api.analysis import router as analysis_router
from .auth.google import router as auth_router
from .gmail.api import router as gmail_router

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="Explainable Email Phishing & Threat Detection Platform",
    version=settings.APP_VERSION,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analysis_router, prefix="/api")
app.include_router(auth_router)
app.include_router(gmail_router)
app.include_router(ai_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "PhishGuard API"}
