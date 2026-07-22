from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print(f"Starting {settings.APP_NAME}")
    print(f"Environment : {settings.ENVIRONMENT}")
    print(f"Version     : {settings.APP_VERSION}")
    print("=" * 60)

    # Database schema is managed by Alembic migrations.
    # Do NOT call Base.metadata.create_all() in production.

    yield

    print("=" * 60)
    print(f"Stopping {settings.APP_NAME}")
    print("=" * 60)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Home"])
async def home():
    return {
        "success": True,
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "message": "Welcome to AI Powered OSINT Investigation Platform",
    }


@app.get("/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/ping", tags=["Health"])
async def ping():
    return JSONResponse(
        status_code=200,
        content={
            "message": "pong",
        },
    )


app.include_router(
    api_router,
    prefix=settings.API_PREFIX,
)