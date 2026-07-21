from fastapi import APIRouter

from backend.app.core.config import settings


router = APIRouter()


@router.get("/")
async def health():

    return {
        "status": "healthy",
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ping")
async def ping():

    return {
        "message": "pong",
    }


@router.get("/version")
async def version():

    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "api": settings.API_VERSION,
    }