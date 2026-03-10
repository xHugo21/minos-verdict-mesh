from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "MinosVerdict API",
        "version": "1.0.0",
    }
