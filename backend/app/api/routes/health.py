from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "MinosVerdictMesh API",
        "version": "1.0.0",
    }
