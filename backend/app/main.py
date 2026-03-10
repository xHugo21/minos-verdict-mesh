from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import PORT, ALLOW_ORIGINS
from app.api.routes.health import router as health_router
from app.api.routes.detect import router as detect_router

app = FastAPI(title="Minos Verdict", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

app.include_router(health_router)
app.include_router(detect_router)

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind the API server.",
    )
    args = parser.parse_args()

    uvicorn.run("app.main:app", host=args.host, port=PORT, reload=True)
