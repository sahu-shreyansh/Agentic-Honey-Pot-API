
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import APP_NAME, API_VERSION, HOST, PORT, DEBUG, ALLOWED_ORIGINS, API_KEY
from core.logger import setup_logger
from api.honeypot import router as honeypot_router

logger = setup_logger("main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application on startup and cleanup on shutdown."""
    logger.info(f"Starting {APP_NAME} v{API_VERSION}")
    if not API_KEY or API_KEY == "demo-key":
        logger.warning("⚠️  Running with demo API key - NOT FOR PRODUCTION")
    yield
    logger.info(f"Shutting down {APP_NAME}")

app = FastAPI(
    title=APP_NAME,
    version=API_VERSION,
    description="Production-ready Agentic Honey-Pot API for scam detection and engagement",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(honeypot_router)

@app.get("/", tags=["Health"])
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": APP_NAME, "version": API_VERSION}

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Documentation available at: http://{HOST}:{PORT}/docs")
    uvicorn.run("main:app", host=HOST, port=PORT, reload=DEBUG)
