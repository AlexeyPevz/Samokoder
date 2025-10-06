import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import docker
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from samokoder.core.config import get_config
from samokoder.core.config.validator import validate_config_security
from samokoder.core.db.session import get_async_engine
from samokoder.api.routers.auth import router as auth_router
from samokoder.api.routers.projects import router as projects_router
from samokoder.api.routers.keys import router as keys_router
from samokoder.api.routers.models import router as models_router
from samokoder.api.routers.workspace import router as workspace_router
from samokoder.api.routers.preview import router as preview_router
from samokoder.api.routers.notifications import router as notifications_router
from samokoder.api.routers.plugins import router as plugins_router
from samokoder.api.routers.analytics import router as analytics_router
from samokoder.api.routers.usage import router as usage_router
from samokoder.api.routers.user import router as user_router
from samokoder.api.routers.gitverse import router as gitverse_router
# from samokoder.api.routers.project_runs import router as project_runs_router
from samokoder.core.monitoring.health import router as health_router
from samokoder.api.middleware.rate_limiter import limiter, _rate_limit_exceeded_handler
from samokoder.api.middleware.metrics import metrics_middleware
from prometheus_client import make_asgi_app
from slowapi.errors import RateLimitExceeded


async def cleanup_orphaned_containers() -> None:
    """Periodically clean up Docker containers left after sessions."""
    await asyncio.sleep(60)
    client = docker.from_env()
    while True:
        try:
            containers = client.containers.list(
                all=True, filters={"label": "managed-by=samokoder"}
            )
            now = datetime.utcnow()
            for container in containers:
                created_str = container.labels.get("creation_timestamp")
                if not created_str:
                    continue

                try:
                    created_time = datetime.fromisoformat(created_str)
                except ValueError:
                    continue

                if now - created_time > timedelta(hours=24):
                    container.stop()
                    container.remove()
        except Exception as exc:
            print(f"Error during container cleanup: {exc}")

        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    # Startup
    try:
        config = get_config()
        validate_config_security(config, fail_fast=True)
        
        _ = get_async_engine(config.db.url)

        cleanup_task = asyncio.create_task(cleanup_orphaned_containers())
    except Exception as exc:
        print(f"Error during startup: {exc}")
        raise
    
    yield
    
    # Shutdown
    try:
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        
        # Dispose database engines to cleanly close all connections
        from samokoder.core.db.session import dispose_engines
        await dispose_engines()
    except Exception as exc:
        print(f"Error during shutdown: {exc}")


app = FastAPI(title="Samokoder SaaS API", version="1.0", lifespan=lifespan)

# Add rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Metrics middleware
app.middleware('http')(metrics_middleware)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount('/metrics', metrics_app)

import os

# Get CORS origins from environment variable
cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
if not cors_origins:
    cors_origins = ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/v1")
app.include_router(projects_router, prefix="/v1")
app.include_router(keys_router, prefix="/v1")
app.include_router(models_router, prefix="/v1")
app.include_router(workspace_router, prefix="/v1")
app.include_router(preview_router, prefix="/v1")
app.include_router(notifications_router, prefix="/v1")
app.include_router(plugins_router, prefix="/v1")
app.include_router(analytics_router, prefix="/v1")
app.include_router(usage_router, prefix="/v1")
app.include_router(user_router, prefix="/v1")
app.include_router(gitverse_router, prefix="/v1")
# app.include_router(project_runs_router, prefix="/v1")
app.include_router(health_router, prefix="/health", tags=["health"])


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "Samokoder SaaS API ready", "version": "1.0"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
