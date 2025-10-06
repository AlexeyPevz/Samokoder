import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

import docker
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from samokoder.core.config import get_config
from samokoder.core.log import get_logger
from samokoder.core.config.validator import validate_config_security
from samokoder.core.db.session import get_async_engine
from samokoder.core.api.error_handlers import generic_exception_handler, validation_exception_handler
from samokoder.core.api.middleware.security_headers import SecurityHeadersMiddleware
from samokoder.api.middleware.request_limits import RequestSizeLimitMiddleware  # FIX: Request size limits
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
from slowapi.middleware import SlowAPIMiddleware

logger = get_logger(__name__)


async def cleanup_orphaned_containers() -> None:
    """Periodically clean up Docker containers left after sessions."""
    await asyncio.sleep(60)  # Initial delay
    try:
        client = docker.from_env()
    except Exception as exc:
        logger.warning(f"Docker not available for cleanup, skipping: {exc}")
        return
    
    while True:
        try:
            containers = client.containers.list(
                all=True, filters={"label": "managed-by=samokoder"}
            )
            now = datetime.utcnow()
            removed_count = 0
            
            for container in containers:
                created_str = container.labels.get("creation_timestamp")
                if not created_str:
                    # Fallback: use container created time from Docker API
                    try:
                        created_time = datetime.fromisoformat(container.attrs['Created'][:19])
                    except (KeyError, ValueError):
                        logger.warning(f"Container {container.id[:12]} has no creation timestamp, skipping")
                        continue
                else:
                    try:
                        created_time = datetime.fromisoformat(created_str)
                    except ValueError:
                        logger.warning(f"Invalid timestamp format for container {container.id[:12]}, skipping")
                        continue

                # Check lifetime based on container type
                max_lifetime_str = container.labels.get("max_lifetime_hours", "24")
                try:
                    max_lifetime_hours = int(max_lifetime_str)
                except ValueError:
                    max_lifetime_hours = 24
                
                age_hours = (now - created_time).total_seconds() / 3600
                if age_hours > max_lifetime_hours:
                    container_type = container.labels.get("preview", "false") == "true" and "preview" or "execution"
                    logger.info(
                        f"Removing orphaned {container_type} container {container.id[:12]} "
                        f"(age: {age_hours:.1f}h, max: {max_lifetime_hours}h)"
                    )
                    try:
                        container.stop(timeout=5)
                        container.remove(v=True, force=True)
                        removed_count += 1
                    except Exception as e:
                        logger.error(f"Failed to remove container {container.id[:12]}: {e}")
            
            if removed_count > 0:
                logger.info(f"Cleanup cycle completed: removed {removed_count} containers")
            
            # Cleanup orphaned named volumes (preview containers create named volumes)
            try:
                volumes = client.volumes.list(filters={"label": "managed-by=samokoder"})
                volumes_removed = 0
                for volume in volumes:
                    # Check if volume is in use
                    try:
                        # If volume has no containers using it, remove it
                        volume.reload()
                        if not volume.attrs.get('UsageData', {}).get('RefCount', 1):
                            volume.remove(force=True)
                            volumes_removed += 1
                            logger.info(f"Removed orphaned volume: {volume.name}")
                    except Exception as e:
                        logger.debug(f"Could not remove volume {volume.name}: {e}")
                
                if volumes_removed > 0:
                    logger.info(f"Removed {volumes_removed} orphaned volumes")
            except Exception as exc:
                logger.error(f"Error during volume cleanup: {exc}", exc_info=True)
                
        except Exception as exc:
            logger.error(f"Error during container cleanup: {exc}", exc_info=True)

        await asyncio.sleep(3600)  # Run every hour


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    # Startup
    try:
        logger.info("Starting Samokoder API server...")
        config = get_config()
        validate_config_security(config, fail_fast=True)
        logger.info("Configuration validated successfully")
        
        _ = get_async_engine(config.db.url)
        logger.info("Database engine initialized")

        cleanup_task = None
        if os.getenv("ENABLE_CONTAINER_CLEANUP", "1") == "1":  # Enabled by default
            cleanup_task = asyncio.create_task(cleanup_orphaned_containers())
            logger.info("Container cleanup task started (runs every hour)")
    except Exception as exc:
        logger.error(f"Error during startup: {exc}", exc_info=True)
        raise
    
    yield
    
    # Shutdown
    try:
        logger.info("Shutting down Samokoder API server...")
        if 'cleanup_task' in locals() and cleanup_task is not None:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Dispose database engines to cleanly close all connections
        from samokoder.core.db.session import dispose_engines
        await dispose_engines()
        logger.info("Shutdown completed successfully")
    except Exception as exc:
        logger.error(f"Error during shutdown: {exc}", exc_info=True)


app = FastAPI(title="Samokoder SaaS API", version="1.0", lifespan=lifespan)

# P1-5: Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# FIX: Add request size limit middleware (защита от DoS через большие payloads)
app.add_middleware(RequestSizeLimitMiddleware, max_size=10 * 1024 * 1024)  # 10 MB default

# Add rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# P1-4: Add secure error handlers
app.add_exception_handler(Exception, generic_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

# Metrics middleware
app.middleware('http')(metrics_middleware)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount('/metrics', metrics_app)

# P2-3: Strict CORS configuration
config = get_config()
cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
if not cors_origins or cors_origins == [""]:
    if config.environment == "production":
        # Production: only allow specific origins
        cors_origins = ["https://samokoder.io", "https://app.samokoder.io"]
    else:
        # Development defaults
        cors_origins = ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # P2-3: Specific methods only
    allow_headers=[  # P2-3: Specific headers only
        "Content-Type",
        "Authorization",
        "Accept",
        "Origin",
        "User-Agent",
        "DNT",
        "Cache-Control",
        "X-Requested-With"
    ],
    max_age=3600,  # Cache preflight requests
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
