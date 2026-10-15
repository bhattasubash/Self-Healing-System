"""
FastAPI Application Entry Point & Lifespan Management.

Provides the orchestration brain runtime:
- Lifespan startup and shutdown hooks
- CORS configuration
- Health & readiness probes
- API routers for analysis, temporal queries, and human approvals
- Production uvicorn runner entrypoint
"""

from __future__ import annotations

import asyncio
import sys
import threading
from contextlib import asynccontextmanager, suppress
from typing import TYPE_CHECKING

import structlog
import uvicorn
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

from app.config import Settings, get_settings
from app.routers.alert_intake import router as alert_intake_router
from app.routers.analysis import router as analysis_router
from app.routers.approval import router as approval_router

# ─── Structured Logging Setup ──────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


# ─── Lifespan Context ──────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manage lifecycle events for the FastAPI application.
    Initializes database driver pools, sandbox caches, and background workers.
    """
    settings = get_settings()
    logger.info(
        "brain_starting",
        host=settings.brain_host,
        port=settings.brain_port,
        temporal_store_db=settings.temporal_store.db_path,
        collector_enabled=settings.kubernetes.collector_enabled,
    )

    collector_task: asyncio.Task[None] | None = None
    stop_event = threading.Event()

    if settings.kubernetes.collector_enabled:
        from app.services.k8s_collector import KubernetesCollector
        from app.services.temporal_store import TemporalStore

        store = TemporalStore(db_path=settings.temporal_store.db_path)
        collector = KubernetesCollector()
        interval = settings.kubernetes.collector_interval_seconds
        allowed_ns = settings.kubernetes.allowed_namespaces

        async def _collector_worker() -> None:
            logger.info(
                "k8s_collector_background_worker_started",
                interval=interval,
                namespaces=allowed_ns,
            )
            while not stop_event.is_set():
                try:
                    if allowed_ns:
                        await collector.sync_namespaces(store, allowed_ns)
                    else:
                        await collector.sync_all(store)
                except Exception as exc:
                    logger.warning("k8s_collector_reconcile_error", error=str(exc))

                # Sleep in short increments to respond promptly to stop_event
                for _ in range(int(interval * 10)):
                    if stop_event.is_set():
                        break
                    await asyncio.sleep(0.1)

            logger.info("k8s_collector_background_worker_stopped")

        collector_task = asyncio.create_task(_collector_worker())

    # Yield control to the running application
    yield

    logger.info("brain_shutting_down")
    stop_event.set()
    if collector_task:
        collector_task.cancel()
        with suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(collector_task, timeout=5.0)


# ─── Application Factory ───────────────────────────────────────────────

def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app_settings = settings or get_settings()

    app = FastAPI(
        title="Self-Healing AI SRE Brain",
        description=(
            "Analytical reasoning brain for the Privacy-First Simulation-Gated AI SRE Agent. "
            "Enforces zero data centralization, regex pre-filtering, and "
            "deterministic FSM pathways."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── CORS Middleware ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.brain_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # ── Health & Diagnostic Routes ──
    @app.get(
        "/health",
        status_code=status.HTTP_200_OK,
        tags=["System"],
        summary="Service liveness probe",
    )
    async def health_check() -> dict[str, str]:
        return {
            "status": "healthy",
            "service": "self-healing-brain",
            "version": "0.1.0",
        }

    @app.get(
        "/ready",
        status_code=status.HTTP_200_OK,
        tags=["System"],
        summary="Service readiness probe",
    )
    async def readiness_check() -> dict[str, str]:
        return {
            "status": "ready",
            "temporal_store": app_settings.temporal_store.db_path,
            "transport": app_settings.mcp.transport,
        }

    # ── Mount Routers ──
    app.include_router(alert_intake_router)
    app.include_router(analysis_router)
    app.include_router(approval_router)

    return app


# Root application instance
app = create_app()


def start() -> None:
    """Entrypoint invoked via pyproject.toml CLI script [project.scripts]."""
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.brain_host,
        port=settings.brain_port,
        log_level=settings.brain_log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    start()
