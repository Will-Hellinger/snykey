from logging import getLogger, Logger
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from services import openbao, redis

logger: Logger = getLogger(__name__)

router: APIRouter = APIRouter()


@router.get("/health")
async def health() -> JSONResponse:
    """
    Reports the health of the application and its dependencies.

    Returns:
        JSONResponse: Health status of the app, Redis, and OpenBao.
    """

    status: dict = {
        "redis": "ok",
        "openbao": "ok",
    }
    healthy: bool = True

    try:
        await redis.redis_client.ping()
    except Exception as e:
        logger.warning("Health check: Redis unreachable: %s", e)
        status["redis"] = "unreachable"
        healthy = False

    try:
        unsealed: bool = await openbao.ensure_vault_unsealed()
        if not unsealed:
            status["openbao"] = "sealed"
            healthy = False
    except Exception as e:
        logger.warning("Health check: OpenBao unreachable: %s", e)
        status["openbao"] = "unreachable"
        healthy = False

    status["status"] = "ok" if healthy else "degraded"

    return JSONResponse(
        status_code=200 if healthy else 503,
        content=status,
    )
