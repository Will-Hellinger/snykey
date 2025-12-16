import core.config
from api.v1 import endpoints

import logging

from fastapi import FastAPI, Request
from fastapi.openapi.utils import get_openapi

from starlette.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


logger: logging.Logger = logging.getLogger(__name__)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate API key from request headers.
    """

    async def dispatch(self, request: Request, call_next):
        """
        Check for valid API key in request headers.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware/handler.

        Returns:
            The response from the next handler or an error response.

        Raises:
            HTTPException: If API key is missing or invalid.
        """

        if request.url.path in core.config.EXCLUDED_PATHS:
            return await call_next(request)

        api_key: str = str(request.headers.get("X-API-Key"))

        if not api_key or api_key != core.config.settings.API_KEY:
            logger.warning(
                "Unauthorized access attempt with invalid or missing API key."
            )

            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized: Invalid or missing API key"},
            )

        response: JSONResponse = await call_next(request)
        return response


def custom_openapi() -> dict:
    """
    Generate custom OpenAPI schema with API key security scheme.

    Returns:
        dict: The OpenAPI schema with security definitions.
    """

    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema: dict = get_openapi(
        title="Snykey API",
        version="1.0.0",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "X-API-Key": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API Key for authentication",
        }
    }
    openapi_schema["security"] = [{"X-API-Key": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


logger.log(logging.INFO, "Starting Snykey API application.")
app: FastAPI = FastAPI()

if core.config.settings.API_KEY:
    logger.info("API Key authentication is enabled.")

    app.openapi = custom_openapi
    app.add_middleware(APIKeyMiddleware)

    logger.info("Middleware is ignored for paths: %s", core.config.EXCLUDED_PATHS)
else:
    logger.warning("API Key is not set. The API is running without authentication!")

app.include_router(endpoints.router, prefix="/v1")
