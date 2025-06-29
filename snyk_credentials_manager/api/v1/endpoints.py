from logging import getLogger, Logger
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from models.schema import CredentialsRequest
from services import openbao, snyk, redis

logger: Logger = getLogger(__name__)

router: APIRouter = APIRouter()


@router.post("/store_credentials", status_code=status.HTTP_201_CREATED)
def store_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Store Snyk credentials in OpenBao.

    Args:
        req (CredentialsRequest): The request containing org_id, client_id, and refresh_key.

    Returns:
        JSONResponse: A response indicating success or failure.
    """

    if not req.refresh_key:
        return JSONResponse(status_code=400, content={"error": "refresh_key required"})

    openbao.store_refresh_key(req.org_id, req.client_id, req.refresh_key)

    return JSONResponse(content={"message": "Credentials stored."})


@router.post("/gather_credentials")
def gather_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Gather Snyk credentials using the provided org_id and client_id.

    Args:
        req (CredentialsRequest): The request containing org_id and client_id.

    Returns:
        JSONResponse: A response containing the gathered credentials or an error message.
    """

    # Get refresh key from OpenBao
    logger.info(
        "Gathering Snyk credentials for org_id: %s, client_id: %s",
        req.org_id,
        req.client_id,
    )

    refresh_key: str | None = openbao.get_refresh_key(req.org_id, req.client_id)

    if not refresh_key:
        return JSONResponse(
            status_code=404, content={"error": "No refresh key found for org/client"}
        )

    # Check if auth token exists in Redis
    logger.info(
        "Checking Redis for auth token for org_id: %s, client_id: %s",
        req.org_id,
        req.client_id,
    )

    auth_token: bytes | None = None

    try:
        auth_token = redis.get_auth_token(req.org_id, req.client_id)
    except Exception as e:
        logger.error("Failed to retrieve auth token from Redis: %s", e)

    if auth_token:
        logger.info("Found auth token in Redis")
        return JSONResponse(
            content={
                "access_token": str(auth_token.decode())
            }
        )

    # Refresh Snyk token
    logger.info(
        "Refreshing Snyk token for org_id: %s, client_id: %s", req.org_id, req.client_id
    )
    try:
        result: dict = snyk.refresh_snyk_token(
            req.client_id, req.client_secret, refresh_key
        )
    except Exception as e:
        logger.error("Failed to refresh Snyk token: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    try:
        redis.store_auth_token(
            req.org_id,
            req.client_id,
            str(result["access_token"]),
            expiration=int(result["expires_in"]) - 60,  # Subtract 60 seconds for safety
        )
    except Exception as e:
        logger.error("Failed to store auth token in Redis: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    # Update refresh key in openbao
    logger.info(
        "Updating refresh key in OpenBao for org_id: %s, client_id: %s",
        req.org_id,
        req.client_id,
    )

    openbao.update_refresh_key(req.org_id, req.client_id, result["refresh_token"])

    return JSONResponse(
        content={
            "access_token": str(result["access_token"])
        }
    )


@router.post("/delete_credentials")
def delete_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Delete Snyk credentials for a given org_id and client_id.

    Args:
        req (CredentialsRequest): The request containing org_id and client_id.

    Returns:
        JSONResponse: A response indicating success or failure of the deletion.
    """

    if not req.org_id or not req.client_id:
        return JSONResponse(
            status_code=400, content={"error": "org_id and client_id are required"}
        )

    # Delete auth token from Redis
    logger.info(
        "Deleting auth token from Redis for org_id: %s, client_id: %s",
        req.org_id,
        req.client_id,
    )

    redis.delete_auth_token(req.org_id, req.client_id)

    openbao.delete_refresh_key(req.org_id, req.client_id)

    return JSONResponse(content={"message": "Credentials deleted."})
