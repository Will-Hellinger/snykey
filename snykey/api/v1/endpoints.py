from logging import getLogger, Logger
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from services import openbao, snyk, redis
from core.config import settings

logger: Logger = getLogger(__name__)

router: APIRouter = APIRouter()


@router.put("/credentials")
async def store_credentials(
    org_id: str, client_id: str, client_secret: str, refresh_key: str
) -> JSONResponse:
    """
    Store Snyk credentials in OpenBao.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        client_secret (str): The client secret.
        refresh_key (str): The refresh key.

    Returns:
        JSONResponse: A response indicating success or failure.
    """

    if await openbao.check_vault_sealed():
        return JSONResponse(
            status_code=503,
            content={"error": "Vault is sealed, cannot store credentials."},
        )

    logger.info("Refreshing key to ensure no other process can use it.")
    try:
        result: dict = await snyk.refresh_snyk_token(client_id, client_secret, refresh_key)

        logger.info(
            "Successfully refreshed Snyk token for org_id: %s, client_id: %s",
            org_id,
            client_id,
        )

        await openbao.store_refresh_key(org_id, client_id, result["refresh_token"])
    except Exception as e:
        logger.error("Failed to refresh Snyk token: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    return JSONResponse(content={"message": "Credentials stored."})


@router.get("/credentials")
async def get_credentials(org_id: str, client_id: str, client_secret: str) -> JSONResponse:
    """
    Gather Snyk credentials using the provided org_id and client_id.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        JSONResponse: A response containing the gathered credentials or an error message.
    """

    # Check if auth token exists in Redis
    logger.info(
        "Checking Redis for auth token for org_id: %s, client_id: %s",
        org_id,
        client_id,
    )

    auth_token: bytes | None = None

    try:
        auth_token = await redis.get_auth_token(org_id, client_id)
    except Exception as e:
        logger.error("Failed to retrieve auth token from Redis: %s", e)

    if auth_token:
        logger.info("Found auth token in Redis")
        return JSONResponse(content={"access_token": str(auth_token.decode())})

    # Get refresh key from OpenBao
    logger.info(
        "Gathering Snyk credentials for org_id: %s, client_id: %s",
        org_id,
        client_id,
    )

    refresh_key: str | None = None
    
    try:
        refresh_key = await openbao.get_refresh_key(org_id, client_id)
    except Exception as e:
        logger.error("Failed to retrieve refresh key from OpenBao: %s", e)

    if not refresh_key:
        return JSONResponse(
            status_code=404, content={"error": "No refresh key found for org/client"}
        )

    # Refresh Snyk token
    logger.info(
        "Refreshing Snyk token for org_id: %s, client_id: %s", org_id, client_id
    )
    try:
        result: dict = await snyk.refresh_snyk_token(client_id, client_secret, refresh_key)

        logger.info(
            "Successfully refreshed Snyk token for org_id: %s, client_id: %s",
            org_id,
            client_id,
        )
        await openbao.update_refresh_key(org_id, client_id, result["refresh_token"])
    except Exception as e:
        logger.error("Failed to refresh Snyk token: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    try:
        await redis.store_auth_token(
            org_id,
            client_id,
            str(result["access_token"]),
            expiration=settings.REDIS_CACHE_TIME * 60,
        )
    except Exception as e:
        logger.error("Failed to store auth token in Redis: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    return JSONResponse(content={"access_token": str(result["access_token"])})


@router.delete("/credentials")
async def delete_credentials(org_id: str, client_id: str) -> JSONResponse:
    """
    Delete Snyk credentials for a given org_id and client_id.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        JSONResponse: A response indicating success or failure of the deletion.
    """

    if not org_id or not client_id:
        return JSONResponse(
            status_code=400, content={"error": "org_id and client_id are required"}
        )

    # Delete auth token from Redis
    logger.info(
        "Deleting auth token from Redis for org_id: %s, client_id: %s",
        org_id,
        client_id,
    )

    await redis.delete_auth_token(org_id, client_id)

    await openbao.delete_refresh_key(org_id, client_id)

    return JSONResponse(content={"message": "Credentials deleted."})


@router.delete("/cache")
async def delete_cache_key(org_id: str, client_id: str) -> JSONResponse:
    """
    Deletes the Snyk auth token for the specified org/client from Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        JSONResponse: A confirmation message indicating the auth token was deleted.
    """

    response: dict = await redis.delete_auth_token(org_id, client_id)

    return JSONResponse(content=response)