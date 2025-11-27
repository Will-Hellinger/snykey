from logging import getLogger, Logger
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from services import openbao, snyk, redis, oauth
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

    org_id = org_id.strip()
    client_id = client_id.strip()
    client_secret = client_secret.strip()
    refresh_key = refresh_key.strip()

    if await openbao.check_vault_sealed():
        return JSONResponse(
            status_code=503,
            content={"error": "Vault is sealed, cannot store credentials."},
        )

    logger.info("Refreshing key to ensure no other process can use it.")
    try:
        result: dict = await snyk.refresh_snyk_token(
            client_id, client_secret, refresh_key
        )

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
async def get_credentials(
    org_id: str, client_id: str, client_secret: str
) -> JSONResponse:
    """
    Gather Snyk credentials using the provided org_id and client_id.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        JSONResponse: A response containing the gathered credentials or an error message.
    """

    org_id = org_id.strip()
    client_id = client_id.strip()
    client_secret = client_secret.strip()

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

    expires_in: int = 3600

    try:
        result: dict = await snyk.refresh_snyk_token(
            client_id, client_secret, refresh_key
        )

        logger.info(
            "Successfully refreshed Snyk token for org_id: %s, client_id: %s",
            org_id,
            client_id,
        )

        expires_in = result.get("expires_in", 3600)

        await openbao.update_refresh_key(org_id, client_id, result["refresh_token"])
    except Exception as e:
        logger.error("Failed to refresh Snyk token: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    try:
        await redis.store_auth_token(
            org_id,
            client_id,
            str(result["access_token"]),
            expiration=min(settings.REDIS_CACHE_TIME, expires_in),
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

    org_id = org_id.strip()
    client_id = client_id.strip()

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

    org_id = org_id.strip()
    client_id = client_id.strip()

    response: dict = await redis.delete_auth_token(org_id, client_id)

    return JSONResponse(content=response)


@router.post("/register-app")
async def register_app(
    name: str,
    scopes: str,
    redirect_uris: str,
    org_id: str,
    auth_token: str,
) -> JSONResponse:
    """
    Register a new Snyk app with the specified parameters.

    Args:
        name (str): Name of the Snyk app.
        scopes (str): Comma-separated list of scopes for the Snyk app.
        redirect_uris (str): Comma-separated list of redirect URIs for the Snyk app. The first one is assumed for storing PKCE data.
        org_id (str): Snyk organization ID (stored in PKCE data for callback).
        auth_token (str): Snyk authentication token.

    Returns:
        JSONResponse: A response containing the registered app details or an error message.
    """

    code_verifier: str | None = None
    code_challenge: str | None = None
    state: str | None = None

    used_states: list[str] = await redis.get_all_states()

    try:
        code_verifier = await oauth.generate_code_verifier()
        code_challenge = await oauth.generate_code_challenge(code_verifier)

        while not (state and state not in used_states):
            state = await oauth.generate_state()

    except Exception as e:
        logger.error("Failed to generate OAuth parameters: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    org_id = org_id.strip()
    auth_token = auth_token.strip()
    name = name.strip()

    scopes_list: list[str] = [s.strip() for s in scopes.split(",")]
    redirect_uris_list: list[str] = [u.strip() for u in redirect_uris.split(",")]

    result: dict = {}

    try:
        result = await snyk.register_snyk_app(
            name, scopes_list, redirect_uris_list, org_id, auth_token
        )
    except Exception as e:
        logger.error("Failed to register Snyk app: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})

    client_id: str | None = (
        result.get("data", {}).get("attributes", {}).get("client_id", None)
    )
    client_secret: str | None = (
        result.get("data", {}).get("attributes", {}).get("client_secret", None)
    )

    if client_id is None:
        logger.error("Client ID not found in Snyk app registration response.")
        return JSONResponse(
            status_code=500, content={"error": "Client ID not found in response."}
        )

    auth_urls: dict = {}

    for uri in redirect_uris_list:
        auth_url: str = snyk.generate_auth_url(
            client_id=client_id,
            redirect_uri=uri,
            scopes=scopes_list,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )

        auth_urls[uri] = auth_url

    result["auth_urls"] = auth_urls

    await redis.store_pkce_data(
        state=state,
        code_verifier=code_verifier,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uris_list[
            0
        ],  # Assuming the first redirect URI is used for storing
        org_id=org_id,
        expiration=settings.REDIS_PKCE_EXPIRATION,
    )

    return JSONResponse(content=result)


@router.get("/callback")
async def oauth_callback(
    code: str = Query(..., description="Authorization code from Snyk"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    instance: str = Query(default="api.snyk.io", description="Snyk instance"),
) -> JSONResponse:
    """
    OAuth callback endpoint to handle the authorization code flow.

    This endpoint receives the authorization code from Snyk, retrieves the PKCE data
    (which includes org_id), exchanges the code for tokens, and stores the refresh token in OpenBao.

    Args:
        code (str): The authorization code from Snyk.
        state (str): The state parameter for CSRF protection.
        instance (str): The Snyk instance (default: api.snyk.io).

    Returns:
        JSONResponse: A response indicating success or failure.
    """

    logger.info("Received OAuth callback with state: %s", state)

    # Retrieve PKCE data from Redis using state
    pkce_data: dict | None = await redis.get_pkce_data(state.strip())

    if not pkce_data:
        logger.error("PKCE data not found for state: %s", state)
        return JSONResponse(
            status_code=400, content={"error": "Invalid or expired state parameter"}
        )

    code_verifier: str = pkce_data.get("code_verifier")
    client_id: str = pkce_data.get("client_id").strip()
    client_secret: str = pkce_data.get("client_secret")
    redirect_uri: str = pkce_data.get("redirect_uri")
    org_id: str = pkce_data.get("org_id").strip()

    if not all([code_verifier, client_id, client_secret, redirect_uri, org_id]):
        logger.error("Incomplete PKCE data for state: %s", state)
        return JSONResponse(status_code=500, content={"error": "Incomplete PKCE data"})

    if await openbao.check_vault_sealed():
        logger.error("Vault is sealed, cannot proceed with OAuth callback")
        return JSONResponse(
            status_code=503,
            content={"error": "Vault is sealed, cannot store credentials."},
        )

    refresh_token: str | None = None
    access_token: str | None = None
    expires_in: int = 3600

    logger.info("Exchanging authorization code for tokens")
    try:
        token_response: dict = await snyk.exchange_code_for_token(
            code=code,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        refresh_token = token_response.get("refresh_token")
        access_token = token_response.get("access_token")
        expires_in = token_response.get("expires_in", 3600)

        logger.info("Successfully exchanged code for tokens")

    except Exception as e:
        logger.error("Failed to exchange code for tokens: %s", e)
        # Clean up PKCE data on failure
        await redis.delete_pkce_data(state)
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to exchange code for tokens: {str(e)}"},
        )

    logger.info(
        "Storing refresh token in OpenBao for org_id: %s, client_id: %s",
        org_id,
        client_id,
    )
    try:
        await openbao.store_refresh_key(org_id, client_id, refresh_token)
        logger.info("Successfully stored refresh token in OpenBao")
    except Exception as e:
        logger.error("Failed to store refresh token in OpenBao: %s", e)

        await redis.delete_pkce_data(state)
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to store refresh token: {str(e)}"},
        )

    logger.info("Storing access token in Redis cache")
    try:
        await redis.store_auth_token(
            org_id=org_id,
            client_id=client_id,
            auth_token=access_token,
            expiration=min(expires_in, settings.REDIS_CACHE_TIME),
        )
        logger.info("Successfully stored access token in Redis")
    except Exception as e:
        logger.warning("Failed to store access token in Redis cache: %s", e)

    await redis.delete_pkce_data(state)
    logger.info("OAuth callback completed successfully")

    return JSONResponse(
        content={
            "message": "Successfully authenticated and stored credentials",
            "org_id": org_id,
            "client_id": client_id,
        }
    )
