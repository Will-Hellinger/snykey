import json
import logging
import redis.asyncio as redis
from core.config import settings

logger: logging.Logger = logging.getLogger(__name__)

redis_client: redis.Redis = redis.Redis(
    host=settings.REDIS_HOST, port=settings.REDIS_PORT, password=settings.REDIS_PASSWORD
)


def format_key(org_id: str, client_id: str) -> str:
    """
    Constructs a Redis key for storing Snyk credentials based on organization and client IDs.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        str: The formatted Redis key.
    """

    return f"snyk:{org_id}:{client_id}"


async def store_auth_token(
    org_id: str, client_id: str, auth_token: str, expiration: int | None = None
) -> dict:
    """
    Stores the Snyk auth token in Redis under the specified org/client key.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        auth_token (str): The Snyk auth token to store.
        expiration (int): The expiration time in seconds for the auth token.

    Returns:
        dict: A confirmation message indicating the auth token was stored.
    """

    key: str = format_key(org_id, client_id)

    await redis_client.set(key, auth_token, ex=expiration)

    return {"message": "Auth token stored."}


async def get_auth_token(org_id: str, client_id: str) -> bytes | None:
    """
    Retrieves the Snyk auth token for the specified org/client from Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        bytes | None: The Snyk auth token if found, otherwise None.
    """

    key: str = format_key(org_id, client_id)

    if not await redis_client.exists(key):
        return None

    return await redis_client.get(key)


async def delete_auth_token(org_id: str, client_id: str) -> dict:
    """
    Deletes the Snyk auth token for the specified org/client from Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        dict: A confirmation message indicating the auth token was deleted.
    """

    key: str = format_key(org_id, client_id)

    if not await redis_client.exists(key):
        return {"message": "Auth token not found."}

    await redis_client.delete(key)

    return {"message": "Auth token deleted."}


async def check_token_age(org_id: str, client_id: str) -> int | None:
    """
    Checks the age of the Snyk auth token for the specified org/client in Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        int | None: The age of the auth token in seconds if found, otherwise None.
    """

    key: str = format_key(org_id, client_id)

    if not await redis_client.exists(key):
        return None

    return await redis_client.ttl(key)


def format_pkce_key(state: str) -> str:
    """
    Constructs a Redis key for storing PKCE and app info based on state.

    Args:
        state (str): The OAuth state parameter.

    Returns:
        str: The formatted Redis key.
    """

    return f"pkce:{state}"


async def store_pkce_data(
    state: str,
    code_verifier: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    org_id: str,
    code: str | None = None,
    expiration: int = 600,
) -> dict:
    """
    Stores PKCE and app registration data in Redis.

    Args:
        state (str): The OAuth state parameter (used as key).
        code_verifier (str): The PKCE code verifier.
        client_id (str): The Snyk app client ID.
        client_secret (str): The Snyk app client secret.
        redirect_uri (str): The redirect URI for the OAuth flow.
        org_id (str): The Snyk organization ID.
        code (str | None): Optional authorization code.
        expiration (int): Expiration time in seconds (default: 600 = 10 minutes).

    Returns:
        dict: A confirmation message indicating the data was stored.
    """

    key: str = format_pkce_key(state)

    data: dict = {
        "code_verifier": code_verifier,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "org_id": org_id,
        "code": code,
    }

    await redis_client.set(key, json.dumps(data), ex=expiration)

    return {"message": "PKCE data stored."}


async def get_pkce_data(state: str) -> dict | None:
    """
    Retrieves PKCE and app registration data from Redis.

    Args:
        state (str): The OAuth state parameter.

    Returns:
        dict | None: The PKCE data if found, otherwise None.
    """

    key: str = format_pkce_key(state)

    if not await redis_client.exists(key):
        return None

    data: bytes | None = await redis_client.get(key)

    if data is None:
        return None

    return json.loads(data)


async def delete_pkce_data(state: str) -> dict:
    """
    Deletes PKCE and app registration data from Redis.

    Args:
        state (str): The OAuth state parameter.

    Returns:
        dict: A confirmation message indicating the data was deleted.
    """

    key: str = format_pkce_key(state)

    if not await redis_client.exists(key):
        return {"message": "PKCE data not found."}

    await redis_client.delete(key)

    return {"message": "PKCE data deleted."}


async def get_all_states() -> list[str]:
    """
    Retrieves all state values (keys) for stored PKCE data.

    Returns:
        list[str]: A list of all state values.
    """

    pattern: str = "pkce:*"
    keys: list[bytes] = []

    async for key in redis_client.scan_iter(match=pattern):
        keys.append(key)

    states: list[str] = [key.decode("utf-8").removeprefix("pkce:") for key in keys]

    return states
