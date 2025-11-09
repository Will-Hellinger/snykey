import redis.asyncio as redis
from core.config import settings

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
