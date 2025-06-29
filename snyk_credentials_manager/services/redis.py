from redis import Redis
from core.config import settings

redis_client: Redis = Redis(
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


def store_auth_token(
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

    redis_client.set(key, auth_token, ex=expiration)

    return {"message": "Auth token stored."}


def get_auth_token(org_id: str, client_id: str) -> str | None:
    """
    Retrieves the Snyk auth token for the specified org/client from Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        str | None: The Snyk auth token if found, otherwise None.
    """

    key: str = format_key(org_id, client_id)

    if not redis_client.exists(key):
        return None

    return redis_client.get(key)


def delete_auth_token(org_id: str, client_id: str) -> dict:
    """
    Deletes the Snyk auth token for the specified org/client from Redis.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        dict: A confirmation message indicating the auth token was deleted.
    """

    key: str = format_key(org_id, client_id)

    if not redis_client.exists(key):
        return {"message": "Auth token not found."}

    redis_client.delete(key)

    return {"message": "Auth token deleted."}
