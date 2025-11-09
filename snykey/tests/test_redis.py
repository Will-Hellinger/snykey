import pytest
from unittest.mock import patch, AsyncMock
from services import redis as redis_service


@pytest.fixture
def org_id() -> str:
    """
    Fixture for organization ID.

    Returns:
        str: The organization ID.
    """

    return "org1"


@pytest.fixture
def client_id() -> str:
    """
    Fixture for client ID.

    Returns:
        str: The client ID.
    """

    return "client1"


def test_format_key(org_id: str, client_id: str):
    """
    Test the format_key function to ensure it constructs the Redis key correctly.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    assert redis_service.format_key(org_id, client_id) == "snyk:org1:client1"


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_store_auth_token(mock_redis, org_id: str, client_id: str):
    """
    Test storing an auth token in Redis.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.set = AsyncMock(return_value=True)
    result: dict = await redis_service.store_auth_token(
        org_id, client_id, "token", expiration=60
    )
    mock_redis.set.assert_awaited_with("snyk:org1:client1", "token", ex=60)

    assert result == {"message": "Auth token stored."}


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_auth_token_found(mock_redis, org_id: str, client_id: str):
    """
    Test retrieving an auth token from Redis when it exists.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.exists = AsyncMock(return_value=True)
    mock_redis.get = AsyncMock(return_value=b"token")
    result: bytes | None = await redis_service.get_auth_token(org_id, client_id)

    assert result == b"token"


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_auth_token_not_found(mock_redis, org_id: str, client_id: str):
    """
    Test retrieving an auth token from Redis when it does not exist.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.exists = AsyncMock(return_value=False)
    result: bytes | None = await redis_service.get_auth_token(org_id, client_id)

    assert result is None


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_delete_auth_token_found(mock_redis, org_id: str, client_id: str):
    """
    Test deleting an auth token from Redis when it exists.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.exists = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)
    result: dict = await redis_service.delete_auth_token(org_id, client_id)
    mock_redis.delete.assert_awaited_with("snyk:org1:client1")

    assert result == {"message": "Auth token deleted."}


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_delete_auth_token_not_found(mock_redis, org_id: str, client_id: str):
    """
    Test deleting an auth token from Redis when it does not exist.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """
    mock_redis.exists = AsyncMock(return_value=False)
    result: dict = await redis_service.delete_auth_token(org_id, client_id)

    assert result == {"message": "Auth token not found."}


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_check_token_age_found(mock_redis, org_id: str, client_id: str):
    """
    Test checking the age of an auth token in Redis when it exists.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.exists = AsyncMock(return_value=True)
    mock_redis.ttl = AsyncMock(return_value=42)
    result: int | None = await redis_service.check_token_age(org_id, client_id)

    assert result == 42


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_check_token_age_not_found(mock_redis, org_id: str, client_id: str):
    """
    Test checking the age of an auth token in Redis when it does not exist.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_redis.exists = AsyncMock(return_value=False)
    result: int | None = await redis_service.check_token_age(org_id, client_id)

    assert result is None
