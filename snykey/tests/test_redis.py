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


def test_format_pkce_key():
    """
    Test the format_pkce_key function to ensure it constructs the Redis key correctly.
    """

    state = "test_state_123"
    assert redis_service.format_pkce_key(state) == "pkce:test_state_123"


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_store_pkce_data(mock_redis):
    """
    Test storing PKCE data in Redis.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    mock_redis.set = AsyncMock(return_value=True)

    result: dict = await redis_service.store_pkce_data(
        state="state123",
        code_verifier="verifier",
        client_id="client1",
        client_secret="secret1",
        redirect_uri="https://example.com",
        org_id="org1",
        code="auth_code",
        expiration=600,
    )

    assert result == {"message": "PKCE data stored."}
    mock_redis.set.assert_awaited_once()

    # Verify the key format
    call_args = mock_redis.set.call_args
    assert call_args[0][0] == "pkce:state123"


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_pkce_data_found(mock_redis):
    """
    Test retrieving PKCE data from Redis when it exists.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    import json

    pkce_data = {
        "code_verifier": "verifier",
        "client_id": "client1",
        "client_secret": "secret1",
        "redirect_uri": "https://example.com",
        "org_id": "org1",
        "code": "auth_code",
    }

    mock_redis.exists = AsyncMock(return_value=True)
    mock_redis.get = AsyncMock(return_value=json.dumps(pkce_data).encode())

    result: dict | None = await redis_service.get_pkce_data("state123")

    assert result == pkce_data


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_pkce_data_not_found(mock_redis):
    """
    Test retrieving PKCE data from Redis when it does not exist.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    mock_redis.exists = AsyncMock(return_value=False)

    result: dict | None = await redis_service.get_pkce_data("state123")

    assert result is None


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_delete_pkce_data_found(mock_redis):
    """
    Test deleting PKCE data from Redis when it exists.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    mock_redis.exists = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)

    result: dict = await redis_service.delete_pkce_data("state123")

    assert result == {"message": "PKCE data deleted."}
    mock_redis.delete.assert_awaited_with("pkce:state123")


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_delete_pkce_data_not_found(mock_redis):
    """
    Test deleting PKCE data from Redis when it does not exist.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    mock_redis.exists = AsyncMock(return_value=False)

    result: dict = await redis_service.delete_pkce_data("state123")

    assert result == {"message": "PKCE data not found."}


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_all_states(mock_redis):
    """
    Test retrieving all state values from Redis.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    # Mock scan_iter to return some keys
    async def mock_scan_iter(match):
        keys = [b"pkce:state1", b"pkce:state2", b"pkce:state3"]
        for key in keys:
            yield key

    mock_redis.scan_iter = mock_scan_iter

    result: list[str] = await redis_service.get_all_states()

    assert result == ["state1", "state2", "state3"]


@pytest.mark.asyncio
@patch.object(redis_service, "redis_client")
async def test_get_all_states_empty(mock_redis):
    """
    Test retrieving all state values from Redis when there are none.

    Args:
        mock_redis (AsyncMock): Mocked Redis client.
    """

    # Mock scan_iter to return no keys
    async def mock_scan_iter(match):
        return
        yield  # Make it an async generator

    mock_redis.scan_iter = mock_scan_iter

    result: list[str] = await redis_service.get_all_states()

    assert result == []
