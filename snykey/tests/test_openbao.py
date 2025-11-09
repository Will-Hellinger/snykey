import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from services import openbao


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


@pytest.fixture
def refresh_key() -> str:
    """
    Fixture for refresh key.

    Returns:
        str: The Snyk refresh key.
    """

    return "refresh123"


@pytest.mark.asyncio
async def test_check_vault_sealed_true():
    """
    Test that check_vault_sealed returns True when Vault is sealed.
    """

    # httpx response methods are sync, not async
    mock_response = MagicMock()
    mock_response.json.return_value = {"sealed": True}
    mock_response.raise_for_status.return_value = None

    # Mock the async get method
    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "get", side_effect=mock_get):
        assert await openbao.check_vault_sealed() is True


@pytest.mark.asyncio
async def test_check_vault_sealed_false():
    """
    Test that check_vault_sealed returns False when Vault is not sealed.
    """

    mock_response = MagicMock()
    mock_response.json.return_value = {"sealed": False}
    mock_response.raise_for_status.return_value = None

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "get", side_effect=mock_get):
        assert await openbao.check_vault_sealed() is False


@pytest.mark.asyncio
async def test_check_vault_sealed_error():
    """
    Test that check_vault_sealed raises an exception when there is an error checking the seal status.
    """

    with patch.object(
        openbao.http_client, "get", side_effect=Exception("Connection failed")
    ):
        with pytest.raises(RuntimeError):
            await openbao.check_vault_sealed()


def test_vault_path(org_id: str, client_id: str):
    """
    Test that _vault_path constructs the correct Vault path for storing Snyk credentials.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    assert openbao._vault_path(org_id, client_id) == "kv/data/snyk/org1/client1"


def test_vault_path_missing_args():
    """
    Test that _vault_path raises ValueError when org_id or client_id is missing.
    """

    with pytest.raises(ValueError):
        openbao._vault_path("", "client1")

    with pytest.raises(ValueError):
        openbao._vault_path("org1", "")


@pytest.mark.asyncio
async def test_store_refresh_key_success(org_id: str, client_id: str):
    """
    Test that store_refresh_key successfully stores the Snyk refresh token in OpenBao.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_response: MagicMock = MagicMock()
    mock_response.raise_for_status.return_value = None

    async def mock_post(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "post", side_effect=mock_post):
        result = await openbao.store_refresh_key(org_id, client_id, "refresh_token")
        assert result is True


@pytest.mark.asyncio
async def test_store_refresh_key_error(org_id: str, client_id: str):
    """
    Test that store_refresh_key handles errors when storing the Snyk refresh token in OpenBao.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    with patch.object(
        openbao.http_client, "post", side_effect=Exception("Connection failed")
    ):
        result = await openbao.store_refresh_key(org_id, client_id, "refresh_token")

        assert result is False


@pytest.mark.asyncio
async def test_get_refresh_key_found(org_id: str, client_id: str, refresh_key: str):
    """
    Test that get_refresh_key retrieves the Snyk refresh key from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to retrieve.
    """
    mock_response = MagicMock()
    mock_response.json.return_value = {"data": {"data": {"refresh_token": refresh_key}}}
    mock_response.raise_for_status.return_value = None

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "get", side_effect=mock_get):
        result = await openbao.get_refresh_key(org_id, client_id)
        assert result == refresh_key


@pytest.mark.asyncio
async def test_get_refresh_key_not_found(org_id: str, client_id: str):
    """
    Test that get_refresh_key returns None when the refresh key is not found.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """
    with patch.object(openbao.http_client, "get", side_effect=Exception("Not found")):
        result = await openbao.get_refresh_key(org_id, client_id)
        assert result is None


@pytest.mark.asyncio
async def test_update_refresh_key(org_id: str, client_id: str, refresh_key: str):
    """
    Test that update_refresh_key updates the Snyk refresh key in Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to update.
    """
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None

    async def mock_post(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "post", side_effect=mock_post):
        result = await openbao.update_refresh_key(org_id, client_id, refresh_key)
        assert result == {"message": "Refresh key updated."}


@pytest.mark.asyncio
async def test_delete_refresh_key(org_id: str, client_id: str):
    """
    Test that delete_refresh_key deletes the Snyk refresh key from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None

    async def mock_delete(*args, **kwargs):
        return mock_response

    with patch.object(openbao.http_client, "delete", side_effect=mock_delete):
        result = await openbao.delete_refresh_key(org_id, client_id)
        assert result == {"message": "Refresh key deleted."}
