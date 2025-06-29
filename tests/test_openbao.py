import pytest
from unittest.mock import patch
from snyk_credentials_manager.services import openbao


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


def test_check_vault_sealed_true():
    """
    Test that check_vault_sealed returns True when Vault is sealed.
    """

    with patch.object(openbao.client.sys, "is_sealed", return_value=False):
        assert openbao.check_vault_sealed() is False


def test_check_vault_sealed_false():
    """
    Test that check_vault_sealed returns False when Vault is not sealed.
    """

    with patch.object(openbao.client.sys, "is_sealed", return_value=True):
        assert openbao.check_vault_sealed() is True


def test_check_vault_sealed_error():
    """
    Test that check_vault_sealed raises an exception when there is an error checking the seal status.
    """

    with patch.object(openbao.client.sys, "is_sealed", side_effect=Exception("fail")):
        with pytest.raises(Exception):
            openbao.check_vault_sealed()


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


@patch.object(openbao.client.secrets.kv.v2, "create_or_update_secret")
def test_store_refresh_key_success(
    mock_create, org_id: str, client_id: str, refresh_key: str
):
    """
    Test that store_refresh_key successfully stores the Snyk refresh key in Vault.

    Args:
        mock_create (MagicMock): Mocked create_or_update_secret method.
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to store.
    """

    mock_create.return_value = None

    result: dict = openbao.store_refresh_key(org_id, client_id, refresh_key)

    assert result == {"message": "Refresh key stored."}

    mock_create.assert_called_once()


@patch.object(
    openbao.client.secrets.kv.v2,
    "create_or_update_secret",
    side_effect=Exception("fail"),
)
def test_store_refresh_key_error(
    mock_create, org_id: str, client_id: str, refresh_key: str
):
    """
    Test that store_refresh_key handles errors when storing the Snyk refresh key in Vault.

    Args:
        mock_create (MagicMock): Mocked create_or_update_secret method that raises an exception.
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to store.
    """

    result: dict = openbao.store_refresh_key(org_id, client_id, refresh_key)

    assert result["message"] == "Failed to store refresh key."
    assert "fail" in result["error"]


@patch.object(openbao.client.secrets.kv.v2, "read_secret_version")
def test_get_refresh_key_found(
    mock_read, org_id: str, client_id: str, refresh_key: str
):
    """
    Test that get_refresh_key retrieves the Snyk refresh key from Vault.

    Args:
        mock_read (MagicMock): Mocked read_secret_version method.
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to retrieve.
    """

    mock_read.return_value = {"data": {"data": {"refresh_key": refresh_key}}}

    result: str | None = openbao.get_refresh_key(org_id, client_id)

    assert result == refresh_key


@patch.object(
    openbao.client.secrets.kv.v2, "read_secret_version", side_effect=Exception()
)
def test_get_refresh_key_not_found(mock_read, org_id: str, client_id: str):
    """
    Test that get_refresh_key returns None when the refresh key is not found.

    Args:
        mock_read (MagicMock): Mocked read_secret_version method that raises an exception.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    result: str | None = openbao.get_refresh_key(org_id, client_id)

    assert result is None


@patch.object(openbao, "store_refresh_key")
def test_update_refresh_key(mock_store, org_id: str, client_id: str, refresh_key: str):
    """
    Test that update_refresh_key updates the Snyk refresh key in Vault.

    Args:
        mock_store (MagicMock): Mocked store_refresh_key method.
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to update.
    """

    mock_store.return_value = {"message": "Refresh key stored."}

    result: dict = openbao.update_refresh_key(org_id, client_id, refresh_key)

    assert result == {"message": "Refresh key stored."}


@patch.object(openbao.client.secrets.kv.v2, "delete_metadata_and_all_versions")
def test_delete_refresh_key(mock_delete, org_id: str, client_id: str):
    """
    Test that delete_refresh_key deletes the Snyk refresh key from Vault.

    Args:
        mock_delete (MagicMock): Mocked delete_metadata_and_all_versions method.
        org_id (str): The organization ID.
        client_id (str): The client ID.
    """

    mock_delete.return_value = None

    result: dict = openbao.delete_refresh_key(org_id, client_id)

    assert result == {"message": "Refresh key deleted."}

    mock_delete.assert_called_once()
