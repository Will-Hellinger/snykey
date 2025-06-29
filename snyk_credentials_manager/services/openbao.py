import hvac
from core.config import settings

OPENBAO_ADDR = settings.OPENBAO_ADDR
OPENBAO_TOKEN = settings.OPENBAO_TOKEN

client: hvac.Client = hvac.Client(url=OPENBAO_ADDR, token=OPENBAO_TOKEN, verify=False)

SECRET_MOUNT_POINT = "kv"  # Default mount point for Vault KV secrets engine


def _vault_path(org_id: str, client_id: str) -> str:
    """
    Constructs the Vault path for storing Snyk credentials.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        str: The Vault path for the Snyk credentials.
    """

    if not org_id or not client_id:
        raise ValueError("Both org_id and client_id must be provided")

    return f"{SECRET_MOUNT_POINT}/data/snyk/{org_id}/{client_id}"


def store_refresh_key(org_id: str, client_id: str, refresh_key: str) -> dict:
    """
    Stores the Snyk refresh key in Vault under the specified org/client path.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The Snyk refresh key to store.

    Returns:
        dict: A confirmation message indicating the refresh key was stored.
    """

    path: str = _vault_path(org_id, client_id)

    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=path.replace(f"{SECRET_MOUNT_POINT}/data/", ""),
            secret={"refresh_key": refresh_key},
            mount_point=SECRET_MOUNT_POINT,
        )
    except Exception as e:
        return {"message": "Failed to store refresh key.", "error": str(e)}

    return {"message": "Refresh key stored."}


def get_refresh_key(org_id: str, client_id: str) -> str | None:
    """
    Retrieves the Snyk refresh key for the specified org/client from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        str | None: The Snyk refresh key if found, otherwise None.
    """

    path: str = _vault_path(org_id, client_id)

    try:
        secret = client.secrets.kv.v2.read_secret_version(
            path=path.replace(f"{SECRET_MOUNT_POINT}/data/", ""),
            mount_point=SECRET_MOUNT_POINT,
        )

        return secret["data"]["data"].get("refresh_key")
    except hvac.exceptions.InvalidPath:
        return None


def update_refresh_key(org_id: str, client_id: str, refresh_key: str) -> dict:
    """
    Updates the Snyk refresh key for the specified org/client in Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The new Snyk refresh key to store.

    Returns:
        dict: A confirmation message indicating the refresh key was updated.
    """

    # Same as store (Vault will overwrite)
    return store_refresh_key(org_id, client_id, refresh_key)


def delete_refresh_key(org_id: str, client_id: str) -> dict:
    """
    Deletes the Snyk refresh key for the specified org/client from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        dict: A confirmation message indicating the refresh key was deleted.
    """

    path: str = _vault_path(org_id, client_id)

    client.secrets.kv.v2.delete_metadata_and_all_versions(
        path=path.replace(f"{SECRET_MOUNT_POINT}/data/", ""),
        mount_point=SECRET_MOUNT_POINT,
    )

    return {"message": "Refresh key deleted."}
