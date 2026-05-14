import httpx
import logging
from core.config import settings

logger: logging.Logger = logging.getLogger(__name__)

OPENBAO_ADDR: str = settings.OPENBAO_ADDR
OPENBAO_TOKEN: str = settings.OPENBAO_TOKEN
OPENBAO_UNSEAL_KEY: str = settings.OPENBAO_UNSEAL_KEY
SECRET_MOUNT_POINT: str = "kv"

_ssl_verify: str | bool = settings.OPENBAO_CA_CERT if settings.OPENBAO_CA_CERT else True

http_client: httpx.AsyncClient = httpx.AsyncClient(
    verify=_ssl_verify,
    timeout=30.0,
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
)


async def check_vault_sealed() -> bool:
    """
    Checks if the Vault is sealed.

    Returns:
        bool: True if Vault is sealed, False otherwise.
    """

    url: str = f"{OPENBAO_ADDR}/v1/sys/seal-status"
    headers: dict[str, str] = {"X-Vault-Token": OPENBAO_TOKEN}

    try:
        resp: httpx.Response = await http_client.get(url, headers=headers)

        resp.raise_for_status()
        data: dict = resp.json()

        sealed = data.get("sealed", True)
        logger.info("Vault seal status check: sealed=%s, response=%s", sealed, data)
        return sealed
    except Exception as e:
        logger.error("Failed to check Vault seal status: %s", str(e))
        raise RuntimeError("Failed to check Vault seal status: %s" % str(e))


async def unseal_vault() -> bool:
    """
    Attempts to unseal the Vault using the configured unseal key.

    Returns:
        bool: True if the Vault is unsealed after the attempt, False otherwise.
    """

    if not OPENBAO_UNSEAL_KEY:
        logger.error("No unseal key configured, cannot unseal Vault")
        return False

    url: str = f"{OPENBAO_ADDR}/v1/sys/unseal"
    headers: dict[str, str] = {"X-Vault-Token": OPENBAO_TOKEN}

    try:
        resp: httpx.Response = await http_client.post(
            url, headers=headers, json={"key": OPENBAO_UNSEAL_KEY}
        )
        resp.raise_for_status()
        data: dict = resp.json()

        sealed: bool = data.get("sealed", True)
        logger.info("Vault unseal attempt result: sealed=%s", sealed)
        return not sealed
    except Exception as e:
        logger.error("Failed to unseal Vault: %s", str(e))
        return False


async def ensure_vault_unsealed() -> bool:
    """
    Checks if the Vault is sealed and attempts to unseal it if so.

    Returns:
        bool: True if the Vault is unsealed, False if it remains sealed.
    """

    try:
        if not await check_vault_sealed():
            return True
    except Exception:
        return False

    logger.info("Vault is sealed, attempting automatic unseal")
    return await unseal_vault()


async def store_refresh_key(org_id: str, client_id: str, refresh_token: str) -> bool:
    """
    Stores the Snyk refresh token in OpenBao.

    Args:
        org_id: Organization ID used as the key identifier
        client_id: Client ID used as the key identifier
        refresh_token: Refresh token from Snyk

    Returns:
        bool: True if successful.

    Raises:
        Exception: If the request to OpenBao fails.
    """

    url: str = f"{OPENBAO_ADDR}/v1/{SECRET_MOUNT_POINT}/data/snyk/{org_id}/{client_id}"
    headers: dict[str, str] = {
        "X-Vault-Token": OPENBAO_TOKEN,
        "Content-Type": "application/json",
    }
    data: dict[str, dict[str, str]] = {"data": {"refresh_token": refresh_token}}

    try:
        resp: httpx.Response = await http_client.post(url, headers=headers, json=data)
        resp.raise_for_status()

        return True
    except Exception as e:
        logger.error(
            "Failed to store refresh key for org %s, client %s: %s",
            org_id,
            client_id,
            str(e),
        )
        raise


async def get_refresh_key(org_id: str, client_id: str) -> str | None:
    """
    Retrieves the Snyk refresh key for the specified org/client from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        str | None: The Snyk refresh key if found, otherwise None.
    """

    url: str = f"{OPENBAO_ADDR}/v1/{SECRET_MOUNT_POINT}/data/snyk/{org_id}/{client_id}"
    headers: dict[str, str] = {"X-Vault-Token": OPENBAO_TOKEN}

    try:
        resp: httpx.Response = await http_client.get(url, headers=headers)

        resp.raise_for_status()
        data: dict = resp.json()

        return data.get("data", {}).get("data", {}).get("refresh_token")
    except Exception:
        return None


async def delete_refresh_key(org_id: str, client_id: str) -> dict:
    """
    Deletes the Snyk refresh key for the specified org/client from Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    Returns:
        dict: A confirmation message indicating the refresh key was deleted.
    """

    url: str = (
        f"{OPENBAO_ADDR}/v1/{SECRET_MOUNT_POINT}/metadata/snyk/{org_id}/{client_id}"
    )
    headers: dict[str, str] = {"X-Vault-Token": OPENBAO_TOKEN}

    try:
        resp: httpx.Response = await http_client.delete(url, headers=headers)
        resp.raise_for_status()

        return {"message": "Refresh key deleted."}
    except Exception as e:
        logger.error(
            "Failed to delete refresh key for org %s, client %s: %s",
            org_id,
            client_id,
            str(e),
        )
        return {"error": f"Failed to delete refresh key: {str(e)}"}


async def update_refresh_key(org_id: str, client_id: str, refresh_key: str) -> dict:
    """
    Updates the Snyk refresh key for the specified org/client in Vault.

    Args:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        refresh_key (str): The new Snyk refresh key to store.

    Returns:
        dict: A confirmation message indicating the refresh key was updated.

    Raises:
        Exception: If the request to OpenBao fails.
    """

    url: str = f"{OPENBAO_ADDR}/v1/{SECRET_MOUNT_POINT}/data/snyk/{org_id}/{client_id}"
    headers: dict[str, str] = {
        "X-Vault-Token": OPENBAO_TOKEN,
        "Content-Type": "application/json",
    }
    data: dict[str, dict[str, str]] = {"data": {"refresh_token": refresh_key}}

    try:
        resp: httpx.Response = await http_client.post(url, headers=headers, json=data)
        resp.raise_for_status()

        return {"message": "Refresh key updated."}
    except Exception as e:
        logger.error(
            "Failed to update refresh key for org %s, client %s: %s",
            org_id,
            client_id,
            str(e),
        )
        raise
