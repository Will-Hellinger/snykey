import pytest
from fastapi.testclient import TestClient
from main import app
import asyncio

client = TestClient(app)


@pytest.fixture
def store_req() -> dict:
    """
    Fixture for storing credentials request.

    Returns:
        dict: A dictionary containing organization ID, client ID, client secret, and refresh key.
    """
    
    return {
        "org_id": "org1",
        "client_id": "client1",
        "client_secret": "secret1",
        "refresh_key": "refresh1",
    }


@pytest.fixture
def get_req() -> dict:
    """
    Fixture for getting credentials request.

    Returns:
        dict: A dictionary containing organization ID and client ID.
    """

    return {"org_id": "org1", "client_id": "client1", "client_secret": "secret1"}


@pytest.fixture
def delete_req() -> dict:
    """
    Fixture for deleting credentials request.

    Returns:
        dict: A dictionary containing organization ID and client ID.
    """
    
    return {"org_id": "org1", "client_id": "client1"}


def test_store_credentials_success(monkeypatch, store_req):
    """
    Test storing Snyk credentials successfully.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        store_req: The request data for storing credentials.
    """

    # Patch all external calls with async mocks
    async def async_check_vault_sealed():
        return False
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.check_vault_sealed",
        async_check_vault_sealed,
    )
    async def async_refresh_snyk_token(cid, cs, rk):
        return {
            "access_token": "token",
            "refresh_token": "refresh",
            "expires_in": 3600,
        }
    monkeypatch.setattr(
        "api.v1.endpoints.snyk.refresh_snyk_token",
        async_refresh_snyk_token,
    )
    async def async_store_refresh_key(o, c, r):
        return True
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.store_refresh_key",
        async_store_refresh_key,
    )

    response = client.put("/credentials", params=store_req)

    assert response.status_code == 200
    assert response.json() == {"message": "Credentials stored."}


def test_store_credentials_vault_sealed(monkeypatch, store_req):
    """
    Test storing Snyk credentials when Vault is sealed.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        store_req: The request data for storing credentials.
    """

    async def async_check_vault_sealed():
        return True
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.check_vault_sealed",
        async_check_vault_sealed,
    )

    response = client.put("/credentials", params=store_req)

    assert response.status_code == 503
    assert "Vault is sealed" in response.json()["error"]


def test_store_credentials_refresh_error(monkeypatch, store_req):
    """
    Test storing Snyk credentials when there is an error refreshing the Snyk token.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        store_req: The request data for storing credentials.
    """

    async def async_check_vault_sealed():
        return False
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.check_vault_sealed",
        async_check_vault_sealed,
    )
    async def async_refresh_snyk_token(cid, cs, rk):
        raise Exception("fail")
    monkeypatch.setattr(
        "api.v1.endpoints.snyk.refresh_snyk_token",
        async_refresh_snyk_token,
    )

    response = client.put("/credentials", params=store_req)

    assert response.status_code == 500
    assert "fail" in response.json()["error"]


def test_get_credentials_from_redis(monkeypatch, get_req):
    """
    Test getting Snyk credentials from Redis.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        get_req: The request data for getting credentials.
    """

    async def async_get_auth_token(o, c):
        return b"token"
    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_auth_token",
        async_get_auth_token,
    )

    response = client.get("/credentials", params=get_req)

    assert response.status_code == 200
    assert response.json() == {"access_token": "token"}


def test_get_credentials_no_refresh_key(monkeypatch, get_req):
    """
    Test getting Snyk credentials when no refresh key is available.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        get_req: The request data for getting credentials.
    """

    async def async_get_auth_token(o, c):
        return None
    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_auth_token",
        async_get_auth_token,
    )
    async def async_get_refresh_key(o, c):
        return None
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.get_refresh_key",
        async_get_refresh_key,
    )

    response = client.get("/credentials", params=get_req)

    assert response.status_code == 404


def test_get_credentials_refresh_error(monkeypatch, get_req):
    """
    Test getting Snyk credentials when there is an error refreshing the Snyk token.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        get_req: The request data for getting credentials.
    """

    async def async_get_auth_token(o, c):
        return None
    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_auth_token",
        async_get_auth_token,
    )
    async def async_get_refresh_key(o, c):
        return "refresh1"
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.get_refresh_key",
        async_get_refresh_key,
    )
    async def async_refresh_snyk_token(cid, cs, rk):
        raise Exception("fail")
    monkeypatch.setattr(
        "api.v1.endpoints.snyk.refresh_snyk_token",
        async_refresh_snyk_token,
    )

    response = client.get("/credentials", params=get_req)

    assert response.status_code == 500


def test_delete_credentials_success(monkeypatch, delete_req):
    """
    Test deleting Snyk credentials successfully.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        delete_req: The request data for deleting credentials.
    """

    async def async_delete_auth_token(o, c):
        return None
    monkeypatch.setattr(
        "api.v1.endpoints.redis.delete_auth_token",
        async_delete_auth_token,
    )
    async def async_delete_refresh_key(o, c):
        return {"message": "Refresh key deleted."}
    monkeypatch.setattr(
        "api.v1.endpoints.openbao.delete_refresh_key",
        async_delete_refresh_key,
    )

    response = client.delete("/credentials", params=delete_req)

    assert response.status_code == 200
    assert response.json() == {"message": "Credentials deleted."}


def test_delete_credentials_missing_fields():
    """
    Test deleting Snyk credentials with missing organization ID or client ID.
    """

    response = client.delete("/credentials", params={"org_id": "", "client_id": ""})

    assert response.status_code == 400


def test_delete_cache_key(monkeypatch, delete_req):
    """
    Test deleting the Snyk auth token from Redis cache.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        delete_req: The request data for deleting the cache key.
    """

    async def async_delete_auth_token(o, c):
        return {"message": "Deleted"}
    monkeypatch.setattr(
        "api.v1.endpoints.redis.delete_auth_token",
        async_delete_auth_token,
    )

    response = client.delete("/cache", params=delete_req)

    assert response.status_code == 200
    assert response.json() == {"message": "Deleted"}