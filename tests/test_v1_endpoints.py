import pytest
from fastapi.testclient import TestClient
from snyk_credentials_manager.main import app

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
        "refresh_key": "refresh1"
    }

@pytest.fixture
def get_req() -> dict:
    """
    Fixture for getting credentials request.

    Returns:
        dict: A dictionary containing organization ID and client ID.
    """

    return {
        "org_id": "org1",
        "client_id": "client1",
        "client_secret": "secret1"
    }

@pytest.fixture
def delete_req() -> dict:
    """
    Fixture for deleting credentials request.

    Returns:
        dict: A dictionary containing organization ID and client ID.
    """

    return {
        "org_id": "org1",
        "client_id": "client1"
    }

def test_store_credentials_success(monkeypatch, store_req):
    """
    Test storing Snyk credentials successfully.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        store_req: The request data for storing credentials.
    """

    # Patch all external calls
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.check_vault_sealed", lambda: True)
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.snyk.refresh_snyk_token", lambda cid, cs, rk: {"access_token": "token", "refresh_token": "refresh", "expires_in": 3600})
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.store_refresh_key", lambda o, c, r: None)

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

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.check_vault_sealed", lambda: False)

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

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.check_vault_sealed", lambda: True)
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.snyk.refresh_snyk_token", lambda cid, cs, rk: (_ for _ in ()).throw(Exception("fail")))

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

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.redis.get_auth_token", lambda o, c: b"token")

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

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.redis.get_auth_token", lambda o, c: None)
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.get_refresh_key", lambda o, c: None)

    response = client.get("/credentials", params=get_req)

    assert response.status_code == 404

def test_get_credentials_refresh_error(monkeypatch, get_req):
    """
    Test getting Snyk credentials when there is an error refreshing the Snyk token.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        get_req: The request data for getting credentials.
    """

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.redis.get_auth_token", lambda o, c: None)
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.get_refresh_key", lambda o, c: "refresh1")
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.snyk.refresh_snyk_token", lambda cid, cs, rk: (_ for _ in ()).throw(Exception("fail")))

    response = client.get("/credentials", params=get_req)

    assert response.status_code == 500

def test_delete_credentials_success(monkeypatch, delete_req):
    """
    Test deleting Snyk credentials successfully.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
        delete_req: The request data for deleting credentials.
    """

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.redis.delete_auth_token", lambda o, c: None)
    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.openbao.delete_refresh_key", lambda o, c: None)

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

    monkeypatch.setattr("snyk_credentials_manager.api.v1.endpoints.redis.delete_auth_token", lambda o, c: {"message": "Deleted"})

    response = client.delete("/cache", params=delete_req)
    
    assert response.status_code == 200
    assert response.json() == {"message": "Deleted"}