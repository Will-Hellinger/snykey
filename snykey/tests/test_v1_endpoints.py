import pytest
from fastapi.testclient import TestClient

from main import app
from core import config

class APIKeyTestClient(TestClient):
    def request(self, *args, **kwargs):
        headers = kwargs.pop("headers", None)
        if headers is None:
            headers = {}

        headers.update({"X-API-Key": config.settings.API_KEY})

        return super().request(*args, headers=headers, **kwargs)

client = APIKeyTestClient(app)


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

    response = client.put("/v1/credentials", params=store_req)

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

    response = client.put("/v1/credentials", params=store_req)

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

    response = client.put("/v1/credentials", params=store_req)

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

    response = client.get("/v1/credentials", params=get_req)

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

    response = client.get("/v1/credentials", params=get_req)

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

    response = client.get("/v1/credentials", params=get_req)

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

    response = client.delete("/v1/credentials", params=delete_req)

    assert response.status_code == 200
    assert response.json() == {"message": "Credentials deleted."}


def test_delete_credentials_missing_fields():
    """
    Test deleting Snyk credentials with missing organization ID or client ID.
    """

    response = client.delete("/v1/credentials", params={"org_id": "", "client_id": ""})

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

    response = client.delete("/v1/cache", params=delete_req)

    assert response.status_code == 200
    assert response.json() == {"message": "Deleted"}


def test_register_app_success(monkeypatch):
    """
    Test successful registration of a Snyk app.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
    """

    async def async_get_all_states():
        return ["state1", "state2"]

    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_all_states",
        async_get_all_states,
    )

    async def async_generate_code_verifier():
        return "verifier123"

    monkeypatch.setattr(
        "api.v1.endpoints.oauth.generate_code_verifier",
        async_generate_code_verifier,
    )

    async def async_generate_code_challenge(verifier):
        return "challenge123"

    monkeypatch.setattr(
        "api.v1.endpoints.oauth.generate_code_challenge",
        async_generate_code_challenge,
    )

    async def async_generate_state():
        return "newstate123"

    monkeypatch.setattr(
        "api.v1.endpoints.oauth.generate_state",
        async_generate_state,
    )

    async def async_register_snyk_app(name, scopes, uris, org, token):
        return {
            "data": {
                "attributes": {"client_id": "client123", "client_secret": "secret123"}
            }
        }

    monkeypatch.setattr(
        "api.v1.endpoints.snyk.register_snyk_app",
        async_register_snyk_app,
    )

    def generate_auth_url(**kwargs):
        return "https://app.snyk.io/oauth2/authorize?..."

    monkeypatch.setattr(
        "api.v1.endpoints.snyk.generate_auth_url",
        generate_auth_url,
    )

    async def async_store_pkce_data(**kwargs):
        return {"message": "Stored"}

    monkeypatch.setattr(
        "api.v1.endpoints.redis.store_pkce_data",
        async_store_pkce_data,
    )

    response = client.post(
        "/v1/register-app",
        params={
            "name": "test_app",
            "scopes": "org.read",
            "redirect_uris": "https://example.com/callback",
            "org_id": "org123",
            "auth_token": "token123",
        },
    )

    assert response.status_code == 200
    assert "data" in response.json()
    assert "auth_urls" in response.json()


def test_oauth_callback_success(monkeypatch):
    """
    Test successful OAuth callback.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
    """

    async def async_get_pkce_data(state):
        return {
            "code_verifier": "verifier123",
            "client_id": "client123",
            "client_secret": "secret123",
            "redirect_uri": "https://example.com/callback",
            "org_id": "org123",
        }

    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_pkce_data",
        async_get_pkce_data,
    )

    async def async_check_vault_sealed():
        return False

    monkeypatch.setattr(
        "api.v1.endpoints.openbao.check_vault_sealed",
        async_check_vault_sealed,
    )

    async def async_exchange_code_for_token(
        code, client_id, client_secret, redirect_uri, code_verifier
    ):
        return {
            "access_token": "access123",
            "refresh_token": "refresh123",
            "expires_in": 3600,
        }

    monkeypatch.setattr(
        "api.v1.endpoints.snyk.exchange_code_for_token",
        async_exchange_code_for_token,
    )

    async def async_store_refresh_key(org_id, client_id, refresh_token):
        return True

    monkeypatch.setattr(
        "api.v1.endpoints.openbao.store_refresh_key",
        async_store_refresh_key,
    )

    async def async_store_auth_token(org_id, client_id, auth_token, expiration):
        return {"message": "Stored"}

    monkeypatch.setattr(
        "api.v1.endpoints.redis.store_auth_token",
        async_store_auth_token,
    )

    async def async_delete_pkce_data(state):
        return {"message": "Deleted"}

    monkeypatch.setattr(
        "api.v1.endpoints.redis.delete_pkce_data",
        async_delete_pkce_data,
    )

    response = client.get(
        "/v1/callback",
        params={
            "code": "auth_code_123",
            "state": "state123",
            "instance": "api.snyk.io",
        },
    )

    assert response.status_code == 200
    assert "message" in response.json()
    assert "org_id" in response.json()
    assert "client_id" in response.json()


def test_oauth_callback_invalid_state(monkeypatch):
    """
    Test OAuth callback with invalid/expired state.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
    """

    async def async_get_pkce_data(state):
        return None

    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_pkce_data",
        async_get_pkce_data,
    )

    response = client.get(
        "/v1/callback",
        params={
            "code": "auth_code_123",
            "state": "invalid_state",
            "instance": "api.snyk.io",
        },
    )

    assert response.status_code == 400
    assert "Invalid or expired state" in response.json()["error"]


def test_oauth_callback_exchange_error(monkeypatch):
    """
    Test OAuth callback when token exchange fails.

    Args:
        monkeypatch: The pytest fixture to patch external calls.
    """

    async def async_get_pkce_data(state):
        return {
            "code_verifier": "verifier123",
            "client_id": "client123",
            "client_secret": "secret123",
            "redirect_uri": "https://example.com/callback",
            "org_id": "org123",
        }

    monkeypatch.setattr(
        "api.v1.endpoints.redis.get_pkce_data",
        async_get_pkce_data,
    )

    async def async_check_vault_sealed():
        return False

    monkeypatch.setattr(
        "api.v1.endpoints.openbao.check_vault_sealed",
        async_check_vault_sealed,
    )

    async def async_exchange_code_for_token(
        code, client_id, client_secret, redirect_uri, code_verifier
    ):
        raise Exception("Exchange failed")

    monkeypatch.setattr(
        "api.v1.endpoints.snyk.exchange_code_for_token",
        async_exchange_code_for_token,
    )

    async def async_delete_pkce_data(state):
        return {"message": "Deleted"}

    monkeypatch.setattr(
        "api.v1.endpoints.redis.delete_pkce_data",
        async_delete_pkce_data,
    )

    response = client.get(
        "/v1/callback",
        params={
            "code": "auth_code_123",
            "state": "state123",
            "instance": "api.snyk.io",
        },
    )

    assert response.status_code == 500
    assert "Exchange failed" in response.json()["error"]
