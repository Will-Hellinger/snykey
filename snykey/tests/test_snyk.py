import pytest
from unittest.mock import patch, MagicMock

from services import snyk


@pytest.mark.asyncio
async def test_refresh_snyk_token_success():
    """
    Test successful refresh of Snyk token.
    """

    # httpx response methods are sync, not async
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 1234,
    }
    mock_response.raise_for_status.return_value = None

    # Mock the shared http_client post method
    async def mock_post(*args, **kwargs):
        return mock_response

    with patch.object(
        snyk.http_client, "post", side_effect=mock_post
    ) as mock_post_method:
        result: dict = await snyk.refresh_snyk_token("cid", "csecret", "rtoken")

        assert result == {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 1234,
        }

        mock_post_method.assert_called_once()
        args, kwargs = mock_post_method.call_args

        assert kwargs["data"]["grant_type"] == "refresh_token"


@pytest.mark.asyncio
async def test_refresh_snyk_token_missing_args():
    """
    Test that ValueError is raised when required arguments are missing.
    """

    with pytest.raises(ValueError):
        await snyk.refresh_snyk_token("", "csecret", "rtoken")

    with pytest.raises(ValueError):
        await snyk.refresh_snyk_token("cid", "", "rtoken")

    with pytest.raises(ValueError):
        await snyk.refresh_snyk_token("cid", "csecret", "")


@pytest.mark.asyncio
async def test_exchange_code_for_token_success():
    """
    Test successful exchange of authorization code for tokens.
    """

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "access_token": "access_token_123",
        "refresh_token": "refresh_token_456",
        "expires_in": 3600,
    }
    mock_response.raise_for_status.return_value = None

    async def mock_post(*args, **kwargs):
        return mock_response

    with patch.object(
        snyk.http_client, "post", side_effect=mock_post
    ) as mock_post_method:
        result: dict = await snyk.exchange_code_for_token(
            code="auth_code",
            client_id="client_id",
            client_secret="client_secret",
            redirect_uri="https://example.com",
            code_verifier="verifier",
        )

        assert result == {
            "access_token": "access_token_123",
            "refresh_token": "refresh_token_456",
            "expires_in": 3600,
        }

        mock_post_method.assert_called_once()
        args, kwargs = mock_post_method.call_args

        assert kwargs["data"]["grant_type"] == "authorization_code"
        assert kwargs["data"]["code"] == "auth_code"
        assert kwargs["data"]["code_verifier"] == "verifier"


@pytest.mark.asyncio
async def test_exchange_code_for_token_missing_args():
    """
    Test that ValueError is raised when required arguments are missing.
    """

    with pytest.raises(ValueError):
        await snyk.exchange_code_for_token("", "cid", "csecret", "uri", "verifier")

    with pytest.raises(ValueError):
        await snyk.exchange_code_for_token("code", "", "csecret", "uri", "verifier")

    with pytest.raises(ValueError):
        await snyk.exchange_code_for_token("code", "cid", "", "uri", "verifier")

    with pytest.raises(ValueError):
        await snyk.exchange_code_for_token("code", "cid", "csecret", "", "verifier")

    with pytest.raises(ValueError):
        await snyk.exchange_code_for_token("code", "cid", "csecret", "uri", "")


@pytest.mark.asyncio
async def test_register_snyk_app_success():
    """
    Test successful registration of a Snyk app.
    """

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "client_id": "new_client_id",
                "client_secret": "new_client_secret",
                "name": "test_app",
            }
        }
    }
    mock_response.raise_for_status.return_value = None

    async def mock_post(*args, **kwargs):
        return mock_response

    with patch.object(
        snyk.http_client, "post", side_effect=mock_post
    ) as mock_post_method:
        result: dict = await snyk.register_snyk_app(
            name="test_app",
            scopes=["org.read"],
            redirect_uris=["https://example.com/callback"],
            org_id="org123",
            auth_token="token123",
        )

        assert result["data"]["attributes"]["client_id"] == "new_client_id"
        assert result["data"]["attributes"]["client_secret"] == "new_client_secret"

        mock_post_method.assert_called_once()


def test_generate_auth_url():
    """
    Test generating the Snyk OAuth2 authorization URL.
    """

    url: str = snyk.generate_auth_url(
        client_id="client123",
        redirect_uri="https://example.com/callback",
        scopes=["org.read", "org.project.read"],
        state="state123",
        code_challenge="challenge123",
        code_challenge_method="S256",
    )

    assert "https://app.snyk.io/oauth2/authorize?" in url
    assert "client_id=client123" in url
    assert "redirect_uri=https" in url
    assert "scope=org.read+org.project.read" in url
    assert "state=state123" in url
    assert "code_challenge=challenge123" in url
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url
