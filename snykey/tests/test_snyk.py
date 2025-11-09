import pytest
from unittest.mock import patch, AsyncMock, MagicMock
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

    # Mock the async context manager and post method
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("services.snyk.httpx.AsyncClient", return_value=mock_client) as mock_async_client:
        result: dict = await snyk.refresh_snyk_token("cid", "csecret", "rtoken")

        assert result == {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 1234,
        }

        mock_client.post.assert_called_once()
        args, kwargs = mock_client.post.call_args

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