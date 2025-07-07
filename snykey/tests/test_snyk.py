import pytest
from unittest.mock import patch, AsyncMock
from services import snyk

@pytest.mark.asyncio
async def test_refresh_snyk_token_success():
    """
    Test successful refresh of Snyk token.
    """

    mock_response = AsyncMock()
    mock_response.json.return_value = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 1234,
    }
    mock_response.raise_for_status.return_value = None

    with patch(
        "services.snyk.httpx.AsyncClient.post",
        return_value=mock_response,
    ) as mock_post:
        result: dict = await snyk.refresh_snyk_token("cid", "csecret", "rtoken")

        assert result == {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 1234,
        }

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

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