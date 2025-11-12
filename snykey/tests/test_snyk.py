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
