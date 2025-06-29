import pytest
from unittest.mock import patch, MagicMock
from snyk_credentials_manager.services import snyk


def test_refresh_snyk_token_success():
    """
    Test successful refresh of Snyk token.
    """

    mock_response: MagicMock = MagicMock()
    mock_response.json.return_value = {
        "access_token": "access",
        "refresh_token": "refresh",
        "expires_in": 1234,
    }
    mock_response.raise_for_status.return_value = None

    with patch(
        "snyk_credentials_manager.services.snyk.requests.post",
        return_value=mock_response,
    ) as mock_post:
        result: dict = snyk.refresh_snyk_token("cid", "csecret", "rtoken")

        assert result == {
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 1234,
        }

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

        assert kwargs["data"]["grant_type"] == "refresh_token"


def test_refresh_snyk_token_missing_args():
    """
    Test that ValueError is raised when required arguments are missing.
    """

    with pytest.raises(ValueError):
        snyk.refresh_snyk_token("", "csecret", "rtoken")

    with pytest.raises(ValueError):
        snyk.refresh_snyk_token("cid", "", "rtoken")

    with pytest.raises(ValueError):
        snyk.refresh_snyk_token("cid", "csecret", "")


def test_refresh_snyk_token_http_error():
    """
    Test that an error is raised when the HTTP request fails.
    """

    mock_response: MagicMock = MagicMock()
    mock_response.raise_for_status.side_effect = Exception("HTTP error")

    with patch(
        "snyk_credentials_manager.services.snyk.requests.post",
        return_value=mock_response,
    ):
        with pytest.raises(Exception) as excinfo:
            snyk.refresh_snyk_token("cid", "csecret", "rtoken")

        assert "HTTP error" in str(excinfo.value)
