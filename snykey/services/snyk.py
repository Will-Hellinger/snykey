import requests


def refresh_snyk_token(client_id: str, client_secret: str, refresh_token: str) -> dict:
    """
    Use Snyk OAuth2 endpoint to exchange a refresh token for a new access token and refresh token.

    Args:
        client_id (str): Snyk OAuth2 client ID.
        client_secret (str): Snyk OAuth2 client secret.
        refresh_token (str): The refresh token to exchange.

    Returns:
        dict: A dictionary containing the new access token, refresh token, and expiration time.
    """

    if not client_id or not client_secret or not refresh_token:
        raise ValueError("client_id, client_secret, and refresh_token must be provided")

    url: str = "https://api.snyk.io/oauth2/token"

    headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "client_id": f"{str(client_id)}",
        "client_secret": f"{str(client_secret)}",
        "refresh_token": f"{str(refresh_token)}",
    }

    resp: requests.Response = requests.post(url, data=data, headers=headers)
    resp.raise_for_status()

    result: dict = resp.json()

    return {
        "access_token": result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "expires_in": result.get("expires_in", 3600),
    }
