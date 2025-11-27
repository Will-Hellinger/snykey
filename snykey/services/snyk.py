import httpx
import urllib.parse

http_client: httpx.AsyncClient = httpx.AsyncClient(
    verify=True,
    timeout=30.0,
    limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
)


async def refresh_snyk_token(
    client_id: str, client_secret: str, refresh_token: str
) -> dict:
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
        "client_id": str(client_id),
        "client_secret": str(client_secret),
        "refresh_token": str(refresh_token),
    }

    resp: httpx.Response = await http_client.post(url, data=data, headers=headers)
    resp.raise_for_status()

    result: dict = resp.json()

    return {
        "access_token": result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "expires_in": result.get("expires_in", 3600),
    }


async def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    """
    Exchange an authorization code for access and refresh tokens using PKCE.

    Args:
        code (str): The authorization code from the callback.
        client_id (str): Snyk OAuth2 client ID.
        client_secret (str): Snyk OAuth2 client secret.
        redirect_uri (str): The redirect URI used in the authorization request.
        code_verifier (str): The PKCE code verifier.

    Returns:
        dict: A dictionary containing the access token, refresh token, and expiration time.
    """

    if (
        not code
        or not client_id
        or not client_secret
        or not redirect_uri
        or not code_verifier
    ):
        raise ValueError("All parameters must be provided")

    url: str = "https://api.snyk.io/oauth2/token"

    headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }

    resp: httpx.Response = await http_client.post(url, data=data, headers=headers)
    resp.raise_for_status()

    result: dict = resp.json()

    return {
        "access_token": result.get("access_token"),
        "refresh_token": result.get("refresh_token"),
        "expires_in": result.get("expires_in", 3600),
    }


async def register_snyk_app(
    name: str,
    scopes: list[str],
    redirect_uris: list[str],
    org_id: str,
    auth_token: str,
    api_version: str = "2024-10-15",
) -> dict:
    """
    Register a new Snyk app with the specified parameters.

    Args:
        name (str): Name of the Snyk app.
        scopes (list[str]): List of scopes for the Snyk app.
        redirect_uris (list[str]): List of redirect URIs for the Snyk app.
        org_id (str): Snyk organization ID.
        auth_token (str): Snyk API authentication token.
        api_version (str): Snyk API version (default: "2024-10-15").

    Returns:
        dict: Response from the Snyk API containing the app registration details.
    """

    url: str = (
        f"https://api.snyk.io/rest/orgs/{org_id}/apps/creations?version={api_version}"
    )

    headers: dict[str, str] = {
        "Authorization": f"token {auth_token}",
        "Content-Type": "application/vnd.api+json",
    }

    data: dict[str, dict[str, object]] = {
        "data": {
            "attributes": {
                "context": "tenant",
                "name": name,
                "redirect_uris": redirect_uris,
                "scopes": scopes,
            },
            "type": "app",
        }
    }

    try:
        resp: httpx.Response = await http_client.post(url, headers=headers, json=data)
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text
        raise Exception(
            f"Snyk API error: {e.response.status_code} - {error_detail}"
        ) from e

    snyk_app_response: dict = resp.json()

    return snyk_app_response


def generate_auth_url(
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
    state: str = "state123",
    code_challenge: str = "challenge123",
    code_challenge_method: str = "S256",
) -> str:
    """
    Generate the Snyk OAuth2 authorization URL.

    Args:
        client_id (str): The client ID for the Snyk app.
        redirect_uri (str): The redirect URI for the Snyk app.
        scopes (list[str]): List of scopes for the Snyk app.
        state (str): State parameter for CSRF protection.
        code_challenge (str): PKCE code challenge.
        code_challenge_method (str): PKCE code challenge method.

    Returns:
        str: The complete authorization URL.
    """

    params: dict = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    return "https://app.snyk.io/oauth2/authorize?" + urllib.parse.urlencode(params)
