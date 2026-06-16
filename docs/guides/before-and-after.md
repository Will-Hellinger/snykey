# Before and After: Snykey vs. Standard App Management

## An Example Scenario

You have a Python service that periodically calls the Snyk API to list vulnerabilities for a project. It needs a valid Snyk access token to make that call.

---

## Without Snykey

Every application that touches the Snyk API must own the full credential lifecycle:

- Persist the refresh token somewhere (file, database, environment variable)
- Detect when the access token has expired
- Call the Snyk OAuth2 token endpoint to get a new one
- Update the stored refresh token (tokens rotate on every refresh)
- Handle failures, retries, and race conditions if multiple workers refresh simultaneously

### Initial App Registration

To start, you'll need to register a Snyk app and complete the OAuth PKCE flow... That means:
 * generating a code verifier
 * building the authorization URL
 * handling the redirect
 * exchanging the code for tokens

```python
import hashlib
import httpx
import json
import os
import secrets
import base64
from urllib.parse import urlencode

CLIENT_ID = os.environ["SNYK_CLIENT_ID"]
CLIENT_SECRET = os.environ["SNYK_CLIENT_SECRET"]
REDIRECT_URI = "https://yourapp.example.com/callback"
TOKEN_FILE = ".snyk_tokens.json"


def generate_code_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def generate_code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def get_auth_url(state: str, verifier: str) -> str:
    challenge = generate_code_challenge(verifier)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "org.read org.project.read",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return "https://app.snyk.io/oauth2/authorize?" + urlencode(params)


def exchange_code(code: str, verifier: str) -> dict:
    resp = httpx.post(
        "https://api.snyk.io/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": verifier,
        },
    )
    resp.raise_for_status()
    return resp.json()


# You must expose a /callback route, receive the code, call exchange_code(), and handle the persistance yourself.
def handle_callback(code: str, verifier: str):
    tokens = exchange_code(code, verifier)
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f)
```

### Getting a Token at Runtime

Every time your service calls Snyk, it must check whether the token is still valid and refresh it if not.

```python
import time
import httpx
import json
import os

CLIENT_ID = os.environ["SNYK_CLIENT_ID"]
CLIENT_SECRET = os.environ["SNYK_CLIENT_SECRET"]
TOKEN_FILE = ".snyk_tokens.json"


def load_tokens() -> dict:
    with open(TOKEN_FILE) as f:
        return json.load(f)


def save_tokens(tokens: dict):
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f)


def refresh_tokens(refresh_token: str) -> dict:
    resp = httpx.post(
        "https://api.snyk.io/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
        },
    )
    resp.raise_for_status()
    return resp.json()


def get_valid_token() -> str:
    tokens = load_tokens()

    # Snyk access tokens expire check stored expiry if you tracked it,
    # otherwise refresh proactively every call to be safe.
    new_tokens = refresh_tokens(tokens["refresh_token"])

    # Refresh tokens rotate meaning you must persist the new one immediately.
    # If this write fails, the old refresh token is invalid and you're locked out.
    save_tokens(new_tokens)

    return new_tokens["access_token"]


def list_projects(org_id: str) -> dict:
    token = get_valid_token()
    resp = httpx.get(
        f"https://api.snyk.io/rest/orgs/{org_id}/projects",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()
```

### Problems with this approach

- **Secrets sprawl**: `CLIENT_SECRET` and the refresh token live in every service that calls Snyk.
- **Token rotation is fragile**: if `save_tokens()` fails after a refresh, the refresh token is burned and you must re-authenticate from scratch.
- **No caching**: each call to `get_valid_token()` hits the Snyk token endpoint, adding latency and burning rate limits unnecessarily.
- **Concurrency**: two workers refreshing simultaneously will invalidate each other's tokens.
- **Duplication**:  this logic must be replicated in every service, in every language, that needs a Snyk token.

---

## With Snykey

Snykey handles registration, token storage, rotation, and caching. All your application only needs to know are two things: the Snykey endpoint and the org/client identifiers.

### One-Time Setup

Register the Snyk app once via the Snykey API. Snykey generates the PKCE parameters, registers the app with Snyk, stores the credentials, and returns the authorization URL.

```bash
curl -s -X POST https://snykey.internal/v1/register-app \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $SNYKEY_API_KEY" \
  -d '{
    "name": "my-service",
    "scopes": "org.read,org.project.read",
    "redirect_uris": "https://yourapp.example.com/callback",
    "org_id": "your-snyk-org-id",
    "auth_token": "your-snyk-personal-token"
  }'
```

The response includes an `auth_urls` field. Open that URL in a browser, authorize the app, and Snykey's `/v1/callback` endpoint handles the rest! (That's the only time you touch a browser)

### Getting a Token at Runtime

```python
import httpx
import os

SNYKEY_URL = os.environ["SNYKEY_URL"]
SNYKEY_API_KEY = os.environ["SNYKEY_API_KEY"]
ORG_ID = os.environ["SNYK_ORG_ID"]
CLIENT_ID = os.environ["SNYK_CLIENT_ID"]
CLIENT_SECRET = os.environ["SNYK_CLIENT_SECRET"]


def get_snyk_token() -> str:
    resp = httpx.post(
        f"{SNYKEY_URL}/v1/credentials",
        headers={"X-API-Key": SNYKEY_API_KEY},
        json={
            "org_id": ORG_ID,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def list_projects(org_id: str) -> dict:
    token = get_snyk_token()
    resp = httpx.get(
        f"https://api.snyk.io/rest/orgs/{org_id}/projects",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()
```

Snykey returns a cached token from Redis if one is still valid, or silently refreshes and rotates the refresh token in OpenBao before returning a new one. Your service sees none of that complexity.

---

## Side-by-Side Summary

| | Without Snykey | With Snykey |
|---|---|---|
| **Secrets in each service** | `CLIENT_SECRET` + refresh token | `CLIENT_SECRET` only (used to verify identity) |
| **Refresh token storage** | File, DB, or env var per service | OpenBao (one place) |
| **Token rotation** | Each service must persist new token immediately | Snykey handles it |
| **Caching** | Refresh on every call unless you add caching yourself | Redis cache built in |
| **Concurrency safety** | Race condition if multiple workers refresh simultaneously | Single point of refresh |
| **Lines of credential code per service** | ~60–80 | ~10 |
| **Re-authentication if token lost** | Manual browser flow per service | Never — Snykey retains the refresh token |
