from pydantic import BaseModel


class CredentialsRequest(BaseModel):
    """
    Request model for Snyk credentials operations.

    Attributes:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        client_secret (str): The client secret.
        refresh_key (str, optional): The refresh key for storing credentials.

    """

    org_id: str
    client_id: str
    client_secret: str
    refresh_key: str | None = None  # Optional for storing credentials
