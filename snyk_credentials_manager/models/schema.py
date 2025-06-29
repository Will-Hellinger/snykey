from pydantic import BaseModel


class StoreCredentialRequest(BaseModel):
    """
    Request model for storing Snyk credentials.

    Attributes:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        client_secret (str): The client secret for authentication.
        refresh_key (str): The refresh key for storing credentials.

    """

    org_id: str
    client_id: str
    client_secret: str
    refresh_key: str


class GetCredentialRequest(BaseModel):
    """
    Request model for retrieving Snyk credentials.

    Attributes:
        org_id (str): The organization ID.
        client_id (str): The client ID.
        client_secret (str): The client secret for authentication.

    """

    org_id: str
    client_id: str
    client_secret: str


class DeleteCredentialRequest(BaseModel):
    """
    Request model for deleting Snyk credentials.

    Attributes:
        org_id (str): The organization ID.
        client_id (str): The client ID.

    """

    org_id: str
    client_id: str
