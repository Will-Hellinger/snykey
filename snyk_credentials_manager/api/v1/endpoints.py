from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from models.schema import CredentialsRequest
from services import openbao, snyk

router: APIRouter = APIRouter()


@router.post("/store_credentials", status_code=status.HTTP_201_CREATED)
def store_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Store Snyk credentials in OpenBao.

    Args:
        req (CredentialsRequest): The request containing org_id, client_id, and refresh_key.

    Returns:
        JSONResponse: A response indicating success or failure.
    """

    if not req.refresh_key:
        return JSONResponse(status_code=400, content={"error": "refresh_key required"})

    openbao.store_refresh_key(req.org_id, req.client_id, req.refresh_key)

    return JSONResponse(content={"message": "Credentials stored."})


@router.post("/gather_credentials")
def gather_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Gather Snyk credentials using the provided org_id and client_id.

    Args:
        req (CredentialsRequest): The request containing org_id and client_id.

    Returns:
        JSONResponse: A response containing the gathered credentials or an error message.
    """

    # Get refresh key from OpenBao
    refresh_key: str | None = openbao.get_refresh_key(req.org_id, req.client_id)

    if not refresh_key:
        return JSONResponse(
            status_code=404, content={"error": "No refresh key found for org/client"}
        )

    # Refresh Snyk token
    result: dict = snyk.refresh_snyk_token(
        req.client_id, req.client_secret, refresh_key
    )

    # Update refresh key in OpenBao
    openbao.update_refresh_key(req.org_id, req.client_id, result["refresh_token"])

    return JSONResponse(
        content={
            "access_token": result["access_token"],
            "expires_in": result["expires_in"],
        }
    )


@router.post("/delete_credentials")
def delete_credentials(req: CredentialsRequest) -> JSONResponse:
    """
    Delete Snyk credentials for a given org_id and client_id.

    Args:
        req (CredentialsRequest): The request containing org_id and client_id.

    Returns:
        JSONResponse: A response indicating success or failure of the deletion.
    """

    openbao.delete_refresh_key(req.org_id, req.client_id)

    return JSONResponse(content={"message": "Credentials deleted."})
