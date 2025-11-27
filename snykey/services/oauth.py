import base64
import hashlib
import secrets
import logging

logger: logging.Logger = logging.getLogger(__name__)


async def generate_code_verifier() -> str:
    """
    Generate a code verifier for PKCE (Proof Key for Code Exchange).

    Returns:
        str: A base64 URL-safe encoded string that serves as the code verifier.
    """

    logger.debug("Generating code verifier for PKCE.")

    code_verifier: str = (
        base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("utf-8")
    )

    logger.debug("Code verifier generated successfully.")

    return code_verifier


async def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a code challenge from the code verifier using SHA-256.

    Args:
        code_verifier (str): The code verifier string.

    Returns:
        str: A base64 URL-safe encoded string that serves as the code challenge.
    """

    logger.debug("Generating code challenge from code verifier.")

    if not code_verifier:
        logger.error("Code verifier must not be empty.")
        raise ValueError("Code verifier must not be empty.")

    code_challenge: bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()

    logger.debug("Code challenge generated successfully.")

    return base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("utf-8")


async def generate_state() -> str:
    """
    Generate a random state string for CSRF protection.

    Returns:
        str: A base64 URL-safe encoded string that serves as the state.
    """

    logger.debug("Generating random state for CSRF protection.")

    state: str = (
        base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("utf-8")
    )

    logger.debug("State generated successfully.")

    return state
