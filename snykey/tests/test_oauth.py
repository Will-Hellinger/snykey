import pytest

from services import oauth


@pytest.mark.asyncio
async def test_generate_code_verifier():
    """
    Test generating a code verifier for PKCE.
    """

    verifier: str = await oauth.generate_code_verifier()

    assert isinstance(verifier, str)
    assert len(verifier) > 40  # Base64 encoded 64 bytes should be longer than 40 chars
    assert "=" not in verifier  # Should have padding stripped


@pytest.mark.asyncio
async def test_generate_code_challenge():
    """
    Test generating a code challenge from a code verifier.
    """

    verifier: str = await oauth.generate_code_verifier()
    challenge: str = await oauth.generate_code_challenge(verifier)

    assert isinstance(challenge, str)
    assert len(challenge) > 0
    assert "=" not in challenge  # Should have padding stripped


@pytest.mark.asyncio
async def test_generate_code_challenge_empty_verifier():
    """
    Test that ValueError is raised when code verifier is empty.
    """

    with pytest.raises(ValueError, match="Code verifier must not be empty"):
        await oauth.generate_code_challenge("")


@pytest.mark.asyncio
async def test_generate_code_challenge_deterministic():
    """
    Test that the same code verifier produces the same code challenge.
    """

    verifier = "test_verifier_123"
    challenge1: str = await oauth.generate_code_challenge(verifier)
    challenge2: str = await oauth.generate_code_challenge(verifier)

    assert challenge1 == challenge2


@pytest.mark.asyncio
async def test_generate_state():
    """
    Test generating a random state string for CSRF protection.
    """

    state: str = await oauth.generate_state()

    assert isinstance(state, str)
    assert len(state) > 0
    assert "=" not in state  # Should have padding stripped


@pytest.mark.asyncio
async def test_generate_state_unique():
    """
    Test that generated states are unique.
    """

    state1: str = await oauth.generate_state()
    state2: str = await oauth.generate_state()

    assert state1 != state2
