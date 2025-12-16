import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings.

    Attributes:
        API_KEY (str): The API key for authenticating requests.
        OPENBAO_ADDR (str): Address of the OpenBao service, defaults to "http://localhost:8200".
        OPENBAO_TOKEN (str): Token for OpenBao authentication, defaults to "changeme".
        REDIS_HOST (str): Hostname for the Redis service, defaults to "redis".
        REDIS_PORT (int): Port for the Redis service, defaults to 6379.
        REDIS_PASSWORD (str): Password for Redis authentication, defaults to "example_password".
        REDIS_CACHE_TIME (int): Expiration time in seconds for cached items in Redis, defaults to 3000 seconds.
        REDIS_PKCE_EXPIRATION (int): Expiration time in seconds for PKCE data in Redis, defaults to 3600 seconds.
    """

    API_KEY: str = os.getenv("API_KEY")
    OPENBAO_ADDR: str = os.getenv("OPENBAO_ADDR", "http://localhost:8200")
    OPENBAO_TOKEN: str = os.getenv("OPENBAO_TOKEN", "changeme")
    REDIS_HOST: str = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "example_password")
    REDIS_CACHE_TIME: int = int(os.getenv("REDIS_CACHE_TIME", 3000))  # in seconds
    REDIS_PKCE_EXPIRATION: int = int(
        os.getenv("REDIS_PKCE_EXPIRATION", 3600)
    )  # in seconds


settings: Settings = Settings()

EXCLUDED_PATHS: list[str] = (
    os.getenv("EXCLUDED_PATHS") if os.getenv("EXCLUDED_PATHS") else ""
).split(",")
