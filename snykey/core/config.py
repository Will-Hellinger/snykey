import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings.

    Attributes:
        OPENBAO_ADDR (str): Address of the OpenBao service, defaults to "http://localhost:8200".
        OPENBAO_TOKEN (str): Token for OpenBao authentication, defaults to "changeme".
        REDIS_HOST (str): Hostname for the Redis service, defaults to "redis".
        REDIS_PORT (int): Port for the Redis service, defaults to 6379.
        REDIS_PASSWORD (str): Password for Redis authentication, defaults to "example_password".
        REDIS_CACHE_TIME (int): Cache expiration time in minutes, defaults to 50.
    """

    OPENBAO_ADDR: str = os.getenv("OPENBAO_ADDR", "http://localhost:8200")
    OPENBAO_TOKEN: str = os.getenv("OPENBAO_TOKEN", "changeme")
    REDIS_HOST: str = os.getenv("REDIS_HOST", "127.0.0.1")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
    REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "example_password")
    REDIS_CACHE_TIME: int = int(os.getenv("REDIS_CACHE_TIME", 50))  # in minutes


settings: Settings = Settings()
