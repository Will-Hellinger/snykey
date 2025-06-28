import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings.

    Attributes:
        OPENBAO_ADDR (str): Address of the OpenBao service, defaults to "http://localhost:8200".
        OPENBAO_TOKEN (str): Token for OpenBao authentication, defaults to "changeme".
    """

    OPENBAO_ADDR: str = os.getenv("OPENBAO_ADDR", "http://localhost:8200")
    OPENBAO_TOKEN: str = os.getenv("OPENBAO_TOKEN", "changeme")


settings: Settings = Settings()
