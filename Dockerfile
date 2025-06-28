FROM python:3.13-alpine

COPY snyk_credentials_manager /snyk_credentials_manager

WORKDIR /snyk_credentials_manager

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt uvicorn pyyaml; \
    mkdir -p /snyk_credentials_manager/logs /snyk_credentials_manager/certs /snyk_credentials_manager/certs/ca

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
    "--log-config", "/snyk_credentials_manager/logging_config.yaml", \
    "--ssl-keyfile", "/snyk_credentials_manager/certs/app.key", \
    "--ssl-certfile", "/snyk_credentials_manager/certs/app.crt", \
    "--ssl-ca-certs", "/snyk_credentials_manager/certs/ca/ca.crt"]