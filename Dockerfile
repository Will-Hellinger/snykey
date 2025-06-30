FROM python:3.13-alpine

COPY snykey /snykey

WORKDIR /snykey

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt uvicorn pyyaml; \
    rm requirements.txt; \
    mkdir -p /snykey/logs \
    /snykey/certs \
    /snykey/certs/ca

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 \
    --log-config /snykey/logging_config.yaml \
    --ssl-keyfile /snykey/certs/app.key \
    --ssl-certfile /snykey/certs/app.crt \
    --ssl-ca-certs /snykey/certs/ca/ca.crt > /snykey/logs/app.log 2>&1"]