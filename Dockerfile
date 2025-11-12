FROM python:3.13-alpine

COPY snykey /snykey

WORKDIR /snykey

# Install dependencies and clean up
RUN apk add --no-cache uv \
    && uv pip install --system --no-cache-dir -r requirements.txt uvicorn pyyaml \
    && rm requirements.txt \
    && mkdir -p /snykey/logs /snykey/certs /snykey/certs/ca \
    && find /snykey -type d -name '__pycache__' -exec rm -rf {} + \
    && rm -rf /usr/local/lib/python*/site-packages/pip* /usr/local/bin/pip* \
    && rm -rf /root/.cache/pip /tmp/pip-*

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port 8000 \
    --log-config /snykey/logging_config.yaml \
    --ssl-keyfile /snykey/certs/app.key \
    --ssl-certfile /snykey/certs/app.crt \
    --ssl-ca-certs /snykey/certs/ca/ca.crt > /snykey/logs/app.log 2>&1"]
