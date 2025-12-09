FROM ghcr.io/astral-sh/uv:python3.13-alpine

RUN addgroup -g 1001 -S snykey && \
    adduser -u 1001 -S snykey -G snykey

COPY snykey /snykey

RUN mkdir -p /snykey/logs /snykey/certs /snykey/certs/ca && \
    chown -R snykey:snykey /snykey

WORKDIR /snykey

# Install dependencies and clean up (just in case)
RUN uv pip install --system --no-cache-dir -r requirements.txt \
    && rm requirements.txt \
    && mkdir -p /snykey/logs /snykey/certs /snykey/certs/ca \
    && find /snykey -type d -name '__pycache__' -exec rm -rf {} + \
    && rm -rf /usr/local/lib/python*/site-packages/pip* /usr/local/bin/pip* \
    && rm -rf /root/.cache/pip /tmp/pip-*

USER snykey

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--log-config", "/snykey/logging_config.yaml", \
     "--ssl-keyfile", "/snykey/certs/app.key", \
     "--ssl-certfile", "/snykey/certs/app.crt", \
     "--ssl-ca-certs", "/snykey/certs/ca/ca.crt"]
