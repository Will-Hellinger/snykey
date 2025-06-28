FROM python:3.13-alpine

COPY snyk_credentials_manager /snyk_credentials_manager

WORKDIR /snyk_credentials_manager

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt uvicorn

CMD ["sh", "-c", "mkdir -p /snyk_credentials_manager/logs && uvicorn main:app --host 0.0.0.0 --port 8000 > /snyk_credentials_manager/logs/uvicorn.log 2>&1"]