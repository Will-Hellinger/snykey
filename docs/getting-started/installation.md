# Installation

Follow these steps to install and set up Snykey.

---

## 1. Clone the Repository

```bash
git clone https://github.com/Will-Hellinger/snykey.git
cd snykey
```

## 2. Prepare Configuration

Copy `.env_example` to `.env` and fill in your values. You won't have the OpenBao token or unseal key yet — that comes after initialization in step 6.

```bash
cp .env_example .env
```

## 3. Run the Setup Script

Creates the required directory structure and copies configuration files for OpenBao and Redis.

```bash
python3 ./scripts/setup.py
```

## 4. Place TLS Certificates

Snykey and OpenBao both require TLS certificates. Place them in the directories created by the setup script:

| Path | Contents |
|------|----------|
| `.container_volumes/certs/ca/ca.crt` | CA certificate (used to verify OpenBao) |
| `.container_volumes/certs/bao/bao.crt` | OpenBao server certificate |
| `.container_volumes/certs/bao/bao.key` | OpenBao server key |
| `.container_volumes/certs/app/app.crt` | App server certificate |
| `.container_volumes/certs/app/app.key` | App server key |

For local development, [`mkcert`](https://github.com/FiloSottile/mkcert) is the easiest way to generate trusted certificates:

```bash
mkcert -install
mkcert -cert-file .container_volumes/certs/bao/bao.crt \
       -key-file  .container_volumes/certs/bao/bao.key \
       openbao localhost 127.0.0.1
mkcert -cert-file .container_volumes/certs/app/app.crt \
       -key-file  .container_volumes/certs/app/app.key \
       app localhost 127.0.0.1
cp "$(mkcert -CAROOT)/rootCA.pem" .container_volumes/certs/ca/ca.crt
```

For production, use certificates from your organization's CA or a public provider. Set `OPENBAO_CA_CERT` in `.env` if OpenBao uses a certificate not trusted by the system store.

## 5. Start the Stack

```bash
docker compose up -d --build
```

## 6. Initialize and Unseal OpenBao

### a. Initialize OpenBao (first time only):

```bash
docker exec -it openbao bao operator init -n 1 -t 1
```

Save the **Unseal Key** and **Root Token** from the output, then add them to your `.env` file:

```
OPENBAO_UNSEAL_KEY=<unseal key>
OPENBAO_TOKEN=<root token>
```

### b. Restart the Stack

```bash
docker compose restart
```

### c. Unseal OpenBao:

```bash
docker exec -it openbao bao operator unseal $OPENBAO_UNSEAL_KEY
```

### d. Login to OpenBao:

```bash
docker exec -it openbao bao login $OPENBAO_TOKEN
```

## 7. Enable the Key-Value Secrets Engine

```bash
docker exec -it openbao bao secrets enable -version=2 kv
```

(If that doesn't work, try: `docker exec -it openbao sh -c 'unset BAO_TOKEN && bao secrets enable -version=2 kv'`)

## 8. (Optional) Verify Everything is Running

- Visit `https://localhost:8000/docs` for the API docs.
- Check logs in `.container_volumes/app/logs/` if needed.

## 9. Next Steps

- Use the API to store and retrieve Snyk credentials for your applications.
