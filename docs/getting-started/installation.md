# Installation

Follow these steps to install and set up Snykey.

---

## 1. Clone the Repository

```bash
git clone https://github.com/Will-Hellinger/snykey.git
cd snykey
```

## 2. Prepare Configuration
Copy .env_example to .env and fill in your secrets and environment-specific values.
Adjust any configuration in configs/ if needed.

## 3. Run the Setup Scripts
The setup scripts will:

* Create required directories and volume mounts
* Copy configuration files for OpenBao and Redis
* Generate self-signed certificates for local development

Run: `python3 ./scripts/setup.py`
Run: `python3 ./scripts/genreate_certs.py`

## 4. Set the configuration
The setup needs an initial configuration .env file. You dont need to know the OPENBAO details just yet.

```bash
cp .env_example .env
```

## 5. Start the Stack
Start all services with Docker Compose:

```bash
docker compose up -d --build
```

## 6. Initialize and Unseal OpenBao
### a. Initialize OpenBao (first time only):
```bash
docker exec -it openbao bao operator init -n 1 -t 1
```

* Save the Unseal Key and Root Token from the output.
* Add them to your .env file as OPENBAO_UNSEAL_KEY and OPENBAO_TOKEN.

### b. Restart the Stack
```bash
docker compose down
```

```bash
docker compose up -d
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
Enable the KV secrets engine (version 2):

```bash
docker exec -it openbao bao secrets enable -version=2 kv
```

## 8. (Optional) Verify Everything is Running
* Visit `https://localhost:8000/docs` for the API docs.
* Check logs in .container_volumes/app/logs/ if needed.

## 9. Next Steps
* Use the API to store and retrieve Snyk credentials for your applications.
* For production, replace the generated certificates with your own trusted certificates.
