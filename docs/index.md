# Snykey Documentation

Welcome to the documentation for **Snykey**!

![image](./images/logo-half.png)

## What is Snykey?

Snykey is a centralized service for managing and distributing Snyk API credentials to your applications.  
It ensures your software always has access to valid Snyk access tokens, while securely storing and rotating refresh keys using OpenBao (Vault).  
This removes the persistence and secrets management burden from your application code.

## Key Features

- **Centralized Snyk credential management**
- **Secure storage and rotation** of refresh keys
- **REST API** for requesting and updating credentials
- **OpenBao integration** for robust secrets management
- **Easy deployment** with Docker Compose

## How It Works

- Applications request Snyk access tokens from the manager via the REST API.
- The manager retrieves and refreshes tokens as needed, using securely stored refresh keys.
- All secrets are stored in OpenBao, ensuring strong security and auditability.

## Quick Start

1. **Clone the repository and configure your environment.**
2. **Run the `setup.sh` script** to prepare directories, configs, and certificates.
3. **Start the stack** with Docker Compose.
4. **Initialize and unseal OpenBao** (see [Installation](getting-started/installation.md) for details).
5. **Enable the KV secrets engine** in OpenBao.
6. **Use the API** to store and retrieve Snyk credentials for your applications.

## Documentation Sections

- [Installation](getting-started/installation.md): Step-by-step setup guide
- [Configuration](getting-started/configuration.md): Environment variables and service configuration
- [API Reference](endpoints/v1.md): REST API endpoints and usage


## Running Tests

To run the test suite:

```bash
pip install -r tests/requirements.txt
pytest
```

## OpenBao Setup (Summary)

1. Initialize OpenBao:
```bash
docker exec -it openbao bao operator init -n 1 -t 1
```

2. Unseal and login:
```bash
docker exec -it openbao bao operator unseal $OPENBAO_UNSEAL_KEY
docker exec -it openbao bao login $OPENBAO_TOKEN
```

3. Enable secrets engine:
```bash
docker exec -it openbao bao secrets enable -version=2 kv
```