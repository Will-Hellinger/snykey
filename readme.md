# Snyk Credentials Manager

![image](./docs/images/logo-half.png)

[![Art by @stawbeby](https://img.shields.io/badge/Art%20by-%40stawbeby-indigo?style=for-the-badge&logo=instagram)](https://www.instagram.com/stawbeby/profilecard)

MAJOR Work in Progress! Things will break and change a lot!

The Snyk Credentials Manager is a secure service for managing and distributing Snyk API credentials to your applications. It ensures that your software always has access to valid Snyk access tokens, while securely storing and automatically rotating refresh keys using OpenBao. Taking the persistence requirement off of your project!

## Features
- Centralized management of Snyk API credentials
- Secure storage and rotation of refresh keys
- REST API for requesting and updating credentials
- Built-in integration with OpenBao for robust secrets management
- Easy deployment with Docker Compose

## How It Works
- Applications request Snyk access tokens from the manager
- The manager retrieves and refreshes tokens as needed, using securely stored refresh keys
- All secrets are stored in OpenBao, ensuring strong security and auditability

## Running Tests

1. **Install test dependencies:**
   ```bash
   pip install -r ./tests/requirements.txt
   ```

2. **Run the test suite:**
   ```bash
   pytest
   ```

---

# OpenBao Setup

The following steps will help you initialize and configure OpenBao for use with the Snyk Credentials Manager.

## 1. Initialize OpenBao
Run the following command to initialize OpenBao:
```bash
docker exec -it openbao bao operator init -n 1 -t 1
```

### Example Output
```
Unseal Key 1: OPENBAO_UNSEAL_KEY

Initial Root Token: OPENBAO_TOKEN

Vault initialized with 1 key shares and a key threshold of 1. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 1 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 1 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```

Save the Unseal Key and the Root Token. You will need them in the next steps and should add them to your `.env` file.

## 2. Restart the Containers
After updating your `.env` file, restart all containers:

```bash
docker compose down
```
```bash
docker compose up -d
```

## 3. Unseal and Login to OpenBao
Unseal the OpenBao vault:
```bash
docker exec -it openbao bao operator unseal $OPENBAO_UNSEAL_KEY
```

Login with your root token:
```bash
docker exec -it openbao bao login $OPENBAO_TOKEN
```

## 4. Enable Secrets Engines
Enable the key-value secrets engine (version 2):
```bash
docker exec -it openbao bao secrets enable -version=2 kv
```

---

# Next Steps
- Use the Snyk Credentials Manager API to store and retrieve Snyk credentials for your applications.
- Ensure your applications are configured to request credentials from this service, not directly from Snyk.