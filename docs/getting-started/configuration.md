# Configuration

Snykey is highly configurable to fit a variety of deployment environments. Below are the main configuration options you can adjust to suit your needs.

## Environment Variables

Most configuration is handled via environment variables, typically set in your `.env` file or passed directly to Docker Compose. See `.env_example` for a template.

| Variable | Description | Default/Example |
|---|---|---|
| `OPENBAO_ADDR` | URL for the OpenBao server | `https://openbao:8200` |
| `OPENBAO_TOKEN` | Root token for OpenBao | *(set after init)* |
| `OPENBAO_UNSEAL_KEY` | Unseal key for OpenBao | *(set after init)* |
| `OPENBAO_CA_CERT` | Path to a CA cert for verifying OpenBao TLS. Leave empty to use the system trust store (e.g. for Let's Encrypt or mkcert) | *(empty)* |
| `REDIS_HOST` | Hostname for Redis | `redis` |
| `REDIS_PORT` | Port for Redis | `6379` |
| `REDIS_PASSWORD` | Password for Redis | `example_password` |
| `REDIS_CACHE_TIME` | Cache time (in seconds) for Redis tokens | `3000` |
| `REDIS_PKCE_EXPIRATION` | Cache time (in seconds) for PKCE data during app registration | `600` |
| `EXCLUDED_PATHS` | Comma-separated endpoints to bypass API key middleware | `/docs,/openapi.json,/v1/callback` |
| `API_KEY` | The key required by middleware, sent via the `X-API-Key` header. Remove the entry to disable authentication | `example_api_key_1234567890` |

You can modify these in your `.env` file or override them in your deployment environment.

---

## Redis Configuration

Redis is configured via [`configs/redis_config.conf`](../configs/redis_config.conf).
You can adjust:

- **Port**: Change the `port` directive.
- **Password**: Set `requirepass` to your desired password. This must match `REDIS_PASSWORD` in your `.env`.
- **Persistence**: Adjust `appendonly` and `appendfsync` for durability/performance.
- **Logging**: Change `loglevel` as needed.

Example:
```conf
--8<-- "configs/redis_config.conf"
```
