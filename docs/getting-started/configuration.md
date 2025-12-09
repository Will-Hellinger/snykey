# Configuration

Snykey is highly configurable to fit a variety of deployment environments. Below are the main configuration options you can adjust to suit your needs.

## Environment Variables

Most configuration is handled via environment variables, typically set in your `.env` file or passed directly to Docker Compose. See `.env_example` for a template.

| Variable            | Description                                              | Default/Example         |
|---------------------|---------------------------------------------------------|-------------------------|
| `OPENBAO_ADDR`      | URL for the OpenBao server                              | `https://openbao:8200`  |
| `OPENBAO_TOKEN`     | Root token for OpenBao                                  | *(set after init)*      |
| `OPENBAO_UNSEAL_KEY`| Unseal key for OpenBao                                  | *(set after init)*      |
| `REDIS_HOST`        | Hostname for Redis                                      | `redis`                 |
| `REDIS_PORT`        | Port for Redis                                          | `6379`                  |
| `REDIS_PASSWORD`    | Password for Redis                                      | `example_password`      |
| `REDIS_CACHE_TIME`  | Cache time (in seconds) for Redis tokens                | `3000`                  |
| `REDIS_PKCE_EXPIRATION`| Cache time (in seconds) for app registration uri to have valid callback | `600`|

You can modify these in your `.env` file or override them in your deployment environment.

---

## Redis Configuration

Redis is configured via [`configs/redis_config.conf`](../configs/redis_config.conf).
You can adjust:

- **Port**: Change the `port` directive.
- **Password**: Set `requirepass` to your desired password.
- **Persistence**: Adjust `appendonly` and `appendfsync` for durability/performance.
- **Logging**: Change `loglevel` as needed.

Example:
```conf
--8<-- "configs/redis_config.conf"
```
