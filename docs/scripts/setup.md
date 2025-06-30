# Setup Script

## Overview

This Python script automates the initial setup for Snykey. It creates the required directory structure and copies configuration files for OpenBao and Redis into the appropriate locations under `.container_volumes`. This prepares your environment for running the stack with Docker Compose.

## Features

* Creates all necessary directories for logs, data, configs, and certificates.
* Copies OpenBao and Redis configuration files from the `configs` directory to their respective locations.
* Sets secure permissions on all created directories and files.
* Provides clear output for each step, making it easy to verify setup progress.

## Source

```python
--8<-- "scripts/setup.py"
```