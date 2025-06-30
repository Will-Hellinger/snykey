# Certificate Generation Script

## Overview

This Bash script automates the creation of a local Certificate Authority (CA) and generates signed TLS certificates for two entities: "OpenBao" and "App". It uses OpenSSL to generate private keys, certificate signing requests (CSRs), and signed certificates, including Subject Alternative Names (SANs) for both server and client authentication. The script is designed to be used in development or testing environments where self-signed certificates are sufficient.

## Features

- Creates a local CA with its own private key and certificate.
- Generates private keys and CSRs for "OpenBao" and "App".
- Signs the CSRs with the local CA, producing valid certificates.
- Supports custom configuration for certificate subject fields and SANs.
- Cleans up intermediate files and sets secure permissions on keys and certificates.

## Source

```python
--8<-- "scripts/generate_certs.py"
```