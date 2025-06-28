{
  "backend": {
    "file": {
      "path": "/bao/file"
    }
  },
  "listener": {
    "tcp": {
      "address": "0.0.0.0:8200",
      "tls_disable": 0,
      "tls_cert_file": "/certs/bao.crt",
      "tls_key_file": "/certs/bao.key",
      "tls_client_ca_file": "/certs/ca/ca.crt"
    }
  },
  "default_lease_ttl": "168h",
  "max_lease_ttl": "0h",
  "ui": true,
  "log_level": "Debug"
}