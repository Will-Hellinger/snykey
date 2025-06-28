#!/bin/bash
set -euo pipefail

# Defaults
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOLUMES_DIR="${SCRIPT_DIR}/../.container_volumes"
CERT_DIR="${VOLUMES_DIR}/certs"
COUNTRY="US"
STATE="State"
CITY="City"
ORG="OrgName"
CA_CN="InternalCA"
BAO_CN="openbao"
APP_CN="app"
BAO_SANS="DNS:openbao,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"
APP_SANS="DNS:app,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"

usage() {
  echo "Usage: $0 [options]"
  echo "  -d DIR         Output cert dir (default: $CERT_DIR)"
  echo "  -c COUNTRY     Country (default: $COUNTRY)"
  echo "  -s STATE       State (default: $STATE)"
  echo "  -l CITY        City (default: $CITY)"
  echo "  -o ORG         Organization (default: $ORG)"
  echo "  --ca-cn CN     CA Common Name (default: $CA_CN)"
  echo "  --bao-cn CN    OpenBao Common Name (default: $BAO_CN)"
  echo "  --app-cn CN    App Common Name (default: $APP_CN)"
  echo "  --bao-sans S   OpenBao SANs (default: $BAO_SANS)"
  echo "  --app-sans S   App SANs (default: $APP_SANS)"
  echo "  -h             Help"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    -d) CERT_DIR="$2"; shift 2;;
    -c) COUNTRY="$2"; shift 2;;
    -s) STATE="$2"; shift 2;;
    -l) CITY="$2"; shift 2;;
    -o) ORG="$2"; shift 2;;
    --ca-cn) CA_CN="$2"; shift 2;;
    --bao-cn) BAO_CN="$2"; shift 2;;
    --app-cn) APP_CN="$2"; shift 2;;
    --bao-sans) BAO_SANS="$2"; shift 2;;
    --app-sans) APP_SANS="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

# Check for openssl
command -v openssl >/dev/null 2>&1 || { echo "openssl required" >&2; exit 1; }

# Subject string
gen_subj() { echo "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$1"; }

# Minimal OpenSSL config with SAN
gen_conf() {
  cat > "$3" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
CN = $1
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $2
EOF
}

# Create dirs
mkdir -p "$CERT_DIR/ca" "$CERT_DIR/bao" "$CERT_DIR/app" "$CERT_DIR/config"
echo "Generating certs in $CERT_DIR"

# CA
openssl genrsa -out "$CERT_DIR/ca/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca/ca.key" -sha256 -days 1024 \
    -out "$CERT_DIR/ca/ca.crt" -subj "$(gen_subj "$CA_CN")"

# OpenBao
BAO_CONF="$CERT_DIR/config/bao.cnf"
gen_conf "$BAO_CN" "$BAO_SANS" "$BAO_CONF"
openssl genrsa -out "$CERT_DIR/bao/bao.key" 2048
openssl req -new -key "$CERT_DIR/bao/bao.key" -out "$CERT_DIR/bao/bao.csr" -config "$BAO_CONF"
openssl x509 -req -in "$CERT_DIR/bao/bao.csr" -CA "$CERT_DIR/ca/ca.crt" -CAkey "$CERT_DIR/ca/ca.key" -CAcreateserial \
    -out "$CERT_DIR/bao/bao.crt" -days 365 -sha256 -extfile "$BAO_CONF" -extensions v3_req

# App
APP_CONF="$CERT_DIR/config/app.cnf"
gen_conf "$APP_CN" "$APP_SANS" "$APP_CONF"
openssl genrsa -out "$CERT_DIR/app/app.key" 2048
openssl req -new -key "$CERT_DIR/app/app.key" -out "$CERT_DIR/app/app.csr" -config "$APP_CONF"
openssl x509 -req -in "$CERT_DIR/app/app.csr" -CA "$CERT_DIR/ca/ca.crt" -CAkey "$CERT_DIR/ca/ca.key" -CAcreateserial \
    -out "$CERT_DIR/app/app.crt" -days 365 -sha256 -extfile "$APP_CONF" -extensions v3_req

# Cleanup
rm -f "$CERT_DIR/bao/bao.csr" "$CERT_DIR/app/app.csr"
rm -rf "$CERT_DIR/config"

chmod 600 "$CERT_DIR/ca/ca.key" "$CERT_DIR/bao/bao.key" "$CERT_DIR/app/app.key"
chmod 644 "$CERT_DIR/ca/ca.crt" "$CERT_DIR/bao/bao.crt" "$CERT_DIR/app/app.crt"

echo "Certificate generation complete!"
echo "Certificates are in: $CERT_DIR"