#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SOFTHSM2_CONF="$SCRIPT_DIR/softhsm2.conf"
TOKEN_DIR="$SCRIPT_DIR/tokens"

# Clean up any previous tokens
rm -rf "$TOKEN_DIR"
mkdir -p "$TOKEN_DIR"

# Initialize token
softhsm2-util --init-token --slot 0 --label "bergshamra-test" --pin 1234 --so-pin 5678

# Generate an RSA 2048 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label "bergshamra-test" \
    --keypairgen --key-type rsa:2048 --id 01 --label "test-rsa-key"

# Generate an EC P-256 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label "bergshamra-test" \
    --keypairgen --key-type EC:prime256v1 --id 02 --label "test-ec-key"

# Generate an EC P-384 key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label "bergshamra-test" \
    --keypairgen --key-type EC:secp384r1 --id 03 --label "test-ec384-key"

# Generate Ed25519 key pair (if SoftHSM2 supports it)
if pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-mechanisms 2>/dev/null | grep -q "EC-EDWARDS-KEY-PAIR-GEN"; then
    if pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
        --login --pin 1234 --token-label "bergshamra-test" \
        --keypairgen --key-type EC:edwards25519 --id 04 --label "test-ed25519-key" 2>/dev/null; then
        echo "  Ed25519 key generated successfully"
    else
        echo "  WARNING: Ed25519 key generation failed (SoftHSM2 may not fully support it)"
    fi
else
    echo "  WARNING: SoftHSM2 does not support EdDSA key generation, skipping Ed25519"
fi

# Generate HMAC key (256-bit = 32 bytes generic secret)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label "bergshamra-test" \
    --keygen --key-type GENERIC:32 --id 05 --label "test-hmac-key" \
    --usage-sign

# Generate AES-256 key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 --token-label "bergshamra-test" \
    --keygen --key-type AES:32 --id 06 --label "test-aes-key"

echo ""
echo "SoftHSM2 test token initialized successfully"
echo "  Token: bergshamra-test"
echo "  PIN: 1234"
echo "  RSA 2048 key:     test-rsa-key    (id 01)"
echo "  EC P-256 key:     test-ec-key     (id 02)"
echo "  EC P-384 key:     test-ec384-key  (id 03)"
echo "  Ed25519 key:      test-ed25519-key (id 04) -- if supported"
echo "  HMAC-256 key:     test-hmac-key   (id 05)"
echo "  AES-256 key:      test-aes-key    (id 06)"
