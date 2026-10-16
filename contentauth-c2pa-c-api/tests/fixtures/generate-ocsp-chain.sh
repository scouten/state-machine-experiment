#!/bin/sh
# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0 or the MIT license.
set -eu
cd "$(dirname "$0")"
key=../../../contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem
tmp=$(mktemp -d)
trap 'rm -f "$tmp/root.csr" "$tmp/root.pem" "$tmp/leaf.csr" "$tmp/leaf.pem" "$tmp/extensions" "$tmp/index"; rmdir "$tmp"' EXIT
printf '%s\n' 'basicConstraints=critical,CA:true' 'keyUsage=critical,keyCertSign,cRLSign' > "$tmp/extensions"
openssl req -new -key "$key" -subj '/CN=C API OCSP test root' -out "$tmp/root.csr"
openssl x509 -req -in "$tmp/root.csr" -signkey "$key" -set_serial 1 -days 36500 \
    -extfile "$tmp/extensions" -out "$tmp/root.pem"
openssl x509 -in "$tmp/root.pem" -outform DER -out ocsp-root.der
printf '%s\n' 'basicConstraints=critical,CA:false' 'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=emailProtection' 'authorityInfoAccess=OCSP;URI:http://ocsp.example/' > "$tmp/extensions"
openssl req -new -key "$key" -subj '/CN=C API OCSP test signer' -out "$tmp/leaf.csr"
openssl x509 -req -in "$tmp/leaf.csr" -CA "$tmp/root.pem" -CAkey "$key" -set_serial 2 \
    -days 36500 -extfile "$tmp/extensions" -outform DER -out ocsp-leaf.der
openssl x509 -inform DER -in ocsp-leaf.der -out "$tmp/leaf.pem"
printf 'V\t361001000000Z\t\t02\tunknown\t/CN=C API OCSP test signer\n' > "$tmp/index"
openssl ocsp -index "$tmp/index" -rsigner "$tmp/root.pem" -rkey "$key" -CA "$tmp/root.pem" \
    -issuer "$tmp/root.pem" -sha256 -cert "$tmp/leaf.pem" -ndays 36500 -respout ocsp-good.der
printf 'R\t361001000000Z\t261014000000Z\t02\tunknown\t/CN=C API OCSP test signer\n' > "$tmp/index"
openssl ocsp -index "$tmp/index" -rsigner "$tmp/root.pem" -rkey "$key" -CA "$tmp/root.pem" \
    -issuer "$tmp/root.pem" -sha256 -cert "$tmp/leaf.pem" -ndays 36500 -respout ocsp-revoked.der
