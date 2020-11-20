#!/bin/bash

# Set up a CA for testing purposes using openssl

set -e
set -o pipefail

. setup-params

init_config

cd "$BASE_DIR"
ensure_dir root/crl
ensure_dir intermediate/crl
openssl ca -name CA_intermediate -config openssl.cnf -gencrl \
    -out intermediate/crl/ca.crl.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -crldays $CRLDAYS
openssl ca -name CA_root -config openssl.cnf -gencrl \
    -out root/crl/ca.crl.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -crldays $CRLDAYS
