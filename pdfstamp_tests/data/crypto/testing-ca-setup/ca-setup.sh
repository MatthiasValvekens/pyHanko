#!/bin/bash

# Set up a CA for testing purposes using openssl

set -e
set -o pipefail

. setup-params
subj_prefix="/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT"

ensure_key () {
    if [[ "$FORCE_NEW_KEYS" = yes || ! -f "$1" ]] ; then
        echo -n "Generating RSA key for $1... "
        openssl genrsa -aes256 -out "$1" -passout "pass:$DUMMY_PASSWORD" \
            2>/dev/null
        echo "OK"
    fi
}


# initialise a CA directory, without signing the certificate
# arg 1: directory name
setup_ca_dir () {
    ensure_dir "$1"
    pushd "$1" > /dev/null
    ensure_dir certs
    ensure_dir csr
    ensure_dir crl
    ensure_dir newcerts
    echo $INITIAL_SERIAL > serial
    rm -f *.old
    rm -f index.*
    touch index.txt
    echo $INITIAL_SERIAL > crlnumber

    ensure_key ca.key.pem

    popd > /dev/null
    cp "$1/ca.key.pem" "keys/$(basename $1)_ca.key.pem"
}


ensure_dir "$BASE_DIR"
echo "Starting run of ca-setup.sh at $(date)" >> "$BASE_DIR/$LOGFILE"

init_config

cd "$BASE_DIR"
ensure_dir keys

echo "Setting up root certificate authority..."
setup_ca_dir root

openssl req -config openssl.cnf -key root/ca.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=Root CA" \
    -out "root/csr/root.csr.pem" -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_root \
    -passin "pass:$DUMMY_PASSWORD" -selfsign \
    -in root/csr/root.csr.pem \
    -out root/certs/ca.cert.pem -md sha256 -notext \
    -extensions v3_ca -startdate $ROOT_START -enddate $ROOT_END \
    2>> "$LOGFILE" >/dev/null


echo "Setting up intermediate certificate authority..."
setup_ca_dir intermediate

openssl req -config openssl.cnf -key intermediate/ca.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=Intermediate CA" \
    -out "root/csr/intermediate.csr.pem" -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_root \
    -extensions v3_intermediate_ca -md sha256 -notext \
    -startdate $INTERM_START -enddate $INTERM_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in root/csr/intermediate.csr.pem \
    -out intermediate/certs/ca.cert.pem \
    2>> "$LOGFILE" >/dev/null

cat "root/certs/ca.cert.pem" "intermediate/certs/ca.cert.pem" \
    > "intermediate/certs/ca-chain.cert.pem"


echo "Signing OCSP responder certificate for intermediate CA..."
ensure_key keys/ocsp.key.pem 
openssl req -config openssl.cnf -key keys/ocsp.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=OCSP Responder" \
    -out intermediate/csr/ocsp.csr.pem -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_intermediate \
    -extensions ocsp -md sha256 -notext \
    -startdate $OCSP_START -enddate $OCSP_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in intermediate/csr/ocsp.csr.pem \
    -out intermediate/newcerts/ocsp.cert.pem \
    2>> "$LOGFILE" >/dev/null



echo "Signing TSA certificate..."
ensure_key keys/tsa.key.pem 
openssl req -config openssl.cnf -key keys/tsa.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=Time Stamping Authority" \
    -out root/csr/tsa.csr.pem -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_root \
    -extensions tsa_cert -md sha256 -notext \
    -startdate $TSA_START -enddate $TSA_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in root/csr/tsa.csr.pem \
    -out root/newcerts/tsa.cert.pem \
    2>> "$LOGFILE" >/dev/null


echo "Signing end-user certificate for $SIGNER_NAME..."
ensure_key keys/$SIGNER_IDENT.key.pem
openssl req -config openssl.cnf -key keys/$SIGNER_IDENT.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=$SIGNER_NAME/emailAddress=$SIGNER_EMAIL" \
    -out intermediate/csr/$SIGNER_IDENT.csr.pem -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_intermediate \
    -extensions usr_cert -md sha256 -notext \
    -startdate $SIGNER_START -enddate $SIGNER_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in intermediate/csr/$SIGNER_IDENT.csr.pem \
    -out intermediate/newcerts/$SIGNER_IDENT.cert.pem \
    2>> "$LOGFILE" >/dev/null

openssl pkcs12 -export -out intermediate/newcerts/$SIGNER_IDENT.pfx \
    -inkey keys/$SIGNER_IDENT.key.pem \
    -in intermediate/newcerts/$SIGNER_IDENT.cert.pem \
    -certfile intermediate/certs/ca-chain.cert.pem \
    -passin "pass:$DUMMY_PASSWORD" -passout "pass:$DUMMY_PFX_PASSWORD" \
    2>> "$LOGFILE" >/dev/null


echo "Signing end-user certificate for $SIGNER2_NAME..."
ensure_key keys/$SIGNER2_IDENT.key.pem
openssl req -config openssl.cnf -key keys/$SIGNER2_IDENT.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=$SIGNER2_NAME/emailAddress=$SIGNER2_EMAIL" \
    -out intermediate/csr/$SIGNER2_IDENT.csr.pem -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_intermediate \
    -extensions usr_cert -md sha256 -notext \
    -startdate $SIGNER2_START -enddate $SIGNER2_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in intermediate/csr/$SIGNER2_IDENT.csr.pem \
    -out intermediate/newcerts/$SIGNER2_IDENT.cert.pem \
    2>> "$LOGFILE" >/dev/null

openssl pkcs12 -export -out intermediate/newcerts/$SIGNER2_IDENT.pfx \
    -inkey keys/$SIGNER2_IDENT.key.pem \
    -in intermediate/newcerts/$SIGNER2_IDENT.cert.pem \
    -certfile intermediate/certs/ca-chain.cert.pem \
    -passin "pass:$DUMMY_PASSWORD" -passout "pass:$DUMMY_PFX_PASSWORD" \
    2>> "$LOGFILE" >/dev/null

echo "Revoking certificate for $SIGNER2_NAME..."
# don't do this using -revoke, because that doesn't allow timestamps
# to be specified

# R	210101000000Z	201017111503Z	1002	unknown	/C=BE/O=Example Inc/OU=Testing Authority/CN=Bob Revoked/emailAddress=bob@example.com
cp intermediate/index.txt intermediate/index.txt.tmp
sed 3s/V/R/ intermediate/index.txt.tmp | sed "3s/		/	$SIGNER2_REVO	/" > intermediate/index.txt
rm intermediate/index.txt.tmp


echo "Setup complete"
