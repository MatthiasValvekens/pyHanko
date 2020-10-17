#!/bin/bash

# Set up a CA for testing purposes using openssl

set -e
set -o pipefail

. setup-params
subj_prefix="/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT"

ensure_dir () {
    if [ -e "$1" ] ; then
        if [ ! -d "$1" ] ; then
            >&2 echo "$1 exists and is not a directory"
            exit 1
        fi
    else 
        mkdir -p "$1"
    fi
}


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


if [[ "$FORCE_CONFIG_REWRITE" = yes || ! -f "$BASE_DIR/openssl.cnf" ]] ; then
    # I'm assuming that the BASE_DIR never contains a colon
    #  which is good enough as far as I'm concerned
    real_base_dir=$(realpath $BASE_DIR)
    sed "s:TESTING_CA_BASE_DIR:$real_base_dir:g" openssl.base.cnf > "$BASE_DIR/openssl.cnf"
fi

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
ensure_key keys/signer.key.pem
openssl req -config openssl.cnf -key keys/signer.key.pem \
    -passin "pass:$DUMMY_PASSWORD" \
    -subj "$subj_prefix/CN=$SIGNER_NAME/emailAddress=$SIGNER_EMAIL" \
    -out intermediate/csr/signer.csr.pem -new -sha256 \
    2>> "$LOGFILE" >/dev/null

openssl ca -batch -config openssl.cnf -name CA_intermediate \
    -extensions usr_cert -md sha256 -notext \
    -startdate $SIGNER_START -enddate $SIGNER_END \
    -passin "pass:$DUMMY_PASSWORD" \
    -in intermediate/csr/signer.csr.pem \
    -out intermediate/newcerts/signer.cert.pem \
    2>> "$LOGFILE" >/dev/null


echo "Setup complete"
