#!/bin/bash

# Set up a CA for testing purposes using "$OPENSSL" and faketime

# NOTE: on macos, you need to set the "$OPENSSL" variable to a 
# non-SIP-protected binary for the time manipulation tricks to work

# NOTE2: This script has been deprecated in favour of a Certomancer-based approach.

set -e
set -o pipefail

. setup-params
subj_prefix="/C=$COUNTRY/O=$ORG/OU=$ORG_UNIT"

ensure_key () {
    if [[ "$FORCE_NEW_KEYS" = yes || ! -f "$1" ]] ; then
        if [[ "$USE_ECC_KEYS" = yes ]] ; then
            echo -n "Generating ECDSA key for $1... "
            # ecparam doesn't have an option for encrypting the output
            # directly, so we need to pipe through openssl ec
            "$OPENSSL" ecparam -name secp384r1 -genkey | \
                "$OPENSSL" ec -aes256 -out "$1" \
                -passout "pass:$DUMMY_PASSWORD" \
                2>> "$LOGFILE" > /dev/null
        else
            echo -n "Generating RSA key for $1... "
            "$OPENSSL" genrsa -aes256 -out "$1" \
                -passout "pass:$DUMMY_PASSWORD" \
                2>> "$LOGFILE" >/dev/null
        fi
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

    # only reinitialise the index when FORCE_NEW_CERTS is yes
    if [[ "$FORCE_NEW_CERTS" = yes || ! -f "serial" ]] ; then
        echo $INITIAL_SERIAL > serial
        rm -f *.old
        rm -f index.*
        touch index.txt
        echo $INITIAL_SERIAL > crlnumber
    fi 

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

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "root/certs/ca.cert.pem" ]] ; then
    "$OPENSSL" req -config openssl.cnf -key root/ca.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=Root CA" \
        -out "root/csr/root.csr.pem" -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_root \
        -passin "pass:$DUMMY_PASSWORD" -selfsign \
        -in root/csr/root.csr.pem \
        -out root/certs/ca.cert.pem -md $MESSAGE_DIGEST -notext \
        -extensions v3_ca -startdate $ROOT_START -enddate $ROOT_END \
        2>> "$LOGFILE" >/dev/null
fi


echo "Setting up intermediate certificate authority..."
setup_ca_dir intermediate

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "intermediate/certs/ca.cert.pem" ]]
then
    "$OPENSSL" req -config openssl.cnf -key intermediate/ca.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=Intermediate CA" \
        -out "root/csr/intermediate.csr.pem" -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_root \
        -extensions v3_intermediate_ca -md $MESSAGE_DIGEST -notext \
        -startdate $INTERM_START -enddate $INTERM_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in root/csr/intermediate.csr.pem \
        -out intermediate/certs/ca.cert.pem \
        2>> "$LOGFILE" >/dev/null
    cat "root/certs/ca.cert.pem" "intermediate/certs/ca.cert.pem" \
        > "intermediate/certs/ca-chain.cert.pem"
fi


LEAF_CERTS=intermediate/newcerts

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "$LEAF_CERTS/ocsp.cert.pem" ]]
then
    echo "Signing OCSP responder certificate for intermediate CA..."
    ensure_key keys/ocsp.key.pem 
    "$OPENSSL" req -config openssl.cnf -key keys/ocsp.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=OCSP Responder" \
        -out intermediate/csr/ocsp.csr.pem -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_intermediate \
        -extensions ocsp -md $MESSAGE_DIGEST -notext \
        -startdate $OCSP_START -enddate $OCSP_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in intermediate/csr/ocsp.csr.pem \
        -out $LEAF_CERTS/ocsp.cert.pem \
        2>> "$LOGFILE" >/dev/null
fi



if [[ "$FORCE_NEW_CERTS" = yes || ! -f "$LEAF_CERTS/tsa.cert.pem" ]]
then
    echo "Signing TSA certificate..."
    ensure_key keys/tsa.key.pem 
    "$OPENSSL" req -config openssl.cnf -key keys/tsa.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=Time Stamping Authority" \
        -out root/csr/tsa.csr.pem -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_root \
        -extensions tsa_cert -md $MESSAGE_DIGEST -notext \
        -startdate $TSA_START -enddate $TSA_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in root/csr/tsa.csr.pem \
        -out root/newcerts/tsa.cert.pem \
        2>> "$LOGFILE" >/dev/null
fi

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "$LEAF_CERTS/tsa2.cert.pem" ]]
then
    echo "Signing TSA2 certificate..."
    ensure_key keys/tsa2.key.pem 
    "$OPENSSL" req -config openssl.cnf -key keys/tsa2.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=Time Stamping Authority 2" \
        -out root/csr/tsa2.csr.pem -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_root \
        -extensions tsa_cert -md $MESSAGE_DIGEST -notext \
        -startdate $TSA2_START -enddate $TSA2_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in root/csr/tsa2.csr.pem \
        -out root/newcerts/tsa2.cert.pem \
        2>> "$LOGFILE" >/dev/null
fi


if [[ "$FORCE_NEW_CERTS" = yes || ! -f "$LEAF_CERTS/$SIGNER_IDENT.cert.pem" ]]
then
    echo "Signing end-user certificate for $SIGNER_NAME..."
    ensure_key keys/$SIGNER_IDENT.key.pem
    "$OPENSSL" req -config openssl.cnf -key keys/$SIGNER_IDENT.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=$SIGNER_NAME/emailAddress=$SIGNER_EMAIL" \
        -out intermediate/csr/$SIGNER_IDENT.csr.pem -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_intermediate \
        -extensions usr_cert -md $MESSAGE_DIGEST -notext \
        -startdate $SIGNER_START -enddate $SIGNER_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in intermediate/csr/$SIGNER_IDENT.csr.pem \
        -out $LEAF_CERTS/$SIGNER_IDENT.cert.pem \
        2>> "$LOGFILE" >/dev/null

    if [[ "$FORCE_NEW_PFX" = yes || ! -f "$LEAF_CERTS/$SIGNER_IDENT.pfx" ]]
    then
        "$OPENSSL" pkcs12 -export -out $LEAF_CERTS/$SIGNER_IDENT.pfx \
            -inkey keys/$SIGNER_IDENT.key.pem \
            -in $LEAF_CERTS/$SIGNER_IDENT.cert.pem \
            -certfile intermediate/certs/ca-chain.cert.pem \
            -passin "pass:$DUMMY_PASSWORD" -passout "pass:$DUMMY_PFX_PASSWORD" \
            2>> "$LOGFILE" >/dev/null
    fi
fi


if [[ "$FORCE_NEW_CERTS" = yes || ! -f "$LEAF_CERTS/$SIGNER_IDENT2.cert.pem" ]]
then
    echo "Signing end-user certificate for $SIGNER2_NAME..."
    ensure_key keys/$SIGNER2_IDENT.key.pem
    "$OPENSSL" req -config openssl.cnf -key keys/$SIGNER2_IDENT.key.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -subj "$subj_prefix/CN=$SIGNER2_NAME/emailAddress=$SIGNER2_EMAIL" \
        -out intermediate/csr/$SIGNER2_IDENT.csr.pem -new -$MESSAGE_DIGEST \
        2>> "$LOGFILE" >/dev/null

    "$OPENSSL" ca -batch -config openssl.cnf -name CA_intermediate \
        -extensions usr_cert -md $MESSAGE_DIGEST -notext \
        -startdate $SIGNER2_START -enddate $SIGNER2_END \
        -passin "pass:$DUMMY_PASSWORD" \
        -in intermediate/csr/$SIGNER2_IDENT.csr.pem \
        -out $LEAF_CERTS/$SIGNER2_IDENT.cert.pem \
        2>> "$LOGFILE" >/dev/null

    if [[ "$FORCE_NEW_PFX" = yes || ! -f "$LEAF_CERTS/$SIGNER2_IDENT.pfx" ]]
    then
        "$OPENSSL" pkcs12 -export -out $LEAF_CERTS/$SIGNER2_IDENT.pfx \
            -inkey keys/$SIGNER2_IDENT.key.pem \
            -in $LEAF_CERTS/$SIGNER2_IDENT.cert.pem \
            -certfile intermediate/certs/ca-chain.cert.pem \
            -passin "pass:$DUMMY_PASSWORD" -passout "pass:$DUMMY_PFX_PASSWORD" \
            2>> "$LOGFILE" >/dev/null
    fi

    echo "Revoking certificate for $SIGNER2_NAME..."
    # don't do this using -revoke, because that doesn't allow timestamps
    # to be specified

    # R	210101000000Z	201017111503Z	1002	unknown	/C=BE/O=Example Inc/OU=Testing Authority/CN=Bob Revoked/emailAddress=bob@example.com
    cp intermediate/index.txt intermediate/index.txt.tmp
    sed 3s/V/R/ intermediate/index.txt.tmp | \
        sed "3s/		/	$SIGNER2_REVO	/" > intermediate/index.txt
    rm intermediate/index.txt.tmp
fi



# Create some CRLs

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "intermediate/crl/ca.crl.pem" ]]
then
    ensure_dir intermediate/crl
    faketime "$CRL_DATE" "$OPENSSL" ca -name CA_intermediate \
        -config openssl.cnf -gencrl \
        -out intermediate/crl/ca.crl.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -crldays $CRLDAYS \
        2>> "$LOGFILE" >/dev/null
fi

if [[ "$FORCE_NEW_CERTS" = yes || ! -f "root/crl/ca.crl.pem" ]]
then
    ensure_dir root/crl
    faketime "$CRL_DATE" "$OPENSSL" ca -name CA_root \
        -config openssl.cnf -gencrl \
        -out root/crl/ca.crl.pem \
        -passin "pass:$DUMMY_PASSWORD" \
        -crldays $CRLDAYS \
        2>> "$LOGFILE" >/dev/null
fi


echo "Cleaning up..."
rm **/*.old
echo "Setup complete"
