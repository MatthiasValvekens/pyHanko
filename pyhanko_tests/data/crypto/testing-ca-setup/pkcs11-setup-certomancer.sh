# WARNING: This script is NOT idempotent!
# Running it more than once will mess up the state!


set -eu

cleanup() {
  softhsm2-util --delete-token --token testrsa
  softhsm2-util --delete-token --token testecdsa
  softhsm2-util --delete-token --token testdsa
  softhsm2-util --delete-token --token tested25519
  softhsm2-util --delete-token --token tested448
}

softhsm2-util --init-token --label testecdsa --pin 1234 --so-pin 5678 --free
softhsm2-util --init-token --label testrsa --pin 1234 --so-pin 5678 --free
softhsm2-util --init-token --label testdsa --pin 1234 --so-pin 5678 --free
softhsm2-util --init-token --label tested25519 --pin 1234 --so-pin 5678 --free
softhsm2-util --init-token --label tested448 --pin 1234 --so-pin 5678 --free

alchemise() {
 python -m certomancer --config "$CERTOMANCER_CONFIG_PATH" alch --cert signer1 \
    --include-chain --pin 1234 --module "$SOFTHSM2_MODULE_PATH" --token-label $1 $2
}

alchemise testrsa testing-ca
alchemise testecdsa testing-ca-ecdsa
alchemise testdsa testing-ca-dsa
alchemise tested25519 testing-ca-ed25519
alchemise tested448 testing-ca-ed448
