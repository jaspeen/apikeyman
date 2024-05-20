#!/bin/bash

set -euo pipefail

# This script is used to run the OpenSSL compatibility tests for the API Key Manager.
akm_cmd=../apikeyman
test_dir="./files"

mkdir -p ${test_dir}

# args: akm_name, openssl_name
ec_openssl_gen_akm_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ec_openssl_gen_akm_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate private key
  openssl ecparam -name ${openssl_name} -genkey -noout -out ${test_dir}/openssl-ec-${akm_name}.priv.pem

  # generate pub key from private
  openssl pkey -in ${test_dir}/openssl-ec-${akm_name}.priv.pem -pubout -out ${test_dir}/openssl-${akm_name}.pub.pem

  # format private key as pkcs8
  openssl pkcs8 -topk8 -in ${test_dir}/openssl-ec-${akm_name}.priv.pem -out ${test_dir}/openssl-${akm_name}.priv.pem -nocrypt

  # sign with akm
  testdata="test data"
  signature=$(echo -n "${testdata}" | $akm_cmd sign -a ${akm_name} --private ${test_dir}/openssl-${akm_name}.priv.pem)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/openssl-${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/openssl-${akm_name}.sig.bin
  echo -n "${testdata}" | openssl dgst -sha256 -verify ${test_dir}/openssl-${akm_name}.pub.pem -signature ${test_dir}/openssl-${akm_name}.sig.bin

  echo "Success"
}

# args: akm_name, openssl_name
ec_akm_gen_openssl_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ec_akm_gen_openssl_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate keypair
  $akm_cmd gen -a ${akm_name} --private ${test_dir}/${akm_name}.priv.pem --public ${test_dir}/${akm_name}.pub.pem

  # sign with openssl
  testdata="test data"
  signature=$(echo -n "${testdata}" | openssl dgst -sha256 -sign ${test_dir}/${akm_name}.priv.pem | openssl enc -base64 -A)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/${akm_name}.sig.bin
  echo -n "${testdata}" | openssl dgst -sha256 -verify ${test_dir}/${akm_name}.pub.pem -signature ${test_dir}/${akm_name}.sig.bin
  echo "Success"
}

# args: akm_name, openssl_name
ed_openssl_gen_akm_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ed_openssl_gen_akm_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate private key
  openssl genpkey -algorithm "${openssl_name}" -out ${test_dir}/openssl-${akm_name}.priv.pem

  # generate pub key from private
  openssl pkey -in ${test_dir}/openssl-${akm_name}.priv.pem -pubout -out ${test_dir}/openssl-${akm_name}.pub.pem

  # test data
  testdata="test data"
  echo -n "${testdata}" > ${test_dir}/openssl-${akm_name}.data.bin

  # sign with akm
  signature=$(echo -n "${testdata}" | $akm_cmd sign -a ${akm_name} --private ${test_dir}/openssl-${akm_name}.priv.pem)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/openssl-${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/openssl-${akm_name}.sig.bin
  openssl pkeyutl -verify -pubin -inkey ${test_dir}/openssl-${akm_name}.pub.pem -rawin -in ${test_dir}/openssl-${akm_name}.data.bin -sigfile ${test_dir}/openssl-${akm_name}.sig.bin

  echo "Success"
}

# args: akm_name, openssl_name
ed_akm_gen_openssl_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ed_akm_gen_openssl_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate keypair
  $akm_cmd gen -a ${akm_name} --private ${test_dir}/${akm_name}.priv.pem --public ${test_dir}/${akm_name}.pub.pem

  # test data
  testdata="test data"
  echo -n "${testdata}" > ${test_dir}/${akm_name}.data.bin

  # sign with openssl
  signature=$(openssl pkeyutl -sign -inkey ${test_dir}/${akm_name}.priv.pem -rawin -in ${test_dir}/${akm_name}.data.bin | openssl enc -base64 -A)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/${akm_name}.sig.bin
  openssl pkeyutl -verify -pubin -inkey ${test_dir}/${akm_name}.pub.pem -rawin -in ${test_dir}/${akm_name}.data.bin -sigfile ${test_dir}/${akm_name}.sig.bin

  echo "Success"
}

# args: akm_name, openssl_name
rsa_openssl_gen_akm_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ed_openssl_gen_akm_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate private key
  openssl genpkey -algorithm "${openssl_name}" -pkeyopt rsa_keygen_bits:2048 -out ${test_dir}/openssl-${akm_name}.priv.pem

  # generate pub key from private
  openssl pkey -in ${test_dir}/openssl-${akm_name}.priv.pem -pubout -out ${test_dir}/openssl-${akm_name}.pub.pem
  #openssl ec -in ${test_dir}/openssl-ec-${akm_name}.priv.pem -pubout -out ${test_dir}/openssl-${akm_name}.pub.pem

  # format private key as pkcs8
  #openssl pkcs8 -topk8 -in ${test_dir}/openssl-ec-${akm_name}.priv.pem -out ${test_dir}/openssl-${akm_name}.priv.pem -nocrypt

  # test data
  testdata="test data"
  echo -n "${testdata}" > ${test_dir}/openssl-${akm_name}.data.bin

  # sign with akm
  signature=$(echo -n "${testdata}" | $akm_cmd sign -a ${akm_name} --private ${test_dir}/openssl-${akm_name}.priv.pem)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/openssl-${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/openssl-${akm_name}.sig.bin
  openssl pkeyutl -verify -pubin -inkey ${test_dir}/openssl-${akm_name}.pub.pem -rawin -in ${test_dir}/openssl-${akm_name}.data.bin -sigfile ${test_dir}/openssl-${akm_name}.sig.bin

  echo "Success"
}

# args: akm_name, openssl_name
rsa_akm_gen_openssl_sign() {
  akm_name="$1"
  openssl_name="$2"
  echo "ed_akm_gen_openssl_sign for akm_name=${akm_name}, openssl_name=${openssl_name}."

  # generate keypair
  $akm_cmd gen -a ${akm_name} --private ${test_dir}/${akm_name}.priv.pem --public ${test_dir}/${akm_name}.pub.pem

  # test data
  testdata="test data"
  echo -n "${testdata}" > ${test_dir}/${akm_name}.data.bin

  # sign with openssl
  
  #signature=$(echo -n "${testdata}" | openssl dgst -sha256 -sign ${test_dir}/${akm_name}.priv.pem | openssl enc -base64 -A)
  signature=$(openssl pkeyutl -sign -inkey ${test_dir}/${akm_name}.priv.pem -rawin -in ${test_dir}/${akm_name}.data.bin | openssl enc -base64 -A)
  echo "Signature: ${signature}"

  # verify with akm
  echo -n "${testdata}" | $akm_cmd verify -a ${akm_name} --public ${test_dir}/${akm_name}.pub.pem --signature "${signature}"

  # verify with openssl
  echo -n "${signature}" | openssl enc -d -A -base64 > ${test_dir}/${akm_name}.sig.bin
  openssl pkeyutl -verify -pubin -inkey ${test_dir}/${akm_name}.pub.pem -rawin -in ${test_dir}/${akm_name}.data.bin -sigfile ${test_dir}/${akm_name}.sig.bin

  echo "Success"
}

ec_openssl_gen_akm_sign "ES256K" "secp256k1"
ec_akm_gen_openssl_sign "ES256K" "secp256k1"

ec_openssl_gen_akm_sign "ES256" "prime256v1"
ec_akm_gen_openssl_sign "ES256" "prime256v1"

ed_openssl_gen_akm_sign "EdDSA" "Ed25519"
ed_akm_gen_openssl_sign "EdDSA" "Ed25519"

rsa_openssl_gen_akm_sign "RS256" "rsa"
rsa_akm_gen_openssl_sign "RS256" "rsa"

echo "All tests passed!"