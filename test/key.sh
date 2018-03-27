#!/bin/sh

keydir=key
mkdir ${keydir}

#
# generate keys for test
#



#
echo -n "sym_pw" > ${keydir}/sym.pw

#
echo -n "${keydir}/rsa_pw" > ${keydir}/rsa.pw
openssl genrsa 2048 > ${keydir}/rsa_prv.pem
openssl rsa -in ${keydir}/rsa_prv.pem -pubout -out ${keydir}/rsa_pub.pem
openssl rsa -in ${keydir}/rsa_prv.pem -aes256 -out ${keydir}/rsa_prv_pw.pem -passout file:${keydir}/rsa.pw
openssl req -new -sha256 -key ${keydir}/rsa_prv.pem -subj "/CN=test ezio" > ${keydir}/rsa.csr
openssl x509 -req -in ${keydir}/rsa.csr -signkey ${keydir}/rsa_prv.pem -out ${keydir}/rsa_pub.crt -days 365

#
echo -n "${keydir}/ec_pw" > ${keydir}/ec.pw
openssl ecparam -name secp521r1 -genkey > ${keydir}/ec_prv.pem
#openssl ecparam -name prime256v1 -genkey > ${keydir}/ec_prv.pem
openssl ec -in ${keydir}/ec_prv.pem -pubout -out ${keydir}/ec_pub.pem
openssl ec -in ${keydir}/ec_prv.pem -aes256 -out ${keydir}/ec_prv_pw.pem -passout file:${keydir}/ec.pw
openssl req -new -sha256 -key ${keydir}/ec_prv.pem -subj "/CN=test ezio" > ${keydir}/ec.csr
openssl x509 -req -in ${keydir}/ec.csr -signkey ${keydir}/ec_prv.pem -out ${keydir}/ec_pub.crt -days 365
