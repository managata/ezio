#!/bin/zsh

source test.sh

function check2() {
  echo "# egrep -c \"^N: signature verified\" ${wrkdir}/x.log"
  egrep -c "^N: signature verified" ${wrkdir}/x.log
}

# rsa

echo; echo "#### rsa sign"
archive --sign-key=${wrkdir}/${keydir}/rsa_prv.pem
check --verify-key=${wrkdir}/${keydir}/rsa_pub.pem
check2

echo; echo "#### rsa sign w/pass"
archive --sign-key=${wrkdir}/${keydir}/rsa_prv_pw.pem --sign-pass-fd=3 3< ${wrkdir}/${keydir}/rsa.pw
check --verify-key=${wrkdir}/${keydir}/rsa_pub.pem
check2

echo; echo "#### rsa sign sha512"
archive --sign-key=${wrkdir}/${keydir}/rsa_prv.pem -H5
check --verify-key=${wrkdir}/${keydir}/rsa_pub.pem
check2

# ecdsa

echo; echo "#### ecdsa sign"
archive --sign-key=${wrkdir}/${keydir}/ec_prv.pem
check --verify-key=${wrkdir}/${keydir}/ec_pub.pem
check2

echo; echo "#### ecdsa sign w/pass"
archive --sign-key=${wrkdir}/${keydir}/ec_prv_pw.pem --sign-pass-fd=3 3< ${wrkdir}/${keydir}/ec.pw
check --verify-key=${wrkdir}/${keydir}/ec_pub.crt
check2

echo; echo "#### ecdsa sign sha512"
archive --sign-key=${wrkdir}/${keydir}/ec_prv.pem -H5
check --verify-key=${wrkdir}/${keydir}/ec_pub.pem
check2
