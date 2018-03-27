#!/bin/zsh

source test.sh

function check2() {
  echo
  echo "# grep -c 'bunzip2' ${wrkdir}/a.aez"
  grep -c 'bunzip2' ${wrkdir}/a.aez
}

# aes

echo; echo "#### symmetric file"
archive -e --pass-file=${wrkdir}/${keydir}/sym.pw
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2

echo; echo "#### symmetric fd"
archive -e --pass-fd=3 3< ${wrkdir}/${keydir}/sym.pw
check --pass-fd=3 3< ${wrkdir}/${keydir}/sym.pw
check2

echo; echo "#### rsa"
archive -e --encrypt-key=${wrkdir}/${keydir}/rsa_pub.pem
check --decrypt-key=${wrkdir}/${keydir}/rsa_prv.pem
check2

echo; echo "#### rsa crt w/pass"
archive -e --encrypt-key=${wrkdir}/${keydir}/rsa_pub.crt
check --decrypt-key=${wrkdir}/${keydir}/rsa_prv_pw.pem --pass-fd=3 3< ${wrkdir}/${keydir}/rsa.pw
check2

# chacha

echo; echo "#### symmetric file chacha"
archive -e --pass-file=${wrkdir}/${keydir}/sym.pw -Ec
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2

echo; echo "#### rsa chacha"
archive -e --encrypt-key=${wrkdir}/${keydir}/rsa_pub.pem -Ec
check --decrypt-key=${wrkdir}/${keydir}/rsa_prv.pem
check2

echo; echo "#### rsa crt w/pass chacha"
archive -e --encrypt-key=${wrkdir}/${keydir}/rsa_pub.crt -Ec
check --decrypt-key=${wrkdir}/${keydir}/rsa_prv_pw.pem --pass-fd=3 3< ${wrkdir}/${keydir}/rsa.pw
check2
