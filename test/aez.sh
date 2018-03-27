#!/bin/zsh

source test.sh

function check2() {
  echo "${bindir}/ezio -l -L1 -O6 -o ${wrkdir}/l.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw"
  time ${bindir}/ezio -l -L1 -O6 -o ${wrkdir}/l.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw
  echo "# wc -l ${wrkdir}/l.log"
  wc -l ${wrkdir}/l.log
  echo "# egrep \"^[WEC]:\" ${wrkdir}/x.log"
  egrep "^[WEC]:" ${wrkdir}/x.log
  echo "# egrep \"^[I]:\" ${wrkdir}/l.log"
  egrep "^[I]:" ${wrkdir}/l.log
}

function check3() {
  echo "${bindir}/ezio -t -o ${wrkdir}/t.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw"
  time ${bindir}/ezio -t -o ${wrkdir}/t.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw
  echo "# wc -l ${wrkdir}/t.log"
  wc -l ${wrkdir}/t.log
  echo "# egrep \"^[WEC]:\" ${wrkdir}/t.log"
  egrep "^[WEC]:" ${wrkdir}/t.log
  echo "# egrep \"^[I]:\" ${wrkdir}/t.log"
  egrep "^[I]:" ${wrkdir}/t.log
}

function check4() {
  echo "${bindir}/ezio -t -r -o ${wrkdir}/t.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw"
  time ${bindir}/ezio -t -r -o ${wrkdir}/r.log -f ${wrkdir}/a.aez --pass-file=${wrkdir}/${keydir}/sym.pw
  echo "# egrep \"^[WEC]:\" ${wrkdir}/r.log"
  egrep "^[WEC]:" ${wrkdir}/r.log
  echo "# egrep \"^[IN]:\" ${wrkdir}/r.log"
  egrep "^[IN]:" ${wrkdir}/r.log
  ls -alp ${wrkdir}/a.aez.rep
  cmp ${wrkdir}/a.aez ${wrkdir}/a.aez.rep
}

# aez

echo; echo "#### aez"
archive -ez --pass-file=${wrkdir}/${keydir}/sym.pw
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2
check3
check4

# aezm

echo; echo "#### aezm"
archive -ezm --pass-file=${wrkdir}/${keydir}/sym.pw
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2
check3
check4

# aezr

echo; echo "#### aezr"
archive -ezr --pass-file=${wrkdir}/${keydir}/sym.pw
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2
check3
check4

# aezmr

echo; echo "#### aezmr"
archive -ezmr --pass-file=${wrkdir}/${keydir}/sym.pw
check --pass-file=${wrkdir}/${keydir}/sym.pw
check2
check3
check4
