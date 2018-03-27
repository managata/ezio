#!/bin/zsh

bindir=/tmp/test
wrkdir=/tmp/test
keydir=key
extdir=d

src=/usr
#src=/usr/share
#src=/usr/share/X11


function archive() {
  /bin/rm -rf ${wrkdir}/{a.log,a.aez,x.log,l.log,t.log,r.log,a.aez.rep} ${wrkdir}/${extdir}

  echo "# ${bindir}/ezio -a -o ${wrkdir}/a.log -f ${wrkdir}/a.aez $* ${src}"
  time ${bindir}/ezio -a -o ${wrkdir}/a.log -f ${wrkdir}/a.aez ${src} $*
  /bin/ls -alp ${wrkdir}/a.aez
  echo "egrep \"^.:\" ${wrkdir}/a.log"
  egrep "^.:" ${wrkdir}/a.log
}

function check() {
  echo "# ${bindir}/ezio -x -o ${wrkdir}/x.log -f ${wrkdir}/a.aez -d ${wrkdir}/${extdir} $*"
  time ${bindir}/ezio -x -o ${wrkdir}/x.log -f ${wrkdir}/a.aez -d ${wrkdir}/${extdir} $*
  echo "# egrep \"^[WEC]:\" ${wrkdir}/x.log"
  egrep "^[WEC]:" ${wrkdir}/x.log
  echo "# rsync -acvn ${src}/ ${wrkdir}/${extdir}/${src}/"
  rsync -acvn ${src}/ ${wrkdir}/${extdir}/${src}/
}
