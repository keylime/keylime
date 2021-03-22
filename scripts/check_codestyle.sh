#!/usr/bin/env bash

for PYLINT in pylint pylint-3; do
	if [ -n "$(type -P ${PYLINT})" ]; then
		break
	fi
done

if [ -z "$(type -P ${PYLINT})" ]; then
	echo "pylint or pylint-3 is required"
	exit 1
fi

${PYLINT} --version

${PYLINT} \
  --jobs=0 \
  --ignored-modules=zmq,alembic.op,alembic.context,M2Crypto.m2,_cLime,Cryptodome,pylab,matplotlib,numpy \
  --disable W1509 \
  --disable C0103,C0115,C0116,C0301,C0302,C0111 \
  --disable W0102,W0511,W0603,W0703,W1201,W1203 \
  --disable E1120 \
  --disable R0801,R0902,R0903,R0904,R0912,R0913,R0914,R0915,R0201,R0911,R1729 \
  *.py $(find ./keylime ./test -name '*.py' ! -name 'oldtest.py')
exit $?
