#!/usr/bin/env bash

if [ -z "$(type -P pylint)" ]; then
	echo "pylint is required"
	exit 1
fi

pylint \
  --disable C0200,C0411,W0707,W0223,W0613,W1509 \
  --disable C0103,C0115,C0116,C0301,C0302,C0111 \
  --disable W0102,W0511,W0603,W0703,W1201,W1203 \
  --disable E0401,E1101,E1120 \
  --disable R0801,R0902,R0903,R0904,R0912,R0913,R0914,R0915,R0201,R0911 \
  *.py $(find ./keylime ./test -name '*.py' ! -name 'oldtest.py')
exit $?
