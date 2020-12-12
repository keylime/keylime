#!/usr/bin/env bash

if [ -z "$(type -P pylint)" ]; then
	echo "pylint is required"
	exit 1
fi

pylint \
  --disable C0103,C0115,C0116,C0200,C0301,C0302,C0411,C0414,C0114,C0111 \
  --disable W0707,W0223,W1201,W0603,W0613,W0703,W0102 \
  --disable W1505,W0511,W0621,W0612,W0105,W0715,W0101,W0221,W0107,W1509,W0614,W0401,W0601 \
  --disable W1203 \
  --disable E0401,E1101,E1120 \
  --disable R0801,R0902,R0903,R0912,R0914,R0915,R1702,R1705,R1711,R1722,R1724,R1720,R0201,R0911 \
  --disable R1716,R0913,R1714,R0124,R0904 \
  *.py $(find ./keylime ./test -name '*.py')
exit $?
