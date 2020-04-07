#!/bin/bash

KEYLIME_HOME=/root/keylime

# Run tests
cd ${KEYLIME_HOME}/test
chmod +x ./run_tests.sh
./run_tests.sh -s openssl
