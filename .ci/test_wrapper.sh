#!/bin/bash
set -x

# Configure swtpm2
mkdir /tmp/tpmdir
swtpm_setup --tpm2 \
     --tpmstate /tmp/tpmdir \
     --createek --allow-signing --decryption --create-ek-cert \
     --create-platform-cert \
     --display
swtpm socket --tpm2 \
     --tpmstate dir=/tmp/tpmdir \
     --flags startup-clear \
     --ctrl type=tcp,port=2322 \
     --server type=tcp,port=2321 \
     --daemon
export TPM2TOOLS_TCTI=swtpm:

# Run tests
chmod +x ./run_tests.sh
./run_tests.sh -s openssl
