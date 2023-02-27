#!/bin/bash
set -x

# Configure swtpm2
mkdir /tmp/tpmdir
swtpm_setup --tpm2 \
     --tpmstate /tmp/tpmdir \
     --createek --decryption --create-ek-cert \
     --create-platform-cert \
     --display
swtpm socket --tpm2 \
     --tpmstate dir=/tmp/tpmdir \
     --flags startup-clear \
     --ctrl type=tcp,port=2322 \
     --server type=tcp,port=2321 \
     --daemon
export TPM2TOOLS_TCTI=tabrmd:
export TCTI=tabrmd:

# Configure dbus
sudo rm -rf /var/run/dbus
sudo mkdir /var/run/dbus
sudo dbus-daemon --system

tpm2-abrmd \
    --logger=stdout \
    --tcti=swtpm: \
    --flush-all \
    --allow-root &

# Create test user
useradd -s /sbin/nologin -g tss keylime

# Run tests
if [ "$GITHUB_ACTIONS" == "true" ]
then
    REPO_DIR=$GITHUB_WORKSPACE
else
    REPO_DIR="/root/keylime"
fi

# Move /etc/keylime.conf because there might a old one distributed with the container.
if [ -f "/etc/keylime.conf" ]
then
    echo "Moving /etc/keylime.conf from the container to /etc/keylime.conf.orig"
    mv /etc/keylime.conf /etc/keylime.conf.orig
fi

# Move configuration files that might be distributed with the container.
for c in agent verifier registrar tenant ca logging
do
    if [ -f "/etc/keylime/$c.conf" ]
    then
        echo "Moving /etc/keylime/$c.conf from the container to /etc/keylime/$c.conf.orig"
        mv /etc/keylime/$c.conf /etc/keylime/$c.conf.orig
    fi
done

chmod +x $REPO_DIR/test/run_tests.sh
$REPO_DIR/test/run_tests.sh
