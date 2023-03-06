#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
################################################################################

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

BASEDIR=$(dirname "$0")

# check keylime scripts directory (same for verifier, agent, registrar)
KEYLIMEDIR=$(dirname $(whereis keylime_verifier | cut -d " " -f 2))
if [[ $KEYLIMEDIR == "." ]]; then
    echo "Unable to find keylime scripts" 1>&2
    exit 1
fi

echo "Using keylime scripts directory: ${KEYLIMEDIR}"

# prepare keylime service files and store them in systemd path
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" $BASEDIR/keylime_registrar.service.template > /etc/systemd/system/keylime_registrar.service
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" $BASEDIR/keylime_verifier.service.template > /etc/systemd/system/keylime_verifier.service

echo "Creating keylime user if it not exists"
if ! getent passwd keylime >/dev/null; then
    adduser --system --shell /bin/false \
            --home /var/lib/keylime --no-create-home \
            keylime
fi

echo "Changing files to be owned by the keylime user"
# Create all directories required if not there
mkdir -p /var/lib/keylime
mkdir -p /var/log/keylime
mkdir -p /var/run/keylime

chown keylime:keylime -R /etc/keylime
chown keylime:keylime -R /var/lib/keylime
chown keylime:keylime -R /var/log/keylime
chown keylime:keylime -R /var/run/keylime

# set permissions
chmod 664 /etc/systemd/system/keylime_registrar.service
chmod 664 /etc/systemd/system/keylime_verifier.service

chmod 700 /var/run/keylime

# enable at startup
systemctl enable keylime_registrar.service
systemctl enable keylime_verifier.service
