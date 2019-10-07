#!/bin/bash

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
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" $BASEDIR/keylime_agent.service.template > /etc/systemd/system/keylime_agent.service
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" $BASEDIR/keylime_registrar.service.template > /etc/systemd/system/keylime_registrar.service
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" $BASEDIR/keylime_verifier.service.template > /etc/systemd/system/keylime_verifier.service

# set permissions
chmod 664 /etc/systemd/system/keylime_agent.service
chmod 664 /etc/systemd/system/keylime_registrar.service
chmod 664 /etc/systemd/system/keylime_verifier.service

# enable at startup
systemctl enable keylime_agent.service
systemctl enable keylime_registrar.service
systemctl enable keylime_verifier.service

