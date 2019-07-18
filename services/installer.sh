#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

BASEDIR=$(dirname "$0")

# create services
cp $BASEDIR/keylime_agent.service /etc/systemd/system
cp $BASEDIR/keylime_registrar.service /etc/systemd/system
cp $BASEDIR/keylime_verifier.service /etc/systemd/system

# set permissions
chmod 664 /etc/systemd/system/keylime_agent.service
chmod 664 /etc/systemd/system/keylime_registrar.service
chmod 664 /etc/systemd/system/keylime_verifier.service

# enable at startup
systemctl enable keylime_agent.service
systemctl enable keylime_registrar.service
systemctl enable keylime_verifier.service

