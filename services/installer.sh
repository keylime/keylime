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
KEYLIMEDIR=$(dirname "$(whereis keylime_verifier | cut -d " " -f 2)")
if [[ $KEYLIMEDIR == "." ]]; then
    echo "Unable to find keylime scripts" 1>&2
    exit 1
fi

echo "Using keylime scripts directory: ${KEYLIMEDIR}"

# prepare keylime service files and store them in systemd path
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" "$BASEDIR/keylime_registrar.service.template" > /etc/systemd/system/keylime_registrar.service
sed "s|KEYLIMEDIR|$KEYLIMEDIR|g" "$BASEDIR/keylime_verifier.service.template" > /etc/systemd/system/keylime_verifier.service

echo "Creating keylime user if it not exists"
if ! getent passwd keylime >/dev/null; then
    adduser --system --shell /bin/false \
            --home /var/lib/keylime --no-create-home \
            keylime
fi

# install TPM certificate store to /usr/share/keylime/
# tmpfiles.d will copy this to /var/lib/keylime/tpm_cert_store
TPM_CERT_STORE_SRC="$BASEDIR/../tpm_cert_store"
if [[ ! -d "$TPM_CERT_STORE_SRC" ]]; then
    echo "Missing TPM certificate store: $TPM_CERT_STORE_SRC" 1>&2
    exit 1
fi

mkdir -p /usr/share/keylime
cp -a "$TPM_CERT_STORE_SRC" /usr/share/keylime/ || exit 1

# install tmpfiles.d config for keylime directories
mkdir -p /usr/lib/tmpfiles.d
cp "$BASEDIR/keylime-tmpfiles.conf" /usr/lib/tmpfiles.d/keylime.conf

# apply the tmpfiles.d config immediately to create directories with correct ownership
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create keylime.conf
else
    echo "Warning: systemd-tmpfiles not found, creating directories manually"
    # Create essential directories as fallback for non-systemd systems
    mkdir -p /var/run/keylime /var/lib/keylime \
        /etc/keylime/ca.conf.d \
        /etc/keylime/logging.conf.d \
        /etc/keylime/verifier.conf.d \
        /etc/keylime/registrar.conf.d \
        /etc/keylime/tenant.conf.d \
        /etc/keylime/agent.conf.d
    chown keylime:keylime /var/run/keylime /var/lib/keylime
    chmod 700 /var/run/keylime /var/lib/keylime
    # Mirror tmpfiles.d Z/z semantics: recursively set ownership and
    # file permissions under /etc/keylime, then fix directories to 0500.
    chown -R keylime:keylime /etc/keylime
    find /etc/keylime -type f -exec chmod 400 {} \;
    find /etc/keylime -type d -exec chmod 500 {} \;
    # Copy TPM cert store from /usr/share to /var/lib only if the
    # target does not exist yet (mirrors the tmpfiles.d C directive).
    # This preserves operator-added EK certificates.
    if [ -d /usr/share/keylime/tpm_cert_store ] && [ ! -d /var/lib/keylime/tpm_cert_store ]; then
        cp -r /usr/share/keylime/tpm_cert_store /var/lib/keylime/
        chown -R keylime:keylime /var/lib/keylime/tpm_cert_store
        find /var/lib/keylime/tpm_cert_store -type f -exec chmod 400 {} \;
        chmod 500 /var/lib/keylime/tpm_cert_store
    fi
fi

# set permissions
chmod 664 /etc/systemd/system/keylime_registrar.service
chmod 664 /etc/systemd/system/keylime_verifier.service

# enable at startup
systemctl enable keylime_registrar.service
systemctl enable keylime_verifier.service
