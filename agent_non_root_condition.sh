#!/bin/sh

KEYLIME_GROUP=${KEYLIME_GROUP:-tss}
KEYLIME_USER=${KEYLIME_USER:-keylime}

# creating group if it isn't already there
if ! getent group $KEYLIME_GROUP >/dev/null; then
    addgroup --system $KEYLIME_GROUP
fi

# creating keylime user if he isn't already there
if ! getent passwd keylime >/dev/null; then
    adduser --system --ingroup $KEYLIME_GROUP --shell /bin/false \
    --home /var/lib/keylime --no-create-home \
    --gecos "Keylime remote attestation" \
    $KEYLIME_USER
fi

# Create keylime operational directory
if [ ! -d /var/lib/keylime ]; then
    mkdir -p /var/lib/keylime/secure
fi

# Only root can mount tmpfs with `-o`
if ! grep -qs '/var/lib/keylime/secure ' /proc/mounts ; then
    mount -t tmpfs -o size=1m,mode=0700 tmpfs /var/lib/keylime/secure
fi

# Setting ownership for keylime operational directory
if [ -d /var/lib/keylime ] && getent passwd $KEYLIME_USER >/dev/null; then
    chown -R $KEYLIME_USER:$KEYLIME_GROUP /var/lib/keylime
fi

# Setting ownership for /sys/kernel/security/<x>, giving keylime agent access to it
chown -R $KEYLIME_USER:$KEYLIME_GROUP /sys/kernel/security/tpm0
chown -R $KEYLIME_USER:$KEYLIME_GROUP /sys/kernel/security/ima
