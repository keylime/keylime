#!/bin/bash

# this is just for testing behind a proxy.  should ignore otherwise
[ -f /etc/proxy ] && source /etc/proxy

if [[ -n "$(command -v yum)" ]]; then
	yum -y install audit-libs-devel bison curl-devel fipscheck-devel flex \
		gcc ldns-devel libcap-ng-devel libevent-devel \
		libseccomp-devel libselinux-devel make nspr-devel nss-devel \
		pam-devel pkgconfig systemd-devel unbound-devel xmlto
elif [[ -n "$(command -v apt-get)" ]]; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get -yq install libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
		libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison gcc make libnss3-tools \
		libevent-dev ppp xl2tpd libsystemd-dev wget
else
   echo "ERROR: No recognized package manager found on this system!" 1>&2
   exit 1
fi

# thanks to https://github.com/hwdsl2/setup-ipsec-vpn/blob/master/vpnsetup.sh
LIBRESWAN_VERSION=3.23

wget -O - https://download.libreswan.org/libreswan-$LIBRESWAN_VERSION.tar.gz > /tmp/libreswan-$LIBRESWAN_VERSION.tar.gz
/bin/rm -rf /tmp/libreswan-$LIBRESWAN_VERSION
tar -xzf /tmp/libreswan-$LIBRESWAN_VERSION.tar.gz -C /tmp/
sed -i '/docker-targets\.mk/d' /tmp/libreswan-$LIBRESWAN_VERSION/Makefile
cat > /tmp/libreswan-$LIBRESWAN_VERSION/Makefile.inc.local <<'EOF'
WERROR_CFLAGS =
USE_DNSSEC = false
EOF
make -C /tmp/libreswan-$LIBRESWAN_VERSION/ -s base

# clear out any old ipsec data in /etc before installing
rm -rf /etc/ipsec.*
make -C /tmp/libreswan-$LIBRESWAN_VERSION/ -s install-base
rm -rf /tmp/libreswan-$LIBRESWAN_VERSION*

# now it's installed, configure it

rm -f /etc/ipsec.d/*db

ipsec initnss

# make consistent names for key files:
ln -sf `ls *-cert.crt | grep -v Revocation` mycert.crt
ln -sf `ls *-private.pem` mykey.pem

openssl pkcs12 -export -in mycert.crt -inkey mykey.pem -out mykey.p12 -name mykey -CAfile cacert.crt -certfile cacert.crt -passout pass:
pk12util -i mykey.p12 -d sql:/etc/ipsec.d -W ""
crlutil -I -i cacrl.der  -d sql:/etc/ipsec.d/

cp -f ipsec.conf /etc/
cp -f private clear /etc/ipsec.d/policies
cp -f oe-keylime.conf /etc/ipsec.d

systemctl enable ipsec
systemctl start ipsec

echo "========== AUTOMATIC IPSEC CONFIGURATION COMPLETE =========="