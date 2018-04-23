#!/bin/bash

# this is just for testing behind a proxy.  should ignore otherwise
[ -f /etc/proxy ] && source /etc/proxy

if [[ -n "$(command -v yum)" ]]; then
		echo "ERROR: this script does not currently work with RH/Centos distros" 1>&2;
		exit 1
elif [[ -n "$(command -v apt-get)" ]]; then
	apt-get update
	apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" racoon ipsec-tools 
else
   echo "ERROR: No recognized package manager found on this system!" 1>&2
   exit 1
fi

# install needed packages:

# enable ipsec
cp ipsec-tools.conf /etc/

# configure racoon
cp racoon.conf /etc/racoon/

# make wierd crl file name
ln -s cacrl.pem `openssl x509 -hash -noout -in cacert.crt`.r0

# make consistent names for key files:
ln -s `ls *-cert.crt | grep -v Revocation` mycert.crt
ln -s `ls *-private.pem` mykey.pem

ip xfrm state flush
service setkey restart
service racoon restart

echo "========== AUTOMATIC IPSEC CONFIGURATION COMPLETE =========="