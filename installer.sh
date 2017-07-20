#!/bin/bash
##########################################################################################
#
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for 
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in 
# this material are those of the author(s) and do not necessarily reflect the views of the 
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2017 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
# above. Use of this work other than as specifically authorized by the U.S. Government may 
# violate any copyrights that exist in this work.
#
##########################################################################################

# Configure the installer here
KEYLIME_GIT=https://llcad-github.llan.ll.mit.edu/LLSRC/LLSRC-tci.git
TPM4720_GIT=https://github.com/mit-ll/tpm4720-keylime.git

# Which extra python packages must be installed? 
PYTHON_DEPS="python-dev python-setuptools python-tornado python-m2crypto python-zmq"


# Command line params 
STUB=0
KEYLIME_DIR=
OPENSSL=0
TARBALL=0
TPM_SOCKET=0
while getopts ":shortkp:" opt; do
    case $opt in
        k) STUB=1 ;;
        p) 
            KEYLIME_DIR=$OPTARG
            # Ensure absolute path
            if [[ "$KEYLIME_DIR" != "/"* ]] ; then
                KEYLIME_DIR=`pwd`"/$KEYLIME_DIR"
            fi
            ;;
        o) OPENSSL=1 ;;
        t) TARBALL=1 ;;
        s) TPM_SOCKET=1 ;;
        h) 
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-k \t\t\t\t Download Keylime (stub installer mode)'
            echo $'-o \t\t\t\t Use OpenSSL instead of CFSSL'
            echo $'-t \t\t\t\t Create tarball with keylime_node'
            echo $'-s \t\t\t\t Install TPM 4720 in socket mode (vs. chardev)'
            echo $'-p PATH \t\t\t Use PATH as Keylime path'
            echo $'-h \t\t\t\t This help info'
            exit
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to call apt-get and install python dependencies" 1>&2
   exit 1
fi

# Download Keylime (if necessary) 
if [[ "$STUB" -eq "1" ]] ; then
    if [[ -z "$KEYLIME_DIR" ]] ; then
        KEYLIME_DIR=`pwd`
        KEYLIME_DIR+="/keylime"
        if [[ ! -d "$KEYLIME_DIR" ]] ; then
            mkdir -p $KEYLIME_DIR
        fi
    fi
    
    echo 
    echo "=================================================================================="
    echo $'\t\t\t\tDownloading Keylime'
    echo "=================================================================================="
    apt-get install -y git
    git clone $KEYLIME_GIT $KEYLIME_DIR
fi


# If all else fails, assume they already have Keylime (we're in it!)
if [[ -z "$KEYLIME_DIR" ]] ; then
    KEYLIME_DIR=`pwd`
fi


# Sanity check 
if [[ ! -d "$KEYLIME_DIR/scripts" || ! -d "$KEYLIME_DIR/keylime" ]] ; then
    echo "ERROR: Invalid keylime directory at $KEYLIME_DIR"
    exit
fi


echo "INFO: Using Keylime directory: $KEYLIME_DIR"


# Ensure everything is latest 
echo 
echo "=================================================================================="
echo $'\t\t\t\tUpdating apt-get'
echo "=================================================================================="
apt-get update


# Keylime python-related dependencies
echo 
echo "=================================================================================="
echo $'\t\t\tInstalling python & crypto libs'
echo "=================================================================================="
apt-get install -y python python-pip
pip install pycryptodomex 
apt-get install -y $PYTHON_DEPS


# OpenSSL or cfssl? 
if [[ "$OPENSSL" -eq "1" ]] ; then
    # Patch config file to use openssl
    echo 
    echo "=================================================================================="
    echo $'\t\t\tSwitching config to OpenSSL'
    echo "=================================================================================="
    cd $KEYLIME_DIR
    patch --forward --verbose -s -p1 < $KEYLIME_DIR/patches/opensslconf-patch.txt \
        && echo "INFO: Keylime config patched!"
else
    if [[ -z "$GOPATH" ]] ; then
        # Install golang (if not already)
        echo 
        echo "=================================================================================="
        echo $'\t\t\tInstalling golang (for cfssl)'
        echo "=================================================================================="
        apt-get install -y golang git
        mkdir -p $HOME/.go
        export GOPATH=$HOME/.go
        export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
        echo "export GOPATH=~/.go" >> $HOME/.bashrc
        echo "export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin" >> $HOME/.bashrc
    fi
    
    if [[ ! `command -v cfssl` ]] ; then
        # Install cfssl (if not already) 
        echo 
        echo "=================================================================================="
        echo $'\t\t\t\tInstalling cfssl'
        echo "=================================================================================="
        # Go is stupid with ENV vars, so we have to spawn a child shell 
        bash -c 'go get -v -u github.com/cloudflare/cfssl/cmd/cfssl'
        install -c $GOPATH/bin/cfssl /usr/local/bin/cfssl
    fi
fi


# Build tpm4720
echo 
echo "=================================================================================="
echo $'\t\t\t\tBuild and install tpm4720'
echo "=================================================================================="
# Create temp dir for building tpm 
TMPDIR=`mktemp -d` || exit 1
echo -n "INFO: Using temp tpm directory: "
echo $TMPDIR

apt-get -y install build-essential libssl-dev libtool automake
mkdir -p $TMPDIR/tpm4720
cd $TMPDIR/tpm4720
git clone $TPM4720_GIT
cd $TMPDIR/tpm4720/tpm4720-keylime
# Install tpm4720
cd tpm
make -f makefile-tpm
install -c tpm_server /usr/local/bin/tpm_server
cd ../libtpm
if [[ "$TPM_SOCKET" -eq "1" ]] ; then
	chmod +x comp-sockets.sh
	./comp-sockets.sh
else 
	chmod +x comp-chardev.sh
	./comp-chardev.sh
fi
make install

if [[ "$TPM_SOCKET" -eq "1" ]] ; then
	cd ../scripts
	install -c tpm_serverd /usr/local/bin/tpm_serverd
	install -c init_tpm_server /usr/local/bin/init_tpm_server
	
	# Start tpm4720
	echo 
	echo "=================================================================================="
	echo $'\t\t\t\tStart tpm4720'
	echo "=================================================================================="
	chmod +x init_tpm_server
	chmod +x tpm_serverd
	# starts emulator and IMA stub at boot
	cd $KEYLIME_DIR/ima_stub_service
	./installer.sh
fi

# Install keylime
echo 
echo "=================================================================================="
echo $'\t\t\t\tInstall Keylime'
echo "=================================================================================="
cd $KEYLIME_DIR
python setup.py install

if [ -f /etc/keylime.conf ] ; then
	if ! cmp -s /etc/keylime.conf keylime.conf ; then
		echo "Modified keylime.conf found in /etc/, creating /etc/keylime.conf.new instead"
		cp keylime.conf /etc/keylime.conf.new
	fi
else
	echo "Installing keylime.conf to /etc/"
	cp -n keylime.conf /etc/
fi

# Run node packager (tarball)
if [[ "$TARBALL" -eq "1" ]] ; then
    echo 
    echo "=================================================================================="
    echo $'\t\t\t\tGenerate node tarball'
    echo "=================================================================================="
    cd $KEYLIME_DIR/keylime
    ./make_node_bundle_tarball.sh
fi


