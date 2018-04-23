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
KEYLIME_GIT=https://github.com/mit-ll/python-keylime.git
TPM4720_GIT=https://github.com/mit-ll/tpm4720-keylime.git
GOLANG_SRC=https://dl.google.com/go
KEYLIME_VER="master"
TPM4720_VER="master"
GOLANG_VER="1.10"

# Minimum version requirements 
MIN_PYTHON_VERSION="2.7.10"
MIN_PYSETUPTOOLS_VERSION="0.7"
MIN_PYTORNADO_VERSION="4.3"
MIN_PYM2CRYPTO_VERSION="0.21.1"
MIN_PYZMQ_VERSION="14.4"
MIN_PYCRYPTODOMEX_VERSION="3.4.1"
MIN_GO_VERSION="1.8.4"


# Check to ensure version is at least minversion 
version_checker () {
    newest=$( printf "$1\n$2" | sort -V | tail -n1 )
    [[ "$1" == "$2" || "$1" != "$newest" ]]
}

confirm_force_install () {
    echo $1
    read -r -p "This may introduce security issues, instability or an incomplete install!  Continue? [y/N] " resp
    case "$resp" in
        [yY]) return 0 ;;
        *) return 1 ;;
    esac
}


# Which package management system are we using? 
if [[ -n "$(command -v yum)" ]]; then
    PACKAGE_MGR=$(command -v yum)
    PYTHON_PREIN="epel-release git wget"
    PYTHON_DEPS="python python-pip python-devel python-setuptools python-zmq gcc openssl-devel"
    PYTHON_PIPS="pycryptodomex m2crypto tornado"
    BUILD_TOOLS="openssl-devel libtool gcc automake gcc-c++"
elif [[ -n "$(command -v apt-get)" ]]; then
    PACKAGE_MGR=$(command -v apt-get)
    PYTHON_PREIN="git"
    PYTHON_DEPS="python python-pip python-dev python-setuptools python-m2crypto python-zmq"
    PYTHON_PIPS="pycryptodomex tornado"
    BUILD_TOOLS="build-essential libssl-dev libtool automake"
else
   echo "No recognized package manager found on this system!" 1>&2
   exit 1
fi


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
   echo -e "This script must be run as root in order to install keylime and its dependencies" 1>&2
   exit 1
fi


# Keylime python-related dependencies
echo 
echo "=================================================================================="
echo $'\t\t\tInstalling python & crypto libs'
echo "=================================================================================="
$PACKAGE_MGR install -y $PYTHON_PREIN
$PACKAGE_MGR install -y $PYTHON_DEPS
pip install $PYTHON_PIPS


# Ensure Python is installed 
if [[ ! `command -v python` ]] ; then
    echo "ERROR: Python failed to install properly!"
    exit 1
else 
    # Ensure Python installed meets min requirements 
    py_ver=$(python -c 'import platform; print platform.python_version()')
    if ! $(version_checker "$MIN_PYTHON_VERSION" "$py_ver"); then
        confirm_force_install "ERROR: Minimum Python version is $MIN_PYTHON_VERSION, but $py_ver is installed!" || exit 1
    fi
    
    # Ensure Python setuptools installed meets min requirements 
    pyset_ver=$(python -c 'import setuptools; print setuptools.__version__')
    if ! $(version_checker "$MIN_PYSETUPTOOLS_VERSION" "$pyset_ver"); then
        confirm_force_install "ERROR: Minimum python-setuptools version is $MIN_PYSETUPTOOLS_VERSION, but $pyset_ver is installed!" || exit 1
    fi
    
    # Ensure Python tornado installed meets min requirements 
    pynado_ver=$(python -c 'import tornado; print tornado.version')
    if ! $(version_checker "$MIN_PYTORNADO_VERSION" "$pynado_ver"); then
        confirm_force_install "ERROR: Minimum python-tornado version is $MIN_PYTORNADO_VERSION, but $pynado_ver is installed!" || exit 1
    fi
    
    # Ensure Python M2Crypto installed meets min requirements 
    pym2_ver=$(python -c 'import M2Crypto; print M2Crypto.version')
    if ! $(version_checker "$MIN_PYM2CRYPTO_VERSION" "$pym2_ver"); then
        confirm_force_install "ERROR: Minimum python-M2Crypto version is $MIN_PYM2CRYPTO_VERSION, but $pym2_ver is installed!" || exit 1
    fi
    
    # Ensure Python ZeroMQ installed meets min requirements 
    pyzmq_ver=$(python -c 'import zmq; print zmq.__version__')
    if ! $(version_checker "$MIN_PYZMQ_VERSION" "$pyzmq_ver"); then
        confirm_force_install "ERROR: Minimum python-zmq version is $MIN_PYZMQ_VERSION, but $pyzmq_ver is installed!" || exit 1
    fi
    
    # Ensure Python pycryptodomex installed meets min requirements 
    pycdom_ver=$(pip freeze | grep pycryptodomex | cut -d"=" -f3)
    if ! $(version_checker "$MIN_PYCRYPTODOMEX_VERSION" "$pycdom_ver"); then
        confirm_force_install "ERROR: Minimum python-pycryptodomex version is $MIN_PYM2CRYPTO_VERSION, but $pycdom_ver is installed!" || exit 1
    fi
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
    git clone $KEYLIME_GIT $KEYLIME_DIR
    pushd $KEYLIME_DIR
    git checkout $KEYLIME_VER
    popd
fi


# If all else fails, assume they already have Keylime (we're in it!)
if [[ -z "$KEYLIME_DIR" ]] ; then
    KEYLIME_DIR=`pwd`
fi


# Sanity check 
if [[ ! -d "$KEYLIME_DIR/scripts" || ! -d "$KEYLIME_DIR/keylime" ]] ; then
    echo "ERROR: Invalid keylime directory at $KEYLIME_DIR"
    exit 1
fi


echo "INFO: Using Keylime directory: $KEYLIME_DIR"


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
    # Pull in correct PATH under sudo (mainly for secure_path)
    if [[ -r "/etc/profile.d/go.sh" ]]; then
        source "/etc/profile.d/go.sh"
    fi
    
    if [[ ! `command -v go` ]] ; then
        # Install golang (if not already)
        echo 
        echo "=================================================================================="
        echo $'\t\t\tInstalling golang (for cfssl)'
        echo "=================================================================================="
        
        # Where should golang's root be?
        # NOTE: If this is changed, golang requires GOROOT to be set!
        GO_INSTALL_TARGET="/usr/local"
        
        # Don't risk clobbering anything if there are traces of golang already on the system
        if [[ -d "$GO_INSTALL_TARGET/go" ]] ; then
            # They have an install (just not on PATH?)
            echo "The '$GO_INSTALL_TARGET/go' directory already exists.  Aborting installation attempt."
            exit 1
        fi
        
        # Figure out which version of golang to download
        PLATFORM_STR=$( uname -s )-$( uname -m )
        case "$PLATFORM_STR" in
            Linux-x86_64) GOFILE_STR="go$GOLANG_VER.linux-amd64.tar.gz" ;;
            Linux-i686) GOFILE_STR="go$GOLANG_VER.linux-386.tar.gz" ;;
            Linux-i386) GOFILE_STR="go$GOLANG_VER.linux-386.tar.gz" ;;
            Darwin-x86_64) GOFILE_STR="go$GOLANG_VER.darwin-amd64.tar.gz" ;;
            *)
                echo "ERROR: Cannot install golang for your platform ($PLATFORM_STR)!"
                echo "Please manually install golang $MIN_GO_VERSION or higher."
                exit 1
                ;;
        esac
        
        # Download and unpack/install golang
        TMPFILE=`mktemp -t go.XXXXXXXXXX.tar.gz` || exit 1
        wget "$GOLANG_SRC/$GOFILE_STR" -O $TMPFILE
        if [[ $? -ne 0 ]] ; then
            echo "ERROR: Failed to download golang!"
            exit 1
        fi
        tar -C "$GO_INSTALL_TARGET" -xzf $TMPFILE
        
        # Set up working directory and env vars (+persistence)
        mkdir -p $HOME/go
        export GOPATH=$HOME/go
        export PATH=$PATH:$GO_INSTALL_TARGET/go/bin:$GOPATH/bin:/usr/local/bin
        {
            echo $'\n# Golang-related settings'
            echo 'export GOPATH=$HOME/go'
            echo "export PATH=\$PATH:$GO_INSTALL_TARGET/go/bin:\$GOPATH/bin:/usr/local/bin"
        } >> "$HOME/.bashrc"
        if [[ -d "/etc/profile.d" ]]; then
            {
                echo $'\n# Golang-related settings'
                echo "export PATH=\$PATH:$GO_INSTALL_TARGET/go/bin:/usr/local/bin"
            } >> "/etc/profile.d/go.sh"
        fi
    fi
    
    if [[ -z "$GOPATH" ]] ; then
        # GOPATH is not set up correctly
        echo "ERROR: GOPATH is not set up correctly!  This is required for cfssl."
        exit 1
    fi
    
    # Ensure Go installed meets min requirements 
    go_ver=$(go version | cut -d" " -f3 | sed "s/go//")
    if ! $(version_checker "$MIN_GO_VERSION" "$go_ver"); then
        confirm_force_install "ERROR: Minimum Go version is $MIN_GO_VERSION, but $go_ver is installed!" || exit 1
    fi
    
    if [[ ! `command -v cfssl` ]] ; then
        # Install cfssl (if not already) 
        echo 
        echo "=================================================================================="
        echo $'\t\t\t\tInstalling cfssl'
        echo "=================================================================================="
        go get -v -u github.com/cloudflare/cfssl/cmd/cfssl
        if [[ $? -ne 0 ]] ; then
            echo "ERROR: Failed to install cfssl!"
            exit 1
        fi
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

$PACKAGE_MGR -y install $BUILD_TOOLS
mkdir -p $TMPDIR/tpm4720
cd $TMPDIR/tpm4720
git clone $TPM4720_GIT tpm4720-keylime
cd $TMPDIR/tpm4720/tpm4720-keylime
git checkout $TPM4720_VER
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
    
    # clear TPM on first use
    init_tpm_server 
    
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
    service tpm_emulator restart
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


