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
KEYLIME_GIT=https://github.com/keylime/keylime.git
TPM4720_GIT=https://github.com/keylime/tpm4720-keylime.git
GOLANG_SRC=https://dl.google.com/go
TPM2TSS_GIT=https://github.com/tpm2-software/tpm2-tss.git
TPM2TOOLS_GIT=https://github.com/tpm2-software/tpm2-tools.git
TPM2SIM_SRC=http://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1119.tar.gz/download
KEYLIME_VER="master"
TPM4720_VER="master"
GOLANG_VER="1.12.4"
TPM2TSS_VER="2.0.x"
TPM2TOOLS_VER="3.X"

# Minimum version requirements
MIN_PYTHON_VERSION="3.6.7"
MIN_PYSETUPTOOLS_VERSION="0.7"
MIN_PYTORNADO_VERSION="4.3"
MIN_PYM2CRYPTO_VERSION="0.21.1"
MIN_PYZMQ_VERSION="14.4"
MIN_PYCRYPTOGRAPHY_VERSION="2.1.4"
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
if [[ -n "$(command -v dnf)" ]]; then
    PACKAGE_MGR=$(command -v dnf)
    PYTHON_PREIN="python3 python3-devel python3-setuptools git wget patch"
    PYTHON_DEPS="python3-pip gcc gcc-c++ openssl-devel swig python3-pyyaml python3-m2crypto  python3-cryptography python3-tornado python3-simplejson python3-requests yaml-cpp-devel procps-ng"
    PYTHON_PIPS="tornado pyzmq"
    BUILD_TOOLS="openssl-devel libtool make automake pkg-config m4 libgcrypt-devel autoconf autoconf-archive libcurl-devel libstdc++-devel uriparser-devel dbus-devel gnulib-devel doxygen"
elif [[ -n "$(command -v yum)" ]]; then
    PACKAGE_MGR=$(command -v yum)
    $PACKAGE_MGR -y install epel-release
    PYTHON_PREIN="python36 python36-devel python36-setuptools python36-pip git wget patch openssl"
    PYTHON_DEPS="gcc gcc-c++ openssl-devel swig python36-PyYAML python36-tornado python3-cryptography python36-simplejson python36-requests yaml-cpp-devel"
    PYTHON_PIPS="tornado pyzmq m2crypto"
    BUILD_TOOLS="openssl-devel libtool make automake m4 libgcrypt-devel autoconf autoconf-archive libcurl-devel libstdc++-devel uriparser-devel dbus-devel gnulib-devel doxygen"
elif [[ -n "$(command -v apt-get)" ]]; then
    PACKAGE_MGR=$(command -v apt-get)
    PYTHON_PREIN="git patch"
    PYTHON_DEPS="python3 python3-pip python3-dev python3-setuptools python3-zmq python3-tornado python3-cryptography python3-simplejson python3-requests gcc g++ libssl-dev swig python3-yaml wget"
    PYTHON_PIPS="m2crypto"
    BUILD_TOOLS="build-essential libtool automake pkg-config m4 libgcrypt20-dev uthash-dev autoconf autoconf-archive libcurl4-gnutls-dev gnulib doxygen libdbus-1-dev"
    $PACKAGE_MGR update
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
TPM_VERSION=1
while getopts ":shotkmp:" opt; do
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
        m) TPM_VERSION=2 ;;
        s) TPM_SOCKET=1 ;;
        h)
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-k \t\t\t\t Download Keylime (stub installer mode)'
            echo $'-o \t\t\t\t Use OpenSSL (vs. CFSSL). NOTE: OpenSSL does not support revocation'
            echo $'-t \t\t\t\t Create tarball with keylime_agent'
            echo $'-m \t\t\t\t Use modern TPM 2.0 libraries (vs. TPM 1.2)'
            echo $'-s \t\t\t\t Install TPM in socket/simulator mode (vs. chardev)'
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
if [[ $? > 0 ]] ; then
    echo "ERROR: Package(s) failed to install properly!"
    exit 1
fi
$PACKAGE_MGR install -y $PYTHON_DEPS
if [[ $? > 0 ]] ; then
    echo "ERROR: Package(s) failed to install properly!"
    exit 1
fi
pip3 install $PYTHON_PIPS


# Ensure Python is installed
if [[ ! `command -v python3` ]] ; then
    echo "ERROR: Python failed to install properly!"
    exit 1
else
    # Ensure Python installed meets min requirements
    py_ver=$(python3 -c 'import platform; print(platform.python_version())')
    if ! $(version_checker "$MIN_PYTHON_VERSION" "$py_ver"); then
        confirm_force_install "ERROR: Minimum Python version is $MIN_PYTHON_VERSION, but $py_ver is installed!" || exit 1
    fi

    # Ensure Python setuptools installed meets min requirements
    pyset_ver=$(python3 -c 'import setuptools; print(setuptools.__version__)')
    if ! $(version_checker "$MIN_PYSETUPTOOLS_VERSION" "$pyset_ver"); then
        confirm_force_install "ERROR: Minimum python-setuptools version is $MIN_PYSETUPTOOLS_VERSION, but $pyset_ver is installed!" || exit 1
    fi

    # Ensure Python tornado installed meets min requirements
    pynado_ver=$(python3 -c 'import tornado; print(tornado.version)')
    if ! $(version_checker "$MIN_PYTORNADO_VERSION" "$pynado_ver"); then
        confirm_force_install "ERROR: Minimum python-tornado version is $MIN_PYTORNADO_VERSION, but $pynado_ver is installed!" || exit 1
    fi

    # Ensure Python M2Crypto installed meets min requirements
    pym2_ver=$(python3 -c 'import M2Crypto; print(M2Crypto.version)')
    if ! $(version_checker "$MIN_PYM2CRYPTO_VERSION" "$pym2_ver"); then
        confirm_force_install "ERROR: Minimum python-M2Crypto version is $MIN_PYM2CRYPTO_VERSION, but $pym2_ver is installed!" || exit 1
    fi

    # Ensure Python ZeroMQ installed meets min requirements
    pyzmq_ver=$(python3 -c 'import zmq; print(zmq.__version__)')
    if ! $(version_checker "$MIN_PYZMQ_VERSION" "$pyzmq_ver"); then
        confirm_force_install "ERROR: Minimum python-zmq version is $MIN_PYZMQ_VERSION, but $pyzmq_ver is installed!" || exit 1
    fi

    # Ensure Python cryptography installed meets min requirements
    pycrypto_ver=$(python3 -c 'import cryptography; print(cryptography.__version__)')
    if ! $(version_checker "$MIN_PYCRYPTOGRAPHY_VERSION" "$pycrypto_ver"); then
        confirm_force_install "ERROR: Minimum python-cryptography version is $MIN_PYCRYPTOGRAPHY_VERSION, but $pycrypto_ver is installed!" || exit 1
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
if [[ "$OPENSSL" -eq "0" ]] ; then
    # Patch config file to use cfssl
    echo
    echo "=================================================================================="
    echo $'\t\t\tSwitching config to cfssl'
    echo "=================================================================================="
    cd $KEYLIME_DIR
    patch --forward --verbose -s -p1 < $KEYLIME_DIR/patches/cfsslconf-patch.txt \
        && echo "INFO: Keylime config patched!"

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
        echo "Do you want to setup a default GOPATH with the following:"
        echo " mkdir -p $HOME/go && echo 'export GOPATH=$HOME/go' >> $HOME/.bashrc && source $HOME/.bashrc"
        read -r -p "Proceed? [y/N] " resp
    	case "$resp" in
        	[yY]) mkdir -p $HOME/go && echo 'export GOPATH=$HOME/go' >> $HOME/.bashrc && source $HOME/.bashrc ;;
        	*) exit 1 ;;
    	esac
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


# Prepare to build TPM libraries
echo
echo "=================================================================================="
echo $'\t\t\tInstalling TPM libraries'
echo "=================================================================================="

# Create temp dir for building tpm
TMPDIR=`mktemp -d` || exit 1
echo "INFO: Using temp tpm directory: $TMPDIR"

$PACKAGE_MGR -y install $BUILD_TOOLS
if [[ $? > 0 ]] ; then
    echo "ERROR: Package(s) failed to install properly!"
    exit 1
fi
mkdir -p $TMPDIR/tpm
cd $TMPDIR/tpm

if [[ "$TPM_VERSION" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tBuild and install tpm4720'
    echo "=================================================================================="
    git clone $TPM4720_GIT tpm4720-keylime
    pushd tpm4720-keylime
    git checkout $TPM4720_VER

    # Install tpm4720
    pushd tpm
    make -f makefile-tpm
    install -c tpm_server /usr/local/bin/tpm_server
    popd # tpm/tpm4720-keylime
    pushd libtpm
    if [[ "$TPM_SOCKET" -eq "1" ]] ; then
        chmod +x comp-sockets.sh
        ./comp-sockets.sh
    else
        chmod +x comp-chardev.sh
        ./comp-chardev.sh
    fi
    make install
    popd # tpm/tpm4720-keylime
elif [[ "$TPM_VERSION" -eq "2" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tBuild and install tpm2-tss'
    echo "=================================================================================="
    git clone $TPM2TSS_GIT tpm2-tss
    pushd tpm2-tss
    git checkout $TPM2TSS_VER
    ./bootstrap
    ./configure --prefix=/usr
    make
    make install
    popd # tpm

    # Example installation instructions for using the tpm2-abrmd resource
    # manager for Ubuntu 18 LTS. The tools and Keylime could run without this
    # by directly communicating with the TPM (though not recommended) by setting:
    # for swtpm2 emulator:
    #   export TPM2TOOLS_TCTI="mssim:port=2321"
    # for chardev communication:
    #   export TPM2TOOLS_TCTI="device:/dev/tpm0"
    #
    # sudo useradd --system --user-group tss
    # git clone https://github.com/tpm2-software/tpm2-abrmd.git tpm2-abrmd
    # pushd tpm2-abrmd
    # ./bootstrap
    # ./configure --with-dbuspolicydir=/etc/dbus-1/system.d \
    #             --with-systemdsystemunitdir=/lib/systemd/system \
    #             --with-systemdpresetdir=/lib/systemd/system-preset \
    #             --datarootdir=/usr/share
    # make
    # sudo make install
    # sudo ldconfig
    # sudo pkill -HUP dbus-daemon
    # sudo systemctl daemon-reload
    # sudo service tpm2-abrmd start
    # export TPM2TOOLS_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
    #
    # NOTE: if using swtpm2 emulator, you need to run the tpm2-abrmd service as:
    # sudo -u tss /usr/local/sbin/tpm2-abrmd --tcti=mssim &

    echo
    echo "=================================================================================="
    echo $'\t\t\t\tBuild and install tpm2-tools'
    echo "=================================================================================="
    git clone $TPM2TOOLS_GIT tpm2-tools
    pushd tpm2-tools
    git checkout $TPM2TOOLS_VER
    ./bootstrap
    ./configure --prefix=/usr/local
    make
    make install
    popd # tpm

    if [[ "$TPM_SOCKET" -eq "1" ]] ; then
        echo
        echo "=================================================================================="
        echo $'\t\t\t\tBuild and install TPM2 simulator'
        echo "=================================================================================="

        # Download and unpack swtpm2
        TMPFILE=`mktemp -t swtpm2.XXXXXXXXXX.tar.gz` || exit 1
        wget "$TPM2SIM_SRC" -O $TMPFILE
        if [[ $? -ne 0 ]] ; then
            echo "ERROR: Failed to download TPM2 simulator!"
            exit 1
        fi
        mkdir swtpm2
        tar -C ./swtpm2 -xzf $TMPFILE
        pushd swtpm2

        # Copy over necessary files
        mkdir scripts
        cp $KEYLIME_DIR/swtpm2_scripts/* scripts/

        # Begin building and installing swtpm2
        pushd src
        make
        install -c tpm_server /usr/local/bin/tpm_server

        popd # tpm/swtpm2
    fi
else
    echo "ERROR: Invalid TPM version chosen: '$TPM_VERSION'"
    exit 1
fi
if [[ "$TPM_SOCKET" -eq "1" ]] ; then
    pushd scripts

    # Ensure everything is executable
    chmod +x init_tpm_server
    chmod +x tpm_serverd

    # Install scripts
    install -c tpm_serverd /usr/local/bin/tpm_serverd
    install -c init_tpm_server /usr/local/bin/init_tpm_server

    # Clear TPM on first use
    init_tpm_server

    # Start tpm4720
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tStart TPM emulator'
    echo "=================================================================================="
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
python3 setup.py install

if [[ -f "/etc/keylime.conf" ]] ; then
    if [[ $(diff -N "/etc/keylime.conf" "keylime.conf") ]] ; then
        echo "Modified keylime.conf found in /etc/, creating /etc/keylime.conf.new instead"
        cp keylime.conf /etc/keylime.conf.new
    fi
else
    echo "Installing keylime.conf to /etc/"
    cp -n keylime.conf /etc/
fi

# Run agent packager (tarball)
if [[ "$TARBALL" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tGenerate agent tarball'
    echo "=================================================================================="
    cd $KEYLIME_DIR/keylime
    TAR_BUNDLE_FLAGS=""
    if [[ "$TPM_VERSION" -eq "2" ]] ; then
        TAR_BUNDLE_FLAGS="-m"
    fi
    ./make_agent_bundle_tarball.sh $TAR_BUNDLE_FLAGS
fi

