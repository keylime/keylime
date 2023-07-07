#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

# Configure the installer here
HTML_DIR=/var/www/html/
TGRUB_GIT=https://github.com/Rohde-Schwarz-Cybersecurity/TrustedGRUB2.git


# Command line params
KEYLIME_DIR=
NOPASSWD=
NOPASSWD_USR=
IMA_ENABLE=
WEBSERVER=
TRUSTED_GRUB=
TRUSTED_GRUB_DIR=/dev/sda
CONFIRM=1
while getopts ":yniwthfp:N:T:" opt; do
    case $opt in
        p)
            KEYLIME_DIR=$OPTARG
            # Ensure absolute path
            if [[ "$KEYLIME_DIR" != "/"* ]] ; then
                KEYLIME_DIR=`pwd`"/$KEYLIME_DIR"
            fi
            ;;
        n)
            NOPASSWD=1
            NOPASSWD_USR=$SUDO_USER
            ;;
        N)
            NOPASSWD=1
            NOPASSWD_USR=$OPTARG
            ;;
        i)  IMA_ENABLE=1 ;;
        w)  WEBSERVER=1 ;;
        t)  TRUSTED_GRUB=1 ;;
        T)
            TRUSTED_GRUB=1
            TRUSTED_GRUB_DIR=$OPTARG
            ;;
        f)
            WEBSERVER=1
            IMA_ENABLE=1
            NOPASSWD=1
            NOPASSWD_USR=$SUDO_USER
            TRUSTED_GRUB=1
            ;;
        y)  CONFIRM= ;;
        h)
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-p PATH \t\t Use PATH as Keylime path'
            echo $'-i \t\t\t Install IMA-related demo'
            echo $'-w \t\t\t Install webserver-related demo'
            echo $'-t \t\t\t Install TrustedGRUB2 (i386-pc w/ TPM) to /dev/sda'
            echo $'-T PATH \t\t Install TrustedGRUB2 (i386-pc w/ TPM) to PATH'
            echo $'-n \t\t\t No-password sudo for current user'
            echo $'-N USER \t\t No-password sudo for user USER'
            echo $'-f \t\t\t Full install (same as -niwt)'
            echo $'-y \t\t\t No confirmations (feeling lucky)'
            echo $'-h \t\t\t This help info'
            exit
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to call ${NAME}'s package manager and install python dependencies" 1>&2
   exit 1
fi

# Determine distibution (using systemd standard `os-release`):
if [ -f /etc/os-release ]; then
        . /etc/os-release
    else
        echo "Not able to determine your OS or Distribution"
        exit 1
fi

# Ensure the nopasswd sudo user is defined
if [[ "$NOPASSWD" -eq "1" ]] ; then
    if [[ -z "$NOPASSWD_USR" ]] ; then
        echo "This script must be run with sudo to do a no-password sudo, or use -N USER" 1>&2
        exit 1
    fi
    echo "INFO: No-password sudo for user '$NOPASSWD_USR'"
fi

# Make sure TrustedGRUB install path is valid
if [[ "$TRUSTED_GRUB" -eq "1" ]] ; then
    if [[ ! $(lsblk -npdo NAME | grep "^$TRUSTED_GRUB_DIR\$") ]] ; then
        echo "Could not find TrustedGRUB install path '$TRUSTED_GRUB_DIR'" 1>&2
        exit 1
    fi

    if [[ "$CONFIRM" -eq "1" ]] ; then
        echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        echo "You've chosen to install TrustedGRUB2.  This requires a physical TPM, "
        echo "otherwise your system will be unbootable.  It also does not support "
        echo "UEFI mode booting, so make sure you are using legacy boot in your "
        echo "BIOS settings.  It will be built for the i386-pc platform."
        echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        read -p "Do you want to continue? Type 'YES': " -r
        echo
        if [[ "$REPLY" != "YES" ]] ; then
            echo "Having second thoughts. Aborting demo install."
            exit 0
        fi
    fi
    echo "INFO: TrustedGRUB2 install target: '$TRUSTED_GRUB_DIR'"
fi

# If all else fails, assume they already have Keylime (we're in demo dir)
if [[ -z "$KEYLIME_DIR" ]] ; then
    cd ..
    KEYLIME_DIR=`pwd`
fi

# Sanity check
if [[ ! -d "$KEYLIME_DIR/demo" || ! -d "$KEYLIME_DIR/keylime" ]] ; then
    echo "ERROR: Invalid keylime directory at $KEYLIME_DIR"
    exit
fi


echo "INFO: Using Keylime directory: $KEYLIME_DIR"


# Set OS specifics (for now the package manager)

case "$ID" in
    debian | ubuntu)
        PACKAGE_MANAGER="apt-get"
    ;;

    redhat | centos)
        PACKAGE_MANAGER="yum"
    ;;

    fedora)
        PACKAGE_MANAGER="dnf"

    ;;

    *)
        echo "${ID} is not currently supported."
        exit 1
esac

# Ensure everything is latest

echo
echo "=================================================================================="
echo $'\t\t\t\tUpdating packages'
echo "=================================================================================="
${PACKAGE_MANAGER} update -y

# Keylime webserver-related dependencies
if [[ "$WEBSERVER" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\tInstalling nginx and cryptsetup'
    echo "=================================================================================="
    ${PACKAGE_MANAGER} install -y nginx cryptsetup


    # Install demo files to respective directories
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tInstalling demo files'
    echo "=================================================================================="
    mkdir -p $HTML_DIR/payload/
    cp -r $KEYLIME_DIR/demo/payload/ $HTML_DIR/
    cp $KEYLIME_DIR/demo/payload.enc $HTML_DIR/
fi


# Install TrustedGRUB2
if [[ "$TRUSTED_GRUB" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tTrustedGRUB2 Installation'
    echo "=================================================================================="

    # Create temp dir for building trusted grub
    TMPDIR=`mktemp -d` || exit 1
    echo -n "INFO: Using temp grub directory: "
    echo $TMPDIR

    # Install dependencies
    ${PACKAGE_MANAGER} -y install git autogen autoconf automake gcc bison flex

    case "$ID" in
    debian | ubuntu)
        ${PACKAGE_MANAGER} -y install libdevmapper-dev vflib3-dev libfuse-dev xfonts-utils libzfslinux-dev liblzma-dev ttf-dejavu ttf-unifont
    ;;

    redhat | centos | fedora)
        ${PACKAGE_MANAGER} -y install device-mapper-libs freetype fuse-devel xorg-x11-font-utils zfs-fuse  lzma-devel dejavu-fonts-common unifont-fonts
    ;;

    *)
        echo "${ID} is not currently supported."
        exit 1
    esac


    # Build TrustedGRUB2
    mkdir -p $TMPDIR/TrustedGRUB2
    mkdir -p $TMPDIR/tgrub-build
    cd $TMPDIR/TrustedGRUB2
    git clone $TGRUB_GIT .

    patch --forward --verbose -s -p1 < $KEYLIME_DIR/patches/trustedgrub-patch.txt \
        && echo "INFO: TrustedGRUB2 patched!"

    ./autogen.sh
    ./configure --prefix=$TMPDIR/tgrub-build/ --target=i386 --with-platform=pc
    if [[ "$CONFIRM" -eq "1" ]] ; then
        read -p "TrustedGRUB configured.  If it looks good, press ENTER."
    fi
    make
    make install

    # Install to device (!!!)
    cd $TMPDIR/tgrub-build/sbin/
    if [[ "$CONFIRM" -eq "1" ]] ; then
        read -p "TrustedGRUB built.  Press ENTER to install to $TRUSTED_GRUB_DIR."
    fi
    ./grub-install --directory=$TMPDIR/tgrub-build/lib/grub/i386-pc $TRUSTED_GRUB_DIR
    # No turning back now
    update-grub
fi


# Enable no-password sudo mode
if [[ "$NOPASSWD" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tNo-password sudo mode'
    echo "=================================================================================="
    echo "$NOPASSWD_USR ALL=(ALL) NOPASSWD:ALL" | EDITOR='tee -a' visudo
fi


# Installing IMA policy (THIS MUST BE LAST!)
if [[ "$IMA_ENABLE" -eq "1" ]] ; then
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tInstalling IMA policy'
    echo "=================================================================================="
    mkdir -p /etc/ima/
    if [[ "$CONFIRM" -eq "1" ]] ; then
        cp -i $KEYLIME_DIR/demo/ima-policy /etc/ima/
    else
        cp $KEYLIME_DIR/demo/ima-policy /etc/ima/
    fi
    echo "INFO: Restart required to enable IMA!"

    # Generating IMA allowlist
    echo
    echo "=================================================================================="
    echo $'\t\t\t\tGenerating Runtime Policy'
    echo "=================================================================================="
    cd $KEYLIME_DIR/scripts
    ./create_runtime_policy.sh -o runtime_policy.json
fi
