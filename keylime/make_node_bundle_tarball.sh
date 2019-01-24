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


# Which package management system are we using? 
if [[ -n "$(command -v dnf)" || -n "$(command -v yum)" ]]; then
    if [[ -n "$(command -v dnf)" ]]; then
        PACKAGE_MGR=$(command -v dnf)
    elif [[ -n "$(command -v yum)" ]]; then
        PACKAGE_MGR=$(command -v yum)
    fi 
    PACKAGE_INSP="rpm -ql"
    
    # Only install epel-release if it is available (e.g., not Fedora)
    EXTRA_PKGS_STR=
    if [[ -n "$($PACKAGE_MGR search epel-release 2>/dev/null)" ]]; then
        EXTRA_PKGS_STR="epel-release python python-devel python-setuptools"
    else
        EXTRA_PKGS_STR="python2 python2-devel python2-setuptools"
    fi
    
    PACKAGE_MGR=$(command -v yum)
    PYTHON_PREIN="$EXTRA_PKGS_STR git wget"
    PYTHON_DEPS="python2-pip gcc gcc-c++ upx czmq-devel zeromq-devel openssl-devel swig"
    PYTHON_PIPS="pycryptodomex m2crypto tornado pyzmq pyinstaller"
elif [[ -n "$(command -v apt-get)" ]]; then
    PACKAGE_MGR=$(command -v apt-get)
    PACKAGE_INSP="dpkg -L"
    PYTHON_PREIN="git"
    PYTHON_DEPS="python python-pip gcc g++ upx-ucl python-dev python-setuptools python-zmq libssl-dev swig"
    PYTHON_PIPS="pycryptodomex m2crypto tornado pyinstaller"
else
   echo "No recognized package manager found on this system!" 1>&2
   exit 1
fi


# Command line params 
TPM_VERSION=1
while getopts ":hm" opt; do
    case $opt in
        m) TPM_VERSION=2 ;;
        h) 
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-m \t\t\t\t Use modern TPM 2.0 libraries (vs. TPM 1.2)'
            echo $'-h \t\t\t\t This help info'
            exit
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to call apt-get and install python dependencies" 1>&2
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


# Build packaged keylime-python installer 
echo 
echo "=================================================================================="
echo $'\t\t\tBuilding Keylime installer'
echo "=================================================================================="
BUNDLE_FLAGS=""
if [[ "$TPM_VERSION" -eq "2" ]] ; then
    BUNDLE_FLAGS="-m"
fi
./make_node_bundle.sh $BUNDLE_FLAGS


# Get all dependencies for tarball
echo 
echo "=================================================================================="
echo $'\t\t\tFinding Keylime dependencies'
echo "=================================================================================="
# Create temp dir for building tarball 
TMPDIR=`mktemp -d`|| exit 1
mkdir -p $TMPDIR/keylime
echo -n "INFO: Using temp directory: "
echo $TMPDIR

cp dist/keylime_node_tpm$TPM_VERSION $TMPDIR/keylime
if [[ "$?" -ne "0" ]] ; then
    echo "ERROR: Cannot copy keylime_node"
    exit 1
fi
cp ../keylime.conf $TMPDIR/keylime
if [[ "$?" -ne "0" ]] ; then
    echo "ERROR: Cannot copy keylime.conf"
    exit 1
fi

mkdir -p $TMPDIR/keylime/lib/
mkdir -p $TMPDIR/keylime/lib64/

# Copy lib dependencies to tarball folder 
copy_deps () {
    if [[ ! -z "$1" ]] ; then
        LDD_PYTHON=`ldd $1 | awk '{if ($0 !~ /=>/) {print $1} else if ($3 ~ /^\//) {print $3}}'`
        for i in $LDD_PYTHON ; do
            if [[ "$i" == "/lib/"* || "$i" == "/usr/lib/"* ]] ; then
                cp $i $TMPDIR/keylime/lib/
            elif [[ "$i" == "/lib64/"* ]] ; then
                cp $i $TMPDIR/keylime/lib64/
            fi
        done 
    fi
}

# Python lib dependencies 
PYPATH=`which python`
copy_deps "$PYPATH"

# Python module lib dependencies 
for pkg in $PYTHON_DEPS ; do
    SO_LIST=`$PACKAGE_INSP $pkg | grep '\.so'`
    for dep in $SO_LIST ; do
        copy_deps "$dep"
    done
done


# Generating tarball
echo 
echo "=================================================================================="
echo $'\t\t\tGenerating Keylime tarball'
echo "=================================================================================="
tar -cvzf dist/keylime.tar.gz -C $TMPDIR/keylime .
