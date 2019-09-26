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
if [[ -n "$(command -v dnf)" ]]; then
    PACKAGE_MGR=$(command -v dnf)
    PACKAGE_INSP="rpm -ql"
    PYTHON_PREIN="python3 python3-devel python3-setuptools git wget"
    PYTHON_DEPS="python3-pip gcc gcc-c++ upx czmq-devel zeromq-devel openssl-devel swig python3-pyyaml python3-m2crypto python3-cryptography python3-tornado python3-simplejson python3-requests yaml-cpp-devel"
    PYTHON_PIPS="pyzmq pyinstaller"
elif [[ -n "$(command -v yum)" ]]; then
    PACKAGE_MGR=$(command -v yum)
    PACKAGE_INSP="rpm -ql"
    $PACKAGE_MGR -y install epel-release
    PYTHON_PREIN="python36 python36-devel python36-setuptools python36-pip git wget patch openssl"
    PYTHON_DEPS="gcc gcc-c++ openssl-devel swig python36-PyYAML python36-tornado python36-simplejson python3-cryptography python36-requests yaml-cpp-devel"
    PYTHON_PIPS="pyzmq m2crypto pyinstaller"
elif [[ -n "$(command -v apt-get)" ]]; then
    PACKAGE_MGR=$(command -v apt-get)
    PACKAGE_INSP="dpkg -L"
    PYTHON_PREIN="git patch wget"
    PYTHON_DEPS="python3 python3-pip python3-dev python3-setuptools python3-zmq python3-cryptography python3-tornado python3-simplejson python3-requests gcc g++ libssl-dev upx-ucl swig python3-yaml"
    PYTHON_PIPS="m2crypto pyinstaller"
    $PACKAGE_MGR update
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
pip3 install $PYTHON_PIPS


# Build packaged keylime-python installer
echo
echo "=================================================================================="
echo $'\t\t\tBuilding Keylime installer'
echo "=================================================================================="
BUNDLE_FLAGS=""
if [[ "$TPM_VERSION" -eq "2" ]] ; then
    BUNDLE_FLAGS="-m"
fi
./make_agent_bundle.sh $BUNDLE_FLAGS


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

cp dist/keylime_agent_tpm$TPM_VERSION $TMPDIR/keylime
if [[ "$?" -ne "0" ]] ; then
    echo "ERROR: Cannot copy keylime_agent"
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
PYPATH=`which python3`
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
