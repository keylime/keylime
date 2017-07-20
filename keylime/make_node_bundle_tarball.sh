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


# Which extra python packages must be installed? 
PYTHON_DEPS="python-dev python-setuptools python-tornado python-m2crypto python-zmq"


if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to call apt-get and install python dependencies" 1>&2
   exit 1
fi

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
apt-get install -y python python-pip upx
pip install pyinstaller
apt-get install -y $PYTHON_DEPS


# Build packaged keylime-python installer 
echo 
echo "=================================================================================="
echo $'\t\t\tBuilding Keylime installer'
echo "=================================================================================="
./make_node_bundle.sh


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

cp dist/keylime_node $TMPDIR/keylime
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
    SO_LIST=`dpkg -L $pkg | grep '\.so'`
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
