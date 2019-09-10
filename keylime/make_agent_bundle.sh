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
# Copyright 2016 Massachusetts Institute of Technology.
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


rm -rf build dist

# copy in extra pycryptodome libraries
mkdir -p build/crypto
CRYPTO_DIR=`pwd`"/build/crypto"

# Copy py dependencies to crypto folder
copy_py_deps () {
    pushd $1
    IFS=$'\n'
    CRYPTO_PY=`find -name _BLAKE2b*.so | awk -F\/ '{print $2}'`
    for dir in $CRYPTO_PY ; do
        find "$dir" -name "*.so" -exec cp -t $CRYPTO_DIR '{}' \;
    done
    popd
}

# Find python's dist-packages or site-packages dirs
IFS=$'\n'
DIST_PATH=`python3 -c "import sys;import re;  print('\n'.join(filter(lambda x:re.search(r'(dist|site)-packages$',x), sys.path)))"`
for path in $DIST_PATH ; do
    copy_py_deps "$path"
done

if [[ "$TPM_VERSION" -eq "2" ]] ; then
    pyinstaller --clean agent_installer_2.spec
else
    pyinstaller --clean agent_installer.spec
fi
