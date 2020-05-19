#!/bin/bash
################################################################################
# SPDX-License-Identifier: BSD-2-Clause
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################


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
