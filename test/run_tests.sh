#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

# Set python3 as default
alias python='/usr/bin/python3'

# Find Keylime directory. It's one directory above the location of this script
KEYLIME_DIR=$(realpath "$(dirname "$(readlink -f "$0")")/../")

# Get list of tests in the test directory
TEST_LIST=`ls | grep "^test_.*\.py$"`


# Command line params
USER_MODE=0
UMODE_OPT=""
COVERAGE=0
COVERAGE_DIR=`pwd`
unset COVERAGE_FILE

for opt in "$@"; do
  shift
  case "$opt" in
    "--ssl") set -- "$@" "-s" ;;
    *)       set -- "$@" "$opt"
  esac
done

while getopts ":cuhs:" opt; do
    case $opt in
        c)
            COVERAGE=1
            export COVERAGE_DIR=`mktemp -d`
            export COVERAGE_FILE=$COVERAGE_DIR/.coverage
            echo "INFO: Using Coverage directory: $COVERAGE_DIR"
            ;;
        u)
            USER_MODE=1
            UMODE_OPT="--user"
            export KEYLIME_TEST=True
            ;;
        s)
            CA_IMP="$OPTARG"
            case $CA_IMP in
                (openssl|cfssl) ;; # OK
                (*) printf >&2 "Invalid: CA Implementation \"$CA_IMP\". Options are openssl or cfssl \n"; exit 1;;
                esac
            ;;
        h)
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-c \t\t Run Coverage scans'
            echo $'-u \t\t Run in user (non-root) mode'
            echo $'-s ssl \t\t Select CA implementation (openssl|cfssl)'
            echo $'-h \t\t This help info'
            exit
            ;;
    esac
done

# Determine distibution (using systemd standard `os-release`):
if [ -f /etc/os-release ]; then
        . /etc/os-release
    else
        echo "Not able to determine your OS or Distribution"
        exit 1
fi

# Set OS specifics (for now the package manager)

case "$ID" in
    debian | ubuntu)
        PACKAGE_MGR="apt-get"
    ;;

    redhat | centos)
        PACKAGE_MGR="yum"
    ;;

    fedora)
        PACKAGE_MGR="dnf"

    ;;

    *)
        echo "${ID} is not currently supported."
        exit 1
esac

# Permissions-related sanity checking
if [[ "$USER_MODE" -eq "0" && $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to call apt-get and install python dependencies.  Use -u for user mode." 1>&2
   exit 1
fi

if [[ "$USER_MODE" -eq "1" && $EUID -eq 0 ]]; then
   echo "It is not recommended to run as root in user mode!" 1>&2
   exit 1
fi


# Keylime directory validity check
if [[ ! -d "$KEYLIME_DIR/test" || ! -d "$KEYLIME_DIR/keylime" ]] ; then
    echo "ERROR: Invalid keylime directory at $KEYLIME_DIR"
    exit 1
fi

# Copy keyline.conf into place
if [ ! -f "/etc/keylime.conf" ]; then
    if [ "$USER_MODE" == "1" ]; then
        echo -e "keylime.conf cannot be copied as a non-root user, please copy keylime.conf to etc/ and restart script"
        exit 1
    else
        echo -e "Copying keylime.conf into /etc/keylime.conf"
        cp -n $KEYLIME_DIR/keylime.conf /etc/keylime.conf
        echo -e "Setting require_ek_cert to False"
        sed -i 's/require_ek_cert = True/require_ek_cert = False/g' /etc/keylime.conf
        if [ "$CA_IMP" == "openssl" ]; then
            echo -e "Setting CA Implementation to OpenSSL"
            sed -i 's/ca_implementation = cfssl/ca_implementation = openssl/g' /etc/keylime.conf
        elif [ "$CA_IMP" == "cfssl" ]; then
            $PACKAGE_MGR install -y golang
        fi
    fi
fi

# Set correct dependencies
# Fedora
if [ $PACKAGE_MGR = "dnf" ]; then
    PYTHON_PREIN="python3"
    PYTHON_DEPS="python3-pip python3-dbus"
# RHEL / CentOS etc
elif [ $PACKAGE_MGR = "yum" ]; then
    PYTHON_PREIN="epel-release python36"
    PYTHON_DEPS="python36-pip python36-dbus"
# Ubuntu / Debian
elif [ $PACKAGE_MGR = "apt-get" ]; then
    PYTHON_PREIN="python3"
    PYTHON_DEPS="python3-pip python3-dbus"
else
    echo "No recognized package manager found on this system!" 1>&2
    exit 1
fi

if [[ "$USER_MODE" -ne "0" ]] ; then
    echo -e "Packages '$PYTHON_DEPS' are required for this script.  Please manually install them, or run this script as root." 1>&2
    exit 1
fi

echo
echo "=================================================================================="
echo $'\t\t\tInstalling python and dependencies'
echo "=================================================================================="
$PACKAGE_MGR install -y $PYTHON_PREIN
$PACKAGE_MGR install -y $PYTHON_DEPS

# Install test dependencies
echo
echo "=================================================================================="
echo $'\t\t\tInstalling test requirements'
echo "=================================================================================="
pip3 install $UMODE_OPT -r $KEYLIME_DIR/test/test-requirements.txt

# Install Keylime
echo
echo "=================================================================================="
echo $'\t\t\tInstalling Keylime'
echo "=================================================================================="
cd $KEYLIME_DIR
python3 -m pip install . -r requirements.txt

# Run the tests as necessary
if [[ "$COVERAGE" -eq "1" ]] ; then
    # Coverage config file
    echo -e "[run]\nsource = $KEYLIME_DIR/keylime\nomit = /usr/local/lib/,\"*/test/*\",$KEYLIME_DIR/keylime/test.py" > $COVERAGE_DIR/.coveragerc

    echo
    echo "=================================================================================="
    echo $'\t\t\tBegin Testing Phase'
    echo "=================================================================================="
    for test in $TEST_LIST ; do
        coverage run --rcfile=$COVERAGE_DIR/.coveragerc --parallel-mode $test
    done

    echo
    echo "=================================================================================="
    echo $'\t\t\tProcessing Coverage Reports'
    echo "=================================================================================="
    pushd $COVERAGE_DIR
    coverage combine
    coverage report
    coverage html
    popd 1>/dev/null
else
    # Do generic testing with no coverage
    echo
    echo "=================================================================================="
    echo $'\t\t\tBegin Testing Phase'
    echo "=================================================================================="
    green -vv
    exit $?
fi
