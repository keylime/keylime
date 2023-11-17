#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

# Set python3 as default
alias python='/usr/bin/python3'

# Find Keylime directory. It's one directory above the location of this script
KEYLIME_SRC=$(realpath "$(dirname "$(readlink -f "$0")")/../")

# Get list of tests in the test directory
TEST_LIST=`ls | grep "^test_.*\.py$"`


# Command line params
USER_MODE=0
UMODE_OPT=""
COVERAGE=0
COVERAGE_DIR=`pwd`
unset COVERAGE_FILE

while getopts ":cuh:" opt; do
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
        h)
            echo "Usage: $0 [option...]"
            echo "Options:"
            echo $'-c \t\t Run Coverage scans'
            echo $'-u \t\t Run in user (non-root) mode'
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

    sles | opensuse-leap | opensuse-tumbleweed )
        PACKAGE_MGR="zypper"
    ;;

    *)
        echo "${ID} is not currently supported."
        exit 1
esac

# Permissions-related sanity checking
if [[ "$USER_MODE" -eq "0" && $EUID -ne 0 ]]; then
   echo "This script must be run as root in order to install dependencies.  Use -u for user mode." 1>&2
   exit 1
fi

if [[ "$USER_MODE" -eq "1" && $EUID -eq 0 ]]; then
   echo "It is not recommended to run as root in user mode!" 1>&2
   exit 1
fi


# Keylime directory validity check
if [[ ! -d "$KEYLIME_SRC/test" || ! -d "$KEYLIME_SRC/keylime" ]] ; then
    echo "ERROR: Invalid keylime directory at $KEYLIME_SRC"
    exit 1
fi

# Set correct dependencies
# Fedora
if [ $PACKAGE_MGR = "dnf" ]; then
    PYTHON_PREIN="python3 openssl"
    PYTHON_DEPS="python3-pip python3-dbus"
# RHEL / CentOS etc
elif [ $PACKAGE_MGR = "yum" ]; then
    PYTHON_PREIN="epel-release python36 openssl"
    PYTHON_DEPS="python36-pip python36-dbus"
# Ubuntu / Debian
elif [ $PACKAGE_MGR = "apt-get" ]; then
    PYTHON_PREIN="python3 openssl"
    PYTHON_DEPS="python3-pip python3-dbus"
# SUSE
elif [ $PACKAGE_MGR = "zypper" ]; then
    PYTHON_PREIN="python3 openssl"
    PYTHON_DEPS="python3-pip python3-dbus"
else
    echo "No recognized package manager found on this system!" 1>&2
    exit 1
fi

if [[ "$USER_MODE" -ne "0" ]] ; then
    echo -e "Packages '$PYTHON_DEPS' are required for this script.  Please manually install them, or run this script as root." 1>&2
fi

echo
echo "=================================================================================="
echo $'\t\t\tInstalling python and dependencies'
echo "=================================================================================="
$PACKAGE_MGR install -y $PYTHON_PREIN
$PACKAGE_MGR install -y $PYTHON_DEPS

echo
echo "=================================================================================="
echo $'\t\t\tCreate and activate virtual environment'
echo "=================================================================================="
if [[ ! -d /tmp/keylime_test ]]; then
    python3 -m venv --system-site-packages /tmp/keylime_test
fi

source /tmp/keylime_test/bin/activate

pip install --upgrade pip

# Deactivate virtual environment on exit
trap deactivate EXIT

# Install test dependencies
echo
echo "=================================================================================="
echo $'\t\t\tInstalling test requirements'
echo "=================================================================================="
pip3 install $UMODE_OPT -r $KEYLIME_SRC/test/test-requirements.txt

KEYLIME_TEMP_DIR=`mktemp -d`
if [[ ! "$KEYLIME_TEMP_DIR" || ! -d "$KEYLIME_TEMP_DIR" ]]; then
    echo "Could not create temp dir"
    exit 1
fi

export KEYLIME_TEMP_DIR=$KEYLIME_TEMP_DIR

# Install Keylime
echo
echo "=================================================================================="
echo $'\t\t\tInstalling Keylime'
echo "=================================================================================="
cd $KEYLIME_SRC
pip install . -r requirements.txt

echo "=================================================================================="
echo $'\t\t\tGenerating configuration'
echo "=================================================================================="
export KEYLIME_CONF_DIR=$KEYLIME_TEMP_DIR/conf
mkdir -p $KEYLIME_CONF_DIR
python3 -m keylime.cmd.convert_config \
    --defaults \
    --out  $KEYLIME_CONF_DIR\
    --templates $KEYLIME_SRC/templates

echo -e "Setting require_ek_cert to False"
sed -i 's/require_ek_cert = True/require_ek_cert = False/g' $KEYLIME_CONF_DIR/tenant.conf

export KEYLIME_VERIFIER_CONFIG=$KEYLIME_CONF_DIR/verifier.conf
export KEYLIME_REGISTRAR_CONFIG=$KEYLIME_CONF_DIR/registrar.conf
export KEYLIME_TENANT_CONFIG=$KEYLIME_CONF_DIR/tenant.conf
export KEYLIME_CA_CONFIG=$KEYLIME_CONF_DIR/ca.conf
export KEYLIME_LOGGING_CONFIG=$KEYLIME_CONF_DIR/logging.conf

export KEYLIME_DIR=$KEYLIME_TEMP_DIR/keylime_dir

echo "=================================================================================="
echo $'\t\t\tRunning Unit Tests'
echo "=================================================================================="
# Run separate unit tests
python3 -m unittest discover -s keylime/ima -p '*_test.py' -v
if [ $? -ne 0 ]; then
    echo "Error: Unit tests failed"
    exit 1
fi

python3 -m unittest discover -s keylime/tpm -p '*_test.py' -v
if [ $? -ne 0 ]; then
    echo "Error: Unit tests failed"
    exit 1
fi

# Run the tests as necessary
if [[ "$COVERAGE" -eq "1" ]] ; then
    # Coverage config file
    echo -e "[run]\nsource = $KEYLIME_SRC/keylime\nomit = /usr/local/lib/,\"*/test/*\",$KEYLIME_SRC/keylime/test.py" > $COVERAGE_DIR/.coveragerc

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
    result=0
else
    # Do generic testing with no coverage
    echo
    echo "=================================================================================="
    echo $'\t\t\tBegin Testing Phase'
    echo "=================================================================================="
    green -vv
    result=$?
fi

echo "=================================================================================="
echo $'\t\t\tCleanup'
echo "=================================================================================="
# The generated files can be kept by setting the environment variable KEEP_TMP_FILES=1
if [[ ! "$KEEP_TMP_FILES" -eq "1" ]]; then
    echo -e "Removing $KEYLIME_TEMP_DIR"
    rm -rf $KEYLIME_TEMP_DIR
else
    echo -e "Not removing $KEYLIME_TEMP_DIR as KEEP_TMP_FILES == 1"
fi

exit $result
