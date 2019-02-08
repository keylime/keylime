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


# Find Keylime directory (we're in test/ directory)
KEYLIME_DIR=`pwd`/../

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
        if [ "$CA_IMP" == "openssl" ]; then
            echo -e "Setting CA Implementation to OpenSSL"
            sed -i 's/ca_implementation = cfssl/ca_implementation = openssl/g' /etc/keylime.conf
        elif [ "$CA_IMP" == "cfssl" ]; then
            $PACKAGE_MGR install -y golang
        fi
    fi     
fi


# pip-related dependencies
if [[ -z "$(command -v pip)" ]] ; then
    # Which package management system are we using?
    if [[ -n "$(command -v yum)" ]]; then
        PACKAGE_MGR=$(command -v yum)
        PYTHON_PREIN="epel-release python"
        PYTHON_DEPS="python-pip"
    elif [[ -n "$(command -v apt-get)" ]]; then
        PACKAGE_MGR=$(command -v apt-get)
        PYTHON_PREIN="python"
        PYTHON_DEPS="python-pip"
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
    echo $'\t\t\tInstalling python and pip'
    echo "=================================================================================="
    $PACKAGE_MGR install -y $PYTHON_PREIN
    $PACKAGE_MGR install -y $PYTHON_DEPS
fi


# Install test dependencies
echo
echo "=================================================================================="
echo $'\t\t\tInstalling test requirements'
echo "=================================================================================="
pip install $UMODE_OPT -r $KEYLIME_DIR/test/test-requirements.txt


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
