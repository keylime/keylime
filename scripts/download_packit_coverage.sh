#!/bin/bash

# There are 3 options how to tell this script where to start
# --artifacts-url - Testing Farm artifacts URL, provided by testing-farm script
# --testing-farm-log - Log of 'testing-farm request' command from where artifacts URL will be parsed
# --github-sha - PR merge commit provided by GitHub, here we will try to get artifacts URL using GitHub API

if [ "$1" == "--artifacts-url" -a -n "$2" ]; then
    TF_ARTIFACTS_URL="$2"
elif [ "$1" == "--testing-farm-log" -a -n "$2" ]; then
    TT_LOG="$2"
elif [ "$1" == "--github-sha" -a -n "$2" ]; then
    GITHUB_SHA="$2"
elif [ -n "$GITHUB_SHA" ]; then
    :
else
    echo "Neither --github-sha nor --artifacts-url nor --testing-farm-log arguments were provided"
    exit 1
fi

##############################################
# initial configuration, adjust when necessary
##############################################

# maximum duration of the task in seconds
MAX_DURATION="${MAX_DURATION:-5400}"  # 90 minutes

# delay in seconds before doing another URL read
# should not be too short not to exceed GitHub API quota
SLEEP_DELAY="${SLEEP_DELAY:-120}"

# github user/project we are going to work with
PROJECT="keylime/keylime"
#PROJECT="keylimecov/keylime"

# TF_JOB_DESC points to a Testing farm job that does code coverage measurement and 
# uploads coverage XML files to a web drive
# currently we are doing that in a job running tests on Fedora-39
TF_JOB_DESC="testing-farm:fedora-39-x86_64"
TF_TEST_OUTPUT="/setup/generate_coverage_report.*/output.txt"
TF_ARTIFACTS_URL_PREFIX="https://artifacts.dev.testing-farm.io"

GITHUB_API_PREFIX_URL="https://api.github.com/repos/${PROJECT}"

##################################
# no need to change anything below
##################################

# build GITHUB_API_URLs
GITHUB_API_COMMIT_URL="${GITHUB_API_PREFIX_URL}/commits"
DURATION=0

TMPFILE=$( mktemp )

# run API call and parse the required value
# repeat until we get the value or exceed job duration
# URL - API URL
# JQ_REF - code for jq that will be used for JSON parsing
# ERROR_MSG - error message to print in case we fail to parse the value
# EXP_VALUE - expected value (used e.g. when waiting for job completion)
function do_GitHub_API_call() {
    local URL="$1"
    local JQ_REF="$2"
    local ERROR_MSG="$3"
    local EXP_VALUE="$4"
    local VALUE=''

    while [ -z "${VALUE}" -o \( -n "${EXP_VALUE}" -a "${VALUE}" != "${EXP_VALUE}" \) ] && [ ${DURATION} -lt ${MAX_DURATION} ]; do
        if [ "$URL" != "-" ]; then  # when URL='-', we reuse data downloaded previously
            curl --retry 5 -s -H "Accept: application/vnd.github.v3+json" "$URL" &> ${TMPFILE}
        fi
        VALUE=$( cat ${TMPFILE} | jq "${JQ_REF}" | sed 's/"//g' )
        if [ -z "${VALUE}" ] || [ -n "${EXP_VALUE}" -a "${VALUE}" != "${EXP_VALUE}" ]; then
            if [ -z "${ERROR_MSG}" ]; then
                echo "Warning: Failed to read data using GitHub API, trying again after ${SLEEP_DELAY} seconds" 1>&2
            else
                echo "$ERROR_MSG" 1>&2
            fi
            sleep ${SLEEP_DELAY}
            DURATION=$(( ${DURATION}+${SLEEP_DELAY} ))
        fi
    done

    if [ ${DURATION} -ge ${MAX_DURATION} ]; then
         echo "Error: Maximum job diration exceeded. Terminating" 1>&2
         exit 9
    fi

    echo $VALUE
}


# if the GitHub Action has been triggered by a PR, 
# we need to find Testing farm test results through GitHub API
if [ -n "${GITHUB_SHA}" -a -z "${TF_ARTIFACTS_URL}" -a -z "${TT_LOG}" ]; then

    echo "Trying to find Testing Farm / Packig CI test results using GitHub API"

    echo "Fist I need to find the respective PR commit"
    GITHUB_API_SHA_URL="${GITHUB_API_COMMIT_URL}/${GITHUB_SHA}"

    # Now we try to parse URL of Testing farm job from GITHUB_API_RUNS_URL page
    GITHUB_PR_SHA=$( do_GitHub_API_call "${GITHUB_API_SHA_URL}" \
                                     ".parents[1].sha" \
                                     "Failed to parse PR commit from ${GITHUB_API_RUNS_URL}, trying again after ${SLEEP_DELAY} seconds..." )
    echo "GITHUB_PR_SHA=${GITHUB_PR_SHA}"

    echo "Now we read check-runs details"
    # build GITHUB_API_RUNS_URL using the COMMIT
    GITHUB_API_RUNS_URL="${GITHUB_API_COMMIT_URL}/${GITHUB_PR_SHA}/check-runs?check_name=${TF_JOB_DESC}"
    echo "GITHUB_API_RUNS_URL=${GITHUB_API_RUNS_URL}"

    # Now we try to parse URL of Testing farm job from GITHUB_API_RUNS_URL page
    TF_ARTIFACTS_URL=$( do_GitHub_API_call "${GITHUB_API_RUNS_URL}" \
                                     ".check_runs[0] | .output.summary | match(\"${TF_ARTIFACTS_URL_PREFIX}[^ ]*\") | .string" \
                                     "Failed to parse Testing Farm job ${TF_JOB_DESC} URL from ${GITHUB_API_RUNS_URL}, trying again after ${SLEEP_DELAY} seconds..." )
    echo "TF_ARTIFACTS_URL=${TF_ARTIFACTS_URL}"

    # now we wait for the Testing farm job to finish
    TF_STATUS=$( do_GitHub_API_call "${GITHUB_API_RUNS_URL}" \
                                    '.check_runs[0] | .status' \
                                    "Testing Farm job ${TF_JOB_DESC} hasn't completed yet, trying again after ${SLEEP_DELAY} seconds..." \
                                    "completed" )
    echo "TF_STATUS=${TF_STATUS}"

fi

# if we were provided with testing-farm command log
# we will parse artifacts from the log
if [ -n "${TT_LOG}" ]; then
    cat ${TT_LOG}
    TF_ARTIFACTS_URL=$( grep -E -o "${TF_ARTIFACTS_URL_PREFIX}[^ ]*" ${TT_LOG} )
fi

# now we have TF_ARTIFACTS_URL so we can proceed with the download
echo "TF_ARTIFACTS_URL=${TF_ARTIFACTS_URL}"

TF_TESTLOG=$( curl --retry 5 ${TF_ARTIFACTS_URL}/results.xml | grep -E -o "${TF_ARTIFACTS_URL}.*${TF_TEST_OUTPUT}" )
echo "TF_TESTLOG=${TF_TESTLOG}"

# parse the URL of coverage XML file and download it
curl --retry 5 -s "${TF_TESTLOG}" &> ${TMPFILE}
for REPORT in coverage.packit.xml coverage.testsuite.xml coverage.unittests.xml; do
    COVERAGE_URL=$( grep "$REPORT report is available at" ${TMPFILE} | grep -E -o "https?://[^[:space:]]*" )
    echo "COVERAGE_URL=${COVERAGE_URL}"

    if [ -z "${COVERAGE_URL}" ]; then
        echo "Could not parse $REPORT URL from test log ${TF_TESTLOG}"
        exit 5
    fi

    # download the file
    curl -L -o "${REPORT}" "${COVERAGE_URL}"
done
rm ${TMPFILE}
