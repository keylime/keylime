#!/bin/bash

##############################################
# initial configuration, adjust when necessary
##############################################

# maximum duration of the task in seconds
MAX_DURATION="${MAX_DURATION:-5400}"  # 90 minutes

# delay in seconds before doing another URL read
# should not be too short not to exceed GitHub API quota
SLEEP_DELAY="${SLEEP_DELAY:-120}"

# TF_JOB_DESC points to a Testing farm job that does code coverage measurement and 
# uploads coverage XML files to a web drive
# currently we are doing that in a job running tests on Fedora-35
TF_JOB_DESC="testing-farm:fedora-35-x86_64"

# TF_TEST_OUTPUT points to a file with test output containing URLs to a web drive
# we are going to parse the output to get those URL and download coverage XML files
TF_TEST_OUTPUT="/setup/generate_coverage_report/output.txt"

# TF_ARTIFACTS_URL is URL prefix of Testing farm test artifacts
TF_ARTIFACTS_URL="https://artifacts.dev.testing-farm.io"

# WEBDRIVE_URL points to a web page that stores coverage XML files
WEBDRIVE_URL="https://transfer.sh"

##################################
# no need to change anything below
##################################

# COMMIT is necessary so we can access the GITHUB API URL to read check runs status
if [ -z "$GITHUB_SHA" -a -z "$1" ]; then
  echo "Commit SHA is required as an argument or in GITHUB_SHA environment variable"
  exit 1
fi
COMMIT="${GITHUB_SHA}"
[ -n "$1" ] && COMMIT="$1"
echo "COMMIT=${COMMIT}"

# github project is also necessary so we can build API URL
if [ -z "${GITHUB_REPOSITORY}" -a -z "$2" ]; then
  echo "GitHub repository name USER/PROJECT is required as an argument or in GITHUB_REPOSITORY environment variable"
  exit 1
fi
PROJECT="${GITHUB_REPOSITORY}"
[ -n "$2" ] && PROJECT="$2"
echo "PROJECT=${PROJECT}"

# build GITHUB_API_URLs
GITHUB_API_PREFIX_URL="https://api.github.com/repos/${PROJECT}"
GITHUB_API_COMMIT_URL="${GITHUB_API_PREFIX_URL}/commits"

# meassure approx. task duration
DURATION=0

TMPFILE=$( mktemp )

####################################
# some functions we are going to use
####################################

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
            curl -s -H "Accept: application/vnd.github.v3+json" "$URL" &> ${TMPFILE}
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

######################################
# now start with the actual processing
######################################

# First we need to check if we are processing PR or a merged commit
# let's try to find some open PRs

# On GitHub commit always changes when doing rebase and merge
# and therefore commit differs between the PR branch and master branch
# Here we try to find the commit from PR branch since this is the commit
# for which tests have been run.

OPEN_PULLS=$( mktemp )
do_GitHub_API_call "${GITHUB_API_PREFIX_URL}/pulls" \
                   '.[] | .head.sha, .base.sha, .url, .head.repo.full_name' \
| tr ' ' '\n' > ${OPEN_PULLS}

if grep -q ${COMMIT} ${OPEN_PULLS}; then
    # we are processing PR.
    echo "We are processing PR"
    PR_HEAD_COMMIT=${COMMIT}
    PR_BASE_COMMIT=$( grep -A 1 "${COMMIT}" ${OPEN_PULLS} | tail -1 )
    GITHUB_API_PR_URL=$( grep -A 2 "${COMMIT}" ${OPEN_PULLS} | tail -1 )
    PR_PROJECT=$( grep -A 3 "${COMMIT}" ${OPEN_PULLS} | tail -1 )
else
    # we are processing merged commit
    echo "We are processing merged commit"
    GITHUB_API_PR_URL="${GITHUB_API_COMMIT_URL}/${COMMIT}/pulls"
    PR_HEAD_COMMIT=$( do_GitHub_API_call "${GITHUB_API_PR_URL}" \
                                         ".[0].head.sha" \
                                         "Failed to get PR HEAD commit from ${GITHUB_API_PR_URL}, trying again after ${SLEEP_DELAY} seconds..." )

    PR_PROJECT=$( do_GitHub_API_call "-" \
                                     ".[0].head.repo.full_name" \
                                     "Failed to get PR HEAD repo name from ${GITHUB_API_PR_URL}, trying again after ${SLEEP_DELAY} seconds..." )

    PR_BASE_COMMIT=$( do_GitHub_API_call "-" \
                                         ".[0].base.sha" )
fi

echo "GITHUB_API_PR_URL=${GITHUB_API_PR_URL}"
echo "PR_HEAD_COMMIT=${PR_HEAD_COMMIT}"
echo "PR_PROJECT=${PR_PROJECT}"
echo "PR_BASE_COMMIT=${PR_BASE_COMMIT}"


# now if PR_HEAD_COMMIT and COMMIT differ, it means we are processing merge to master branch
# in this case we can use PR code coverage only if the parent and base commit are equal,
# i.e. there were no other commits added to master branch in the meantime
if [ "${PR_HEAD_COMMIT}" != "${COMMIT}" ]; then

    echo "Provided commit ${COMMIT} differs from PR commit ${PR_HEAD_COMMIT}"
    echo "Need to verify that there were no other change merged in the mean time"
    echo "and point to the original PR project and commit"

    # now we need to check that there were no other changes merged, otherwise
    # code coverage data would be outdated and we should not use them
    # we do that by checking that all commits between PR HEAD and base refer to the same PR
    TMP_COMMIT=${COMMIT}
    PR_LIST=$( mktemp )
    while [ "$TMP_COMMIT" != "${PR_BASE_COMMIT}" ]; do
        PR=$( do_GitHub_API_call "${GITHUB_API_COMMIT_URL}/${TMP_COMMIT}/pulls" \
                                 '.[0].url' \
                                 "Cannot get PR URL for commit ${TMP_COMMIT} from ${GITHUB_API_COMMIT_URL}/${TMP_COMMIT}/pulls, trying again in ${SLEEP_DELAY} seconds..." )
        echo ${PR} >> ${PR_LIST}
        # now move to the parent commit
        TMP_COMMIT=$( do_GitHub_API_call "${GITHUB_API_COMMIT_URL}/${TMP_COMMIT}" \
                                 ' .parents[0].sha ' \
                                 "Cannot get parent commit for commit ${TMP_COMMIT} from ${GITHUB_API_COMMIT_URL}/${TMP_COMMIT}, trying again in ${SLEEP_DELAY} seconds..." )
    done

    echo "PRs merged since commit ${COMMIT} PR base ${PR_BASE_COMMIT}:"
    cat ${PR_LIST}
    # now check the list to confirm there is just a single PR listed
    if [ $( sort ${PR_LIST} | wc -l ) -gt 1 ]; then
        echo "Error: There were other PR's merged in the mean time, coverage data cannot be re-used"
        exit 5
    fi
    rm ${PR_LIST}

fi

# build GITHUB_API_RUNS_URL using the COMMIT
GITHUB_API_RUNS_URL="${GITHUB_API_COMMIT_URL}/${PR_HEAD_COMMIT}/check-runs?check_name=${TF_JOB_DESC}"
echo "GITHUB_API_RUNS_URL=${GITHUB_API_RUNS_URL}"

# Now we try to parse URL of Testing farm job from GITHUB_API_RUNS_URL page
TF_BASEURL=$( do_GitHub_API_call "${GITHUB_API_RUNS_URL}" \
                                 ".check_runs[0] | .output.summary | match(\"${TF_ARTIFACTS_URL}/[^ ]*\") | .string" \
                                 "Failed to parse Testing Farm job ${TF_JOB_DESC} URL from ${GITHUB_API_RUNS_URL}, trying again after ${SLEEP_DELAY} seconds..." )
echo "TF_BASEURL=${TF_BASEURL}"

# now we wait for the Testing farm job to finish
TF_STATUS=$( do_GitHub_API_call "${GITHUB_API_RUNS_URL}" \
                                 '.check_runs[0] | .status' \
                                 "Testing Farm job ${TF_JOB_DESC} hasn't completed yet, trying again after ${SLEEP_DELAY} seconds..." \
                                 "completed" )
echo "TF_STATUS=${TF_STATUS}"
                                
# check test results - we won't proceed if test failed since coverage data may be incomplete,
# see https://docs.codecov.com/docs/comparing-commits#commits-with-failed-ci
TF_RESULT=$( do_GitHub_API_call "-" \
                                '.check_runs[0] | .conclusion' \
                                "Cannot get Testing Farm job ${TF_JOB_DESC} result, trying again after ${SLEEP_DELAY} seconds..." )
echo TF_RESULT=${TF_RESULT}

if [ "${TF_RESULT}" != "success" ]; then
    echo "Testing Farm tests failed, we won't be uploading coverage data since they may be incomplete"
    return 3
fi

# wait a bit since there could be some timing issue
sleep 10

# now we read the actual test log URL
TF_TESTLOG=$( curl -s ${TF_BASEURL}/results.xml | egrep -o "${TF_ARTIFACTS_URL}.*${TF_TEST_OUTPUT}" )
echo "TF_TESTLOG=${TF_TESTLOG}"

# parse the URL of coverage XML file on WEBDRIVE_URL and download it
curl -s "${TF_TESTLOG}" &> ${TMPFILE}
for REPORT in coverage.packit.xml coverage.testsuite.xml coverage.unittests.xml; do
    COVERAGE_URL=$( grep "$REPORT report is available at" ${TMPFILE} | grep -o "${WEBDRIVE_URL}.*\.xml" )
    echo "COVERAGE_URL=${COVERAGE_URL}"

    if [ -z "${COVERAGE_URL}" ]; then
        echo "Could not parse $REPORT URL at ${WEBDRIVE_URL} from test log ${TF_TESTLOG}"
        exit 5
    fi

    # download the file
    curl -O ${COVERAGE_URL}
done
rm ${TMPFILE}
