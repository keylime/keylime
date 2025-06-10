#!/bin/bash

# You can specify the path of the local keylime repository as argument
# of this script or using the KEYLIME_REPO_PATH environment variable.
# The default value is one directory above where this script is located.
REPO=${KEYLIME_REPO_PATH:-${1:-$(realpath "$(dirname "$(readlink -f "$0")")/../")}}

# You can specify the container engine to use with the CONTAINER_ENGINE
# environment variable. The default to be used will be 'docker',
# or 'podman' if it exists and 'docker' don't
if [ -z "$CONTAINER_ENGINE" ]; then
    if command -v docker &> /dev/null; then
        CONTAINER_ENGINE="docker"
    elif command -v podman &> /dev/null; then
        CONTAINER_ENGINE="podman"
    else
        echo "ERROR: No container engine specified, and could not find 'docker' or 'podman' in PATH." >&2
        exit 1
    fi
fi

# keylime images
tpmimage="quay.io/keylime/keylime-ci"
tpmtag="latest"

echo -e "Fetching Keylime CI container"

${CONTAINER_ENGINE} pull ${tpmimage}:${tpmtag}

echo -e "Running Keylime's test suite"

container_id=$(mktemp)
${CONTAINER_ENGINE} run --detach --user root --env KEYLIME_TEST='true' --env RUST_TEST=1\
    -v $REPO:/root/keylime:Z \
    --mount type=tmpfs,destination=/var/lib/keylime/,tmpfs-mode=1770 \
    -it ${tpmimage}:${tpmtag} >> ${container_id}
# run the Keylime test suite
${CONTAINER_ENGINE} exec -u root -it --tty "$(cat ${container_id})" \
    /bin/bash /root/keylime/.ci/test_wrapper.sh
${CONTAINER_ENGINE} stop "$(cat ${container_id})"
${CONTAINER_ENGINE} rm "$(cat ${container_id})"
