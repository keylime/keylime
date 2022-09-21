#!/bin/bash

# You can specify the path of the local keylime repository as argument
# of this script or using the KEYLIME_REPO_PATH environment variable.
# The default value is one directory above where this script is located.
REPO=${KEYLIME_REPO_PATH:-${1:-$(realpath "$(dirname "$(readlink -f "$0")")/../")}}

# keylime images
tpmimage="quay.io/keylime/keylime-ci"
tpmtag="latest"

echo -e "Fetching Keylime CI container"

docker pull ${tpmimage}:${tpmtag}

echo -e "Running Keylime's test suite"

container_id=$(mktemp)
docker run --detach --user root --env KEYLIME_TEST='true' --env RUST_TEST=1\
    -v $REPO:/root/keylime:Z \
    --mount type=tmpfs,destination=/var/lib/keylime/,tmpfs-mode=1770 \
    -it ${tpmimage}:${tpmtag} >> ${container_id}
# run the Keylime test suite
docker exec -u root -it --tty "$(cat ${container_id})" \
    /bin/bash /root/keylime/.ci/test_wrapper.sh
docker stop "$(cat ${container_id})"
docker rm "$(cat ${container_id})"
