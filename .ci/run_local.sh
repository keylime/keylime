#!/bin/bash

# keylime images
tpmimage="quay.io/keylime/keylime-ci"
tpmtag="latest"

echo -e "Fetching Keylime CI container"

docker pull ${tpmimage}:${tpmtag}

echo -e "Running Keylime's test suite"

container_id=$(mktemp)
docker run --detach --user root --env KEYLIME_TEST='true' \
    --mount type=tmpfs,destination=/var/lib/keylime/,tmpfs-mode=1770 \
    -it ${tpmimage}:${tpmtag} >> ${container_id}
# clone the Keylime repository
docker exec -u root -it --tty "$(cat ${container_id})" \
    git clone https://github.com/keylime/keylime.git /root/keylime
# run the Keylime test suite
docker exec -u root -it --tty "$(cat ${container_id})" \
    /bin/bash /root/keylime/.ci/test_wrapper.sh
docker stop "$(cat ${container_id})"
docker rm "$(cat ${container_id})"
