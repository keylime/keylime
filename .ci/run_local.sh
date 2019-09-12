#!/bin/bash

# Your local keylime (you should likely change this)
REPO="/home/${USER}/keylime"

# keylime images
tpm12image="lukehinds/keylime-ci-tpm12"
tpm12tag="v500"
tpm20image="lukehinds/keylime-ci-tpm20"
tpm20tag="v501"

echo -e "Grabbing latest images"

docker pull ${tpm12image}:${tpm12tag}
docker pull ${tpm20image}:${tpm20tag}

function tpm1 {
    container_id=$(mktemp)
    docker run --detach --privileged \
        -v $REPO:/root/keylime \
        -it ${tpm12image}:${tpm12tag} >> ${container_id}
    docker exec -u 0 -it --tty "$(cat ${container_id})" \
        /bin/sh -c 'cd /root/keylime/test; chmod +x ./run_tests.sh; ./run_tests.sh -s openssl'
    docker stop "$(cat ${container_id})"
    docker rm "$(cat ${container_id})"
}

function tpm2 {
    container_id=$(mktemp)
    docker run --detach --privileged \
        -v $REPO:/root/keylime \
        -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
        -it ${tpm20image}:${tpm20tag} >> ${container_id}
    docker exec -u 0 -it --tty "$(cat ${container_id})" \
        /bin/bash /root/keylime/.ci/test_wrapper.sh
    docker stop "$(cat ${container_id})"
    docker rm "$(cat ${container_id})"
}

while true; do
    echo -e ""
    read -p "Do you wish to test against TPM1.2(a) / TPM 2.0(b) or q(quit): " abq
    case $abq in
        [a]* ) tpm1;;
        [b]* ) tpm2;;
        [q]* ) exit;;
        * ) echo "Please answer 1, 2 q(quit)";;
    esac
done
