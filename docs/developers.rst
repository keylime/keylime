===================
KeyLime Development
===================

Contributing
------------

When contributing to this repository, please first discuss the change you wish
to make via an issue in the relevant repository for your change or email to the
[keylime mailing list](https://groups.io/g/keylime).

## Pull Request Process

1. Create an [issue](https://github.com/keylime/python-keylime/issues)
   outlining the fix or feature.
2. Fork the keylime repository to your own github account and clone it locally.
3. Hack on your changes.
4. Update the README.md or documentation with details of changes to any
   interface, this includes new environment variables, exposed ports, useful
   file locations, CLI parameters and configuration values.
5. Add and commit your changes with some descriptive text on the nature of the
   change / feature in your commit message. Also reference the issue raised at
   [1] as follows: `Fixes #45`. See [here](https://help.github.com/articles/closing-issues-using-keywords/)
   for more message types
6. Ensure that CI passes, if it fails, fix the failures.
7. Every pull request requires a review from the [core keylime team](https://github.com/orgs/keylime/teams/core)

Docker Development Environment
------------------------------

The following is a guide to mounting your local repository as a Docker volume
and performing a test run using a TPM simulator. This will replicate the same
test that occurs within the KeyLime CI gate for python-KeyLime

* ToDo: Also run rust checks

This requires a working installation of Docker. See your distributions guide on
how to set that up.

As an example, on Fedora 29:

```
sudo dnf -y install dnf-plugins-core
sudo dnf install docker-ce docker-ce-cli containerd.io
sudo usermod -aG docker $USER
sudo systemctl enable docker
sudo systemctl start docker
```

Note: login and out of your shell, if you want to run docker as `$USER`

Save the following script to your local machine (tip: create an alias to call the
script in an easy to remember way)

```
#!/bin/bash

# Your local python-keylime (you should likely change this)
REPO="/home/${USER}/python-keylime"

# keylime images
tpm12image="lukehinds/keylime-ci-tpm12"
tpm12tag="v300"
tpm20image="lukehinds/keylime-ci-tpm20"
tpm20tag="v301"

echo -e "Grabbing latest images"

docker pull ${tpm12image}:${tpm12tag}
docker pull ${tpm20image}:${tpm20tag}

function tpm1 {
    container_id=$(mktemp)
    docker run --detach --privileged \
        -v $REPO:/root/python-keylime \
        -it ${tpm12image}:${tpm12tag} >> ${container_id}
    docker exec -u 0 -it --tty "$(cat ${container_id})" \
        /bin/sh -c 'cd /root/python-keylime/test; chmod +x ./run_tests.sh; ./run_tests.sh -s openssl'
    docker stop "$(cat ${container_id})"
    docker rm "$(cat ${container_id})"
}

function tpm2 {
    container_id=$(mktemp)
    docker run --detach --privileged \
        -v $REPO:/root/python-keylime \
        -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
        -it ${tpm20image}:${tpm20tag} >> ${container_id}
    docker exec -u 0 -it --tty "$(cat ${container_id})" \
        /bin/bash /root/python-keylime/.ci/test_wrapper.sh
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
```
