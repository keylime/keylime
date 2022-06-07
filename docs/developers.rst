===================
KeyLime Development
===================

Contributing
------------

When contributing any keylime repository, please first discuss the change you wish
to make via an issue in the relevant repository for your change or email to the
`keylime mailing list <https://groups.io/g/keylime>`_

Pull Request Process
~~~~~~~~~~~~~~~~~~~~

1. Create an `issue <https://github.com/keylime/keylime/issues>`_
   outlining the fix or feature.
2. Fork the keylime repository to your own github account and clone it locally.
3. Hack on your changes.
4. Update the README.md or documentation with details of changes to any
   interface, this includes new environment variables, exposed ports, useful
   file locations, CLI parameters and configuration values.
5. Add and commit your changes with some descriptive text on the nature of the
   change / feature in your commit message. Also reference the issue raised at
   [1] as follows: `Fixes #45`. See `the following link <https://help.github.com/articles/closing-issues-using-keywords>`_
   for more message types
6. Ensure that CI passes, if it fails, fix the failures.
7. Every pull request requires a review from the `core keylime team <https://github.com/orgs/keylime/teams/core>`_
8. If your pull request consists of more than one commit, please squash your
   commits as described in see :ref:`squash-commits`.

Commit Message Guidelines
-------------------------

We follow the commit formatting recommendations found on `Chris Beams' How to Write a Git Commit Message article <https://chris.beams.io/posts/git-commit>`_.

Well formed commit messages not only help reviewers understand the nature of
the Pull Request, but also assists the release process where commit messages
are used to generate release notes.

A good example of a commit message would be as follows::

  Summarize changes in around 50 characters or less

  More detailed explanatory text, if necessary. Wrap it to about 72
  characters or so. In some contexts, the first line is treated as the
  subject of the commit and the rest of the text as the body. The
  blank line separating the summary from the body is critical (unless
  you omit the body entirely); various tools like `log`, `shortlog`
  and `rebase` can get confused if you run the two together.

  Explain the problem that this commit is solving. Focus on why you
  are making this change as opposed to how (the code explains that).
  Are there side effects or other unintuitive consequences of this
  change? Here's the place to explain them.

  Further paragraphs come after blank lines.

  - Bullet points are okay, too

  - Typically a hyphen or asterisk is used for the bullet, preceded
    by a single space, with blank lines in between, but conventions
    vary here

  If you use an issue tracker, put references to them at the bottom,
  like this:

  Resolves: #123
  See also: #456, #789

Note the `Resolves #123` tag, this references the issue raised and allows us to
ensure issues are associated and closed when a pull request is merged.

Please refer to `the github help page on message types <https://help.github.com/articles/closing-issues-using-keywords>`_
for a complete list of issue references.

.. _squash-commits:

Squash Commits
--------------

Should your pull request consist of more than one commit (perhaps due to
a change being requested during the review cycle), please perform a git squash
once a reviewer has approved your pull request.

A squash can be performed as follows. Let's say you have the following commits::

   initial commit
   second commit
   final commit

Run the command below with the number set to the total commits you wish to
squash (in our case 3 commits)::

   git rebase -i HEAD~3

You default text editor will then open up and you will see the following::

   pick eb36612 initial commit
   pick 9ac8968 second commit
   pick a760569 final commit

   # Rebase eb1429f..a760569 onto eb1429f (3 commands)

We want to rebase on top of our first commit, so we change the other two commits
to `squash`::

   pick eb36612 initial commit
   squash 9ac8968 second commit
   squash a760569 final commit

After this, should you wish to update your commit message to better summarise
all of your pull request, run::

   git commit --amend

You will then need to force push (assuming your initial commit(s) were posted
to github)::

   git push origin your-branch --force

Docker Development Environment
------------------------------

The following is a guide to mounting your local repository as a Docker volume
and performing a test run using a TPM simulator. This will replicate the same
test that occurs within the KeyLime CI gate for keylime.

This requires a working installation of Docker. See your distributions guide on
how to set that up.

As an example, on Fedora 29::

    sudo dnf -y install dnf-plugins-core
    sudo dnf install docker-ce docker-ce-cli containerd.io
    sudo usermod -aG docker $USER
    sudo systemctl enable docker
    sudo systemctl start docker

Note: login and out of your shell, if you want to run docker as `$USER`

Save the following script to your local machine (tip: create an alias to call the
script in an easy to remember way)::

    #!/bin/bash

    # Your local keylime (you should likely change this)
    REPO="/home/${USER}/keylime"

    # keylime images
    tpm12image="lukehinds/keylime-ci-tpm12"
    tpm12tag="v550"
    tpm20image="lukehinds/keylime-ci-tpm20"
    tpm20tag="v301"

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
