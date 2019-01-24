##############################################################################
# python-keylime Test Dockerfile
#
# This file is for automatic test running of Keylime
# Note: This needs to be run with `----privileged`
#       For the reason that it requires CAP_SYS_ADMIN (for secure.mount)
#       A workaround will be tried using a host mount
# To build / run:
# docker build -t keylime .
# docker run -t -i --privileged keylime /bin/sh -c 'cd /root/python-keylime/test; ./run_tests.sh'
##############################################################################

FROM fedora:28
MAINTAINER Luke Hinds <lukehinds@gmail.com>
LABEL version="0.1" description="Keylime - Bootstrapping and Maintaining Trust in the Cloud"

# environment variables
ARG BRANCH=master

ENV HOME /root
ENV KEYLIME_HOME ${HOME}/python-keylime
ENV TPM_HOME ${HOME}/tpm4720-keylime

# Packaged dependencies
RUN dnf -y update
RUN dnf -y install git \
           golang \
           python-devel \
           python-pip \
           python-setuptools \
           python-tornado \
           python-virtualenv \
           python2-zmq \
           procps \
           openssl-devel \
           libtool \
           gcc \
           make \
           automake \
           m2crypto \
           redhat-rpm-config \
           libselinux-python
RUN dnf clean all

# Commands to clone and install
#RUN mkdir -p ${KEYLIME_HOME}
#RUN git clone https://github.com/mit-ll/python-keylime ${KEYLIME_HOME}
RUN git clone https://github.com/mit-ll/tpm4720-keylime ${TPM_HOME}
WORKDIR ${TPM_HOME}/tpm
RUN make -f makefile-tpm
RUN install -c tpm_server /usr/local/bin/tpm_server
WORKDIR ${TPM_HOME}/libtpm
RUN ./autogen
RUN ./configure
RUN /usr/bin/make
RUN /usr/bin/make install
WORKDIR ${TPM_HOME}/scripts
RUN /usr/bin/install -c tpm_serverd /usr/local/bin/tpm_serverd
RUN /usr/bin/install -c init_tpm_server /usr/local/bin/init_tpm_server
RUN /usr/local/bin/tpm_serverd
RUN /usr/local/bin/init_tpm_server
