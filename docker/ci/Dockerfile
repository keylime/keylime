##############################################################################
# keylime TPM 2.0 Dockerfile
#
# This file is for automatic test running of Keylime and rust-keylime.
# It is not recommended for use beyond testing scenarios.
##############################################################################

FROM quay.io/fedora/fedora@sha256:8ee615865d2a61745fa23d2608ddc8d17a4c9be58a199c8cd8ee64037a016f9a
MAINTAINER Luke Hinds <lhinds@redhat.com>
LABEL version="1.2.0" description="Keylime - Bootstrapping and Maintaining Trust in the Cloud"

# environment variables
ARG BRANCH=master
ENV container docker
ENV HOME /root
ENV KEYLIME_HOME ${HOME}/keylime
ENV TPM_HOME ${HOME}/swtpm2
COPY dbus-policy.conf /etc/dbus-1/system.d/

# Packaged dependencies
ENV PKGS_DEPS="automake \
clang clang-devel \
createrepo_c \
czmq-devel \
dbus \
dbus-daemon \
dbus-devel \
dnf-plugins-core \
efivar-devel \
gcc \
git \
glib2-devel \
glib2-static \
gnulib \
iproute \
kmod \
libarchive-devel \
libselinux-python3 \
libtool \
libtpms \
llvm llvm-devel \
make \
openssl \
openssl-devel \
pkg-config \
procps \
python3-cryptography \
python3-dbus \
python3-devel \
python3-gpg \
python3-pip \
python3-requests \
python3-setuptools \
python3-sqlalchemy \
python3-tornado \
python3-virtualenv \
python3-yaml \
python3-zmq \
redhat-rpm-config \
rpm-build \
rpm-sign \
rust clippy cargo \
swtpm \
swtpm-tools \
tpm2-abrmd \
tpm2-openssl \
tpm2-tools \
tpm2-tss \
tpm2-tss-devel \
uthash-devel \
wget \
which \
xxd"

RUN dnf makecache && \
  dnf -y install $PKGS_DEPS && \
  dnf clean all && \
  rm -rf /var/cache/dnf/*

# Install cargo dependencies
RUN cargo install cargo-tarpaulin

# Move tarpaulin to be available for all users
RUN cp /root/.cargo/bin/cargo-tarpaulin /usr/bin
