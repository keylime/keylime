##############################################################################
# keylime TPM 2.0 Dockerfile
#
# This file is for automatic test running of Keylime.
# It is not recommended for use beyond testing scenarios.
##############################################################################

FROM fedora:29
MAINTAINER Luke Hinds <lhinds@redhat.com>
LABEL version="3.0.0" description="Keylime - Bootstrapping and Maintaining Trust in the Cloud"

ENV container docker
# environment variables
ARG BRANCH=master

ENV container docker
ENV HOME /root
ENV KEYLIME_HOME ${HOME}/keylime
ENV TPM_HOME ${HOME}/swtpm2
ENV TPM2_TSS ${HOME}/tpm2-tss
ENV TPM2_TOOLS ${HOME}/tpm2-tools
ENV TPM2_ABRMD ${HOME}/tpm2-abrmd
RUN useradd --system --user-group tss

# Packaged dependencies
RUN dnf -y update
RUN dnf -y install dnf-plugins-core --allowerasing
RUN dnf -y builddep tpm2-tss
RUN dnf -y builddep tpm2-tools
RUN dnf -y install git \
           dbus-devel \
           golang \
           openssl-devel \
           python-devel \
           python-pip \
           python-setuptools \
           python-tornado \
           python-virtualenv \
           python2-zmq \
           python-yaml \
           procps \
           libtool \
           tpm2-abrmd \
           gcc \
           make \
           automake \
           m2crypto \
           redhat-rpm-config \
           libselinux-python \
           gnulib \
           glib2-devel \
           glib2-static \
           uthash-devel \
           wget \
           which

RUN dnf clean all

RUN cd "/lib/systemd/system/sysinit.target.wants/"; \
    for i in *; do [ $i = systemd-tmpfiles-setup.service ] || rm -f "$i"; done

RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
    /etc/systemd/system/*.wants/* \
    /lib/systemd/system/local-fs.target.wants/* \
    /lib/systemd/system/sockets.target.wants/*udev* \
    /lib/systemd/system/sockets.target.wants/*initctl* \
    /lib/systemd/system/basic.target.wants/* \
    /lib/systemd/system/anaconda.target.wants/*

RUN systemctl set-default multi-user.target
ENV init /lib/systemd/systemd

# TPM-TSS

RUN git clone https://github.com/tpm2-software/tpm2-tss.git ${TPM2_TSS}
WORKDIR ${TPM2_TSS}
RUN ./bootstrap
RUN ./configure --prefix=/usr --disable-doxygen-doc
RUN make
RUN make install

# TPM2-TOOLS
RUN git clone https://github.com/keylime/tpm2-tools.git ${TPM2_TOOLS}
WORKDIR ${TPM2_TOOLS}
RUN ./bootstrap
RUN SAPI_CFLAGS=' ' SAPI_LIBS='-ltss2-sys -L/usr/lib/' ./configure --prefix=/usr/local
RUN make
RUN make install

# Enable TPM-ABRMD service
RUN git clone https://github.com/tpm2-software/tpm2-abrmd.git ${TPM2_ABRMD}
WORKDIR ${TPM2_ABRMD}
RUN ./bootstrap
RUN TSS2_SYS_CFLAGS=' ' TSS2_SYS_LIBS='-ltss2-sys -L/usr/lib/' ./configure --prefix=/usr
RUN make
RUN make install
RUN ldconfig

# Build and install TPM 2.0 simulator
WORKDIR ${TPM_HOME}
RUN wget --content-disposition http://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1119.tar.gz/download
RUN tar -zxvf ibmtpm1119.tar.gz
WORKDIR ${TPM_HOME}/src
RUN make
RUN install -c tpm_server /usr/local/bin/tpm_server

VOLUME [ "/sys/fs/cgroup" ]

ENTRYPOINT ["/lib/systemd/systemd"]
