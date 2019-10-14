#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo -e "Please run as the root user"
   exit 1
fi

read -p "Name for vtpm vm: " vm_name
echo -e "Path to TPM"
echo -e "For testing of vTPM with tmpfs, use /var/lib/keylime (the folder needs to exist, i.e. Keylime should be installed at this point)"
echo -e "For general testing, you can for example use /tmp/tpm0"
read -p ": " tpm_path

echo -e "Updating Packages"
dnf update -y

echo -e "Install virtualization package group and deps"
dnf install -y @virtualization
dnf -y install make \
                libguestfs-tools-c \
                libseccomp-devel \
                wget \
                libtasn1-devel \
                expect \
                socat \
                python3-twisted \
                fuse-devel glib2-devel \
                gnutls \
                gnutls-devel \
                gnutls-utils \
                tpm-tools \
                tpm2-tools \
                openssl-devel \
                git \
                libtool \
                autoconf \
                libtpms \
                swtpm \
                swtpm-tools

systemctl enable libvirtd
systemctl start libvirtd

if [[ $tpm_path == "/var/lib/keylime" ]]; then
	mount -t tmpfs -o size=10m,mode=0700 tmpfs /var/lib/keylime/
else
	mkdir -p ${tpm_path}
fi

swtpm socket --tpmstate dir=${tpm_path} --ctrl type=unixio,path=${tpm_path}/swtpm-sock --log level=20 &

wget -c https://download.fedoraproject.org/pub/fedora/linux/releases/30/Cloud/x86_64/images/Fedora-Cloud-Base-30-1.2.x86_64.qcow2 -O /var/lib/libvirt/images/fedora30.qcow2

cd /var/lib/libvirt/images

qemu-img create -f qcow2 -b fedora30.qcow2 ${vm_name}.qcow2
virt-customize -a ${vm_name}.qcow2  --root-password password:root --uninstall cloud-init \
          --run-command 'sed -i s/^SELINUX=.*$/SELINUX=disabled/ /etc/selinux/config'

virt-install --ram 2048 --vcpus 2 --os-variant rhel7.0 \
     --disk path=/var/lib/libvirt/images/${vm_name}.qcow2,format=qcow2,bus=virtio,cache=none,device=disk \
     --import --noautoconsole --graphics vnc --network network:default --name ${vm_name} \
     --tpm emulator,model=tpm-tis,version=2.0,path=${tpm_path}/swtpm_sock

echo -e "To login, use virsh console ${vm_name}"
echo -e "login: root"
echo -e "password: root"
