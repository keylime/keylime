#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

# Configure the installer here
INITRAMFS_TOOLS_GIT=https://salsa.debian.org/kernel-team/initramfs-tools.git
INITRAMFS_TOOLS_VER="master"


# Grabs Debian's initramfs_tools from Git repo if no other options exist
if [[ ! `command -v unmkinitramfs` && ! -x "/usr/lib/dracut/skipcpio" ]] ; then
    # Create temp dir for pulling in initramfs-tools
    TMPDIR=`mktemp -d` || exit 1
    echo "INFO: Downloading initramfs-tools: $TMPDIR"

    # Clone initramfs-tools repo
    pushd $TMPDIR
    git clone $INITRAMFS_TOOLS_GIT initramfs-tools
    pushd initramfs-tools
    git checkout $INITRAMFS_TOOLS_VER
    popd # $TMPDIR
    popd

    shopt -s expand_aliases
    alias unmkinitramfs=$TMPDIR/initramfs-tools/unmkinitramfs
fi


if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

if [ $# -lt 1 ]
then
    echo "No arguments provided" >&2
    echo "Usage:  `basename $0` -o [filename] -h [hash-algo]" >&2
    exit $NOARGS;
fi

ALGO=sha1sum

while getopts ":o:h:" opt; do
    case $opt in
        o)
            OUTPUT=$(readlink -f $OPTARG)
            rm -f $OUTPUT
            ;;
        h)
            ALGO=$OPTARG
            ;;
    esac
done

if [ ! "$OUTPUT" ]
then
    echo "Missing argument for -o" >&2;
    echo "Usage: $0 -o [filename] -h [hash-algo]" >&2;
    exit 1
fi


# Where to look for initramfs image
INITRAMFS_LOC="/boot/"
if [ -d "/ostree" ]; then
    # If we are on an ostree system change where we look for initramfs image
    loc=$(grep -E "/ostree/[^/]([^/]*)" -o /proc/cmdline | head -n 1 | cut -d / -f 3)
    INITRAMFS_LOC="/boot/ostree/${loc}/"
fi


echo "Writing allowlist to $OUTPUT with $ALGO..."

# Add boot_aggregate from /sys/kernel/security/ima/ascii_runtime_measurements (IMA Log) file.
# The boot_aggregate measurement is always the first line in the IMA Log file.
# The format of the log lines is the following:
#     <PCR_ID> <PCR_Value> <IMA_Template> <File_Digest> <File_Name> <File_Signature>
# File_Digest may start with the digest algorithm specified (e.g "sha1:", "sha256:") depending on the template used.
head -n 1 /sys/kernel/security/ima/ascii_runtime_measurements | awk '{ print $4 "  boot_aggregate" }' | sed 's/.*://' >> $OUTPUT

# Add all appropriate files under root FS to allowlist
cd /
find `ls / | grep -v "\bsys\b\|\brun\b\|\bproc\b\|\blost+found\b\|\bdev\b\|\bmedia\b\|\bsnap\b\|mnt"` \( -fstype rootfs -o -xtype f -type l -o -type f \) -uid 0 -exec $ALGO '/{}' >> $OUTPUT \;

# Create staging area for init ram images
rm -rf /tmp/ima/
mkdir -p /tmp/ima

# Iterate through init ram disks and add files to allowlist
echo "Creating allowlist for init ram disk"
for i in `ls ${INITRAMFS_LOC}/initr*`
do
    echo "extracting $i"
    mkdir -p /tmp/ima/$i-extracted
    cd /tmp/ima/$i-extracted

    # platform-specific handling of init ram disk images
    if [[ `command -v unmkinitramfs` ]] ; then
        mkdir -p /tmp/ima/$i-extracted-unmk
        unmkinitramfs $i /tmp/ima/$i-extracted-unmk
        if [[ -d "/tmp/ima/$i-extracted-unmk/main/" ]] ; then
            cp -r /tmp/ima/$i-extracted-unmk/main/. /tmp/ima/$i-extracted
        else
            cp -r /tmp/ima/$i-extracted-unmk/. /tmp/ima/$i-extracted
        fi
    elif [[ -x "/usr/lib/dracut/skipcpio" ]] ; then
        /usr/lib/dracut/skipcpio $i | gunzip -c | cpio -i -d 2> /dev/null
    else
        echo "ERROR: No tools for initramfs image processing found!"
        break
    fi

    find -type f -exec $ALGO "./{}" \; | sed "s| \./\./| /|" >> $OUTPUT
done

# Clean up
rm -rf /tmp/ima
