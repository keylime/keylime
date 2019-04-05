#!/bin/bash
##########################################################################################
#
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in
# this material are those of the author(s) and do not necessarily reflect the views of the
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2016 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
# above. Use of this work other than as specifically authorized by the U.S. Government may
# violate any copyrights that exist in this work.
#
##########################################################################################

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
    echo "Usage:  `basename $0` list.txt [hash-algo]" >&2
    exit $NOARGS;
fi

if [ $# -eq 2 ]
then
    ALGO=$2
else
    ALGO=sha1sum
fi

OUTPUT=$(readlink -f $1)
rm -f $OUTPUT


echo "Writing whitelist to $OUTPUT with $ALGO..."

# Add all appropriate files under root FS to whitelist
cd /
find `ls / | grep -v "\bsys\b\|\brun\b\|\bproc\b\|\blost+found\b\|\bdev\b\|\bmedia\b\|\bsnap\b\|mnt"` \( -fstype rootfs -o -xtype f -type l -o -type f \) -uid 0 -exec $ALGO '/{}' >> $OUTPUT \;

# Create staging area for init ram images
rm -rf /tmp/ima/
mkdir -p /tmp/ima

# Iterate through init ram disks and add files to whitelist
echo "Creating whitelist for init ram disk"
for i in `ls /boot/initr*`
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

    find -type f -exec sha1sum "./{}" \; | sed "s| \./\./| /|" >> $OUTPUT
done

# Clean up
rm -rf /tmp/ima
