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

cd /
find `ls / | grep -v "\bsys\b\|\brun\b\|\bproc\b\|\blost+found\b\|\bdev\b\|\bmedia\b\|\bsnap\b\|mnt"` \( -fstype rootfs -o -xtype f -type l -o -type f \) -uid 0 -exec $ALGO '/{}' >> $OUTPUT \;

rm -rf /tmp/ima/
mkdir -p /tmp/ima

echo "Creating whitelist for initrd..."
for i in `ls /boot/initrd*`
do
    echo "extracting $i"
    mkdir -p /tmp/ima/$i-extracted
    cd /tmp/ima/$i-extracted
    
    # Try standard gzip encoding
    gzip -dc $i | cpio -id 2> /dev/null
    
    # if that fails, try xz
    if [ $? -ne 0 ]
    then
        xz -dc $i | cpio -id 2> /dev/null
    fi
    
    # If that fails, maybe it's in raw CPIO format?
    if [ $? -ne 0 ]
    then
        cat $i | cpio -id 2> /dev/null
    fi
    
    find -type f -exec sha1sum "./{}" \; | sed "s| \./\./| /|" >> $OUTPUT
done
rm -rf /tmp/ima
