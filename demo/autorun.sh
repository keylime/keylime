#!/bin/sh
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################


# Start web server
#nginx


# Pause for demo effect
#sleep 0.25m


# Set up new protected space on web server
#cryptsetup luksFormat /var/www/html/payload.enc keyfile.txt
#cryptsetup luksOpen /var/www/html/payload.enc encdrive --key-file keyfile.txt
#mkfs.ext4 -j /dev/mapper/encdrive


# Decrypt and mount protected web server data
mkdir -p /var/www/html/payload/
cryptsetup luksOpen /var/www/html/payload.enc encdrive --key-file keyfile.txt
mount /dev/mapper/encdrive /var/www/html/payload/


# Unmount encrypted space
#umount /var/www/html/payload
#cryptsetup luksClose encdrive
#nginx -s quit
