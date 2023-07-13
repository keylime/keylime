#!/usr/bin/env bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

function announce {
    # 1 - MESSAGE

	MESSAGE=$(echo "${1}" | tr '\n' ' ')
	MESSAGE=$(echo $MESSAGE | sed "s/\t\t*/ /g")

	echo "==> $(date) - ${0} - $MESSAGE"
}

function valid_algo {
        local algo=$1

        [[ " ${ALGO_LIST[@]} " =~ " ${algo} " ]]
}

# Configure the installer here
INITRAMFS_TOOLS_GIT=https://salsa.debian.org/kernel-team/initramfs-tools.git
INITRAMFS_TOOLS_VER="master"

WORKING_DIR=$(readlink -f "$0")
WORKING_DIR=$(dirname "$WORKING_DIR")

# All defaults
ALGO=sha1sum
INITRAMFS_LOC="/boot/"
INITRAMFS_STAGING_DIR=/tmp/ima/
INITRAMFS_TOOLS_DIR=/tmp/initramfs-tools
BOOT_AGGREGATE_LOC="/sys/kernel/security/ima/ascii_runtime_measurements"
ROOTFS_LOC="/"
EXCLUDE_LIST="none"
SKIP_PATH="none"
ALGO_LIST=("sha1sum" "sha256sum" "sha512sum")

# Grabs Debian's initramfs_tools from Git repo if no other options exist
if [[ ! `command -v unmkinitramfs` && ! -x "/usr/lib/dracut/skipcpio" ]] ; then
    # Create temp dir for pulling in initramfs-tools
    announce "INFO: Downloading initramfs-tools: $INITRAMFS_TOOLS_DIR"

    mkdir -p $INITRAMFS_TOOLS_DIR
    # Clone initramfs-tools repo
    pushd $INITRAMFS_TOOLS_DIR > /dev/null 2>&1
    git clone $INITRAMFS_TOOLS_GIT initramfs-tools > /dev/null 2>&1
    pushd initramfs-tools > /dev/null 2>&1
    git checkout $INITRAMFS_TOOLS_VER > /dev/null 2>&1
    popd > /dev/null 2>&1
    popd > /dev/null 2>&1

    shopt -s expand_aliases
    alias unmkinitramfs=$INITRAMFS_TOOLS_DIR/initramfs-tools/unmkinitramfs

    which unmkinitramfs > /dev/null 2>&1 || exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

USAGE=$(cat <<-END
    Usage: $0 -o/--output_file FILENAME [-a/--algo ALGO] [-x/--ramdisk-location PATH] [-y/--boot_aggregate-location PATH] [-z/--rootfs-location PATH] [-e/--exclude_list FILENAME] [-s/--skip-path PATH] [-h/--help]

    optional arguments:
        -a/--algo                    (checksum algorithm to be used, default: $ALGO)
        -x/--ramdisk-location        (path to initramdisk, default: $INITRAMFS_LOC, set to "none" to skip)
        -y/--boot_aggregate-location (path for IMA log, used for boot aggregate extraction, default: $BOOT_AGGREGATE_LOC, set to "none" to skip)
        -z/--rootfs-location         (path to root filesystem, default: $ROOTFS_LOC, cannot be skipped)
        -e/--exclude_list            (filename containing a list of paths to be excluded (i.e., verifier will not try to match checksums, default: $EXCLUDE_LIST)
        -s/--skip-path               (comma-separated path list, files found there will not have checksums calculated, default: $SKIP_PATH)
        -h/--help                    (show this message and exit)
END
)

while [[ $# -gt 0 ]]
do
    key="$1"

    case $key in
        -a|--algo)
        ALGO="$2"
        shift
        ;;
        -a=*|--algo=*)
        ALGO=$(echo $key | cut -d '=' -f 2)
        ;;
        -x|--ramdisk-location)
        INITRAMFS_LOC="$2"
        shift
        ;;
        -x=*|--ramdisk-location=*)
        INITRAMFS_LOC=$(echo $key | cut -d '=' -f 2)
        ;;
        -y|--boot_aggregate-location)
        BOOT_AGGREGATE_LOC=$2
        shift
        ;;
        -y=*|--boot_aggregate-location=*)
        BOOT_AGGREGATE_LOC=$(echo $key | cut -d '=' -f 2)
        ;;
        -z|--rootfs-location)
        ROOTFS_LOC=$2
        shift
        ;;
        -z=*|--rootfs-location=*)
        ROOTFS_LOC=$(echo $key | cut -d '=' -f 2)
        ;;
        -e|--exclude_list)
        EXCLUDE_LIST=$2
        shift
        ;;
        -e=*|--exclude_list=*)
        EXCLUDE_LIST=$(echo $key | cut -d '=' -f 2)
        ;;        
        -o=*|--output_file=*)
        OUTPUT=$(echo $key | cut -d '=' -f 2)
        ;;
        -o|--output_file)
        OUTPUT=$2
        shift
        ;;
        -s=*|--skip-path=*)
        SKIP_PATH=$(echo $key | cut -d '=' -f 2)
        ;;
        -s|--skip-path)
        SKIP_PATH=$2
        shift
        ;;        
        -h|--help)
        printf "%s\n" "$USAGE"
        exit 0
        shift
        ;;
        *)
                # unknown option
        ;;
        esac
        shift
done

if ! valid_algo $ALGO
then
    echo "Invalid hash function argument: pick from \"${ALGO_LIST[@]}\""
    exit 1
fi

if [[ -z $OUTPUT ]]
then
    printf "%s\n" "$USAGE"
    exit 1
fi

rm -rf ${OUTPUT}_allowlist
rm -rf ${OUTPUT}

announce "Writing allowlist to $OUTPUT with $ALGO..."

if [[ $BOOT_AGGREGATE_LOC != "none" ]]
then
    announce "    Adding boot agregate from $BOOT_AGGREGATE_LOC on allowlist $OUTPUT..."
# Add boot_aggregate from /sys/kernel/security/ima/ascii_runtime_measurements (IMA Log) file.
# The boot_aggregate measurement is always the first line in the IMA Log file.
# The format of the log lines is the following:
#     <PCR_ID> <PCR_Value> <IMA_Template> <File_Digest> <File_Name> <File_Signature>
# File_Digest may start with the digest algorithm specified (e.g "sha1:", "sha256:") depending on the template used.
    head -n 1 $BOOT_AGGREGATE_LOC | awk '{ print $4 "  boot_aggregate" }' | sed 's/.*://' >> ${OUTPUT}_allowlist
else
    announce "    Skipping boot aggregate..."
fi

announce "    Adding all appropriate files from $ROOTFS_LOC on allowlist $OUTPUT..."
# Add all appropriate files under root FS to allowlist
pushd $ROOTFS_LOC > /dev/null 2>&1
ls . | wc -l
BASE_EXCLUDE_DIRS="\bsys\b\|\brun\b\|\bproc\b\|\blost+found\b\|\bdev\b\|\bmedia\b\|\bsnap\b\|\bmnt\b\|\bvar\b\|\btmp\b"
ROOTFS_FILE_LIST=$(ls | grep -v $BASE_EXCLUDE_DIRS)
if [[ $SKIP_PATH != "none" ]]
then
    SKIP_PATH=$(echo $SKIP_PATH | sed -e "s#^$ROOTFS_LOC##g" -e "s#,$ROOTFS_LOC##g" -e "s#,#\\\|#g")
    ROOTFS_FILE_LIST=$(echo "$ROOTFS_FILE_LIST" | grep -v "$SKIP_PATH")
fi
find $ROOTFS_FILE_LIST \( -fstype rootfs -o -xtype f -type l -o -type f \) -uid 0 -exec $ALGO "$ROOTFS_LOC/{}" >> ${OUTPUT}_allowlist \;
popd > /dev/null 2>&1

# Create staging area for init ram images
rm -rf $INITRAMFS_STAGING_DIR
mkdir -p $INITRAMFS_STAGING_DIR

if [[ $INITRAMFS_LOC != "none" ]]
then
    # Where to look for initramfs image
    if [[ -d "/ostree" ]] 
    then
        X=$INITRAMFS_LOC
        # If we are on an ostree system change where we look for initramfs image
        loc=$(grep -E "/ostree/[^/]([^/]*)" -o /proc/cmdline | head -n 1 | cut -d / -f 3)
        INITRAMFS_LOC="/boot/ostree/${loc}/"
        announce "    The location of initramfs was overrode from \"${X}\" to \"$INITRAMFS_LOC\""
    fi

    announce "     Creating allowlist for init ram disks found under \"$INITRAMFS_LOC\"..."
    for i in $(ls ${INITRAMFS_LOC}/initr* 2> /dev/null)
    do
        announce "            extracting $i"
        mkdir -p $INITRAMFS_STAGING_DIR/$i-extracted
        cd $INITRAMFS_STAGING_DIR/$i-extracted

        # platform-specific handling of init ram disk images
        if [[ `command -v unmkinitramfs` ]] ; then
            mkdir -p $INITRAMFS_STAGING_DIR/$i-extracted-unmk
            unmkinitramfs $i $INITRAMFS_STAGING_DIR/$i-extracted-unmk
            if [[ -d "$INITRAMFS_STAGING_DIR/$i-extracted-unmk/main/" ]] ; then
                cp -r $INITRAMFS_STAGING_DIR/$i-extracted-unmk/main/. /tmp/ima/$i-extracted
            else
                cp -r $INITRAMFS_STAGING_DIR/$i-extracted-unmk/. /tmp/ima/$i-extracted
            fi
        elif [[ -x "/usr/lib/dracut/skipcpio" ]] ; then
            /usr/lib/dracut/skipcpio $i | gunzip -c | cpio -i -d 2> /dev/null
        else
            echo "ERROR: No tools for initramfs image processing found!"
            break
        fi

        find -type f -exec $ALGO "./{}" \; | sed "s| \./\./| /|" >> ${OUTPUT}_allowlist
    done
fi

# A bit of cleanup on the resulting file (among other problems, sha256sum might output a hash with the prefix '//')
sed -i "s^ //^ /^g"  ${OUTPUT}_allowlist 
sed -i 's^"\\\\^"^g' ${OUTPUT}_allowlist

# Convert to runtime policy
announce "Converting created allowlist to Keylime runtime policy"
CONVERT_CMD_OPTS="--allowlist ${OUTPUT}_allowlist --output_file $OUTPUT"

[ -f $EXCLUDE_LIST ] && CONVERT_CMD_OPTS="$CONVERT_CMD_OPTS --excludelist $EXCLUDE_LIST"

python3 $WORKING_DIR/../keylime/cmd/convert_runtime_policy.py $CONVERT_CMD_OPTS

# Clean up
rm -rf $INITRAMFS_STAGING_DIR
