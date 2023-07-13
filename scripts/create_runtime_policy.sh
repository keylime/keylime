#!/usr/bin/env bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################


if [ $0 != "-bash" ] ; then
    pushd `dirname "$0"` > /dev/null 2>&1
fi
KCRP_BASE_DIR=$(pwd)
if [ $0 != "-bash" ] ; then
    popd 2>&1 > /dev/null
fi
KCRP_BASE_DIR=$KCRP_BASE_DIR/..

function detect_hash {
    local hashstr=$1

    case "${#hashstr}" in
      32) hashalgo=md5sum ;;
      40) hashalgo=sha1sum ;;
      64) hashalgo=sha256sum ;;
      128) hashalgo=sha512sum ;;
      *) hashalgo="na";;
    esac

    echo $hashalgo
}

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

# All defaults
ALGO=sha1sum
WORK_DIR=/tmp/kcrp
OUTPUT_DIR=${WORK_DIR}/output
ALLOWLIST_DIR=${WORK_DIR}/allowlist
INITRAMFS_LOC="/boot/"
INITRAMFS_STAGING_DIR=${WORK_DIR}/ima_ramfs/
INITRAMFS_TOOLS_DIR=${WORK_DIR}/initramfs-tools
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

rm -rf $ALLOWLIST_DIR
rm -rf $INITRAMFS_STAGING_DIR
rm -rf $OUTPUT_DIR

announce "Writing allowlist $ALLOWLIST_DIR/${OUTPUT} with $ALGO..."
mkdir -p $ALLOWLIST_DIR

if [[ $BOOT_AGGREGATE_LOC != "none" ]]
then
    announce "--- Adding boot agregate from $BOOT_AGGREGATE_LOC on allowlist $ALLOWLIST_DIR/${OUTPUT} ..."
# Add boot_aggregate from /sys/kernel/security/ima/ascii_runtime_measurements (IMA Log) file.
# The boot_aggregate measurement is always the first line in the IMA Log file.
# The format of the log lines is the following:
#     <PCR_ID> <PCR_Value> <IMA_Template> <File_Digest> <File_Name> <File_Signature>
# File_Digest may start with the digest algorithm specified (e.g "sha1:", "sha256:") depending on the template used.
    head -n 1 $BOOT_AGGREGATE_LOC | awk '{ print $4 "  boot_aggregate" }' | sed 's/.*://' >> $ALLOWLIST_DIR/${OUTPUT}

    bagghash=$(detect_hash $(cat $ALLOWLIST_DIR/${OUTPUT} | cut -d ' ' -f 1))
    if [[ $ALGO != $bagghash ]]
    then
        announce "ERROR: \"boot aggregate\" has was calculated with $bagghash, but files will be calculated with $ALGO. Use option -a $bagghash"
        exit 1
    fi
else
    announce "--- Skipping boot aggregate..."
fi

announce "--- Adding all appropriate files from $ROOTFS_LOC on allowlist $ALLOWLIST_DIR/${OUTPUT} ..."
# Add all appropriate files under root FS to allowlist
pushd $ROOTFS_LOC > /dev/null 2>&1
BASE_EXCLUDE_DIRS="\bsys\b\|\brun\b\|\bproc\b\|\blost+found\b\|\bdev\b\|\bmedia\b\|\bsnap\b\|\bmnt\b\|\bvar\b\|\btmp\b"
ROOTFS_FILE_LIST=$(ls | grep -v $BASE_EXCLUDE_DIRS)
if [[ $SKIP_PATH != "none" ]]
then
    SKIP_PATH=$(echo $SKIP_PATH | sed -e "s#^$ROOTFS_LOC##g" -e "s#,$ROOTFS_LOC##g" -e "s#,#\\\|#g")
    ROOTFS_FILE_LIST=$(echo "$ROOTFS_FILE_LIST" | grep -v "$SKIP_PATH")
fi
find $ROOTFS_FILE_LIST \( -fstype rootfs -o -xtype f -type l -o -type f \) -uid 0 -exec $ALGO "$ROOTFS_LOC/{}" >> $ALLOWLIST_DIR/${OUTPUT} \;
popd > /dev/null 2>&1

# Create staging area for init ram images
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
        announce "--- The location of initramfs was overriden from \"${X}\" to \"$INITRAMFS_LOC\""
    fi

    announce "--- Creating allowlist for init ram disks found under \"$INITRAMFS_LOC\" to $ALLOWLIST_DIR/${OUTPUT} ..."
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
            announce "ERROR: No tools for initramfs image processing found!"
            exit 1
        fi

        find -type f -exec $ALGO "./{}" \; | sed "s| \./\./| /|" >> $ALLOWLIST_DIR/${OUTPUT}
    done
fi

# Non-critical cleanup on the resulting file (when ROOTFS_LOC = '/', the path starts on allowlist ends up with double '//' )
sed -i "s^ //^ /^g"  $ALLOWLIST_DIR/${OUTPUT}
# A bit of cleanup on the resulting file (among other problems, sha256sum might output a hash with the prefix '\\')
sed -i "s/^\\\//g" $ALLOWLIST_DIR/${OUTPUT}

# Convert to runtime policy
mkdir -p $OUTPUT_DIR
announce "Converting created allowlist ($ALLOWLIST_DIR/${OUTPUT}) to Keylime runtime policy ($OUTPUT_DIR/${OUTPUT}) ..."
CONVERT_CMD_OPTS="--allowlist $ALLOWLIST_DIR/${OUTPUT} --output_file $OUTPUT_DIR/${OUTPUT}"
[ -f $EXCLUDE_LIST ] && CONVERT_CMD_OPTS="$CONVERT_CMD_OPTS --excludelist $EXCLUDE_LIST"

pushd $KCRP_BASE_DIR  > /dev/null 2>&1
export PYTHONPATH=$KCRP_BASE_DIR:$PYTHONPATH
# only 3 dependencies required: pip3 install cryptography lark packaging
python3 ./keylime/cmd/convert_runtime_policy.py $CONVERT_CMD_OPTS; echo " "
if [[ $? -eq 0 ]]
then
    announce "Done, new runtime policy file present at ${OUTPUT_DIR}/$OUTPUT. It can be used on the tenant keylime host with \"keylime_tenant -c add --runtime-policy ${OUTPUT_DIR}/$OUTPUT <other options>"
fi
popd  > /dev/null 2>&1
