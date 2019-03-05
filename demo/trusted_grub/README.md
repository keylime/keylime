# TrustedGRUB

A demonstration of trusted boot using `TrustedGRUB`.

This demonstration will be depreciated when work is complete on keylimes
main trusted boot attestation service. This is kept here in respect of
maintaining an archive.

Two arguments can be sourced to the `demo_setup.sh` script for TrustedGRUB:

    -t              Install TrustedGRUB2 (i386-pc w/ TPM) to /dev/sda
    -T PATH         Install TrustedGRUB2 (i386-pc w/ TPM) to PATH

The demo defaults to [TrustedGRUB2](https://github.com/Rohde-Schwarz-Cybersecurity/TrustedGRUB2)

Caveats: This requires a physical TPM, otherwise your system will be
*unbootable*.  It also does not support UEFI mode booting, so make sure you are
using legacy boot in your BIOS settings. It will be built for the i386-pc
platform.

Use at your own risk! This script is only for demonstration and research. 
