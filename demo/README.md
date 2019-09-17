# Deluxe Demo Bundle Setup

## Introduction 

The Deluxe Demo Bundle shows off the fancy technology that Keylime is capable of.  It is intended to be installed on a throwaway demo machine! 

It includes the following demos: 
* IMA Demo 
* Webserver Demo (using nginx) 
* TrustedGRUB Demo 

The bundle contains the following files: 
* **demo_setup.sh**: This sets up and installs the demos (on top of an existing Keylime installation) 
* **ima-policy**: IMA policy file (less burdensome than the IMA TCB policy) 
* **ima-policies/**: Additional IMA policy file examples, including the default TCB policy
* **keyfile.txt**: Keyfile that decrypts the payload.enc and payload.txt files 
* **autorun.sh**: This file is sent to the cloud agent, which will decrypt and mount the payload.enc 
    * *__NOTE:__ Your keylime.conf file's ```cloud_agent.payload_script``` should be set to autorun.sh*
* **payload.enc**: The target of the mount.sh script (LUKS encrypted payload), containing the "protected" website 
* **payload.txt**: A simple encrypted payload to demonstrate the "Keyfile" payload type 
* **payload/**: Directory containing the "unprotected" website 

Also, see the **demo/agent_monitor** directory for an agent "phone-home" demo! 

## Usage 

The demo_setup.sh script can be executed with the following options: 
```
Usage: ./demo_setup.sh [option...]
Options:
-p PATH         Use PATH as Keylime path
-i              Install IMA-related demo
-w              Install webserver-related demo
-t              Install TrustedGRUB2 (i386-pc w/ TPM) to /dev/sda
-T PATH         Install TrustedGRUB2 (i386-pc w/ TPM) to PATH
-n              No-password sudo for current user
-N USER         No-password sudo for user USER
-f              Full install (same as -niwt)
-y              No confirmations (feeling lucky)
-h              This help info
```

## Important Notes

### Webserver Demo

Both the keyfile.txt and autorun.sh files should be sent to the agent (via "CA Dir" mode provisioning).  

`keylime_tenant -t 192.168.0.100 -u my_agent_id --cert default --include agent_files_dir`

The payload.enc file should be in the web server HTML directory (demo_setup.sh will put it there). 

### TrustedGRUB

Defaults to using https://github.com/Rohde-Schwarz-Cybersecurity/TrustedGRUB2 

Caveats: This requires a physical TPM, otherwise your system will be *unbootable*.  
It also does not support UEFI mode booting, so make sure you are using legacy boot in your BIOS settings.  
It will be built for the i386-pc platform.

### No-password sudo

Obviously a bad idea unless done on a scrappable, demo-only system! 

## License

Copyright (c) 2015 Massachusetts Institute of Technology.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.

