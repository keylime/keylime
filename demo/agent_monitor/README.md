# Agent Monitor Demo

## Introduction 

The Agent Monitor demo is designed to provide a way for agents to "phone home", indicating that they have successfully been provisioned.  

It consists of three parts: 
* **autorun.sh**: This file is sent to the cloud agent, to be executed during provisioning 
    * *__NOTE:__ Your keylime.conf file's ```cloud_agent.payload_script``` should be set to autorun.sh*
* **tenant_agent_monitor.py**: The Agent Monitor server that listens for phone-home requests.  
    * Should be run on the **_same filesystem_** as the tenant (since it shares its CA certs) 
* **tenant_agent_monitor.sh**: The script that the Agent Monitor executes each time it receives a phone-home (it is the 'action' portion of phoning home) 

## Usage 

The Agent Monitor server can be started with the following options: 
```
Usage: python tenant_agent_monitor.py [option...]
Options:
-p PORT         Port for the Agent Monitor to listen on (defaults to 6892)
-i IP           IP address for the Agent Monitor (defaults to localhost)
-s SCRIPT       Specify the script to execute when the agent phones home
-c CA_DIR       Tenant-generated certificate. Pass in the CA directory or 
                use "default" to use the standard dir
-h              This help info
```

For example: 
```
python tenant_agent_monitor.py -s tenant_agent_monitor.sh
```

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

