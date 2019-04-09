# Automatic IPsec Configuration with Libreswan

Using the certificate distribution mechanism built into keylime, you can automatically configure keylime to use IPsec to securely communicate with other hosts in a network.  

## Overview

These scripts allow keylime agents to create a virtual private network between them that is protected by cryptographic keys bootstrapped by keylime.  Keylime will also automatically remove failed agents from the network.  The scripts work by leveraging two features of keylime: automatic certificate generation/delivery, and the ability run scripts provided in the payload after successful bootstrapping.  The following high level actions will happen:

* the tenant will first run generate.py in this folder to generate the IPsec configuration files to pass to the tenant.  the tenant must specify the subnets/ips that they wish for agents to always use IPsec to communicate.
* the tenant will generate a new CA (if one hasn't been generated yet) and then generate a new cert/key combo for the agent to be bootstrapped
* the tenant will include the IPsec config files generated above with the `--include` option
* tenant and verifier will bootstrap the agent and derive a key as normal
* once the bootstrap key has been derived, keylime will decrypt and extract the zipped payload that includes both the cert/key and the ipsec config.
* Then keylime will run the provided autorun.sh script.  This script will install/configure IPsec using the certificate provided.
* at this point, IPsec will initialize and run between any specified IPs or subnets.

To support revocation:

* the tenant must host the CA's CRL and listen for revocations.  `keylime_ca -c listen` will do this job
* If the verifier determines that an agent has failed its integrity check, it will create and sign a revocation notice that it will distribute to all the agents over 0mq
* the tenant's CRL listener will receive and validate the revocation, update the CRL using the CA private key, and publish it to a locally running websever.
* in parallel, all the other agents in the network will also receive the revocation notice and retrieve the new CRL from the tenant.  It is important that the certificates include the appropriate address for the CRL or this won't work.
* the other agents in the network will also search their active IPsec security associations for the revoked agent and force IKE re-negotiation with them.  Because the CRL has also been updated, this will cause the agents to be unable to do key agreement with the revoked agent and block any traffic to it.

## Pre-requisites

This set of scripts works with Ubuntu Linux 16.04 and Centos/RHEL 7.  It may work with other versions of centos, but they have not been tested.  Keylime will install libreswan package and configure it.

In addition to basic keylime setup, the following configuration options must be set in the keylime.conf.  Many of these are defaults, so it shouldn't be hard to achieve this configuration.

### keylime.conf on each agent

to support automatic revocation, the revocation notifier must be enabled and reachable by agents.  Set the IP/port to the verifier that hosts the revocation notifier:
```
revocation_notifier_ip = xxx.xxx.xxx.xxx
revocation_notifier_port = xxxx
listen_notifications = True
revocation_cert = default
```

To enable cert mode and payload scripts the following options should be set:
```
extract_payload = True
payload_script=autorun.sh
```

### keylime.conf on the verifier

The verifier must host the revocation notifier:

`revocation_notifier = True`

### keylime.conf on the tenant

Finally: the tenant must setup the [ca] section of the config file with appropriate cert_* options.
Importantly, the following option must be set with the ip/port of the crl listener:

`cert_crl_dist = http://xxx.xxx.xxx.xxx:port/crl`

## Bootstrapping a agent with IPsec Configuration

First, generate the ipsec config files using generate.py in this directory.  It takes in a file with 1 or more subnets to enable IPsec to/from.
You can also specify single hosts using the notation `192.168.1.1/32`  The order in which the lines in the file are specified is how they'll be encoded into `/etc/ipsec.d/policies/private` and `/etc/ipsec.d/policies/clear`.  

`python generate.py file.txt`

Example: generate.py file.txt

```
# Any file starting with # will be ignored
# All Subnets after ipsec are enabled by default
ipsec
192.168.0.0/24
172.22.2.4/32
# All subnets after exclude will not use ipsec
exclude
192.168.0.1/32
```

This script will output the files you need to include into the directory `ipsec-extra`

Next provision a agent as you would normally.  Be sure to use the `--cert` option to generate a certificate.  Also include the files generated above using `--include`.

`keylime_tenant -t 192.168.0.100 -u agent1 --cert myca --include ipsec-extra`

## Revocation Support

### WARNING: Revocation does not currently work with Centos 7.  Libreswan doesn't seem to act upon CRLs.

To support revocation, you must run a CRL host/listener.  This will host a copy of the CRL on a web server and listen for notification of revocation from the verifier.  To run this service:

`keylime_ca -c listen -d myca`
 
It will start up a web server and listen for notifications.  Be sure that the cert_crl_dist option in keylime.conf is set to point to this server.

If a agent is revoked, the listener will update the CRL.  All the agents will run their configured revocation actions:

```
local_action_update_crl
local_action_crashsa
```

The first action updates the CRL stored locally.  The second action will update the CRL in the NSS database and then force a rekey with any agents communicating with the revoked server. It will match the certificate by its x509 distinguished name. Within a second or two, all agents in the network should stop communicating with the revoked host. 

## IPsec Configuration

Keylime uses libreswan to setup IPsec.  It uses AES256 in GCM mod and modp2048 for DH.  See src/oe-keylime.conf for more details.  Keylime does not currently check the hostname of the certificate, only that it was valid and signed.  This configuration is for demonstration purposes only.  It is neither the most secure nor the most efficient IPsec setup.  If you customize src/oe-keylime.conf, these scripts will distribute and act upon them.
