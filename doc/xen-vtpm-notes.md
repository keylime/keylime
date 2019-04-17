
# Xen vTPM Setup Notes

These notes are a rough guide to getting xen set up with vTPM support and having keylime work with it. 

## Install keylime and get EKs

clone the source tree and run the installer:
```
git clone keylime

./installer.sh
```

You must obtain the public EK and the EK certificate from outside of Xen when the kernel still has hardware tpm drivers
take ownership first, then obtain pubek, and ekcert as follows
```
takeown -pwdo <owner_password>
getpubek -pwdo <owner-password>
nv_readvalue -pwdo <owner-password> -in 1000f000 -cert -of tpm_ekcert.der
```

the files pubek.pem and tpm_ekcert.der will pop out.  You'll need these inside of the vtpmmgr domain

## Install Xen

starting with fresh install of ubuntu 16.04 minimal server

setup proxy if needed
setup passwordless sudo

update apt and install latest packages

install xen first
https://help.ubuntu.com/community/Xen

`sudo apt-get install xen-hypervisor-amd64`

reboot

### Setup Xen networking

NAT for VM

create a bridge xenbr0

put in /etc/network/interfaces
```
auto xenbr0
iface xenbr0 inet static
	address 10.0.0.1
	netmask 255.255.255.0
	bridge_ports eth22
```	
we dont' want to bridge to internet, we'll nat instead.  so use a non-existent interface for bridge_ports.  it will bring up an empty bridge

add this to /etc/rc.local to turn on NAT

`iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eno1 -j MASQUERADE`

## Rebuilding the dom0 kernel

now we've got to get tpm support out of the dom0 kernel

confirm that it is there by looking for `/dev/tpm0` and initialization in dmesg

`dmesg | grep -i tpm`

we want this gone!

https://wiki.ubuntu.com/Kernel/BuildYourOwnKernel

```
mkdir ubuntu-kernel
cd ubuntu-kernel
apt-get source linux-image-$(uname -r)
sudo apt-get build-dep linux-image-$(uname -r)
cd linux-4.4.0
chmod a+x debian/rules
chmod a+x debian/scripts/*
chmod a+x debian/scripts/misc/*
fakeroot debian/rules clean
fakeroot debian/rules editconfigs
```

Edit the amd64 architecture when you do configs.  Leave the others alone.

Turn off IMA:
secure options->Integrity Subsystem->IMA

Turn off all TPM support:
device-drivers->character devices->TPM Hardware support

It will complain about various things related to config-checks.  these are for other arch's.  just ignore

Now you need to add a local version extension to the name so that we know which one it is and can boot it

change the first line of debian.master/changelog to add -notpm like 

```$ head debian.master/changelog
linux (4.4.0-112.135+notpm) xenial; urgency=low

  * linux: 4.4.0-112.135 -proposed tracker (LP: #1744244)

  * CVE-2017-5715 // CVE-2017-5753
```

We need to remove mention of the tpm modules and symbols from the abi to get it not to complain. this is a bit of a hack.

go to debian.master/abi/4.4.0-111.134/amd64 and get rid of anything that says "tpm from generic or generic.modules
```
grep -v tpm generic > tmp && mv tmp generic
grep -v tpm generic.modules > tmp && tmp generic.modules
```

now it is time to build. Go back to linux 4.4.0 dir and kick it off.  Took about 20 mins on my rather old machine.
```
fakeroot debian/rules clean
fakeroot debian/rules binary-headers binary-generic binary-perarch
```

now in the parent directory `ubuntu-kernel` there should be a pkg for the new kernel

`sudo dpkg -i ../linux-image-(VERSION).deb`

### using git

**NOTE that this doesn't seem to work since Meltdown and Spectre got patched.  Try building the 16.04 kernel the ubuntu way above.**

https://wiki.ubuntu.com/KernelTeam/GitKernelBuild

```
sudo apt-get install git build-essential kernel-package fakeroot libncurses5-dev libssl-dev ccache
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
cp /boot/config-`uname -r` .config
yes '' | make oldconfig
make menuconfig
```

Turn off IMA:
secure options->Integrity Subsystem->IMA

Turn off all TPM support:
device-drivers->character devices->TPM Hardware support

```
make clean
make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-notpm
sudo dpkg -i ../linux-image-(VERSION).deb
```

### Boot the new dom0 kernel

if you used the ubuntu kernel build method (as opposed to git) and haven't updated your kernel recently, it should boot up in that kernel (as the latest) automatically.

set default kernel to the one we just built:

https://unix.stackexchange.com/questions/198003/set-default-kernel-in-grub

i used the third answer.  linked: http://www.humans-enabled.com/2014/08/how-to-set-default-grub-kernel-boot.html

now reboot

Confirm that the correct kernel with (notpm) in the name got booted in Xen.

`uname -r`

and that we're still in xen:

`sudo xl list`

## Building vtpm and vtpmmgr kernels

now we've got to build the vtpm and vtpmmgr subdomain in xen.

following pre-reqs here: https://wiki.xenproject.org/wiki/Compiling_Xen_From_Source

```
sudo -E apt-get install bcc bin86 gawk bridge-utils iproute libcurl3 libcurl4-openssl-dev bzip2 module-init-tools transfig tgif 
sudo -E apt-get install texinfo texlive-latex-base texlive-latex-recommended texlive-fonts-extra texlive-fonts-recommended pciutils-dev mercurial
sudo -E apt-get install make gcc libc6-dev zlib1g-dev python python-dev python-twisted libncurses5-dev patch
sudo -E apt-get install iasl libbz2-dev e2fslibs-dev git-core uuid-dev ocaml ocaml-findlib libx11-dev bison flex xz-utils libyajl-dev
sudo -E apt-get install gettext libpixman-1-dev libaio-dev markdown pandoc
sudo -E apt-get install cmake
```

check out the source
git clone git://xenbits.xen.org/xen.git

I had various build problems with stubdoms,  xen version 4.8 seemed to work.  Not a lot has changed in vtpm land in xen in a while, so mis-matching versions is ok.

```
cd xen
git checkout stable-4.8

# just need patched stubdoms, nothing else
./configure --enable-stubdom --disable-xen --disable-tools --disable-docs --disable-pv-grub --disable-xenstore-stubdom --disable-ioemu-stubdom
```

need to patch up stubdom/vtpmmgr/mgmt_authority.c
```
cd xen
wget https://raw.githubusercontent.com/mit-ll/keylime/master/patches/xen-vtpmmgr-patch.txt
patch -p1 < ../xen-vtpmmgr-patch.txt
make build-stubdom
```

this build may fail on something related to pv-grub, but it's usually ok

the unikernel elf files for vtpm and vtpmmgr are in xen/stubdom/mini-os-x86_64-vtpm and xen/stubdom/mini-os-x86_64-vtpmmgr

called mini-os.gz get those two gz files and rename them to something like vtpm.gz and vtpmmgr.gz

### Boot vtpm domains

Build a vtpmmgr domain

see: https://xenbits.xen.org/docs/4.7-testing/misc/vtpmmgr.txt

also see http://xenbits.xen.org/docs/unstable/misc/vtpm-platforms.txt for example configs

```
mkdir -p /var/lib/xen/images/
cp the two gz's there

mkdir -p /var/lib/xen/disks

dd if=/dev/zero of=/var/lib/xen/disks/vtpmmgr.img bs=2M count=1
```

create the config file in /etc/xen/vtpmmgr.cfg
```
    kernel="/var/lib/xen/images/vtpmmgr.gz"
    memory=8
    disk=["file:/var/lib/xen/disks/vtpmmgr.img,hda,w"]
    name="vtpmmgr"
    iomem=["fed40,5"]
    extra="tpmlocality=0"
```
now start it up.

`sudo xl create -c vtpmmgr.cfg`

you should see "INFO[VTPM]: Waiting for commands from vTPM's:"  if all went well

now it's time to build a vtpm domain.  Build an empty disk image for it to put its stuff. 
You'll also need to give it a random UUID.  we will change this later when configuring keylime

The config file will look like:
```
    kernel="/var/lib/xen/images/vtpm.gz"
    memory=8
    disk=["file:/var/lib/xen/disks/vtpm0.img,hda,w"]
    name="vtpm0"
    extra="loglevel=debug"
    vtpm=["backend=vtpmmgr,uuid=C7319AEA-F895-436C-A110-556C2DDC1EE2"]
```  

start up with:

`xl create -c vtpm0.cfg`

it will say something like "tpm_startup.c:43: Info: TPM_Startup(1)" when it is started up.

You'll also see some log messages in the vtpmmgr showing that it talked to it: like TPM_GetRandom

## Building Linux Domains

now we need to create a linux machine to hook our first vtpm to.

http://www.virtuatopia.com/index.php/Building_a_Xen_Guest_Domain_using_Xen-Tools

`sudo apt-get install xen-tools`

we'll use xen-create-image.

```
cd /etc/xen/
xen-create-image --hostname xenial-linux-vtpmmgr --dist=xenial  --ip 10.0.0.3 --netmask 255.255.255.0 --gateway=10.0.0.1 --nameserver="155.34.3.8" --dir /var/lib/xen/ --password=passwd
```

change whatever needs changing for this as needed for your environment.  Note root password.

a cfg file will come out.  we need to configure the vtpm we just made to talk to it.  Note the name of the vtpm we just made.
put it into the config at the bottom:

`vtpm=["backend=vtpm0"]`

now start it up

`xl create -c xenial-linux-vtpmmgr.cfg`

once up you can login, confirm that network is working, setup ssh/keys and then login via ssh. it's much better than the xen console.

### Kernel vtpm driver bug

bah, now we've got to patch up a kernel to talk to the vtpm in 16.04
https://patchwork.kernel.org/patch/9485637/

using the instructions above, but without the need to change the ABI or tpm config: Apply this patch, update the changelog with +vtpmpatch, and build the kernel.

You'll need to install both the linux-image deb and the linux-image-extras deb to get the kernel modules for the TPM driver.

You need to install the crda package before installing these two debs.

```
apt-get update
apt-get install crda
dpkg -i linux-image-*
```

reboot and confirm that you have the file /dev/tpm0 now.  

Note that 14.04 (trusty) predates this bug.  So, if you don't want to build a new kernel, you can try 14.04.

### Testing vtpm

if the machine booted up and you didn't get the dreaded timeouts bug above, you should be ready to test the vtpm.  Download and install keylime:

```
git clone keylime
./installer.sh
```
check that you can talk to the vtpm with:

```
getcapability -cap 1a
Result for capability 0x1a is : 
major      : 0x01
minor      : 0x02
revMajor   : 0x00
revMinor   : 0x07
specLevel  : 0x0002
errataRev  : 0x01
VendorID   : 45 54 48 5A 
VendorID   : ETHZ
[not displaying vendor specific information]
```

Note Vendor ID: ETHZ  that means you're talking to the vtpm

### Creating a second linux/vtpm combo

now clone the vtpmmgr vm so that we have another one from which to test.  I called this one xenial-linux-keylime

i just copied the config file in /etc/xen and the .img file dir in /var/lib/xen/domains/
update config to have new name, and redirect the swap and disk locations to the place you copied

Make another vtpm (follow procedure above including makeing a fresh disk image) and then hook it to the new machine.

## Running keylime with vtpms

we're going to run all of the keylime services on dom0 of the xen machine.  Only client and cloud agent processes will run on the vms.

So, on dom0 of the xen box start up the following:
```
keylime_verifier
keylime_provider_registrar
keylime_registrar
```
Now on both vms: find and replace all 127.0.0.1 in /etc/keylime.conf with 10.0.0.1  this will point them to dom0 for all the services you just started

also make sure that vtpm_policy is somethign reasonable:

`vtpm_policy = {"23":["ffffffffffffffffffffffffffffffffffffffff","0000000000000000000000000000000000000000"],"15":"0000000000000000000000000000000000000000"}`

on the vtpmmgr domain (which must should have been brought up first before the vtpm attached to the clone xenial-linux-keylime.

first need to do platform init with the keys from dom0 from way back at the beginning of this guide.  scp them over and then run:

`keylime_provider_platform_init pubek.pem tpm_ekcert.der`

you should see something like "keylime.provider_platform_init - INFO - Activated VTPM group"

Now you need to add a vtpm

`keylime_provider_vtpm_add current_group.tpm`

Note that current_group.tpm is a symlink to the latest initialized group that comes from platform_init.  

log message like the following means that it worked:
"keylime.platform-init - INFO - Registered new vTPM with UUID: 33C6AD2C-F20D-40B0-B3F6-BC0FB0627637

Copy this uuid.  Shutdown the keylime vm and its vtpm.  Put this UUID into the cfg file for the vtpm:

`vtpm=["backend=vtpmmgr,uuid=33C6AD2C-F20D-40B0-B3F6-BC0FB0627637"]`
    
Boot the vtpm back up.  then boot up the linux machine.  Now you must put this UUID into the keylime vm /etc/keylime.conf.

`agent_uuid=33C6AD2C-F20D-40B0-B3F6-BC0FB0627637`

Ok, now it is time to start up the agent process.  (this is where it all comes together, so if this works, the rest likely will too)

watch for any 400 errors from registration.

if you see the following:  

keylime.cloudagent - INFO - Starting Cloud Agent on port 9002 use <Ctrl-C> to stop

then it's good.

Now lets actualy run through the entire process:

back on dom0 xen machine we want to run the tenant:

`keylime_tenant -u 33C6AD2C-F20D-40B0-B3F6-BC0FB0627637 -t 10.0.0.4 --verify -f SOMEFILE.txt`

where SOMEFILE.txt is any old file that you want delivered securely to the agent.  The --verify option will poll the agent to make sure everything worked

if all goes well you should see:
keylime.tenant - INFO - Key derivation successful

that's it folks!
