# Mac Development Setup Notes

These instructions describe how to setup a development environment for keylime on a modern copy of OSX.  Right now, these instructions only cover how to get things running with TPM version 1.2.  It may be possible to build and install tpm2-tools and swtpm2 on a mac, but I haven't attempted that yet.  Despite this limitation with TPM 1.2, you can still do a lot of useful development of APIs, and other non-tpm related stuff on a mac.

## Prerequisites:

You'll need homebrew for this.  To use homebrew, you'll need the xcode command line utilities.  

`xcode-select --install`

Now go get home brew from https://brew.sh and curl bash it

`/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`

Now you'll need to install some packages for keylime to use:

`brew install python`

## Installing TPM 1.2 Library

Go get the ibm tpm emulator library and build it:

```
git clone https://github.com/keylime/tpm4720-keylime.git
cd tpm4720-keylime/scripts
./install-mac.sh
```

## Installing Keylime

Get the code and use `setup.py` to install:

`python3 setup.py install`

## Running keylime

There's a helpful script that will setup the TPM emulator and clear out any state in the `keylime` directory called `dev-clean.sh`  Run that first then you can run the verifier, registrar, agent and tenant as usual.


