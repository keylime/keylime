# Instructions for Installing Keylime on FreeBSD

These instructions were a proof-of-concept for getting keylime to work.  These instructions may or may not work, depending on the version of FreeBSD or changes to tpm2-tools.

get dependencies
`pkg install -y gmake libtool pkgconf wget gcc openssl tpm2-tss tpm2-abrmd`

link python and gcc
`ln -s /usr/local/bin/gcc /usr/bin/gcc && ln -s /usr/local/bin/python3.7 /usr/bin/python`

## swtpm2 Installation
download swtpm2 from sourceforge
```
wget https://sourceforge.net/projects/ibmswtpm2/files/latest/download -O swtpm.tgz
mkdir -p swtpm && tar -xzf swtpm.tgz -C swtpm
cd swtpm/src
```
change the syntax for USE_BIT_FIELD_STRUCTURES in TpmBuildSwitches.h (removing default #define)
```
#if !(defined USE_BIT_FIELD_STRUCTURES)                                 \
    || ((USE_BIT_FIELD_STRUCTURES != NO) && (USE_BIT_FIELD_STRUCTURES != YES))
#   undef   USE_BIT_FIELD_STRUCTURES
#	ifndef __FreeBSD__
#   	define  USE_BIT_FIELD_STRUCTURES    YES        // Default: Either YES or NO
#	endif
#endif
```

in BaseTypes.h add this towards the bottom
```
#ifdef  __FreeBSD__
        typedef SOCKET int;
#endif
```

Now Build
```
make
install -c tpm_server /usr/local/bin/tpm_server
```

# TPM Abrmd Configuration

enable dbus in /etc/rc.conf by adding `dbus_enable="YES"` and then reboot

# Old Tpm2-tools

We need to update the tpm2-tools package to be version 4.1.

```
portsnap fetch && portsnap extract
cd /usr/ports/security/tpm2-tools/
```

Update the makefile with version 4.1
`DISTVERSION=     4.1`

and remove this line:
`BROKEN_SSL=     openssl`


update the file distinfo with:
```buildoutcfg
TIMESTAMP = 1568138495
SHA256 (tpm2-tools-4.1.tar.gz) = 07ce37f552ed47f582fbc3423bc316fea64012ef15a92a25766a36534524dcf2
SIZE (tpm2-tools-4.1.tar.gz) = 779577
```

Now build and install
```
make 
make install
```

# Installing keylime

`pkg install -y git py37-pip py37-pyaml py37-pyzmq py37-tornado py37-cryptography py37-requests py37-sqlite3`

clone keylime repo and install
```
git clone keylime
python setup.py install
```

# Running the Emulator

```
tpm_server &
tpm2-abrmd --tcti=libtss2-tcti-mssim.so.0:host=127.0.0.1,port=2321 -o
```

# Running keylime
 
Now you should be able to use keylime normally.  Note if you're using an emulator, you'll need to set `require_ek_cert=False` in `/etc/keylime.cconf`  On my virtual system, it was very slow, so i had to lengthen the timeouts in `keylime/httpclient_requests.py`

```
keylime_verifier &
keylime_registrar &
keylime_agent &
keylime_tenant -f afile.txt -t 127.0.0.1
```
