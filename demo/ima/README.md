# IMA Demo Setup


## Overview

---

The following steps are required to peform the IMA demo on a Fedora 28
Machine. This should also work for other distrbutions. If you get this working
on a different variant, please feel free to make a pull request and add the
addition steps required.

All steps should be performed as root, as the following is for a throwaway
demo environment.

## Configure grub

We first need to add some `rootflags` to grub to enable the population of
`ascii_runtime_measurements`.

Find out your current default (active) Kernel

    grubby --default-kernel
    /boot/vmlinuz-4.18.16-300.fc29.x86_64

Update the args for grub.

    grubby --args="rootflags=i_version ima_tcb" --update-kernel /boot/vmlinuz-4.18.16-300.fc29.x86_64

Now reboot the machine and ensure that `/sys/kernel/security/ima/ascii_runtime_measurements` is populated:

    [root@localhost ~]# head /sys/kernel/security/ima/ascii_runtime_measurements
    10 1d8d532d463c9f8c205d0df7787669a85f93e260 ima-ng sha1:0000000000000000000000000000000000000000 boot_aggregate
    10 fb8f064de6c692300a2a95b587d634f770c8443f ima-ng sha1:9d0ea4909d6575c795bc44304e10e1ad946a9401 /usr/lib/systemd/systemd
    10 9decc71c00f0358e53a9175bb830eb96b4f2f917 ima-ng sha1:e72a9c090fc81a95fd33474c0b95571b544c7961 /usr/lib64/ld-2.27.so
    10 7f8e9a50d05bb5ecc9d705c925cb15fed28696cd ima-ng sha1:72536f158d24644adeb47c04e92ba5c9ed769b03 /usr/lib/systemd/libsystemd-shared-238.so
    10 9074e2f90b250d396247ea37bb4849d772d7cf48 ima-ng sha1:74388d008c872c591d044a42a70976b13d00b1dd /etc/ld.so.cache
    10 008eda89553bcdae118a5127601728c6269caaa9 ima-ng sha1:3dfe67f567422215d8f7529ed78c890e98d63dee /usr/lib64/librt-2.27.so
    10 a6d37202c6daf91a63f30b498bf513b3689261e3 ima-ng sha1:2d3cefb39ab16ec5515859bdb479358b687b7074 /usr/lib64/libseccomp.so.2.3.3
    10 4acb16029fd8b45d57a1895d0cd4d4403b7dd4ff ima-ng sha1:7de9c045f90f7ffece822394be6a620bf6deb1d4 /usr/lib64/libselinux.so.1
    10 925337232b5078e233a9d9386b91608dcdbd4763 ima-ng sha1:d162a590d078fcf37342b56823dbe96901ebd2a4 /usr/lib64/libmount.so.1.1.0
    10 bc972002fbc8c9a4e3c715711d41b6a7ca11c5ff ima-ng sha1:8fb16503f233480617758fb97e100ca621da11b2 /usr/lib64/libblkid.so.1.1.0

Verify IMA is loaded

    dmesg |grep -i ima:
    [    1.560511] ima: Allocated hash algorithm: sha1

Run the `demo_setup.sh` script from `/root/python-keylime` using the `-i` args
to set up IMA.

    demo/demo_setup.sh -i -p .

    demo/demo_setup.sh -i -p .
    INFO: Using Keylime directory: /root/python-keylime/.

    ==================================================================================
    				Updating Fedora packages
    ==================================================================================
    Last metadata expiration check: 0:48:38 ago on Wed 16 Jan 2019 05:23:04 PM UTC.
    Dependencies resolved.
    Nothing to do.
    Complete!

    ==================================================================================
    				Installing IMA policy
    ==================================================================================
    cp: overwrite '/etc/ima/ima-policy'? y
    INFO: Restart required to enable IMA!

    ==================================================================================
    				Generating IMA whitelist
    ==================================================================================
    Writing whitelist to /root/python-keylime/keylime/whitelist.sh with sha1sum...
    Creating whitelist for init ram disk
    extracting /boot/initramfs-4.16.3-301.fc28.x86_64.img
    extracting /boot/initramfs-4.19.15-200.ima_kernel.fc28.x86_64.img

Kill the running tpm_server with `pkill -x tpm_server`

Run `python-keylime/ima_stub_service/installer.sh`

Set up the tpm wrapper scripts:

    chmod +x $KEYLIME_HOME/swtpm2_scripts/init_tpm_server
    chmod +x $KEYLIME_HOME/swtpm2_scripts/tpm_serverd
    install -c $KEYLIME_HOME/swtpm2_scripts/tpm_serverd /usr/local/bin/tpm_serverd
    install -c $KEYLIME_HOME/swtpm2_scripts/init_tpm_server /usr/local/bin/init_tpm_server

Enable the service:

    systemctl enable tpm_emulator.service

Start the service

    systemctl start tpm_emulator.service

Check the service works ok and is building a hash list

    [root@localhost ~]# watch -n 2 systemctl status tpm_emulator.service
    ● tpm_emulator.service
       Loaded: loaded (/etc/systemd/system/tpm_emulator.service; enabled; vendor preset: disabled)
       Active: active (running) since Thu 2019-01-17 14:27:34 UTC; 9min ago
     Main PID: 15519 (tpm_with_ima.sh)
        Tasks: 3 (limit: 4915)
       Memory: 262.2M
       CGroup: /system.slice/tpm_emulator.service
               ├─15519 /bin/bash /usr/local/bin/tpm_with_ima.sh
               ├─15525 tpm_server
               └─15547 /usr/bin/python2.7 /usr/bin/keylime_ima_emulator

    Jan 17 14:36:15 localhost.localdomain tpm_with_ima.sh[15519]: extending hash ffffffffffffffffffffffffffffffffffffffff for /tmp/tmpysMw8f
    Jan 17 14:36:15 localhost.localdomain tpm_with_ima.sh[15519]: extending hash cf0b49572eb50cdb476feab380a314697b259ff4 for /tmp/tmpysMw8f
    Jan 17 14:36:15 localhost.localdomain tpm_with_ima.sh[15519]: extending hash 22a6722b84082f2f1d601dd1b386cc062fd1ccf1 for /var/lib/keylime/cv_ca/client-private.pem
    Jan 17 14:36:15 localhost.localdomain tpm_with_ima.sh[15519]: extending hash 7a234f811fbd04aade986cdab591611d6fc11477 for /root/python-keylime/keylime/whitelist.sh
    Jan 17 14:36:15 localhost.localdomain tpm_with_ima.sh[15519]: extending hash bec665ef7b9e4b3f4e8e2359c46127b49c316949 for /root/exclude.txt

---

Change `require_ek_cert` to `False` in `/etc/keylime.conf`

Open three terminals (or use `&`) and start the verifier, registrar and
cloud node:

Terminal 1:

    # keylime_verifier

Terminal 2:

    # keylime_registrar

Terminal 3:

    # keylime_node


# Upload whitelist

We will now upload a whitelist which we earlier created from the initramfs

    keylime_tenant -v 127.0.0.1 -t 127.0.0.1 -f /root/exclude.txt --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --whitelist /root/python-keylime/keylime/whitelist.sh --exclude /root/exclude.txt

Now that the whitelist is updated, you can perform a hash change and invoke an
integrity failure. You can see these from the message `failed, stopping polling`

If you need to delete the node (to clear a failure):

    keylime_tenant -t 127.0.0.1 -u D432FBB3-D2F1-4A97-9EF7-75BD81C00000 -c delete

# File not found

    1551283456.39 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/tmate
    1551283456.39 - keylime.ima - WARNING - File not found in whitelist: /usr/lib64/libmsgpackc.so.2.0.0

Just add them to the exclude.txt

`cat exclude.txt
/etc/udev/rules.d/70-luks.rules
/dracut-state.sh
/usr/lib/dracut/hooks/initqueue/finished/*
/sysroot/etc/fstab
/usr/local/bin/tpm_with_ima.sh
/usr/local/bin/tpm_serverd
/usr/bin/tmate
/usr/lib64/libmsgpackc.so.2.0.0`

Delete the node, and resend the whitelist and new exclude.txt

ToDo:

* Add examples of notification of a failure
