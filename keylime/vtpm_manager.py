'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64
import hashlib
import logging
import os.path
import subprocess
import struct
import sys
import time
import tempfile
from uuid import UUID

import json

try:
    from yaml import CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeDumper

from keylime import config
from keylime import keylime_logging
from keylime.tpm.tpm_main import tpm

# get the tpm object
tpm_instance = tpm(need_hw_tpm=True)

sys.path.append(os.path.dirname(__file__))

# Logging boiler plate
logger = keylime_logging.init_logging('vtpmmgr')
logger.setLevel(logging.INFO)

# ./utils/encaik -ek ~/tmp/LLSRC-tci/scripts/llsrc-vtpm-host0_pubek.pem -ik ~/tmp/LLSRC-tci/scripts/llsrc-vtpm-host0_pubek.pem -ok key.blob -oak key.aes
# cd /home/rudd/tmp/tpm4720/libtpm

# VTPM Command Ordinals. Taken from Xen's stubdoms/vtpmmgr/vtpm_manager.h
VTPM_ORD_GROUP_LIST = 0x02000101
VTPM_ORD_GROUP_NEW = 0x02000102
VTPM_ORD_GROUP_DEL = 0x02000103
VTPM_ORD_GROUP_ACTIVATE = 0x02000104
VTPM_ORD_GROUP_SHOW = 0x02000107

VTPM_ORD_VTPM_LIST = 0x02000201
VTPM_ORD_VTPM_NEW = 0x02000204

# Serialized format of a UUID
uuid_fmt = '4s2s2s2s6s'

#
# def get_default_data_dir():
#     keylime_dir = os.path.expanduser("~/.keylime")
#     if not os.path.exists(keylime_dir):
#         os.mkdir(keylime_dir)
#     return keylime_dir
#
#
#
#
# class VTPMGroup(object):
#     """A class that represents a groupof VTPMs managed by the VTPM Manager
#
#     This class is not intended to be instantiated directly.
#     `VTPMManager`` returns objects that are instances of this class.
#     """
#     _groups = { }
#
#     def __new__(cls, uuid, aik_path, vtpm, added=False):
#         """
#         Args
#         ----
#         uuid: str
#             The UUID for this VTPM Group
#         aik_path: str
#             The path to the .pem for this group's AIK
#         """
#         if uuid in VTPMGroup._groups:
#             return VTPMGroup._groups[uuid]
#
#         obj = object.__new__(cls)
#         obj.uuid = uuid
#         obj.aik_path = aik_path
#         obj.vtpm = vtpm
#
#         if added:
#             VTPMGroup._groups[uuid] = obj
#         return obj
#
#     @property
#     def num(self):
#         return self.vtpm.get_groupnum(self.uuid)
#
#
# class VTPMManager(object):
#     """A class that represents the Xen VTPM Manager"""
#     keyblob_path = 'key.blob'
#
#     def __init__(self, data_dir=get_default_data_dir(), pubek_path=None,
#                  force_reinit=True):
#         """
#         Args
#         ----
#         data_dir: str
#             The path to store keys
#         pubek_path: str
#             The path to the .pem for the underlying physical TPM.
#             Defaults to ``data_dir + '/pubek.pem'``
#         force_reinit: bool
#             Whether to initialize when ``data_dir`` contains files
#         """
#         if pubek_path is None:
#             pubek_path = data_dir + '/pubek.pem'
#         if not os.path.exists(pubek_path):
#             raise OSError('"{0}" does not exist'.format(pubek_path),
#                           os.strerror(errno.ENOENT), errno.ENOENT)
#
#         with open(pubek_path, 'rb') as pubek_f:
#             pubek = pubek_f.read()
#
#             rsamod_path = pubek_path + '.bin'
#             public_mod = get_mod_from_pem(pubek)
#             with open(rsamod_path, 'wb') as f:
#                 f.write(public_mod)
#             print('Wrote {0} bytes to {1}'.format(len(public_mod), rsamod_path))
#
#             self.pubek_path = pubek_path
#             self.rsamod_path = rsamod_path
#             self.groupaiks = {}
#
#         VTPMGroup._groups = {}
#         for i in range(self.count_groups()):
#             self.get_group(i)
#
#     def count_groups(self):
#         """ Returns the number of Added VTPM Groups """
#         return count_groups()
#
#     def get_groupnum(self, group_uuid):
#         for i in range(self.count_groups()):
#             group = show_group(i)
#             if group_uuid == group['uuid']:
#                 return i
#         raise LookupError('Could not find group with UUID: {0}'.format(group_uuid))
#
#     def get_group(self, groupnum):
#         """ Returns the ```VTPMGroup``` for ``groupnum``"""
#         ginfo = get_group_info(groupnum)
#         return VTPMGroup(ginfo['uuid'], ginfo['aikpem'], self)
#
#     def activate_group(self, groupnum, keyblob):
#         """ Returns an AES symmetric key derived from base64 ``keyblob`` """
#         with open(self.keyblob_path, 'w') as f:
#             f.write(base64.b64decode(keyblob))
#         symkey = do_group_activate(groupnum, self.keyblob_path)
#         self.groupaiks[groupnum] = symkey
#         return symkey
#
#     def add_group(self):
#         """ Adds a new VTPM Group and returns its ``VTPMGroup``"""
#         (uuid, aik, _) = do_group_add(self.rsamod_path)
#         aik_base = aik.split('.pub')[0]
#         check_call('tpmconv -ik {0} -ok {1}'.format(aik, aik_base), shell=True)
#
#         return VTPMGroup(uuid, aik_base + '.pem', self, True)
#
#     def add_vtpm(self, groupnum):
#         """ Adds a new VTPM to VTPMGroup ``groupnum`` and returns its UUID"""
#         return add_vtpm(groupnum)
#
#
# class StubVTPMManager(VTPMManager):
#     """
#     A stub implementation of VTPMManager which performs no writes to /dev/tpm0
#     but implements all methods.
#     """
#
#     group_uuid = 'c697ce76-641c-41fb-a4a6-b816860afd11'
#     vtpm_uuid = 'C432FBB3-D2F1-4A97-9EF7-75BD81C866E9'
#
#     def __init__(self):
#         self.aikpath = '{0}/{1}_aik.pem'.format(get_default_data_dir(),self.group_uuid)
#         self.pubekpath = '{0}/test_pubek.pem'.format(get_default_data_dir())
#         self.blobpath = '{0}/test_key.blob'.format(get_default_data_dir())
#         self.aespath = '{0}/test_key.aes'.format(get_default_data_dir())
#
#         if not os.path.exists(self.aikpath):
#             with open(self.aikpath, 'wb') as f:
#                 f.write(common.TEST_HAIK)
#
#         if not os.path.exists(self.pubekpath):
#             with open(self.pubekpath, 'wb') as f:
#                 f.write(common.TEST_PUB_EK)
#
#     def get_groupnum(self, group_uuid):
#         """ Returns ``0`` """
#         return 0
#
#     def count_groups(self):
#         """ Returns ``1`` """
#         return 1
#
#     def activate_group(self, groupnum, keyblob):
#         """
#         Returns the symkey generated from ``encaik`` on
#         ``common.TEST_AIK`` and ``common.TEST_PUB_EK``
#         """
#         return common.TEST_AES_REG_KEY
#
#     def add_group(self):
#         """ Returns the uuid in ``StubVTPMManager.group_uuid``"""
#         return VTPMGroup(self.group_uuid, self.aikpath, self)
#
#     def add_vtpm(self, groupnum):
#         """ Returns the uuid in ``StubVTPMManager.vtpm_uuid``"""
#         return self.vtpm_uuid


def check_call(*args, **kwargs):
    print(args, kwargs)
    return subprocess.check_call(*args, **kwargs)


def unpack(fmt, s):
    """
    Partially unpack `s` according to `fmt`. Returns a
    tuple containing the unpacked elements, and the portion of `s` leftover
    after unpacking.
    """
    s_len = struct.calcsize(fmt)
    first, rest = s[:s_len], s[s_len:]
    return struct.unpack(fmt, first), rest


def vtpm_raw(hdr, msg):
    """ Sends a raw vtpm command. """
    hdr = struct.pack('>HI', hdr, len(msg) + 6)
    cmd = hdr + msg
    logger.debug('Sending "%r"', cmd.encode('hex'))
    with open('/dev/tpm0', 'wb+') as f:
        f.write(cmd)
        f.flush()
        rsp = f.read(4096)
    rsp_hdr = rsp[:10]
    rsp_body = rsp[10:]
    (rsp_type, rsp_len, _) = struct.unpack('>HII', rsp_hdr)
    assert rsp_len == 10 + len(rsp_body), \
        "Invalid Response:[Len]: {0:#x} vs {1:#x}".format(rsp_len, 10 + rsp_body)
    logger.debug('Response Type: 0x%x (%d bytes)', rsp_type, rsp_len)
    logger.debug('Response Body: "%r"', repr(rsp_body.encode('hex')))
    return rsp_body


def vtpm_cmd(cmd, msg):
    """ Sends vtpm command with ordinal `cmd` and message `m`. """
    return vtpm_raw(0x1C2, struct.pack('>I', cmd) + msg)


def stringify_uuid(raw_uuid):
    """ Converts the serialized uuid `raw_uuid` into a string """
    uuid = struct.unpack(uuid_fmt, raw_uuid)
    uuid = [part.encode('hex') for part in uuid]
    uuid = '-'.join(uuid)
    return uuid.upper()


def show_group(group_num):
    """ Returns info about group `group_num` using VTPM_ORD_GROUP_SHOW"""
    out = {'num': group_num, 'vtpms': []}
    body = vtpm_raw(0x1C2, struct.pack('>II', 0x02000107, group_num))
    (uuid, pk, cfg) = struct.unpack('16s 256s 16s', body)
    uuid = stringify_uuid(uuid)
    logger.info('Group [%d] UUID: %s', group_num, uuid)
    pk_hash = hashlib.sha1(pk).hexdigest()
    logger.info('  PK Hash:  %s', pk_hash)
    logger.info('  Cfg list: %s', cfg.encode('hex'))
    body = vtpm_cmd(VTPM_ORD_VTPM_LIST, struct.pack('>II', group_num, 0))
    ((num_vtpms,), body) = unpack('>I', body)
    if num_vtpms > 0:
        logger.info('  vTPMs:  ')
        vtpms = struct.unpack('16s' * num_vtpms, body)
        vtpms = [stringify_uuid(vtpm) for vtpm in vtpms]
        for i, vtpm in enumerate(vtpms):
            logger.info('    [%d]: %s', i, vtpm)
            out['vtpms'].append(vtpm)
    out['uuid'] = uuid
    return out


def count_groups():
    """ Get number of groups using VTPM_ORD_GROUP_LIST"""
    body = vtpm_raw(0x1C2, struct.pack('>I', VTPM_ORD_GROUP_LIST))
    (num_groups,) = struct.unpack('>I', body)
    return num_groups


def list_groups():
    """ Used to print groups for ``./vtpm_manager.py list``"""
    for i in range(count_groups()):
        show_group(i)


def do_list():
    """ Implementation of ``./vtpm_manager.py list``"""
    list_groups()


def do_group_del(group_id):
    """ Implementation of ``./vtpm_manager.py group-del``"""
    group_id = int(group_id)
    if group_id < count_groups():
        vtpm_cmd(VTPM_ORD_GROUP_DEL, struct.pack('>I', group_id))


def do_group_activate(group_id, priv_ca_blob):
    """ Implementation of ``./vtpm_manager.py group-activate``"""
    group_id = int(group_id)
    with open(priv_ca_blob, 'rb') as f:
        priv_ca = f.read()
    assert len(priv_ca) == 256
    logger.debug('Activating group number %d', group_id)
    body = vtpm_cmd(VTPM_ORD_GROUP_ACTIVATE,
                    struct.pack('>II', group_id, 256) + priv_ca)
    (algId, encScheme, size), body = unpack('>IHH', body)
    logger.info('Received Key. AlgID: 0x%x, encScheme: 0x%x, size: 0x%x',
                algId, encScheme, size)
    logger.info('Key: %r', body)
    assert size == len(body)
    return body


def add_group(rsa_mod_path):
    """ Add new vtpm group"""
    logger.debug('Adding group')
    with open(rsa_mod_path, 'rb') as f:
        rsa_mod = f.read()
    assert len(rsa_mod) == 256
    ca_digest = '\x00' * 20
    rsp = vtpm_cmd(VTPM_ORD_GROUP_NEW, ca_digest + rsa_mod)

    (uuid, aik_pub, aik_priv_ca) = struct.unpack('16s256s256s', rsp)
    uuid = struct.unpack(uuid_fmt, uuid)
    uuid = '-'.join([part.encode('hex') for part in uuid])
    logger.info('Created group with UUID: %s', uuid)
    return (aik_pub, aik_priv_ca, uuid)


def add_vtpm(groupnum):
    """ Add new vtpm to ``groupnum`` """
    rsp = vtpm_cmd(VTPM_ORD_VTPM_NEW, struct.pack('>I', groupnum))
    (uuid,) = struct.unpack('16s', rsp)
    uuid = '-'.join([part.encode('hex') for part in uuid])
    logger.info('Received UUID: %s\n', uuid)
    return uuid


def do_group_add(rsa_mod_path):
    """ Implementation of ``./vtpm_manager.py group-add``"""
    (aik_pub, aik_priv_ca, uuid) = add_group(rsa_mod_path)
    (aik_pub_path, aik_priv_ca_path) = ('{0}_aik.pub'.format(uuid),
                                        '{0}_aik_priv_ca'.format(uuid))
    with open(aik_pub_path, 'wb') as f:
        f.write(aik_pub)
    with open(aik_priv_ca_path, 'wb') as f:
        f.write(aik_priv_ca)

    return (uuid, aik_pub_path, aik_priv_ca_path)


def get_group_info(num):
    """Returns UUID and path to the group AIK file for vtpm group `num`."""
    # Get info for group `num`
    ginfo = show_group(num)
    uuid = ginfo['uuid']
    aikname = '{0}_aik'.format(uuid)
    pubaik_path = '{0}.pub'.format(aikname)

    # Check that we have the group's AIK
    if not os.path.exists(pubaik_path):
        logger.error('Group %d AIK Path %r doesn\'t exist', num, pubaik_path)
        raise OSError()

    aikbase = '{0}'.format(aikname)
    aikpem = aikbase + '.pem'

    # Convert group AIK to PEM
    check_call('tpmconv -ik {0} -ok {1}'.format(pubaik_path, aikbase),
               shell=True)
    return {'aikpem': aikpem, 'uuid': uuid}


def get_group_symkey(groupnum, keyblob):
    logger.info('Keyblob: %r', open(keyblob, 'rb').read())
    return do_group_activate(groupnum, keyblob)


def do_register_test_helper(groupnum=1,
                            pubekpem='llsrc-vtpm-host0_pubek.pem',
                            keyblob='vtpm_key.blob',
                            symkey='vtpm_key.aes'):
    """ Implementation of ``./vtpm_manager.py test``"""
    # TODO, how do I tell when group 0 hasn't been initialized?

    # We use group 1 by default so  we can add it
    # and delete it without messing with the default group
    num_groups = count_groups()
    if num_groups < 2:
        do_group_add("llsrc-vtpm-host0_pubek.bin")
        time.sleep(1)

    ginfo = get_group_info(groupnum)
    aikpem = ginfo['aikpem']
    goalkey = symkey + '.goal'

    # Use encaik to obtain keyblob and goalkey (normally whoever is using
    # us would handle providing the keyblob)
    check_call('encaik -ik {0!r} -ek {1!r} -ok {2!r} -oak {3!r}'.format(
        aikpem, pubekpem, keyblob, goalkey), shell=True)

    # Obtain the symkey via group activate
    symkey_raw = get_group_symkey(groupnum, keyblob)
    with open(symkey, 'wb') as f:
        f.write(symkey_raw)
    logger.info('Wrote %s', symkey)

    # Verify the key we got from the VTPM is the same as we'd get from encaik
    check_call('diff "{0}" "{1}"'.format(symkey, goalkey), shell=True)
    print('[vtpmmgr] Test succeeded')


def do_register_test():
    do_register_test_helper()


def tpmconv(inmod):
    """ convert a raw modulus file into a pem file """
    tmppath = None
    try:
        # make a temp file for the output
        tmpfd, tmppath = tempfile.mkstemp()

        # make temp file for the input
        infd, intemp = tempfile.mkstemp()
        inFile = open(intemp, "wb")
        inFile.write(inmod)
        inFile.close()
        os.close(infd)

        command = ('tpmconv', '-ik', 'inFile.name', '-ok', tmppath)
        tpm_instance.run(command)

        # read in the pem
        f = open(tmppath, "rb")
        pem = f.read()
        f.close()
        os.close(tmpfd)
    finally:
        if tmppath is not None:
            os.remove(tmppath)
        if inFile is not None:
            os.remove(inFile.name)

    return pem


def get_group_num(desired_uuid):
    desired_uuid = desired_uuid.upper()
    for group_num in range(count_groups()):
        body = vtpm_raw(0x1C2, struct.pack('>II', 0x02000107, group_num))
        (uuid, _, _) = struct.unpack('16s 256s 16s', body)
        uuid = stringify_uuid(uuid)
        if uuid == desired_uuid:
            return group_num
    raise Exception("Group %s not found" % (desired_uuid))


def add_vtpm_group(rsa_mod=None):
    """ Add new vtpm group"""
    fprt = "add_vtpm_group"
    if config.STUB_TPM and config.TPM_CANNED_VALUES is not None:
        # Use canned values for stubbing
        jsonIn = config.TPM_CANNED_VALUES
        if fprt in jsonIn:
            # The value we're looking for has been canned!
            thisTiming = jsonIn[fprt]['timing']
            thisRetout = jsonIn[fprt]['retout']
            logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec" % (
                fprt, thisTiming))
            time.sleep(thisTiming)
            return tuple(thisRetout)

        # Our command hasn't been canned!
        raise Exception("Command %s not found in canned JSON!" % (fprt))

    logger.debug('Adding group')

    t0 = time.time()

    if rsa_mod is None:
        rsa_mod = '\x00' * 256
    assert len(rsa_mod) == 256
    ca_digest = '\x00' * 20
    rsp = vtpm_cmd(VTPM_ORD_GROUP_NEW, ca_digest + rsa_mod)

    (uuid, aik_pub, aik_priv_ca) = struct.unpack('16s256s256s', rsp)
    uuid = struct.unpack(uuid_fmt, uuid)
    uuid = '-'.join([part.encode('hex') for part in uuid])
    logger.info('Created group with UUID: %s', uuid)

    aikpem = tpmconv(aik_pub)
    # return the group
    group_num = get_group_num(uuid)
    t1 = time.time()

    retout = (uuid, aikpem, group_num, base64.b64encode(aik_priv_ca))

    if config.TPM_CANNED_VALUES_PATH is not None:
        with open(config.TPM_CANNED_VALUES_PATH, "ab") as can:
            jsonObj = {
                'type': "add_vtpm_group",
                'retout': list(retout),
                'fileout': "",
                'cmd': "add_vtpm_group",
                'timing': t1 - t0,
                'code': 0,
                'nonce': None
            }
            can.write("\"%s\": %s,\n" % ("add_vtpm_group", json.dumps(
                jsonObj, indent=4, sort_keys=True, Dumper=SafeDumper)))

    return retout


def activate_group(uuid, keyblob):
    fprt = "activate_group"
    if config.STUB_TPM and config.TPM_CANNED_VALUES is not None:
        # Use canned values for stubbing
        jsonIn = config.TPM_CANNED_VALUES
        if fprt in jsonIn:
            # The value we're looking for has been canned!
            thisTiming = jsonIn[fprt]['timing']
            thisRetout = jsonIn[fprt]['retout']
            logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec" % (
                fprt, thisTiming))
            time.sleep(thisTiming)
            return base64.b64decode(thisRetout)

        # Our command hasn't been canned!
        raise Exception("Command %s not found in canned JSON!" % (fprt))

    t0 = time.time()
    group_id = get_group_num(uuid)
    priv_ca = base64.b64decode(keyblob)
    assert len(priv_ca) == 256
    logger.debug('Activating group number %d', group_id)
    body = vtpm_cmd(VTPM_ORD_GROUP_ACTIVATE,
                    struct.pack('>II', group_id, 256) + priv_ca)
    (algId, encScheme, size), body = unpack('>IHH', body)
    assert size == len(body)
    t1 = time.time()
    logger.info('Received Key. AlgID: 0x%x, encScheme: 0x%x, size: 0x%x',
                algId, encScheme, size)
    logger.info('Key: %r', body)

    if config.TPM_CANNED_VALUES_PATH is not None:
        with open(config.TPM_CANNED_VALUES_PATH, "ab") as can:
            jsonObj = {
                'type': "activate_group",
                'retout': base64.b64encode(body),
                'fileout': "",
                'cmd': "activate_group",
                'timing': t1 - t0,
                'code': 0,
                'nonce': None
            }
            can.write("\"%s\": %s,\n" % ("activate_group",
                                         json.dumps(jsonObj, indent=4, sort_keys=True)))

    return body


def add_vtpm_to_group(uuid):
    fprt = "add_vtpm_to_group"
    if config.STUB_TPM and config.TPM_CANNED_VALUES is not None:
        # Use canned values for stubbing
        jsonIn = config.TPM_CANNED_VALUES
        if fprt in jsonIn:
            # The value we're looking for has been canned!
            thisTiming = jsonIn[fprt]['timing']
            thisRetout = jsonIn[fprt]['retout']
            logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec" % (
                fprt, thisTiming))
            time.sleep(thisTiming)
            return thisRetout

        # Our command hasn't been canned!
        raise Exception("Command %s not found in canned JSON!" % (fprt))

    t0 = time.time()
    num = get_group_num(uuid)
    vtpm_uuid = add_vtpm(num)
    t1 = time.time()

    retout = str(UUID(vtpm_uuid)).upper()

    if config.TPM_CANNED_VALUES_PATH is not None:
        with open(config.TPM_CANNED_VALUES_PATH, "ab") as can:
            jsonObj = {
                'type': "add_vtpm_to_group",
                'retout': retout,
                'fileout': "",
                'cmd': "add_vtpm_to_group",
                'timing': t1 - t0,
                'code': 0,
                'nonce': None
            }
            can.write("\"%s\": %s,\n" % ("add_vtpm_to_group",
                                         json.dumps(jsonObj, indent=4, sort_keys=True)))

    return retout
