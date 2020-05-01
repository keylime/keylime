"""
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of
Defense for Research and Engineering under Air Force Contract No.
FA8721-05-C-0002 and/or FA8702-15-D-0001.
Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the
views of the Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S.
Government rights in this work are defined by DFARS 252.227-7013 or
DFARS 252.227-7014 as detailed above.
Use of this work other than as specifically authorized by the U.S. Government
may violate any copyrights that exist in this work.
"""

import setuptools
from setuptools import Extension
import sys

extensions = []

if '--with-clime' in sys.argv:
    if 'linux' in sys.platform:
        extensions.append(
            Extension('_cLime', ['keylime/_cLime.c'],
                      define_macros=[('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                      include_dirs=['/usr/local/include'],
                      libraries=['tpm', 'keylime'],
                      library_dirs=['/usr/local/lib'],
                      runtime_library_dirs=['/usr/local/lib']))
    sys.argv.remove('--with-clime')

setuptools.setup(
    setup_requires=['pbr'],
    pbr=True,
    ext_modules=extensions,
    data_files = [('/etc', ['keylime.conf'])])
