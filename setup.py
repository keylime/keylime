'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

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
    ext_modules=extensions,
    data_files=[('/etc', ['keylime.conf'])])
