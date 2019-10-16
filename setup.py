'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''


# Always prefer setuptools over distutils
from setuptools import setup, find_packages, Extension
# To use a consistent encoding
from codecs import open
from os import path
from os import walk
from os import geteuid
import sys

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'DESCRIPTION.md'), encoding='utf-8') as f:
    long_description = f.read()

# cLime only builds against glibc at the moment. If we ever want to change this
# it shouldn't be too hard.
extensions = []
if '--with-clime' in sys.argv:
    if 'linux' in sys.platform:
        extensions.append(Extension('_cLime',
                                define_macros = [('MAJOR_VERSION', '1'),
                                                 ('MINOR_VERSION', '0')],
                                include_dirs = ['/usr/local/include'],
                                libraries = ['tpm', 'keylime'],
                                library_dirs = ['/usr/local/lib'],
                                runtime_library_dirs = ['/usr/local/lib'],
                                sources = ['keylime/_cLime.c']))
    sys.argv.remove('--with-clime')

# enumerate all of the data files we need to package up
if geteuid() == 0:
    data_files = [('/etc', ['keylime.conf'])]
else:
    data_files = [('package_default', ['keylime.conf'])]
    
setup(
    name='keylime',

    # Versions should comply with PEP440.  For a discussion on single-sourcing
    # the version across setup.py and the project code, see
    # https://packaging.python.org/en/latest/single_source_version.html
    version='5.2.0',

    description='TPM-based key bootstrapping and system integrity measurement system for cloud',
    long_description=long_description,

    # The project's main homepage.
    url='https://github.com/keylime/keylime',

    # Author details
    author='MIT Lincoln Laboratory',
    author_email='nabil@ll.mit.edu',

    # Choose your license
    license='BSD-2-Clause',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',

        # where does it run
        'Environment :: Console',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: BSD License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.7',
    ],

    # What does your project relate to?
    keywords='tpm cloud cloud-init tls',

    # You can just specify the packages manually here if your project is
    # simple. Or you can use find_packages().
    packages=['keylime'],
    package_data={'keylime': ['static/*/*', 'static/*/*/*']},

    # List run-time dependencies here.  These will be installed by pip when
    # your project is installed. For an analysis of "install_requires" vs pip's
    # requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['cryptography>=2.1.4','tornado>=5.0.2','m2crypto>=0.21.1','pyzmq>=14.4','pyyaml>=3.11','simplejson>=3.8','requests>=2.6'],

    # test packages required
    tests_require=['green','coverage'],

    # List additional groups of dependencies here (e.g. development
    # dependencies). You can install these using the following syntax,
    # for example:
    # $ pip install -e .[dev,test]
    #extras_require={
    #    'dev': ['check-manifest'],
    #    'test': ['coverage'],
    #},

    # If there are data files included in your packages that need to be
    # installed, specify them here.  If using Python 2.6 or less, then these
    # have to be included in MANIFEST.in as well.

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files # noqa
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    data_files=data_files,

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'keylime_verifier=keylime.cloud_verifier_tornado:main',
            'keylime_provider_verifier=keylime.provider_verifier:main',
            'keylime_agent=keylime.cloud_agent:main',
            'keylime_tenant=keylime.tenant:main',
            'keylime_userdata_encrypt=keylime.user_data_encrypt:main',
            'keylime_registrar=keylime.registrar:main',
            'keylime_provider_registrar=keylime.provider_registrar:main',
            'keylime_provider_platform_init=keylime.provider_platform_init:main',
            'keylime_provider_vtpm_add=keylime.provider_vtpm_add:main',
            'keylime_ca=keylime.ca_util:main',
            'keylime_ima_emulator=keylime.ima_emulator_adapter:main',
            'keylime_webapp=keylime.tenant_webapp:main',
        ],
    },

    ext_modules = extensions
)