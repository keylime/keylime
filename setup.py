'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''
import sys
import setuptools

from setuptools import Extension


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


with open('README.md', 'r') as fh:
    long_description = fh.read()


setuptools.setup(
    name='keylime',
    description=(
        'TPM-based key bootstrapping and system '
        'integrity measurement system for cloud'),
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Keylime Community',
    author_email='keylime@groups.io',
    url='https://keylime.dev',
    python_requires='>=3.6',
    packages=setuptools.find_packages(exclude=['test*']),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: System :: Hardware',
    ],
    entry_points={
        "console_scripts": [
            'keylime_verifier=keylime.cmd.verifier:main',
            'keylime_agent=keylime.cmd.agent:main',
            'keylime_tenant=keylime.cmd.tenant:main',
            'keylime_userdata_encrypt=keylime.cmd.user_data_encrypt:main',
            'keylime_registrar=keylime.cmd.registrar:main',
            'keylime_provider_registrar=keylime.cmd.provider_registrar:main',
            'keylime_provider_platform_init=keylime.cmd.provider_platform_init:main',  # noqa
            'keylime_provider_vtpm_add=keylime.cmd.provider_vtpm_add:main',
            'keylime_ca=keylime.cmd.ca:main',
            'keylime_ima_emulator=keylime.cmd.ima_emulator_adapter:main',
            'keylime_webapp=keylime.cmd.webapp:main',
            'keylime_migrations_apply=keylime.cmd.migrations_apply:main',
        ],
    },
    ext_modules=extensions,
    data_files=[('/etc', ['keylime.conf'])],
    package_data={'keylime': ['migrations/alembic.ini']}
)
