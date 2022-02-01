'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import setuptools


with open('README.md', encoding="utf-8") as fh:
    long_description = fh.read()


setuptools.setup(
    name='keylime',
    version='6.3.1',
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
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: System :: Hardware',
    ],
    entry_points={
        "console_scripts": [
            'keylime_verifier=keylime.cmd.verifier:main',
            'keylime_agent=keylime.cmd.agent:main',
            'keylime_tenant=keylime.cmd.tenant:main',
            'keylime_userdata_encrypt=keylime.cmd.user_data_encrypt:main',
            'keylime_registrar=keylime.cmd.registrar:main',
            'keylime_ca=keylime.cmd.ca:main',
            'keylime_ima_emulator=keylime.cmd.ima_emulator_adapter:main',
            'keylime_webapp=keylime.cmd.webapp:main',
            'keylime_migrations_apply=keylime.cmd.migrations_apply:main',
        ],
    },
    package_data={'keylime': ['migrations/alembic.ini', "keylime.conf"]}
)
