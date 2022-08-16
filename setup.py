"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""

import os
import sys

import setuptools
from setuptools.command.build_py import build_py


class keylime_build(build_py):
    def run(self):

        # Generate the split configuration files, if not present
        setup_dir = os.path.dirname(os.path.abspath(__file__))
        config_dir = os.path.join(setup_dir, "config")
        keylime_conf = os.path.join(setup_dir, "keylime.conf")
        if not os.path.exists(config_dir) and os.path.exists(keylime_conf):
            sys.path.append(setup_dir)
            import scripts.convert_config as convert  # pylint: disable=C0415

            os.mkdir(config_dir)
            old_config = convert.get_config([[keylime_conf]])
            templates_dir = os.path.join(setup_dir, "scripts/templates")
            config = convert.process_versions(templates_dir, old_config)
            # Empty components list makes the script to output the config for
            # all components
            convert.output([], config, templates_dir, config_dir)

        build_py.run(self)


if __name__ == "__main__":
    setuptools.setup(cmdclass={"build_py": keylime_build})
