"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""

import configparser
import os
import sys

import setuptools
from setuptools.command.build_py import build_py


class keylime_build(build_py):
    def run(self):

        # Generate the split configuration files, if not present
        setup_dir = os.path.dirname(os.path.abspath(__file__))
        config_dir = os.path.join(setup_dir, "config")
        if not os.path.exists(config_dir):
            sys.path.append(setup_dir)
            import keylime.cmd.convert_config as convert  # pylint: disable=C0415

            os.mkdir(config_dir)
            # Empty configuration makes the scripts to use the default value for
            # all options
            old_config = configparser.RawConfigParser()
            templates_dir = os.path.join(setup_dir, "templates")
            config = convert.process_versions(convert.COMPONENTS, templates_dir, old_config)
            convert.output(convert.COMPONENTS, config, templates_dir, config_dir)

        build_py.run(self)


if __name__ == "__main__":
    setuptools.setup(cmdclass={"build_py": keylime_build})
