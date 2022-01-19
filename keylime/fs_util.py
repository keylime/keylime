"""Utility module for secure directory management."""

import os


def ch_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, 0o700)
    os.umask(0o077)
    os.chdir(path)
