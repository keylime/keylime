"""Utility module for secure directory management."""

import os


def ch_dir(path: str) -> None:
    """Change directory and create it if missing."""
    if not os.path.exists(path):
        os.makedirs(path, 0o700)
    os.chdir(path)
