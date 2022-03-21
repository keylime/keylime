"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Kaifeng Wang
"""

import time


class Timer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.start = 0
        self.end = 0
        self.secs = 0
        self.msecs = 0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs
        if self.verbose:
            print(f'elapsed time: {self.msecs} ms')


def timerfunc(func):
    """
    A timer decorator for debugging function return times.
    To use, decorate a function with @common.timerfunc
    """
    def function_timer(*args, **kwargs):
        """
        A nested function for timing other functions
        """
        start = time.time()
        value = func(*args, **kwargs)
        end = time.time()
        runtime = end - start
        msg = "The runtime for {func} took {time} seconds to complete"
        print(msg.format(func=func.__name__,
                         time=runtime))
        return value
    return function_timer
