"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Angelo Ruocco - IBM Research Lab Zurich
"""

import random
import unittest

from keylime.common import retry


def rand_base():
    return random.uniform(-99, 99)


def rand_base_proper():
    return random.uniform(1, 99)


def rand_ntries():
    return random.randint(1, 99)


def rand_exp():
    return random.choice([True, False])


class RetryInterval_Test(unittest.TestCase):
    def test_general(self):
        self.assertTrue(retry.retry_time(rand_exp(), rand_base(), rand_ntries(), None) >= 0)

    def test_linear(self):
        b = rand_base()
        self.assertEqual(retry.retry_time(False, b, rand_ntries(), None), abs(b))

    def test_exponential(self):
        b0 = rand_base_proper()
        b1 = random.random()
        n = rand_ntries()
        self.assertEqual(retry.retry_time(True, b0, n, None), b0**n)
        self.assertEqual(retry.retry_time(True, b1, n, None), abs(b1))


if __name__ == "__main__":
    unittest.main()
