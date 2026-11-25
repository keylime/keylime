"""Claims translators, one module per evidence type.

This package's __init__ is the explicit registration point: each import
below registers one translator in the translator registry. Adding a new
evidence type = one new module + one import line here.
"""

from keylime.claims.translators import tpm  # noqa: F401  (registration side effect)
from keylime.claims.translators import tee_snp  # noqa: F401  (registration side effect)
