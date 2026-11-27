"""Output renderers, one module per output format.

This package is the explicit registration point: each import below
registers one renderer in the renderer registry. Adding a new output
format = one new module + one import line here (+ an OutputFormat enum
member, which is the web layer's negotiation key).
"""

from keylime.claims.renderers import ear_jwt, jsonapi  # noqa: F401  (registration side effect)
