import sys
from typing import Dict

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


TpmsAttestType = TypedDict(
    "TpmsAttestType",
    {
        "extraData": bytes,
        "clockInfo": Dict[str, int],
        "attested.quote.pcrDigest": bytes,
    },
)
