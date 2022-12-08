from typing import Dict

from keylime import json, keylime_logging

logger = keylime_logging.init_logging("print_metadata")


async def execute(revocation: Dict[str, str]) -> None:
    print(json.loads(revocation["meta_data"]))
