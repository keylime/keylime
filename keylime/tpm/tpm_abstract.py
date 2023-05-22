import string
from typing import Any, Dict, Optional

from keylime import config, crypto, json, keylime_logging

logger = keylime_logging.init_logging("tpm")


class TPM_Utilities:
    @staticmethod
    def check_mask(mask: Optional[str], pcr: int) -> bool:
        if mask is None:
            return False
        return bool(1 << pcr & int(mask, 0))

    @staticmethod
    def random_password(length: int = 20) -> str:
        rand = crypto.generate_random_key(length)
        chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
        password = ""
        for i in range(length):
            password += chars[(rand[i]) % len(chars)]
        return password

    @staticmethod
    def readPolicy(configval: str) -> Dict[str, Any]:
        policy: Dict[str, Any] = json.loads(configval)

        # compute PCR mask from tpm_policy
        mask = 0
        for key in list(policy.keys()):
            if not key.isdigit() or int(key) > 24:
                raise Exception(f"Invalid tpm policy pcr number: {key}")

            if int(key) == config.TPM_DATA_PCR:
                raise Exception(f"Invalid allowlist PCR number {key}, keylime uses this PCR to bind data.")
            if int(key) == config.IMA_PCR:
                raise Exception(f"Invalid allowlist PCR number {key}, this PCR is used for IMA.")

            mask = mask | (1 << int(key))

            # wrap it in a list if it is a singleton
            if isinstance(policy[key], str):
                policy[key] = [policy[key]]

            # convert all hash values to lowercase
            policy[key] = [x.lower() for x in policy[key]]

        policy["mask"] = hex(mask)
        return policy
