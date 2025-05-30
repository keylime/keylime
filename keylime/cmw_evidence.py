import base64
import json
from typing import Any, Dict, List, Optional, Union

import requests

AGENT_URL = "https://localhost:9002/v2.2/quotes/integrity"
NONCE = "1234567890ABCDEFHIJK"
PCR_MASK = "0x10401"
PARTIAL = "0"

CLIENT_CERT = "/var/lib/keylime/cv_ca/client-cert.crt"
CLIENT_KEY = "/var/lib/keylime/cv_ca/client-private.pem"

CMW_COLLECTION_TYPE = "tag:keylime.org,2025:tpm2-agent"


def get_keylime_quote() -> Optional[Dict[str, Any]]:
    try:
        response = requests.get(
            AGENT_URL,
            params={"nonce": NONCE, "mask": PCR_MASK, "partial": PARTIAL},
            cert=(CLIENT_CERT, CLIENT_KEY),
            verify=False,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()["results"]  # type: ignore[no-any-return]
    except requests.exceptions.RequestException as err:
        print(f"Error fetching Keylime quote: {err}")
        return None


def build_event_log(ima_list_str: str, mb_list_b64: str) -> List[Dict[str, Any]]:
    event_log_entries = []
    recnum = 0

    # Parse IMA measurement list (PCR 10)
    if ima_list_str:
        lines = ima_list_str.strip().splitlines()
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 5:
                continue  # unexpected format

            try:
                pcr_index = int(parts[0])
                template_type = parts[2]
                template_hash = parts[3]

                if ":" not in template_hash:
                    continue  # unexpected format

                hash_alg, hash_val = template_hash.split(":", 1)
                path = parts[4]
                digest = bytes.fromhex(hash_val)

                event_log_entries.append(
                    {
                        "recnum": recnum,
                        "pcr": pcr_index,
                        "digests": [
                            {
                                "hashAlg": hash_alg.lower(),
                                "digest": base64.urlsafe_b64encode(digest).rstrip(b"=").decode(),
                            }
                        ],
                        "content_type": "ima_template",
                        "content": {
                            "template_name": template_type,
                            "template_data": base64.urlsafe_b64encode(f"{template_hash} {path}".encode())
                            .rstrip(b"=")
                            .decode(),
                        },
                    }
                )
                recnum += 1

            except Exception as err:
                print(f"[warning] Skipping IMA line due to error: {err}")
                continue

    # Parse Measured Boot Log (PCR 0)
    if mb_list_b64:
        try:
            raw_mb_log = base64.b64decode(mb_list_b64)
            event_log_entries.append(
                {
                    "recnum": recnum,
                    "pcr": 0,
                    "digests": [
                        {
                            "hashAlg": "sha1",  # assumed hash
                            "digest": base64.urlsafe_b64encode(raw_mb_log[:20]).rstrip(b"=").decode(),
                        }
                    ],
                    "content_type": "pcclient_std",
                    "content": base64.urlsafe_b64encode(raw_mb_log).rstrip(b"=").decode(),
                }
            )
            recnum += 1
        except Exception as err:
            print(f"[error] Failed to parse measured boot log: {err}")

    return event_log_entries


def get_keylime_metadata(kdata: Dict[str, Any]) -> Dict[str, Optional[Union[str, int]]]:
    return {
        "boottime": kdata.get("boottime"),
        "pubkey": kdata.get("pubkey"),
        "hash_alg": kdata.get("hash_alg"),
        "sign_alg": kdata.get("sign_alg"),
    }


def parse_quote_fields(quote_str: str) -> Dict[str, bytes]:
    parts = quote_str.split(":")
    if len(parts) != 3:
        raise ValueError("Unexpected quote format.")
    return {
        "TPMS_ATTEST": parts[0].encode(),
        "TPMT_SIGNATURE": parts[1].encode(),
        "PCRs": parts[2].encode(),
    }


def build_cmw_collection(
    pquote: Dict[str, bytes], evlog: List[Dict[str, Any]], meta: Dict[str, Optional[Union[str, int]]]
) -> Dict[str, Any]:
    return {
        "__cmwc_t": CMW_COLLECTION_TYPE,
        "evidence": {
            "tpms_attest": [
                "application/vnd.keylime.tpm2.tpms_attest",
                base64.urlsafe_b64encode(pquote["TPMS_ATTEST"]).rstrip(b"=").decode(),
            ],
            "tpmt_signature": [
                "application/vnd.keylime.tpm2.tpmt_signature",
                base64.urlsafe_b64encode(pquote["TPMT_SIGNATURE"]).rstrip(b"=").decode(),
            ],
            "pcr_values": [
                "application/vnd.keylime.tpm2.pcr_values",
                base64.urlsafe_b64encode(pquote["PCRs"]).rstrip(b"=").decode(),
            ],
            "event_log": [
                "application/vnd.keylime.cel",
                base64.urlsafe_b64encode(json.dumps(evlog).encode()).rstrip(b"=").decode(),
            ],
            "keylime_metadata": [
                "application/vnd.keylime.tpm2.metadata",
                base64.urlsafe_b64encode(json.dumps(meta).encode()).rstrip(b"=").decode(),
            ],
        },
    }


if __name__ == "__main__":
    keylime_quote_data: Optional[Dict[str, Any]] = get_keylime_quote()
    if keylime_quote_data:
        try:
            parsed_quote_data = parse_quote_fields(keylime_quote_data["quote"])
            ima_raw: str = keylime_quote_data.get("ima_measurement_list", "")
            mb_raw: str = keylime_quote_data.get("mb_measurement_list", "")
            event_log_built = build_event_log(ima_raw, mb_raw)
            metadata_obj = get_keylime_metadata(keylime_quote_data)
            cmw_output = build_cmw_collection(parsed_quote_data, event_log_built, metadata_obj)
            print(json.dumps(cmw_output, indent=2))

        except ValueError as val_err:
            print(f"Error parsing quote: {val_err}")
        except Exception as unexp_err:
            print(f"An unexpected error occurred: {unexp_err}")
