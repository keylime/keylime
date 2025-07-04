import base64
import json
from io import BytesIO
from typing import Any, Dict

import requests


def decode_base64url(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def read_tlv(stream: BytesIO):
    tag_bytes = stream.read(1)
    if not tag_bytes:
        return None, None, None
    tag = tag_bytes[0]
    length_bytes = stream.read(4)
    if len(length_bytes) < 4:
        return None, None, None
    length = int.from_bytes(length_bytes, "big")
    value = stream.read(length)
    return tag, length, value


def parse_cel(event_log: bytes):
    stream = BytesIO(event_log)
    ima_lines = []
    mb_base64 = None

    while True:
        tag, _, _ = read_tlv(stream)
        if tag is None:
            break
        if tag != 0:
            continue  # skip non-recnum start

        tag, _, pcr_val = read_tlv(stream)
        if tag != 1 or not pcr_val:
            continue
        pcr_index = pcr_val[0]

        tag, _, digests_val = read_tlv(stream)
        if tag != 3 or not digests_val:
            continue
        digest_stream = BytesIO(digests_val)
        digest_tag, _, _ = read_tlv(digest_stream)
        if digest_tag is None:
            continue

        tag, _, content_val = read_tlv(stream)
        if tag != 5 or not content_val:
            continue
        content_stream = BytesIO(content_val)
        content_type_tag, _, content_data = read_tlv(content_stream)

        if content_type_tag == 6:  # IMA
            template_stream = BytesIO(content_data)
            template_name = ""
            template_data_bytes = b""
            file_hash = ""
            while True:
                inner_tag, _, inner_val = read_tlv(template_stream)
                if inner_tag is None:
                    break
                if inner_tag == 7:
                    template_name = inner_val.decode("utf-8", errors="ignore")
                elif inner_tag == 8:
                    template_data_bytes = inner_val
                elif inner_tag == 10:  # TYPE_FILE_HASH
                    file_hash = inner_val.decode("utf-8", errors="ignore")

            if template_data_bytes:
                try:
                    template_str_from_rust = template_data_bytes.decode(errors="ignore").strip()
                    parts = template_str_from_rust.split(" ", 1)
                    algo_digest = parts[0] if len(parts) > 0 else ""
                    name = parts[1] if len(parts) > 1 else ""

                    # Build the original IMA line
                    line = f"{pcr_index} {file_hash} {template_name} {algo_digest} {name}"
                    ima_lines.append(line)
                except Exception:
                    continue

        elif content_type_tag == 9:  # MB block
            mb_base64 = base64.b64encode(content_data).decode()

    return "\n".join(ima_lines), mb_base64


def decode_cmw_to_keylimequote(cmw_json: Dict[str, Any]) -> Dict[str, Any]:
    evidence = cmw_json["evidence"]

    tpms_attest = decode_base64url(evidence["tpms_attest"][1])
    tpmt_signature = decode_base64url(evidence["tpmt_signature"][1])
    pcr_values = decode_base64url(evidence["pcr_values"][1])
    event_log = decode_base64url(evidence["event_log"][1])
    metadata_json = decode_base64url(evidence["keylime_metadata"][1])
    metadata = json.loads(metadata_json.decode("utf-8"))

    ima_ml, mb_ml = parse_cel(event_log)

    quote_str = f"r{base64.b64encode(tpms_attest).decode()}:{base64.b64encode(tpmt_signature).decode()}:{base64.b64encode(pcr_values).decode()}"

    return {
        "quote": quote_str,
        "hash_alg": metadata.get("hash_alg", "sha256"),
        "enc_alg": "rsa",
        "sign_alg": metadata.get("sign_alg", "rsassa"),
        "pubkey": metadata.get("pubkey"),
        "ima_measurement_list": ima_ml if ima_ml else None,
        "mb_measurement_list": mb_ml if mb_ml else None,
        "ima_measurement_list_entry": 0,
    }


def fetch_and_decode_cmw(url: str, cert: str, key: str, verify_ssl: bool = False) -> Dict[str, Any]:
    response = requests.get(url, cert=(cert, key), verify=verify_ssl, timeout=10)
    response.raise_for_status()
    cmw_json = response.json()["results"]
    return decode_cmw_to_keylimequote(cmw_json)


# Example usage
# if __name__ == "__main__":
#     url = "https://localhost:9002/v2.4/quotes/integrity?nonce=1234567890ABCDEF&mask=0x10401&partial=0"
#     cert_path = "/var/lib/keylime/cv_ca/client-cert.crt"
#     key_path = "/var/lib/keylime/cv_ca/client-private.pem"

#     quote = fetch_and_decode_cmw(url, cert_path, key_path)
#     print(json.dumps(quote, indent=2))
