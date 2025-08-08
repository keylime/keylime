import cryptography
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from keylime.failure import Component, Failure


# Verify that a SEV-SNP attestation report is verified by a VEK.
def verify_attestation(report: bytes, gen: str, nonce: str) -> Failure:
    failure = Failure(Component.TEE)

    if gen not in ("Milan", "Genoa"):
        failure.add_event(
            "invalid_generation",
            {"message": f"invalid SEV-SNP processor generation: {gen}", "data": gen},
            False,
        )
        return failure

    reported_tcb = report[0x180:0x188]

    hw_id = report[0x1A0:0x1E0].hex()
    bl = str(reported_tcb[0]).zfill(2)
    tee = str(reported_tcb[1]).zfill(2)
    snp = str(reported_tcb[6]).zfill(2)
    ucode = str(reported_tcb[7]).zfill(2)

    vcek_url = "https://kdsintf.amd.com/vcek/v1/"
    vcek_url += gen + "/"
    vcek_url += hw_id + "?"
    vcek_url += "blSPL=" + bl
    vcek_url += "&teeSPL=" + tee
    vcek_url += "&snpSPL=" + snp
    vcek_url += "&ucodeSPL=" + ucode

    res = requests.get(vcek_url)
    if res.status_code != 200:
        failure.add_event(
            "vcek_fetch",
            {"message": "unable to fetch VCEK for SEV-SNP report"},
            False,
        )
        return failure

    vcek_x509 = cryptography.x509.load_der_x509_certificate(res.content, default_backend())
    pk = vcek_x509.public_key()

    sig = report[0x2A0:0x49F]
    r = int.from_bytes(sig[:0x48], byteorder="little")
    s = int.from_bytes(sig[0x48:0x90], byteorder="little")

    signature = encode_dss_signature(r, s)

    try:
        pk.verify(signature, report[:0x2A0], ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as _:
        failure.add_event(
            "invalid_signature",
            {"message": "VEK public key does not sign SEV-SNP attestation report"},
            False,
        )

    return failure
