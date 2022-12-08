import base64
import os
import sys
from typing import Dict

from keylime import crypto


def usage() -> None:
    print("Please pass in a file input file to encrypt")
    sys.exit(-1)


def encrypt(contents: bytes) -> Dict[str, bytes]:
    k = crypto.generate_random_key(32)
    v = crypto.generate_random_key(32)
    u = crypto.strbitxor(k, v)
    ciphertext = crypto.encrypt(contents, k)

    # Try decrypting to check encrypted content
    recovered = crypto.decrypt(ciphertext, k)

    if recovered != contents:
        raise Exception("Test decryption failed")
    return {"u": u, "v": v, "k": k, "ciphertext": ciphertext}


def main() -> None:
    if len(sys.argv) < 2:
        usage()

    infile = sys.argv[1]

    if not os.path.isfile(infile):
        print(f"ERROR: File %s not found. {infile}")
        usage()

    with open(infile, "rb") as f:
        contents = f.read()

    ret = encrypt(contents)

    print("Writing keys to content_keys.txt")
    with open("content_keys.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(ret["k"]).decode("utf-8"))
        f.write("\n")
        f.write(base64.b64encode(ret["v"]).decode("utf-8"))
        f.write("\n")
        f.write(base64.b64encode(ret["u"]).decode("utf-8"))
        f.write("\n")

    print("Writing encrypted data to content_payload.txt")
    with open("content_payload.txt", "w", encoding="utf-8") as f:
        f.write(ret["ciphertext"].decode("utf-8"))


if __name__ == "__main__":
    main()
