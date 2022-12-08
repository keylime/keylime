import argparse
import codecs
import itertools
import select
import sys
import time
from typing import Optional

from keylime import config
from keylime.common import algorithms
from keylime.ima import ast
from keylime.tpm.tpm_main import tpm

# Instaniate tpm
tpm_instance = tpm(need_hw_tpm=True)


def measure_list(
    file_path: str,
    position: int,
    ima_hash_alg: algorithms.Hash,
    pcr_hash_alg: algorithms.Hash,
    search_val: Optional[str] = None,
) -> int:
    with open(file_path, encoding="utf-8") as f:
        lines = itertools.islice(f, position, None)

        runninghash = ast.get_START_HASH(pcr_hash_alg)

        search_val_bytes = None
        if search_val is not None:
            search_val_bytes = codecs.decode(search_val.encode("utf-8"), "hex")

        for line in lines:
            # remove only the newline character, as there can be the
            # space as the delimiter character followed by an empty
            # field at the end
            line = line.strip("\n")
            position += 1

            entry = ast.Entry(line, None, ima_hash_alg=ima_hash_alg, pcr_hash_alg=pcr_hash_alg)

            if search_val_bytes is None:
                val = codecs.encode(entry.pcr_template_hash, "hex").decode("utf8")
                tpm_instance.extendPCR(config.IMA_PCR, val, pcr_hash_alg)
            else:
                runninghash = pcr_hash_alg.hash(runninghash + entry.pcr_template_hash)
                if runninghash == search_val_bytes:
                    return position

        if search_val_bytes is not None:
            raise Exception(
                "Unable to find current measurement list position, Resetting the TPM emulator may be neccesary"
            )

    return position


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--hash_algs", nargs="*", default=["sha1"], help="PCR banks hash algorithms")
    parser.add_argument("-i", "--ima-hash-alg", default="sha1", help="Set hash algorithm that is used in IMA log")
    parser.add_argument("-f", "--ima-log", default=config.IMA_ML, help="path to the IMA log")
    args = parser.parse_args()

    if not tpm_instance.is_emulator():
        raise Exception("This stub should only be used with a TPM emulator")

    ima_hash_alg = algorithms.Hash(args.ima_hash_alg)
    position = {}
    for pcr_hash_alg in args.hash_algs:
        pcr_hash_alg = algorithms.Hash(pcr_hash_alg)
        position[pcr_hash_alg] = 0

    for pcr_hash_alg in dict(position):
        try:
            pcr_val = tpm_instance.readPCR(config.IMA_PCR, pcr_hash_alg)
        except Exception as ex:
            print(f"Error: {ex}")
            sys.exit(1)

        if codecs.decode(pcr_val.encode("utf-8"), "hex") != ast.get_START_HASH(pcr_hash_alg):
            print(
                f"Warning: IMA PCR is not empty for hash algorithm {pcr_hash_alg}, "
                "trying to find the last updated file in the measurement list..."
            )
            position[pcr_hash_alg] = measure_list(
                args.ima_log, position[pcr_hash_alg], ima_hash_alg, pcr_hash_alg, pcr_val
            )

    print(f"Monitoring {args.ima_log}")
    poll_object = select.poll()
    with open(args.ima_log, encoding="utf-8") as fd_object:
        number = fd_object.fileno()
        poll_object.register(fd_object, select.POLLIN | select.POLLPRI)

        try:
            while True:
                results = poll_object.poll()
                for result in results:
                    if result[0] != number:
                        continue
                    for pcr_hash_alg, pos in position.items():
                        position[pcr_hash_alg] = measure_list(args.ima_log, pos, ima_hash_alg, pcr_hash_alg)

                    time.sleep(0.2)
        except (SystemExit, KeyboardInterrupt):
            sys.exit(1)


if __name__ == "__main__":
    main()
