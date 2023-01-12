import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, cast

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict


EXIT_SUCESS = 0

EnvType = Dict[str, str]


class RetDictType(TypedDict):
    retout: List[bytes]
    reterr: List[bytes]
    code: int
    fileouts: Dict[str, bytes]
    timing: Dict[str, float]


def _execute(cmd: Sequence[str], env: Optional[EnvType] = None, **kwargs: Any) -> Tuple[bytes, bytes, int]:
    with subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs) as proc:
        out, err = proc.communicate()
        # All callers assume to receive a list of bytes back; none of them uses 'text mode'
        assert isinstance(out, bytes)
        assert isinstance(err, bytes)
        return out, err, proc.returncode


def run(
    cmd: Sequence[str],
    expectedcode: int = EXIT_SUCESS,
    raiseOnError: bool = True,
    outputpaths: Optional[Union[List[str], str]] = None,
    env: Optional[EnvType] = None,
    **kwargs: Any,
) -> RetDictType:
    """Execute external command.

    :param cmd: a sequence of command arguments
    """
    if env is None:
        env = cast(EnvType, os.environ)  # cannot use os._Environ as type

    t0 = time.time()
    retout, reterr, code = _execute(cmd, env=env, **kwargs)

    t1 = time.time()
    timing = {"t1": t1, "t0": t0}

    # Gather subprocess response data; retout & reterr are assumed to be 'bytes'
    retout_list = retout.splitlines(keepends=True)
    reterr_list = reterr.splitlines(keepends=True)

    # Don't bother continuing if call failed and we're raising on error
    if code != expectedcode and raiseOnError:
        raise Exception(
            f"Command: {cmd} returned {code}, expected {expectedcode}, " f"output {reterr_list}, stderr {reterr_list}"
        )

    # Prepare to return their file contents (if requested)
    fileouts = {}
    if isinstance(outputpaths, str):
        outputpaths = [outputpaths]
    if isinstance(outputpaths, list):
        for thispath in outputpaths:
            with open(thispath, "rb") as f:
                fileouts[thispath] = f.read()

    returnDict: RetDictType = {
        "retout": retout_list,
        "reterr": reterr_list,
        "code": code,
        "fileouts": fileouts,
        "timing": timing,
    }
    return returnDict


# list_contains_substring checks whether a substring is contained in the given
# list. The list may be the reterr from 'run' and contains bytes-like objects.
def list_contains_substring(lst: List[bytes], substring: str) -> bool:
    for s in lst:
        if substring in str(s):
            return True
    return False
