"""Bridge shim - adapts the navi bridge's run(args) onto app_labkit.core."""

import shlex
import sys
import os

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from app_labkit import core


def run(args):
    text = getattr(args, "text", "") or ""
    try:
        argv = shlex.split(text)
    except ValueError as exc:
        print(f"error: could not parse arguments: {exc}")
        return
    core.run_command(argv)


def main(argv=None):
    return core.run_command(list(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
