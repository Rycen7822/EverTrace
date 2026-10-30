"""The version path deliberately imports no server, template or HTTP runtime."""
import argparse
import errno
from importlib.metadata import version
import json
import re
import sys


def main():
    parser = argparse.ArgumentParser(prog="evertrace-web")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--startup-stdin", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or later is required for the optional Web component")
    build = version("evertrace-web")
    if args.version:
        print(f"evertrace-web {build}")
        return
    if not args.startup_stdin or sys.stdin.isatty() or not 0 <= args.port <= 65535:
        parser.error("a private launcher stdin and valid loopback port are required")
    raw = sys.stdin.buffer.read(8193)
    try:
        context = json.loads(raw)
        if len(raw) > 8192 or set(context) != {"socket", "config_hash", "build_id"}:
            raise ValueError()
        if not isinstance(context["socket"], str) or not context["socket"].startswith("/") or not re.fullmatch("[0-9a-f]{64}", context["config_hash"]) or context["build_id"] != build:
            raise ValueError()
    except (ValueError, TypeError):
        parser.error("invalid private startup context")
    from . import BackendError
    try:
        from .server import run
        run(context, args.port)
    except BackendError as error:
        messages = {
            "version_mismatch": "Web and daemon package versions do not match.",
            "inactive_configuration": "Daemon mode/configuration does not match the selected context.",
            "unsafe_namespace": "The native namespace must be private and owned by this user.",
            "unsafe_socket": "The native socket must be private and owned by this user.",
        }
        print(messages.get(error.code, "Cannot read the matching daemon through its private socket."), file=sys.stderr)
        raise SystemExit(1)
    except ImportError:
        print("Optional Web dependencies are missing; assemble the matching Web component first.", file=sys.stderr)
        raise SystemExit(1)
    except OSError as error:
        message = "Requested loopback port is already in use." if error.errno == errno.EADDRINUSE else "The local Web listener could not be opened."
        print(message, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
