"""The version path deliberately imports no server, template or HTTP runtime."""
import argparse
import errno
from importlib.metadata import version
import json
import os
import re
import socket
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
    try:
        raw = sys.stdin.buffer.read(4097)
        context = json.loads(raw)
        if len(raw) > 4096 or set(context) != {"socket", "config_hash", "build_id", "channel_fd"}:
            raise ValueError()
        path, config_hash, fd = context["socket"], context["config_hash"], context.pop("channel_fd")
        if not isinstance(path, str) or not path.startswith("/") or not re.fullmatch("[0-9a-f]{64}", config_hash):
            raise ValueError()
        if context["build_id"] != build or type(fd) is not int or fd < 3:
            raise ValueError()
        os.set_inheritable(fd, False)
        channel = socket.socket(fileno=fd)
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM or channel.getpeername() != path:
            channel.close()
            raise ValueError()
    except (OSError, TypeError, ValueError, KeyError):
        parser.error("invalid private launcher context")
    from . import BackendError
    try:
        from .server import run
        with channel:
            run(context, args.port, channel)
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
