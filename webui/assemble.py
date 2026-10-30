#!/usr/bin/env python3
"""Explicitly assemble the optional Web environment for an existing package.

Not called by normal CLI/daemon/Host installation. Dependencies are installed
only here, from webui/uv.lock; runtime launch never invokes this tool or uv.
"""
import argparse
from email.parser import BytesParser
import os
from pathlib import Path
import shutil
import subprocess
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    return subprocess.run(command, check=True, timeout=180, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--wheel", type=Path)
    source.add_argument("--editable", action="store_true", help="explicit development source installation")
    args = parser.parse_args()
    for path in [args.bin_dir, args.python] + ([args.wheel] if args.wheel else []):
        if not path.is_absolute():
            parser.error("package, Python and wheel paths must be absolute")
    directory = args.bin_dir.resolve(strict=True)
    prefix = directory.parent
    environment = prefix / "webui"
    project = ROOT / "webui"
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if tomllib.loads((project / "pyproject.toml").read_text())["project"]["version"] != version:
        parser.error("Rust and Python package versions do not match")
    for path in [prefix, directory]:
        info = path.lstat()
        if not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            parser.error("package directories must be owned by this user and not group/world writable")
    if environment.exists() or environment.is_symlink():
        parser.error("Web environment already exists; do not overwrite a running or installed component")
    if not (directory / "evertrace").is_file():
        parser.error("assemble the native evertrace binary first")
    native = run([str(directory / "evertraced"), "--version"], capture_output=True, text=True, env={}).stdout
    if native != f"evertraced {version}\n":
        parser.error("native daemon version does not match this source package")
    run([str(args.python), "-I", "-c", "import sys; assert sys.version_info >= (3,12), 'Python 3.12+ required'"])
    uv = shutil.which("uv")
    if uv is None:
        parser.error("uv is required at explicit assembly time, never at runtime")
    if args.wheel:
        with zipfile.ZipFile(args.wheel) as wheel:
            names = [name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")]
            if len(names) != 1:
                parser.error("wheel has no unique distribution metadata")
            metadata = BytesParser().parsebytes(wheel.read(names[0]))
            if metadata["Name"] != "evertrace-web" or metadata["Version"] != version:
                parser.error("wheel is not the matching EverTrace Web distribution")
    requirements = run([uv, "export", "--project", str(project), "--locked", "--no-dev", "--no-emit-project", "--format", "requirements-txt"], capture_output=True).stdout
    environment.mkdir(mode=0o700)
    try:
        run([uv, "venv", "--no-project", "--no-config", "--no-python-downloads", "--python", str(args.python), str(environment)])
        python = environment / "bin/python"
        run([uv, "pip", "install", "--python", str(python), "--require-hashes", "-r", "-"], input=requirements)
        if args.wheel:
            run([uv, "pip", "install", "--python", str(python), "--no-deps", "--no-index", str(args.wheel)])
        else:
            run([uv, "pip", "install", "--python", str(python), "--no-deps", "--editable", str(project)])
        # The CLI invokes Python -I with this managed entry as a file argument.
        # No shebang/shell trampoline, even for long or whitespace package paths.
        entry = environment / "bin/evertrace-web"
        entry.write_text("from evertrace_web.__main__ import main\n\nif __name__ == '__main__':\n    main()\n")
        entry.chmod(0o644)
        result = run([str(python), "-I", "-B", str(entry), "--version"], capture_output=True, text=True, env={})
        if result.stdout != f"evertrace-web {version}\n":
            raise RuntimeError("assembled Web component version is not the native package version")
    except BaseException:
        # Only this invocation's freshly-created environment is ours to remove.
        shutil.rmtree(environment)
        raise
    print("Optional Web component assembled. Start the matching daemon, then evertrace --web.")


if __name__ == "__main__":
    main()
