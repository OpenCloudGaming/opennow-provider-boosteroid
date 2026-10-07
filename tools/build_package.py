#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Verify and package this machine's native Boosteroid provider")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    destination = arguments.output.resolve()
    if destination.exists():
        parser.error("Output already exists; choose a new package path")
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ, RUSTUP_TOOLCHAIN="1.99.0")

    def run(*command, capture=False):
        return subprocess.run(command, cwd=root, env=environment, check=True,
                              encoding="utf-8", stdout=subprocess.PIPE if capture else None).stdout

    compiler = dict(line.split(": ", 1) for line in run("rustc", "-vV", capture=True).splitlines()
                    if ": " in line)
    target = compiler["host"]
    run(sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py")
    run("cargo", "fmt", "--all", "--", "--check")
    run("cargo", "test", "--locked", "--workspace", "--target", target)
    run("cargo", "clippy", "--locked", "--workspace", "--all-targets", "--target", target,
        "--", "-D", "warnings")
    metadata = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1",
                              "--no-deps", capture=True))
    notices = Path(metadata["target_directory"]) / target / "THIRD_PARTY_NOTICES.txt"
    run(sys.executable, "tools/third_party_notices.py", "--target", target, "--output", str(notices))
    run("cargo", "build", "--locked", "--release", "--workspace", "--target", target)
    binaries = Path(metadata["target_directory"]) / target / "release"
    extension = ".exe" if sys.platform == "win32" else ""
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(str(binaries / f"boosteroid-package{extension}"),
        str(binaries / f"boosteroid-control{extension}"),
        str(binaries / f"boosteroid-media{extension}"), str(notices), str(destination))
    print(f"Created {destination}")


if __name__ == "__main__":
    main()
