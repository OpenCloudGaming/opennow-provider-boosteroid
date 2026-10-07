#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description="Verify local host installation without account or service calls")
    parser.add_argument("--core", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    arguments = parser.parse_args()
    source = "org.opennow.boosteroid"
    with tempfile.TemporaryDirectory(prefix="boosteroid-host-check-") as data:
        process = subprocess.Popen([str(arguments.core.resolve()), "--data-dir", data],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, encoding="utf-8")
        messages = queue.Queue(maxsize=128)

        def receive():
            try:
                while line := process.stdout.readline(1024 * 1024 + 1):
                    if len(line) > 1024 * 1024:
                        raise ValueError("Host response exceeds protocol limit")
                    messages.put(json.loads(line), timeout=5)
            except Exception as error:
                messages.put(error, timeout=5)

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        sequence = 0

        def rpc(method, params, expect_error=False):
            nonlocal sequence
            sequence += 1
            identity = str(sequence)
            process.stdin.write(json.dumps({"type": "request", "id": identity,
                                            "method": method, "params": params}) + "\n")
            process.stdin.flush()
            deadline = time.monotonic() + 15
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"Host response timed out for {method}")
                response = messages.get(timeout=remaining)
                if isinstance(response, Exception):
                    raise response
                if response.get("type") == "event":
                    continue
                if response.get("id") != identity:
                    raise RuntimeError("Host returned an unexpected response ID")
                if response.get("ok") == expect_error:
                    code = response.get("error", {}).get("code", "unknown")
                    raise RuntimeError(f"Unexpected outcome for {method}: {code}")
                return response.get("result")

        def descriptor(snapshot):
            return next(plugin for plugin in snapshot["plugins"] if plugin["id"] == source)

        try:
            hello = rpc("core.hello", {"protocolVersion": 5, "shell": "qt", "shellVersion": "verification"})
            assert "sources.v2" in hello["capabilities"]
            inspected = rpc("plugins.install.inspect", {"path": str(arguments.package.resolve())})
            rpc("plugins.install.commit", {"token": inspected["inspection"]["token"],
                                            "expectedGeneration": inspected["generation"],
                                            "consent": False}, expect_error=True)
            snapshot = rpc("plugins.list", {})
            assert all(plugin["id"] != source for plugin in snapshot["plugins"])
            inspected = rpc("plugins.install.inspect", {"path": str(arguments.package.resolve())})
            snapshot = rpc("plugins.install.commit", {"token": inspected["inspection"]["token"],
                                                       "expectedGeneration": inspected["generation"],
                                                       "consent": True})
            assert descriptor(snapshot)["enabled"] is False
            snapshot = rpc("plugins.setEnabled", {"id": source, "enabled": True,
                                                   "expectedGeneration": snapshot["generation"]})
            assert descriptor(snapshot)["enabled"] is True
            state = rpc("sources.auth.state", {"sourceId": source, "request": {}})
            assert state["result"]["state"] == "signed-out"
            accounts = rpc("sources.accounts.list", {"sourceId": source, "request": {}})
            assert accounts["result"]["accounts"] == []
            snapshot = rpc("plugins.list", {})
            assert descriptor(snapshot)["state"] == "ready"
            snapshot = rpc("plugins.setEnabled", {"id": source, "enabled": False,
                                                   "expectedGeneration": snapshot["generation"]})
            assert descriptor(snapshot)["enabled"] is False
            snapshot = rpc("plugins.uninstall", {"id": source, "confirmed": True,
                                                  "expectedGeneration": snapshot["generation"]})
            assert all(plugin["id"] != source for plugin in snapshot["plugins"])
            print("Verified real host inspection, required consent, disabled installation, native control startup,")
            print("signed-out authentication, empty accounts, disablement and uninstall in isolated storage.")
            print("No live login, allocation, playback or remote cleanup was tested.")
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            reader.join(timeout=2)


if __name__ == "__main__":
    main()
