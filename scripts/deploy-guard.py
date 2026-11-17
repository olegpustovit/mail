#!/usr/bin/env python3
"""Bound a binary deployment/rollback to the running enforcement mode and env.

Never sources, rewrites or reports service credentials. An enforcement cutover
is a separate reviewed operation; binary rollback must keep that mode enabled.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import urllib.request


class GuardError(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def configuration(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise GuardError("Service environment must be a private owned regular file")
    data = path.read_bytes()
    values = []
    for line in data.decode().splitlines():
        match = re.fullmatch(r"\s*(?:export\s+)?MAIL_ID_ACCESS_ENABLED\s*=(.*)", line)
        if match:
            words = shlex.split(match[1], comments=True)
            if len(words) > 1:
                raise GuardError("Invalid literal access flag")
            values.append(words[0] if words else "")
    if len(values) > 1 or (values and values[0] not in ("", "false", "true")):
        raise GuardError("Invalid or duplicate access flag")
    return hashlib.sha256(data).hexdigest(), bool(values and values[0] == "true")


def health(url):
    # This endpoint is fixed to the host's loopback service by deploy.sh.
    with urllib.request.urlopen(url, timeout=2) as response:
        result = json.load(response)
    if result.get("status") != "ok":
        raise GuardError("Mail is not healthy")
    if "access_enforced" in result and type(result["access_enforced"]) is not bool:
        raise GuardError("Malformed enforcement health")
    return result


def check(env_file, health_url):
    env_digest, enabled = configuration(env_file)
    live = health(health_url)
    # The legacy binary had no field and can only be a flag-off rollback target.
    if live.get("access_enforced", False) != enabled:
        raise GuardError("Running enforcement differs from service configuration; finish the reviewed cutover first")
    return {"env_digest": env_digest, "access_enforced": enabled, "previous_health": live}


def capture(root, env_file, health_url, key, version, new_digest):
    record = check(env_file, health_url)
    record.update(key=key, version=version, previous_digest=digest(root / "mail-server"), new_digest=new_digest)
    if digest(root / ("mail-server.next-" + key)) != new_digest:
        raise GuardError("Uploaded binary checksum differs")
    state = root / (".deploy-" + key + ".json")
    with open(state, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as output:
        json.dump(record, output)
    return record


def unchanged(record, env_file):
    env_digest, enabled = configuration(env_file)
    if env_digest != record["env_digest"] or enabled != record["access_enforced"]:
        raise GuardError("Service environment changed; refusing deployment or rollback")


def activate(root, env_file, record):
    unchanged(record, env_file)
    if digest(root / "mail-server") != record["previous_digest"]:
        raise GuardError("Concurrent binary change; refusing activation")
    staged = root / ("mail-server.next-" + record["key"])
    if digest(staged) != record["new_digest"]:
        raise GuardError("Uploaded binary changed")
    previous = root / ("mail-server.previous-" + record["key"])
    if previous.exists():
        raise GuardError("Previous binary already captured")
    shutil.copy2(root / "mail-server", previous)
    staged.chmod(0o755)
    os.replace(staged, root / "mail-server")


def rollback(root, env_file, record):
    unchanged(record, env_file)
    current = digest(root / "mail-server")
    if current == record["previous_digest"]:
        return False  # Activation never occurred, or rollback already finished.
    if current != record["new_digest"]:
        raise GuardError("Concurrent binary change; refusing rollback")
    previous = root / ("mail-server.previous-" + record["key"])
    if digest(previous) != record["previous_digest"]:
        raise GuardError("Previous binary checksum differs")
    failed = root / ("mail-server.failed-" + record["key"])
    shutil.copy2(root / "mail-server", failed)
    staged = root / ("mail-server.rollback-" + record["key"])
    shutil.copy2(previous, staged)
    os.replace(staged, root / "mail-server")
    return True


def verify(env_file, health_url, record, previous=False):
    unchanged(record, env_file)
    live = health(health_url)
    if live.get("access_enforced", False) != record["access_enforced"]:
        raise GuardError("Activated enforcement does not match the captured mode")
    expected = record["previous_health"].get("version") if previous else record["version"]
    if not previous and "access_enforced" not in live:
        raise GuardError("New release does not report enforcement")
    if expected is not None and live.get("version") != expected:
        raise GuardError("Activated version does not match the captured release")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "capture", "activate", "rollback", "verify", "verify-previous"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--health-url", default="http://127.0.0.1:4290/healthz")
    parser.add_argument("--key")
    parser.add_argument("--version")
    parser.add_argument("--digest")
    args = parser.parse_args()
    if args.action == "check":
        check(args.env_file, args.health_url)
        return
    if not re.fullmatch("[0-9a-f]{24}", args.key or ""):
        raise GuardError("Invalid deployment key")
    with (args.root / ".deploy.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "capture":
            if not re.fullmatch("[0-9a-f]{7,40}", args.version or "") or not re.fullmatch("[0-9a-f]{64}", args.digest or ""):
                raise GuardError("Invalid release version or checksum")
            capture(args.root, args.env_file, args.health_url, args.key, args.version, args.digest)
            return
        record = json.loads((args.root / (".deploy-" + args.key + ".json")).read_text())
        if record["key"] != args.key:
            raise GuardError("Deployment state mismatch")
        if args.action == "activate":
            activate(args.root, args.env_file, record)
        elif args.action == "rollback":
            rollback(args.root, args.env_file, record)
        else:
            verify(args.env_file, args.health_url, record, args.action == "verify-previous")


if __name__ == "__main__":
    try:
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink):
            main()
    except GuardError as error:
        raise SystemExit(str(error))
    except Exception:
        # Neither response bodies nor environment contents belong in deploy logs.
        raise SystemExit("Mail deployment guard failed (details withheld)")
