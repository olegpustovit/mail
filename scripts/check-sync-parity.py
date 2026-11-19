#!/usr/bin/env python3
import base64
import datetime
import imaplib
import json
import os
import re
import subprocess
import sys
import time


def mailbox_name(line):
    match = re.search(rb'("(?:\\.|[^"\\])*"|[^ ]+)\s*$', line)
    if not match:
        raise RuntimeError(f"cannot parse IMAP LIST row: {line!r}")
    raw = match.group(1)
    if raw.startswith(b'"'):
        raw = re.sub(rb'\\(.)', rb'\1', raw[1:-1])
    return decode_utf7(raw.decode("ascii"))


def decode_utf7(value):
    def decode(match):
        encoded = match.group(1)
        if not encoded:
            return "&"
        payload = encoded.replace(",", "/")
        payload += "=" * (-len(payload) % 4)
        return base64.b64decode(payload).decode("utf-16-be")

    return re.sub(r"&([A-Za-z0-9+,]*)-", decode, value)


def encode_utf7(value):
    output = []
    plain = []

    def flush():
        plain.clear()

    for char in value:
        if 0x20 <= ord(char) <= 0x7E:
            flush()
            output.append("&-" if char == "&" else char)
        else:
            plain.append(char)
            if len(plain) == 1:
                output.append("&")
            encoded = base64.b64encode("".join(plain).encode("utf-16-be")).decode("ascii").rstrip("=").replace("/", ",")
            output[-1] = "&" + encoded + "-"
    flush()
    return "".join(output)


def remote_mirror(account):
    # Runs as the VM user over the local Postgres socket; the account is passed as a psql variable.
    sql = '''SELECT json_build_object(
 'folders', COALESCE((SELECT json_agg(json_build_object('name', f.name, 'total', (f.data->>'total')::float8, 'uidNext', (f.data->>'uidNext')::float8,
   'count', (SELECT count(*) FROM mail_messages m WHERE m.owner = f.owner AND m.account = f.account AND m.folder = f.name)::float8))
   FROM mail_folders f WHERE f.account = :'account'), '[]'::json),
 'status', (SELECT json_build_object('phase', data->>'phase', 'at', to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
   FROM mail_sync_status WHERE account = :'account' ORDER BY at DESC LIMIT 1));'''
    result = subprocess.run(
        ["ssh", "oracle-vm", "psql", "-d", "mail", "-At", "-v", f"account={account}"],
        input=sql,
        text=True,
        capture_output=True,
        check=True,
    )
    for line in reversed(result.stdout.splitlines()):
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError("Postgres parity query returned no JSON")


def icloud_folders(email, password):
    client = imaplib.IMAP4_SSL("imap.mail.me.com", 993, timeout=30)
    try:
        client.login(email, password)
        status, rows = client.list('""', "*")
        if status != "OK":
            raise RuntimeError(f"IMAP LIST failed: {status}")
        names = [mailbox_name(row) for row in rows]
        result = {}
        for name in names:
            quoted = '"' + encode_utf7(name).replace("\\", "\\\\").replace('"', '\\"') + '"'
            status, rows = client.status(quoted, "(MESSAGES UIDNEXT)")
            if status != "OK" or not rows:
                raise RuntimeError(f"IMAP STATUS failed for {name!r}: {status}")
            match = re.search(rb"MESSAGES\s+(\d+)\s+UIDNEXT\s+(\d+)", rows[0], re.I)
            if not match:
                raise RuntimeError(f"cannot parse IMAP STATUS row: {rows[0]!r}")
            result[name] = tuple(map(int, match.groups()))
        return result
    finally:
        try:
            client.logout()
        except OSError:
            pass


def main():
    email, password = os.environ.get("ICLOUD_EMAIL"), os.environ.get("ICLOUD_PASSWORD")
    if not email or not password:
        raise RuntimeError("source .envrc to provide ICLOUD_EMAIL and ICLOUD_PASSWORD")
    remote = remote_mirror(email)
    local = icloud_folders(email, password)
    folders = {row["name"]: row for row in remote["folders"]}
    if set(local) != set(folders):
        raise RuntimeError(f"folder set differs: iCloud={sorted(local)!r}, mirror={sorted(folders)!r}")
    for name, (messages, uid_next) in local.items():
        mirror = folders[name]
        if messages != mirror["total"] or messages != mirror["count"] or uid_next != mirror["uidNext"]:
            raise RuntimeError(f"parity failed for {name!r}: iCloud=({messages},{uid_next}) mirror={mirror!r}")
    status = remote["status"]
    age = time.time() - datetime.datetime.fromisoformat(status["at"].replace("Z", "+00:00")).timestamp()
    if status["phase"] != "live" or age > 120:
        raise RuntimeError(f"sync status is stale or not live: phase={status['phase']}, age={int(age)}s")
    print(f"S1 PASS: {len(local)} folders at exact MESSAGES/UIDNEXT parity; status age {int(age)}s")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"S1 FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
