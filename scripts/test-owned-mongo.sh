#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ $# == 0 ]]; then set -- go test -race ./...; fi
owned_root=$(mktemp -d /tmp/mail-access-mongo.XXXXXXXX)
owned_container="mail-access-image-$$-$RANDOM"
owned_pid=
cleanup(){
 if [[ -n "$owned_pid" ]]; then kill "$owned_pid" 2>/dev/null || true; wait "$owned_pid" 2>/dev/null || true; fi
 docker rm -f "$owned_container" >/dev/null 2>&1 || true
 rm -rf "$owned_root"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Run natively on loopback. A Docker daemon may live on a different host, so a
# container's published localhost port is not assumed to be the test host.
if [[ -n ${MAIL_TEST_MONGOD:-} ]]; then
 owned_binary=$MAIL_TEST_MONGOD
elif command -v mongod >/dev/null; then
 owned_binary=$(command -v mongod)
else
 docker create --name "$owned_container" mongo:8 >/dev/null
 docker cp "$owned_container:/usr/bin/mongod" "$owned_root/mongod"
 docker rm "$owned_container" >/dev/null
 owned_binary="$owned_root/mongod"
fi
owned_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
 sock.bind(('127.0.0.1',0));print(sock.getsockname()[1])
PY
)
mkdir "$owned_root/data"
(ulimit -n 1048576; exec "$owned_binary" --dbpath "$owned_root/data" --bind_ip 127.0.0.1 --port "$owned_port" --nounixsocket --quiet) >"$owned_root/mongo.log" 2>&1 &
owned_pid=$!
python3 - "$owned_port" "$owned_pid" <<'PY'
import socket,sys,time,os
port,pid=map(int,sys.argv[1:]);deadline=time.monotonic()+15
while time.monotonic()<deadline:
 try:
  with socket.create_connection(('127.0.0.1',port),.1):break
 except OSError:time.sleep(.05)
else:raise SystemExit('Owned native MongoDB did not become ready; its private log was withheld')
PY
export MAIL_TEST_MONGODB_URI="mongodb://127.0.0.1:$owned_port"
"$@"
