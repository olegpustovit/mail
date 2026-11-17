#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."
[[ "$(git branch --show-current)" == main ]]
git merge-base --is-ancestor HEAD origin/main
[[ -z "$(git status --porcelain --untracked-files=no)" ]]

if [[ -f .envrc ]]; then
  set -a
  source .envrc
  set +a
fi
# The sync parity gate compares the mirror with a real iCloud mailbox. Skip it only explicitly,
# for changes that do not touch mail synchronization (for example sign-in changes).
skip_parity=${MAIL_DEPLOY_SKIP_PARITY:-0}
[[ "$skip_parity" == 1 || ( -n "${ICLOUD_EMAIL:-}" && -n "${ICLOUD_PASSWORD:-}" ) ]]

# Read-only preflight: binary deployment keeps the current enforcement mode.
# Provider policy restoration is separate; rollback must never turn checks off.
ssh oracle-vm python3 - check --root /home/snowbear/ci/mail --env-file /home/snowbear/.config/smdctl/env/mail.env < scripts/deploy-guard.py

version=$(git rev-parse --short HEAD)
deploy_key=$(python3 -c 'import secrets; print(secrets.token_hex(12))')
cd web
npm ci
npm test
npm run build
cd ..
bash scripts/test-owned-mongo.sh go test -race ./...
python3 -m unittest discover -s scripts -p 'test_deploy_guard.py'
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$version" -o "/tmp/mail-server-$version" ./cmd/mail
binary_digest=$(sha256sum "/tmp/mail-server-$version" | cut -d' ' -f1)
scp "/tmp/mail-server-$version" "oracle-vm:/home/snowbear/ci/mail/mail-server.next-$deploy_key"
scp scripts/deploy-guard.py "oracle-vm:/home/snowbear/ci/mail/.deploy-guard-$deploy_key.py"
ssh oracle-vm bash -s -- "$deploy_key" "$version" "$binary_digest" <<'REMOTE'
set -euo pipefail
cd /home/snowbear/ci/mail
python3 ".deploy-guard-$1.py" capture --root . --env-file /home/snowbear/.config/smdctl/env/mail.env --key "$1" --version "$2" --digest "$3"
REMOTE

deployed=0
rollback() {
  local status=$?
  trap - ERR
  if [[ $deployed == 1 ]]; then
    if ! ssh oracle-vm bash -s -- "$deploy_key" <<'REMOTE'
set -euo pipefail
cd /home/snowbear/ci/mail
guard=(python3 ".deploy-guard-$1.py" --root . --env-file /home/snowbear/.config/smdctl/env/mail.env --key "$1")
"${guard[@]}" rollback
smdctl restart mail
"${guard[@]}" verify-previous
REMOTE
    then
      echo 'Rollback guard failed; inspect the captured deployment privately. No environment or policy was rewritten.' >&2
    fi
  fi
  exit "$status"
}
trap rollback ERR

# Set before activation so a failed restart/health check also restores the binary.
deployed=1
ssh oracle-vm bash -s -- "$deploy_key" <<'REMOTE'
set -euo pipefail
cd /home/snowbear/ci/mail
guard=(python3 ".deploy-guard-$1.py" --root . --env-file /home/snowbear/.config/smdctl/env/mail.env --key "$1")
"${guard[@]}" activate
smdctl restart mail
smdctl status mail | grep -F 'Status:  active (running)'
"${guard[@]}" verify
curl -fsS http://127.0.0.1:4290/healthz/sync >/dev/null
for attempt in {1..12}; do
  if ss -tnp | grep mail-server | grep -q ':993'; then exit 0; fi
  sleep 5
done
echo 'S0 FAIL: no iCloud IMAP sync socket' >&2
exit 1
REMOTE
curl -fsS https://mail.microapps.space/ >/dev/null
curl -fsS https://mail.microapps.space/healthz/sync

# Pass as soon as iCloud and the mirror agree; give the post-restart import up to ~3 min.
if [[ "$skip_parity" == 1 ]]; then
  echo 'Sync parity check skipped (MAIL_DEPLOY_SKIP_PARITY=1)'
else
  for attempt in {1..18}; do
    if python3 scripts/check-sync-parity.py; then break; fi
    if [[ "$attempt" == 18 ]]; then false; fi
    sleep 10
  done
fi
ssh oracle-vm bash -s -- "$deploy_key" <<'REMOTE'
set -euo pipefail
cd /home/snowbear/ci/mail
python3 ".deploy-guard-$1.py" verify --root . --env-file /home/snowbear/.config/smdctl/env/mail.env --key "$1"
REMOTE
trap - ERR
echo "Deploy PASS: $version"
