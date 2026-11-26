#!/usr/bin/env bash
# Deploy the mail app to oracle-vm through Aquifer (see the aquifer-deploy skill).
set -Eeuo pipefail

cd "$(dirname "$0")/.."
[[ "$(git branch --show-current)" == dev ]]
git fetch -q origin dev
git merge-base --is-ancestor HEAD origin/dev # push first: production only runs pushed commits
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

version=$(git rev-parse --short HEAD)
cd web
npm ci
npm test
npm run build
cd ..
[[ -n "${MAIL_TEST_POSTGRES_URI:-}" ]] # tests need a disposable Postgres; they use private schemas
go test -race ./...
go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$version" -o "/tmp/mail-server-$version" ./cmd/mail
scp "/tmp/mail-server-$version" "oracle-vm:/tmp/mail-server-$version"
status=0
ssh oracle-vm aq deploy mail "/tmp/mail-server-$version" || status=$?
ssh oracle-vm unlink "/tmp/mail-server-$version"
((status == 0)) || exit "$status"

rollback() {
  local result=$?
  trap - ERR
  ssh oracle-vm aq rollback mail || echo 'Rollback failed; inspect with ssh oracle-vm aq status mail' >&2
  exit "$result"
}
trap rollback ERR

ssh oracle-vm curl -fsS http://127.0.0.1:4290/healthz/sync >/dev/null
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
trap - ERR
echo "Deploy PASS: $version"
