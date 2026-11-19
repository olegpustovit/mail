
## Deploy (Aquifer)

Production runs on `oracle-vm` as the Aquifer app `mail`. Use the `aquifer-deploy` skill:
build locally, `scp` the artifact to `oracle-vm:/tmp/`, then `ssh oracle-vm aq deploy mail /tmp/<file>`.
Env vars: `printf %s "$VALUE" | ssh oracle-vm aq secret set mail NAME`. Logs, status and rollback:
`ssh oracle-vm aq logs|status|rollback mail`. Writable state lives in `/home/apps/data/`.
smdctl, its units and `/home/snowbear/ci/...` are retired: do not deploy there.
