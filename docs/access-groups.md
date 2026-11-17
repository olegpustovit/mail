# Central app access integration

Mail's integration is locally qualified. Production has not been changed. Provider migration, reviewed seed grants, legacy verification, per-app cutover and the other apps remain requirements of the complete access-groups proposal.

## Configuration and identity

`MAIL_ID_ACCESS_ENABLED` defaults false and accepts only literal `true`/`false`. Enabling requires confidential `MAIL_ID_CLIENT_ID`/`MAIL_ID_CLIENT_SECRET`; public PKCE credentials alone cannot call the central endpoint. The SDK is pinned with checksums to `v0.0.0-20261117021458-a8a6d8068d30`. Access checking is configured before Mail starts any owner monitors, rules, scheduled jobs, push or prefetch loops.

A fresh decision precedes signed callback linking. Local verified-email admission (`@olegpustovit.com` or the existing exact owner address) remains in force. `identities` uniquely binds stable subject `_id` to the original mailbox owner email. A later verified email change does not move the mailbox to a different owner. No local-owner bypass exists.

New sessions, consent records, authorization codes, OAuth access and refresh credentials retain a private `subject` field. Enforced resolution requires both that field and the current stored binding; legacy records without it fail closed. The subject is not returned by account/client JSON. Long cookie/token expiration never renews central eligibility.

Before cutover, inventory legacy sessions and MCP grants without changing them. Have eligible users sign in again and explicitly authorize their clients to obtain bound credentials, or complete a separately reviewed migration with evidence of exact stable ownership. Do not silently infer old credential subjects from a caller's email. Owner jobs require a valid stored identity binding. Manual central grants do not fabricate verified-email proof for old ID accounts; the provider's legacy proof issue must be resolved before changing production behavior.

## Coverage and cancellation

| Boundary | Enforcement |
| --- | --- |
| ID callback | Fresh confidential decision before linking; SDK verifies issuer/signature/audience/nonce/verified email; local admission remains. |
| Browser/session controls | Bound-subject checks cover mail, sync, account, client and session APIs. Account connection validation uses a cancelable IMAP setup. Login, logout and health remain available with a blocked cookie. |
| OAuth | Fresh eligibility before consent/code issuance, code redemption and refresh. Existing client/resource/redirect/PKCE/single-use checks remain. Denied/unavailable refresh does not consume a valid credential. |
| MCP | Every bearer request validates its bound record, then retains a watched request context. Stateless Streamable HTTP propagates cancellation to the tool dependency and mail work. |
| Browser sync/download/remote image | Protected request owns the watched lifetime; sync heartbeat also checks the local session. Context cancellation stops streams and upstream work. A per-response write deadline also interrupts blocked socket writes; bootstrap checks cancellation between rows. |
| IMAP monitors | Owner's stored subject controls the entire monitor, including idle IDLE connections and reconciliation. Revocation/outage closes the wire; restoration starts a new monitor instead of reusing a canceled one. |
| Commands and SMTP | Borrowed IMAP commands terminate on context cancellation, even for legacy protocol calls that ignore context. Release waits for the abort callback before returning the serialized lane. SMTP closes its wire on cancellation. |
| Scheduled sends/snooze/folder recovery/rules | Check before dispatch/claim and watch active work. Denial/unavailability pauses without consuming attempts; deferred eligibility prevents one blocked owner starving other dispatchable owners. |
| Prefetch and push | Owner check precedes reading/downloading/delivering. Existing local active-session and account requirements remain; denial does not remove a subscription. |
| Outcome maintenance | Bounded cancellation-independent database finalization records uncertain/sent results to prevent duplicates. Post-send refresh re-enters owner enforcement; borrowed IMAP wires cannot escape cancellation for a Sent copy. A send with ambiguous acceptance remains `uncertain`, never automatically retried. |
| Independent maintenance and stdio | Schema/index/recovery metadata, retention cleanup and explicit root stdio configuration are service maintenance or independent machine use. Hosted iCloud credentials and account-owned OAuth grants remain human work. |

The helper permits at most 60 seconds of positive caching, measured from request start. Watched work starts with a fresh decision, then checks fresh every 25 seconds with a two-second total bound per attempt. This prevents an older near-expiry lease from adding an extra interval to active work. Failure/denial invalidates the old positive lease. Controlled-clock tests use the production intervals; no continued traffic is needed for cancellation. Already delivered messages or downloaded bytes cannot be recalled.

## Qualification

`make access-check` passes the full Go race suite with an owned native Mongo process, and `go vet ./...` passes. The web's existing 32 tests and production build pass without a frontend source change. Tests cover stable/foreign/missing bindings, all credential paths, typed 403/503 failures, refresh preservation, callback rejection, blocked-cookie logout, watcher timeout/release, raw IMAP setup cancellation, active command abortion, every job dispatcher, queue fairness, push/prefetch pauses, and actual HTTP socket-write interruption with an unread response.

`make access-rehearsal` uses real Mongo storage and the published SDK with an owned policy endpoint and simulated IMAP/SMTP transports. Four protected workers issue one request per 100 ms while idle owner work, an IDLE monitor, a borrowed raw command and an in-flight send stay open. Removal cancels all within **25,000 ms**; policy unavailability within **24,999 ms**. All **1,955** responses have expected allowed/denied/unavailable status, restoration restarts the monitor, and both interrupted sends retain `uncertain` status. This measurement does not claim real iCloud or actual provider behavior.

`make identity-provider-check` separately runs the actual sibling Rust Identity binary and native Mail binary, owned PostgreSQL and Mongo, captured-email verified invitations, a confidential fixture client and explicit reviewed test policy through the protected admin API. It passes signed callbacks, replay rejection, secure bound cookies, local admission despite central allow, actual local OAuth/PKCE issuance, existing browser/MCP denial, a real isolated ID policy-table outage, refresh restoration without prior consumption, and blocked-cookie logout preserving the global ID device. It makes no real mailbox connection. Sanitized reports are in `measurements/access-mail-20261117.json` and `measurements/access-mail-native-20261117.json`.

The Mongo runner binds only loopback, owns its temporary directory/process and cleans them on exit. It uses a native installed `mongod`, `MAIL_TEST_MONGOD`, or extracts the binary from the Mongo 8 image; it does not assume a Docker daemon's localhost is the test machine. The native provider runner requires the sibling Identity debug build and installed e2e dependencies. No test uses production accounts, grants, databases or iCloud delivery.

## Deployment and rollback

Binary deployment preserves the currently running enforcement mode. `scripts/deploy.sh` performs a read-only preflight against the private owned service environment and loopback health; a pending configuration change must first be completed as a reviewed cutover. Per-attempt private state records the environment fingerprint, old/new binary checksums, mode and release versions, never credential values. Activation and rollback reject configuration drift, changed uploads and concurrent binary replacement. Health must report the exact new version and enforcement mode. A legacy release without the health field can only be captured in flag-off mode. Once the current release reports enforcement true, the previous binary and unchanged service environment retain true during automatic rollback.

Eleven local Python tests execute the guard and actual deployment shell through owned SSH/SCP/service fixtures, covering successful activation, restart failure, wrong enforcement, exhausted parity, legacy mode, changed configuration and concurrent binaries. These tests do not deploy. Real-iCloud sync parity remains mandatory for this change when deployment is eventually authorized by the complete proposal; do not use `MAIL_DEPLOY_SKIP_PARITY=1` for the synchronization changes here.

Install a supporting release in the existing mode before any later enforcement cutover. Complete the provider migration/verification and reviewed policy first, reconcile legacy credentials, then change only the intended app's protected flag and verify its full acceptance suite. Do not use flag-off or a pre-enforcement binary as a policy rollback. Restore a reviewed previous policy through a new audited revision while keeping checks enabled. Deployment state and binary backups are local operations records; retain them privately until the release is accepted.
