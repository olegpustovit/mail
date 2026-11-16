# Terminal Mail

An invite-only iCloud Mail web client and OAuth MCP server, served by the same Go binary at mail.microapps.space. Humans and agents access the user's connected mailbox using the existing encrypted app-specific credentials.

The approved product and visual specification is https://artifacts.microapps.space/a/mx4gywdnv23g (version 3), preserved in docs/design/web-client.html. PROPOSAL.md supplies implementation context. The requested outcome includes every specified screen and interaction, deployment, and verification; a styled settings screen or a simulated mailbox does not satisfy it.

Humans sign in only with Microapps ID (no local passwords, registration, verification or reset). Keep per-user iCloud app-password connection, OAuth consent for MCP clients (its sign-in step goes through Microapps ID), and MCP tool contracts working. Real mail is private, isolated by owner, and never replaced by demonstration records. Destructive operations require an explicit action and permanent deletion requires confirmation.
