# WeldForge marketing site — TeamCity deployment

The `www.weldforge.org` static site is deployed to Xneelo shared hosting by
the `intelli-sso-www/scripts/deploy.sh` script. This document describes the
TeamCity build configuration that runs that script automatically on every
push that touches the marketing site.

## Transport: plain FTP (deliberate)

The current Xneelo shared-hosting plan does **not** offer SSH/SFTP and does
not accept `AUTH TLS` on its FTP control channel. The only working transport
is plain FTP on port 21 — credentials travel in the clear.

This is an explicit tradeoff documented at the top of `deploy.sh`. The
marketing site is public content, the FTP password is scoped to a single
disposable account, and the realistic alternative (move to S3+CloudFront or
Cloudflare Pages) is a bigger change than this project currently wants.

The TeamCity step therefore calls `deploy.sh --insecure-ftp`. When/if the
hosting plan is upgraded (or the site migrated elsewhere), drop the flag and
the script will use SFTP automatically.

**Rotation policy**: rotate the Xneelo FTP password any time you suspect the
TeamCity server or build logs have been compromised. The password controls
nothing other than the ability to overwrite the marketing site, so rotating
it is cheap — do it routinely if in doubt.

## TeamCity build configuration

Create a new build configuration inside whichever project already hosts the
backend deploys (e.g. `intelli-sso / WWW`). Settings below assume TeamCity
2024.x or later.

### 1. Version Control Settings

- **VCS Root**: the existing `intelli-sso` Git root (or a new one pointed at
  the same repo). No special clone settings — a shallow clone is fine.
- **Checkout mode**: On Agent.
- **Clean build**: no (faster; the deploy script only reads files under
  `intelli-sso-www/public/`).

### 2. Build Triggers

**VCS trigger** with a path filter so the build only fires when the
marketing site actually changes:

```
+:root=<VCS root name>:intelli-sso-www/**
```

This stops every backend commit from triggering an unnecessary redeploy.

### 3. Parameters

Define these typed parameters at the build-config level:

| Name             | Type                 | Value                                                                |
|------------------|----------------------|----------------------------------------------------------------------|
| `env.SFTP_HOST`  | Environment variable | `weldforge.org`                                                      |
| `env.SFTP_USER`  | Environment variable | `weldfejtyq_0` *(or whatever konsoleH shows)*                        |
| `env.SFTP_DIR`   | Environment variable | `/`                                                                  |
| `env.SFTP_PASS`  | **Password**         | Xneelo FTP password. Marked `Password` so TeamCity encrypts and masks it in logs. |

Never check the password into the repo. TeamCity stores `Password`-typed
parameters encrypted with the server key and scrubs them from build output.

### 4. Build Step

One command-line step:

```bash
#!/usr/bin/env bash
set -euo pipefail
chmod +x intelli-sso-www/scripts/deploy.sh
./intelli-sso-www/scripts/deploy.sh --insecure-ftp
```

Name it `Deploy www.weldforge.org`, runner type `Command Line`, format
`Custom script`. Working directory: `%teamcity.build.checkoutDir%`.

The `--insecure-ftp` flag is deliberate — it tells the script to use plain
FTP instead of SFTP. See the "Transport" section at the top of this doc for
the rationale.

### 5. Agent requirements

The deploy script needs a Linux/macOS agent with the following tools on
`$PATH`:

- `bash` (>= 4)
- `curl` (the only transport used in `--insecure-ftp` mode)
- `find`, `awk`, `sed`

Add an Agent Requirement `env.AGENT_OS` `does not equal` `Windows` if you
have mixed agents. The script does not need `sftp`, `ssh` or `sshpass` in
plain-FTP mode — curl is sufficient.

### 6. Verification after first build

1. Watch the build log; the script prints `deploy: host=... user=... dir=...`
   then `auth=publickey` or `auth=password`, then `opening SFTP session...`
2. A successful run ends with `deploy: SFTP transfer complete ✓`.
3. Browse <https://www.weldforge.org/> in an incognito window and confirm
   the WeldForge logo, dark theme and tutorials page all load.
4. If the site does not answer, the remaining work is DNS:
   point `www.weldforge.org` as a **CNAME** at the Xneelo hostname
   (usually the same A record `weldforge.org` already resolves to). That
   is a konsoleH DNS-zone change, not a TeamCity one.

## Local preview without deploying

```bash
./intelli-sso-www/scripts/deploy.sh --dry-run         # what would be sent
python3 -m http.server 8000 --directory intelli-sso-www/public    # preview
```

## Rolling back

Because the script uploads in-place and Xneelo has no atomic swap, a rollback
is a re-deploy of an older commit:

```bash
git checkout <previous-good-sha> -- intelli-sso-www/public
./intelli-sso-www/scripts/deploy.sh
git checkout HEAD -- intelli-sso-www/public
```

Or, more cleanly, revert the commit in git and let TeamCity re-deploy from
the revert.
