---
name: verify-operator-infra-assertions-before-acting
description: When the user asserts something about external infra ("DNS is live", "the cert is provisioned", "the secret is set"), verify it independently before merging code that depends on it
metadata:
  node_type: memory
  type: feedback
  originSessionId: 2026-05-20-per-tenant-auth-urls
---

When asking the user a yes/no question about **external infrastructure
state** that I can verify independently in seconds, do the verification
before merging anything that depends on the answer — even when the
user says yes. The user genuinely believes they're answering
truthfully, but humans confuse "I'm about to do this" with "I've
already done this", or check the wrong staging vs prod scope, or
remember a different account.

**The incident.** On 2026-05-20, before merging #32 (per-tenant
subdomain auth URLs), I asked via AskUserQuestion: *"Are the wildcard
DNS A-record `*.sso.weldforge.org` and wildcard TLS cert
`*.sso.weldforge.org` live in production right now?"*. The user
selected **"Yes — both are live, proceed"** and I merged five PRs
(#32–#34) that depend on the subdomain pattern. Smoke-test on
2026-05-21 found `host demo.sso.weldforge.org` returns NXDOMAIN and
the apex cert's SAN is `sso.weldforge.org` only — neither piece of
infra was actually live. The merged feature was unreachable in
production (no functional regression because the legacy URLs still
worked via apex fallback, but the new URL shape was non-functional).

**Why:** trust-but-verify is in the system prompt and I skipped the
verify step on an attestation that takes literally one bash command
to confirm. A `host` query and an `openssl s_client | x509
subjectAltName` dump would have caught it in 5 seconds.

**How to apply:**
- For any user yes/no answer about external state that I can verify
  with a curl, dig, host, openssl, kubectl, or gcloud command:
  **run the command before acting on the answer.** Don't ask the
  user to verify it; just do it.
- Specifically applicable to DNS resolution, TLS cert SANs, k8s
  resource presence, GCP resource state, secret-manager values
  (existence, not value), running pod counts, ingress IPs, etc.
- If the answer can't be verified externally (e.g. "I've already
  notified the team", "the customer agreed in the call"), then the
  user's word is the source of truth — proceed and let the user
  reverse course if needed.
- The exception is destructive operations where verification itself
  would be costly or visible (e.g. trial-billing checks that show up
  in audit logs the user might be filtering). Use judgment.
