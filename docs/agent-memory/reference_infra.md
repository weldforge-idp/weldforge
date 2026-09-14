---
name: Weldforge infra & deploy reference
description: Where the production system actually lives now — k3s on tech01 via Flux GitOps, GHCR images, SOPS secrets; GCP/GKE is dormant history
metadata:
  node_type: memory
  type: reference
---

> **Rewritten 2026-09-14.** The previous version of this note described GCP/GKE
> as live. It has not been since 2026-08-31. If you find GKE, Artifact Registry,
> Cloud SQL or GCP Secret Manager cited as the deploy path anywhere, it is
> stale.

- **GitHub repo**: `weldforge-idp/weldforge` — **public**, default branch
  `main`. (It was private originally; `publish-images` depends on it being
  public, because GitHub's arm64 runners are only free for public repos.)
- **Where it runs**: a single-node **k3s** cluster on `tech01`. Namespaces
  `weldforge-staging` and `weldforge-production`. Access:
  `ssh tech01`, `export KUBECONFIG=/etc/rancher/k3s/k3s.yaml`.
- **Deploy is two repos and there is no push-to-deploy.** Merging to `main`
  runs `.github/workflows/publish-images.yml`, which publishes
  `ghcr.io/weldforge-idp/{weldforge-auth,weldforge-admin-portal}` tagged
  `sha-<short-sha>`. Nothing goes live until someone bumps `newTag` in the
  **infrastructure** repo (`christiaanwvermaak/cwvermaak_infrastructure`,
  branch `main`) at `apps/weldforge/overlays/{staging,production}/kustomization.yaml`
  and Flux reconciles:

  ```sh
  flux reconcile source git flux-system -n flux-system
  flux reconcile kustomization weldforge-staging -n flux-system
  flux reconcile kustomization weldforge-production -n flux-system
  ```

  Staging first, then production. Pre-deploy dump before a migration:
  `kubectl -n postgres create job <name> --from=cronjob/postgres-backup`
  (dumps at `/var/backups/postgres` on the node).
- **CI workflow**: `.github/workflows/ci.yml`. Backend job runs
  `./mvnw -B -ntp verify -Dtests.integration=true` — that flag is set **only**
  in CI; a local `./mvnw clean verify` skips the Testcontainers Postgres tests.
- **Secrets**: SOPS/age in the infrastructure repo, per environment at
  `apps/weldforge/overlays/{staging,production}/secret.sops.yaml`. Age key at
  `.important/sops-age.key` (git-ignored). sops is **3.7.3** — no `edit`
  subcommand, just `sops <file>`; `code --wait` hangs, use `notepad`.
  **Staging and production hold different values.** Verify, don't assume.
- **A changed Secret restarts nothing.** Kustomize-generated ConfigMaps carry a
  name-suffix hash and force a rollout; plain Secrets do not. After editing one,
  `kubectl rollout restart` the deployment — otherwise the change deploys and
  silently does nothing.
- **GCP is dormant, not deleted.** `deploy-gcp.yml` lost its push trigger on
  2026-08-16; every run since 2026-06-05 failed on billing. Kept as a record of
  the old topology and a starting point if the estate is rebuilt there.
- **URLs**: production `https://sso.weldforge.org`, staging
  `https://staging.weldforge.org`, per-tenant subdomains on both with wildcard
  certs from the `letsencrypt-dns` (DNS-01/Cloudflare) ClusterIssuer.
  Outside-in liveness is `GET /health` (200, JSON).
  **`/actuator/**` is deliberately not routed** as of 2026-09-13 — it had been
  serving `/actuator/prometheus` and `/actuator/health` unauthenticated to the
  internet. Prometheus scrapes the ClusterIP Service in-cluster instead.
- **Monitoring**: Prometheus, Alertmanager, Grafana
  (`https://grafana.cwvermaak.tech`) and self-hosted ntfy
  (`https://ntfy.cwvermaak.tech`, topic `alerts`) on the same node. Runbook:
  `docs/monitoring.md` in the infrastructure repo. See [[session_2026_09_14]].
- **`leap`** is the live public demo tenant for any "prove it's up" check — not
  `demo`, which does not exist. Staging has no `leap`; use `default` there.
- Pre-existing quirk: `/api/auth/tenants/*/{branding,social-providers,saml-providers}`
  are gated by `AppAuthorizationFilter` and need an `x-app-authorization` header.

Several Claude sessions share this checkout — see [[feedback_shared_repo_index]]
before committing.
