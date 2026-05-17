---
name: Weldforge infra & deploy reference
description: Where the production system lives — repo, GCP project, GKE cluster, kubectl context, deploy trigger
type: reference
originSessionId: 9f38af7d-b118-4b7d-ab14-ea150e67a780
---
- **GitHub repo**: `weldforge-idp/weldforge` (private). Default branch `main`. Active feature branch as of 2026-05-04: `feature/write-buddy-integration`.
- **Deploy workflow**: `.github/workflows/deploy-gcp.yml` — fires on push to `main` whenever `weldforge-auth/**`, `weldforge-admin-portal/**`, `infrastructure/helm/weldforge/**`, or the workflow itself changes. Single job `build-push-deploy` builds both images, pushes to Artifact Registry, runs `helm upgrade --wait --timeout=10m`. PR merge → ~10 min to live.
- **CI workflow**: `.github/workflows/ci.yml`. Backend job runs `./mvnw -B -ntp verify -Dtests.integration=true` (the `-Dtests.integration` flag is **only** set in CI; local `./mvnw clean verify` skips Testcontainers Postgres tests).
- **GCP project**: `weldforge` (region `africa-south1`). Authenticated locally as `inspired.christiaan@gmail.com`.
- **Artifact Registry**: `africa-south1-docker.pkg.dev/weldforge/images/{weldforge-auth,weldforge-admin-portal}`.
- **GKE cluster**: `weldforge-gke` in `africa-south1`. Get creds: `gcloud container clusters get-credentials weldforge-gke --region africa-south1`. Context name once configured: `gke_weldforge_africa-south1_weldforge-gke` — pass with `kubectl --context=...` because the default context on this machine reverts to an EKS cluster.
- **Cloud SQL**: instance `weldforge-db`, catalog name `weldforge` (renamed from `intelli_sso` on 2026-05-06 via in-place `ALTER DATABASE`; see PR #10).
- **Public URL**: `https://sso.weldforge.org`. Internal API health: `kubectl -n sso exec deploy/sso-api -c sso-api -- curl -s http://localhost:8080/actuator/health`.
- **Image OCI label**: `org.opencontainers.image.source = https://github.com/weldforge-idp/weldforge` set on both images via Dockerfile LABEL. Inspect via Artifact Registry blob fetch (Docker daemon not running on this Mac).

Pre-existing 403 quirk: `/api/auth/tenants/*/{branding,social-providers,saml-providers}` are gated by `AppAuthorizationFilter` and the SPA does not inject the header — see the pending-allowlist memory.
