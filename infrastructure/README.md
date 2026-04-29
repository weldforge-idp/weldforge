# Infrastructure - intelli-sso

GCP-hosted deployment for the WeldForge / intelli-sso platform.

## Layout

```
infrastructure/
└── helm/intelli-sso/   # Helm chart deployed to GKE Autopilot
    ├── Chart.yaml
    ├── values.yaml         # defaults
    ├── values-prod.yaml    # production overrides
    ├── values-staging.yaml # staging overrides
    └── templates/          # api + frontend + ingress + ManagedCertificate
```

## Live environment

| Resource | Value |
|---|---|
| GCP project | `weldforge` |
| Region | `africa-south1` |
| GKE cluster | `weldforge-gke` (Autopilot) |
| Cloud SQL | `weldforge-db` (Postgres 16) — accessed via Cloud SQL Auth Proxy sidecar |
| Artifact Registry | `africa-south1-docker.pkg.dev/weldforge/images/{intelli-sso-auth,intelli-sso-admin-portal}` |
| Static IP | `sso-frontend-ip` (`34.120.183.117`) bound to GKE Ingress |
| Domain | `sso.weldforge.org` (Google-managed certificate) |
| Workload Identity | KSA `sso/sso-api` ↔ GSA `sso-api@weldforge.iam` (`roles/cloudsql.client`) |
| Sensitive secrets | Google Secret Manager: `wf-db-password`, `wf-jwt-secret`, `wf-app-crypto-secret` |

## Deploying

Pushes to `main` that touch `intelli-sso-auth/**`, `intelli-sso-admin-portal/**`, or
`infrastructure/helm/intelli-sso/**` trigger `.github/workflows/deploy-gcp.yml`,
which builds the two container images, pushes them to Artifact Registry, and
runs `helm upgrade --install intelli-sso` against the GKE cluster.

CI uses Workload Identity Federation (no static AWS/GCP keys); the
`gha-deployer@weldforge.iam` service account is bound to the WIF pool
`projects/42633983307/locations/global/workloadIdentityPools/github-actions`.

To deploy locally (rare — the GHA workflow is the canonical path):

```bash
gcloud container clusters get-credentials weldforge-gke \
    --location africa-south1 --project weldforge

helm upgrade --install intelli-sso infrastructure/helm/intelli-sso \
    --namespace sso \
    -f infrastructure/helm/intelli-sso/values-prod.yaml \
    --set api.image.tag=$TAG \
    --set frontend.image.tag=$TAG \
    --set-string api.secrets.SPRING_DATASOURCE_PASSWORD="$(gcloud secrets versions access latest --secret=wf-db-password)" \
    --set-string api.secrets.JWT_SECRET="$(gcloud secrets versions access latest --secret=wf-jwt-secret)" \
    --set-string api.secrets.APP_CRYPTO_SECRET="$(gcloud secrets versions access latest --secret=wf-app-crypto-secret)"
```
