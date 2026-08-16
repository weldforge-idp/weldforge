# Infrastructure - weldforge

GCP-hosted deployment for the WeldForge platform.

## Layout

```
infrastructure/
└── helm/weldforge/   # Helm chart deployed to GKE Autopilot
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
| Artifact Registry | `africa-south1-docker.pkg.dev/weldforge/images/{weldforge-auth,weldforge-admin-portal}` |
| Static IP | `sso-frontend-ip` (`34.120.183.117`) bound to GKE Ingress |
| Domain | `sso.weldforge.org` (Google-managed certificate) |
| Workload Identity | KSA `sso/sso-api` ↔ GSA `sso-api@weldforge.iam` (`roles/cloudsql.client`) |
| Sensitive secrets | Google Secret Manager: `wf-db-password`, `wf-jwt-secret`, `wf-app-crypto-secret` |

## Deploying

Pushes to `main` that touch `weldforge-auth/**`, `weldforge-admin-portal/**`, or
`infrastructure/helm/weldforge/**` trigger `.github/workflows/deploy-gcp.yml`,
which builds the two container images, pushes them to Artifact Registry, and
runs `helm upgrade --install weldforge` against the GKE cluster.

CI uses Workload Identity Federation (no static AWS/GCP keys); the
`gha-deployer@weldforge.iam` service account is bound to the WIF pool
`projects/42633983307/locations/global/workloadIdentityPools/github-actions`.

To deploy locally (rare — the GHA workflow is the canonical path):

```bash
gcloud container clusters get-credentials weldforge-gke \
    --location africa-south1 --project weldforge

helm upgrade --install weldforge infrastructure/helm/weldforge \
    --namespace sso \
    -f infrastructure/helm/weldforge/values-prod.yaml \
    --set api.image.tag=$TAG \
    --set frontend.image.tag=$TAG \
    --set-string api.secrets.SPRING_DATASOURCE_PASSWORD="$(gcloud secrets versions access latest --secret=wf-db-password)" \
    --set-string api.secrets.JWT_SECRET="$(gcloud secrets versions access latest --secret=wf-jwt-secret)" \
    --set-string api.secrets.APP_CRYPTO_SECRET="$(gcloud secrets versions access latest --secret=wf-app-crypto-secret)"
```

## Second environment — GCP project `weldforge-499409`

A self-contained WeldForge stack was bootstrapped in the separate GCP project
`weldforge-499409` (region `africa-south1`). It is **not** wired to
`deploy-gcp.yml` (that workflow targets the `weldforge` project) — this
environment is deployed manually with the overrides in
[`helm/weldforge/values-499409.yaml`](helm/weldforge/values-499409.yaml).

| Resource | Value |
|---|---|
| GCP project | `weldforge-499409` |
| Region | `africa-south1` |
| GKE cluster | `weldforge-gke` (Autopilot) |
| Cloud SQL | `weldforge-db` (Postgres 16, ENTERPRISE, db-f1-micro) — DB `weldforge`, user `wfuser` |
| Artifact Registry | `africa-south1-docker.pkg.dev/weldforge-499409/images/{weldforge-auth,weldforge-admin-portal}` |
| Static IP | `weldforge-ingress-ip` (`34.117.149.97`) bound to GKE Ingress |
| Domain | `sso.weldforge.org` (Google-managed cert `sso-frontend-cert`) — apex `weldforge.org`/`www` stays on Xneelo |
| DNS | `sso.weldforge.org` A-record → `34.117.149.97`, hosted at Xneelo/KonsoleH |
| Workload Identity | KSA `sso/sso-api` ↔ GSA `sso-api@weldforge-499409.iam` (`roles/cloudsql.client`) |
| Sensitive secrets | Secret Manager: `wf-db-password`, `wf-jwt-secret`, `wf-app-crypto-secret` |

Build, push, and deploy (run from repo root; `gcloud` must be on `PATH` so
`docker-credential-gcloud` and the GKE auth plugin resolve):

```bash
PROJ=weldforge-499409
TAG=r1   # bump per release

gcloud auth configure-docker africa-south1-docker.pkg.dev --quiet
for img in weldforge-auth weldforge-admin-portal; do
  docker build -t africa-south1-docker.pkg.dev/$PROJ/images/$img:$TAG ./$img
  docker push   africa-south1-docker.pkg.dev/$PROJ/images/$img:$TAG
done

gcloud container clusters get-credentials weldforge-gke \
    --location africa-south1 --project $PROJ

helm upgrade --install weldforge infrastructure/helm/weldforge \
    --namespace sso \
    -f infrastructure/helm/weldforge/values-prod.yaml \
    -f infrastructure/helm/weldforge/values-499409.yaml \
    --set api.image.tag=$TAG --set frontend.image.tag=$TAG \
    --set-string api.secrets.SPRING_DATASOURCE_PASSWORD="$(gcloud secrets versions access --project $PROJ latest --secret=wf-db-password)" \
    --set-string api.secrets.JWT_SECRET="$(gcloud secrets versions access --project $PROJ latest --secret=wf-jwt-secret)" \
    --set-string api.secrets.APP_CRYPTO_SECRET="$(gcloud secrets versions access --project $PROJ latest --secret=wf-app-crypto-secret)"
```

Notes:
- The chart templates its own `Namespace`; on a first install pre-create `sso`
  with Helm's adoption metadata (`app.kubernetes.io/managed-by=Helm` +
  `meta.helm.sh/release-{name,namespace}`) so Helm adopts it rather than
  erroring on ownership.
- `values-499409.yaml` carries non-secret overrides only (image repos, Cloud SQL
  `connectionName`, GSA, static IP, cert host). Secrets are injected at deploy
  time from Secret Manager and never committed.
- The Google-managed cert stays `Provisioning` until the DNS A-record resolves
  to the ingress IP, then issues in ~15–60 min. Verify with
  `kubectl -n sso get managedcertificate sso-frontend-cert`.
