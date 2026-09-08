# Dedicated WeldForge instance — Tech Metropolis trio

Stands up a WeldForge instance that serves **Safe Space, Commentalk and
Krusty** (plus the Commons microservice) on the single tenant slug
`techmetropolis`, separate from the shared `weldforge` instance.

Values file: `helm/weldforge/values-techmetropolis.yaml`.

---

## 0. Blocker — nothing below can run yet

Every GCP project across all four credentialed accounts has
`billingEnabled: false`, and all five billing accounts report `OPEN: False`:

| Project | Billing account | Enabled |
|---|---|---|
| `weldforge` | `011EF4-501DEC-D95B97` | false |
| `weldforge-499409` | `01BC97-762F6F-067EF6` | false |
| `techmetropolis-501911` | `01BC97-762F6F-067EF6` | false |

`gcloud container clusters list` returns HTTP 403 *"This API method requires
billing to be enabled"* on each. Restore billing first. Separately,
`wimpiev@techmetropolis.co.za`'s token needs an interactive
`gcloud auth login` — it cannot be refreshed non-interactively.

---

## 1. Decisions baked into the values file

Change these if any assumption is wrong; each one is a single edit.

| Choice | Value | Why |
|---|---|---|
| Project | `techmetropolis-501911` | Consumers, Artifact Registry and Secret Manager already live here. One billing account to restore instead of two. |
| Cluster | `techmetropolis-gke` (africa-south1) | Existing, and **confirmed Autopilot** 2026-08-17 (nodes are `gk3-`-prefixed, master `1.35.5-gke.1241004`). The chart targets Autopilot, so this matches. |
| Namespace / release | `sso` / `weldforge-tm` | `sso` is unused in this cluster. |
| Tenant slug | `techmetropolis` (unchanged) | **The key call.** Consumers send `X-Tenant-Slug: techmetropolis`; keeping the slug means zero consumer code change. Only the base URL and HMAC secret move. |
| Base domain | `sso.techmetropolis.co.za` | Needs an A record to the static IP plus a DNS-authorised wildcard cert for `*.sso.techmetropolis.co.za`. |
| Database | new Cloud SQL `weldforge-tm-db` | A dedicated instance must not share the shared instance's database. |

---

## 2. Bootstrap (once, after billing is restored)

```bash
export PROJECT=techmetropolis-501911
export REGION=africa-south1
gcloud config set project $PROJECT

# Cloud SQL — dedicated Postgres for this instance.
gcloud sql instances create weldforge-tm-db \
  --database-version=POSTGRES_16 --region=$REGION --tier=db-g1-small
gcloud sql databases create weldforge --instance=weldforge-tm-db
gcloud sql users create wfuser --instance=weldforge-tm-db --password=<db-password>

# Workload Identity service account for the API pod.
gcloud iam service-accounts create sso-api
gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:sso-api@$PROJECT.iam.gserviceaccount.com \
  --role=roles/cloudsql.client
gcloud iam service-accounts add-iam-policy-binding \
  sso-api@$PROJECT.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:$PROJECT.svc.id.goog[sso/sso-api]"

# Static IP for the ingress.
gcloud compute addresses create sso-tm-frontend-ip --global

# Secrets. Generate fresh ones — do NOT copy the shared instance's values.
for s in wf-db-password wf-jwt-secret wf-app-crypto-secret; do
  gcloud secrets create $s --replication-policy=automatic
done
openssl rand -base64 48 | gcloud secrets versions add wf-jwt-secret --data-file=-
openssl rand -base64 48 | gcloud secrets versions add wf-app-crypto-secret --data-file=-
```

DNS: point `sso.techmetropolis.co.za` at the static IP, then provision the
`*.sso.techmetropolis.co.za` wildcard through Certificate Manager
(DNS-authorised) and attach it via CertificateMap. Google-managed certs cannot
issue wildcards, which is why the chart's `managedCert` covers only the apex.

---

## 3. Deploy

```bash
TAG=$(git rev-parse HEAD | cut -c1-12)
AR=africa-south1-docker.pkg.dev/techmetropolis-501911/images

gcloud builds submit weldforge-auth          --tag $AR/weldforge-auth:$TAG
gcloud builds submit weldforge-admin-portal  --tag $AR/weldforge-admin-portal:$TAG

gcloud container clusters get-credentials techmetropolis-gke --region africa-south1

helm upgrade --install weldforge-tm infrastructure/helm/weldforge \
  --namespace sso --create-namespace \
  -f infrastructure/helm/weldforge/values-techmetropolis.yaml \
  --set api.image.tag=$TAG --set frontend.image.tag=$TAG \
  --set-string api.secrets.SPRING_DATASOURCE_PASSWORD="$(gcloud secrets versions access latest --secret=wf-db-password)" \
  --set-string api.secrets.JWT_SECRET="$(gcloud secrets versions access latest --secret=wf-jwt-secret)" \
  --set-string api.secrets.APP_CRYPTO_SECRET="$(gcloud secrets versions access latest --secret=wf-app-crypto-secret)" \
  --wait --timeout=10m
```

Flyway creates the schema on first boot. Then create the tenant with slug
`techmetropolis` through the admin portal at `https://sso.techmetropolis.co.za`.

---

## 4. Cutover hazards — read before switching consumers over

**The HMAC secret is shared platform-wide.** `app.jwt.secret` is mirrored to
every consumer's `WELDFORGE_JWT_SECRET` via Secret Manager `wf-jwt-secret`, and
all three verify with the same key. The dedicated instance has a *different*
secret, so Safe Space, Commentalk, Krusty and Commons must all be rotated and
restarted in one window. Any consumer left on the old value rejects every token
the new instance issues.

**Users do not come across automatically.** Accounts, credentials, MFA
enrolments and API keys live in tenant id 6 on the shared instance. Either
export and re-import them, or every existing user is locked out at cutover.
Password hashes are portable; TOTP enrolments and WebAuthn credentials are
bound to the issuer/origin and will need re-enrolment once the base domain
changes from `sso.weldforge.org` to `sso.techmetropolis.co.za`.

**Known consumer-side bug, still open.** Failed-login audit and lockout counter
writes happen inside `AuthService.login`'s `@Transactional`, so
`BadCredentialsException` rolls them back — failed logins are not audited and
lockout never engages. Worth fixing with `REQUIRES_NEW` while this instance is
still pre-production.

---

## 5. Verify

```bash
kubectl -n sso get pods,svc,ingress
kubectl -n sso logs deploy/weldforge-tm-api --tail=100

# OIDC discovery for the tenant — the real liveness check.
curl -s https://techmetropolis.sso.techmetropolis.co.za/.well-known/openid-configuration | jq .issuer
```

The API's own health endpoint is not a useful outside-in check; use a live
tenant's OIDC discovery document instead.
