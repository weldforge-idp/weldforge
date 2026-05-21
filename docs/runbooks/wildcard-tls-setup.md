# Runbook — Wildcard DNS + TLS for `*.sso.weldforge.org`

**Why this exists.** The per-tenant subdomain feature (`docs/auth-url-spec.md`)
needs `https://<slug>.sso.weldforge.org` to resolve and serve a valid
TLS certificate. GCP's `ManagedCertificate` (the k8s CRD the apex cert
uses) does **not** support wildcard SANs. Google Certificate Manager
does, via DNS-01 authorization. This runbook walks through the one-time
setup.

**Audience.** A platform operator with:
- `gcloud` auth as a project-level admin on GCP project `weldforge`
- Owner / DNS Admin on the Cloud DNS zone `weldforge.org`
- `kubectl` against `gke_weldforge_africa-south1_weldforge-gke`

**Time.** ~20 minutes hands-on; ~30 minutes wait for cert provisioning.

**Reversibility.** Every step is reversible. The DNS wildcard A-record
can be removed (subdomain becomes `NXDOMAIN` again). The cert
attachment is a single Ingress annotation that can be removed. The
existing apex `ManagedCertificate` is untouched throughout — `https://sso.weldforge.org`
keeps working at every stage.

---

## 0. Prerequisites — set once

```bash
export PROJECT=weldforge
export REGION=africa-south1
export DNS_ZONE=weldforge-org          # Cloud DNS zone name (NOT the domain itself)
export DOMAIN=weldforge.org            # parent domain
export BASE_HOST=sso.weldforge.org     # apex auth host
export WILDCARD=*.sso.weldforge.org
export INGRESS_STATIC_IP=sso-frontend-ip
export KCTX=gke_weldforge_africa-south1_weldforge-gke

gcloud config set project "$PROJECT"
gcloud config set compute/region "$REGION"

# Confirm the existing apex setup before touching anything.
gcloud compute addresses describe "$INGRESS_STATIC_IP" --global --format='value(address)'
gcloud dns managed-zones describe "$DNS_ZONE" --format='value(dnsName)'
kubectl --context="$KCTX" -n sso get ingress sso-frontend -o jsonpath='{.metadata.annotations}'
```

You should see: the apex IP, the zone name (`weldforge.org.`), and the
ingress annotations. Confirm `kubernetes.io/ingress.global-static-ip-name`
matches `$INGRESS_STATIC_IP`.

---

## 1. Wildcard `A`-record (Cloud DNS)

```bash
INGRESS_IP=$(gcloud compute addresses describe "$INGRESS_STATIC_IP" --global --format='value(address)')
echo "Ingress IP: $INGRESS_IP"

gcloud dns record-sets create "$WILDCARD." \
    --zone="$DNS_ZONE" \
    --type=A \
    --ttl=300 \
    --rrdatas="$INGRESS_IP"

# Verify (give it ~60s to propagate to Google's auth DNS):
sleep 60
host "demo.${BASE_HOST}"   # any subdomain — must resolve to $INGRESS_IP
```

**Expected:** `demo.sso.weldforge.org has address <INGRESS_IP>`.

**If `NXDOMAIN`:** the record didn't land. Re-check `gcloud dns record-sets
list --zone="$DNS_ZONE"`.

**Side-effect immediately visible.** Once the wildcard A-record is up,
every per-tenant subdomain serves HTTP **but TLS will still fail** —
the cert is the next step. The GCP HTTPS LB falls back to the apex
cert which doesn't cover the new SAN.

---

## 2. DNS-01 authorization (Google Certificate Manager)

```bash
gcloud certificate-manager dns-authorizations create wildcard-sso-auth \
    --domain="$BASE_HOST" \
    --location=global

# Read the CNAME target Google asks us to add.
AUTH_CNAME=$(gcloud certificate-manager dns-authorizations describe wildcard-sso-auth \
    --location=global \
    --format='value(dnsResourceRecord.name)')
AUTH_TARGET=$(gcloud certificate-manager dns-authorizations describe wildcard-sso-auth \
    --location=global \
    --format='value(dnsResourceRecord.data)')

echo "Add CNAME:  $AUTH_CNAME  →  $AUTH_TARGET"
```

`$AUTH_CNAME` will be something like `_acme-challenge.sso.weldforge.org.`
and `$AUTH_TARGET` will be a `*.acme-challenge.googletrust.com.`-shaped
hostname.

```bash
gcloud dns record-sets create "$AUTH_CNAME" \
    --zone="$DNS_ZONE" \
    --type=CNAME \
    --ttl=300 \
    --rrdatas="$AUTH_TARGET"

# Verify the CNAME resolves.
host "${AUTH_CNAME%.}"
```

---

## 3. Issue the wildcard certificate

```bash
gcloud certificate-manager certificates create wildcard-sso-cert \
    --domains="$WILDCARD" \
    --dns-authorizations=wildcard-sso-auth \
    --location=global
```

Watch the state. Provisioning normally takes 5–30 minutes — Google
needs to verify the DNS-01 challenge and issue from their CA.

```bash
# Poll until ACTIVE.
until [ "$(gcloud certificate-manager certificates describe wildcard-sso-cert \
            --location=global --format='value(managed.state)')" = "ACTIVE" ]; do
    sleep 30
    gcloud certificate-manager certificates describe wildcard-sso-cert \
        --location=global --format='value(managed.state,managed.provisioningIssue.reason)'
done
echo "Certificate ACTIVE."
```

**If stuck on `PROVISIONING` past 30 minutes**, check
`managed.provisioningIssue.reason` — usually a DNS-01 propagation
issue. `dig +short CNAME "$AUTH_CNAME"` should return the target.

---

## 4. CertificateMap + Entry

A CertificateMap is the bridge between the issued certificate and the
GCE HTTPS load balancer. The Ingress references the map; the map's
entries decide which cert to serve for which Host header.

```bash
gcloud certificate-manager maps create sso-wildcard-cert-map \
    --location=global

# One entry per hostname pattern. The wildcard entry is keyed by hostname=*.sso.weldforge.org.
gcloud certificate-manager maps entries create wildcard-sso-entry \
    --map=sso-wildcard-cert-map \
    --certificates=wildcard-sso-cert \
    --hostname="$WILDCARD" \
    --location=global

# Verify.
gcloud certificate-manager maps entries list \
    --map=sso-wildcard-cert-map \
    --location=global
```

---

## 5. Attach the map to the GKE Ingress

```bash
kubectl --context="$KCTX" -n sso annotate ingress sso-frontend \
    networking.gke.io/v1.certificatemap=sso-wildcard-cert-map --overwrite

# Force a re-sync (GKE Ingress controller polls every ~30s but a
# touch usually wakes it up).
kubectl --context="$KCTX" -n sso get ingress sso-frontend -o yaml | head -30
```

**The apex `ManagedCertificate` is left in place.** The HTTPS LB now
has two cert sources: the legacy ManagedCertificate (serving
`sso.weldforge.org`) and the CertificateMap (serving
`*.sso.weldforge.org`). The LB picks per SNI Host header.

---

## 6. Smoke test

```bash
# DNS
host "demo.${BASE_HOST}"            # → $INGRESS_IP

# TLS — the SAN should now include the wildcard.
echo | openssl s_client -connect "demo.${BASE_HOST}:443" -servername "demo.${BASE_HOST}" 2>/dev/null \
     | openssl x509 -noout -subject -ext subjectAltName

# Backend reaches with correct Host
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' "https://demo.${BASE_HOST}/"
# X-Robots-Tag: noindex, nofollow  (TenantSubdomainNoIndexFilter + nginx)
curl -sS -o /dev/null -D - "https://demo.${BASE_HOST}/" | grep -i x-robots-tag

# Apex still works unchanged
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' "https://${BASE_HOST}/health"
```

**Expected:**
- DNS resolves to the ingress IP.
- TLS cert SAN includes `*.sso.weldforge.org`.
- Per-tenant subdomain returns 200 (Angular SPA) and `X-Robots-Tag: noindex, nofollow`.
- Apex health still 200.

---

## 7. Codify (follow-up PR)

After the manual `kubectl annotate` is verified working, fold the
annotation into the Helm chart so a fresh cluster reconstructs the
same state:

```yaml
# infrastructure/helm/weldforge/templates/frontend-ingress.yaml
metadata:
  annotations:
    ...
    networking.gke.io/v1.certificatemap: sso-wildcard-cert-map
```

The CertificateMap itself stays out of Helm — it's a GCP project
resource, not a k8s resource, and is managed via Terraform / gcloud.

---

## 8. Rollback

If anything goes wrong:

```bash
# Detach the map from the ingress (cert falls back to apex ManagedCertificate;
# tenant subdomains stop serving valid TLS again but apex stays fine).
kubectl --context="$KCTX" -n sso annotate ingress sso-frontend \
    networking.gke.io/v1.certificatemap- --overwrite

# Remove the wildcard A-record (tenant subdomains NXDOMAIN again — safe).
gcloud dns record-sets delete "$WILDCARD." --zone="$DNS_ZONE" --type=A

# The cert itself is harmless to leave in place — it's not serving anything
# once the map is detached. Delete only if the project's cert quota matters:
gcloud certificate-manager maps entries delete wildcard-sso-entry \
    --map=sso-wildcard-cert-map --location=global
gcloud certificate-manager maps delete sso-wildcard-cert-map --location=global
gcloud certificate-manager certificates delete wildcard-sso-cert --location=global
gcloud certificate-manager dns-authorizations delete wildcard-sso-auth --location=global
# (DNS-01 CNAME can also be removed once the cert is gone.)
```

---

## 9. Operational notes

- **Renewal is automatic.** Google Certificate Manager rotates the cert
  ~30 days before expiry. The DNS-01 authorization stays valid as long
  as the CNAME record stays in place — don't remove it.
- **Adding a custom tenant domain** (e.g. `auth.acmecorp.com` as an
  alias for `acme.sso.weldforge.org`) needs its own
  `dns-authorization` + `certificate` + a separate `maps entries`
  with that hostname. Out of scope for this runbook.
- **Monitoring.** Add an alert on the certificate's `expireTime` minus
  14 days — if Google fails to renew silently, the alert fires before
  expiry.
- **Cost.** Google Certificate Manager bills per cert + per
  certificate-map-entry; a single wildcard is essentially free at our
  scale (under the included quota).
