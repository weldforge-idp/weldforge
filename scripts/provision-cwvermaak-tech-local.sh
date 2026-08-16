#!/usr/bin/env bash
# Provision the shared `cwvermaak-tech` tenant in the LOCAL WeldForge, and register
# an OIDC client for each in-house app under CWVermaak/Tech.
#
# One tenant, one login, across CastForge, KeyCrypt, NoteForge, Clepsydra and
# Sentinel. Products that serve their own end users — Wellspring, Lyceum,
# Oggend-Boodskap — deliberately keep their own tenants; multi-tenancy is what
# keeps their users out of ours.
#
# SignalForge needs no client here: it is a multi-tenant resource server that
# resolves the issuer per request from `WELDFORGE_ISSUER_BASE`, so it already
# accepts cwvermaak-tech tokens.
#
# Requires: WeldForge auth UP on :8076, its Postgres in container
# `weldforge-auth-db-1` (user/db postgres/weldforge), and python3 for JSON.
#
# Re-runnable: tenant/role/user inserts are ON CONFLICT DO NOTHING, and each OIDC
# client is deleted before it is recreated — client secrets are returned exactly
# once, so recreating is the only way to recover one.
#
# Writes each app's local env file at the end. Those files are git-ignored;
# nothing here touches committed defaults or deployed configuration.
set -uo pipefail

B=${WELDFORGE_BASE:-http://localhost:8076}
DB=${WELDFORGE_DB_CONTAINER:-weldforge-auth-db-1}
SLUG=cwvermaak-tech
ISSUER=${WELDFORGE_LOCAL_ISSUER:-http://lvh.me:8076/t/$SLUG}
TECH=${TECH_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}

# The platform admin used to drive the admin API. WeldForge reserves client
# registration for a real platform SUPER_ADMIN, and the users table ships empty,
# so the first one has to be seeded by SQL.
#
# No defaults, deliberately. An earlier revision of this script carried literal
# passwords and a bcrypt hash, which put working credentials for a platform
# SUPER_ADMIN into a public repository. "It is only local" holds right up until
# a local instance is port-forwarded or its seed reaches a deployed one.
BOOT_EMAIL=${CWVERMAAK_BOOTSTRAP_EMAIL:-castforge-bootstrap@castforge.local}
BOOT_PASS=${CWVERMAAK_BOOTSTRAP_PASSWORD:-}
BOOT_HASH=${CWVERMAAK_BOOTSTRAP_PASSWORD_HASH:-}

ADMIN_EMAIL=${CWVERMAAK_ADMIN_EMAIL:-wimpie.vermaak@gmail.com}
ADMIN_PASS=${CWVERMAAK_ADMIN_PASSWORD:-}

if [ -z "$BOOT_PASS" ] || [ -z "$BOOT_HASH" ] || [ -z "$ADMIN_PASS" ]; then
    cat >&2 <<'USAGE'
This script needs its credentials from the environment; it carries no defaults.

    export CWVERMAAK_BOOTSTRAP_PASSWORD='...'        # bootstrap platform admin
    export CWVERMAAK_BOOTSTRAP_PASSWORD_HASH='...'   # bcrypt of the above, cost 12
    export CWVERMAAK_ADMIN_PASSWORD='...'            # your tenant admin

WeldForge hashes at bcrypt cost 12 (SEC-06). To generate the hash:

    htpasswd -bnBC 12 "" 'your-password' | tr -d ':\n' | sed 's/^\$2y/\$2a/'

or, with the JDK and the jar Maven has already fetched for weldforge-auth:

    java -cp ~/.m2/repository/org/springframework/security/spring-security-crypto/6.5.7/spring-security-crypto-6.5.7.jar\
:~/.m2/repository/org/springframework/spring-jcl/6.2.14/spring-jcl-6.2.14.jar \
        - <<'JAVA'
    // BCryptPasswordEncoder(12).encode("your-password")
    JAVA

The bootstrap account exists only to drive the admin API; nothing signs in as it
day to day, so a long random value is the right choice.
USAGE
    exit 1
fi

jget() { python -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

# This script seeds a platform SUPER_ADMIN whose password is written in plain sight
# a few lines up, and mints OIDC clients with redirect URIs on localhost. Against a
# deployed WeldForge that is an account takeover, not a convenience — so the base URL
# is checked rather than trusted. Override deliberately with ALLOW_NONLOCAL=1 if you
# have some reason to point it elsewhere.
case "${ALLOW_NONLOCAL:-0}$B" in
    1*) ;;
    0http://localhost:*|0http://127.0.0.1:*|0http://lvh.me:*|0http://*.lvh.me:*) ;;
    *)
        echo "Refusing to run against '$B'." >&2
        echo "This provisions local-dev credentials with a known password; it is not safe" >&2
        echo "against a deployed WeldForge. Set ALLOW_NONLOCAL=1 only if you are certain." >&2
        exit 1
        ;;
esac

echo "1) tenant '$SLUG' + roles"
docker exec "$DB" psql -U postgres -d weldforge -v ON_ERROR_STOP=1 -q -c "
INSERT INTO tenants (slug, name, display_name, contact_email,
                     registration_enabled, password_recovery_enabled, email_verification_required)
VALUES ('$SLUG', 'CWVermaak Tech', 'CWVermaak Tech', '$ADMIN_EMAIL', true, true, false)
ON CONFLICT (slug) DO NOTHING;
INSERT INTO roles (name, description, tenant_id)
SELECT 'USER', 'Standard CWVermaak Tech user', t.id FROM tenants t WHERE t.slug = '$SLUG'
ON CONFLICT (tenant_id, lower(name)) DO NOTHING;
INSERT INTO roles (name, description, tenant_id)
SELECT 'SUPERADMIN', 'CWVermaak Tech superadmin', t.id FROM tenants t WHERE t.slug = '$SLUG'
ON CONFLICT (tenant_id, lower(name)) DO NOTHING;
"

echo "2) bootstrap platform super admin"
docker exec "$DB" psql -U postgres -d weldforge -v ON_ERROR_STOP=1 -q -c "
INSERT INTO users (tenant_id, username, email, password, name, provider, provider_id,
                   email_verified, admin_role, is_super_admin, active)
SELECT t.id, '$BOOT_EMAIL', '$BOOT_EMAIL', '$BOOT_HASH',
       'Bootstrap Admin', 'LOCAL', 'local', true, 'SUPER_ADMIN', true, true
  FROM tenants t WHERE t.slug = 'default'
ON CONFLICT (tenant_id, lower(email)) DO NOTHING;
INSERT INTO admin_membership (user_id, tenant_id, admin_role)
SELECT u.id, NULL, 'SUPER_ADMIN' FROM users u WHERE lower(u.email) = '$BOOT_EMAIL'
ON CONFLICT DO NOTHING;
"

TOKEN=$(curl -s -X POST "$B/api/auth/login" -H "X-Tenant-Slug: default" -H "Content-Type: application/json" \
  -d "{\"identifier\":\"$BOOT_EMAIL\",\"password\":\"$BOOT_PASS\"}" | jget token)
if [ -z "$TOKEN" ]; then echo "   login failed — is WeldForge up on $B?"; exit 1; fi

# register <clientId> <json-body> -> prints the secret (empty for public clients)
register() {
  local id=$1 body=$2 existing
  existing=$(curl -s "$B/api/admin/oidc/clients" -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Slug: $SLUG" \
    | python -c "
import sys,json
for c in json.load(sys.stdin):
    if c.get('clientId') == '$id':
        print(c['id']); break
" 2>/dev/null)
  if [ -n "$existing" ]; then
    curl -s -o /dev/null -X DELETE "$B/api/admin/oidc/clients/$existing" \
      -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Slug: $SLUG"
  fi
  curl -s -X POST "$B/api/admin/oidc/clients" \
    -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Slug: $SLUG" -H "Content-Type: application/json" \
    -d "$body" | jget clientSecret
}

echo "3) OIDC clients"

CASTFORGE_SECRET=$(register castforge-console '{"clientId":"castforge-console","name":"CastForge Console",
  "redirectUris":["http://localhost:8090/login/oauth2/code/weldforge"],
  "postLogoutRedirectUris":["http://localhost:8090/signed-out","http://localhost:8090/"],
  "webOrigins":["http://localhost:8090"],"scopes":["openid","profile","email"],
  "grantTypes":["authorization_code","refresh_token"],
  "tokenEndpointAuthMethod":"client_secret_post","requirePkce":true}')
echo "   castforge-console"

CASTFORGE_EDGE_SECRET=$(register castforge-edge '{"clientId":"castforge-edge","name":"CastForge Edge Client",
  "redirectUris":["http://localhost:8090/unused"],"scopes":["openid"],
  "grantTypes":["client_credentials"],"tokenEndpointAuthMethod":"client_secret_post","requirePkce":false}')
echo "   castforge-edge"

# clientId is `keycrypt`, not `keycrypt-auth`: WeldForge stamps `aud` with the
# client id, and KeyCrypt's default expected audience is `keycrypt`. The browser
# client necessarily gets `aud=keycrypt-web`, so the generated env files name
# both in KEYCRYPT_OIDC_EXPECTED_AUDIENCE.
KEYCRYPT_SECRET=$(register keycrypt '{"clientId":"keycrypt","name":"KeyCrypt Auth Service",
  "redirectUris":["http://localhost:8081/login/oauth2/code/weldforge"],
  "postLogoutRedirectUris":["http://localhost:8081/"],"webOrigins":["http://localhost:8081"],
  "scopes":["openid","profile","email"],
  "grantTypes":["authorization_code","refresh_token","client_credentials"],
  "tokenEndpointAuthMethod":"client_secret_post","requirePkce":true}')
echo "   keycrypt"

register keycrypt-web '{"clientId":"keycrypt-web","name":"KeyCrypt Web","publicClient":true,
  "tokenEndpointAuthMethod":"none","requirePkce":true,
  "redirectUris":["http://localhost:5173/callback"],"postLogoutRedirectUris":["http://localhost:5173"],
  "webOrigins":["http://localhost:5173"],"scopes":["openid","profile","email"],
  "grantTypes":["authorization_code","refresh_token"]}' > /dev/null
echo "   keycrypt-web (public, PKCE)"

NOTEFORGE_SECRET=$(register noteforge '{"clientId":"noteforge","name":"NoteForge",
  "redirectUris":["http://localhost:8088/login/oauth2/code/weldforge"],
  "webOrigins":["http://localhost:8088"],"scopes":["openid","profile","email"],
  "grantTypes":["authorization_code","client_credentials"],
  "tokenEndpointAuthMethod":"client_secret_post","requirePkce":true}')
echo "   noteforge"

CLEPSYDRA_SECRET=$(register clepsydra '{"clientId":"clepsydra","name":"Clepsydra API",
  "redirectUris":["http://localhost:8080/login/oauth2/code/weldforge"],
  "webOrigins":["http://localhost:8080"],"scopes":["openid","profile","email"],
  "grantTypes":["authorization_code","client_credentials"],
  "tokenEndpointAuthMethod":"client_secret_post","requirePkce":true}')
echo "   clepsydra"

SENTINEL_SECRET=$(register sentinel '{"clientId":"sentinel","name":"Sentinel Console",
  "redirectUris":["http://localhost:3000/login/oauth2/code/weldforge"],
  "postLogoutRedirectUris":["http://localhost:3000/"],"webOrigins":["http://localhost:3000"],
  "scopes":["openid","profile","email"],"grantTypes":["authorization_code","refresh_token"],
  "tokenEndpointAuthMethod":"client_secret_post","requirePkce":true}')
echo "   sentinel"

echo "4) tenant admin $ADMIN_EMAIL"
RESET=$(curl -s -X POST "$B/api/admin/users/invite" \
  -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Slug: $SLUG" -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"name\":\"Wimpie Vermaak\",\"isSuperAdmin\":true}" | jget resetToken)
if [ -n "$RESET" ]; then
  curl -s -o /dev/null -X POST "$B/api/auth/reset-password" -H "X-Tenant-Slug: $SLUG" \
    -H "Content-Type: application/json" -d "{\"token\":\"$RESET\",\"newPassword\":\"$ADMIN_PASS\"}"
fi

echo "5) write local env files under $TECH"

write_env() {  # write_env <path> <<'EOF' ... EOF
  mkdir -p "$(dirname "$1")"
  cat > "$1"
  echo "   $1"
}

write_env "$TECH/castforge/castforge-backend/dev/weldforge.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
CASTFORGE_OIDC_ISSUER_URI=$ISSUER
CASTFORGE_OIDC_CLIENT_ID=castforge-console
CASTFORGE_OIDC_CLIENT_SECRET=$CASTFORGE_SECRET
CASTFORGE_EDGE_CLIENT_ID=castforge-edge
CASTFORGE_EDGE_CLIENT_SECRET=$CASTFORGE_EDGE_SECRET
EOF

write_env "$TECH/keycrypt/services/auth-service/.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5438/keycrypt_auth
SPRING_DATASOURCE_USERNAME=keycrypt
SPRING_DATASOURCE_PASSWORD=keycrypt
WELDFORGE_ISSUER_URI=$ISSUER
WELDFORGE_CLIENT_ID=keycrypt
WELDFORGE_CLIENT_SECRET=$KEYCRYPT_SECRET
WELDFORGE_REDIRECT_URI=http://localhost:8081/login/oauth2/code/weldforge
EOF

write_env "$TECH/keycrypt/infrastructure/.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
AUTH_DB_NAME=keycrypt_auth
AUTH_DB_USERNAME=keycrypt
AUTH_DB_PASSWORD=keycrypt
VAULT_DB_NAME=keycrypt_vault
VAULT_DB_USERNAME=keycrypt
VAULT_DB_PASSWORD=keycrypt
WELDFORGE_ISSUER_URI=$ISSUER
WELDFORGE_CLIENT_ID=keycrypt
WELDFORGE_CLIENT_SECRET=$KEYCRYPT_SECRET
WELDFORGE_REDIRECT_URI=http://localhost:8081/login/oauth2/code/weldforge
KEYCRYPT_OIDC_EXPECTED_AUDIENCE=keycrypt,keycrypt-web
KEYCRYPT_CORS_ALLOWED_ORIGINS=http://localhost:5173
JAVA_TOOL_OPTIONS=
SPRING_PROFILES_ACTIVE=docker
EOF

write_env "$TECH/keycrypt/services/secrets-service/.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
# Resource server only: validates tokens, never starts a login flow, so it needs
# the issuer but no client credentials.
WELDFORGE_ISSUER_URI=$ISSUER
KEYCRYPT_OIDC_EXPECTED_AUDIENCE=keycrypt,keycrypt-web
EOF

write_env "$TECH/keycrypt/services/vault-service/.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5439/keycrypt_vault
SPRING_DATASOURCE_USERNAME=keycrypt
SPRING_DATASOURCE_PASSWORD=keycrypt
WELDFORGE_ISSUER_URI=$ISSUER
KEYCRYPT_CORS_ALLOWED_ORIGINS=http://localhost:5173
KEYCRYPT_OIDC_EXPECTED_AUDIENCE=keycrypt,keycrypt-web
EOF

write_env "$TECH/keycrypt/web/.env.local" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
VITE_WELDFORGE_ISSUER=$ISSUER
VITE_OIDC_CLIENT_ID=keycrypt-web
VITE_VAULT_API_URL=http://localhost:8082
EOF

write_env "$TECH/noteforge/.env" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
# docker compose interpolates these into the note-service environment.
WELDFORGE_ISSUER=$ISSUER
WELDFORGE_AUDIENCE=noteforge
NOTEFORGE_OIDC_CLIENT_ID=noteforge
NOTEFORGE_OIDC_CLIENT_SECRET=$NOTEFORGE_SECRET
EOF

# Note the escaping: these heredocs are unquoted so $ISSUER and the secrets
# expand — which also means no backticks in the body, or the shell runs them.
write_env "$TECH/clepsydra/backend/.env.local" <<EOF
# Generated by weldforge/scripts/provision-cwvermaak-tech-local.sh — local-dev only.
# Clepsydra has no local runner yet (docker-compose.yml is Sprint 0 work), and
# Spring does not read .env files on its own, so source this first:
#   set -a; . backend/.env.local; set +a
#   mvn -pl api-gateway spring-boot:run
#
# Both api-gateway and tenant-service are resource servers configured through
# spring.security.oauth2.resourceserver.jwt.issuer-uri, which Spring resolves by
# fetching discovery at startup — so WeldForge must be up on :8076 to boot them.
WELDFORGE_ISSUER_URI=$ISSUER
CLEPSYDRA_OIDC_CLIENT_ID=clepsydra
CLEPSYDRA_OIDC_CLIENT_SECRET=$CLEPSYDRA_SECRET
EOF

# Sentinel's .env carries a lot of unrelated local settings (Postgres, RabbitMQ,
# Kafka, break-glass credentials), so its three OIDC lines are rewritten in place
# rather than the file being regenerated.
SENTINEL_ENV="$TECH/sentinel/infrastructure/.env"
if [ -f "$SENTINEL_ENV" ]; then
  python - "$SENTINEL_ENV" "$ISSUER" "$SENTINEL_SECRET" <<'PY'
import io, re, sys
path, issuer, secret = sys.argv[1], sys.argv[2], sys.argv[3]
s = io.open(path, encoding='utf-8').read()
for key, val in (('SENTINEL_OIDC_ISSUER', issuer),
                 ('SENTINEL_OIDC_CLIENT_ID', 'sentinel'),
                 ('SENTINEL_OIDC_CLIENT_SECRET', secret)):
    s = re.sub(r'(?m)^%s=.*$' % key, '%s=%s' % (key, val), s)
io.open(path, 'w', encoding='utf-8', newline='\n').write(s)
PY
  echo "   $SENTINEL_ENV (OIDC lines rewritten in place)"
fi

echo
echo "tenant    : $ISSUER"
echo "login as  : $ADMIN_EMAIL / $ADMIN_PASS"
echo "hosted UI : http://$SLUG.lvh.me:8076/login/"
echo
echo "SignalForge needs nothing: it resolves the issuer per request from WELDFORGE_ISSUER_BASE."
