#!/usr/bin/env bash
# WeldForge secrets helper — SOPS + age.
#
# Every secret in this repo lives encrypted under infrastructure/secrets/ and is
# decrypted only in memory (or into a gitignored file) at the moment it is used.
# There is no plaintext secret committed anywhere, and no external secret store
# is required — which is the point: the GCP Secret Manager path died with the
# GCP estate, and self-hosters never had access to it in the first place.
#
#   ./scripts/secrets.sh edit    prod|selfhost   open decrypted in $EDITOR, re-encrypt on save
#   ./scripts/secrets.sh view    prod|selfhost   print decrypted to stdout (careful)
#   ./scripts/secrets.sh env     selfhost        write .env for docker compose (gitignored)
#   ./scripts/secrets.sh helm    prod            write a decrypted Helm overlay to a temp path
#   ./scripts/secrets.sh rotate                  re-encrypt everything to current .sops.yaml keys
#   ./scripts/secrets.sh check                   verify every secret file decrypts
#
# Key location. SOPS looks in a platform-specific place and they differ:
#   Linux/macOS  ~/.config/sops/age/keys.txt
#   Windows      %AppData%\sops\age\keys.txt
# Set SOPS_AGE_KEY_FILE to override, or SOPS_AGE_KEY to pass the key inline (CI).

set -euo pipefail

cd "$(dirname "$0")/.."
SECRETS_DIR="infrastructure/secrets"

die() { echo "error: $*" >&2; exit 1; }

resolve() {
  case "${1:-}" in
    prod)     echo "$SECRETS_DIR/prod.enc.yaml" ;;
    selfhost) echo "$SECRETS_DIR/selfhost.enc.env" ;;
    *)        die "unknown environment '${1:-}' (expected: prod, selfhost)" ;;
  esac
}

require_key() {
  [ -n "${SOPS_AGE_KEY:-}" ] && return 0
  [ -n "${SOPS_AGE_KEY_FILE:-}" ] && [ -f "$SOPS_AGE_KEY_FILE" ] && return 0
  for p in "$HOME/.config/sops/age/keys.txt" "${APPDATA:-}/sops/age/keys.txt"; do
    [ -f "$p" ] && return 0
  done
  die "no age key found. Expected SOPS_AGE_KEY, SOPS_AGE_KEY_FILE, ~/.config/sops/age/keys.txt or %AppData%/sops/age/keys.txt"
}

cmd="${1:-}"; shift || true

case "$cmd" in
  edit)
    require_key; f=$(resolve "${1:-}"); exec sops "$f" ;;

  view)
    require_key; f=$(resolve "${1:-}"); exec sops --decrypt "$f" ;;

  env)
    require_key
    [ "${1:-}" = "selfhost" ] || die "env only applies to selfhost"
    sops --decrypt "$SECRETS_DIR/selfhost.enc.env" > .env
    chmod 600 .env 2>/dev/null || true
    echo "wrote .env (gitignored, chmod 600). Bring the stack up with:"
    echo "  docker compose -f docker-compose.selfhost.yml up -d"
    ;;

  helm)
    # Prints the path of a decrypted overlay. The caller owns deleting it —
    # deploy.yml traps EXIT so a failed deploy cannot leave plaintext behind.
    require_key
    [ "${1:-}" = "prod" ] || die "helm only applies to prod"
    out=$(mktemp -t wf-helm-XXXXXX.yaml)
    chmod 600 "$out" 2>/dev/null || true
    sops --decrypt "$SECRETS_DIR/prod.enc.yaml" > "$out"
    echo "$out"
    ;;

  rotate)
    require_key
    for f in "$SECRETS_DIR"/*.enc.*; do
      [ -e "$f" ] || continue
      sops updatekeys --yes "$f"
      echo "rotated recipients: $f"
    done
    ;;

  check)
    require_key
    rc=0
    for f in "$SECRETS_DIR"/*.enc.*; do
      [ -e "$f" ] || continue
      if sops --decrypt "$f" >/dev/null 2>&1; then
        echo "  ok      $f"
      else
        echo "  FAILED  $f"; rc=1
      fi
    done
    exit $rc
    ;;

  *)
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 1 ;;
esac
