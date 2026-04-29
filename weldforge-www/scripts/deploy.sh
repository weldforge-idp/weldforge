#!/usr/bin/env bash
# ============================================================
# WeldForge marketing site deployer.
#
# Uploads everything under weldforge-www/public/ to the
# Xneelo shared-hosting web root.
#
# ---- SECURITY CONTEXT ----
# The current host (weldforge.org on Xneelo shared hosting)
# does not expose SSH/SFTP and rejects AUTH TLS on its FTP
# control channel. The only working transport is plain FTP
# on port 21 — credentials travel in cleartext.
#
# This is an informed tradeoff: the site content is public
# marketing copy (no user data, no secrets), the FTP password
# is scoped to one disposable account that cannot touch
# anything else, and the only realistic alternatives are
# (a) upgrading to a plan with SSH, or (b) migrating to
# Cloudflare Pages / Netlify / S3+CloudFront.
#
# If you ever migrate to a host that offers SFTP, drop the
# --insecure-ftp flag and the script will use SFTP
# automatically without any other change.
#
# ---- Transport modes ----
#   SFTP (default)     — used when the deploy pipeline ships
#                        to a host that accepts it.
#   Plain FTP          — opted into with --insecure-ftp or
#                        INSECURE_FTP=1. This is the mode
#                        TeamCity uses for weldforge.org.
#
# ---- Credentials ----
# Environment variables set by the CI runner:
#   SFTP_HOST, SFTP_USER
#   SFTP_KEY    (path to SSH private key)  — SFTP mode only
#   SFTP_PASS   (password)                 — SFTP or FTP mode
#   SFTP_DIR    (remote root, default /)
#
# Or an .env.local file at the repository root (for local dev):
#   SERVER_ADDRESS, USERNAME, PASSWORD, REMOTE_DIR
#
# ---- Usage ----
#   ./scripts/deploy.sh                 # deploy over SFTP
#   ./scripts/deploy.sh --insecure-ftp  # deploy over plain FTP
#   ./scripts/deploy.sh --dry-run       # list what *would* upload
# ============================================================
set -euo pipefail

DRY_RUN=0
INSECURE_FTP=${INSECURE_FTP:-0}
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n)    DRY_RUN=1 ;;
        --insecure-ftp)  INSECURE_FTP=1 ;;
        --help|-h)
            sed -n '2,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "deploy: unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SITE_DIR="$( cd "$SCRIPT_DIR/.." && pwd )/public"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

if [[ ! -d "$SITE_DIR" ]]; then
    echo "deploy: site directory not found at $SITE_DIR" >&2
    exit 1
fi

# ---- Load credentials -------------------------------------------

# Back-fill from .env.local — that file uses the legacy FTP keys
# so we map them across. The awk parse handles either KEY=value
# or the whitespace-padded form (KEY = value) that vi tends to
# produce.
if [[ -z "${SFTP_HOST:-}" && -f "$REPO_ROOT/.env.local" ]]; then
    SFTP_HOST=${SFTP_HOST:-$(awk -F= '/^SERVER_ADDRESS/ {sub(/^[^=]*= */,""); gsub(/^[ \t]+|[ \t]+$/,""); print}' "$REPO_ROOT/.env.local")}
    SFTP_USER=${SFTP_USER:-$(awk -F= '/^USERNAME/       {sub(/^[^=]*= */,""); gsub(/^[ \t]+|[ \t]+$/,""); print}' "$REPO_ROOT/.env.local")}
    SFTP_PASS=${SFTP_PASS:-$(awk -F= '/^PASSWORD/       {sub(/^[^=]*= */,""); gsub(/^[ \t]+|[ \t]+$/,""); print}' "$REPO_ROOT/.env.local")}
    SFTP_DIR=${SFTP_DIR:-$( awk -F= '/^REMOTE_DIR/     {sub(/^[^=]*= */,""); gsub(/^[ \t]+|[ \t]+$/,""); print}' "$REPO_ROOT/.env.local")}
fi

: "${SFTP_HOST:?SFTP_HOST is required (set env or put SERVER_ADDRESS in .env.local)}"
: "${SFTP_USER:?SFTP_USER is required (set env or put USERNAME in .env.local)}"
: "${SFTP_DIR:=/}"

# Xneelo drops the account straight into its web root. The
# /public_html/ REMOTE_DIR label in the supplied .env.local is
# cosmetic — the server denies CWD on it. Coerce to /.
if [[ "$SFTP_DIR" == "/public_html/" || "$SFTP_DIR" == "/public_html" ]]; then
    SFTP_DIR="/"
fi

echo "deploy: host=$SFTP_HOST user=$SFTP_USER dir=$SFTP_DIR site=$SITE_DIR"

# ---- Enumerate files --------------------------------------------

cd "$SITE_DIR"
mapfile -t FILES < <(find . -type f -not -name '.DS_Store' | sed 's|^\./||' | sort)
if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "deploy: no files found under $SITE_DIR" >&2
    exit 1
fi
echo "deploy: ${#FILES[@]} files to transfer"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "deploy: DRY RUN — no upload"
    printf '  %s\n' "${FILES[@]}"
    exit 0
fi

# ---- SFTP path (preferred) --------------------------------------

deploy_sftp() {
    local ssh_common_opts=(
        -o StrictHostKeyChecking=accept-new
        -o UserKnownHostsFile="$HOME/.ssh/known_hosts"
        -o ConnectTimeout=15
        -o ServerAliveInterval=30
        -o PreferredAuthentications=publickey,password,keyboard-interactive
    )

    # Pick an auth mode. Key is preferred; password is the fallback
    # only if explicitly set. An unset SFTP_KEY + unset SFTP_PASS
    # means "try the agent".
    local sftp_cmd=(sftp)
    if [[ -n "${SFTP_KEY:-}" ]]; then
        if [[ ! -r "$SFTP_KEY" ]]; then
            echo "deploy: SFTP_KEY=$SFTP_KEY is not readable" >&2
            exit 1
        fi
        echo "deploy: auth=publickey ($SFTP_KEY)"
        ssh_common_opts+=(-i "$SFTP_KEY" -o IdentitiesOnly=yes -o PubkeyAuthentication=yes -o PasswordAuthentication=no)
    elif [[ -n "${SFTP_PASS:-}" ]]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "deploy: sshpass is required for password SFTP. Install it or use SFTP_KEY." >&2
            exit 1
        fi
        echo "deploy: auth=password (sshpass)"
        sftp_cmd=(sshpass -p "$SFTP_PASS" sftp)
        ssh_common_opts+=(-o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)
    else
        echo "deploy: auth=agent (no SFTP_KEY or SFTP_PASS set)"
    fi

    # Build the SFTP batch. -b - reads commands from stdin, which
    # keeps the password out of process args and makes the whole
    # thing restartable.
    local batch
    batch=$(mktemp)
    trap 'rm -f "$batch"' EXIT

    {
        echo "cd ${SFTP_DIR%/}"
        # Ensure subdirectories exist. We only have one flat public/
        # right now, but this keeps the script honest for the future.
        local seen_dirs=()
        for rel in "${FILES[@]}"; do
            local dir
            dir=$(dirname "$rel")
            if [[ "$dir" != "." ]] && [[ ! " ${seen_dirs[*]} " =~ " $dir " ]]; then
                echo "-mkdir $dir"      # leading - ignores "already exists"
                seen_dirs+=("$dir")
            fi
        done
        for rel in "${FILES[@]}"; do
            echo "put \"$rel\" \"$rel\""
        done
        echo "bye"
    } > "$batch"

    echo "deploy: opening SFTP session..."
    if ! "${sftp_cmd[@]}" "${ssh_common_opts[@]}" -b "$batch" "$SFTP_USER@$SFTP_HOST"; then
        cat <<'HINT' >&2

deploy: SFTP transfer FAILED.

If the failure was "Permission denied (password)" the most likely
cause is that SSH access is not enabled on this Xneelo account, or
the account is configured for key-based auth only. Fixes:

  1. In the Xneelo control panel (konsoleH), open the hosting
     account and look for "Shell / SSH Access". Activate it and
     set the SSH password; then set SFTP_PASS to the new password.
  2. Or, generate an SSH keypair locally, upload the public key
     via the konsoleH "SSH keys" page, and run this script with
     SFTP_KEY=/path/to/private_key.

Until one of those is done, re-run with --insecure-ftp to fall
back to plain FTP on port 21 (credentials travel in the clear —
not recommended for anything but a one-off smoke test).
HINT
        exit 1
    fi
    echo "deploy: SFTP transfer complete ✓"
}

# ---- Plain FTP fallback -----------------------------------------

deploy_ftp() {
    if [[ -z "${SFTP_PASS:-}" ]]; then
        echo "deploy: FTP fallback requires SFTP_PASS (or PASSWORD in .env.local)" >&2
        exit 1
    fi
    echo "deploy: using PLAIN FTP (credentials in cleartext)"
    local uploaded=0 failed=0
    for rel in "${FILES[@]}"; do
        local remote="ftp://$SFTP_HOST${SFTP_DIR%/}/$rel"
        if curl -sS --connect-timeout 15 --max-time 120 \
                --ftp-pasv --ftp-create-dirs \
                -u "$SFTP_USER:$SFTP_PASS" \
                -T "$rel" "$remote"; then
            printf '  ✓ %s\n' "$rel"
            uploaded=$((uploaded + 1))
        else
            printf '  ✗ %s\n' "$rel" >&2
            failed=$((failed + 1))
        fi
    done
    echo "deploy: uploaded=$uploaded failed=$failed"
    [[ "$failed" -eq 0 ]]
}

# ---- Transport selection ----------------------------------------

if [[ "$INSECURE_FTP" -eq 1 ]]; then
    deploy_ftp
else
    deploy_sftp
fi

