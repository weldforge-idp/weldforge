# Secrets — SOPS + age

Every secret WeldForge needs is committed to this repository **encrypted**, under
`infrastructure/secrets/`. Nothing is stored in plaintext, and no external secret
store is required to deploy.

That last point is the reason this exists. Secrets used to be read from **GCP
Secret Manager** at deploy time, which meant two things: the deploy could not run
without a live GCP project, and self-hosters had no equivalent at all — they were
told to hand-fill a `.env` and left to it. When the GCP estate went away, the
production secret path went with it. SOPS moves the secrets into the repo, where
they travel with the code and work identically on GKE, on a self-hosted cluster,
or on a laptop.

## What is encrypted

| File | Used by | Contents |
|---|---|---|
| `infrastructure/secrets/prod.enc.yaml` | Helm, as a values overlay | `api.secrets.*`, `mail.password` |
| `infrastructure/secrets/selfhost.enc.env` | `docker-compose.selfhost.yml` | the full self-host dotenv |

The `.enc.yaml` file uses `encrypted_regex`, so **structure stays readable and
only the values are ciphertext**. A reviewer can see which keys exist and which
environment a file belongs to without being able to read a single value — which
keeps diffs meaningful instead of an opaque blob changing wholesale.

## One-time setup

**1. Get an age key.** If you do not have one:

```bash
age-keygen -o ~/.config/sops/age/keys.txt   # Linux/macOS
chmod 600 ~/.config/sops/age/keys.txt
```

On **Windows**, SOPS looks in `%AppData%\sops\age\keys.txt` instead — not
`~/.config`. If you keep the Unix path, either copy the file to the Windows
location or set `SOPS_AGE_KEY_FILE`. This is a common first stumble; the symptom
is `no age identity found in ...` on decrypt while encryption works fine.

**2. Get yourself added as a recipient.** Send your **public** key (the
`age1...` line, safe to share) to an existing operator. They add it to
`.sops.yaml` and run `./scripts/secrets.sh rotate`.

## Daily use

```bash
./scripts/secrets.sh check              # verify every secret file decrypts
./scripts/secrets.sh edit prod          # open decrypted in $EDITOR, re-encrypt on save
./scripts/secrets.sh view selfhost      # print decrypted to stdout
./scripts/secrets.sh env selfhost       # write .env for docker compose (gitignored)
./scripts/secrets.sh rotate             # re-encrypt to the current .sops.yaml recipients
```

**Never** decrypt into a file inside the repo and edit that. Use `edit`, which
decrypts to a temp file, opens your editor, and re-encrypts on save. `.gitignore`
covers `*.dec.*` as a backstop, but the habit is what actually protects you.

## Self-hosting

```bash
./scripts/secrets.sh env selfhost
docker compose -f docker-compose.selfhost.yml up -d
```

Self-hosters who are not recipients of this repo's key cannot decrypt these files
— nor should they. Copy `.env.selfhost.example`, generate your own values, and
optionally encrypt them to your own age key using the same `.sops.yaml` pattern.

## Deploys

`deploy-gcp.yml` decrypts `prod.enc.yaml` into a `mktemp` file (mode 600) and
passes it to `helm -f`. The file is shredded by a trap on `EXIT`, so a failed
deploy cannot leave plaintext on the runner. Values never pass through step
outputs or get echoed, so nothing reaches the workflow log even without masking.

CI needs the age **private** key as the `SOPS_AGE_KEY` repository secret:

```
Settings -> Secrets and variables -> Actions -> New repository secret
Name:  SOPS_AGE_KEY
Value: the AGE-SECRET-KEY-1... line from your keys.txt
```

## Rotating

**Adding or removing a recipient** is `.sops.yaml` plus `./scripts/secrets.sh rotate`.

Be clear about what that does and does not achieve: it changes who can decrypt
the file **going forward**. It does nothing about git history. Anyone who was a
recipient before can still decrypt every historical version of these files from
any clone they hold. **Removing an operator therefore means rotating the secret
values themselves** — new database password, new JWT secret — not just editing
the recipient list.

`APP_CRYPTO_SECRET` is the exception that cannot simply be rotated: it encrypts
data at rest, so changing it makes previously stored secrets undecryptable.
Rotating it is a data migration, not a config change.

## If a secret leaks

Treat committed-then-deleted secrets as compromised — deletion does not remove
them from history, and anyone with a clone has them. Rotate the value, then
consider whether history needs rewriting (`git filter-repo`, BFG). Do that
**before** a repository is made public, not after: clones, forks and search
caches survive re-privatisation.
