# WeldForge launch playbook

Internal document. One-shot distribution events are limited — **don't waste
them**. This is the checklist + copy templates for each channel, the
recommended order, and what to measure.

---

## Before launch day — prerequisites

All of these must be true *before* you post anywhere:

- [ ] **README.md looks right** on the github.com repo page (check the
      rendered badges, that images resolve, that the quickstart actually
      works as written)
- [ ] **`https://www.weldforge.org` is up** — Friday-afternoon downtime is
      a launch killer
- [ ] **Status page live** at `status.weldforge.org` so a curious visitor
      can verify uptime history
- [ ] **Legal pages resolve** (TOS / Privacy / DPA at least as placeholder
      stubs referencing Termly — don't 404)
- [ ] **Email addresses route** — `christiaan@`, `sales@`, `support@`,
      `security@` all deliver to an inbox you actually check
- [ ] **GitHub issues enabled**, issue templates in place, "good first
      issue" label created
- [ ] **Sign-up flow works end-to-end** — even if just to Stripe test
      mode. A broken order form mid-launch is catastrophic
- [ ] **Analytics in place** — at minimum Plausible or Umami self-hosted
      to see traffic spikes and referrers in real time
- [ ] **You've personally done a 5-minute test** of the quickstart on a
      fresh machine (different laptop, fresh Docker install)

---

## Timing — what to post when

| When | Channel | Why |
|---|---|---|
| **Tuesday 7:30am PT / 4:30pm SAST** | Hacker News Show HN | Tues–Wed morning PT is consistently the best HN slot. Fri/weekend underperforms. |
| Same day, 9:00am PT / 6:00pm SAST | Reddit r/selfhosted | Pacific morning aligns with the sub's peak activity |
| Same day, 10:00am PT / 7:00pm SAST | Reddit r/devops + r/programming | Stagger by 60 min so each sub gets a separate peak |
| +1 day Wednesday 9:00am SAST | IndieHackers "Building" thread | IH audience is quieter but warmer — good for follow-up engagement |
| +2 days Thursday | LinkedIn technical post (CEO voice) | Drives B2B CTO awareness |
| +3 days Friday | X / Twitter thread (15 tweets) | Quote-tweet any HN/Reddit action from earlier |
| +1 week Monday | Dev.to + Hashnode cross-post of the launch blog post | Long-tail indexing |
| +2 weeks Monday | Product Hunt | Use HN success as PH social proof |

**Never combine Show HN and Product Hunt on the same day.** Both expect your
undivided attention for 12+ hours of replies; splitting focus halves the
outcome on both.

---

## Hacker News "Show HN"

### Title format

> `Show HN: WeldForge – open-source SAML + OIDC + SCIM + PKI, one binary`

**Title rules HN enforces (unofficially):**

- Under 80 chars. Ours is 69 — good.
- `Show HN:` prefix is mandatory. Not `Show HN -`, not `ShowHN:`.
- No trailing period.
- No "launch," "announcing," "introducing," "new" — editors will rewrite.
- No marketing adjectives ("powerful," "modern," "simple") — HN commenters
  eat them for breakfast.

### Alternative title variants (pick one, A/B is not possible)

1. `Show HN: WeldForge – open-source SAML + OIDC + SCIM + PKI, one binary`  ← recommended
2. `Show HN: WeldForge – Auth0 alternative with SAML IdP and PKI built in`
3. `Show HN: Self-hosted multi-tenant identity platform in one Spring Boot jar`

The first variant scores best because it front-loads the feature list and
says "one binary" which signals operational simplicity — HN readers value
that signal.

### URL

Point at `https://www.weldforge.org` (not the GitHub repo). Landing page
has the product pitch + social proof; the repo is one click away in the
nav. Post the GitHub link in your first comment instead.

### First comment (post yourself immediately after submission)

```
OP here. Quick context since the landing page doesn't say it:

This started as an internal identity platform for a multi-tenant SaaS
product and grew into its own thing. The design target was "how do we
get Auth0's feature set without Auth0's bill" — specifically the
combination of per-tenant OIDC issuer + SAML IdP + SCIM that usually
only shows up on Enterprise tiers.

Stack is Spring Boot 3.3.5 / Java 21 / Postgres / Angular. Tenant
isolation is application-layer, enforced at every DAO via a
TenantAccessor guard that also drives the audit log. BDD coverage is
134 scenarios / 819 steps; went through an independent security audit
in April.

Happy to answer anything on the architecture, the SAML IdP
implementation (OpenSAML 4 + tenant-owned signing keys), the PKI
integration (Bouncy Castle, per-tenant CA / CRL / OCSP), the payment
gateway abstraction (Strategy pattern, cheapest-wins routing), or the
"source-available not OSS" licence choice.

Source: https://github.com/weldforge-idp/weldforge
Pricing: https://www.weldforge.org/pricing.html
How we compare vs Auth0 / Keycloak / FusionAuth / Clerk (honestly):
https://www.weldforge.org/compare/

Not claiming this beats Keycloak / FusionAuth on maturity. It's a newer
entrant. The wedge is "every protocol in the base paid tier" plus POPIA-
native Cape Town residency.
```

### Things to expect in the comments

- **Licence question** — "is this open source?" Answer: no, source-available,
  here's why. Don't get defensive. Cite BSL / SSPL precedents (HashiCorp,
  MongoDB). Most HN readers respect the tradeoff if you're honest.
- **"Why not Keycloak?"** — point at `/compare/keycloak.html`. The TCO
  framing lands well.
- **"Why not Ory Hydra / Dex / Zitadel?"** — we haven't compared those yet.
  Answer honestly: Hydra is OAuth2-only; Dex is OIDC proxy; Zitadel is the
  closest real competitor and is genuinely good.
- **Security questions** — point at `SECURITY_AUDIT_2026-04-15.md`.
- **"But is this production-ready?"** — honest answer: yes, used internally
  since 2024, but you are an early external user and should expect friction.

### Reply discipline

- Reply to **every top-level comment** within the first 2 hours
- Stay on HN for at least 6 hours after posting, ideally 12
- Use the ShowHN + username on the post so commenters know you're here
- If someone finds a bug, thank them, open the issue yourself, close the
  loop in the comment
- **Never argue.** If someone says they prefer Keycloak — "totally fair,
  here's when we'd agree" — not "actually if you look at the TCO table…"

---

## Reddit

### r/selfhosted (820K+ members)

**Title:** `WeldForge — multi-tenant SSO, OIDC, SAML, SCIM, PKI in one container`

**Body (lead with the self-host story):**

```
Built this over the last couple of years as an internal identity platform
for a multi-tenant SaaS and got tired of paying Auth0 bills, so I
open-sourced the backend. Self-host tier is free and unlimited forever.

What's in the box:
- OAuth2/OIDC issuer per tenant (own signing keys)
- SAML 2.0 as both SP and IdP
- SCIM 2.0 inbound + outbound
- MFA: TOTP, WebAuthn, SMS, backup codes
- Internal PKI per tenant (CA, CRL, OCSP, client certs for mTLS)
- HMAC-signed audit webhooks with retry queue
- Scoped API keys (path + method restrictions)
- LDAP/AD upstream federation with break-glass fallback

Runs as one Spring Boot jar + Postgres. Docker Compose for dev, K8s
manifests under infrastructure/ for production. 134 Cucumber scenarios
in the repo. Went through an independent security audit in April 2026
(report in the repo).

Source: github.com/weldforge-idp/weldforge
Docs: weldforge.org
Honest comparison vs Keycloak: weldforge.org/compare/keycloak.html
  (short version: keep using Keycloak if it works for you)
```

### r/devops (450K+ members)

**Title:** `WeldForge — self-hosted identity platform with built-in PKI, HMAC audit webhooks, SCIM (Java/Spring Boot)`

**Body:** Focus on the **operational** angle — upgrade path, scaling,
observability, circuit breakers, Flyway-managed schema.

### r/programming (6M+ members)

**Title:** `Source-available Auth0 alternative in Spring Boot — SAML IdP, OIDC, SCIM, PKI in one binary`

**Body:** Lean technical. Show the Strategy-pattern payment-gateway
architecture diagram and the BDD test coverage.

### r/opensource

Be honest about source-available vs OSS from the first line. This sub
will call you out otherwise, rightfully.

### r/SaaS (400K+ members)

Focus on the **pricing transparency** angle — post the cost calculator.

### r/southafrica (500K+ members)

**Title:** `Built an identity platform in Cape Town — looking for ZA SaaS teams with POPIA constraints`

Lead with the POPIA-native hosting angle. Mention it's Cape Town-built.
**Do not** cross-post the same copy as r/devops — local audience wants
local story.

### Subreddit timing rule

**Post to one sub per hour at most** on launch day. Reddit's algorithm
punishes cross-posts that look spammy. Stagger.

### If your post gets removed by a sub's mod

Don't argue in modmail. Accept, learn the sub's rules, re-post in 48
hours with the violation fixed.

---

## Product Hunt

### Timing

Launch **Tuesday** for maximum first-24-hours velocity. PH day starts at
12:01am PT.

### Title

`WeldForge — Multi-tenant identity platform, one binary`

### Tagline

`Open-source SAML + OIDC + SCIM + PKI. Self-host free or hosted from $29/mo.`

### Gallery

Required — PH rewards rich submissions. Prepare in advance:

1. Hero screenshot — admin portal dashboard
2. Architecture diagram (same one from the README)
3. SAML IdP metadata endpoint screenshot
4. Cost calculator screenshot
5. BDD test output (terminal screencap)
6. 30-second demo video — record in Loom, upload to Vimeo/YouTube unlisted

### Launch-day routine

- **Midnight PT**: post
- **First hour**: ping every personal contact who has a PH account to
  vote — honestly, don't ask for upvotes from people who won't actually
  use the product
- **Throughout the day**: reply to every comment within 15 minutes
- **5pm PT**: most-voted-of-day is typically decided by this point
- **Next day**: thank-you post with screenshot of final position

### What "success" looks like on PH

Top-5-of-day = front-page sidebar for a week + "Featured on Product Hunt"
badge you can use on your site for years. That's the actual prize; raw
vote count matters less.

---

## IndieHackers

### Thread 1: the "building in public" post

Title: `I built a self-hosted Auth0 alternative as a solo founder — here's what I learned about pricing`

Content: Focus on the *business* journey. Pricing strategy, competition,
POPIA angle, the decision to go source-available. IH audience is other
bootstrapped founders; they resonate with story, not features.

### Thread 2: the "launch" post in #launch

Post 24 hours after HN. Link to the HN thread. IH has a built-in "if HN
liked it, we probably will too" heuristic.

---

## LinkedIn

### Target audience

CTOs, VP Engineering, Platform Engineering leads at companies 50–500
people. This is the B2B awareness play, not the dev-relations play.

### Post structure

```
We built our own identity platform instead of paying Auth0 six figures.

Here's what that cost us — and what we learned.

[paragraph on why we built it]
[paragraph on what's in it]
[paragraph on the POPIA / ZA residency angle]
[paragraph on the "it's open to your team now" pivot]

Full story: [link to weldforge.org]
Source: [link to repo]
Honest comparison vs Auth0: [link to compare/auth0.html]

#identity #sso #saml #saas #opensource #southafrica
```

### Cadence

Post weekly for the first month, dropping to fortnightly after. Each post
a single technical angle — the PKI integration, the multi-tenancy model,
the SAML IdP implementation.

---

## X / Twitter

### Thread 1 (launch-week)

```
1/ We built an identity platform that does everything Auth0 charges
Enterprise tier money for, in one binary, source-available. Here's the
breakdown. 🧵

2/ [per-tenant OIDC + SAML IdP — what most IdPs won't give you under $1500/mo]

3/ [built-in PKI — most alternatives don't ship this at all]

4/ [the multi-tenant architecture — one Postgres, tenant-scoped queries]

5/ [the price table — honest where we lose vs FusionAuth at scale]

6/ [the self-host story — free forever, we're betting on the upgrade path]

7/ Source: github.com/weldforge-idp/weldforge
   Docs: weldforge.org
   Compare honestly vs the big four: weldforge.org/compare/
```

### Engagement rule

Reply to every reply in the first hour. Quote-tweet any thoughtful
criticism with your answer. Never block unless clearly a bot.

---

## Dev.to + Hashnode

### Cross-post template

Title: `Building a multi-tenant identity platform in Java: SAML IdP, PKI, and why we chose source-available`

Include canonical link back to `weldforge.org/blog/first-post` (once the
blog exists).

Dev.to likes a "lessons learned" angle. Hashnode rewards depth and code
samples. Same copy, reformatted headings for each platform.

### Tags

- Dev.to: `#java`, `#saml`, `#identity`, `#opensource`, `#spring`
- Hashnode: `#java`, `#spring-boot`, `#oauth2`, `#saml`, `#identity-management`

---

## Local ZA channels

### MyBroadband

Email the editor with a specific pitch: "Cape Town engineer builds
POPIA-native identity platform, open-sources it." Include a 200-word
summary + 2 images + contact details. MyBroadband runs local dev stories
when the angle is clear.

**Contact:** editor@mybroadband.co.za

### ITWeb

Business-oriented. Pitch as "South African SaaS alternative to Auth0 /
Okta for local POPIA compliance." Longer angle, more corporate tone.

**Contact:** editor@itweb.co.za

### Silicon Cape Slack

Post in `#announcements` — quick, founder-to-founder tone. Share the
story more than the product.

### Startup Grind Cape Town meetup

Apply to speak at a future event once you have a customer case study.
Lead time: 3–6 months.

---

## Metrics to watch during launch

### Real-time (first 24 hours)

- **Plausible/Umami**: sessions per hour, top referrers, top pages
- **GitHub stars**: chart the velocity — 50+/hour on HN front page, 5–10/hour
  on r/selfhosted front page
- **Sign-up rate on /order.html**: how many form submissions convert to
  checkout
- **Support inbox**: monitor `christiaan@` for the "does this work with
  X?" questions

### Week 1

- **Newsletter / account signups**
- **GitHub issues opened**: volume + sentiment signal quality of response
- **Reddit / HN comment quality**: track the thoughtful ones, reply to all

### Week 4

- **Organic search traffic**: is Google indexing the comparison pages?
- **`llms.txt` hits in access logs**: are AI crawlers (GPTBot, ClaudeBot,
  PerplexityBot) fetching?
- **Referrer mix**: HN fades quickly; what's still driving traffic after
  the spike flattens?

---

## What to do post-launch

### Week 1

- Write a retrospective post: "What we learned launching WeldForge"
- Publish on weldforge.org/blog + Dev.to + Hashnode
- Include: what worked, what didn't, what surprised us, metrics

### Month 1

- Ship any high-signal feature request from launch-day comments
- Add a "Featured on HN" or "Featured on Product Hunt" badge to the homepage
- Start writing the weekly technical blog post

### Month 3

- If sign-up numbers justify it, run one targeted ad campaign — Google
  Ads on "Auth0 pricing" / "Keycloak alternative" keywords. $500/mo to
  test signal.

---

## What NOT to do

- **Don't post to HN a second time within 30 days** of the first attempt.
  The second "Show HN" gets buried unless the product has materially
  changed.
- **Don't buy upvotes or sock-puppet comments** on any channel. All of
  them detect it, all of them ban for it, and the one time you get
  caught kills the brand permanently.
- **Don't paste the same post body to every subreddit.** Each sub has
  its own rhythm and moderator. Tailor at least the opening paragraph.
- **Don't respond to hostile comments with the pricing page.** If
  someone doesn't want to pay, arguing with them on a public forum is
  a losing move. Thank them for the feedback, move on.
- **Don't promise features in the comments.** "This will be in the next
  release" becomes a commitment you have to ship. If you want to signal
  interest, say "good idea, adding to the roadmap issue" and link to
  the GitHub issue.
- **Don't pretend you don't have competitors.** The comparison pages are
  the antidote — link them constantly.

---

## Emergency checklist — if something goes wrong

- **Site goes down mid-HN launch**: post immediate comment "Site down, we
  hit the HN hug of death, back in 10." Failover to a static cached
  version served from GitHub Pages or Cloudflare.
- **Critical bug discovered**: thank the reporter publicly, push a fix
  same-day if possible, pin a comment with the workaround in the meantime.
- **Aggressive competitor response**: if a Clerk / FusionAuth / Auth0
  person shows up in the thread, reply professionally, acknowledge where
  they're right, point at the honest-comparison sections. Don't punch
  down, don't pretend they don't have a point.

---

<div align="center">
<sub>WeldForge launch playbook — keep this updated as lessons accumulate.</sub>
</div>
