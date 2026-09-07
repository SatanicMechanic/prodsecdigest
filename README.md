# n2ksecdigest

> **This repo is a template and does not run.** Every scheduled workflow is gated off this repository; the bot only starts working once you mirror it and configure your own copy ([§3](#3-stack-description-and-why-you-want-a-private-fork)). `stack.txt` and `feeds.md` ship as starter content for you to replace.

Automated product-security news digest. Runs on GitHub Actions twice each weekday, fetches from RSS and web search, triages through any OpenAI-compatible LLM provider (**GitHub Models by default — no third-party account needed**; presets also cover xAI, Mistral, OpenAI, Groq, OpenRouter, Together, DeepSeek, and Ollama, and you pick the model) against a **news-cycle fire-tier bar**, and emails a short digest via Resend.

## Should you actually use this?

For most security engineers, **a well-tuned set of Google News Alerts is the right answer.** A few queries like `"actively exploited" CVE`, `"emergency patch" zero-day`, `"CISA emergency directive"`, `"supply chain compromise" malicious package`, plus vendor-specific terms for your stack, will hit most of the same articles this bot's web-search pass surfaces — for free, with zero maintenance, and no LLM API spend. The cost: significantly more noise (Patch Tuesday recaps, trailing coverage, vendor PR, out-of-scope vulnerabilities) and the same article arriving from 5 different sources. You triage that pile yourself, every day.

The reason to fork this instead is if you specifically want:

- **The LLM applying the editorial bar**, not you. SKIP-default: no email unless something clears the bar — in practice an email arrives a bit more than half of days, almost always with a single item.
- **Stack-aware scope filtering.** "Cisco out of scope" and "Microsoft = Windows Server only" don't have to live in your head.
- **Synthesis, not headlines.** Each item arrives as a rewritten headline + "why this matters to your stack" + "action to take" — 30 seconds of decision, not 5 minutes of reading.
- **Aggressive dedup + state.** Trailing coverage doesn't recycle for weeks; sent items are suppressed for 30 days.

If you're willing to spend 5 minutes a day skimming headlines, Google Alerts wins. If you want 0 minutes of triage at the cost of an LLM doing it on a schedule, this might be worth the setup.

## Design principle

The reader already has vulnerability scanners, SCA, CNAPP, and dependency-alert pipelines. This bot is **not** a scanner front-end. It does not enrich with KEV or EPSS. It does not surface newly-disclosed CVEs, Patch Tuesday roundups, or high-CVSS findings in isolation — those are scanner territory.

What it surfaces falls into three categories, each held to the same SKIP-preferred bar:

1. **Fire-tier security news** — active mass exploitation, emergency/out-of-cycle advisories, unfolding supply chain compromises, multiple independent sources converging on the same story with urgent framing. Signal the news cycle produces; not signal a catalog produces.

2. **Platform and tooling developments** — notable new capabilities in your stack (cloud, CI/CD, runtimes, security platforms) and noteworthy new open-source security tooling relevant to CI/CD, container security, dependency management, code security, or monitoring. Things worth awareness today, not just eventually.

3. **Compliance and policy changes** — substantive regulatory or policy shifts affecting SaaS and software vendors that a product-security team should be aware of.

Typical output: **0–2 items per day**, delivered as an email a bit more than half of days. SKIP is the default on quiet days; 3 items is rare.

### Where it fits alongside weekly newsletters

This bot is complementary to — not a replacement for — weekly digests like [SANS NewsBites](https://www.sans.org/newsletters/newsbites/) and [tl;dr sec](https://tldrsec.com/). Those give you breadth, analysis, and tooling round-ups on a weekly cadence; this bot covers the narrow gap they can't: **same-day notice of the handful of events that shouldn't wait for Friday** — active exploitation of something in your stack, an emergency advisory, an unfolding supply-chain compromise. Read the newsletters for depth; let this interrupt you only when the news cycle says now.

## Pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│  1. RSS fetch        round-robin across FEEDS, per-feed cap,             │
│                      blocklist filter, state/cooldown filter             │
│                                                                          │
│  2. Query gen        LLM generates 1 anchored + 5 independent +          │
│                      1 tooling-scan + 1 ai-lab; on the Monday catch-up   │
│                      run also 1 compliance + 1 PQC (slow-moving beats,   │
│                      weekly-only to avoid daily backfill noise)          │
│                                                                          │
│  3. Brave Search     executes queries (fewer results fetched for the     │
│                      backfill-prone abstract query types), dedupes       │
│                      against RSS pool                                    │
│                                                                          │
│  4. Triage           two parallel LLM calls:                             │
│                        • prompt_threat.txt — fire-tier bar (threats +    │
│                          compliance + TTP residual)                      │
│                        • prompt_tooling.txt — tooling bar (platform,     │
│                          CI/CD, OSS features, ≤1 item)                   │
│                      results merged with URL-dedup, global cap of 3      │
│                                                                          │
│  5. Enrich           fetch each selected article (≤3), LLM sharpens      │
│                      why/action with full text; best-effort, falls       │
│                      back to triage-time fields on any failure           │
│                                                                          │
│  6. Render + send    HTML (escaped) + plain-text body, severity-aware    │
│                      subject line, delivered via Resend (+ optional      │
│                      Slack webhook)                                      │
│                                                                          │
│  7. Persist state    sent URLs → 30-day suppression                      │
│                      candidate URLs → 5-day cooldown                     │
└──────────────────────────────────────────────────────────────────────────┘
```

## Module layout

| File             | Purpose |
|------------------|---------|
| `config.py`      | Feeds, tuning constants, blocklists, TTLs |
| `digest.py`      | Orchestrator (entrypoint: `python digest.py`) |
| `fetchers.py`    | RSS + Brave Search |
| `state.py`       | URL normalization, sent/candidate state persistence |
| `llm.py`         | Single OpenAI-compatible provider client, query gen, triage parsing |
| `render.py`      | HTML (escaped) + plain-text rendering, subject line |
| `mailer.py`      | Resend delivery |
| `slack.py`       | Optional Slack webhook notification |
| `prompt_threat.txt` | Threat/compliance triage prompt (fire-tier bar) |
| `prompt_tooling.txt` | Tooling triage prompt (platform/CI/CD/OSS-tool bar) |
| `prompt_slow_queries.txt` | Compliance + PQC query-generation prompt |
| `stack.txt` | Stack description injected into prompts (generic template here; real one in your private fork) |
| `feeds.md` | RSS feed list (markdown links, parsed at import; starter set here — repopulate for your stack) |
| `security-news.goggle` | Brave goggle boosting curated security sources (opt-in via `BRAVE_GOGGLES`) |
| `check_feeds.py` | Feed health check (standalone) |
| `tests/`         | pytest suite |

## Security model

Two invariants hold the untrusted-input boundary. Both are easy to break by accident, so keep them in mind when changing the pipeline:

- **Feed articles and Brave search results are untrusted external content.** When passing them into LLM prompts, treat them as data only — never structure a prompt so article content can override system or user instructions. In `llm.py` the fetched text is fenced and explicitly labelled as untrusted before it reaches the model.
- **LLM output is rendered into HTML email.** Escape all model output before inserting it into HTML templates; never trust it as safe markup. `render.py` escapes on the way in, and `tests/` covers it.

Two related boundaries worth knowing: outbound article fetches are restricted to public hosts (`_is_public_host` in `fetchers.py`) so a malicious link can't pull an internal address, and `security-news.goggle` must stay generic — Brave fetches it over the public internet, so it must never encode hints about your stack.

## Setup

**This repo is a template and is inert.** `digest.yml`, `check_feeds.yml`, and `sync-upstream.yml` are all gated on `github.repository != 'SatanicMechanic/n2ksecdigest'`, so nothing scheduled runs here at all. They activate automatically in your fork or private mirror.

**Which means: in your copy they start running on GitHub's schedule immediately**, using *your* repo's secrets — that's by design (§3 below is written for you). Until you finish this Setup section, `digest.yml` fails fast on every scheduled run (deliberately — it refuses to run without a `stack.txt` and an `LLM_MODEL`; see [§3](#3-stack-description-and-why-you-want-a-private-fork)). If you're not ready to configure it yet, disable Actions under Settings → Actions until you are; otherwise GitHub auto-disables a fork's scheduled workflows after 60 days with no repo activity.

### 1. Clone and install

Requires [uv](https://docs.astral.sh/uv/) — replaces `pip` + `venv`. Install with `curl -LsSf https://astral.sh/uv/install.sh | sh` or your platform's package manager.

```
git clone git@github.com:SatanicMechanic/n2ksecdigest.git
cd n2ksecdigest
uv venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements.txt -r requirements-dev.txt
```

Dependencies are compiled, not floor-pinned: edit the `.in` files (direct deps, `>=`) and regenerate the fully-pinned `.txt` files that CI actually installs, so transitive packages can't float to a new release mid-run.

```
uv pip compile requirements.in     -o requirements.txt     --python-version 3.12
uv pip compile requirements-dev.in -o requirements-dev.txt --python-version 3.12 -c requirements.txt
```

### 2. Environment (local runs only)

Copy `.env.example` → `.env` and fill in the values below. This file is for running on your machine — CI reads the same values from repo secrets/variables (§4), never from `.env`.

| Variable            | Source | Required? |
|---------------------|--------|-----------|
| `GH_MODELS_TOKEN`   | Fine-grained PAT with `models:read` — the default provider's key | Yes, unless `LLM_PROVIDER` points elsewhere |
| `LLM_PROVIDER`      | One of `github`, `xai`, `mistral`, `openai`, `groq`, `openrouter`, `together`, `deepseek`, `ollama` (default `github`) | No |
| `LLM_MODEL`         | Model id for that provider, e.g. `openai/gpt-4.1-nano`, `grok-4.5`. **No default by design** — see [Choosing a model](#choosing-a-model) | **Yes** |
| `LLM_BASE_URL`      | Only for a provider not in the table — any OpenAI-compatible base URL | No |
| `LLM_API_KEY_ENV`   | Only for a provider not in the table — name of the env var holding its key | No |
| `LLM_EXTRA`         | JSON merged into the request body. Defaults per provider — `{}` for `github`, `{"reasoning_effort": "low"}` for `xai` | No |
| `RESEND_API_KEY`    | Resend dashboard | Yes |
| `DIGEST_TO_EMAIL`   | Comma-separated recipient list | Yes |
| `DIGEST_FROM_EMAIL` | Verified domain in Resend | Yes |
| `BRAVE_API_KEY`     | Brave Search API (free tier: 2K queries/month) | **Strongly recommended** — without it the web-search pass is a no-op |
| `SLACK_WEBHOOK_URL` | Slack app's [Incoming Webhooks](https://api.slack.com/messaging/webhooks) page | No — when set, the plain-text digest is also posted to that channel; unset = Slack step is a no-op |

Set `LLM_PROVIDER` to something other than `github` and that provider's own key becomes the required one instead of `GH_MODELS_TOKEN` — `XAI_API_KEY` for `xai`, `MISTRAL_API_KEY` for `mistral`, and so on (the mapping is `config.PROVIDERS`). Only one LLM key is ever needed.

#### Choosing a model

`LLM_MODEL` has **no built-in default and is required**. That is deliberate: provider base URLs and key env vars are stable infrastructure and keep their defaults, but model ids churn constantly (`grok-4.5` → `grok-5` → …). A default baked into the code makes every model release a code change, a commit, and a sync to every private mirror. Requiring it means upgrading is editing one repo variable.

The trade-off: the bot **fails fast at startup** if `LLM_MODEL` is unset, rather than quietly running a model you didn't choose.

```
LLM_MODEL is required (provider 'github'). Set it to the model id you want to run —
it has no built-in default so that switching models is a config change, not a
code change.
```

Pick whatever your provider currently offers — `openai/gpt-4.1-nano` or a larger GitHub-hosted model for `github`, `grok-4.5` for xAI, `mistral-large-latest` for Mistral.

### 3. Stack description (and why you want a private fork)

The triage and query-generation prompts inject a description of your infrastructure (`stack.txt`) so the LLM can apply relevance and scope-filtering rules. The version committed to this repo is a **generic template** — the bot runs with it, but the digest is only useful once `stack.txt` describes *your* stack.

A real stack description is reconnaissance gold: products, cloud providers, base images, security tooling, scope carve-outs. **Don't commit yours to a public repo.** The intended setup is a private mirror:

```
# GitHub can't make a private fork of a public repo, so mirror instead:
git clone --bare git@github.com:SatanicMechanic/n2ksecdigest.git
cd n2ksecdigest.git
git push --mirror git@github.com:YOU/your-private-repo.git
cd .. && rm -rf n2ksecdigest.git

git clone git@github.com:YOU/your-private-repo.git
cd your-private-repo
git remote add upstream git@github.com:SatanicMechanic/n2ksecdigest.git
```

Then edit `stack.txt` with your real stack and commit — in the private repo this is safe and is the single source of truth for both local runs and CI. To pull upstream updates (dependency bumps, Actions pin bumps), either run `git fetch upstream && git merge upstream/main` manually, or rely on the included `sync-upstream.yml` workflow: it merges upstream weekly, runs the test suite as a gate, and pushes only if green (inert on this public repo; active in your mirror). One setup note: the built-in Actions token cannot push changes to workflow files, so syncs that include `.github/workflows/` changes need a fine-grained PAT (your mirror only; Contents + Workflows read/write) stored as a `SYNC_TOKEN` secret — without it, the sync works until a workflow file changes upstream, then fails loudly. Your `stack.txt` edit lives on a private commit; merges only conflict if the upstream template itself changes.

If `stack.txt` is missing or empty the bot exits with an error rather than silently triaging with no stack context.

### 4. Repo secrets + variables (for Actions)

**Secrets:** `GH_MODELS_TOKEN`, `RESEND_API_KEY`, `BRAVE_API_KEY` (plus your provider's key if you switch off the default)
**Variables:** `DIGEST_TO_EMAIL`, `DIGEST_FROM_EMAIL`, `LLM_MODEL` (required), optionally `LLM_PROVIDER` / `LLM_EXTRA`

Upgrading to a newer model is editing the `LLM_MODEL` variable — no code change, no commit, and nothing to sync to private mirrors.

Switching provider is two variables and a secret — e.g. `LLM_PROVIDER=mistral`, `LLM_MODEL=mistral-large-latest`, secret `MISTRAL_API_KEY`. Switching *model* on the same provider is just `LLM_MODEL`. `GH_MODELS_TOKEN`, `XAI_API_KEY`, `MISTRAL_API_KEY`, and `OPENAI_API_KEY` are already wired into `digest.yml`; for any other provider add one `env:` line there. A provider missing from `config.PROVIDERS` works too — set `LLM_BASE_URL` and `LLM_API_KEY_ENV` instead of `LLM_PROVIDER`. An unknown `LLM_PROVIDER` fails fast at startup rather than silently calling the default.

`GH_MODELS_TOKEN` must be a fine-grained PAT with `models:read` — Actions' built-in `GITHUB_TOKEN` does not have that scope. It is the only LLM credential the default setup needs.

### 5. Local run

```
python digest.py
```

Reads `.env` and the committed `stack.txt`, writes `last_run.txt` with the raw LLM output, updates `state.json`.

## Tests

```
pytest -q
```

Pytest suite covers URL normalization, state TTL semantics, HTML escaping, URL scheme validation, LLM output parsing, triage input formatting, blocklist matching, and triage-merge logic (dedup, slot caps, ordering). CI (`tests.yml`) runs on every push and PR.

## Feeds

The RSS set is intentionally small — a handful of primary-source, blog-shaped, low-volume feeds. The list lives in `feeds.md` as a markdown link list, parsed at import.

**The shipped list is a starter set, not a finished one** — like `stack.txt`, it's meant to be repopulated in your clone. It skews cloud-native / AWS / GitHub-heavy; if you run on Azure, GCP, Rails, or .NET, swap in your own primary sources. The selection principle is what transfers, not the URLs: low-volume, blog-shaped, primary-source, stack-relevant. See `feeds.md` itself for the current set and the rationale for what's deliberately excluded.

Volume trade-off: this bot gives up Krebs-breaks-a-story first-mover windows (maybe 12–24h faster than the rest of the news cycle on a small number of stories per year) in exchange for a clean candidate pool where the search pass is the primary signal mechanism and RSS is the primary-source safety net.

## Tuning

Most signal tuning lives in `config.py`:

- `feeds.md` — add/remove RSS sources (markdown link list parsed at import)
- `BLOCKLIST_TITLE_TERMS` / `BLOCKLIST_DOMAINS` / `BLOCKLIST_URL_PATTERNS` — suppress known noise before triage (title match is word-boundary, case-insensitive; URL patterns are full-link regexes that catch evergreen index/price/marketing pages whose host also serves real news)
- `MAX_RSS_ARTICLES`, `PER_FEED_CAP` — candidate pool shape (round-robin merge enforces per-feed fairness)
- `STATE_SENT_TTL_DAYS` (30) — how long sent URLs stay suppressed
- `STATE_CANDIDATE_COOLDOWN_DAYS` (5) — how long near-misses are filtered to avoid daily recycling
- `MAX_SEARCH_QUERIES` (6) — anchored (1) + independent (5) fire-tier queries; `COMPLIANCE_QUERIES` (1) and `PQC_QUERIES` (1) are separate and run only on the Monday catch-up
- `MAX_SEARCH_RESULTS` (5) / `BROAD_SEARCH_RESULTS` (3) — Brave results fetched per query; abstract query types (independent/compliance/PQC) use the smaller count to shrink trending-news backfill
- `BRAVE_GOGGLES` (env, optional) — URL of a Brave goggle to bias results toward a curated source set. The repo ships `security-news.goggle` (boosts primary security news/advisories, downranks aggregator backfill). Brave fetches the goggle at query time, so the URL must be publicly reachable — **a private fork's own raw URL won't work**; point at this repo's copy (`https://raw.githubusercontent.com/SatanicMechanic/n2ksecdigest/main/security-news.goggle`), or host a customized goggle at any public URL (a public gist works). Because it must be public, keep customizations generic — don't encode stack hints. Boost-only by design; hard exclusions stay in the testable `config.py` blocklists
- `LLM_TIMEOUT_SEC` (60) — per-provider request budget; the digest gives each parallel triage future twice this plus slack before timing out

The triage bars live in `prompt_threat.txt` (fire-tier threats + compliance) and `prompt_tooling.txt` (platform/CI/CD/OSS-tool features). Tuning what qualifies is a prompt edit, not a code change. Slot caps (`TRIAGE_GLOBAL_CAP`, `TRIAGE_TOOLING_CAP`) are in `config.py`.

## State persistence

`state.json` is persisted between runs via GitHub Actions cache (key prefix `digest-state-`). It is gitignored and never committed. Two TTL classes share the file:

- **sent** — article was delivered in a digest; suppressed for 30 days
- **candidate** — article reached triage but wasn't selected; cooled down 5 days

URLs are canonicalized before storage: scheme/host lowercased, fragment stripped, tracking params (utm_*, fbclid, gclid, etc.) removed, default ports and trailing slashes dropped. So `https://Example.com/a/?utm_source=x` and `https://example.com/a` collapse.

The cache save step runs with `if: always()` so state is preserved even when the digest is skipped or fails. The 7-day Actions cache eviction window is much longer than the weekday run cadence (twice per weekday), so the cache is never idle long enough to expire and state survives weekends. If the cache is ever evicted, the bot starts fresh — sent/candidate history is lost, so some suppressed items may reappear until they age out.

v1.2.0 tried committing the **sent** subset back to the repo as a durability backstop. It never worked (the commit gate ran `git diff` before staging, which ignores untracked files) and was removed in v1.3.0: `main`'s ruleset requires a PR plus the `test` check, GitHub Actions is not an eligible bypass actor, and the digest job is the one job that must not hold a bypass credential — it installs third-party code, so branch protection is what stops a bad dependency release from pushing to `main`. A repeated story ages out in 30 days; that trade wasn't worth it.

## Costs

Anywhere from **free to about $0.60/month**, depending on your choice of provider and model. Everything except the LLM is free at this volume:

- LLM provider: free on the default (GitHub Models, within its free tier), up to roughly $0.60/month on a paid frontier model. Volume is small either way — 5–6 query/triage calls per run (anchored query when warranted, independent query, combined compliance+PQC query, tooling-scan, ai-lab, threat + tooling triage in parallel; ~25K tokens), plus up to 3 short enrichment calls on days when items are actually selected (most days: zero). On xAI, reasoning effort is pinned to "low" via `LLM_EXTRA` — enough judgment for triage-style calls without deep-reasoning latency or cost.
- GitHub Actions: ~1 min/run, well within free tier
- Brave Search: 2,000 queries/month free; this bot uses ~160/month (8 queries/run × ~20 runs)
- Resend: 3,000 emails/month free; this sends ≤22/month — and typically far fewer given the SKIP-preferred bar
- All RSS feeds: no auth required

The author's own instance currently runs at **$0/month**, using `mistral-medium-latest` on Mistral's free tier.

## Failure modes

- **All feeds dead**: RSS pool empty; search-only digest if queries still generate; SKIP if nothing found
- **Brave Search down / key missing**: `fetch_search_articles` returns empty, RSS-only digest
- **LLM provider down**: query gen / triage raise; if both triage calls fail the digest is skipped and state is still persisted. There is no fallback provider — a failed run means no digest that cycle
- **Triage hangs**: each future is bounded by `2 * LLM_TIMEOUT_SEC + 10` seconds so the workflow doesn't sit until the 10‑minute job timeout
- **Enrichment fetch/LLM failure**: per-item and best-effort; the digest ships with the triage-time why/action
- **Resend 4xx/5xx**: raises; state is not updated, so the next run will re-consider the same articles
- **Slack webhook down / URL missing**: logged and ignored; email delivery (the delivery of record) is unaffected

## Operational notes

- State is saved with `if: always()` — it persists even on SKIP or failure. A crash before `save_state()` is called means `state.json` on disk is stale, but the cache save still captures whatever was on disk.
- `concurrency: group: digest` prevents two runs from racing on the cache key.
- Feed health check runs weekly (`check_feeds.yml`) or on demand.
