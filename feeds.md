# RSS feeds

One markdown link per line. URLs are extracted with a regex against `[name](url)`; headings, blank lines, and free-form comments are ignored, so this file can also serve as its own documentation.

The default set below is opinionated and skews cloud-native / AWS / GitHub-heavy. If your shop runs on Azure, GCP, or a Ruby/Rails or .NET stack, swap these for your own primary-source feeds — the principle is the same: low-volume, blog-shaped, primary-source, stack-relevant.

- [GitHub security blog](https://github.blog/security/feed/) — Platform tooling announcements + research
- [GitHub changelog](https://github.blog/changelog/feed/) — Platform feature releases (Dependabot, secret scanning, npm controls, etc.). ~40% prodsec-relevant; non-security Copilot/product churn is rejected by the tooling-prompt's fire-tier bar.
- [AWS security blog](https://aws.amazon.com/blogs/security/feed/) — Service announcements + research
- [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/feed/) — Security research, tool announcements, threat intelligence
- [Wiz blog](https://www.wiz.io/feed/rss.xml) — Cloud security research, supply chain incident coverage
- [Node.js vulnerability feed](https://nodejs.org/en/feed/vulnerability.xml) — Node.js security releases (primary source, low volume)
- [Python blog](https://blog.python.org/feeds/posts/default) — CPython releases including security releases; fire-tier bar filters routine posts
- [NCSC (UK) blog](https://www.ncsc.gov.uk/api/1/services/v1/blog-post-rss-feed.xml) — Editorial guidance and policy analysis (AI risk, OT resilience, crypto/PKI); low-volume (~2/week), not a CVE feed
- [OWASP blog](https://owasp.org/feed) — AppSec guidance + project releases (Top 10, Dependency-Track, etc.)

## What's intentionally not here

- **Krebs, The Register, SANS ISC, other journalism** — not primary sources. Surfaced via the Brave Search pass with urgency-biased queries instead.
- **MSRC, Amazon Linux ALAS, Red Hat errata, etc.** — per-CVE firehoses. Scanner territory; those pipelines already handle it.
- **CISA advisories** — surfaced via the Brave Search pass (`CISA emergency directive`, `CISA out-of-band advisory`).
- **Engineering and exploit-research blogs** (Cloudflare, Netflix, Meta, Project Zero, etc.) — not fed directly. General engineering blogs flood the pool with non-security posts; dedicated exploit-research blogs skew toward consumer endpoint/mobile/OS/browser/hardware work that's out of scope for a server-side product-security reader. The genuinely transferable write-ups are surfaced on demand via the tooling-scan Brave query instead.

Forks: edit this file directly to add or remove feeds for your stack.
