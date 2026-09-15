#!/usr/bin/env python3
"""Need to Know — daily security digest orchestrator.

Pipeline:
  1. Fetch RSS articles (round-robin across feeds, state + blocklist filter)
  2. Generate web-search queries (RSS-anchored + independent horizon scan,
     both biased toward unfolding/on-fire events)
  3. Execute Brave Search and merge results
  4. Triage with two parallel GitHub Models calls: threat/compliance and tooling
  5. Render HTML + plain text and send via Resend
  6. Persist state (sent URLs -> 30-day suppression, candidate URLs -> cooldown)
"""

import json
import os
import datetime
import concurrent.futures
from dotenv import load_dotenv

from llm import (
    generate_anchored_queries, generate_slow_queries, generate_slot_queries,
    build_triage_input, parse_triage_output, call_llm, enrich_items,
    QUERY_SLOTS, ANCHORED_QUERIES,
    STACK_SUMMARY,
)
from config import (
    COMPLIANCE_QUERIES, PQC_QUERIES,
    TRIAGE_GLOBAL_CAP, TRIAGE_TOOLING_CAP,
    LLM_TIMEOUT_SEC, LLM_API_KEY_ENV, LLM_MODEL, LLM_PROVIDER,
    LLM_BASE_URL, LLM_EXTRA, PROVIDERS,
    MAX_SEARCH_RESULTS, BROAD_SEARCH_RESULTS,
)
from fetchers import fetch_rss_articles, fetch_search_articles
from state import (load_state, save_state, record_candidates, record_sent,
                   recent_sent_headlines, sent_today, normalize_url, digest_day)
from render import render_html, render_slack, render_text, subject_line
from mailer import send_email
from slack import send_slack

load_dotenv()


# Required env vars. The LLM key is whichever one the configured provider uses —
# hardcoding XAI_API_KEY here meant every non-xAI provider still demanded an
# unused xAI key. Delivery is email, Slack, or both; see _check_env.
_REQUIRED_ENV = (LLM_API_KEY_ENV,)
_EMAIL_ENV = ("RESEND_API_KEY", "DIGEST_TO_EMAIL", "DIGEST_FROM_EMAIL")


def _email_configured() -> bool:
    return any(os.environ.get(name) for name in _EMAIL_ENV)


def _slack_configured() -> bool:
    return bool(os.environ.get("SLACK_WEBHOOK_URL", "").strip())


def _check_env() -> None:
    if not LLM_MODEL:
        raise RuntimeError(
            f"LLM_MODEL is required (provider {LLM_PROVIDER!r}). Set it to the "
            "model id you want to run — it has no built-in default so that "
            "switching models is a config change, not a code change."
        )
    if not LLM_BASE_URL or not LLM_API_KEY_ENV:
        raise RuntimeError(
            f"Unknown LLM_PROVIDER {LLM_PROVIDER!r}; pick one of "
            f"{', '.join(sorted(PROVIDERS))} or set LLM_BASE_URL + LLM_API_KEY_ENV."
        )
    # Parsed here, not at the first LLM call: query generation swallows
    # exceptions, so a typo'd LLM_EXTRA used to surface only as a failed triage.
    try:
        extra = json.loads(LLM_EXTRA or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM_EXTRA is not valid JSON: {exc}") from None
    if not isinstance(extra, dict):
        raise RuntimeError("LLM_EXTRA must be a JSON object.")
    missing = [name for name in _REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            f"See .env.example for the full list."
        )
    # Partial email config is a typo, not a choice: fail rather than silently
    # dropping to Slack-only.
    if _email_configured():
        missing = [name for name in _EMAIL_ENV if not os.environ.get(name)]
        if missing:
            raise RuntimeError(
                f"Email delivery is partially configured; missing: {', '.join(missing)}."
            )
    elif not _slack_configured():
        raise RuntimeError(
            "No delivery configured. Set RESEND_API_KEY, DIGEST_TO_EMAIL and "
            "DIGEST_FROM_EMAIL for email, and/or SLACK_WEBHOOK_URL for Slack."
        )
    if not os.environ.get("BRAVE_API_KEY"):
        print("Warning: BRAVE_API_KEY is unset; web search stage will be a no-op.")


def _load_prompt(filename: str, today_str: str, lookback_hours: int) -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(path) as f:
        text = f.read()
    return (text
            .replace("{{DATE}}", today_str)
            .replace("{{LOOKBACK_HOURS}}", str(lookback_hours))
            .replace("{{STACK}}", STACK_SUMMARY))


def _ground_urls(items, pool_urls: set[str]):
    """Drop triage items whose URL was not in the candidate pool; canonicalize
    the rest.

    The prompts ask for "the original URL of the primary source", but nothing
    stops the model from inventing one or cross-wiring two candidates. An
    ungrounded URL is emailed to the reader and fetched by the enrichment pass,
    so anything we did not put in front of the model is dropped. Rewriting the
    survivors to their normalized form also gives the merge dedupe below and
    state suppression a single URL-equality rule.

    None (a legitimate SKIP) passes through untouched.
    """
    if not items:
        return items
    grounded = []
    for item in items:
        norm = normalize_url(item.get("url") or "")
        if norm not in pool_urls:
            print(f"Warning: dropping LLM item whose URL is not in the candidate "
                  f"pool: {item.get('headline', '(no headline)')!r} -> "
                  f"{item.get('url')!r}")
            continue
        item["url"] = norm
        grounded.append(item)
    return grounded


def _merge_triage_results(items_a, items_b, emergency: bool = False) -> list:
    """Merge threat-triage and tooling-triage outputs with dedup and slot caps.

    Dedup uses normalize_url — the same rule state suppression uses — so a
    story that appears once with tracking params and once bare collapses here
    instead of surviving as two items.
    """
    a = items_a or []
    b = items_b or []

    seen: set = set()
    deduped_a: list = []
    deduped_b: list = []
    for it in a:
        u = normalize_url(it.get("url") or "")
        if u and u not in seen:
            seen.add(u)
            deduped_a.append(it)
    for it in b:
        u = normalize_url(it.get("url") or "")
        if u and u not in seen:
            seen.add(u)
            deduped_b.append(it)

    # The emergency bar applies before any cap: a critical threat ranked past
    # the global cap would otherwise be sliced off and the run logged "clear".
    if emergency:
        return _emergency_filter(deduped_a)

    # Threats fill first; tooling contributes at most TRIAGE_TOOLING_CAP items.
    a_picks = deduped_a[:TRIAGE_GLOBAL_CAP]
    b_picks = deduped_b[:TRIAGE_TOOLING_CAP]
    return (a_picks + b_picks)[:TRIAGE_GLOBAL_CAP]


def _no_digest_reason(degraded: list[str], emergency: bool) -> str:
    """The line printed when a run ends without sending.

    Three outcomes end here and they are not the same event: the model looked
    and found nothing, the emergency re-check found nothing critical, or we
    never got a usable answer. Printing one message for all three made a
    broken run read as a quiet news day.
    """
    if degraded:
        return (f"DEGRADED — no digest sent: {'; '.join(degraded)}. "
                f"This is not an editorial SKIP.")
    if emergency:
        return ("Emergency re-check clear — nothing critical since the earlier "
                "digest. Persisting state and exiting.")
    return ("Nothing noteworthy today (SKIP — triage returned a clean skip). "
            "Persisting state and exiting.")


def _empty_pool_report(lookback_hours: int, rss_stats: dict, search_stats: dict) -> str:
    """Why there was nothing to triage, from the two fetch funnels.

    "No articles found" alone read the same whether nothing was published,
    everything was already seen, or search came back empty — on a green run.
    2026-09-14's Monday run was the first of those and the log couldn't say so.
    """
    lines = ["No articles found — nothing to triage. Exiting."]
    if rss_stats.get("fetched", 0) == 0:
        lines.append(f"  RSS: no feed entries published in the last {lookback_hours}h.")
    else:
        lines.append(f"  RSS: {rss_stats['fetched']} in window"
                     f" -> {rss_stats['after_state_dedup']} after state dedup"
                     f" -> {rss_stats['after_blocklist']} after blocklist.")
    lines.append(f"  Search: {search_stats['fetched']} returned (after age filter)"
                 f" -> {search_stats['after_rss_dedup']} after RSS dedup"
                 f" -> {search_stats['after_state_dedup']} after state dedup"
                 f" -> {search_stats['after_blocklist']} after blocklist.")
    return "\n".join(lines)


def _emergency_filter(items: list) -> list:
    """The out-of-band bar: one critical threat, or nothing.

    Triage already selects on fire-tier, but that bar delivers the daily
    digest. Re-interrupting a reader who has had their digest today needs a
    higher one, and severity is the gate the model already assigns — no second
    prompt to keep in sync.
    """
    qualifying = [i for i in items
                  if (i.get("severity") or "").lower() == "critical"
                  and (i.get("category") or "").lower() == "threat"]
    if items and not qualifying:
        # Only when something actually survived triage — otherwise the caller's
        # SKIP/DEGRADED line already says what happened, and this would claim
        # "nothing critical" about items that were dropped upstream.
        print(f"Emergency re-check found nothing critical "
              f"({len(items)} item(s) triaged, none qualifying).")
    return qualifying[:1]


def _fail_on_total_triage_failure(threat_exc: Exception | None,
                                   tooling_exc: Exception | None,
                                   emergency: bool = False) -> None:
    """Both triage calls failing (not a legitimate SKIP) means an outage —
    auth, billing, network — not a quiet news day. A silent return here would
    let a scheduled run finish "successfully" having sent nothing; raise
    instead so the Actions run goes red and GitHub's scheduled-workflow
    failure notification actually fires.
    """
    if emergency:
        # Only the threat call runs on this path, so "both failed" would be a
        # confusing thing to read on a red run.
        raise RuntimeError(
            "Emergency re-check triage failed — no re-check happened this run. "
            f"Threat: {threat_exc!r}."
        )
    raise RuntimeError(
        "Both triage calls failed — no digest sent this run. "
        f"Threat: {threat_exc!r}. Tooling: {tooling_exc!r}."
    )


def get_lookback_hours() -> int:
    """72 hours on Monday (covers the weekend), 24 hours otherwise.

    Monday means the digest day, so Monday's evening run still covers the
    weekend when it fires after UTC midnight."""
    return 72 if digest_day().weekday() == 0 else 24


def run() -> None:
    _check_env()
    lookback_hours = get_lookback_hours()
    mode = "Monday catchup" if lookback_hours == 72 else "standard"
    print(f"Lookback: {lookback_hours}h ({mode})")

    state = load_state()
    print(f"Loaded state: {len(state)} URLs in dedup/cooldown window.")

    # An earlier run today already delivered, so this is the emergency
    # re-check rather than the daily digest. It exists because a low-stakes
    # tooling item in the morning used to consume the day's delivery slot and
    # blind the afternoon run to an actual fire. The bar is deliberately much
    # higher: threats only, critical only, at most one item.
    #
    # Both scheduled runs fall on the same digest day, which rolls over at
    # 04:00 UTC rather than midnight because the evening run often fires after
    # UTC midnight (state._DAY_ROLLOVER). Revisit if a run moves across 04:00.
    emergency = sent_today(state)
    if emergency:
        print("An earlier run today already delivered. Emergency re-check only: "
              "threats, critical severity, at most 1 item.")

    # --- RSS ---
    # The candidate cooldown is skipped in emergency mode: a story that was a
    # near-miss this morning and has since escalated has to be able to come
    # back. Sent-suppression still applies, so nothing already delivered
    # returns, and the recent-headlines block below still bars follow-up
    # coverage of the same event.
    rss_articles, rss_stats = fetch_rss_articles(lookback_hours, state,
                                                 sent_only=emergency)
    print(f"RSS: {len(rss_articles)} articles after dedup/blocklist.")

    # --- Query generation ---
    print(f"Generating {ANCHORED_QUERIES} RSS-anchored queries...")
    anchored = generate_anchored_queries(rss_articles)
    for q in anchored:
        print(f"  [anchored] → {q}")

    # tooling-scan and ai-lab cannot produce a fire-tier threat, so the
    # emergency re-check pays for neither.
    active_slots = [s for s in QUERY_SLOTS
                    if not emergency or s.label == "independent"]
    slot_specs: dict[str, list[dict]] = {}
    for slot in active_slots:
        print(f"Generating {slot.n_queries} {slot.label} queries...")
        queries = generate_slot_queries(slot, lookback_hours)
        for q in queries:
            print(f"  [{slot.label}] → {q}")
        slot_specs[slot.label] = [
            {"label": slot.label, "query": q, "count": slot.n_results}
            for q in queries
        ]

    # Compliance + PQC are slow-moving beats with little genuinely new coverage
    # day-to-day, so daily polling just guarantees backfill noise. Restricted
    # to the Monday catch-up run (72h lookback).
    if lookback_hours >= 48 and not emergency:
        print(f"Generating {COMPLIANCE_QUERIES} compliance + {PQC_QUERIES} PQC queries (combined call)...")
        compliance, pqc = generate_slow_queries(lookback_hours)
        for q in compliance:
            print(f"  [compliance] → {q}")
        for q in pqc:
            print(f"  [pqc] → {q}")
    else:
        compliance, pqc = [], []
        print("Skipping compliance + PQC queries "
              "(weekly-only, and never on the emergency re-check).")

    # --- Search ---
    # Labeled query specs carry a per-type result count and a label so the SKIP
    # report can attribute each candidate to the query that produced it. Abstract
    # horizon-scan types (independent urgency phrases, compliance, PQC) fetch fewer
    # results because Brave backfills their empty slots with trending noise; types
    # with concrete anchors keep the full count.
    def _specs(label: str, queries: list[str], count: int) -> list[dict]:
        return [{"label": label, "query": q, "count": count} for q in queries]

    query_specs = (
        _specs("anchored", anchored, MAX_SEARCH_RESULTS)
        + slot_specs.get("independent", [])
        + _specs("compliance", compliance, BROAD_SEARCH_RESULTS)
        + _specs("pqc", pqc, BROAD_SEARCH_RESULTS)
        + slot_specs.get("tooling-scan", [])
        + slot_specs.get("ai-lab", [])
    )

    search_articles: list[dict] = []
    search_stats: dict = {"fetched": 0, "after_rss_dedup": 0, "after_state_dedup": 0, "after_blocklist": 0}
    if query_specs:
        search_articles, search_stats = fetch_search_articles(
            query_specs, lookback_hours, state, rss_articles,
            sent_only=emergency,
        )

    all_articles = rss_articles + search_articles
    print(f"Total candidates for triage: {len(all_articles)} "
          f"({len(rss_articles)} RSS + {len(search_articles)} web search)")

    if not all_articles:
        print(_empty_pool_report(lookback_hours, rss_stats, search_stats))
        return

    # Record every candidate URL that reached triage. This drives cooldown:
    # near-misses won't recycle into the pool every day. Sent URLs later
    # override this with a longer TTL.
    record_candidates(state, [a["link"] for a in all_articles])

    # --- Load and interpolate analyst prompts ---
    today_str = datetime.date.today().strftime("%B %d, %Y")
    threat_prompt = _load_prompt("prompt_threat.txt", today_str, lookback_hours)
    tooling_prompt = _load_prompt("prompt_tooling.txt", today_str, lookback_hours)

    recent_headlines = recent_sent_headlines(state)
    recent_block = ""
    if recent_headlines:
        lines = "\n".join(f"- {h}" for h in recent_headlines)
        recent_block = (
            "Recently delivered digest items (last 7 days). The reader has already "
            "seen these events covered. Do NOT re-cover the same underlying event, "
            "even if a new article or source has appeared. The following are NOT new "
            "developments that override this suppression — exclude follow-up coverage "
            "describing: additional victims; additional compromises; expanded scope "
            "within the same campaign; newly discovered packages, payloads, or IOCs "
            "within an already-reported operation; 'still ongoing', 'still unfolding', "
            "'continues to spread', 'no sign of slowing'; updated incident-response "
            "timelines; retrospective analysis or post-mortems. Re-cover ONLY if the "
            "new article reports a genuinely distinct attack vector, a previously "
            "unaffected ecosystem newly drawn in (not 'more victims in the same "
            "ecosystem'), or a vendor-confirmed material change to remediation guidance.\n\n"
            f"Already covered:\n{lines}\n\n"
        )

    article_preamble = (
        f"Today is {today_str}. "
        f"Here are {len(all_articles)} articles from the last {lookback_hours} hours "
        f"({len(rss_articles)} from RSS feeds, {len(search_articles)} from web search).\n\n"
    )
    article_body = build_triage_input(all_articles)

    threat_user_msg = (
        f"{article_preamble}"
        f"Apply the fire-tier bar. SKIP is a better answer than marginal inclusions.\n\n"
        f"{recent_block}"
        f"{article_body}"
    )
    tooling_user_msg = (
        f"{article_preamble}"
        f"Select at most one tooling item worth the reader's time today. SKIP if nothing qualifies.\n\n"
        f"{recent_block}"
        f"{article_body}"
    )

    # --- Parallel triage ---
    print("Triaging (threat + tooling in parallel)...")
    raw_threat: str = ""
    raw_tooling: str = ""
    threat_exc: Exception | None = None
    tooling_exc: Exception | None = None
    # call_llm makes a single request and raises on failure (see llm.py —
    # there is no provider fallback), so worst-case wall time for one future
    # is roughly LLM_TIMEOUT_SEC. Add slack and let the future-level timeout
    # act as a hard backstop if the SDK hangs instead of raising.
    triage_deadline = LLM_TIMEOUT_SEC + 10
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fut_threat = executor.submit(
            call_llm, threat_prompt, threat_user_msg,
            temperature=0.15, json_mode=True,
        )
        fut_tooling = None if emergency else executor.submit(
            call_llm, tooling_prompt, tooling_user_msg,
            temperature=0.15, json_mode=True,
        )
        try:
            raw_threat = fut_threat.result(timeout=triage_deadline)
        except Exception as exc:
            threat_exc = exc
            print(f"Threat triage call failed: {exc}")
        if fut_tooling is not None:
            try:
                raw_tooling = fut_tooling.result(timeout=triage_deadline)
            except Exception as exc:
                tooling_exc = exc
                print(f"Tooling triage call failed: {exc}")

    pool_summary = (
        f"RSS pool: {rss_stats['fetched']} fetched"
        f" -> {rss_stats['after_state_dedup']} after state dedup"
        f" -> {rss_stats['after_blocklist']} after blocklist"
        f" -> {rss_stats['after_cross_feed_dedup']} after cross-feed dedup\n"
        f"Search pool: {search_stats['fetched']} fetched"
        f" -> {search_stats['after_rss_dedup']} after RSS dedup"
        f" -> {search_stats['after_state_dedup']} after state dedup"
        f" -> {search_stats['after_blocklist']} after blocklist\n"
        f"Queries: {len(anchored)} anchored,"
        f" {len(slot_specs.get('independent', []))} independent,"
        f" {len(compliance)} compliance, {len(pqc)} pqc,"
        f" {len(slot_specs.get('tooling-scan', []))} tooling-scan,"
        f" {len(slot_specs.get('ai-lab', []))} ai-lab\n"
        f"Triage candidates: {len(all_articles)} total"
        f" ({len(rss_articles)} RSS + {len(search_articles)} search)\n"
    )

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_run.txt")
    with open(log_path, "w") as f:
        f.write(pool_summary)
        f.write("\n=== THREAT ===\n")
        f.write(raw_threat)
        f.write("\n\n=== TOOLING ===\n")
        f.write(raw_tooling)
    print(f"Raw LLM output written to {log_path}")

    if not raw_threat and not raw_tooling:
        save_state(state)
        _fail_on_total_triage_failure(threat_exc, tooling_exc, emergency)

    # Parse each call independently: bad JSON from one must not discard the
    # other's good output or crash the run before save_state.
    #
    # `degraded` separates "the model looked and found nothing" from "we never
    # got a usable answer". Both end with no email, and without this they print
    # the same line — so a broken run reads as a quiet news day.
    degraded: list[str] = []

    def _safe_parse(raw: str, label: str):
        if not raw:
            degraded.append(f"{label.lower()} triage call failed")
            return None
        stats: dict = {}
        try:
            parsed = parse_triage_output(raw, stats)
        except RuntimeError as exc:
            degraded.append(f"{label.lower()} triage returned unparseable JSON")
            print(f"{label} triage output unusable: {exc}")
            return None
        # Every item the model sent was rejected by the schema or hallucination
        # guards. That is an empty list either way, but it is not the model
        # deciding there was nothing worth sending. Partial drops are normal
        # filtering and are not flagged — the per-item warnings cover those.
        if parsed == [] and stats.get("returned", 0) > 0:
            degraded.append(f"{label.lower()} triage returned "
                            f"{stats['dropped']} item(s), all rejected by the "
                            f"schema/hallucination guards")
        return parsed

    pool_urls = {normalize_url(a["link"]) for a in all_articles if a.get("link")}

    def _parse_and_ground(raw: str, label: str):
        parsed = _safe_parse(raw, label)
        grounded = _ground_urls(parsed, pool_urls)
        if parsed and not grounded:
            degraded.append(f"{label.lower()} triage returned only ungrounded URLs")
        return grounded

    items_threat = _parse_and_ground(raw_threat, "Threat")
    items_tooling = [] if emergency else _parse_and_ground(raw_tooling, "Tooling")

    items = _merge_triage_results(items_threat, items_tooling, emergency)
    if not items:
        print(_no_digest_reason(degraded, emergency))
        save_state(state)
        return
    if degraded:
        # Partial failure that still delivered: worth seeing in the log even
        # though the run is green.
        print(f"Note: delivering a partial digest — {'; '.join(degraded)}.")

    # --- Second-pass enrichment ---
    # Triage selected on title + short summary; fetch the chosen articles and
    # let the LLM sharpen why/action with full text. Best-effort: any failure
    # ships the triage-time fields. Selection itself is never re-litigated.
    print(f"Enriching {len(items)} item(s) with article text...")
    try:
        items = enrich_items(items)
    except Exception as exc:
        print(f"Enrichment pass failed (continuing with triage output): {exc}")

    # --- Render and send ---
    print(f"Rendering and sending {len(items)} item(s)"
          f"{' as an out-of-band alert' if emergency else ''}.")
    html_body = render_html(items, today_str)
    text_body = render_text(items, today_str)
    subject = subject_line(items, today_str, alert=emergency)
    email = _email_configured()
    if email:
        send_email(html_body, text_body, subject)
    # Slack-only: its failure must fail the run, or the items below get
    # recorded as sent without ever being delivered.
    send_slack(render_slack(items, today_str, alert=emergency), fatal=not email)

    # --- Promote sent URLs (longer TTL) and persist ---
    sent_count = 0
    for item in items:
        url = item.get("url")
        if url:
            record_sent(state, [url], headline=item.get("headline", ""))
            sent_count += 1
    save_state(state)
    print(f"Recorded {sent_count} sent URLs. State now: {len(state)} entries.")


if __name__ == "__main__":
    run()
