"""HTML, plain-text and Slack rendering for the digest.

All LLM-supplied content is HTML-escaped before interpolation.
Item URLs are validated to be http/https before use as anchor targets —
anything else renders as "#" to neutralize javascript:/data:/file: payloads.
"""

import html
from urllib.parse import urlsplit


_CATEGORY_LABEL = {
    "threat":     "Threat",
    "tooling":    "Tooling Update",
    "compliance": "Compliance / Policy",
}

# Severity reads as a solid chip: (label, background, text color).
_SEVERITY_CHIP = {
    "critical": ("Critical", "#ef4444", "#180404"),
    "high":     ("High",     "#f97316", "#1a0902"),
    "medium":   ("Medium",   "#eab308", "#1a1302"),
}

_MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

_PAGE_BG = "#0b1220"
_CARD_BG = "#131d2f"
_INSET_BG = "#0b1220"
_BORDER = "#24324a"
_RULE = "#1e2c42"
_TEXT = "#f1f5f9"
_TEXT_DIM = "#9fb0c6"
_TEXT_MUTED = "#64748b"
_AMBER = "#f5a524"
_LINK = "#38bdf8"


def _safe_url(url: str) -> str:
    """Return the URL only if it is http(s); otherwise '#'."""
    if not url:
        return "#"
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return "#"
    if scheme not in ("http", "https"):
        return "#"
    return url


def _esc(s: str) -> str:
    return html.escape(s or "", quote=True)


def _source_domain(url: str) -> str:
    """Host of an http(s) URL, minus a leading www. Empty if not renderable.

    Shown so the reader can weigh the source before clicking — a vendor
    advisory and an aggregator repost are not the same evidence.
    """
    if _safe_url(url) == "#":
        return ""
    try:
        host = urlsplit(url).netloc.lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _stack_note(item: dict) -> str:
    """The verbatim stack.txt quote a threat item grounded its relevance in.

    Parsed and validated in llm._stack_grounded but never shown until now.
    It names the part of the stack the story concerns — not a claim that
    anything is exposed.
    """
    return (item.get("stack_match") or "").strip()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _item_card(index: int, item: dict) -> str:
    cat = (item.get("category") or "").lower()
    sev = (item.get("severity") or "").lower()
    cat_label = _CATEGORY_LABEL.get(cat, _esc(cat.title()))
    sev_label, chip_bg, chip_fg = _SEVERITY_CHIP.get(
        sev, (_esc(sev.title()) or "Unrated", "#475569", "#e2e8f0"))

    headline = _esc(item.get("headline", ""))
    why = _esc(item.get("why", ""))
    action = _esc(item.get("action", ""))
    url = _safe_url(item.get("url", ""))

    meta_bits = []
    domain = _source_domain(item.get("url", ""))
    if domain:
        meta_bits.append(f"Source: {_esc(domain)}")
    stack = _stack_note(item)
    if stack:
        meta_bits.append(f"Stack: {_esc(stack)}")
    meta_html = ""
    if meta_bits:
        meta_html = f"""
              <p style="margin:18px 0 0 0; font-size:11px; font-family:{_MONO};
                         letter-spacing:0.06em; color:{_TEXT_MUTED};">
                {"  ·  ".join(meta_bits)}
              </p>"""
    link_html = ""
    if url != "#":
        link_html = f"""
              <p style="margin:16px 0 0 0;">
                <a href="{_esc(url)}"
                   style="display:inline-block; padding:9px 16px;
                          border:1px solid {_BORDER}; font-size:12px;
                          font-family:{_MONO}; letter-spacing:0.08em;
                          text-transform:uppercase; color:{_LINK};
                          text-decoration:none;">
                  Read more →
                </a>
              </p>"""

    return f"""
    <tr>
      <td style="padding:0 0 16px 0;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="background:{_CARD_BG}; border:1px solid {_BORDER};">
          <tr>
            <td style="padding:22px 24px 24px 24px;">

              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-size:0; line-height:0;">
                    <span style="display:inline-block; padding:4px 9px;
                                 background:{chip_bg}; color:{chip_fg};
                                 font-family:{_MONO}; font-size:11px;
                                 font-weight:700; letter-spacing:0.1em;
                                 text-transform:uppercase;">{sev_label}</span><span
                          style="display:inline-block; padding-left:12px;
                                 font-family:{_MONO}; font-size:11px;
                                 letter-spacing:0.1em; text-transform:uppercase;
                                 color:{_TEXT_MUTED};">{cat_label}</span>
                  </td>
                  <td align="right" style="font-family:{_MONO}; font-size:11px;
                                           letter-spacing:0.1em; color:#3f4d64;">
                    {index:02d}
                  </td>
                </tr>
              </table>

              <p style="margin:16px 0 0 0; font-size:19px; font-weight:700;
                         color:{_TEXT}; line-height:1.38; letter-spacing:-0.01em;">
                {headline}
              </p>

              <table width="100%" cellpadding="0" cellspacing="0" border="0"
                     style="margin-top:16px;">
                <tr>
                  <td style="background:{_INSET_BG}; border:1px solid {_BORDER};
                             padding:14px 16px;">
                    <p style="margin:0 0 5px 0; font-size:11px; font-family:{_MONO};
                               text-transform:uppercase; letter-spacing:0.1em;
                               color:{_AMBER};">
                      Do now
                    </p>
                    <p style="margin:0; font-size:14px; color:{_TEXT};
                               line-height:1.62;">
                      {action}
                    </p>
                  </td>
                </tr>
              </table>

              <p style="margin:18px 0 5px 0; font-size:11px; font-family:{_MONO};
                         text-transform:uppercase; letter-spacing:0.1em; color:{_TEXT_MUTED};">
                Why it matters
              </p>
              <p style="margin:0; font-size:14px; color:{_TEXT_DIM}; line-height:1.62;">
                {why}
              </p>
              {meta_html}{link_html}

            </td>
          </tr>
        </table>
      </td>
    </tr>"""


def render_html(items: list[dict], date_str: str) -> str:
    cards = "\n".join(_item_card(i, item) for i, item in enumerate(items, 1))
    date_safe = _esc(date_str)
    n = len(items)
    count = f"{n} item" if n == 1 else f"{n} items"
    # Inbox preview line: the lead headline beats repeating the subject.
    preheader = _esc(items[0].get("headline", "")) if items else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Need to Know — {date_safe}</title>
</head>
<body style="margin:0; padding:0; background:{_PAGE_BG};
             font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI',
             Roboto, 'Helvetica Neue', Arial, sans-serif;">

  <div style="display:none; max-height:0; overflow:hidden; opacity:0;
              color:transparent; font-size:1px; line-height:1px;">{preheader}</div>

  <table width="100%" cellpadding="0" cellspacing="0" border="0"
         style="background:{_PAGE_BG};">
    <tr>
      <td align="center" style="padding:36px 16px 44px 16px;">
        <table width="600" cellpadding="0" cellspacing="0" border="0"
               style="max-width:600px; width:100%;">

          <tr>
            <td style="height:3px; line-height:3px; font-size:0;
                       background:{_AMBER};">&nbsp;</td>
          </tr>

          <tr>
            <td style="padding:22px 0 20px 0; border-bottom:1px solid {_RULE};">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="font-family:{_MONO}; font-size:21px; font-weight:700;
                             letter-spacing:-0.01em;">
                    <span style="color:{_AMBER};">n2k</span><span
                          style="color:{_TEXT};">secdigest</span>
                  </td>
                  <td align="right" style="font-family:{_MONO}; font-size:12px;
                                           letter-spacing:0.1em; text-transform:uppercase;
                                           color:{_TEXT_MUTED};">
                    {date_safe} &nbsp;·&nbsp; {count}
                  </td>
                </tr>
              </table>
              <p style="margin:14px 0 0 0; font-size:15px; color:{_TEXT_DIM};
                         line-height:1.55;">
                What cleared the bar since the last run.
              </p>
            </td>
          </tr>

          <tr><td style="padding-top:24px;"></td></tr>

          {cards}

          <tr>
            <td style="padding:10px 0 0 0; border-top:1px solid {_RULE};">
              <p style="margin:16px 0 0 0; font-size:11px; color:#3f4d64;
                         text-align:center; font-family:{_MONO};
                         letter-spacing:0.06em; line-height:1.7;">
                Generated automatically from public security and platform feeds.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------

def render_text(items: list[dict], date_str: str) -> str:
    """Plain-text fallback. Resend takes both html and text bodies."""
    out = [
        f"NEED TO KNOW — {date_str}",
        "=" * 60,
        "",
    ]
    for i, item in enumerate(items, 1):
        cat = (item.get("category") or "").upper()
        sev = (item.get("severity") or "").upper()
        out.append(f"{i}. [{cat} / {sev}] {item.get('headline','')}")
        out.append("")
        out.append(f"   Do now: {item.get('action','')}")
        out.append(f"   Why: {item.get('why','')}")
        stack = _stack_note(item)
        if stack:
            out.append(f"   Stack: {stack}")
        domain = _source_domain(item.get("url", ""))
        if domain:
            out.append(f"   Source: {domain}")
        url = _safe_url(item.get("url", ""))
        if url != "#":
            out.append(f"   Link: {url}")
        out.append("")
    out.append("-" * 60)
    out.append("Generated automatically from public security and platform feeds.")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Subject line
# ---------------------------------------------------------------------------

def _clip(text: str, limit: int) -> str:
    """Collapse whitespace and cap length, for LLM text entering a header.

    Both halves matter and neither is optional: a CR/LF in a mail subject is
    header injection, and an LLM headline has no length bound of its own, so
    an uncapped one produces a broken subject or notification.
    """
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[:limit - 1].rstrip() + "…"


def _severity_prefix(items: list[dict]) -> str:
    severities = {(i.get("severity") or "").lower() for i in items}
    if "critical" in severities:
        return "🛡️🔴"
    if "high" in severities:
        return "🛡️🟠"
    return "🛡️"


def subject_line(items: list[dict], date_str: str, alert: bool = False) -> str:
    """Prefix a severity indicator so Critical/High digests sort visually.

    alert=True is the out-of-band emergency re-check: one item, and the reader
    needs to know what it is from the notification alone.
    """
    if alert and items:
        lead = _clip(items[0].get("headline"), 120)
        return f"{_severity_prefix(items)} ALERT — {lead}"
    n = len(items)
    suffix = f"({n} item{'s' if n != 1 else ''})"
    return f"{_severity_prefix(items)} Need to Know — {date_str} {suffix}"


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def _slack_esc(s: str) -> str:
    """Slack's three reserved characters, so LLM text can't forge <url|link> markup."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def slack_fallback(items: list[dict], date_str: str) -> str:
    """Notification / sidebar preview text.

    Escaped like any other item text: an unescaped headline could forge
    <url|label> markup in the one place the reader sees before clicking.
    """
    if not items:
        return subject_line(items, date_str)
    more = f" (+{len(items) - 1} more)" if len(items) > 1 else ""
    # Clip before escaping: _slack_esc expands & into &amp;, and slicing after
    # that can cut an entity in half.
    lead = _clip(items[0].get("headline"), 150)
    return f"{_severity_prefix(items)} {_slack_esc(lead)}{more}"


def render_slack(items: list[dict], date_str: str) -> dict:
    """Block Kit payload mirroring the email cards.

    Each item is its own attachment so Slack draws the severity color as a
    left bar — the only color affordance Slack offers, and the closest thing
    to the email's severity chip.
    """
    attachments = []
    for item in items:
        cat = (item.get("category") or "").lower()
        sev = (item.get("severity") or "").lower()
        cat_label = _CATEGORY_LABEL.get(cat, (cat or "Unrated").title())
        sev_label, color, _ = _SEVERITY_CHIP.get(
            sev, (sev.title() or "Unrated", "#475569", ""))

        headline = _slack_esc(item.get("headline", ""))
        url = _safe_url(item.get("url", ""))
        if url != "#":
            headline = f"<{url}|{headline}>"

        blocks = [
            {"type": "context", "elements": [{
                "type": "mrkdwn",
                "text": f"*{_slack_esc(sev_label)}*  ·  {_slack_esc(cat_label)}",
            }]},
            {"type": "section", "text": {
                "type": "mrkdwn", "text": f"*{headline}*"}},
            {"type": "section", "text": {
                "type": "mrkdwn",
                "text": f"*Do now*\n{_slack_esc(item.get('action', ''))}",
            }},
            {"type": "section", "text": {
                "type": "mrkdwn",
                "text": f"*Why it matters*\n{_slack_esc(item.get('why', ''))}",
            }},
        ]

        meta_bits = []
        domain = _source_domain(item.get("url", ""))
        if domain:
            meta_bits.append(f"Source: {_slack_esc(domain)}")
        stack = _stack_note(item)
        if stack:
            meta_bits.append(f"Stack: {_slack_esc(stack)}")
        if meta_bits:
            blocks.append({"type": "context", "elements": [{
                "type": "mrkdwn", "text": "  ·  ".join(meta_bits),
            }]})

        attachments.append({"color": color, "blocks": blocks})

    return {
        # Fallback: what push notifications and the sidebar preview show.
        # The lead headline goes first — a notification truncates, and the
        # subject line repeats verbatim in the header block below anyway.
        "text": slack_fallback(items, date_str),
        "blocks": [{"type": "header", "text": {
            "type": "plain_text",
            "text": subject_line(items, date_str)[:150],
            "emoji": True,
        }}],
        "attachments": attachments,
        "unfurl_links": False,
        "unfurl_media": False,
    }
