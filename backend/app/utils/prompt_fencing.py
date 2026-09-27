"""
Shared prompt-fencing helpers (F-22).

Untrusted email-derived text must never be able to terminate the delimiter
that the surrounding prompt uses to mark trusted/untrusted boundaries.

Both the AI verifier and the MailBuddy assistant build prompts that wrap
email content in XML-ish tags (<email_body>, <email_content>, ...). An
attacker-controlled email containing a literal "</email_content>" could
otherwise escape the content boundary and have its remaining text interpreted
as prompt scaffolding (e.g. "<system>ignore previous instructions").

The fix is one shared sanitizer:
  - neutralize every literal closing tag variant the model could recognize
    (case-insensitive, whitespace-tolerant);
  - optionally escape ALL XML-style tags so content can never open a new
    boundary either;
  - keep the text otherwise intact (meaning preserved);
  - apply a bounded length limit.

This module is deliberately dependency-free and synchronous so every caller
(assistant context builders, verifier payload builder, tests, probes) shares
EXACTLY the same behavior instead of two subtly different implementations.
"""

import re

# Max characters of untrusted content embedded per fenced block. Mirrors the
# assistant's existing 1200-char snippet bound; callers may pass a smaller
# limit but not a larger one (a hard ceiling keeps prompts bounded even when
# a caller forgets to truncate first).
MAX_FENCED_CONTENT = 4000

# Matches a closing XML-ish tag such as </email_content>, including optional
# internal whitespace (</ email_content >) and any case (</EMAIL_CONTENT>).
# Group 1 captures the tag name so we can rebuild a neutralized form.
_CLOSING_TAG_RE = re.compile(r"<\s*/\s*([A-Za-z][A-Za-z0-9_-]*)\s*>")

# Matches any XML-ish tag (opening, closing, or self-closing) — used for the
# stricter "escape all tags" mode so content cannot OPEN a new boundary
# (e.g. "</email_content><system>").
_ANY_TAG_RE = re.compile(r"<\s*/?\s*([A-Za-z][A-Za-z0-9_-]*)\s*(/?)\s*>")


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + " …[truncated]"


def sanitize_untrusted(text: str, *, limit: int = MAX_FENCED_CONTENT,
                       escape_all_tags: bool = False) -> str:
    """Make untrusted text safe to embed inside a fenced prompt block.

    - Neutralizes literal closing tags ("</email_content>" → "<\\/email_content>")
      so the content can never terminate the trusted delimiter, for ANY tag
      name, any letter case, optional inner whitespace, and repeated attempts.
    - With escape_all_tags=True also escapes opening tags, so content cannot
      introduce a NEW boundary (covers '</email_content><system>' chains).
    - Preserves the text otherwise (meaning intact), bounded by `limit`.
    - Never raises on None/empty input.
    """
    if not text:
        return ""

    if escape_all_tags:
        def _esc_any(m: re.Match) -> str:
            name = m.group(1)
            slash = m.group(2) or ""
            return f"<\\/{name}{slash}>"

        escaped = _ANY_TAG_RE.sub(_esc_any, text)
    else:
        def _esc_close(m: re.Match) -> str:
            name = m.group(1)
            return f"<\\/{name}>"

        escaped = _CLOSING_TAG_RE.sub(_esc_close, text)

    return _truncate(escaped, limit)


def fence_block(text: str, tag: str = "email_content", *,
                limit: int = MAX_FENCED_CONTENT) -> str:
    """Wrap untrusted content in <tag>...</tag> with the shared sanitizer.

    The content is sanitized so it cannot contain a literal closing
    f"</{tag}>" (nor any other closing tag), guaranteeing the fence holds.
    """
    safe = sanitize_untrusted(text, limit=limit, escape_all_tags=True)
    return f"<{tag}>{safe}</{tag}>"
