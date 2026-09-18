"""
HTML sanitizer for untrusted email content.

Email HTML is UNTRUSTED INPUT. This module renders it down to a minimal,
readable subset of HTML using Python's stdlib html.parser (no external
dependencies, no JavaScript execution — parsing is purely textual).

Removed entirely:
- <script>, <style>, <iframe>, <object>, <embed>, <form>, <svg>, <math>,
  <meta>, <link>, <base>, plus HTML comments and CDATA/processing instructions
- All event-handler attributes (on*)

Rewritten or dropped:
- <a href> links are kept as plain text (defanged) — we never render
  clickable links from email content and never visit them
- <img> tags become "[image: alt]" text (blocks tracking pixels and
  url(...) exfiltration)
- Dangerous URL schemes (javascript:, data:, vbscript:, file:) are dropped
- Style/size attributes are dropped (layout stays readable via CSS in the app)

Never use this to produce "trusted" HTML for arbitrary contexts — it is
specifically for displaying email bodies in the PhishGuard detail page,
alongside Content-Security-Policy defence in depth (see index.html).
"""

from html.parser import HTMLParser
from html import escape


# Elements whose entire content is dropped.
_DROP_WITH_CONTENT = {
    "script", "style", "iframe", "object", "embed", "noscript", "noembed",
    "noframes", "frameset", "frame", "svg", "math", "template",
    "head", "title", "textarea", "select", "option", "button",
    "applet", "xmp", "plaintext", "listing",
}

# Void/standalone elements that must NOT open a content-dropped region
# even when they appear as "<input ...>" without a closing tag.
_VOID_ELEMENTS = {
    "input", "img", "br", "hr", "area", "base", "col", "embed", "frame",
    "link", "meta", "param", "source", "track", "wbr",
}

# Elements rendered as block-level containers (line breaks around them).
_BLOCK_ELEMENTS = {
    "p", "div", "br", "hr", "table", "thead", "tbody", "tfoot", "tr",
    "td", "th", "ul", "ol", "li", "blockquote", "pre", "h1", "h2", "h3",
    "h4", "h5", "h6", "address", "article", "aside", "figcaption", "figure",
    "footer", "header", "main", "nav", "section", "dl", "dt", "dd",
    "caption", "col", "colgroup", "legend", "details", "summary",
}

# URL schemes allowed in href/src before we drop the attribute.
_SAFE_URL_SCHEMES = ("http://", "https://", "mailto:")


def _is_safe_url(url: str) -> bool:
    url = (url or "").strip().lower()
    # Control characters can be used to smuggle schemes (e.g. java\\0script:).
    if any(ord(c) < 0x20 for c in url):
        return False
    # Remove all whitespace — schemes like "j a v a script:" are illegal in
    # browsers but a naive check can be fooled.
    collapsed = "".join(url.split())
    return collapsed.startswith(_SAFE_URL_SCHEMES)


def _defang_url(url: str) -> str:
    """Render a URL as non-clickable plain text: hxxps://example[.]com/path."""
    text = url.strip()
    if text.lower().startswith("https://"):
        text = "hxxps://" + text[len("https://"):]
    elif text.lower().startswith("http://"):
        text = "hxxp://" + text[len("http://"):]
    return text.replace(".", "[.]")


class _EmailHTMLSanitizer(HTMLParser):
    """Streaming sanitizer: safe HTML in, safe minimal HTML out."""

    def __init__(self, linkify: bool = False):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._linkify = linkify
        self._drop_depth = 0  # >0 while inside a dropped element
        self._open_block = None

    # -- helpers --------------------------------------------------------

    def _emit_text(self, text: str):
        if self._drop_depth:
            return
        self.out.append(escape(text, quote=False))

    def _emit_newline(self):
        if self._drop_depth:
            return
        self.out.append("\n")

    # -- tag handling ----------------------------------------------------

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "br":
            self._emit_newline()
            return
        if tag == "hr":
            self._emit_newline()
            self._emit_text("─────────")
            self._emit_newline()
            return
        if tag in _DROP_WITH_CONTENT:
            self._drop_depth += 1
            return
        if self._drop_depth:
            return
        if tag == "img":
            attrs_d = dict(attrs)
            alt = escape((attrs_d.get("alt") or "image").strip(), quote=False)
            self._emit_text(f"[image: {alt}]")
            return
        if tag in _VOID_ELEMENTS:
            # Standalone element outside a dropped region: emit nothing.
            return
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.strip() and _is_safe_url(href):
                # Emit the defanged URL as text, never a clickable <a>.
                self._emit_text(f"[link: {_defang_url(href)}] ")
            return
        if tag in _BLOCK_ELEMENTS:
            self.out.append("\n")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _VOID_ELEMENTS:
            return  # never opened a region
        if tag in _DROP_WITH_CONTENT:
            if self._drop_depth:
                self._drop_depth -= 1
            return
        if tag in _BLOCK_ELEMENTS and not self._drop_depth:
            self.out.append("\n")

    def handle_data(self, data):
        self._emit_text(data)

    def handle_comment(self, data):
        pass  # comments dropped

    def handle_decl(self, decl):
        pass

    def handle_pi(self, data):
        pass

    def unknown_decl(self, data):
        pass

    def handle_entityref(self, name):
        # convert_charrefs=True handles standard refs; anything else dropped.
        pass

    def result(self) -> str:
        html = "".join(self.out)
        # Collapse 3+ consecutive newlines to 2, strip outer whitespace.
        lines = [ln.rstrip() for ln in html.split("\n")]
        html = "\n".join(lines)
        while "\n\n\n" in html:
            html = html.replace("\n\n\n", "\n\n")
        return html.strip()


def sanitize_email_html(html: str) -> str:
    """
    Sanitize untrusted email HTML into a safe display representation.

    Returns HTML containing only structural tags (p, div, headings, lists,
    tables, pre, blockquote) with all text escaped. No script/style/iframe/
    form/object/img tags and no attributes survive. URLs are emitted as
    defanged plain text.
    """
    if not html:
        return ""
    parser = _EmailHTMLSanitizer()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # On any parse failure fall back to fully-escaped text with tags stripped.
        import re
        text = re.sub(r"<[^>]*>", " ", html)
        return escape(text, quote=False)
    return parser.result()
