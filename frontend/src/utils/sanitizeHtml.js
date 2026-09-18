/**
 * Frontend HTML sanitizer (defense-in-depth second pass).
 *
 * The backend sanitizes email HTML before it is ever sent to the client
 * (backend/app/utils/html_sanitizer.py). This module provides an additional
 * browser-side pass with the same guarantees, plus utilities for defanging
 * URLs so they are never clickable in the analyst UI.
 *
 * Email HTML is UNTRUSTED INPUT. Nothing here renders active content:
 * no scripts, no event handlers, no iframes, no forms, no tracking images,
 * no dangerous URL schemes.
 */

// Elements whose entire content is removed.
const DROP_WITH_CONTENT = [
  'script', 'style', 'iframe', 'object', 'embed', 'noscript', 'noembed',
  'noframes', 'frameset', 'frame', 'form', 'svg', 'math', 'template',
  'head', 'title', 'textarea', 'select', 'option', 'button', 'input',
  'applet', 'xmp', 'plaintext', 'listing',
]

// Elements that are safe to keep as structure. All attributes are stripped.
const SAFE_TAGS = new Set([
  'p', 'div', 'span', 'br', 'hr', 'table', 'thead', 'tbody', 'tfoot', 'tr',
  'td', 'th', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'b', 'em', 'i', 'u', 's',
  'address', 'article', 'aside', 'figcaption', 'figure', 'footer', 'header',
  'main', 'nav', 'section', 'dl', 'dt', 'dd', 'caption', 'small', 'sub', 'sup',
])

const BLOCK_ELEMENTS = new Set([
  'p', 'div', 'br', 'hr', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'td',
  'th', 'ul', 'ol', 'li', 'blockquote', 'pre', 'h1', 'h2', 'h3', 'h4',
  'h5', 'h6', 'address', 'article', 'aside', 'figcaption', 'figure',
  'footer', 'header', 'main', 'nav', 'section', 'dl', 'dt', 'dd', 'caption',
])

/** URL schemes allowed before we consider a URL safe to even display. */
const SAFE_URL_SCHEMES = ['http://', 'https://', 'mailto:']

function isSafeUrl(url) {
  const trimmed = (url || '').trim().toLowerCase()
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) return false
  const collapsed = trimmed.split(/\s+/).join('')
  return SAFE_URL_SCHEMES.some((scheme) => collapsed.startsWith(scheme))
}

/**
 * Defang a URL for display: https://evil.com/path → hxxps://evil[.]com/path
 * Prevents accidental clicks and link-verification lookups.
 */
export function defangUrl(url) {
  if (!url) return url
  let text = String(url).trim()
  if (text.toLowerCase().startsWith('https://')) {
    text = 'hxxps://' + text.slice('https://'.length)
  } else if (text.toLowerCase().startsWith('http://')) {
    text = 'hxxp://' + text.slice('http://'.length)
  }
  return text.replace(/\./g, '[.]')
}

/**
 * Sanitize untrusted email HTML into safe structural HTML.
 * Implemented with DOMParser in an isolated document — the parsed content
 * is never attached to the live document, so nothing executes during parsing.
 */
export function sanitizeEmailHtml(html) {
  if (!html) return ''

  try {
    return sanitizeEmailHtmlUnsafe(String(html))
  } catch {
    // Sanitizer must never crash the page: degrade to fully-escaped plain text.
    return `<pre>${escapeText(String(html))}</pre>`
  }
}

function sanitizeEmailHtmlUnsafe(html) {
  let doc
  try {
    doc = new DOMParser().parseFromString(html, 'text/html')
  } catch {
    return escapeText(html)
  }

  // Remove dangerous elements with their entire content.
  for (const tag of DROP_WITH_CONTENT) {
    doc.querySelectorAll(tag).forEach((el) => el.remove())
  }
  // HTML comments can hide payloads; remove them all.
  const commentWalker = doc.createTreeWalker(doc, NodeFilter.SHOW_COMMENT)
  const comments = []
  while (commentWalker.nextNode()) comments.push(commentWalker.currentNode)
  comments.forEach((c) => c.remove())

  // Sanitize remaining elements: strip all attributes, drop unsafe tags.
  const elements = doc.querySelectorAll('*')
  for (const el of Array.from(elements)) {
    const tag = el.tagName.toLowerCase()

    // <html>/<body> are the parser's own containers, not email content. They
    // cannot be replaced (direct children of the Document) and must not be
    // unwrapped — doing so throws HierarchyRequestError and crashes React.
    if (tag === 'html' || tag === 'body') continue

    if (tag === 'img') {
      // Tracking pixels / remote content: replace with alt text.
      const alt = el.getAttribute('alt') || 'image'
      el.replaceWith(doc.createTextNode(`[image: ${escapeText(alt)}]`))
      continue
    }

    if (tag === 'a') {
      const href = el.getAttribute('href') || ''
      const label = el.textContent || ''
      if (href.trim() && isSafeUrl(href)) {
        el.replaceWith(doc.createTextNode(`${label} [link: ${defangUrl(href)}]`))
      } else {
        el.replaceWith(doc.createTextNode(label))
      }
      continue
    }

    if (!SAFE_TAGS.has(tag)) {
      // Unknown/unsafe tag: keep its text children, drop the wrapper.
      const fragment = doc.createDocumentFragment()
      while (el.firstChild) fragment.appendChild(el.firstChild)
      el.replaceWith(fragment)
      continue
    }

    // Safe tag: remove every attribute (no style, no event handlers, …).
    for (const attr of Array.from(el.attributes)) {
      el.removeAttribute(attr.name)
    }
  }

  // Normalize whitespace around block elements for readability.
  const container = doc.body || doc
  let out = container.innerHTML || ''
  out = out
    .replace(/<(p|div|table|thead|tbody|tfoot|tr|ul|ol|li|blockquote|pre|h[1-6]|section|article|header|footer|address|dl|dt|dd|figcaption|figure|main|nav|caption|details|summary)(\s[^>]*)?>/gi, '\n<$1>')
    .replace(/<\/(p|div|table|thead|tbody|tfoot|tr|ul|ol|li|blockquote|pre|h[1-6]|section|article|header|footer|address|dl|dt|dd|figcaption|figure|main|nav|caption|details|summary)>/gi, '</$1>\n')
  // Collapse 3+ newlines.
  while (/\n{3,}/.test(out)) out = out.replace(/\n{3,}/g, '\n\n')
  return out.trim()
}

/** Escape a plain-text string for safe interpolation into HTML. */
export function escapeText(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Regression guard used in dev mode: sanitized output must never contain
 * executable markup or dangerous URL schemes.
 */
export function containsUnsafeContent(html) {
  if (!html) return false
  return (
    /<script/i.test(html) ||
    /<iframe/i.test(html) ||
    /<object/i.test(html) ||
    /<embed/i.test(html) ||
    /<form/i.test(html) ||
    /\son\w+\s*=/i.test(html) ||
    /javascript\s*:/i.test(html) ||
    /vbscript\s*:/i.test(html) ||
    /data:text\/html/i.test(html)
  )
}
