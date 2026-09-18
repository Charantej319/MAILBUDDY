/**
 * Shared time utilities.
 *
 * All API timestamps are timezone-aware ISO-8601 UTC strings ending in "Z"
 * (see backend/app/utils/timeutil.py). JS Date parses the Z suffix as UTC,
 * so relative times are correct in every timezone.
 */

/**
 * Parse an API timestamp into a Date.
 * Handles: "2026-09-17T07:35:05Z" (new format) and
 * "2026-09-17T07:35:05" (legacy, stored as UTC) and full RFC strings.
 */
export function parseTimestamp(value) {
  if (!value) return null
  const str = String(value).trim()
  let d = new Date(str)
  if (isNaN(d.getTime())) return null
  // No timezone marker at all → the backend stores UTC; interpret as UTC.
  if (!/(Z|[+-]\d{2}:?\d{2})$/.test(str)) {
    const m = str.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?$/)
    if (m) {
      d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)))
    }
  }
  return d
}

/** "Just now", "N minutes ago", "N hours ago", or a localized date. */
export function formatRelativeTime(value) {
  const d = parseTimestamp(value)
  if (!d) return value ? String(value) : 'never'
  const diff = Date.now() - d.getTime()
  if (diff < 45 * 1000) return 'Just now'
  if (diff < 90 * 1000) return '1 minute ago'
  if (diff < 3600000) return `${Math.floor((diff + 30000) / 60000)} minutes ago`
  if (diff < 7200000) return '1 hour ago'
  if (diff < 86400000) return `${Math.floor((diff + 1800000) / 3600000)} hours ago`
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

/** Full local date/time for detail views. */
export function formatDateTime(value) {
  const d = parseTimestamp(value)
  if (!d) return value ? String(value) : '-'
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}
