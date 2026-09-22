/**
 * MailBuddy V2 display metadata — "Calm Desktop + Functional Color".
 *
 * Single source of truth mapping engine values to the centralized CSS
 * tokens defined in index.css (:root). Components never hardcode hues.
 *
 * Two independent axes:
 * - Priority  (importance): CRITICAL / HIGH / IMPORTANT / NORMAL / LOW
 * - Security  (risk):       SAFE / LOW RISK / SUSPICIOUS / HIGH RISK
 *   presented in plain language as Safe / Review / Suspicious / Threat.
 */

export const PRIORITY_LEVELS = ['CRITICAL', 'HIGH', 'IMPORTANT', 'NORMAL', 'LOW']
export const PRIORITY_CATEGORIES = ['SECURITY', 'JOB', 'INTERNSHIP', 'ACADEMIC', 'PERSONAL', 'FINANCE', 'TRANSACTION', 'PROMOTION', 'GENERAL']

/** Sidebar/page metadata per priority level (icon chars are decorative; text carries meaning). */
export const LEVEL_META = {
  CRITICAL: { label: 'Critical', plural: 'messages require attention', cls: 'prio-critical', dot: 'prio-dot-critical', icon: 'icon-critical' },
  HIGH: { label: 'High', plural: 'messages worth your time', cls: 'prio-high', dot: 'prio-dot-high', icon: 'icon-high' },
  IMPORTANT: { label: 'Important', plural: 'messages to keep in view', cls: 'prio-important', dot: 'prio-dot-important', icon: 'icon-important' },
  NORMAL: { label: 'Normal', plural: 'everyday messages', cls: 'prio-normal', dot: 'prio-dot-normal', icon: 'icon-normal' },
  LOW: { label: 'Low', plural: 'messages you can skip', cls: 'prio-low', dot: 'prio-dot-low', icon: 'icon-low' },
}

/** Back-compat: badge class + uppercase label (used by list rows and legacy views). */
export const PRIORITY_STYLES = {
  CRITICAL: { label: 'CRITICAL', cls: 'prio-critical' },
  HIGH: { label: 'HIGH PRIORITY', cls: 'prio-high' },
  IMPORTANT: { label: 'IMPORTANT', cls: 'prio-important' },
  NORMAL: { label: 'NORMAL', cls: 'prio-normal' },
  LOW: { label: 'LOW', cls: 'prio-low' },
}

export function priorityStyle(level) {
  return PRIORITY_STYLES[level] || { label: 'PENDING', cls: 'prio-pending' }
}

export function levelMeta(level) {
  return LEVEL_META[level] || { label: level || 'Unsorted', plural: 'messages', cls: 'prio-pending', dot: 'prio-dot-low', icon: 'prio-icon-low' }
}

/**
 * Security axis in plain language. Engine values:
 * SAFE / LOW RISK -> Safe, SUSPICIOUS -> Review/Suspicious, HIGH RISK -> Threat.
 * Colors come from the --security-* tokens only.
 */
const SECURITY_STYLES = {
  SAFE: { label: 'Safe', cls: 'sec-safe' },
  'LOW RISK': { label: 'Safe', cls: 'sec-safe' },
  LOW_RISK: { label: 'Safe', cls: 'sec-safe' },
  SUSPICIOUS: { label: 'Suspicious', cls: 'sec-suspicious' },
  'HIGH RISK': { label: 'Threat', cls: 'sec-high' },
  HIGH_RISK: { label: 'Threat', cls: 'sec-high' },
}

export function securityStyle(classification) {
  if (!classification) return { label: 'Safe', cls: 'sec-safe' }
  return SECURITY_STYLES[classification] || SECURITY_STYLES[String(classification).toUpperCase()] || { label: String(classification), cls: 'sec-low' }
}

export function categoryLabel(category) {
  if (!category) return 'GENERAL'
  const labels = {
    SECURITY: 'Security',
    JOB: 'Job',
    INTERNSHIP: 'Internship',
    ACADEMIC: 'Academic',
    PERSONAL: 'Personal',
    FINANCE: 'Finance',
    TRANSACTION: 'Transaction',
    PROMOTION: 'Promotion',
    GENERAL: 'General',
  }
  return labels[category] || category
}

export function formatDeadline(deadlineIso) {
  if (!deadlineIso) return null
  try {
    const d = new Date(deadlineIso + (deadlineIso.length === 10 ? 'T23:59:59' : ''))
    const today = new Date()
    const dayDiff = Math.ceil((d - today) / 86400000)
    const dateStr = d.toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' })
    if (dayDiff < 0) return `${dateStr} (passed)`
    if (dayDiff === 0) return 'Today'
    if (dayDiff === 1) return 'Tomorrow'
    if (dayDiff <= 7) return `${dateStr} (${dayDiff} days)`
    return dateStr
  } catch {
    return deadlineIso
  }
}
