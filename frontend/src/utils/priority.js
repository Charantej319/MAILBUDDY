/**
 * MailBuddy priority display helpers.
 * Priority (real-world importance) and Security (risk) are separate axes
 * and are always rendered separately.
 */

export const PRIORITY_LEVELS = ['CRITICAL', 'HIGH', 'IMPORTANT', 'NORMAL', 'LOW']
export const PRIORITY_CATEGORIES = ['SECURITY', 'JOB', 'INTERNSHIP', 'ACADEMIC', 'PERSONAL', 'FINANCE', 'TRANSACTION', 'PROMOTION', 'GENERAL']

// Restrained, professional palette per level.
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
