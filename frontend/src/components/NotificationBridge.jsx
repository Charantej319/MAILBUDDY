import { useEffect } from 'react'
import { api } from '../services/api'

/**
 * NotificationBridge — mounted once in App. Polls the backend for pending
 * important-email notifications and delivers desktop notifications exactly
 * once (backend ledger dedupes; ack marks delivered).
 *
 * Notification permission failures never break the app.
 */

let permissionRequested = false

async function ensurePermission() {
  if (!('Notification' in window)) return false
  if (Notification.permission === 'granted') return true
  if (Notification.permission === 'denied') return false
  if (permissionRequested) return false
  permissionRequested = true
  try {
    const result = await Notification.requestPermission()
    return result === 'granted'
  } catch {
    return false
  }
}

export default function NotificationBridge() {
  useEffect(() => {
    let cancelled = false
    let timer = null

    const poll = async () => {
      try {
        const data = await api.getPendingNotifications()
        if (cancelled || !data?.notifications?.length) return
        if (window.electronAPI?.showNotification) {
          // Electron path: main process delivers native notifications.
          for (const n of data.notifications) {
            const email = n.email || {}
            window.electronAPI.showNotification({
              title: 'MailBuddy',
              body: email.subject
                ? `${email.priority_level || 'Important'}: ${email.subject}`.slice(0, 140)
                : 'New important email received',
            })
          }
        } else {
          const granted = await ensurePermission()
          if (!granted) return
          for (const n of data.notifications) {
            const email = n.email || {}
            new Notification('MailBuddy', {
              body: email.subject
                ? `${email.priority_level || 'Important'}: ${email.subject}`.slice(0, 140)
                : 'New important email received',
              icon: '/brand/mailbuddy.svg',
              tag: n.key, // browser-level dedupe
            })
          }
        }
        await api.acknowledgeNotifications(data.notifications.map((n) => n.key))
      } catch {
        /* notifications are best-effort; never break the app */
      }
    }

    const loop = () => {
      poll().finally(() => {
        if (!cancelled) timer = setTimeout(loop, 60000)
      })
    }
    loop()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [])

  return null
}
