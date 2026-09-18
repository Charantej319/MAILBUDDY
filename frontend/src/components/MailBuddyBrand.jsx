import React, { useState } from 'react'
import { api } from '../services/api'

/**
 * MailBuddy brand mark. Single source of truth for logo usage.
 *
 * The OFFICIAL MailBuddy logo lives at `frontend/public/brand/mailbuddy.svg`
 * (replace the placeholder file there with the uploaded logo — no code
 * changes needed). This component renders the official asset in-app.
 */
export function MailBuddyLogo({ size = 22 }) {
  return (
    <img
      src="/brand/mailbuddy.svg"
      alt="MailBuddy logo"
      width={size}
      height={size}
      style={{ borderRadius: 4, flexShrink: 0 }}
    />
  )
}

export default function MailBuddyBrand({ size = 22 }) {
  return (
    <span className="mb-brand" style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <MailBuddyLogo size={size} />
      <span className="mb-brand-name">MailBuddy</span>
    </span>
  )
}
