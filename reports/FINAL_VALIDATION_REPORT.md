# MailBuddy — Final Real-World Production Validation Report

**Date:** 2026-09-21 · **Environment:** installed MailBuddy 1.0.0 (`%LOCALAPPDATA%\Programs\MailBuddy`) + packaged backend (`phishguard-backend.exe`) on Windows 11 · **Account:** geralt.thewitcher432@gmail.com

## Resume verdict (prior session)

The previous validation session **terminated prematurely** while waiting for the live Google consent window (session killed ~11:36). Evidence: the app window was still parked on Google's "Request for Permission" page, `backend.log` showed no successful callback, and the prior watcher process was orphaned. No validation results existed.

No rebuild and no code changes were needed: the installed build (11:01) was newer than every source file (`main.js` 10:31, `preload.js` 10:30), the packaged backend was healthy, and the running backend had originated the pending consent, so the flow was resumed in place.

## TEST 1 — REAL GOOGLE OAUTH: **PASS (8/8)**

| # | Check | Result |
|---|-------|--------|
| 1 | Consent window appears in-app; user approves | ✅ observed (live consent page, watcher attached) |
| 2 | Callback detected automatically | ✅ watcher observed return at `http://localhost:8000/analytics` |
| 3 | Callback host is `localhost` | ✅ returned to `localhost:8000` origin |
| 4 | No redirect to `127.0.0.1` | ✅ no 127.0.0.1 in any post-auth URL |
| 5 | No redirect to `localhost:5173` | ✅ no :5173 in any post-auth URL |
| 6 | `phishguard_session` stored for `localhost` | ✅ domain=localhost, httpOnly, 7-day expiry (fp `2da5c45d79b9a04d`) |
| 7 | Gmail status becomes connected | ✅ `connected=true`, 33 emails synced & analyzed |
| 8 | Settings page loads | ✅ h1=Settings, shows "Connected" + account email — 7/7 sub-checks |
| 9 | Session survives app restart without re-auth | ✅ graceful quit → relaunch: identical cookie fingerprint, `connected=true`, window straight to app origin (verified across **two** restarts) |

## TEST 2 — WINDOWS NOTIFICATION: **PASS**

Queued two CRITICAL emails through the real ingestion endpoint (`POST /api/analyze/eml`); both classified CRITICAL (OTP + security-alert path) and verified end-to-end:

| Link in pipeline | Evidence | Result |
|---|----------|--------|
| NotificationBridge invoked | bridge acked the notification (only the bridge acks) → ledger `delivered=1` | ✅ |
| Electron IPC receives request | toast XML stored by Windows seconds after dispatch | ✅ |
| Windows native notification displayed | **wpndatabase.db** contains the exact toasts; **user confirmed entries visible in Notification Center** | ✅ (banner suppressed by Do Not Disturb) |
| Title correct | `<text id="1">MailBuddy</text>` | ✅ |
| Body correct | `CRITICAL: [VALIDATION-TEST] Unusual sign-in attempt - verify code 774913` / `CRITICAL: [VALIDATION-TEST 2] Security alert: verify code 330812 to keep access` | ✅ |
| MailBuddy branding | AUMID `com.phishguard.desktop`, title "MailBuddy" | ✅ |

Bonus: a **live** Gmail alert (`CRITICAL: New login to Instagram from Chrome on Windows`) fired through the same pipeline at 12:17 — the production path works on real inbox traffic.

### Banner suppression note
Banners did not appear on screen because **Do Not Disturb / Focus Assist** suppresses banners (user chose to keep DND on and accept the evidence). Windows still stores and lists the toasts in Notification Center. To see future banners: Win+N → toggle off "Do not disturb".

## Artifacts

- `reports/test1_oauth_watch.log` — watcher output for the real OAuth completion
- `reports/test1_settings_verify.log` — Settings page 7/7 PASS
- `reports/test1_session_before_restart.log`, `reports/test1_restart_persistence.log` — cookie fingerprint pre/post restart
- `reports/test2_notification_e2e.log` — ingestion → queue verification
- `reports/notif_diagnostics.log` — AUMID / notification-settings diagnostics
- `reports/wpn_database_findings.log` — Windows-stored toast payloads
- Validation emails: `datasets/validation_critical_test.eml`, `datasets/validation_critical_test2.eml`

## Tooling added (no application code changed)

`scripts/verify_settings.mjs`, `scripts/get_session_fp.mjs`, `scripts/verify_restart_persistence.mjs`, `scripts/phase2b_notification_e2e.mjs`, `scripts/probe_bridge.mjs`, `scripts/check_wpndatabase.py`, `scripts/notif_diagnostics.ps1`

## Overall verdict

**TEST 1: PASS · TEST 2: PASS · Production validation COMPLETE.**
