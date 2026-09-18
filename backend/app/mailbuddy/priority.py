"""
MailBuddy deterministic email priority classification (heuristic layer).

IMPORTANT DESIGN BOUNDARY
    This module classifies REAL-WORLD IMPORTANCE (priority) only. It has NO
    authority over security: the deterministic phishing engine and the Groq
    security verifier are untouched and remain the security authorities.
    Priority and security are displayed separately, end to end.

Layer order:
    1. This fast, offline classifier runs for every analyzed email.
    2. The Groq AI priority service (priority_ai.py) refines it when
       configured; this module's output is the fallback when AI is
       unavailable or returns malformed data.

Signals used (content-aware, not a naive keyword matcher): sender identity
and domain, subject/body n-grams, OTP code shapes, deadline dates, question
and action requests, greeting/formality patterns, and existing deterministic
security findings as a modifier — never as a replacement.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

VALID_LEVELS = ("CRITICAL", "HIGH", "IMPORTANT", "NORMAL", "LOW")
VALID_CATEGORIES = (
    "SECURITY", "JOB", "INTERNSHIP", "ACADEMIC", "PERSONAL",
    "FINANCE", "TRANSACTION", "PROMOTION", "GENERAL",
)

# OTP: a short numeric code near OTP-ish vocabulary. Requires BOTH the
# vocabulary and a code-shaped token so ordinary numbers don't trigger it.
_OTP_WORDS = re.compile(
    r"\b(otp|verification\s*code|verify\s*code|one[-\s]?time\s*(password|code)|"
    r"security\s*code|passcode|login\s*code|confirmation\s*code)\b",
    re.IGNORECASE,
)
_OTP_CODE = re.compile(r"\b\d{4,8}\b")

# Security/account events
_SECURITY_WORDS = re.compile(
    r"\b(suspicious\s*(login|sign[\s-]?in|activity|attempt)|unusual\s*(login|sign[\s-]?in|activity)|"
    r"(password|security)\s*(reset|alert|warning)|account\s*(compromis|locked|suspended|disabled|alert)|"
    r"new\s*(sign[\s-]?in|login|device)\b|sign[\s-]?in\s*attempt|security\s*alert|"
    r"unauthorized\s*(access|login|attempt)|two[-\s]?factor|2fa)\b",
    re.IGNORECASE,
)

_JOB_WORDS = re.compile(
    r"\b(interview\s*(invitation|invite|schedule|request|call)|job\s*(offer|opportunity|opening|application)|"
    r"(hiring|recruit\w*|talent)\s*(team|drive|update)|offer\s*letter|joining\s*(formalit\w*|date)|"
    r"we\s*would\s*like\s*to\s*(invite|move\s*forward|proceed)\b|selection\s*(for|drive)|"
    r"candidate\s*(selection|shortlist)|application\s*(status|deadline|received)|"
    r"(salary|compensation|ctc)\s*(discussion|breakdown|offer))\b",
    re.IGNORECASE,
)

_INTERNSHIP_WORDS = re.compile(
    r"\binternship\b|\bintern\s*(position|opportunity|role|program\w*|selection|offer)\b|"
    r"\bintern\b\s*(?!al)", re.IGNORECASE,
)

_ACADEMIC_WORDS = re.compile(
    r"\b(examination|exam\s*(schedule|timetable|form|fee)|assignment\s*(due|deadline|submission)|"
    r"(mid|end)\s*[-\s]?term|semester\s*(registration|results|datesheet)|"
    r"(university|college|institute|department)\s*(notice|announcement|circular)|"
    r"(class|lecture|course)\s*(schedule|notice|cancellation)|"
    r"academic\s*(calendar|deadline|alert)|grade\s*(card|release|declaration)|"
    r"(project|thesis|dissertation)\s*(deadline|submission|defense))\b",
    re.IGNORECASE,
)

_FINANCE_WORDS = re.compile(
    r"\b(invoice|payment\s*(due|reminder|received|failed)|bill\s*(due|generated)|"
    r"(credit|debit)\s*card|bank\s*(account|statement|transfer)|"
    r"(emi|premium|subscription)\s*(due|renewal|payment)|"
    r"salary\s*credited|refund\s*(status|processed)|tax\s*(filing|deadline|return))\b",
    re.IGNORECASE,
)

_TRANSACTION_WORDS = re.compile(
    r"\b(order\s*(confirmed|shipped|delivered|placed)|shipping\s*(update|confirmation)|"
    r"track(ing)?\s*(your)?\s*order|out\s*for\s*delivery|package\s*(delivered|arrived)|"
    r"(booking|ticket)\s*confirmation|appointment\s*(confirmed|reminder|scheduled)|"
    r"receipt\s*(for|of)\s*payment|your\s*order\b)\b",
    re.IGNORECASE,
)

_PROMOTION_WORDS = re.compile(
    r"\b(\d{1,3}\s*%\s*off|flash\s*sale|limited\s*time\s*offer|exclusive\s*(deal|discount)|"
    r"unsubscribe|promotional|newsletter|sale\s*(ends|alert)|special\s*offer|"
    r"deal\s*of\s*the\s*day|shop\s*now|discount\s*(code|coupon))\b",
    re.IGNORECASE,
)

# Strong personal/conversational markers (a human wrote TO you personally)
_PERSONAL_HINTS = re.compile(
    r"^\s*(hi|hello|hey|dear)\b[^\n]{0,40}$", re.IGNORECASE | re.MULTILINE,
)
_PERSONAL_WORDS = re.compile(
    r"\b(happy\s*birthday|congratulations|how\s*are\s*you|long\s*time|"
    r"(dinner|lunch|coffee|catch\s*up|party)\s*(on|this|next|sometime)?|"
    r"family|weekend\s*(plans|trip)|birthday\s*(wishes|party))\b", re.IGNORECASE,
)

_ACTION_WORDS = re.compile(
    r"\b(action\s*required|respond\s*by|reply\s*by|confirm\s*(by|your)|"
    r"(submit|complete|review|sign|verify|apply)\s*(by|before|your)|"
    r"deadline|rsvp|no\s*later\s*than|on\s*or\s*before)\b", re.IGNORECASE,
)

# Free email providers: bulk/marketing rarely originates from personal accounts,
# and job/academic senders on personal domains are still high-signal.
# Boundary-safe matching: only match these as the local part of the address or
# the first label of the domain ("mail" must NOT match "gmail.com").
_KNOWN_BULK_LOCALS = re.compile(
    r"^(.*[.\-_])?(no[-_]?reply|donotreply|do[-_]?not[-_]?reply|newsletter|promo|promotions|marketing|offers?|notify|notifications?|bounce|mailer[-_]?daemon)([.\-_].*)?$",
    re.IGNORECASE,
)
_KNOWN_BULK_DOMAIN_LABELS = re.compile(
    r"^(newsletter|promo\w*|marketing|offers?|notify\w*|bounce|mailings?)\b",
    re.IGNORECASE,
)
_FREE_MAIL = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com", "proton.me")

_DATE_PATTERNS = (
    re.compile(r"\b(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s*(\d{4})\b", re.IGNORECASE),
    re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(\d{1,2}),?\s+(\d{4})\b", re.IGNORECASE),
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"),
)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}

_URGENT_WINDOW_DAYS = 21  # deadlines further out than this stop being "deadline" evidence


def _is_bulk_sender(sender_email: str, sender_domain: str) -> bool:
    """True when the address itself looks like a bulk/mail pipeline identity."""
    local = (sender_email or "").split("@")[0]
    if local and _KNOWN_BULK_LOCALS.match(local):
        return True
    first_label = (sender_domain or "").split(".")[0]
    return bool(first_label and _KNOWN_BULK_DOMAIN_LABELS.match(first_label))


def _is_bulk_sender_legacy_stub():  # pragma: no cover - clarity helper, unused
    return False


def _find_deadline(text: str, now: datetime):
    """Extract the first parseable future-ish date mentioned in the body/subject."""
    if not text:
        return None, None
    lower = text.lower()
    has_deadline_context = bool(re.search(
        r"(deadline|due|by|before|no later than|ends on|submit|apply|expires?|last date)",
        lower,
    ))
    for pattern in _DATE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        groups = match.groups()
        try:
            if len(groups) == 3 and not groups[0].isdigit() or (len(groups) == 3 and len(groups[2]) == 4 and not groups[0].isdigit()):
                month = _MONTHS[groups[0][:3].lower()]
                day, year = int(groups[1]), int(groups[2])
            elif len(groups) == 3:
                day, month, year = int(groups[0]), _MONTHS[groups[1][:3].lower()], int(groups[2])
            else:
                year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
            candidate = datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
        except (ValueError, KeyError, TypeError):
            continue
        if has_deadline_context and (now - timedelta(days=2)) <= candidate <= now + timedelta(days=120):
            return candidate, candidate.date().isoformat()
    return None, None


def _has(header_or_text: str, pattern) -> bool:
    return bool(pattern.search(header_or_text or ""))


def heuristic_classify(
    *,
    subject: str = "",
    sender: str = "",
    sender_email: str = "",
    sender_domain: str = "",
    body_text: str = "",
    security_classification: str = "SAFE",
    received_at: datetime | None = None,
) -> dict:
    """Classify real-world importance without AI.

    Returns a dict matching the AI priority schema (minus confidence, which is
    derived from signal strength).
    """
    now = received_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    text_blob = f"{subject}\n{body_text or ''}"
    subject_l = (subject or "").lower()
    from_l = f"{sender} {sender_email}".lower()

    is_otp = _has(text_blob, _OTP_WORDS) and bool(_OTP_CODE.search(body_text or subject or ""))
    security_alert = _has(text_blob, _SECURITY_WORDS)
    job = _has(text_blob, _JOB_WORDS)
    internship = _has(text_blob, _INTERNSHIP_WORDS)
    academic = _has(text_blob, _ACADEMIC_WORDS)
    finance = _has(text_blob, _FINANCE_WORDS)
    transaction = _has(text_blob, _TRANSACTION_WORDS)
    promotion = _has(text_blob, _PROMOTION_WORDS) or _is_bulk_sender(sender_email, sender_domain)
    personal = _has(text_blob, _PERSONAL_WORDS) or (_has(body_text or "", _PERSONAL_HINTS) and not job and not academic)
    action = _has(text_blob, _ACTION_WORDS)
    deadline_dt, deadline_iso = _find_deadline(text_blob, now)

    # ---- Category resolution (decisive content first; bulk sender last) ----
    if is_otp or security_alert:
        category = "SECURITY"   # transactional senders (no-reply@) stay SECURITY
    elif internship:
        category = "INTERNSHIP"
    elif job:
        category = "JOB"
    elif academic:
        category = "ACADEMIC"
    elif finance:
        category = "FINANCE"
    elif transaction:
        category = "TRANSACTION"
    elif promotion:
        category = "PROMOTION"
    elif personal:
        category = "PERSONAL"
    else:
        category = "GENERAL"

    # ---- Level resolution ----
    reasons = []
    if category == "SECURITY":
        level = "CRITICAL"
        reasons.append("Account/security event" if security_alert else "Verification code detected")
    elif category == "INTERNSHIP":
        level = "HIGH"
        reasons.append("Internship opportunity or status update")
    elif category == "JOB":
        level = "HIGH"
        reasons.append("Job/recruitment related")
    elif category == "ACADEMIC":
        level = "IMPORTANT"
        reasons.append("Academic communication")
    elif category == "FINANCE":
        level = "IMPORTANT" if action or deadline_dt else "NORMAL"
        reasons.append("Financial/billing related")
    elif category == "TRANSACTION":
        level = "IMPORTANT" if action else "NORMAL"
        reasons.append("Order/booking/appointment update")
    elif category == "PROMOTION":
        level = "LOW"
        reasons.append("Marketing/promotional content")
    elif category == "PERSONAL":
        level = "NORMAL"
        reasons.append("Personal correspondence")
    else:
        level = "NORMAL"

    if action and level in ("NORMAL", "IMPORTANT") and category != "PROMOTION":
        level = "IMPORTANT" if level == "NORMAL" else level
        reasons.append("Explicit action or response requested")
    if deadline_dt and level in ("IMPORTANT", "HIGH"):
        days = (deadline_dt - now).days
        if days <= 3 and level == "IMPORTANT" and category in ("JOB", "INTERNSHIP", "ACADEMIC"):
            level = "HIGH"
        reasons.append(f"Deadline detected: {deadline_iso}" if deadline_iso else "Deadline detected")
    if promotion and category != "PROMOTION":
        # Promotional framing must not drag genuine content down, but it caps
        # the level: newsletters announcing jobs are still bulk.
        if level == "NORMAL":
            level = "LOW"
        reasons.append("Bulk/promotional sender characteristics")
    if security_classification in ("HIGH_RISK", "SUSPICIOUS") and level in ("NORMAL", "IMPORTANT"):
        # A security-flagged email deserves attention either way — as
        # "look at this", never as "trust this". Security stays separate.
        level = "HIGH"
        reasons.append("Flagged by the security engine for review")

    # Confidence: proportion of decisive signals found.
    signals = [is_otp or security_alert, job or internship, academic, finance,
               transaction, promotion, personal, action, deadline_dt is not None]
    hits = sum(1 for s in signals if s)
    confidence = round(min(0.9, 0.45 + 0.09 * hits), 2)

    summary = _summarize(subject, sender, category, level, deadline_iso)
    return {
        "priority": level,
        "category": category,
        "confidence": confidence,
        "reasons": reasons[:5],
        "deadline": deadline_iso,
        "summary": summary,
    }


def _summarize(subject: str, sender: str, category: str, level: str, deadline_iso) -> str:
    subj = (subject or "").strip()[:90]
    cat = category.title() if category != "GENERAL" else "General"
    base = f"{cat} email"
    if subj:
        base = f"{base}: \"{subj}\""
    if deadline_iso:
        base = f"{base} — deadline {deadline_iso}"
    return base
