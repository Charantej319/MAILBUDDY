"""
Generate synthetic .eml test emails for PhishGuard evaluation.
Creates legitimate, phishing, spam, and suspicious emails for testing.
Expanded with diverse categories.
"""

import os
import csv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from datetime import datetime


def create_eml(msg, filename):
    """Save a MIME message as an .eml file."""
    filepath = os.path.join(os.path.dirname(__file__), filename)
    with open(filepath, 'wb') as f:
        f.write(msg.as_bytes())
    return filepath


# ── Legitimate Emails ──────────────────────────────────────────────

def create_legitimate_email():
    """Create a legitimate business email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'John Smith <john.smith@acmecorp.com>'
    msg['To'] = 'employee@company.com'
    msg['Subject'] = 'Q4 Budget Review Meeting - Thursday 3PM'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('acmecorp.com')
    msg['Reply-To'] = 'john.smith@acmecorp.com'
    msg['Return-Path'] = '<john.smith@acmecorp.com>'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Hi Team,

I wanted to remind everyone about our Q4 budget review meeting scheduled for this Thursday at 3 PM in Conference Room B.

Please bring your department budget summaries. If you can't attend, please send your report to me beforehand.

Thanks,
John Smith
Finance Director, Acme Corp
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_newsletter():
    """Create a legitimate newsletter email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'TechCrunch <newsletter@techcrunch.com>'
    msg['To'] = 'subscriber@example.com'
    msg['Subject'] = 'TechCrunch Daily: Latest Tech News'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('techcrunch.com')
    msg['List-Unsubscribe'] = '<https://techcrunch.com/unsubscribe>'
    msg['Precedence'] = 'bulk'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """TechCrunch Daily Digest

Top Stories:
1. AI Startup Raises $100M Series B
2. New iPhone Features Leaked
3. Cloud Computing Trends for 2024

Read more at techcrunch.com

To unsubscribe: https://techcrunch.com/unsubscribe
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_support():
    """Create a legitimate support email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'GitHub Support <support@github.com>'
    msg['To'] = 'developer@example.com'
    msg['Subject'] = 'Re: [Ticket #12345] Password Reset Request'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('github.com')
    msg['Reply-To'] = 'support@github.com'
    msg['Return-Path'] = '<support@github.com>'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Hi,

Thank you for contacting GitHub Support.

We've processed your password reset request. You can reset your password using the link below (valid for 1 hour):

https://github.com/password_reset/abc123def456

If you didn't request this, please ignore this email and consider enabling two-factor authentication.

Best regards,
GitHub Support Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_receipt():
    """Create a legitimate receipt/transaction email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Amazon.com <shipment-tracking@amazon.com>'
    msg['To'] = 'buyer@example.com'
    msg['Subject'] = 'Your Amazon.com order has shipped!'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('amazon.com')
    msg['Reply-To'] = 'ship-confirm@amazon.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Hello,

Your order #112-3456789-1234567 has shipped!

Estimated delivery: Friday, January 15

Track your package: https://amazon.com/track/11234567891234567

Items in this shipment:
- Wireless Mouse (x1) - $29.99

Thank you for shopping with us.

Amazon.com
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_meeting_invite():
    """Create a legitimate meeting invitation email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Sarah Chen <sarah.chen@company.com>'
    msg['To'] = 'team@company.com'
    msg['Subject'] = 'Re: Sprint Planning - Tomorrow 10 AM'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('company.com')
    msg['Reply-To'] = 'sarah.chen@company.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Hi team,

Just a reminder that our sprint planning meeting is tomorrow at 10 AM in the main conference room.

Please come prepared with your task estimates for the upcoming sprint.

Agenda:
1. Review previous sprint
2. Backlog grooming
3. Sprint planning
4. Task assignments

See you there!

Sarah
Engineering Manager
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


# ── Phishing Emails ────────────────────────────────────────────────

def create_phishing_email():
    """Create a phishing email impersonating a bank."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Security Alert <security@secure-banking-alert.com>'
    msg['To'] = 'user@gmail.com'
    msg['Subject'] = 'URGENT: Your Account Has Been Compromised'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('secure-banking-alert.com')
    msg['Reply-To'] = 'support@secure-banking-alert.com'
    msg['Return-Path'] = '<bounce@secure-banking-alert.com>'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'

    body = """Dear Valued Customer,

We have detected UNUSUAL ACTIVITY on your bank account. Your account has been temporarily SUSPENDED due to unauthorized access attempts.

You must ACT NOW to restore access to your account. If you do not respond within 24 hours, your account will be PERMANENTLY CLOSED.

Please click the link below to verify your identity and restore your account:

http://192.168.1.100/secure-banking/verify?token=abc123&session=xyz789

You will need to provide:
- Your account number
- Your online banking password
- Your PIN code
- Your social security number

This is for your protection. Do not ignore this warning.

Bank Security Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_credential_phishing():
    """Create a credential phishing email impersonating Microsoft."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Microsoft Account Team <no-reply@micr0soft-365.com>'
    msg['To'] = 'user@company.com'
    msg['Subject'] = 'Action Required: Verify Your Microsoft 365 Account'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('micr0soft-365.com')
    msg['Reply-To'] = 'support@micr0soft-365.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=softfail; dkim=none; dmarc=fail'

    body = """Dear User,

Microsoft has detected that your Microsoft 365 account requires verification. Your account will be locked within 48 hours if you do not verify.

Please click here to update your account information:

http://login-micr0soft365.com/signin?redirect=verify&continue=https://outlook.office365.com

Please provide your credentials to continue:
- Email address
- Password
- Verification code

If you do not verify, your account and all associated data will be permanently deleted.

Microsoft Account Security
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_fake_delivery():
    """Create a fake delivery notification email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'DHL Express <tracking@dhl-delivery-update.com>'
    msg['To'] = 'recipient@example.com'
    msg['Subject'] = 'Your Package Is Waiting - Action Required'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('dhl-delivery-update.com')
    msg['Reply-To'] = 'customercare@dhl-delivery-update.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=none'

    body = """Dear Customer,

Your package could not be delivered. You must confirm your delivery address within 24 hours or the package will be returned to sender.

Track your package: http://192.0.2.100/tracking?id=DHL987654

To reschedule delivery, please provide:
- Full name
- Home address
- Phone number
- Credit card for shipping verification: $2.99 re-delivery fee

Click below to update your information:
http://bit.ly/dhl-reschedule

DHL Customer Service
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_account_update_phishing():
    """Create an account update phishing email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Netflix Support <support@update-netflix-account.com>'
    msg['To'] = 'user@email.com'
    msg['Subject'] = 'Your Netflix Subscription Will Be Cancelled'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('update-netflix-account.com')
    msg['Reply-To'] = 'billing@update-netflix-account.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'

    body = """Dear Netflix Member,

We were unable to process your payment. Your account will be suspended within 24 hours.

To update your payment information, please visit:
http://netflix-account-update.com/billing?user=member&ref=12345

Please provide:
- Credit card number
- Expiration date
- CVV
- Billing address

If you do not update within 24 hours, your account will be permanently deleted and you will lose all viewing history.

Netflix Billing Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_social_engineering():
    """Create a social engineering email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'CEO Office <ceo-office@company-intl.com>'
    msg['To'] = 'finance@company.com'
    msg['Subject'] = 'Confidential: Wire Transfer Needed Urgently'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('company-intl.com')
    msg['Reply-To'] = 'ceo-office@company-intl.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'

    body = """Hi,

I need you to process an urgent wire transfer for a confidential acquisition. Please do NOT discuss this with anyone.

Transfer $45,000 to:
Account: 1234567890
Bank: First National
Routing: 021000021

This is time-sensitive. Please send the funds within 2 hours.

I'm in a meeting and can't take calls. Just handle this directly.

CEO
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_suspicious_attachment():
    """Create an email with suspicious attachment."""
    msg = MIMEMultipart('mixed')
    msg['From'] = 'Invoice System <billing@invoice-system.xyz>'
    msg['To'] = 'accounts@company.com'
    msg['Subject'] = 'Invoice #INV-2024-891 - Payment Overdue'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('invoice-system.xyz')
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=none'

    body = """Please find attached your overdue invoice.

Payment is due immediately to avoid service disruption.

Invoice Amount: $2,340.00
Due Date: URGENT

Please review the attached document and process payment within 24 hours.

Attached: invoice.pdf.exe

Billing Department
"""
    msg.attach(MIMEText(body, 'plain'))

    from email.mime.base import MIMEBase
    from email import encoders
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(b'fake executable content')
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', 'attachment', filename='invoice.pdf.exe')
    msg.attach(attachment)

    return msg


def create_google_phishing():
    """Create a Google credential phishing email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Google Security <no-reply@google-security-check.com>'
    msg['To'] = 'user@gmail.com'
    msg['Subject'] = 'Security Alert: Unusual sign-in activity detected'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('google-security-check.com')
    msg['Reply-To'] = 'security@google-security-check.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=fail; dmarc=fail'

    body = """Dear Google User,

We detected a sign-in from a new device in Moscow, Russia.

If this was you, you can ignore this message. But if you don't recognize this activity, someone else may have access to your account.

Verify your account now to secure it:
https://google-security-check.com/verify/account?id=12345&redirect=gmail

Please confirm your identity:
- Your Google account password
- Your recovery phone number
- Verification code sent to your phone

If you do not verify within 24 hours, your account will be locked for security reasons.

Google Security Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_password_reset_phishing():
    """Create a fake password reset phishing email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Apple ID <noreply@apple-id-verification.com>'
    msg['To'] = 'user@icloud.com'
    msg['Subject'] = 'Your Apple ID has been locked'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('apple-id-verification.com')
    msg['Reply-To'] = 'support@apple-id-verification.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=fail'

    body = """Your Apple ID (user@icloud.com) has been locked due to too many failed login attempts.

To unlock your account, you must verify your identity within 48 hours.

Click here to reset your password:
https://apple-id-verification.com/unlock?id=user@icloud.com

You will need to provide:
- Your Apple ID password
- Your credit card number for verification
- Your Social Security Number

If you do not verify, your account and all purchased content will be permanently deleted.

Apple Support
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_spam_email():
    """Create a spam email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Special Offers <deals@best-price-online.com>'
    msg['To'] = 'user@email.com'
    msg['Subject'] = 'CONGRATULATIONS! You Won $1,000,000!'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('best-price-online.com')
    msg['X-Mailer'] = 'Bulk Mail Sender v2.0'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=none'

    body = """CONGRATULATIONS!!!

You have been selected as our WINNER of $1,000,000 in our annual lottery!

Claim your prize NOW before it expires TODAY!

Click here: http://click.example.com/claim-prize?winner=you

Act immediately! This offer expires in 24 hours!

Don't delay! Claim your reward NOW!

Best Price Online Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


# ── Legitimate Edge Cases ─────────────────────────────────────────

def create_legitimate_with_url():
    """Legitimate email that simply contains a URL (no phishing markers)."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Priya Sharma <priya@contoso.dev>'
    msg['To'] = 'teammate@contoso.dev'
    msg['Subject'] = 'Notes from today\'s design review'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('contoso.dev')
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
    body = """Hi Sam,

Great discussion today. I've posted the notes and the Figma boards here:

https://wiki.contoso.dev/design-review/2026-09-15

Let me know if you have any comments before Friday.

Priya
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_security_alert():
    """Legitimate security notification (urgent words, but authentic)."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'GitHub <notifications@github.com>'
    msg['To'] = 'developer@example.com'
    msg['Subject'] = '[GitHub] A new sign-in to your account'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('github.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
    body = """Hi,

We noticed a new sign-in to your account from a Windows device in Bengaluru, India.

If this was you, you can safely ignore this email. If not, please review your recent activity and secure your account:

https://github.com/settings/security

Thanks,
The GitHub Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_urgent():
    """Legitimate email with genuinely urgent language from a known domain."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Ops On-Call <ops-oncall@company.com>'
    msg['To'] = 'engineering@company.com'
    msg['Subject'] = 'URGENT: Production incident — checkout service degraded'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('company.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
    body = """Team,

We are investigating a SEV-1 incident: the checkout service is returning 500s for ~30% of requests.

War room: https://meet.company.com/incident-4712
Status page will be updated every 15 minutes.

On-call lead,
Ops
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_benign_mismatch():
    """Benign sender/reply-to mismatch (mailing list Reply-To is normal)."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Python-list <python-list-bounces@python.org>'
    msg['To'] = 'python-list@python.org'
    msg['Subject'] = 'Question about asyncio task groups'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('python.org')
    msg['Reply-To'] = 'python-list@python.org'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
    body = """Hello,

I'm trying to cancel a TaskGroup when one child fails but the others are still useful.

Any pointers appreciated!

Thanks,
A lurking list member
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_legitimate_html_multipart():
    """Legitimate HTML/multipart email with links and a normal attachment."""
    msg = MIMEMultipart('mixed')
    msg['From'] = 'Coursera <no-reply@coursera.org>'
    msg['To'] = 'learner@example.com'
    msg['Subject'] = 'Your weekly learning streak'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('coursera.org')
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    html = """<html><body>
<p>Congratulations — you kept your learning streak going this week!</p>
<p>Continue your course: <a href="https://www.coursera.org/learn/python">Python for Everybody</a></p>
</body></html>"""
    text = "Congratulations — you kept your learning streak going this week!\n\nContinue your course: https://www.coursera.org/learn/python"
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    from email.mime.base import MIMEBase
    from email import encoders
    cert = MIMEBase('application', 'pdf')
    cert.set_payload(b'%PDF-1.4 fake certificate')
    encoders.encode_base64(cert)
    cert.add_header('Content-Disposition', 'attachment', filename='certificate.pdf')
    msg.attach(cert)
    return msg


def create_legitimate_recruiter():
    """Unusual but legitimate sender (recruiter with a hyphenated domain)."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Talent Team <hello@acme-talent-pool.io>'
    msg['To'] = 'candidate@example.com'
    msg['Subject'] = 'Senior Python role — are you open to a chat?'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('acme-talent-pool.io')
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'
    body = """Hi,

I came across your profile and think you could be a strong fit for a Senior Python Engineer role at one of our partner companies (remote, India-based team).

If you're open to it, just reply with a convenient time for a short call. No preparation needed.

Best regards,
Talent Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


# ── Phishing Edge Cases ────────────────────────────────────────────

def create_phishing_shortened_url():
    """Phishing email using only a shortened URL."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Admin <admin@corp-portal-notify.com>'
    msg['To'] = 'employee@company.com'
    msg['Subject'] = 'Your mailbox quota has been exceeded'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('corp-portal-notify.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=none; dkim=none; dmarc=none'
    body = """Dear User,

Your mailbox has exceeded its storage limit and outgoing mail is now blocked.

Increase your quota immediately: http://bit.ly/mailbox-quota

System Administrator
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_phishing_punycode():
    """Phishing email with a punycode/homograph domain."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'PayPal <service@xn--pypal-4ve.com>'
    msg['To'] = 'user@example.com'
    msg['Subject'] = 'Unusual activity: confirm your information'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('xn--pypal-4ve.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=fail'
    body = """Dear Customer,

We detected unusual activity in your account. For your protection, please confirm your information within 24 hours:

https://www.xn--pypal-4ve.com/confirm?session=abc123

We ask you to verify your account details to avoid account limitation.

PayPal
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_phishing_ip_url():
    """Phishing email where the login page is a raw IP address."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Webmail Support <support@webmail-verify-team.com>'
    msg['To'] = 'user@example.com'
    msg['Subject'] = 'Validate your webmail account now'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('webmail-verify-team.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=none; dkim=none; dmarc=none'
    body = """Dear Email User,

Your webmail account will be deactivated within 48 hours. Validate immediately to keep your account active:

http://203.0.113.55/validate/login.aspx

Enter your username and password to confirm your identity.

Webmail Support Team
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_phishing_html_multipart():
    """HTML/multipart phishing email — credential harvest via pretty HTML."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Office 365 <security@o365-mail-security.com>'
    msg['To'] = 'employee@company.com'
    msg['Subject'] = 'Action required: 5 pending messages held in quarantine'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('o365-mail-security.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=softfail; dkim=none; dmarc=fail'

    html = """<html><body>
<p>Dear User,</p>
<p>You have <strong>5 messages</strong> held in quarantine awaiting release.
Messages will be <strong>deleted within 24 hours</strong> unless you release them.</p>
<p><a href="https://o365-mail-security.com/release?token=9f8e7d6c">Release messages — sign in with your email password</a></p>
<p>Thank you,<br>Office 365 Security Team</p>
</body></html>"""
    text = """Dear User,

You have 5 messages held in quarantine awaiting release. Messages will be deleted within 24 hours unless you release them.

Release messages — sign in with your email password:
https://o365-mail-security.com/release?token=9f8e7d6c

Thank you,
Office 365 Security Team
"""
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))
    return msg


def create_phishing_invoice_lookalike():
    """Invoice-themed phishing from a lookalike accounting domain."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Accounting <billing@company-accounting.com>'
    msg['To'] = 'finance@company.com'
    msg['Subject'] = 'Overdue invoice — bank details updated'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('company-accounting.com')
    msg['Authentication-Results'] = 'mx.google.com; spf=none; dkim=none; dmarc=none'
    body = """Dear Finance Team,

Invoice INV-77120 is overdue. Note that our bank details have changed — please remit payment to the new account below within 24 hours to avoid service interruption:

Bank: Meridian Trust
Account: 8837462910
Routing: 026009593

Amount due: $14,890.00

Accounts Department
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


# ── Suspicious Emails ──────────────────────────────────────────────

def create_suspicious_reply_to():
    """Create an email with suspicious Reply-To mismatch."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'IT Department <it@company.com>'
    msg['To'] = 'employee@company.com'
    msg['Subject'] = 'Password Expiration Notice - Update Required'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('company.com')
    msg['Reply-To'] = 'it-support@external-helpdesk.com'
    msg['Return-Path'] = '<it@company.com>'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Dear Employee,

Your network password will expire in 3 days. Please update it using the link below:

https://password-update.company.com/change?user=employee

If you have questions, reply to this email and our support team will assist you.

IT Department
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_compromised_legitimate():
    """Create an email from a compromised legitimate domain."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Shared Files <docs@legitimate-company.com>'
    msg['To'] = 'user@company.com'
    msg['Subject'] = 'Shared document: Q4 Financial Summary'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('legitimate-company.com')
    msg['Reply-To'] = 'docs@legitimate-company.com'
    msg['Authentication-Results'] = 'mx.google.com; spf=pass; dkim=pass; dmarc=pass'

    body = """Hi,

Please review the attached document. It contains the Q4 financial summary you requested.

View document: https://docs.legitimate-company.com/shared/q4-financial-abc123

If you can't view the document, please sign in with your company credentials.

Best regards,
Shared Documents System
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


def create_spam_inheritance():
    """Create an inheritance scam email."""
    msg = MIMEMultipart('alternative')
    msg['From'] = 'Barrister James Wilson <james.wilson@barrister-legal.com>'
    msg['To'] = 'lucky recipient@email.com'
    msg['Subject'] = 'URGENT: Unclaimed Inheritance Fund - $4.5 Million'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid('barrister-legal.com')
    msg['X-Mailer'] = 'Mass Mail Pro'
    msg['Authentication-Results'] = 'mx.google.com; spf=fail; dkim=none; dmarc=none'

    body = """Dear Sir/Madam,

I am writing to inform you of an unclaimed inheritance fund of $4,500,000 USD left by a deceased client with a similar surname.

As the legal representative, I need a beneficiary to claim these funds. You have been selected as the next of kin.

To claim your inheritance, please provide:
- Your full legal name
- Your bank account details
- Your passport or ID copy
- Processing fee of $500

This is a confidential matter. Please respond within 72 hours.

Barrister James Wilson
LLB, LLM (London)
"""
    msg.attach(MIMEText(body, 'plain'))
    return msg


# ── Main ───────────────────────────────────────────────────────────

def main():
    """Generate all test emails and labels."""
    os.makedirs(os.path.join(os.path.dirname(__file__), 'legitimate'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'phishing'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), 'spam'), exist_ok=True)

    labels = []

    # Create emails
    test_cases = [
        # Legitimate emails
        (create_legitimate_email(), 'legitimate/meeting_email.eml', 'legitimate'),
        (create_legitimate_newsletter(), 'legitimate/newsletter.eml', 'legitimate'),
        (create_legitimate_support(), 'legitimate/support_reply.eml', 'legitimate'),
        (create_legitimate_receipt(), 'legitimate/receipt.eml', 'legitimate'),
        (create_legitimate_meeting_invite(), 'legitimate/meeting_invite.eml', 'legitimate'),

        # Legitimate edge cases
        (create_legitimate_with_url(), 'legitimate/with_url.eml', 'legitimate'),
        (create_legitimate_security_alert(), 'legitimate/security_alert.eml', 'legitimate'),
        (create_legitimate_urgent(), 'legitimate/urgent_internal.eml', 'legitimate'),
        (create_legitimate_benign_mismatch(), 'legitimate/benign_replyto_mismatch.eml', 'legitimate'),
        (create_legitimate_html_multipart(), 'legitimate/html_multipart.eml', 'legitimate'),
        (create_legitimate_recruiter(), 'legitimate/recruiter.eml', 'legitimate'),

        # Phishing emails
        (create_phishing_email(), 'phishing/bank_phishing.eml', 'phishing'),
        (create_credential_phishing(), 'phishing/microsoft_credential_phishing.eml', 'phishing'),
        (create_fake_delivery(), 'phishing/fake_delivery.eml', 'phishing'),
        (create_account_update_phishing(), 'phishing/netflix_phishing.eml', 'phishing'),
        (create_social_engineering(), 'phishing/ceo_wire_transfer.eml', 'phishing'),
        (create_suspicious_attachment(), 'phishing/suspicious_attachment.eml', 'phishing'),
        (create_google_phishing(), 'phishing/google_credential_phishing.eml', 'phishing'),
        (create_password_reset_phishing(), 'phishing/apple_password_reset_phishing.eml', 'phishing'),

        # Phishing edge cases
        (create_phishing_shortened_url(), 'phishing/shortened_url.eml', 'phishing'),
        (create_phishing_punycode(), 'phishing/punycode_domain.eml', 'phishing'),
        (create_phishing_ip_url(), 'phishing/ip_url.eml', 'phishing'),
        (create_phishing_html_multipart(), 'phishing/html_multipart.eml', 'phishing'),
        (create_phishing_invoice_lookalike(), 'phishing/invoice_lookalike.eml', 'phishing'),

        # Suspicious emails
        (create_suspicious_reply_to(), 'phishing/suspicious_reply_to.eml', 'phishing'),
        (create_compromised_legitimate(), 'phishing/compromised_legitimate.eml', 'phishing'),

        # Spam
        (create_spam_email(), 'spam/lottery_spam.eml', 'spam'),
        (create_spam_inheritance(), 'spam/inheritance_spam.eml', 'spam'),
    ]

    for msg, filename, category in test_cases:
        filepath = create_eml(msg, filename)
        labels.append({
            'filename': filename,
            'category': category,
            'label': 1 if category in ('phishing', 'spam') else 0,
            'sender_domain': msg['From'].split('@')[-1].split('>')[0] if '@' in str(msg['From']) else '',
            'subject': msg['Subject'],
        })
        print(f"Created: {filename}")

    # Write labels.csv
    csv_path = os.path.join(os.path.dirname(__file__), 'labels.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['filename', 'category', 'label', 'sender_domain', 'subject'])
        writer.writeheader()
        writer.writerows(labels)

    print(f"\nCreated {len(test_cases)} test emails")
    print(f"Labels saved to: {csv_path}")

    # Print summary
    categories = {}
    for label in labels:
        cat = label['category']
        categories[cat] = categories.get(cat, 0) + 1

    print("\nDataset Summary:")
    for cat, count in categories.items():
        print(f"  {cat}: {count}")


if __name__ == '__main__':
    main()
