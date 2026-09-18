"""
Attachment analysis module.
Analyzes attachment metadata without executing or opening files.
Enhanced with full explainability.
"""

import os
from .rules import Finding, Severity, Category


# Dangerous executable extensions
EXECUTABLE_EXTENSIONS = {
    '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsh', '.ps1', '.msi', '.msp', '.mst',
    '.cpl', '.hta', '.inf', '.reg', '.rgs', '.sct', '.shb', '.shs',
    '.lnk', '.url', '.application', '.gadget',
}

# Script extensions
SCRIPT_EXTENSIONS = {
    '.js', '.jse', '.vbs', '.vbe', '.wsf', '.wsh', '.ps1', '.psc1',
    '.psc2', '.ms1', '.ms2', '.py', '.rb', '.pl', '.sh', '.bash',
}

# Macro-enabled Office formats
MACRO_EXTENSIONS = {
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
    '.sldm', '.ppam', '.odp', '.ods',
}

# Archive extensions (may contain malware)
ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.iso', '.img', '.vhd', '.vhdx',
}

# Safe extensions
SAFE_EXTENSIONS = {
    '.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.rtf',
    '.odt', '.ods', '.odp',
}

# MIME type categories
DANGEROUS_MIME_TYPES = {
    'application/x-msdownload', 'application/x-executable',
    'application/x-dosexec', 'application/x-bat', 'application/x-vbs',
    'application/javascript', 'text/javascript', 'text/x-script',
    'application/x-sh', 'application/x-perl', 'text/x-python',
}


def get_extension(filename: str) -> str:
    """Get the lowercase file extension."""
    _, ext = os.path.splitext(filename.lower())
    return ext


def check_double_extension(filename: str) -> bool:
    """Check if filename has a double extension (e.g., invoice.pdf.exe)."""
    parts = filename.lower().split('.')
    if len(parts) > 2:
        doc_extensions = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.jpg', '.png'}
        second_ext = '.' + parts[-2]
        return second_ext in doc_extensions
    return False


class AttachmentAnalyzer:
    """Analyzes email attachments for security concerns."""

    def analyze(self, attachments: list[dict]) -> list[Finding]:
        """
        Analyze attachment metadata and return findings.
        Each attachment dict should have: filename, content_type, size
        """
        findings = []

        for attachment in attachments:
            findings.extend(self._analyze_single_attachment(attachment))

        # Check for multiple attachments (bulk attack indicator)
        if len(attachments) > 5:
            findings.append(Finding(
                rule_id="ATTACHMENT_MULTIPLE",
                category=Category.ATTACHMENT,
                severity=Severity.LOW.value,
                points=2,
                message=f"Email contains {len(attachments)} attachments — unusually many.",
                evidence=f"Attachment count: {len(attachments)}",
                explanation=(
                    "A high number of attachments can indicate a bulk attack or "
                    "an attempt to overwhelm the recipient."
                ),
                source="Attachment metadata analysis",
            ))

        return findings

    def _analyze_single_attachment(self, attachment: dict) -> list[Finding]:
        """Analyze a single attachment."""
        findings = []

        filename = attachment.get('filename', 'unknown')
        content_type = attachment.get('content_type', '').lower()
        size = attachment.get('size', 0)
        ext = get_extension(filename)

        # 1. Executable extension
        if ext in EXECUTABLE_EXTENSIONS:
            findings.append(Finding(
                rule_id="ATTACHMENT_EXECUTABLE",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH.value,
                points=8,
                message=f"Attachment has an executable extension ({ext}).",
                evidence=f"Filename: {filename}, Extension: {ext}",
                explanation=(
                    f"Files with '{ext}' extension are executable. Opening such files "
                    f"can install malware or compromise the system."
                ),
                source="Attachment metadata analysis",
            ))

        # 2. Double extension
        if check_double_extension(filename):
            findings.append(Finding(
                rule_id="ATTACHMENT_DOUBLE_EXTENSION",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH.value,
                points=8,
                message="Attachment has a double extension — commonly used to disguise malicious files.",
                evidence=f"Filename: {filename}",
                explanation=(
                    "Double extensions (e.g., 'invoice.pdf.exe') are used to make "
                    "malicious files appear to be legitimate documents."
                ),
                source="Attachment metadata analysis",
            ))

        # 3. Script extension
        if ext in SCRIPT_EXTENSIONS:
            findings.append(Finding(
                rule_id="ATTACHMENT_SCRIPT",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH.value,
                points=7,
                message=f"Attachment is a script file ({ext}).",
                evidence=f"Filename: {filename}",
                explanation=(
                    f"Script files ('{ext}') can execute arbitrary code. "
                    f"Opening such attachments can compromise your system."
                ),
                source="Attachment metadata analysis",
            ))

        # 4. Macro-enabled Office format
        if ext in MACRO_EXTENSIONS:
            findings.append(Finding(
                rule_id="ATTACHMENT_MACRO",
                category=Category.ATTACHMENT,
                severity=Severity.MEDIUM.value,
                points=5,
                message=f"Attachment is a macro-enabled Office document ({ext}).",
                evidence=f"Filename: {filename}",
                explanation=(
                    "Macro-enabled documents can contain embedded macros that "
                    "execute code when the document is opened."
                ),
                source="Attachment metadata analysis",
            ))

        # 5. MIME type mismatch with extension
        if content_type and ext:
            self._check_mime_mismatch(filename, ext, content_type, findings)

        # 6. Dangerous MIME type
        if content_type in DANGEROUS_MIME_TYPES:
            findings.append(Finding(
                rule_id="ATTACHMENT_DANGEROUS_MIME",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH.value,
                points=7,
                message=f"Attachment has a potentially dangerous MIME type ({content_type}).",
                evidence=f"Filename: {filename}, MIME: {content_type}",
                explanation=(
                    f"MIME type '{content_type}' is associated with executable "
                    f"or script content."
                ),
                source="Attachment metadata analysis",
            ))

        # 7. Very large attachment
        if size > 10 * 1024 * 1024:
            findings.append(Finding(
                rule_id="ATTACHMENT_LARGE",
                category=Category.ATTACHMENT,
                severity=Severity.LOW.value,
                points=2,
                message=f"Attachment is unusually large ({size / (1024*1024):.1f} MB).",
                evidence=f"Filename: {filename}, Size: {size} bytes",
                explanation=(
                    "Very large attachments may contain embedded malware, "
                    "encrypted archives, or other suspicious content."
                ),
                source="Attachment metadata analysis",
            ))

        return findings

    def _check_mime_mismatch(self, filename: str, ext: str, content_type: str, findings: list):
        """Check for mismatches between file extension and MIME type."""
        expected_mimes = {
            '.pdf': ['application/pdf'],
            '.jpg': ['image/jpeg'],
            '.jpeg': ['image/jpeg'],
            '.png': ['image/png'],
            '.gif': ['image/gif'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.xls': ['application/vnd.ms-excel'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.txt': ['text/plain'],
            '.html': ['text/html'],
            '.htm': ['text/html'],
            '.exe': ['application/x-msdownload', 'application/x-executable'],
        }

        if ext in expected_mimes:
            if content_type not in expected_mimes[ext]:
                findings.append(Finding(
                    rule_id="ATTACHMENT_MIME_MISMATCH",
                    category=Category.ATTACHMENT,
                    severity=Severity.MEDIUM.value,
                    points=5,
                    message=f"MIME type ({content_type}) does not match expected type for {ext} file.",
                    evidence=f"Filename: {filename}, MIME: {content_type}, Expected: {expected_mimes[ext]}",
                    explanation=(
                        f"The file extension '{ext}' suggests a {expected_mimes[ext][0]} file, "
                        f"but the actual MIME type is '{content_type}'. This mismatch "
                        f"may indicate the file type has been disguised."
                    ),
                    source="Attachment metadata analysis",
                ))
