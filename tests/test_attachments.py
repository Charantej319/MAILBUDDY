"""
Unit tests for attachment analysis.
Tests executable extensions, double extensions, MIME mismatches.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.attachment_analyzer import AttachmentAnalyzer


def test_safe_attachment():
    """Test that a safe PDF attachment produces no high-severity findings."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'report.pdf',
        'content_type': 'application/pdf',
        'size': 102400,
    }])
    high_findings = [f for f in findings if f.severity in ('HIGH', 'CRITICAL')]
    assert len(high_findings) == 0, f"Safe attachment should have no HIGH findings, got: {high_findings}"
    print("[PASS]  test_safe_attachment passed")


def test_executable_extension():
    """Test detection of executable file extension."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'malware.exe',
        'content_type': 'application/x-msdownload',
        'size': 51200,
    }])
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_EXECUTABLE" in rule_ids, f"Expected ATTACHMENT_EXECUTABLE, got: {rule_ids}"
    print("[PASS]  test_executable_extension passed")


def test_double_extension():
    """Test detection of double extension (invoice.pdf.exe)."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'invoice.pdf.exe',
        'content_type': 'application/x-msdownload',
        'size': 51200,
    }])
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_DOUBLE_EXTENSION" in rule_ids, f"Expected ATTACHMENT_DOUBLE_EXTENSION, got: {rule_ids}"
    print("[PASS]  test_double_extension passed")


def test_script_extension():
    """Test detection of script file extension."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'payload.vbs',
        'content_type': 'text/vbs',
        'size': 1024,
    }])
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_SCRIPT" in rule_ids, f"Expected ATTACHMENT_SCRIPT, got: {rule_ids}"
    print("[PASS]  test_script_extension passed")


def test_macro_office_format():
    """Test detection of macro-enabled Office format."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'document.docm',
        'content_type': 'application/vnd.ms-word.document.macroEnabled.12',
        'size': 204800,
    }])
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_MACRO" in rule_ids, f"Expected ATTACHMENT_MACRO, got: {rule_ids}"
    print("[PASS]  test_macro_office_format passed")


def test_mime_mismatch():
    """Test detection of MIME type mismatch with extension."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([{
        'filename': 'image.jpg',
        'content_type': 'application/x-msdownload',
        'size': 50000,
    }])
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_MIME_MISMATCH" in rule_ids, f"Expected ATTACHMENT_MIME_MISMATCH, got: {rule_ids}"
    print("[PASS]  test_mime_mismatch passed")


def test_multiple_attachments():
    """Test detection of many attachments."""
    analyzer = AttachmentAnalyzer()
    attachments = [{'filename': f'file{i}.pdf', 'content_type': 'application/pdf', 'size': 1000} for i in range(7)]
    findings = analyzer.analyze(attachments)
    rule_ids = [f.rule_id for f in findings]
    assert "ATTACHMENT_MULTIPLE" in rule_ids, f"Expected ATTACHMENT_MULTIPLE, got: {rule_ids}"
    print("[PASS]  test_multiple_attachments passed")


def test_no_attachments():
    """Test that no attachments produces no findings."""
    analyzer = AttachmentAnalyzer()
    findings = analyzer.analyze([])
    assert len(findings) == 0, f"No attachments should produce no findings, got: {len(findings)}"
    print("[PASS]  test_no_attachments passed")


if __name__ == '__main__':
    test_safe_attachment()
    test_executable_extension()
    test_double_extension()
    test_script_extension()
    test_macro_office_format()
    test_mime_mismatch()
    test_multiple_attachments()
    test_no_attachments()
    print("\nAll attachment tests passed! ")
