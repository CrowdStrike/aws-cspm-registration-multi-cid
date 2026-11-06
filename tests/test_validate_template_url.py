"""Tests for aws-cspm-registration-multi-cid SSRF validation fix.

Covers validate_template_url() in source/update/lambda_function.py:
- Accepts HTTPS URLs pointing to amazonaws.com hostnames
- Rejects non-HTTPS schemes
- Rejects non-amazonaws hostnames
- Rejects raw private / link-local IP addresses
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Environment setup (required by module-level os.environ reads on import)
# ---------------------------------------------------------------------------

os.environ.setdefault("admin_role_arn", "arn:aws:iam::123456789012:role/admin")
os.environ.setdefault("exec_role_arn", "arn:aws:iam::123456789012:role/exec")

sys.modules.setdefault("boto3", MagicMock())
sys.modules.setdefault("botocore", MagicMock())
sys.modules.setdefault("botocore.exceptions", MagicMock())

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../source/update"))
from lambda_function import validate_template_url  # noqa: E402


# ---------------------------------------------------------------------------
# Valid URLs
# ---------------------------------------------------------------------------

class TestValidTemplateUrls:
    def test_virtual_hosted_s3(self):
        assert validate_template_url(
            "https://my-bucket.s3.amazonaws.com/template.yaml"
        ) is True

    def test_path_style_s3(self):
        assert validate_template_url(
            "https://s3.amazonaws.com/my-bucket/template.yaml"
        ) is True

    def test_regional_s3(self):
        assert validate_template_url(
            "https://s3.us-east-1.amazonaws.com/bucket/template.yaml"
        ) is True

    def test_crowdstrike_prod_bucket(self):
        assert validate_template_url(
            "https://cs-prod-cloudconnect-templates.s3.amazonaws.com/template.yaml"
        ) is True

    def test_china_region(self):
        assert validate_template_url(
            "https://bucket.s3.amazonaws.com.cn/template.yaml"
        ) is True


# ---------------------------------------------------------------------------
# Rejected URLs
# ---------------------------------------------------------------------------

class TestInvalidTemplateUrls:
    def test_http_rejected(self):
        assert validate_template_url(
            "http://bucket.s3.amazonaws.com/template.yaml"
        ) is False

    def test_ftp_rejected(self):
        assert validate_template_url(
            "ftp://bucket.s3.amazonaws.com/template.yaml"
        ) is False

    def test_non_amazonaws_host(self):
        assert validate_template_url(
            "https://evil.com/template.yaml"
        ) is False

    def test_subdomain_confusion(self):
        # amazonaws.com.evil.com does not end with .amazonaws.com
        assert validate_template_url(
            "https://bucket.s3.amazonaws.com.evil.com/template.yaml"
        ) is False

    def test_private_ip_10(self):
        assert validate_template_url("https://10.0.0.1/template.yaml") is False

    def test_private_ip_172(self):
        assert validate_template_url("https://172.16.0.1/template.yaml") is False

    def test_private_ip_192_168(self):
        assert validate_template_url("https://192.168.1.1/template.yaml") is False

    def test_link_local_imds(self):
        # AWS Instance Metadata Service
        assert validate_template_url(
            "https://169.254.169.254/latest/meta-data/"
        ) is False

    def test_loopback(self):
        assert validate_template_url("https://127.0.0.1/template.yaml") is False

    def test_empty_string(self):
        assert validate_template_url("") is False
