"""Tests for CSPM module — cloud config assessment, compliance, remediation."""
import pytest
from src.cyber.cspm import (
    CSPMEngine,
    CloudResource,
    Finding,
    ComplianceFramework,
    Remediation,
    assess_resource,
    check_compliance,
    generate_remediation,
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def s3_bucket_public():
    return CloudResource(
        resource_type="aws_s3_bucket",
        resource_id="my-public-bucket",
        config={"public_access_block": False, "encryption": None, "versioning": False},
    )


@pytest.fixture
def s3_bucket_secure():
    return CloudResource(
        resource_type="aws_s3_bucket",
        resource_id="my-secure-bucket",
        config={
            "public_access_block": True,
            "encryption": "AES256",
            "versioning": True,
        },
    )


@pytest.fixture
def security_group_open():
    return CloudResource(
        resource_type="aws_security_group",
        resource_id="sg-open",
        config={
            "ingress_rules": [
                {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
                {"protocol": "tcp", "port": 3389, "cidr": "0.0.0.0/0"},
            ]
        },
    )


@pytest.fixture
def security_group_restricted():
    return CloudResource(
        resource_type="aws_security_group",
        resource_id="sg-restricted",
        config={
            "ingress_rules": [
                {"protocol": "tcp", "port": 443, "cidr": "10.0.0.0/8"},
            ]
        },
    )


@pytest.fixture
def iam_policy_admin():
    return CloudResource(
        resource_type="aws_iam_policy",
        resource_id="admin-policy",
        config={"policy_document": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
    )


@pytest.fixture
def iam_policy_least_privilege():
    return CloudResource(
        resource_type="aws_iam_policy",
        resource_id="least-priv-policy",
        config={
            "policy_document": {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }
        },
    )


@pytest.fixture
def engine():
    return CSPMEngine()


# ─── Cloud Config Assessment ───────────────────────────────────────────────

class TestCloudConfigAssessment:
    """Tests for assess_resource function."""

    def test_public_s3_bucket_detected(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        assert len(findings) > 0
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_secure_s3_bucket_no_critical(self, s3_bucket_secure):
        findings = assess_resource(s3_bucket_secure)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) == 0

    def test_open_security_group_detected(self, security_group_open):
        findings = assess_resource(security_group_open)
        assert any("0.0.0.0/0" in f.description for f in findings)

    def test_restricted_security_group_passes(self, security_group_restricted):
        findings = assess_resource(security_group_restricted)
        assert len(findings) == 0

    def test_admin_iam_policy_detected(self, iam_policy_admin):
        findings = assess_resource(iam_policy_admin)
        assert any(f.rule_id == "IAM-001" for f in findings)

    def test_least_privilege_iam_policy_passes(self, iam_policy_least_privilege):
        findings = assess_resource(iam_policy_least_privilege)
        assert len(findings) == 0

    def test_unknown_resource_type_returns_empty(self):
        resource = CloudResource(
            resource_type="aws_unknown",
            resource_id="unknown-1",
            config={},
        )
        findings = assess_resource(resource)
        assert findings == []

    def test_finding_has_required_fields(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        for f in findings:
            assert f.resource_id == "my-public-bucket"
            assert f.rule_id
            assert f.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert f.description


# ─── Compliance Checking ───────────────────────────────────────────────────

class TestComplianceChecking:
    """Tests for check_compliance function."""

    def test_cis_benchmark_compliance(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        report = check_compliance(findings, ComplianceFramework.CIS)
        assert report.framework == ComplianceFramework.CIS
        assert report.total_findings == len(findings)
        assert report.compliant_count + report.non_compliant_count == len(findings)

    def test_nist_compliance_report(self, security_group_open):
        findings = assess_resource(security_group_open)
        report = check_compliance(findings, ComplianceFramework.NIST)
        assert report.framework == ComplianceFramework.NIST
        assert report.compliance_score <= 100.0

    def test_pci_dss_compliance(self, iam_policy_admin):
        findings = assess_resource(iam_policy_admin)
        report = check_compliance(findings, ComplianceFramework.PCI_DSS)
        assert report.framework == ComplianceFramework.PCI_DSS

    def test_hipaa_compliance(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        report = check_compliance(findings, ComplianceFramework.HIPAA)
        assert report.framework == ComplianceFramework.HIPAA

    def test_empty_findings_compliant(self):
        report = check_compliance([], ComplianceFramework.CIS)
        assert report.compliance_score == 100.0
        assert report.compliant_count == 0

    def test_compliance_score_decreases_with_findings(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        report = check_compliance(findings, ComplianceFramework.CIS)
        assert report.compliance_score < 100.0


# ─── Remediation ────────────────────────────────────────────────────────────

class TestRemediation:
    """Tests for generate_remediation function."""

    def test_s3_public_access_remediation(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        remediations = generate_remediation(findings)
        assert len(remediations) > 0
        assert any("public" in r.action.lower() for r in remediations)

    def test_security_group_remediation(self, security_group_open):
        findings = assess_resource(security_group_open)
        remediations = generate_remediation(findings)
        assert any("0.0.0.0/0" in r.action for r in remediations)

    def test_iam_admin_remediation(self, iam_policy_admin):
        findings = assess_resource(iam_policy_admin)
        remediations = generate_remediation(findings)
        assert any("*" in r.action for r in remediations)

    def test_remediation_has_required_fields(self, s3_bucket_public):
        findings = assess_resource(s3_bucket_public)
        remediations = generate_remediation(findings)
        for r in remediations:
            assert r.finding_id
            assert r.action
            assert r.automatable in (True, False)

    def test_no_findings_no_remediation(self, s3_bucket_secure):
        findings = assess_resource(s3_bucket_secure)
        remediations = generate_remediation(findings)
        assert remediations == []


# ─── CSPMEngine Integration ────────────────────────────────────────────────

class TestCSPMEngine:
    """Tests for the CSPMEngine class."""

    def test_engine_assess_multiple_resources(self, engine, s3_bucket_public, security_group_open):
        findings = engine.assess([s3_bucket_public, security_group_open])
        assert len(findings) > 0

    def test_engine_compliance_report(self, engine, s3_bucket_public):
        findings = engine.assess([s3_bucket_public])
        report = engine.compliance_report(findings, ComplianceFramework.CIS)
        assert report.framework == ComplianceFramework.CIS

    def test_engine_full_pipeline(self, engine, s3_bucket_public):
        findings = engine.assess([s3_bucket_public])
        report = engine.compliance_report(findings, ComplianceFramework.CIS)
        remediations = engine.remediate(findings)
        assert len(findings) > 0
        assert report.compliance_score < 100.0
        assert len(remediations) > 0

    def test_engine_empty_resources(self, engine):
        findings = engine.assess([])
        assert findings == []
