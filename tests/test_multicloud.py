"""Tests for multi-cloud posture management, compliance automation, and remediation."""
import pytest
from src.cyber.multicloud import (
    CloudProvider,
    MultiCloudResource,
    PostureManager,
    ComplianceAutomation,
    RemediationWorkflow,
    RemediationStatus,
    PostureReport,
    ConsolidatedComplianceReport,
)


# ─── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def aws_s3_public():
    return MultiCloudResource(
        cloud_provider=CloudProvider.AWS,
        resource_type="aws_s3_bucket",
        resource_id="aws-public-bucket",
        config={"public_access_block": False, "encryption": None, "versioning": False},
    )


@pytest.fixture
def azure_storage_open():
    return MultiCloudResource(
        cloud_provider=CloudProvider.AZURE,
        resource_type="azure_storage_account",
        resource_id="azure-open-storage",
        config={"public_access": True, "encryption": None, "network_rules": "AllowAll"},
    )


@pytest.fixture
def gcp_storage_public():
    return MultiCloudResource(
        cloud_provider=CloudProvider.GCP,
        resource_type="gcp_storage_bucket",
        resource_id="gcp-public-bucket",
        config={"public_access": True, "encryption": None, "versioning": False},
    )


@pytest.fixture
def aws_sg_open():
    return MultiCloudResource(
        cloud_provider=CloudProvider.AWS,
        resource_type="aws_security_group",
        resource_id="aws-sg-open",
        config={
            "ingress_rules": [
                {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
            ]
        },
    )


@pytest.fixture
def secure_resources():
    return [
        MultiCloudResource(
            cloud_provider=CloudProvider.AWS,
            resource_type="aws_s3_bucket",
            resource_id="aws-secure-bucket",
            config={"public_access_block": True, "encryption": "AES256", "versioning": True},
        ),
        MultiCloudResource(
            cloud_provider=CloudProvider.AZURE,
            resource_type="azure_storage_account",
            resource_id="azure-secure-storage",
            config={"public_access": False, "encryption": "AES256", "network_rules": "DenyAll"},
        ),
    ]


@pytest.fixture
def posture_manager():
    return PostureManager()


@pytest.fixture
def compliance_automation():
    return ComplianceAutomation()


@pytest.fixture
def remediation_workflow():
    return RemediationWorkflow()


# ─── MultiCloudResource ─────────────────────────────────────────────────────

class TestMultiCloudResource:
    """Tests for MultiCloudResource dataclass."""

    def test_has_cloud_provider(self, aws_s3_public):
        assert aws_s3_public.cloud_provider == CloudProvider.AWS

    def test_has_resource_type(self, aws_s3_public):
        assert aws_s3_public.resource_type == "aws_s3_bucket"

    def test_has_resource_id(self, aws_s3_public):
        assert aws_s3_public.resource_id == "aws-public-bucket"

    def test_has_config(self, aws_s3_public):
        assert aws_s3_public.config["public_access_block"] is False

    def test_azure_resource(self, azure_storage_open):
        assert azure_storage_open.cloud_provider == CloudProvider.AZURE

    def test_gcp_resource(self, gcp_storage_public):
        assert gcp_storage_public.cloud_provider == CloudProvider.GCP


# ─── PostureManager ─────────────────────────────────────────────────────────

class TestPostureManager:
    """Tests for PostureManager class."""

    def test_assess_single_cloud_resource(self, posture_manager, aws_s3_public):
        findings = posture_manager.assess([aws_s3_public])
        assert len(findings) > 0

    def test_assess_multiple_clouds(self, posture_manager, aws_s3_public, azure_storage_open, gcp_storage_public):
        findings = posture_manager.assess([aws_s3_public, azure_storage_open, gcp_storage_public])
        assert len(findings) > 0

    def test_filter_by_cloud_provider(self, posture_manager, aws_s3_public, azure_storage_open):
        findings = posture_manager.assess([aws_s3_public, azure_storage_open])
        aws_findings = [f for f in findings if f.get("cloud_provider") == "AWS"]
        azure_findings = [f for f in findings if f.get("cloud_provider") == "AZURE"]
        assert len(aws_findings) > 0
        assert len(azure_findings) > 0

    def test_secure_resources_no_findings(self, posture_manager, secure_resources):
        findings = posture_manager.assess(secure_resources)
        assert len(findings) == 0

    def test_empty_resources_returns_empty(self, posture_manager):
        findings = posture_manager.assess([])
        assert findings == []

    def test_posture_report_generation(self, posture_manager, aws_s3_public, azure_storage_open):
        findings = posture_manager.assess([aws_s3_public, azure_storage_open])
        report = posture_manager.generate_posture_report(findings)
        assert isinstance(report, PostureReport)
        assert report.total_findings == len(findings)
        assert report.cloud_providers == {"AWS", "AZURE"}

    def test_posture_report_by_severity(self, posture_manager, aws_s3_public):
        findings = posture_manager.assess([aws_s3_public])
        report = posture_manager.generate_posture_report(findings)
        assert report.critical_count > 0

    def test_compare_posture_across_clouds(self, posture_manager, aws_s3_public, azure_storage_open):
        findings = posture_manager.assess([aws_s3_public, azure_storage_open])
        comparison = posture_manager.compare_posture(findings)
        assert "AWS" in comparison
        assert "AZURE" in comparison
        assert comparison["AWS"] > 0
        assert comparison["AZURE"] > 0


# ─── ComplianceAutomation ───────────────────────────────────────────────────

class TestComplianceAutomation:
    """Tests for ComplianceAutomation class."""

    def test_run_compliance_single_framework(self, compliance_automation, aws_s3_public):
        findings = [{"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"}]
        report = compliance_automation.run_compliance(findings, "CIS")
        assert report["framework"] == "CIS"
        assert report["total_findings"] == 1

    def test_run_compliance_multiple_frameworks(self, compliance_automation, aws_s3_public):
        findings = [{"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"}]
        report = compliance_automation.run_compliance(findings, ["CIS", "NIST", "PCI_DSS"])
        assert isinstance(report, ConsolidatedComplianceReport)
        assert len(report.frameworks) == 3

    def test_consolidated_report_has_scores(self, compliance_automation, aws_s3_public):
        findings = [{"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"}]
        report = compliance_automation.run_compliance(findings, ["CIS", "NIST"])
        assert report.scores["CIS"] <= 100.0
        assert report.scores["NIST"] <= 100.0

    def test_compliance_detects_drift(self, compliance_automation, aws_s3_public):
        findings_before = []
        findings_after = [{"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"}]
        drift = compliance_automation.detect_drift(findings_before, findings_after)
        assert drift is True

    def test_no_drift_when_unchanged(self, compliance_automation, aws_s3_public):
        findings = [{"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"}]
        drift = compliance_automation.detect_drift(findings, findings)
        assert drift is False

    def test_compliance_score_decreases_with_findings(self, compliance_automation, aws_s3_public):
        findings = [
            {"cloud_provider": "AWS", "severity": "CRITICAL", "rule_id": "S3-001"},
            {"cloud_provider": "AWS", "severity": "HIGH", "rule_id": "S3-002"},
        ]
        report = compliance_automation.run_compliance(findings, "CIS")
        assert report["compliance_score"] < 100.0


# ─── RemediationWorkflow ────────────────────────────────────────────────────

class TestRemediationWorkflow:
    """Tests for RemediationWorkflow class."""

    def test_create_workflow(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        assert workflow["name"] == "test-workflow"
        assert workflow["status"] == RemediationStatus.PENDING

    def test_add_remediation_step(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        step = remediation_workflow.add_step(workflow, "Enable public access block", "aws-public-bucket")
        assert step["action"] == "Enable public access block"
        assert step["resource_id"] == "aws-public-bucket"
        assert step["status"] == RemediationStatus.PENDING

    def test_execute_workflow(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        remediation_workflow.add_step(workflow, "Enable public access block", "aws-public-bucket")
        result = remediation_workflow.execute_workflow(workflow)
        assert result["status"] == RemediationStatus.COMPLETED

    def test_workflow_with_multiple_steps(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        remediation_workflow.add_step(workflow, "Step 1", "resource-1")
        remediation_workflow.add_step(workflow, "Step 2", "resource-2")
        result = remediation_workflow.execute_workflow(workflow)
        assert result["status"] == RemediationStatus.COMPLETED
        assert len(result["steps"]) == 2

    def test_workflow_rollback(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        remediation_workflow.add_step(workflow, "Step 1", "resource-1")
        remediation_workflow.execute_workflow(workflow)
        result = remediation_workflow.rollback_workflow(workflow)
        assert result["status"] == RemediationStatus.ROLLED_BACK

    def test_workflow_tracks_failed_steps(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        remediation_workflow.add_step(workflow, "Step 1", "resource-1")
        remediation_workflow.add_step(workflow, "Step 2", "resource-2")
        workflow["steps"][0]["status"] = RemediationStatus.FAILED
        result = remediation_workflow.execute_workflow(workflow)
        assert result["status"] == RemediationStatus.PARTIAL

    def test_workflow_respects_dependencies(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        step1 = remediation_workflow.add_step(workflow, "Step 1", "resource-1")
        step2 = remediation_workflow.add_step(workflow, "Step 2", "resource-2", depends_on=[step1["id"]])
        assert step2["depends_on"] == [step1["id"]]

    def test_empty_workflow_completes(self, remediation_workflow):
        workflow = remediation_workflow.create_workflow("test-workflow", [])
        result = remediation_workflow.execute_workflow(workflow)
        assert result["status"] == RemediationStatus.COMPLETED
