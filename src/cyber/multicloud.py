"""Multi-cloud posture management, compliance automation, and remediation workflows."""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Set
import uuid


class CloudProvider(Enum):
    """Supported cloud providers."""
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class RemediationStatus(Enum):
    """Status of a remediation workflow or step."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    PARTIAL = "partial"


@dataclass
class MultiCloudResource:
    """Represents a cloud resource across multiple cloud providers."""
    cloud_provider: CloudProvider
    resource_type: str
    resource_id: str
    config: dict = field(default_factory=dict)


@dataclass
class PostureReport:
    """Represents a posture assessment report."""
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    cloud_providers: Set[str] = field(default_factory=set)


@dataclass
class ConsolidatedComplianceReport:
    """Represents a consolidated compliance report across multiple frameworks."""
    frameworks: List[str]
    scores: Dict[str, float]
    total_findings: int


def _assess_aws_s3(config: dict) -> List[dict]:
    """Assess AWS S3 bucket configuration."""
    findings = []
    if not config.get("public_access_block", False):
        findings.append({
            "cloud_provider": "AWS",
            "resource_type": "aws_s3_bucket",
            "rule_id": "S3-001",
            "severity": "CRITICAL",
            "description": "S3 bucket has public access enabled",
        })
    if not config.get("encryption"):
        findings.append({
            "cloud_provider": "AWS",
            "resource_type": "aws_s3_bucket",
            "rule_id": "S3-002",
            "severity": "HIGH",
            "description": "S3 bucket does not have encryption enabled",
        })
    if not config.get("versioning", False):
        findings.append({
            "cloud_provider": "AWS",
            "resource_type": "aws_s3_bucket",
            "rule_id": "S3-003",
            "severity": "MEDIUM",
            "description": "S3 bucket does not have versioning enabled",
        })
    return findings


def _assess_azure_storage(config: dict) -> List[dict]:
    """Assess Azure Storage Account configuration."""
    findings = []
    if config.get("public_access", False):
        findings.append({
            "cloud_provider": "AZURE",
            "resource_type": "azure_storage_account",
            "rule_id": "AZ-001",
            "severity": "CRITICAL",
            "description": "Storage account has public access enabled",
        })
    if not config.get("encryption"):
        findings.append({
            "cloud_provider": "AZURE",
            "resource_type": "azure_storage_account",
            "rule_id": "AZ-002",
            "severity": "HIGH",
            "description": "Storage account does not have encryption enabled",
        })
    if config.get("network_rules") == "AllowAll":
        findings.append({
            "cloud_provider": "AZURE",
            "resource_type": "azure_storage_account",
            "rule_id": "AZ-003",
            "severity": "CRITICAL",
            "description": "Storage account allows all network traffic",
        })
    return findings


def _assess_gcp_storage(config: dict) -> List[dict]:
    """Assess GCP Storage Bucket configuration."""
    findings = []
    if config.get("public_access", False):
        findings.append({
            "cloud_provider": "GCP",
            "resource_type": "gcp_storage_bucket",
            "rule_id": "GCP-001",
            "severity": "CRITICAL",
            "description": "GCP bucket has public access enabled",
        })
    if not config.get("encryption"):
        findings.append({
            "cloud_provider": "GCP",
            "resource_type": "gcp_storage_bucket",
            "rule_id": "GCP-002",
            "severity": "HIGH",
            "description": "GCP bucket does not have encryption enabled",
        })
    if not config.get("versioning", False):
        findings.append({
            "cloud_provider": "GCP",
            "resource_type": "gcp_storage_bucket",
            "rule_id": "GCP-003",
            "severity": "MEDIUM",
            "description": "GCP bucket does not have versioning enabled",
        })
    return findings


def _assess_aws_security_group(config: dict) -> List[dict]:
    """Assess AWS Security Group configuration."""
    findings = []
    for rule in config.get("ingress_rules", []):
        if rule.get("cidr") == "0.0.0.0/0":
            findings.append({
                "cloud_provider": "AWS",
                "resource_type": "aws_security_group",
                "rule_id": "SG-001",
                "severity": "CRITICAL",
                "description": f"Security group allows inbound traffic from 0.0.0.0/0 on port {rule.get('port')}",
            })
    return findings


_ASSESSORS = {
    "aws_s3_bucket": _assess_aws_s3,
    "azure_storage_account": _assess_azure_storage,
    "gcp_storage_bucket": _assess_gcp_storage,
    "aws_security_group": _assess_aws_security_group,
}


class PostureManager:
    """Multi-cloud posture management engine."""

    def assess(self, resources: List[MultiCloudResource]) -> List[dict]:
        """Assess multiple cloud resources across providers."""
        findings = []
        for resource in resources:
            assessor = _ASSESSORS.get(resource.resource_type)
            if assessor:
                findings.extend(assessor(resource.config))
        return findings

    def generate_posture_report(self, findings: List[dict]) -> PostureReport:
        """Generate a posture report from findings."""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        providers = set(f.get("cloud_provider", "") for f in findings)
        return PostureReport(
            total_findings=len(findings),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            cloud_providers=providers,
        )

    def compare_posture(self, findings: List[dict]) -> Dict[str, int]:
        """Compare posture across cloud providers."""
        comparison = {}
        for f in findings:
            provider = f.get("cloud_provider", "UNKNOWN")
            comparison[provider] = comparison.get(provider, 0) + 1
        return comparison


class ComplianceAutomation:
    """Compliance automation engine."""

    def run_compliance(self, findings: List[dict], frameworks) -> Any:
        """Run compliance checks against one or more frameworks."""
        if isinstance(frameworks, str):
            frameworks = [frameworks]

        if len(frameworks) == 1:
            total = len(findings)
            score = max(0.0, 100.0 - total * 10.0)
            return {
                "framework": frameworks[0],
                "total_findings": total,
                "compliant_count": 0,
                "non_compliant_count": total,
                "compliance_score": score,
            }

        scores = {}
        for fw in frameworks:
            total = len(findings)
            scores[fw] = max(0.0, 100.0 - total * 10.0)

        return ConsolidatedComplianceReport(
            frameworks=frameworks,
            scores=scores,
            total_findings=len(findings),
        )

    def detect_drift(self, findings_before: List[dict], findings_after: List[dict]) -> bool:
        """Detect compliance drift between two assessment snapshots."""
        return findings_before != findings_after


class RemediationWorkflow:
    """Remediation workflow engine."""

    def create_workflow(self, name: str, steps: List[dict]) -> dict:
        """Create a new remediation workflow."""
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "status": RemediationStatus.PENDING,
            "steps": steps,
        }

    def add_step(self, workflow: dict, action: str, resource_id: str, depends_on: Optional[List[str]] = None) -> dict:
        """Add a remediation step to a workflow."""
        step = {
            "id": str(uuid.uuid4()),
            "action": action,
            "resource_id": resource_id,
            "status": RemediationStatus.PENDING,
            "depends_on": depends_on or [],
        }
        workflow["steps"].append(step)
        return step

    def execute_workflow(self, workflow: dict) -> dict:
        """Execute all steps in a workflow."""
        failed = False
        for step in workflow["steps"]:
            if step["status"] == RemediationStatus.FAILED:
                failed = True
            else:
                step["status"] = RemediationStatus.COMPLETED

        if failed:
            workflow["status"] = RemediationStatus.PARTIAL
        else:
            workflow["status"] = RemediationStatus.COMPLETED

        return workflow

    def rollback_workflow(self, workflow: dict) -> dict:
        """Rollback all steps in a workflow."""
        for step in workflow["steps"]:
            step["status"] = RemediationStatus.ROLLED_BACK
        workflow["status"] = RemediationStatus.ROLLED_BACK
        return workflow
