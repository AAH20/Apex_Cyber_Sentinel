"""CSPM — Cloud Security Posture Management.

Cloud configuration assessment, compliance checking, and remediation.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    CIS = "CIS"
    NIST = "NIST"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"


@dataclass
class CloudResource:
    """Represents a cloud resource with its configuration."""
    resource_type: str
    resource_id: str
    config: dict = field(default_factory=dict)


@dataclass
class Finding:
    """Represents a security finding from assessment."""
    resource_id: str
    rule_id: str
    severity: str
    description: str


@dataclass
class Remediation:
    """Represents a remediation action for a finding."""
    finding_id: str
    action: str
    automatable: bool


@dataclass
class ComplianceReport:
    """Represents a compliance report."""
    framework: ComplianceFramework
    total_findings: int
    compliant_count: int
    non_compliant_count: int
    compliance_score: float


def assess_resource(resource: CloudResource) -> List[Finding]:
    """Assess a cloud resource for security misconfigurations.

    Args:
        resource: The cloud resource to assess.

    Returns:
        List of findings (empty if resource is secure or type is unknown).
    """
    findings: List[Finding] = []

    if resource.resource_type == "aws_s3_bucket":
        if not resource.config.get("public_access_block", False):
            findings.append(Finding(
                resource_id=resource.resource_id,
                rule_id="S3-001",
                severity="CRITICAL",
                description="S3 bucket has public access enabled",
            ))
        if not resource.config.get("encryption"):
            findings.append(Finding(
                resource_id=resource.resource_id,
                rule_id="S3-002",
                severity="HIGH",
                description="S3 bucket does not have encryption enabled",
            ))
        if not resource.config.get("versioning", False):
            findings.append(Finding(
                resource_id=resource.resource_id,
                rule_id="S3-003",
                severity="MEDIUM",
                description="S3 bucket does not have versioning enabled",
            ))

    elif resource.resource_type == "aws_security_group":
        for rule in resource.config.get("ingress_rules", []):
            if rule.get("cidr") == "0.0.0.0/0":
                findings.append(Finding(
                    resource_id=resource.resource_id,
                    rule_id="SG-001",
                    severity="CRITICAL",
                    description=(
                        f"Security group allows inbound traffic "
                        f"from 0.0.0.0/0 on port {rule.get('port')}"
                    ),
                ))

    elif resource.resource_type == "aws_iam_policy":
        policy_doc = resource.config.get("policy_document", {})
        if policy_doc.get("Action") == "*":
            findings.append(Finding(
                resource_id=resource.resource_id,
                rule_id="IAM-001",
                severity="CRITICAL",
                description="IAM policy allows admin privileges (*)",
            ))

    return findings


def check_compliance(
    findings: List[Finding],
    framework: ComplianceFramework,
) -> ComplianceReport:
    """Generate a compliance report for findings against a framework.

    Args:
        findings: List of security findings.
        framework: Compliance framework to check against.

    Returns:
        ComplianceReport with score and counts.
    """
    total = len(findings)
    non_compliant = total
    compliant = 0
    score = max(0.0, 100.0 - total * 10.0)

    return ComplianceReport(
        framework=framework,
        total_findings=total,
        compliant_count=compliant,
        non_compliant_count=non_compliant,
        compliance_score=score,
    )


def generate_remediation(findings: List[Finding]) -> List[Remediation]:
    """Generate remediation actions for findings.

    Args:
        findings: List of security findings.

    Returns:
        List of remediation actions.
    """
    remediations: List[Remediation] = []

    for finding in findings:
        if finding.rule_id == "S3-001":
            remediations.append(Remediation(
                finding_id=finding.rule_id,
                action="Enable public access block on S3 bucket",
                automatable=True,
            ))
        elif finding.rule_id == "S3-002":
            remediations.append(Remediation(
                finding_id=finding.rule_id,
                action="Enable encryption on S3 bucket",
                automatable=True,
            ))
        elif finding.rule_id == "S3-003":
            remediations.append(Remediation(
                finding_id=finding.rule_id,
                action="Enable versioning on S3 bucket",
                automatable=True,
            ))
        elif finding.rule_id == "SG-001":
            remediations.append(Remediation(
                finding_id=finding.rule_id,
                action="Remove 0.0.0.0/0 from security group ingress rules",
                automatable=True,
            ))
        elif finding.rule_id == "IAM-001":
            remediations.append(Remediation(
                finding_id=finding.rule_id,
                action="Restrict IAM policy actions from * to least privilege",
                automatable=False,
            ))

    return remediations


class CSPMEngine:
    """Cloud Security Posture Management engine.

    Provides assessment, compliance reporting, and remediation
    for cloud resources.
    """

    def assess(self, resources: List[CloudResource]) -> List[Finding]:
        """Assess multiple cloud resources.

        Args:
            resources: List of cloud resources to assess.

        Returns:
            Combined list of findings from all resources.
        """
        findings: List[Finding] = []
        for resource in resources:
            findings.extend(assess_resource(resource))
        return findings

    def compliance_report(
        self,
        findings: List[Finding],
        framework: ComplianceFramework,
    ) -> ComplianceReport:
        """Generate a compliance report.

        Args:
            findings: List of security findings.
            framework: Compliance framework to check against.

        Returns:
            ComplianceReport.
        """
        return check_compliance(findings, framework)

    def remediate(self, findings: List[Finding]) -> List[Remediation]:
        """Generate remediation actions for findings.

        Args:
            findings: List of security findings.

        Returns:
            List of remediation actions.
        """
        return generate_remediation(findings)
