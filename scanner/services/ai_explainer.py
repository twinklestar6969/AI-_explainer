"""
Security explainer for AWS findings.

Uses Groq for structured JSON reasoning when configured. Falls back to a
local rule knowledge base if the API is disabled, missing, or fails.

The scanner rules remain the source of truth: this module never changes
status, severity, or invents resources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from models.finding import Finding
from services.llm_client import groq_client_from_env

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")

SYSTEM_PROMPT = """You are an AWS cloud security analyst.

You receive a deterministic scanner finding and the collected AWS resource
configuration. Your job is to explain the finding, assess impact, assign an
advisory priority, and suggest remediation.

Hard rules:
- Treat the scanner fields (rule_id, status, severity, message, resource_id)
  as ground truth. Never change status or severity.
- Do not invent AWS resources, accounts, regions, IPs, policies, or
  configuration values that are not in the evidence.
- If evidence is incomplete, say so instead of guessing.
- Do not recommend destructive or mutating AWS API calls as if they already
  ran. Suggest operator steps only.
- Return a single JSON object with exactly these keys:
  what_is_wrong (string),
  why_it_matters (string),
  security_impact (string),
  blast_radius (string),
  remediation_steps (array of strings),
  priority (one of CRITICAL, HIGH, MEDIUM, LOW),
  confidence (one of high, medium, low).
Priority is advisory only and must not contradict the scanner severity
without explaining the nuance in blast_radius.
"""

SECURITY_RULES = {
    "S3_PUBLIC_ACCESS": {
        "what_is_wrong": (
            "The S3 bucket does not have all Public Access Block settings enabled. "
            "This means the bucket's access control could potentially allow public access "
            "through bucket policies or Access Control Lists (ACLs)."
        ),
        "why_it_matters": (
            "Public access to S3 buckets can expose sensitive data, intellectual property, "
            "and personally identifiable information (PII) to unauthorized users on the internet."
        ),
        "security_impact": (
            "Data breach: Sensitive files could be downloaded by anyone with an internet connection. "
            "Compliance violation: Regulatory frameworks like GDPR, HIPAA, and PCI-DSS require "
            "strict access controls. Reputational damage: Public exposure of customer data leads to "
            "loss of trust and brand damage."
        ),
        "remediation": (
            "1. Go to the S3 bucket in AWS Console\n"
            "2. Click 'Permissions' tab → 'Block public access (bucket settings)'\n"
            "3. Enable all four Block Public Access settings\n"
            "4. Click 'Save changes'\n"
            "5. Verify no bucket policies grant public access"
        ),
        "priority": "HIGH",
    },
    "S3_VERSIONING": {
        "what_is_wrong": (
            "S3 bucket versioning is not enabled. This means only one version of each object is kept, "
            "and accidentally deleted or overwritten files cannot be recovered."
        ),
        "why_it_matters": (
            "Versioning provides protection against accidental deletions and modifications. "
            "It allows you to restore previous versions of objects and maintain a complete history of changes."
        ),
        "security_impact": (
            "Data loss: Accidental deletion of critical files cannot be recovered. "
            "Ransomware risk: Attackers could delete files without any recovery option. "
            "Compliance requirements: Many regulations require version history for audit purposes."
        ),
        "remediation": (
            "1. Go to the S3 bucket in AWS Console\n"
            "2. Click 'Properties' tab\n"
            "3. Find 'Versioning' section and click 'Edit'\n"
            "4. Select 'Enable' for versioning\n"
            "5. Click 'Save changes'"
        ),
        "priority": "MEDIUM",
    },
    "S3_ENCRYPTION": {
        "what_is_wrong": (
            "S3 bucket encryption is not enabled. Objects are stored without server-side encryption, "
            "meaning data at rest is not protected by encryption."
        ),
        "why_it_matters": (
            "Encryption at rest protects data from unauthorized access if storage media is compromised. "
            "It is a fundamental security best practice and often a compliance requirement."
        ),
        "security_impact": (
            "Data exposure: If the storage medium is physically stolen, data could be readable. "
            "Compliance violation: Frameworks like HIPAA, PCI-DSS, and GDPR require encryption at rest."
        ),
        "remediation": (
            "1. Go to the S3 bucket in AWS Console\n"
            "2. Click 'Properties' tab\n"
            "3. Find 'Default encryption' section and click 'Edit'\n"
            "4. Choose SSE-S3 or SSE-KMS\n"
            "5. Click 'Save changes'"
        ),
        "priority": "MEDIUM",
    },
    "S3_LOGGING": {
        "what_is_wrong": (
            "S3 bucket access logging is not enabled. This means there is no record of who accessed "
            "the bucket, when they accessed it, and what actions they performed."
        ),
        "why_it_matters": (
            "Access logging provides visibility into bucket usage and helps detect unauthorized access attempts. "
            "It is essential for security monitoring, compliance audits, and incident response."
        ),
        "security_impact": (
            "No audit trail: Cannot identify who made changes or when they occurred. "
            "Threat detection: Suspicious access patterns may go unnoticed."
        ),
        "remediation": (
            "1. Go to the S3 bucket in AWS Console\n"
            "2. Click 'Properties' tab\n"
            "3. Find 'Server access logging' and click 'Edit'\n"
            "4. Enable server access logging and choose a target bucket\n"
            "5. Click 'Save changes'"
        ),
        "priority": "MEDIUM",
    },
    "IAM_MFA": {
        "what_is_wrong": (
            "The IAM user does not have Multi-Factor Authentication (MFA) enabled. "
            "This means the user account can be accessed with only a username and password."
        ),
        "why_it_matters": (
            "MFA adds a second layer of security by requiring an additional verification method "
            "beyond the password. Even if credentials are compromised, an attacker cannot access "
            "the account without the second factor."
        ),
        "security_impact": (
            "Account takeover: Stolen credentials alone are sufficient for unauthorized access. "
            "Privilege escalation: Attackers could gain access to AWS resources and cause damage."
        ),
        "remediation": (
            "1. Go to AWS Console → IAM → Users and select the user\n"
            "2. Open the Security credentials tab\n"
            "3. Assign an MFA device (authenticator app or hardware key)\n"
            "4. Complete the setup wizard and test sign-in"
        ),
        "priority": "HIGH",
    },
    "IAM_CONSOLE_MFA": {
        "what_is_wrong": (
            "The IAM user has console access enabled but does not have MFA configured."
        ),
        "why_it_matters": (
            "Console access without MFA poses a security risk for console-based operations."
        ),
        "security_impact": (
            "Console access risk: Administrative operations could be performed by unauthorized users. "
            "Impact depends on the IAM policies attached to the user."
        ),
        "remediation": (
            "1. Enable MFA for this user if console access is required\n"
            "2. If console access is not needed, disable the login profile"
        ),
        "priority": "HIGH",
    },
    "IAM_ACCESS_KEY": {
        "what_is_wrong": (
            "The IAM user has one or more active access keys that can be used to make API calls."
        ),
        "why_it_matters": (
            "If an access key is leaked, an attacker could perform any action the IAM user is permitted to do."
        ),
        "security_impact": (
            "Credential compromise can lead to unauthorized API calls. Prefer IAM roles and short-lived credentials."
        ),
        "remediation": (
            "1. Delete unused access keys\n"
            "2. Rotate keys that are still required\n"
            "3. Prefer IAM roles / STS over long-lived keys\n"
            "4. Monitor usage in CloudTrail"
        ),
        "priority": "MEDIUM",
    },
    "EC2_PUBLIC_IP": {
        "what_is_wrong": (
            "The EC2 instance has a public IPv4 address and is directly reachable from the internet."
        ),
        "why_it_matters": (
            "Public IPs increase the attack surface. Combined with open security groups, they enable remote scanning and exploitation."
        ),
        "security_impact": (
            "Internet-facing instances are more likely to be probed. Compromise risk depends on open ports and software exposed."
        ),
        "remediation": (
            "1. Remove the public IP if internet access is not required\n"
            "2. Use a load balancer, NAT gateway, VPN, or SSM Session Manager instead"
        ),
        "priority": "MEDIUM",
    },
    "EC2_SECURITY_GROUP": {
        "what_is_wrong": (
            "One or more attached security groups may allow unrestricted SSH or RDP from 0.0.0.0/0."
        ),
        "why_it_matters": (
            "Exposing administrative ports to the internet is a common path to instance takeover."
        ),
        "security_impact": (
            "Brute-force and exploit attempts against SSH/RDP become possible from any internet host."
        ),
        "remediation": (
            "1. Remove inbound 0.0.0.0/0 rules for ports 22 and 3389\n"
            "2. Restrict access to trusted CIDRs, a VPN, or a bastion host"
        ),
        "priority": "HIGH",
    },
}


class AIExplainer:
    """Explains FAIL findings with Groq JSON reasoning, or local templates."""

    def __init__(self):
        self._client = groq_client_from_env()
        self.available = True
        self.llm_enabled = self._client is not None

        if self.llm_enabled:
            print(f"✅ Groq security reasoner ready (model={self._client.model})")
        else:
            print(
                "⚠️  Groq not configured — using local rule templates. "
                "Set GROQ_API_KEY in .env to enable LLM explanations."
            )

    def explain_finding(
        self,
        finding: Finding,
        configuration: dict[str, Any] | None = None,
        region: str | None = None,
        risk_score: int | None = None,
    ) -> str:
        if finding.status == "PASS":
            return None

        reasoning = None
        source = "template"

        if self.llm_enabled:
            try:
                reasoning = self._reason_with_llm(
                    finding,
                    configuration=configuration or {},
                    region=region,
                    risk_score=risk_score,
                )
                source = "groq"
            except Exception as exc:
                print(f"   ⚠️  Groq failed for {finding.rule_id} ({exc}); using template fallback")

        if reasoning is None:
            reasoning = self._template_reasoning(finding)
            source = "template"

        return self._format_explanation(
            finding,
            reasoning,
            source=source,
            region=region,
            risk_score=risk_score,
        )

    def _reason_with_llm(
        self,
        finding: Finding,
        configuration: dict[str, Any],
        region: str | None,
        risk_score: int | None,
    ) -> dict[str, Any]:
        payload = {
            "rule_id": finding.rule_id,
            "service": finding.service,
            "resource_id": finding.resource_id,
            "region": region,
            "severity": finding.severity,
            "status": finding.status,
            "message": finding.message,
            "description": finding.description,
            "scanner_remediation": finding.remediation,
            "risk_score": risk_score,
            "configuration": _redact_configuration(configuration),
        }

        user_prompt = (
            "Explain this AWS scanner finding using only the evidence below.\n\n"
            f"{json.dumps(payload, indent=2, default=str)}"
        )

        last_error = None
        for _ in range(2):
            try:
                raw = self._client.complete_json(SYSTEM_PROMPT, user_prompt)
                return _normalize_reasoning(raw, finding)
            except Exception as exc:
                last_error = exc

        raise last_error

    def _template_reasoning(self, finding: Finding) -> dict[str, Any]:
        rule = SECURITY_RULES.get(finding.rule_id)
        if rule:
            steps = [
                line.strip(" -")
                for line in rule["remediation"].splitlines()
                if line.strip()
            ]
            return {
                "what_is_wrong": rule["what_is_wrong"],
                "why_it_matters": rule["why_it_matters"],
                "security_impact": rule["security_impact"],
                "blast_radius": (
                    f"Affects {finding.service.upper()} resource "
                    f"{finding.resource_id} at scanner severity {finding.severity}."
                ),
                "remediation_steps": steps,
                "priority": rule.get("priority", finding.severity),
                "confidence": "high",
            }

        return {
            "what_is_wrong": f"{finding.message}\n\n{finding.description}".strip(),
            "why_it_matters": (
                f"A {finding.severity} finding on {finding.service.upper()} "
                "can increase exposure or weaken controls if left unaddressed."
            ),
            "security_impact": (
                "Impact follows the scanner severity: CRITICAL/HIGH need prompt "
                "attention; MEDIUM/LOW can be scheduled."
            ),
            "blast_radius": f"Limited to resource {finding.resource_id} based on scanner evidence.",
            "remediation_steps": [finding.remediation],
            "priority": finding.severity,
            "confidence": "medium",
        }

    def _format_explanation(
        self,
        finding: Finding,
        reasoning: dict[str, Any],
        *,
        source: str,
        region: str | None,
        risk_score: int | None,
    ) -> str:
        steps = reasoning.get("remediation_steps") or []
        if isinstance(steps, str):
            steps = [steps]
        formatted_steps = []
        for index, step in enumerate(steps, start=1):
            text = str(step).strip()
            if text[:1].isdigit():
                formatted_steps.append(text)
            else:
                formatted_steps.append(f"{index}. {text}")
        remediation_block = "\n".join(formatted_steps) or finding.remediation

        region_line = f"Region: {region}\n" if region else ""
        score_line = f"Risk score (scanner): {risk_score}\n" if risk_score is not None else ""
        source_label = "Groq LLM" if source == "groq" else "local template fallback"

        return f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY FINDING: {finding.rule_id}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Service: {finding.service.upper()}
Resource: {finding.resource_id}
{region_line}Severity (scanner): {finding.severity}
Status (scanner): {finding.status}
{score_line}AI advisory priority: {reasoning.get("priority", finding.severity)}
AI confidence: {reasoning.get("confidence", "medium")}
Explanation source: {source_label}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1️⃣  WHAT IS WRONG?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{reasoning.get("what_is_wrong", finding.message)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2️⃣  WHY IT MATTERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{reasoning.get("why_it_matters", "")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3️⃣  POTENTIAL SECURITY IMPACT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{reasoning.get("security_impact", "")}

Blast radius: {reasoning.get("blast_radius", "Not assessed.")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4️⃣  STEP-BY-STEP REMEDIATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{remediation_block}

Scanner remediation note: {finding.remediation}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""".strip()


def _normalize_reasoning(raw: dict[str, Any], finding: Finding) -> dict[str, Any]:
    steps = raw.get("remediation_steps") or []
    if isinstance(steps, str):
        steps = [steps]
    if not isinstance(steps, list):
        steps = [str(steps)]

    priority = str(raw.get("priority") or finding.severity).upper()
    if priority not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        priority = finding.severity

    confidence = str(raw.get("confidence") or "medium").lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "medium"

    return {
        "what_is_wrong": str(raw.get("what_is_wrong") or finding.message).strip(),
        "why_it_matters": str(raw.get("why_it_matters") or "").strip(),
        "security_impact": str(raw.get("security_impact") or "").strip(),
        "blast_radius": str(raw.get("blast_radius") or "").strip(),
        "remediation_steps": [str(step).strip() for step in steps if str(step).strip()],
        "priority": priority,
        "confidence": confidence,
    }


def _redact_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    redacted = json.loads(json.dumps(configuration, default=str))
    access_keys = redacted.get("access_keys")
    if isinstance(access_keys, list):
        for key in access_keys:
            if isinstance(key, dict) and "access_key_id" in key:
                key["access_key_id"] = "***REDACTED***"
    return redacted
