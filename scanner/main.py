import os
import sys

# Allow `database.*` imports when running with PYTHONPATH=scanner:project_root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.ec2_analyzer import EC2Analyzer
from analyzers.iam_analyzer import IAMAnalyzer
from analyzers.s3_analyzer import S3Analyzer
from services.ec2_scanner import EC2Scanner
from services.iam_scanner import IAMScanner
from services.s3_scanner import S3Scanner
from services.risk_engine import RiskEngine
from services.ai_explainer import AIExplainer

from database.persistence import persist_scan


def run_scan():
    print("AWS Security Scanner")
    print("====================")

    # ── Scan ──────────────────────────────────────────────────────────────
    s3_scanner = S3Scanner()
    s3_scan_results = s3_scanner.scan()
    print(f"\nS3 Resources Found:  {len(s3_scan_results)}")

    ec2_scanner = EC2Scanner()
    ec2_scan_results = ec2_scanner.scan()
    print(f"EC2 Resources Found: {len(ec2_scan_results)}")

    iam_scanner = IAMScanner()
    iam_scan_results = iam_scanner.scan()
    print(f"IAM Users Found:     {len(iam_scan_results)}")

    all_scan_results = s3_scan_results + ec2_scan_results + iam_scan_results

    # ── Analyze ───────────────────────────────────────────────────────────
    s3_findings  = S3Analyzer().analyze(s3_scan_results)
    ec2_findings = EC2Analyzer().analyze(ec2_scan_results)
    iam_findings = IAMAnalyzer().analyze(iam_scan_results)

    all_findings = s3_findings + ec2_findings + iam_findings

    # ── Score ─────────────────────────────────────────────────────────────
    risk_engine = RiskEngine()
    calculated_findings = risk_engine.calculate_findings(all_findings)

    # ── Print findings ────────────────────────────────────────────────────
    print("\nSecurity Findings")
    print("-----------------")
    for finding in all_findings:
        print(f"\nRule:     {finding.rule_id}")
        print(f"Service:  {finding.service}")
        print(f"Resource: {finding.resource_id}")
        print(f"Severity: {finding.severity}")
        print(f"Status:   {finding.status}")
        print(f"Message:  {finding.message}")

    # ── Calculate and display risk score ──────────────────────────────────
    total_risk_score = sum(f.get("risk_score", 0) for f in calculated_findings)
    print(f"\nRisk Score: {total_risk_score}")

    # ── AI Explanations (print-only; scanner results are unchanged) ───────
    ai_explainer = AIExplainer()

    print("\nAI Security Explanations")
    print("=======================")
    if ai_explainer.llm_enabled:
        print("Using Groq for FAIL findings. Scanner status/severity are not modified.")
    else:
        print("Using local templates. Add GROQ_API_KEY to .env for LLM reasoning.")

    resources_by_key = {
        (result.service, result.resource_id): result
        for result in all_scan_results
    }

    sorted_findings = sorted(
        zip(all_findings, calculated_findings),
        key=lambda x: x[1].get("risk_score", 0),
        reverse=True,
    )

    for finding, calc_finding in sorted_findings:
        print(f"\n[{finding.rule_id}] {finding.resource_id}")

        if finding.status == "PASS":
            print("✅ Status: PASS (No issue detected)")
            continue

        scan_result = resources_by_key.get((finding.service, finding.resource_id))
        explanation = ai_explainer.explain_finding(
            finding,
            configuration=scan_result.configuration if scan_result else {},
            region=scan_result.region if scan_result else None,
            risk_score=calc_finding.get("risk_score", 0),
        )

        if explanation:
            print(explanation)
        else:
            print(f"Status: {finding.status}")
            print(f"Message: {finding.message}")

    # ── Persist to Supabase ───────────────────────────────────────────────
    print("\nPersisting to database...")
    scan = persist_scan(
        scan_results=all_scan_results,
        calculated_findings=calculated_findings,
    )
    print(f"✅ Scan saved!  scan_id={scan.id}")
    print(f"   Resources:   {scan.total_resources}")
    print(f"   Findings:    {scan.total_findings}")
    print(f"   Risk Score:  {scan.total_risk_score}")

    return {
        "scan_id": str(scan.id),
        "total_resources": scan.total_resources,
        "total_findings": scan.total_findings,
        "risk_score": scan.total_risk_score,
        "findings": [
            {
                "rule_id": f.rule_id,
                "service": f.service,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "status": f.status,
                "message": f.message,
            }
            for f in all_findings
        ],
    }

if __name__ == "__main__":
    run_scan()
