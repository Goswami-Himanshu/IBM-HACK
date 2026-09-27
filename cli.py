"""
BobSpec-Provenance Standalone CLI
Enables automated CI/CD pipeline auditing, patch generation, and compliance verification.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bob_verifier.config import SPECS_DIR, CODEBASE_DIR
from bob_verifier.ingestion.spec_generator import generate_enterprise_specs
from bob_verifier.ingestion.pdf_parser import SpecPDFParser
from bob_verifier.ingestion.rule_extractor import SpecRuleExtractor
from bob_verifier.audit.scanner import CodebaseScanner
from bob_verifier.agents.bob_orchestrator import BobOrchestrator
from bob_verifier.patcher.patch_applier import PatchApplier
from bob_verifier.reporting.report_generator import ReportGenerator
from bob_verifier.ledger.provenance_ledger import ProvenanceLedger


def main():
    parser = argparse.ArgumentParser(
        description="BobSpec-Provenance: Autonomous Spec-to-Code Compliance Verifier (IBM Bob 2.0)"
    )
    parser.add_argument("--spec", type=str, default="", help="Path to architectural PDF or standard")
    parser.add_argument("--target", type=str, default=str(CODEBASE_DIR), help="Path to codebase directory")
    parser.add_argument("--patch", action="store_true", help="Apply synthesized patches automatically")
    parser.add_argument("--report", action="store_true", default=True, help="Generate PDF, HTML, and JSON reports")
    parser.add_argument("--serve", action="store_true", help="Launch the interactive web dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Web server port")
    parser.add_argument("--verify-ledger", action="store_true", help="Verify provenance ledger chain integrity and exit")

    args = parser.parse_args()

    # Shared ledger instance
    ledger = ProvenanceLedger()

    # Verify-only mode
    if args.verify_ledger:
        result = ledger.verify_chain()
        status = "✅ VALID" if result["valid"] else "❌ COMPROMISED"
        print(f"\nProvenance Ledger Chain Integrity: {status}")
        print(f"Total entries: {result['entryCount']}")
        if result["breaks"]:
            print("Breaks detected:")
            for b in result["breaks"]:
                print(f"  - Seq {b['seq']}: {b['reason']}")
        return

    if args.serve:
        import uvicorn
        print(f"Launching BobSpec-Provenance Web Dashboard on http://localhost:{args.port}...")
        uvicorn.run("bob_verifier.web.app:app", host="127.0.0.1", port=args.port, reload=False)
        return

    # 1. Spec handling
    if not args.spec:
        specs = generate_enterprise_specs()
        spec_path = specs[0]
    else:
        spec_path = Path(args.spec)

    print(f"\n=================================================================")
    print(f"  BobSpec-Provenance: Autonomous Compliance Verifier (Bob 2.0)")
    print(f"=================================================================")
    print(f"Ingesting Architecture Spec: {spec_path.name}")

    pdf_parser = SpecPDFParser(spec_path)
    doc_data = pdf_parser.extract_full_content()
    rule_extractor = SpecRuleExtractor()
    rules = rule_extractor.extract_rules(doc_data)
    print(f"-> Extracted {len(rules)} compliance rules across 4 domains.")

    # 2. Codebase Audit
    target_dir = Path(args.target)
    print(f"Auditing Target Codebase: {target_dir}")
    scanner = CodebaseScanner(target_dir, rules)
    violations, metrics = scanner.scan()
    print(f"-> Files Scanned: {metrics['files_scanned']}")
    print(f"-> Violations Found: {len(violations)}")
    print(f"-> Compliance Adherence Score: {metrics['compliance_score']}% [{metrics['overall_risk']}]")

    for v in violations:
        print(f"   [{v.severity.value}] {v.rule_id} at {Path(v.file_path).name}:{v.line_start} - {v.title}")

    # 3. Bob 2.0 Orchestrator (auto-logs to provenance ledger)
    orchestrator = BobOrchestrator(ledger=ledger)
    dag = orchestrator.execute_agent_mode(spec_path.name, rules, violations, metrics["compliance_score"])
    print(f"\nBob 2.0 Orchestration (Agent Mode):")
    for sub in dag.subagents:
        print(f"   * {sub.name} [{sub.domain.value}]: {sub.patches_generated} patches ({sub.tool_calls_count} tool calls in {sub.execution_time_ms}ms)")

    # 4. Patch Application
    if args.patch and dag.patches:
        print("\nApplying Targeted Patches and Re-Verifying...")
        applier = PatchApplier(ledger=ledger)
        success, new_score, new_metrics = applier.apply_all_and_verify(dag.patches, target_dir, rules)
        dag.post_patch_score = new_score
        print(f"-> Post-Patch Compliance Adherence Score: {new_score}% [{new_metrics['overall_risk']}]")
        if success:
            print("-> SUCCESS: Codebase is 100% compliant with enterprise architecture!")

    # 5. Reports
    if args.report:
        reporter = ReportGenerator(ledger=ledger)
        pdf_file = reporter.generate_pdf_report(dag, metrics)
        html_file = reporter.generate_html_report(dag, metrics)
        json_file = reporter.generate_watsonx_manifest(dag, metrics)
        print(f"\nAudit Reports Generated:")
        print(f"   - PDF:      {pdf_file}")
        print(f"   - HTML:     {html_file}")
        print(f"   - JSON:     {json_file}")
        print(f"   - watsonx Signature: {dag.audit_hash}")

    # 6. Show ledger summary
    chain = ledger.verify_chain()
    print(f"\nProvenance Ledger: {chain['entryCount']} entries | Chain: {'✅ VALID' if chain['valid'] else '❌ COMPROMISED'}")
    print(f"   Ledger file: {ledger.file_path}")
    print("\nCompliance verification process finished successfully.\n")


if __name__ == "__main__":
    main()
