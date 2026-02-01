import argparse
import sys
import json
import time
from dataclasses import asdict

# Importăm logica lui Ionuț
from inspector import DnssecChainCollector, InspectorTrace

EXPLANATIONS = {
    "SECURE_CHAIN_CANDIDATE": {
        "text": "Lanț Securizat",
        "desc": "Lanțul de încredere de la Root până la domeniu este intact. Semnăturile sunt valide.",
        "severity": "INFO"
    },
    "BROKEN_CHAIN": {
        "text": "Lanț Rupt (BOGUS)",
        "desc": "Validarea a eșuat. O semnătură nu se potrivește sau lipsește o cheie. Datele nu pot fi verificate.",
        "severity": "CRITICAL"
    },
    "INSECURE_DELEGATION": {
        "text": "Nesecurizat (Insecure)",
        "desc": "Domeniul funcționează, dar nu folosește DNSSEC (sau un părinte nu a semnat delegarea).",
        "severity": "WARN"
    },
    "DS_MISMATCH": {
        "text": "Eroare DS (Mismatch)",
        "desc": "Zona părinte spune că zona copil ar trebui să aibă o anumită cheie, dar copilul prezintă alta. Este un Key Rollover eșuat.",
        "severity": "CRITICAL"
    },
    "EXPIRED": {
        "text": "Semnătură Expirată",
        "desc": "Semnătura RRSIG nu mai este validă. Ceasul serverului sau perioada de valabilitate a cheii este greșită.",
        "severity": "CRITICAL"
    },
    "DEPRECATED": {
        "text": "Algoritm Învechit",
        "desc": "Se folosește un algoritm criptografic considerat slab. Ar trebui migrat la SHA-256 sau ECDSA.",
        "severity": "WARN"
    }
}

class ReportGenerator:
    @staticmethod
    def get_explanation(key):
        return EXPLANATIONS.get(key, {"text": key, "desc": "N/A", "severity": "INFO"})

    @staticmethod
    def to_json(trace: InspectorTrace):
        """Generează JSON-ul pentru automatizări."""
        return json.dumps(asdict(trace), indent=2)

    @staticmethod
    def to_markdown(trace: InspectorTrace):
        """Generează raportul Human-Readable."""
        verdict_info = ReportGenerator.get_explanation(trace.chainVerdict)
        icon = "✅" if trace.chainVerdict == "SECURE_CHAIN_CANDIDATE" else ("❌" if trace.chainVerdict == "BROKEN_CHAIN" else "⚠️")
        
        lines = []
        lines.append(f"# DNSSEC Report for: {trace.targetName} ({trace.targetType})")
        lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Verdict:** {icon} {verdict_info['text']}")
        lines.append(f"> *{verdict_info['desc']}*")

        # --- SECȚIUNE NOUĂ: FINAL ANSWER ---
        lines.append(f"\n## 🎯 0. Final Answer (Requested: {trace.targetType})")
        if not trace.finalAnswerRrsets:
             lines.append(f"No {trace.targetType} records found (NODATA) or query failed.")
        else:
             lines.append("Here is the data received:")
             for rrset_text in trace.finalAnswerRrsets:
                 # Curățăm textul pentru aspect (uneori dnspython lasă metadate urâte)
                 lines.append(f"```\n{rrset_text}\n```")
        # -----------------------------------
        
        lines.append("\n## 1. Chain of Trust (Delegation Path)")
        if not trace.delegationChain:
            lines.append("No delegation chain found.")
        
        for link in trace.delegationChain:
            status_icon = "🔗" if link.status == "OK" else "💔"
            lines.append(f"### {status_icon} Hop: `{link.parentZone}` → `{link.childZone}`")
            lines.append(f"- **Status:** {link.status}")
            if link.details:
                lines.append(f"- **Details:** {link.details}")
            
            if link.dsDenialProof:
                lines.append(f"- **Note:** DS Denial Proof found (NSEC/NSEC3). This makes it INSECURE but valid DNS.")

        lines.append("\n## 2. Crypto Hygiene & Algorithms")
        if not trace.algoAssessments:
            lines.append("No algorithms assessed.")
        
        lines.append("| Scope | Algo/Digest | Verdict | Notes |")
        lines.append("|---|---|---|---|")
        for algo in trace.algoAssessments:
            v_icon = "✅" if algo.verdict == "OK" else ("❌" if "DEPRECATED" in algo.verdict else "⚠️")
            lines.append(f"| {algo.kind} ({algo.owner}) | {algo.value} | {v_icon} {algo.verdict} | {algo.notes} |")

        lines.append("\n## 3. Signature Validity (RRSIG)")
        issues = [s for s in trace.signatureChecks if s.timeStatus != "OK" or s.cryptoStatus == "BOGUS"]
        if not issues:
            lines.append("✅ All checked signatures are VALID and within time window.")
        else:
            for sig in issues:
                lines.append(f"- ❌ **{sig.rrtype} @ {sig.owner}**: Time={sig.timeStatus}, Crypto={sig.cryptoStatus}")
                if sig.failureReason:
                    lines.append(f"  - Reason: {sig.failureReason}")

        if trace.chainBreakAt:
            lines.append(f"\n## 🛑 FAILURE POINT: {trace.chainBreakAt}")
            lines.append("The chain of trust stopped here.")

        return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="DNSSEC Inspector Tool (The Q.R.F. Project)")
    
    parser.add_argument("domain", help="Domain to inspect (e.g., google.com)")
    parser.add_argument("-t", "--type", default="A", help="Record type (A, AAAA, MX...)")
    parser.add_argument("-f", "--format", choices=["json", "md", "text"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout per query")

    args = parser.parse_args()

    print(f"🕵️  Inspecting {args.domain} (Type: {args.type})... please wait.")
    
    # Instanțiem colectorul lui Ionuț
    collector = DnssecChainCollector(timeoutSeconds=args.timeout, preferIpv4=True)
    
    # Rulăm inspecția
    start_time = time.time()
    trace = collector.inspectDomain(args.domain, args.type)
    duration = time.time() - start_time

    # Generăm raportul
    output_content = ""
    if args.format == "json":
        output_content = ReportGenerator.to_json(trace)
    else:
        # Default text/md folosesc formatul Markdown pentru lizibilitate
        output_content = ReportGenerator.to_markdown(trace)
        output_content += f"\n\n(Scan took {duration:.2f} seconds)"

    # Afișare sau Salvare
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_content)
        print(f"💾 Report saved to {args.output}")
    else:
        print("\n" + "="*40)
        print(output_content)
        print("="*40 + "\n")

if __name__ == "__main__":
    main()