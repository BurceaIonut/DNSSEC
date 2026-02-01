import argparse
import sys
import json
import time
from dataclasses import asdict

from inspector import DnssecChainCollector, InspectorTrace

EXPLANATIONS = {
    "SECURE_CHAIN_CANDIDATE": {
        "text": "SECURE (LANȚ SECURIZAT)",
        "desc": "Lanțul de încredere este valid de la Root (.) până la domeniu.",
        "severity": "OK"
    },
    "BROKEN_CHAIN": {
        "text": "BOGUS (LANȚ RUPT)",
        "desc": "Validarea a eșuat. Semnătură invalidă sau cheie lipsă.",
        "severity": "CRITICAL"
    },
    "INSECURE_DELEGATION": {
        "text": "INSECURE (NESECURIZAT)",
        "desc": "Domeniul nu are DNSSEC sau delegarea nu este semnată.",
        "severity": "WARN"
    },
    "DS_MISMATCH": {
        "text": "DS MISMATCH (EROARE CRITICĂ)",
        "desc": "Amprenta din părinte nu se potrivește cu cheia copilului.",
        "severity": "CRITICAL"
    }
}

class ReportGenerator:
    @staticmethod
    def get_explanation(key):
        return EXPLANATIONS.get(key, {"text": key, "desc": "Status necunoscut", "severity": "INFO"})

    @staticmethod
    def to_json(trace: InspectorTrace):
        return json.dumps(asdict(trace), indent=2)

    @staticmethod
    def _make_box(lines, color_char=""):
        """Crează o cutie ASCII în jurul textului."""
        width = 70
        border_top = "╔" + "═" * (width - 2) + "╗"
        border_bottom = "╚" + "═" * (width - 2) + "╝"
        
        result = [border_top]
        for line in lines:
            stripped = line[:width-4]
            result.append(f"║ {stripped:<{width-4}} ║")
        result.append(border_bottom)
        return "\n".join(result)

    @staticmethod
    def to_markdown(trace: InspectorTrace):
        """Generează raportul."""
        verdict_info = ReportGenerator.get_explanation(trace.chainVerdict)
        
        # Selectăm iconița
        icon = "✅"
        if trace.chainVerdict == "BROKEN_CHAIN" or "MISMATCH" in trace.chainVerdict:
            icon = "❌"
        elif trace.chainVerdict == "INSECURE_DELEGATION":
            icon = "⚠️"
        elif trace.chainVerdict == "UNKNOWN":
            icon = "❓"

        output = []

        # --- 1. HEADER & VERDICT ---
        output.append("\n" + "="*70)
        output.append(f" DNSSEC INSPECTOR REPORT: {trace.targetName} ({trace.targetType})")
        output.append("="*70 + "\n")
        
        verdict_box = [
            f"VERDICT FINAL: {icon} {verdict_info['text']}",
            "-" * 66,
            f"{verdict_info['desc']}",
            f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        output.append(ReportGenerator._make_box(verdict_box))
        output.append("\n")

        # --- 2. FINAL DATA (Răspunsul DNS) ---
        output.append(f" 0. DATE PRIMITE (Answer Section - {trace.targetType})")
        output.append("-" * 70)
        if not trace.finalAnswerRrsets:
             output.append(f"   [!] Niciun răspuns de tip {trace.targetType} (NODATA) sau eroare.")
        else:
             for rrset_text in trace.finalAnswerRrsets:
                 output.append(f"   > {rrset_text}")
        output.append("\n")

        # --- 3. CHAIN OF TRUST ---
        output.append(" 1. LANȚUL DE ÎNCREDERE (Chain of Trust)")
        output.append("-" * 70)
        if not trace.delegationChain:
            output.append("   [!] Niciun lanț de delegare detectat.")
        
        for i, link in enumerate(trace.delegationChain, 1):
            status_icon = "✅ OK" if link.status == "OK" else "❌ FAIL"
            arrow = "  ⌄" if i < len(trace.delegationChain) else "  "
            
            output.append(f"   [{i}] Zona: {link.parentZone:<25} ->  Copil: {link.childZone}")
            output.append(f"       Status: {status_icon:<10} | Detalii: {link.details}")
            if link.dsDenialProof:
                output.append(f"       Info:   ⚠️ S-a găsit dovadă NSEC/NSEC3 că NU există DS.")
            output.append(arrow)

        if trace.chainBreakAt:
             output.append(f"\n   ❌ LANȚUL S-A RUPT LA: {trace.chainBreakAt}")

        output.append("\n")

        # --- 4. ALGORITHMS (Tabel) ---
        output.append("  2. IGIENA CRIPTOGRAFICĂ (Algorithms & Digests)")
        output.append("-" * 70)
        
        output.append(f"   {'SCOPE (Zona)':<30} | {'ID':<5} | {'VERDICT':<10} | {'NOTES'}")
        output.append("   " + "-"*30 + "+-------+------------+-------------------")
        
        if not trace.algoAssessments:
            output.append("   [!] Niciun algoritm evaluat.")
        
        for algo in trace.algoAssessments:
            v_txt = "✅ OK" if algo.verdict == "OK" else "❌ WEAK"
            if "DEPRECATED" in algo.verdict: v_txt = "❌ OLD"
            
            output.append(f"   {algo.owner[:28]:<30} | {str(algo.value):<5} | {v_txt:<10} | {algo.notes}")

        output.append("\n")

        # --- 5. SIGNATURES (Grouped) ---
        output.append("  3. VALIDARE SEMNĂTURI (RRSIG)")
        output.append("-" * 70)
        
        issues = [s for s in trace.signatureChecks if s.timeStatus != "OK" or s.cryptoStatus == "BOGUS"]
        
        real_errors = [s for s in issues if s.cryptoStatus == "BOGUS" or s.timeStatus == "EXPIRED"]
        optimize_info = [s for s in issues if s.failureReason in ("NO_DNSKEY", "NO_RRSIG")]

        if not issues:
            output.append("   ✅ Toate semnăturile verificate sunt VALIDE.")
        else:
            if real_errors:
                output.append("   ❌ ERORI CRITICE (Semnături invalide/expirate):")
                for sig in real_errors:
                     output.append(f"      ❌ {sig.owner} ({sig.rrtype}): {sig.failureReason} (Time: {sig.timeStatus})")
            
            if optimize_info:
                output.append(f"\n   ⚠️  INFO: {len(optimize_info)} semnături nu au putut fi verificate complet")
                output.append("       (Motiv: Lipsă cheie publică pentru resurse externe - Optimizare viteză).")
                output.append("       Exemple:")

                for sig in optimize_info[:3]:
                    reason = sig.failureReason if sig.failureReason else "INDETERMINATE"
                    output.append(f"      * {sig.owner:<30} ({sig.rrtype}): {reason}")
                if len(optimize_info) > 3:
                    output.append(f"      ... și alte {len(optimize_info)-3}.")

        output.append("\n" + "="*70)
        return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description="DNSSEC Inspector Tool")
    parser.add_argument("domain", help="Domain to inspect")
    parser.add_argument("-t", "--type", default="A", help="Record type")
    parser.add_argument("-f", "--format", choices=["json", "text"], default="text")
    parser.add_argument("-o", "--output", help="Save output file")
    
    args = parser.parse_args()
    
    print(f"Inspecting {args.domain}...")
    collector = DnssecChainCollector(timeoutSeconds=3.0)
    trace = collector.inspectDomain(args.domain, args.type)
    
    if args.format == "json":
        print(ReportGenerator.to_json(trace))
    else:
        print(ReportGenerator.to_markdown(trace))

if __name__ == "__main__":
    main()