import argparse
import sys
import json
import time
from dataclasses import asdict

from inspector import DnssecChainCollector, InspectorTrace

EXPLANATIONS = {
    "SECURE_CHAIN_CANDIDATE": {
        "text": "SECURE CHAIN",
        "desc": "The Chain of Trust is valid from Root (.) down to the domain.",
        "severity": "OK"
    },
    "BROKEN_CHAIN": {
        "text": "BOGUS (BROKEN CHAIN)",
        "desc": "Validation failed. Invalid signature or missing key.",
        "severity": "CRITICAL"
    },
    "INSECURE_DELEGATION": {
        "text": "INSECURE",
        "desc": "Domain does not use DNSSEC or delegation is unsigned.",
        "severity": "WARN"
    },
    "DS_MISMATCH": {
        "text": "DS MISMATCH (CRITICAL)",
        "desc": "Parent DS record does not match the Child DNSKEY.",
        "severity": "CRITICAL"
    }
}

class ReportGenerator:
    @staticmethod
    def get_explanation(key):
        """Returnează explicația și severitatea pe baza verdictului tehnic."""
        return EXPLANATIONS.get(key, {"text": key, "desc": "Unknown Status", "severity": "INFO"})

    @staticmethod
    def to_json(trace: InspectorTrace):
        """Exportă întregul obiect trace în format JSON."""
        return json.dumps(asdict(trace), indent=2)

    @staticmethod
    def _make_header(title):
        """
        Creează un antet de secțiune profesional, încadrat cu linii duble.
        Folosit acum și pentru Titlul Principal.
        """
        width = 70
        # Caractere box-drawing double
        top = "╔" + "═" * (width - 2) + "╗"
        # Formatăm textul cu padding la stânga
        mid = f"║ {title:<{width-4}} ║"
        bot = "╚" + "═" * (width - 2) + "╝"
        return f"\n{top}\n{mid}\n{bot}"

    @staticmethod
    def _make_verdict_box(lines):
        """Creează cutia pentru verdict (linii simple)."""
        width = 70
        border_top = "┌" + "─" * (width - 2) + "┐"
        border_bottom = "└" + "─" * (width - 2) + "┘"
        result = [border_top]
        for line in lines:
            stripped = line[:width-4]
            result.append(f"│ {stripped:<{width-4}} │")
        result.append(border_bottom)
        return "\n".join(result)

    @staticmethod
    def to_markdown(trace: InspectorTrace):
        verdict_info = ReportGenerator.get_explanation(trace.chainVerdict)
        
        icon = "[OK]"
        if trace.chainVerdict == "BROKEN_CHAIN" or "MISMATCH" in trace.chainVerdict:
            icon = "[XX]"
        elif trace.chainVerdict == "INSECURE_DELEGATION":
            icon = "[!!]"
        elif trace.chainVerdict == "UNKNOWN":
            icon = "[??]"

        output = []

        # --- 1. TITLU PRINCIPAL (BOXED) ---
        title_text = f"DNSSEC INSPECTOR REPORT: {trace.targetName} ({trace.targetType})"
        output.append(ReportGenerator._make_header(title_text))
        
        # --- 2. VERDICT (BOXED) ---
        verdict_box = [
            f"FINAL VERDICT: {icon} {verdict_info['text']}",
            "─" * 66,
            f"{verdict_info['desc']}",
            f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        output.append(ReportGenerator._make_verdict_box(verdict_box))
        
        # --- 3. DATELE FINALE ---
        output.append(ReportGenerator._make_header("0. RECEIVED DATA"))
        
        if not trace.finalAnswerRrsets:
             output.append(f"   [!] No answer for {trace.targetType} (NODATA) or query failed.")
        else:
             for rrset_text in trace.finalAnswerRrsets:
                 output.append(f"   >> {rrset_text}")

        # --- 4. LANȚUL DE ÎNCREDERE ---
        output.append(ReportGenerator._make_header("1. CHAIN OF TRUST (Delegation Path)"))
        
        if not trace.delegationChain:
            output.append("   [!] No delegation chain detected.")
        
        for i, link in enumerate(trace.delegationChain, 1):
            status_tag = "[OK]" if link.status == "OK" else "[XX] FAIL"
            
            output.append(f"   #{i:02d} {link.parentZone}")
            output.append(f"       `-->> {link.childZone:<35} {status_tag}")
            
            if link.details and link.status != "OK":
                 output.append(f"       Note: {link.details}")

            if link.dsDenialProof:
                output.append(f"       Info: [!!] NSEC proof found (No DS).")
            
            output.append("") 

        if trace.chainBreakAt:
             output.append(f"   [STOP] CHAIN BROKEN AT: {trace.chainBreakAt}")

        # --- 5. VERIFICARE CRIPTOGRAFICĂ ---
        output.append(ReportGenerator._make_header("2. ALGORITHMS & DIGESTS"))
        
        output.append(f"   {'SCOPE':<25} | {'ALGO':<6} | {'STATUS':<10} | {'NOTES'}")
        output.append("   " + "-"*25 + "+--------+------------+-------------------")
        
        if not trace.algoAssessments:
            output.append("   [!] No algorithms assessed.")
        
        for algo in trace.algoAssessments:
            v_txt = "[OK]" if algo.verdict == "OK" else "[XX] WEAK"
            if "DEPRECATED" in algo.verdict: v_txt = "[XX] OLD"
            
            owner_short = (algo.owner[:22] + '..') if len(algo.owner) > 22 else algo.owner
            output.append(f"   {owner_short:<25} | {str(algo.value):<6} | {v_txt:<10} | {algo.notes}")

        # --- 6. SEMNĂTURI ---
        output.append(ReportGenerator._make_header("3. SIGNATURES (RRSIG)"))

        if not trace.signatureChecks:
            output.append("   [!] No signatures processed.")
        else:
            for sig in trace.signatureChecks:
                s_icon = "[!!]"
                if sig.cryptoStatus == "VALID": s_icon = "[OK]"
                elif sig.cryptoStatus == "BOGUS": s_icon = "[XX]"
                
                key_str = f"Key:{sig.keyTag}" if sig.keyTag else "NoKey"
                
                details = sig.cryptoStatus
                if sig.cryptoStatus == "INDETERMINATE": details = "UNVERIFIED"
                elif sig.cryptoStatus == "BOGUS": details = f"ERROR: {sig.failureReason}"
                if sig.timeStatus != "OK": details += f" [TIME: {sig.timeStatus}]"

                owner_short = (sig.owner[:28] + '..') if len(sig.owner) > 28 else sig.owner
                output.append(f"   {s_icon} {owner_short:<30} {key_str:<10} {details}")

        # --- 7. FOOTER (BOXED) ---
        output.append(ReportGenerator._make_header("END OF REPORT"))
        return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(description="DNSSEC Inspector Tool")
    parser.add_argument("domain", help="Domain to inspect")
    parser.add_argument("-t", "--type", default="A", help="Record type")
    parser.add_argument("-f", "--format", choices=["json", "text"], default="text")
    parser.add_argument("-o", "--output", help="Save output file")
    
    args = parser.parse_args()
    
    print(f"Inspecting {args.domain}...")
    collector = DnssecChainCollector(timeoutSeconds=3.5)
    trace = collector.inspectDomain(args.domain, args.type)
    
    if args.format == "json":
        print(ReportGenerator.to_json(trace))
    else:
        print(ReportGenerator.to_markdown(trace))

if __name__ == "__main__":
    main()