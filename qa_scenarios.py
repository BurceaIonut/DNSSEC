from inspector import DnssecChainCollector
from cli import ReportGenerator
import sys

SCENARIOS = [
    {
        "domain": "ietf.org", 
        "expected": "SECURE_CHAIN_CANDIDATE", 
        "desc": "Standard domain, signature valid"
    },
    {
        "domain": "dnssec-failed.org", 
        "expected": "BROKEN_CHAIN", 
        "desc": "Domain configured to fail (Bogus)"
    },
    {
        "domain": "cnn.com", 
        "expected": "INSECURE_DELEGATION", 
        "desc": "Unsigned domain  (or unsigned TLD)"
    },
    {
        "domain": "sigfail.verteiltesysteme.net",
        "expected": "BROKEN_CHAIN",
        "desc": "Invalid signatures"
    }
]

def run_qa():
    print("Starting QA / Demo Suite...\n")
    collector = DnssecChainCollector(timeoutSeconds=2.0)
    
    results = []
    
    for case in SCENARIOS:
        print(f"Testing: {case['domain']} (Expect: {case['expected']})...", end=" ")
        sys.stdout.flush()
        
        trace = collector.inspectDomain(case['domain'], "A")
        
        status = "[OK] PASS" if trace.chainVerdict == case['expected'] else f"[XX] FAIL (Got {trace.chainVerdict})"
        print(status)
        
        results.append({
            "domain": case['domain'],
            "verdict": trace.chainVerdict,
            "pass": trace.chainVerdict == case['expected']
        })

    print("\n--- QA Summary ---")
    passed = sum(1 for r in results if r['pass'])
    total = len(results)
    print(f"Total Tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")

if __name__ == "__main__":
    run_qa()

