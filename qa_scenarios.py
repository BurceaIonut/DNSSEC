from inspector import DnssecChainCollector
from cli import ReportGenerator
import sys

SCENARIOS = [
    {
        "domain": "ietf.org", 
        "expected": "SECURE_CHAIN_CANDIDATE", 
        "desc": "Domeniu standard, semnat corect"
    },
    {
        "domain": "dnssec-failed.org", 
        "expected": "BROKEN_CHAIN", 
        "desc": "Domeniu configurat intenționat să eșueze (Bogus)"
    },
    {
        "domain": "cnn.com", 
        "expected": "INSECURE_DELEGATION", 
        "desc": "Domeniu nesemnat (sau TLD nesemnat)"
    },
    {
        "domain": "sigfail.verteiltesysteme.net",
        "expected": "BROKEN_CHAIN",
        "desc": "Test case clasic pentru semnături invalide"
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
        
        status = "✅ PASS" if trace.chainVerdict == case['expected'] else f"❌ FAIL (Got {trace.chainVerdict})"
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