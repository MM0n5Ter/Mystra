"""Runner for synthetic taint test suite.

Usage: ./python testsuite/synthetic_taint/run_synthetic_taint_tests.py
"""
import subprocess
import sys
import os

_dir = os.path.dirname(os.path.abspath(__file__))
_python = sys.executable

tests = [
    "test_a_propagation.py",
    "test_b_functions.py",
    "test_c_containers.py",
    "test_d_sinks.py",
    "test_e_provenance.py",
]

print("=" * 70)
print("Synthetic Taint Test Suite")
print("Python: %s" % sys.version.split()[0])
print("=" * 70)

total_pass = 0
total_fail = 0
category_results = []

for test_file in tests:
    path = os.path.join(_dir, test_file)
    r = subprocess.run(
        [_python, path],
        capture_output=True, text=True, timeout=60,
        cwd=os.path.dirname(_dir)  # repo root
    )

    # Parse output for results
    output = r.stdout + r.stderr
    # Filter DTA-INFO/INIT noise
    lines = [l for l in output.split("\n")
             if "DTA-INFO" not in l and "DTA-INIT" not in l]
    display = "\n".join(lines)

    # Count PASS/FAIL
    p = sum(1 for l in lines if l.strip().startswith("PASS:"))
    f = sum(1 for l in lines if l.strip().startswith("FAIL:"))
    total_pass += p
    total_fail += f

    # Show output
    print()
    print(display.strip())

    # Extract category summary
    for l in lines:
        if l.strip().startswith("["):
            category_results.append(l.strip())

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print("| %-30s | %-20s | %-8s |" % ("Category", "Expected", "Result"))
print("|" + "-" * 32 + "|" + "-" * 22 + "|" + "-" * 10 + "|")

categories = [
    ("A. Basic propagation", "taint propagates", None),
    ("B. Function propagation", "taint survives calls", None),
    ("C. Container/object", "heap taint works", None),
    ("D. Sink detection", "alerts fire correctly", None),
    ("E. Provenance", "DAG chain intact", None),
]

for line in category_results:
    # Parse [X] N passed, M failed
    if "passed" in line:
        parts = line.split()
        cat = parts[0]  # [A] etc
        p_idx = parts.index("passed,")
        f_idx = parts.index("failed")
        p = int(parts[p_idx - 1])
        f = int(parts[f_idx - 1])
        cat_name = {"[A]": "A. Basic propagation",
                    "[B]": "B. Function propagation",
                    "[C]": "C. Container/object",
                    "[D]": "D. Sink detection",
                    "[E]": "E. Provenance"}.get(cat, cat)
        result = "%d PASS" % p if f == 0 else "%d PASS, %d FAIL" % (p, f)
        expected = {"[A]": "taint propagates",
                    "[B]": "taint survives calls",
                    "[C]": "heap taint works",
                    "[D]": "alerts fire correctly",
                    "[E]": "DAG chain intact"}.get(cat, "—")
        print("| %-30s | %-20s | %-8s |" % (cat_name, expected, result))

print()
print("Total: %d passed, %d failed" % (total_pass, total_fail))
if total_fail > 0:
    print("(Failures may include known XFAILs — check individual output)")
print("=" * 70)

sys.exit(0 if total_fail == 0 else 1)
