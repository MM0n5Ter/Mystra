"""_io.open as a CWE-22 sink via TSL, and the single-route alert logger.

open() carries two TSL sub-rules under one signature: a CWE-22 SINK_CHECK and
an fs_taint write-park. They were previously shadowed by a spurious @argc guard
(two same-signature rules merged as arity overloads), so open alerted only via
the hardcoded table. After merging them into one rule, open is detected by TSL,
which is now the single alert route: stderr "[ALERT]" text or, with DTA_JSON,
exactly one JSONL record.
"""
import sys
import subprocess
import os
import json
import tempfile

passed = 0
failed = 0


def test(name, condition):
    global passed, failed
    if condition:
        print("  PASS: " + name)
        passed += 1
    else:
        print("  FAIL: " + name)
        failed += 1


_cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def capture(code, dta_json=None):
    """Run code; return (stderr, [parsed jsonl records])."""
    env = dict(os.environ)
    records = []
    path = None
    if dta_json:
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        env["DTA_JSON"] = path
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=10,
                       cwd=_cwd, env=env)
    if path:
        with open(path) as f:
            records = [json.loads(l) for l in f if l.strip()]
        os.unlink(path)
    return r.stderr, records


print("=" * 60)
print("_io.open CWE-22 sink + single-route logger")
print("=" * 60)

_OPEN = """
import tempfile, _taint
d = tempfile.mkdtemp()
name = _taint.set_taint("../../../etc/evil", "UPLOAD")
try: open(d + "/" + name, "wb+").close()
except OSError: pass
"""

# [1] tainted open() fires CWE-22 on stderr (text mode)
stderr, _ = capture(_OPEN)
test("open(tainted) -> [ALERT] CWE-22 on stderr", "[ALERT]" in stderr and "22" in stderr)

# [2] single alert route: with DTA_JSON, exactly ONE JSONL record, no stderr dup
stderr, recs = capture(_OPEN, dta_json=True)
test("open(tainted) -> exactly 1 JSONL record", len(recs) == 1)
test("JSONL record is CWE-22 _io.open", bool(recs) and recs[0]["cwe"] == 22
     and recs[0]["sink"] == "_io.open")
test("JSONL carries a non-empty provenance DAG",
     bool(recs) and len(next(iter(recs[0]["dag"].values()))) >= 2)
test("JSON mode does not also print [ALERT] to stderr", "[ALERT]" not in stderr)

# [N1] clean open() must not alert
stderr, _ = capture("""
import tempfile
d = tempfile.mkdtemp()
open(d + "/plain.txt", "wb+").close()
""")
test("open(clean) -> no alert", "[ALERT]" not in stderr)

# [N2] the stderr string is the logger format, not the old hardcoded one
stderr, _ = capture(_OPEN)
test("uses [ALERT] format, not legacy [DTA-ALERT]",
     "[ALERT]" in stderr and "[DTA-ALERT]" not in stderr)

print("\n" + "=" * 60)
print("Results: %d passed, %d failed" % (passed, failed))
print("=" * 60)

if failed > 0:
    sys.exit(1)
