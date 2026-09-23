// Canonical singletons must never carry taint.
//
// `true`, `false`, `null`, `undefined`, "" and NaN are ONE immutable object each
// in V8, shared by every occurrence of the value. A shadow-heap entry keyed on
// such an address marks the value tainted for the whole process: after one
// `JSON.parse('true')` on tainted input, every `true` in the program reads as
// tainted, and because the sink check inspects every argument, any hooked call
// receiving `true` anywhere raises that rule's alert.
//
//   ./node --dta-maglev --allow-natives-syntax testsuite/test-singleton-taint.js
//
// Regression for the FUXA case-01 misfire: CWE-94 on
// compileFunctionForCJSLoader whose only tainted argument was the boolean
// `shouldDetectModule`, with the code argument clean.
const fs = require('fs');

let pass = 0, fail = 0;

function check(name, ok, detail) {
    if (ok) { pass++; console.log(`✅ PASS | ${name}`); }
    else { fail++; console.log(`❌ FAIL | ${name}${detail ? '  -> ' + detail : ''}`); }
}

function expectClean(name, produce) {
    const t = %GetTaint(produce());
    check(name, t === 0, `taint id ${t}`);
}

// Kept referenced so the values above are not optimised away.
function touch(...xs) { return xs.length; }

function expectTainted(name, value) {
    const t = %GetTaint(value);
    check(name, t !== 0, 'taint id 0');
}

console.log('=== baseline: fresh singletons are clean ===');
expectClean('fresh true', () => 2 > 1);
expectClean('fresh false', () => 1 > 2);
expectClean('fresh ""', () => 'abc'.slice(0, 0));

console.log('\n=== contaminating attempts: each must leave singletons clean ===');

// (1) a rule scattering to @ret[*] where the parsed value IS the canonical true.
//
// Note what is and is not asserted. `%GetTaint(parsedTrue)` reads the *register*
// taint of that expression first (Runtime_GetTaint steps 1-2) and is expected to
// be non-zero: that register genuinely holds a value derived from tainted input,
// which is the documented Smi/register-taint principle. What must never happen is
// the *shared* `true` object carrying heap taint, which is what a fresh
// occurrence elsewhere in the program observes.
const parsedTrue = JSON.parse(%SetTaint('true'));
expectClean('after JSON.parse(taint("true")) -> fresh true', () => 2 > 1);

// (2) same for false and null
JSON.parse(%SetTaint('false'));
JSON.parse(%SetTaint('null'));
expectClean('after JSON.parse(taint("false")) -> fresh false', () => 1 > 2);
expectClean('after JSON.parse(taint("null")) -> fresh null', () => null);

// (3) a tainted string sliced down to the canonical empty string. Same
// distinction as (1): the slice expression keeps register taint, the shared ""
// object must not.
const emptied = %SetTaint('abcdef').slice(0, 0);
expectClean('after taint("abcdef").slice(0,0) -> fresh ""', () => 'x'.slice(0, 0));

// (4) %SetTaint applied directly to a singleton: refused, with a warning
expectClean('%SetTaint(true) leaves fresh true clean', () => { %SetTaint(true); return 2 > 1; });
expectClean('%SetTaint("") leaves fresh "" clean', () => { %SetTaint(''); return 'y'.slice(0, 0); });

touch(parsedTrue, emptied);

console.log('\n=== positive control: real taint still propagates ===');
const secret = %SetTaint('/tmp/dta_singleton_probe');
expectTainted('tainted string keeps its taint', secret);
expectTainted('derived string keeps its taint', secret + '/x');
expectTainted('slice of a tainted string', secret.slice(1));
const obj = JSON.parse(%SetTaint('{"a":"payload"}'));
expectTainted('JSON.parse of a tainted object literal', obj.a);

console.log('\n=== the sink must not fire on a clean path + literal singleton ===');
// This raised a spurious CWE-22 before the guard. No assertion is possible from
// inside the process (alerts go to --dta-json-log), so run with
// --dta-json-log=/tmp/x.jsonl and confirm no `access` alert is recorded.
try { fs.accessSync('/tmp', true); } catch (e) {}
try { fs.existsSync('' + '/tmp'); } catch (e) {}
console.log('   (check the json log: no CWE-22 alert on `access` or `existsSync`)');

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exitCode = 1;
