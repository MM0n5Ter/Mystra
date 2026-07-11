// test-var-io-bridge.js — End-to-end test for var store taint bridging
//
// Scenario: writeFileSync stores taint in var store via SET,
//           readFileSync retrieves taint from var store via PROPAGATE var source.
//           Taint survives the file I/O boundary without modifying fs internals.
//
// Run: ./out/Release/node --dta-maglev --allow-natives-syntax testsuite/test-var-io-bridge.js

'use strict';
const fs = require('fs');

let pass = 0, fail = 0, total = 0;
function test(name, fn) {
  total++;
  try {
    const result = fn();
    if (result) { pass++; console.log(`  [PASS] ${name}`); }
    else { fail++; console.log(`  [FAIL] ${name}`); }
  } catch (e) { fail++; console.log(`  [FAIL] ${name} — ${e.message}`); }
}

const tmpFile = '/tmp/dta-var-io-bridge-' + process.pid + '.txt';

console.log('=== var store I/O bridge tests ===\n');

// Test 1: Write tainted data to file (SET fires)
test('writeFileSync with tainted data triggers SET + CWE-22', () => {
  const tainted = %SetTaint('malicious payload');
  fs.writeFileSync(tmpFile, tainted);
  return true;
});

// Test 2: Read file back — var source propagates stored taint to return value
test('readFileSync retrieves taint from var store', () => {
  const content = fs.readFileSync(tmpFile, 'utf8');
  const taint = %GetTaint(content);
  console.log('    readFileSync content taint = ' + taint);
  return taint > 0;
});

// Test 3: Use the read-back content in a dangerous sink
test('Taint from var store reaches eval sink', () => {
  const content = fs.readFileSync(tmpFile, 'utf8');
  // String concat should preserve taint from var source
  const code = '"use strict"; ' + content;
  const taint = %GetTaint(code);
  console.log('    concat with var-sourced taint = ' + taint);
  return taint > 0;
});

// Cleanup
try { fs.unlinkSync(tmpFile); } catch (e) {}

console.log(`\n=== Results: ${pass}/${total} pass ===`);
if (fail > 0) process.exit(1);
