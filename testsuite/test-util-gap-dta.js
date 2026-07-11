// ============================================================
// util.deprecate / util.promisify taint propagation
//   util.deprecate(fn): arg[0] -> ret
//   util.promisify:     wraps a callback API
// These are pure-JS wrappers (no C++ binding), so taint flows
// through them via normal interpretation, with no rule needed.
//
// Run: ./node --dta-maglev --allow-natives-syntax testsuite/test-util-gap-dta.js
// ============================================================
const util = require('util');
let pass = 0, fail = 0, total = 0;
function test(name, fn) {
  total++;
  return Promise.resolve().then(fn).then(ok => {
    if (ok) { console.log(`  ✅ PASS | ${name}`); pass++; }
    else    { console.log(`  ❌ FAIL | ${name}`); fail++; }
  }).catch(e => { console.log(`  ❌ CRASH | ${name}: ${e.message}`); fail++; });
}

console.log('\n=== util.deprecate / util.promisify propagation ===\n');
(async () => {

  // 1. util.deprecate wraps a fn; calling the wrapper returns the fn's result.
  //    Tainted input flowing through the deprecated fn must stay tainted.
  await test('util.deprecate(fn) - taint flows through deprecated wrapper', () => {
    const echo = (x) => x;
    const dep = util.deprecate(echo, 'echo is deprecated');
    const t = %SetTaint('USERINPUT');
    return %GetTaint(dep(t)) !== 0;
  });

  // 2. util.deprecate on a string-transforming fn (concat) preserves taint.
  await test('util.deprecate(transform) - derived taint preserved', () => {
    const wrap = util.deprecate((s) => 'pre/' + s, 'd');
    const t = %SetTaint('etc/passwd');
    return %GetTaint(wrap(t)) !== 0;
  });

  // 3. util.promisify of a callback API: taint from the callback value must
  //    reach the resolved promise value (rigorous await).
  await test('util.promisify(cbApi) - taint flows callback -> resolved value', async () => {
    function cbApi(input, cb) { cb(null, input); }
    const p = util.promisify(cbApi);
    const v = await p(%SetTaint('SECRET'));
    return %GetTaint(v) !== 0;
  });

  // 4. promisify identity: the wrapper exists and is callable (structural).
  await test('util.promisify returns a function wrapper', () => {
    const p = util.promisify((x, cb) => cb(null, x));
    return typeof p === 'function';
  });

  console.log(`\n=== ${pass}/${total} passed (${fail} failed) ===\n`);
})();
