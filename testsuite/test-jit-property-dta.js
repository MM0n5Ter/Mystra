// Test: Verify taint propagation through property access in JIT-compiled code
// With --dta-maglev, property taint must survive after Maglev compilation.

let pass = 0;
let fail = 0;

function test(name, fn) {
  try {
    fn();
    pass++;
    console.log(`  PASS: ${name}`);
  } catch (e) {
    fail++;
    console.log(`  FAIL: ${name} - ${e.message}`);
  }
}

// === Test 1: Named property taint roundtrip in hot function ===
test("Hot named property read/write", () => {
  function propRoundtrip(val) {
    const obj = {};
    obj.data = val;
    return obj.data;
  }
  // Warm up to trigger Maglev
  for (let i = 0; i < 1000; i++) propRoundtrip("cold");
  // Now with tainted input
  const tainted = %SetTaint("secret");
  const result = propRoundtrip(tainted);
  const t = %GetTaint(result);
  if (t === 0) throw new Error("Taint lost through named property in hot function");
});

// === Test 2: Context variable (closure) taint in hot function ===
test("Hot closure variable taint", () => {
  function makeGetter(val) {
    return function() { return val; };
  }
  // Warm up
  for (let i = 0; i < 1000; i++) makeGetter("cold")();
  // Now with tainted input
  const tainted = %SetTaint("closure-secret");
  const getter = makeGetter(tainted);
  const result = getter();
  const t = %GetTaint(result);
  if (t === 0) throw new Error("Taint lost through closure in hot function");
});

// === Test 3: Global variable taint ===
test("Global variable taint", () => {
  globalThis.__dta_test_global = %SetTaint("global-secret");
  const result = globalThis.__dta_test_global;
  const t = %GetTaint(result);
  if (t === 0) throw new Error("Taint lost through global variable");
  delete globalThis.__dta_test_global;
});

// === Test 4: Keyed property taint ===
test("Keyed property taint", () => {
  function keyedRoundtrip(val, key) {
    const obj = {};
    obj[key] = val;
    return obj[key];
  }
  // Warm up
  for (let i = 0; i < 1000; i++) keyedRoundtrip("cold", "k");
  // Tainted
  const tainted = %SetTaint("keyed-secret");
  const result = keyedRoundtrip(tainted, "mykey");
  const t = %GetTaint(result);
  if (t === 0) throw new Error("Taint lost through keyed property in hot function");
});

console.log(`\nResults: ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
