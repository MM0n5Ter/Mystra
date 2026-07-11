// test-dynkey-dta.js — End-to-end test for kDynamicKey and new TSL features
// Tests Object.defineProperty dynamic key propagation and @is_new guard
//
// Run: DTA_RULES_PATH=./v8-rules.tbin ./node --dta-maglev --allow-natives-syntax testsuite/test-dynkey-dta.js

let passed = 0;
let failed = 0;

function test(name, actual, expected) {
    const ok = (expected ? actual > 0 : actual === 0);
    if (ok) {
        console.log(`  PASS: ${name}`);
        passed++;
    } else {
        console.log(`  FAIL: ${name} (expected taint=${expected ? '>0' : '0'}, got=${actual})`);
        failed++;
    }
}

// === Test 1: Object.defineProperty with tainted value ===
// Rule: ObjectDefineProperty(target, key, desc): desc.value -> target[key]
{
    const obj = {};
    const val = %SetTaint("tainted-value");
    Object.defineProperty(obj, "prop", { value: val, writable: true, enumerable: true });
    test("defineProperty: tainted value propagates to target[key]",
         %GetTaint(obj.prop), true);
}

// === Test 2: Object.defineProperty with clean value ===
{
    const obj = {};
    Object.defineProperty(obj, "clean", { value: "clean-value", writable: true });
    test("defineProperty: clean value stays clean",
         %GetTaint(obj.clean), false);
}

// === Test 3: Object.defineProperty with dynamic key ===
{
    const obj = {};
    const key = "dynamicKey";
    const val = %SetTaint("dynamic-tainted");
    Object.defineProperty(obj, key, { value: val, writable: true, enumerable: true });
    test("defineProperty: dynamic key + tainted value",
         %GetTaint(obj[key]), true);
}

// === Test 4: StringConstructor @is_new guard ===
// Rule: StringConstructor(value): value -> @ret where not @is_new
//                                 value -> @ret.** where @is_new
{
    const src = %SetTaint("hello");

    // String(tainted) — Call context (not new)
    const callResult = String(src);
    test("String(tainted): Call context propagates",
         %GetTaint(callResult), true);

    // new String(tainted) — Construct context
    const newResult = new String(src);
    // Note: new String() wraps in String object. Taint may be on the wrapper's properties.
    // The rule says value -> @ret.** (property wildcard on the wrapper object)
    const unwrapped = newResult.valueOf();
    test("new String(tainted): Construct context (valueOf)",
         %GetTaint(unwrapped), true);
}

// === Results ===
console.log(`\n=== Results: ${passed}/${passed + failed} passed ===`);
if (failed > 0) process.exit(1);
