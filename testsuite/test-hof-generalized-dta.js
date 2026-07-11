// test-hof-generalized-dta.js — HOF Generalization: Named Callbacks
//
// Tests the TSL v3.1 named callback feature:
//   - Named callback references (callback.param[N], callback.ret)
//   - Backward compat (@callback.param[N] still works)
//   - Multi-callback rules (Promise.then with onFulfilled/onRejected)
//   - Polymorphic callback (String.replace with fn vs string)
//   - Named reduce (callback.param[1] for accumulator)
//
// KNOWN GAP (1 expected failure): "map result[1] clean (precision)" — a
// non-tainted map result element is over-approximated as tainted. This is a
// precision (false-positive) limitation, not a soundness issue.

'use strict';

let passed = 0, failed = 0;

function test(name, expected_tainted, value) {
    const taint = %GetTaint(value);
    const is_tainted = taint !== 0;
    if (is_tainted === expected_tainted) {
        console.log(`  PASS: ${name}`);
        passed++;
    } else {
        console.log(`  FAIL: ${name} — expected ${expected_tainted ? 'tainted' : 'clean'}, got taint=${taint}`);
        failed++;
    }
}

// ============================================================
// Test 1: Named callback — Array.map (named syntax in rules)
// ============================================================
console.log('\n--- Test 1: Named callback Array.map ---');
{
    const tainted = %SetTaint("hello");
    const arr = [tainted, "clean"];
    const result = arr.map(x => x + "_suffix");
    test("map result[0] tainted", true, result[0]);
    test("map result[1] clean (precision)", false, result[1]);
}

// ============================================================
// Test 2: Named callback — Array.reduce (callback at param[1])
// ============================================================
console.log('\n--- Test 2: Named callback Array.reduce ---');
{
    const tainted = %SetTaint("secret");
    const arr = [tainted, "b", "c"];
    const result = arr.reduce((acc, val) => acc + val, "");
    test("reduce result tainted", true, result);
}

// ============================================================
// Test 3: Polymorphic — String.replace with function callback
// ============================================================
console.log('\n--- Test 3: String.replace with function callback ---');
{
    const tainted = %SetTaint("hello world");
    const result = tainted.replace("hello", (match) => match.toUpperCase());
    test("replace with fn callback tainted", true, result);
}

// ============================================================
// Test 4: Polymorphic — String.replace with string (no callback)
// ============================================================
console.log('\n--- Test 4: String.replace with string ---');
{
    const tainted = %SetTaint("hello world");
    const result = tainted.replace("hello", "HELLO");
    test("replace with string tainted", true, result);
}

// ============================================================
// Test 5: Backward compat — forEach still works (legacy @callback syntax)
// ============================================================
console.log('\n--- Test 5: Backward compat forEach ---');
{
    const tainted = %SetTaint("secret");
    const arr = [tainted];
    let received = null;
    arr.forEach(x => { received = x; });
    test("forEach callback received taint", true, received);
}

// ============================================================
// Test 6: Named callback — ArrayFrom with mapFn
// ============================================================
console.log('\n--- Test 6: Array.from with mapFn ---');
{
    const tainted = %SetTaint("item");
    const arr = [tainted];
    const result = Array.from(arr, x => x + "_mapped");
    test("Array.from mapFn result tainted", true, result[0]);
}

// ============================================================
// Test 7: Multi-callback — Promise.then (resolve path)
// ============================================================
console.log('\n--- Test 7: Promise.then resolve path ---');
{
    const tainted = %SetTaint("async_secret");
    const p = Promise.resolve(tainted);
    p.then(
        (value) => {
            test("then onFulfilled receives taint", true, value);
        },
        (reason) => {
            test("then onRejected should not fire", false, true);
        }
    );
}

// ============================================================
// Test 8: Multi-callback — Promise.then (reject path)
// ============================================================
console.log('\n--- Test 8: Promise.then reject path ---');
{
    const tainted = %SetTaint("error_secret");
    const p = Promise.reject(tainted);
    p.then(
        (value) => {
            test("then onFulfilled should not fire", false, true);
        },
        (reason) => {
            test("then onRejected receives taint", true, reason);
        }
    );
}

// Wait for async tests to complete
setTimeout(() => {
    console.log(`\n=== Results: ${passed}/${passed + failed} passed` +
                (failed > 0 ? `, ${failed} failed` : '') + ' ===');
    process.exit(failed > 0 ? 1 : 0);
}, 500);
