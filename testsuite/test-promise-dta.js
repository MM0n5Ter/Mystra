// test_promise.js — DTA Promise/Async/Await Taint Tracking Tests
// Usage: ./node --dta-maglev --allow-natives-syntax test_taint/test_promise.js

let pass = 0, fail = 0;
function check(name, got) {
  if (got) { pass++; console.log(`  PASS: ${name}`); }
  else     { fail++; console.log(`  FAIL: ${name}`); }
}

function taint(s, label) {
  return %SetTaint(s, label || "TaintSource");
}

function hasTaint(v) {
  return %GetTaint(v) !== 0;
}

// =========================================================================
// Phase 1: Basic await with heap objects
// =========================================================================
async function test_basic_await() {
  console.log("\n--- Basic await ---");

  // 1. await Promise.resolve(tainted_string)
  {
    const t = taint("secret", "basic1");
    const result = await Promise.resolve(t);
    check("await Promise.resolve(tainted_string)", hasTaint(result));
  }

  // 2. await async function identity
  {
    async function identity(x) { return x; }
    const t = taint("pass-through", "basic2");
    const result = await identity(t);
    check("await async identity(tainted)", hasTaint(result));
  }

  // 3. await with .then() toUpperCase
  {
    const t = taint("data", "basic3");
    const result = await Promise.resolve(t).then(x => x.toUpperCase());
    check("await .then(toUpperCase)", hasTaint(result));
  }

  // 4. Property access through .then()
  {
    const t = taint("value", "basic4");
    const obj = { key: t };
    const result = await Promise.resolve(obj).then(o => o.key);
    check("await .then(o => o.key)", hasTaint(result));
  }
}

// =========================================================================
// Phase 2: Async function return value taint
// =========================================================================
async function test_async_return() {
  console.log("\n--- Async function return ---");

  // 5. Async function returning concatenated tainted
  {
    async function process(input) { return input + " processed"; }
    const t = taint("input", "ret1");
    const result = await process(t);
    check("async func returns tainted + ' processed'", hasTaint(result));
  }

  // 6. Async function with internal transform
  {
    async function transform(input) { return input.toUpperCase(); }
    const t = taint("hello", "ret2");
    const result = await transform(t);
    check("async func returns tainted.toUpperCase()", hasTaint(result));
  }

  // 7. Chained async functions
  {
    async function step1(s) { return s + "_step1"; }
    async function step2(s) { return s + "_step2"; }
    const t = taint("chain", "ret3");
    const r1 = await step1(t);
    const r2 = await step2(r1);
    check("chained async: step2(await step1(tainted))", hasTaint(r2));
  }

  // 8. Async function returning slice
  {
    async function getSlice(s) { return s.slice(0, 3); }
    const t = taint("abcdef", "ret4");
    const result = await getSlice(t);
    check("async func returns tainted.slice(0,3)", hasTaint(result));
  }
}

// =========================================================================
// Promise chain propagation
// =========================================================================
async function test_promise_chains() {
  console.log("\n--- Promise chains ---");

  // 9. Double .then() identity
  {
    const t = taint("chain1", "chain1");
    const result = await Promise.resolve(t).then(x => x).then(x => x);
    check(".then(x=>x).then(x=>x)", hasTaint(result));
  }

  // 10. new Promise(resolve => resolve(tainted))
  {
    const t = taint("manual", "chain2");
    const result = await new Promise(resolve => resolve(t));
    check("new Promise(resolve => resolve(tainted))", hasTaint(result));
  }

  // 11. setTimeout-based async resolution
  {
    const t = taint("timeout", "chain3");
    const result = await new Promise(resolve => {
      setTimeout(() => resolve(t), 0);
    });
    check("setTimeout => resolve(tainted)", hasTaint(result));
  }

  // 12. .then() with string concat
  //     KNOWN LIMITATION: .then() callbacks are called from CSA builtins
  //     (PromiseFulfillReactionJob), bypassing DTA pre-hooks. The arg `x`
  //     has heap taint but NOT shadow frame register taint. Binary ops
  //     (x + "...") read shadow frame → 0 → skip. Workaround: await first,
  //     then operate in the async function body where shadow frame is active.
  {
    const t = taint("prefix", "chain4");
    const result = await Promise.resolve(t)
      .then(x => x + "-middle")
      .then(x => x + "-suffix");
    check(".then(concat).then(concat) [KNOWN: callback shadow frame gap]",
          hasTaint(result));
  }

  // 13. .then() with builtin-only operations (no binary op, uses call hooks)
  {
    const t = taint("HELLO WORLD", "chain5");
    const result = await Promise.resolve(t)
      .then(x => x.toLowerCase())
      .then(x => x.trim())
      .then(x => x.replace("hello", "hi"));
    check(".then(lower).then(trim).then(replace)", hasTaint(result));
  }
}

// =========================================================================
// Realistic async patterns
// =========================================================================
async function test_realistic_patterns() {
  console.log("\n--- Realistic async patterns ---");

  // 14. Simulated HTTP handler: parse → transform → return
  {
    async function parseBody(raw) {
      return raw.trim();
    }
    async function handleRequest(body) {
      const parsed = await parseBody(body);
      return "Response: " + parsed;
    }
    const userInput = taint("  malicious_input  ", "http1");
    const response = await handleRequest(userInput);
    check("HTTP handler: parse → transform → return", hasTaint(response));
  }

  // 15. Simulated database query
  {
    async function query(sql) {
      // Simulate async DB round-trip
      return await new Promise(resolve => {
        setTimeout(() => resolve("result_of_" + sql), 0);
      });
    }
    const userParam = taint("' OR 1=1", "db1");
    const sqlQuery = "SELECT * FROM users WHERE name = '" + userParam + "'";
    const dbResult = await query(sqlQuery);
    check("DB query with tainted SQL", hasTaint(dbResult));
  }

  // 16. Simulated file read pipeline
  {
    async function readFile(path) {
      return "contents_of_" + path;
    }
    async function processFile(path) {
      const content = await readFile(path);
      return content.toUpperCase();
    }
    const userPath = taint("../../etc/passwd", "file1");
    const result = await processFile(userPath);
    check("File read pipeline with tainted path", hasTaint(result));
  }

  // 17. Promise.all with tainted elements
  {
    const t1 = taint("secret1", "all1");
    const t2 = taint("secret2", "all2");
    const [r1, r2] = await Promise.all([
      Promise.resolve(t1),
      Promise.resolve(t2)
    ]);
    check("Promise.all[0] tainted", hasTaint(r1));
    check("Promise.all[1] tainted", hasTaint(r2));
  }

  // 18. Nested async/await
  {
    async function inner(s) { return s + "_inner"; }
    async function middle(s) {
      const r = await inner(s);
      return r + "_middle";
    }
    async function outer(s) {
      const r = await middle(s);
      return r + "_outer";
    }
    const t = taint("deep", "nest1");
    const result = await outer(t);
    check("3-level nested async (deep→inner→middle→outer)", hasTaint(result));
  }

  // 19. Async with try/catch
  {
    async function riskyOp(input) {
      try {
        if (input.includes("bad")) throw new Error("bad: " + input);
        return input + "_safe";
      } catch (e) {
        return "caught: " + e.message;
      }
    }
    const t = taint("bad_data", "try1");
    const result = await riskyOp(t);
    check("async try/catch with tainted throw", hasTaint(result));
  }

  // 20. Async IIFE
  {
    const t = taint("iife_data", "iife1");
    const result = await (async () => {
      const x = t + "_processed";
      return x;
    })();
    check("async IIFE returns tainted", hasTaint(result));
  }
}

// =========================================================================
// Edge cases
// =========================================================================
async function test_edge_cases() {
  console.log("\n--- Edge cases ---");

  // 21. Already-resolved promise
  {
    const t = taint("already", "edge1");
    const p = Promise.resolve(t);
    // Let microtask queue drain
    await new Promise(r => setTimeout(r, 0));
    const result = await p;
    check("await already-resolved promise", hasTaint(result));
  }

  // 22. Promise wrapping promise
  {
    const t = taint("wrapped", "edge2");
    const inner = Promise.resolve(t);
    const outer = Promise.resolve(inner);
    const result = await outer;
    check("Promise.resolve(Promise.resolve(tainted))", hasTaint(result));
  }

  // 23. Async generator (yield + return)
  {
    async function* gen(input) {
      yield input + "_yielded";
    }
    const t = taint("asyncgen", "edge3");
    const g = gen(t);
    const { value } = await g.next();
    // Note: this tests the async generator path which uses a different
    // resume mechanism than regular async functions
    check("async generator yield tainted", hasTaint(value));
  }

  // 24. Multiple awaits in sequence
  {
    const t = taint("sequential", "edge4");
    const r1 = await Promise.resolve(t);
    const r2 = await Promise.resolve(r1 + "_a");
    const r3 = await Promise.resolve(r2 + "_b");
    check("3 sequential awaits preserve taint", hasTaint(r3));
  }

  // 25. Async function called without await (fire and forget, then await)
  {
    async function delayed(s) {
      return s + "_delayed";
    }
    const t = taint("delayed", "edge5");
    const promise = delayed(t);  // not awaited yet
    // do some other work
    const x = 1 + 2;
    const result = await promise;  // now await
    check("delayed await of async call", hasTaint(result));
  }
}

// =========================================================================
// Run all tests
// =========================================================================
async function main() {
  console.log("=== DTA Promise/Async/Await Taint Tests ===");

  await test_basic_await();
  await test_async_return();
  await test_promise_chains();
  await test_realistic_patterns();
  await test_edge_cases();

  console.log(`\n=== Results: ${pass}/${pass + fail} passed ===`);
  if (fail > 0) process.exit(1);
}

main().catch(e => {
  console.error("Test runner error:", e);
  process.exit(1);
});
