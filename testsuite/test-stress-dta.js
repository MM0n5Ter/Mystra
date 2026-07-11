// ============================================================
// DTA Engine Stress Test — Edge Conditions
// Tests crash safety, cross-tier taint flow, and boundary cases.
// Run: ./node --dta-maglev --allow-natives-syntax --expose-gc claudespace/test/test_stress.js
// ============================================================
let pass = 0, fail = 0, total = 0;
function test(name, fn) {
  total++;
  try {
    const result = fn();
    if (result) { pass++; }
    else { fail++; console.log("  FAIL:", name, "— returned falsy"); }
  } catch (e) {
    fail++;
    console.log("  FAIL:", name, "—", e.message);
  }
}

// === 1. Deep Call Chain (shadow frame stack depth) ===
test("Deep recursion (100 levels)", () => {
  function deep(s, n) { return n === 0 ? s : deep(s + "x", n - 1); }
  const t = %SetTaint("deep");
  return %GetTaint(deep(t, 100)) !== 0;
});

test("Deep recursion (500 levels)", () => {
  function deep(s, n) { return n === 0 ? s : deep(s + "x", n - 1); }
  const t = %SetTaint("deep500");
  return %GetTaint(deep(t, 500)) !== 0;
});

// === 2. Many arguments ===
test("10 arguments — taint in pos 1", () => {
  function f(a,b,c,d,e,f2,g,h,i,j) { return a+b+c+d+e+f2+g+h+i+j; }
  const t = %SetTaint("X");
  return %GetTaint(f(t,"b","c","d","e","f","g","h","i","j")) !== 0;
});

test("10 arguments — taint in pos 5", () => {
  function f(a,b,c,d,e,f2,g,h,i,j) { return a+b+c+d+e+f2+g+h+i+j; }
  const t = %SetTaint("X");
  return %GetTaint(f("a","b","c","d",t,"f","g","h","i","j")) !== 0;
});

test("10 arguments — taint in pos 10", () => {
  function f(a,b,c,d,e,f2,g,h,i,j) { return a+b+c+d+e+f2+g+h+i+j; }
  const t = %SetTaint("X");
  return %GetTaint(f("a","b","c","d","e","f","g","h","i",t)) !== 0;
});

// === 3. Zero arguments (closure capture) ===
test("Zero-arg function with closure taint", () => {
  const t = %SetTaint("closed");
  function f() { return t + " world"; }
  return %GetTaint(f()) !== 0;
});

// === 4. Spread call ===
test("Spread call with tainted element", () => {
  function f(a, b, c) { return a + b + c; }
  const t = %SetTaint("spread");
  return %GetTaint(f(...[t, "b", "c"])) !== 0;
});

// === 5. Rest parameters ===
test("Rest parameters capture taint", () => {
  function f(...args) { return args.join(","); }
  const t = %SetTaint("rest");
  return %GetTaint(f(t, "b", "c")) !== 0;
});

// === 6. Constructor (new) ===
test("Constructor taint propagation", () => {
  function Obj(val) { this.data = val + "_constructed"; }
  const t = %SetTaint("ctor");
  const o = new Obj(t);
  return %GetTaint(o.data) !== 0;
});

// === 7. Try/catch ===
test("Taint survives try/catch", () => {
  const t = %SetTaint("try");
  let result;
  try {
    result = t + " in try";
    throw new Error("test");
  } catch (e) { /* result was set before throw */ }
  return %GetTaint(result) !== 0;
});

test("Taint in catch block", () => {
  const t = %SetTaint("catch");
  let result;
  try { throw t; } catch (e) { result = e + " caught"; }
  return %GetTaint(result) !== 0;
});

// === 8. Property chains ===
test("Nested property taint", () => {
  const t = %SetTaint("prop");
  const o = { a: { b: { c: t } } };
  return %GetTaint(o.a.b.c) !== 0;
});

test("Dynamic property key taint", () => {
  const t = %SetTaint("dynamic");
  const o = {};
  o["myKey"] = t;
  return %GetTaint(o["myKey"]) !== 0;
});

// === 9. String method chains ===
test("Long string method chain", () => {
  const t = %SetTaint("chain");
  const r = t.toUpperCase().toLowerCase().trim().slice(0, 3).padStart(10, "-");
  return %GetTaint(r) !== 0;
});

// === 10. Array operations ===
test("Array.map preserves taint", () => {
  const t = %SetTaint("arrmap");
  const mapped = [t, "clean"].map(x => x + "!");
  return %GetTaint(mapped[0]) !== 0;
});

test("Array.join propagates taint", () => {
  const t = %SetTaint("arrjoin");
  return %GetTaint([t, "b", "c"].join(",")) !== 0;
});

test("Array.concat preserves taint", () => {
  const t = %SetTaint("arrconcat");
  return %GetTaint([t].concat(["b"])[0]) !== 0;
});

// === 11. Hot function all arg positions (50k warmup) ===
test("Hot 2-arg pos1 (50k warmup)", () => {
  function f(a, b) { return a + b; }
  for (let i = 0; i < 50000; i++) f("x", "y");
  const t = %SetTaint("hot2p1");
  return %GetTaint(f(t, "w")) !== 0;
});

test("Hot 2-arg pos2 (50k warmup)", () => {
  function f(a, b) { return a + b; }
  for (let i = 0; i < 50000; i++) f("x", "y");
  const t = %SetTaint("hot2p2");
  return %GetTaint(f("w", t)) !== 0;
});

test("Hot 3-arg all positions (50k warmup)", () => {
  function f(a, b, c) { return a + b + c; }
  for (let i = 0; i < 50000; i++) f("x", "y", "z");
  const t1 = %SetTaint("p1"), t2 = %SetTaint("p2"), t3 = %SetTaint("p3");
  return %GetTaint(f(t1, "b", "c")) !== 0 &&
         %GetTaint(f("a", t2, "c")) !== 0 &&
         %GetTaint(f("a", "b", t3)) !== 0;
});

// === 12. Cross-tier: SetTaint before warmup ===
test("Cross-tier taint (SetTaint before 20k warmup)", () => {
  const input = %SetTaint("cross");
  function hotFn(s) { return s + " hot"; }
  for (let i = 0; i < 20000; i++) hotFn("cold");
  return %GetTaint(hotFn(input)) !== 0;
});

// === 13. RCE sinks (crash safety) ===
test("eval with tainted code (crash safety)", () => {
  const t = %SetTaint("1+1");
  try { eval(t); } catch(e) {}
  return true;
});

test("new Function() with tainted body (crash safety)", () => {
  const t = %SetTaint("return 42");
  try { new Function(t); } catch(e) {}
  return true;
});

// === 14. Rapid taint create/destroy ===
test("1000 rapid taint cycles", () => {
  let lastTaint = 0;
  for (let i = 0; i < 1000; i++) {
    const t = %SetTaint("cycle" + i);
    lastTaint = %GetTaint(t + "_derived");
  }
  return lastTaint !== 0;
});

// === 15. Template literals ===
test("Template literal taint", () => {
  const t = %SetTaint("template");
  return %GetTaint(`prefix_${t}_suffix`) !== 0;
});

// === 16. Ternary ===
test("Ternary preserves taint", () => {
  const t = %SetTaint("ternary");
  return %GetTaint(true ? t + "x" : "clean") !== 0;
});

// === 17. JSON roundtrip (crash safety) ===
test("JSON stringify tainted value (crash safety)", () => {
  const t = %SetTaint("json");
  try { JSON.stringify({ val: t }); } catch(e) {}
  return true;
});

// === 18. Buffer.from (crash safety) ===
test("Buffer.from tainted string (crash safety)", () => {
  const t = %SetTaint("buffer");
  try { Buffer.from(t); } catch(e) {}
  return true;
});

// === 19. Prototype chain ===
test("Prototype chain taint", () => {
  const t = %SetTaint("proto");
  function Base() {}
  Base.prototype.data = t;
  return %GetTaint(new Base().data) !== 0;
});

// === 20. Symbol key (crash safety) ===
test("Symbol property key (crash safety)", () => {
  const t = %SetTaint("sym");
  const o = {};
  o[Symbol("key")] = t;
  return true;
});

// === 21. WeakRef + GC (crash safety) ===
test("WeakRef to tainted object + GC (crash safety)", () => {
  let wr;
  { const t = %SetTaint("weak"); wr = new WeakRef({ val: t }); }
  if (typeof gc === 'function') gc();
  return true;
});

// === 22. Promise chain (crash safety) ===
test("Promise chain taint (crash safety)", () => {
  const t = %SetTaint("promise");
  Promise.resolve(t).then(v => v + " then1").then(v => v + " then2");
  return true;
});

// === 23. Generator function ===
test("Generator function taint", () => {
  function* gen(s) { yield s + "_y1"; yield s + "_y2"; }
  const t = %SetTaint("gen");
  return %GetTaint(gen(t).next().value) !== 0;
});

// === 24. Async/await (crash safety) ===
test("Async function (crash safety)", () => {
  async function af(s) { return s + " async"; }
  const t = %SetTaint("async");
  af(t); // fire and forget — test crash safety
  return true;
});

// === 25. GC stress with tainted objects ===
// Previously crashed at 2000+ due to OSR frame state corruption with DTA bytecodes.
// Fixed by disabling OSR (--dta-maglev implies --no-use-osr). Now safe at 5000+.
test("GC stress: 5000 tainted objects + push", () => {
  const arr = [];
  for (let i = 0; i < 5000; i++) {
    const t = %SetTaint("gc" + i);
    arr.push({ val: t + "_d", key: t });
  }
  return %GetTaint(arr[arr.length - 1].val) !== 0;
});

console.log(`\n=== Results: ${pass}/${total} passed, ${fail} failed ===`);
if (fail > 0) process.exit(1);
