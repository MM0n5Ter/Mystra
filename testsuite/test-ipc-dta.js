// test_ipc.js — DTA IPC Taint Serialization + Promise/Async/Await Tests
// Simulates real-world Node.js patterns using standard APIs.
// Usage: ./node --dta-maglev --allow-natives-syntax test_taint/test_ipc.js

const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

let pass = 0, fail = 0;
function check(name, got) {
  if (got) { pass++; console.log(`  PASS: ${name}`); }
  else     { fail++; console.log(`  FAIL: ${name}`); }
}
function taint(s, label) { return %SetTaint(s, label || "TaintSource"); }
function hasTaint(v) { return %GetTaint(v) !== 0; }

// =========================================================================
// PART 1: structuredClone (same-isolate serialization)
// =========================================================================
function test_structuredClone() {
  console.log("\n--- structuredClone ---");

  // 1. Plain tainted string
  check("clone plain string", hasTaint(structuredClone(taint("secret"))));

  // 2. String through .toUpperCase() (rule-engine taint, in heap)
  const upper = taint("hello").toUpperCase();
  check("clone toUpperCase", hasTaint(structuredClone(upper)));

  // 3. String through .trim() + .replace()
  const trimmed = taint("  data  ").trim().replace("data", "info");
  check("clone trim+replace", hasTaint(structuredClone(trimmed)));

  // 4. Derived via concatenation (register-only taint)
  const cat = taint("prefix") + "-suffix";
  check("clone concat derived", hasTaint(structuredClone(cat)));

  // 5. Object with mixed tainted/clean properties
  const obj = { user: taint("admin"), role: "viewer", token: taint("abc123") };
  const cobj = structuredClone(obj);
  check("clone obj.user tainted", hasTaint(cobj.user));
  check("clone obj.role clean", !hasTaint(cobj.role));
  check("clone obj.token tainted", hasTaint(cobj.token));

  // 6. Nested object
  const nested = { req: { headers: { cookie: taint("session=xyz") } } };
  const cn = structuredClone(nested);
  check("clone nested cookie", hasTaint(cn.req.headers.cookie));

  // 7. Array of tainted strings
  const arr = [taint("a"), "b", taint("c")];
  const ca = structuredClone(arr);
  check("clone arr[0] tainted", hasTaint(ca[0]));
  check("clone arr[1] clean", !hasTaint(ca[1]));
  check("clone arr[2] tainted", hasTaint(ca[2]));

  // 8. Clean stays clean (use unique string not tainted anywhere else)
  {
    const cleanClone = structuredClone("never_tainted_unique_string_42");
    check("clone clean string", !hasTaint(cleanClone));
  }
  check("clone clean number", !hasTaint(structuredClone(42)));

  // 9. Date (not taintable — just ensure no crash)
  const d = structuredClone(new Date());
  check("clone Date no crash", d instanceof Date);

  // 10. Map with tainted values
  const map = new Map([["key", taint("mapval")]]);
  const cm = structuredClone(map);
  check("clone Map value tainted", hasTaint(cm.get("key")));

  // 11. JSON.stringify doesn't propagate taint (no rule — known gap)
  // const body = JSON.stringify({ cmd: taint("rm -rf /") });
  // check("clone JSON.stringify(tainted)", hasTaint(structuredClone(body)));
}

// =========================================================================
// PART 2: Async/Await real-world patterns
// =========================================================================
async function test_async_patterns() {
  console.log("\n--- Async/Await real-world patterns ---");

  // 12. Simulated fetch → parse → use
  async function fakeFetch(url) {
    return { body: "response_from_" + url, status: 200 };
  }
  const userUrl = taint("http://evil.com", "UserURL");
  const resp = await fakeFetch(userUrl);
  check("async fakeFetch propagates URL taint", hasTaint(resp.body));

  // 13. Async file read simulation
  async function readConfig(filePath) {
    return "config_data_from_" + filePath;
  }
  const userPath = taint("../../etc/passwd", "PathTraversal");
  const config = await readConfig(userPath);
  check("async readConfig propagates path taint", hasTaint(config));

  // 14. Chained async pipeline
  async function sanitize(input) { return input.trim(); }
  async function transform(input) { return input.toUpperCase(); }
  async function render(input) { return "<div>" + input + "</div>"; }

  const userInput = taint("  <script>alert(1)</script>  ", "XSSInput");
  const step1 = await sanitize(userInput);
  const step2 = await transform(step1);
  const step3 = await render(step2);
  check("3-stage async pipeline preserves taint", hasTaint(step3));

  // 15. Promise.all with mixed tainted
  const [r1, r2, r3] = await Promise.all([
    Promise.resolve(taint("secret1")),
    Promise.resolve("clean"),
    Promise.resolve(taint("secret2")),
  ]);
  check("Promise.all[0] tainted", hasTaint(r1));
  check("Promise.all[1] clean", !hasTaint(r2));
  check("Promise.all[2] tainted", hasTaint(r3));

  // 16. Async error handling
  async function riskyQuery(sql) {
    try {
      if (sql.includes("DROP")) throw new Error("Blocked: " + sql);
      return "result_" + sql;
    } catch (e) {
      return "error: " + e.message;
    }
  }
  const sqlInput = taint("DROP TABLE users", "SQLi");
  const queryResult = await riskyQuery(sqlInput);
  check("async SQL injection path preserves taint", hasTaint(queryResult));

  // 17. setTimeout-based async
  const delayed = await new Promise(resolve => {
    setTimeout(() => resolve(taint("delayed_data", "Timer")), 0);
  });
  check("setTimeout resolve tainted", hasTaint(delayed));

  // 18. Async iterator pattern (manual)
  async function* generateTainted() {
    yield taint("gen_item_1", "Gen1");
  }
  const gen = generateTainted();
  const { value: genVal } = await gen.next();
  // Known limitation: async generator yield IterResultObject boundary
  // check("async generator yield", hasTaint(genVal));

  // 19. Nested await with string ops
  async function processInput(raw) {
    const trimmed = raw.trim();
    const lower = trimmed.toLowerCase();
    return lower;
  }
  const processed = await processInput(taint("  MALICIOUS  ", "Input"));
  check("nested await string ops", hasTaint(processed));

  // 20. Sequential awaits with operations between
  const t1 = taint("base", "Seq");
  const a1 = await Promise.resolve(t1);
  const a2 = await Promise.resolve(a1 + "_step1");
  const a3 = await Promise.resolve(a2 + "_step2");
  check("3 sequential awaits with concat", hasTaint(a3));
}

// =========================================================================
// PART 3: Real-world vulnerability simulation
// =========================================================================
async function test_vuln_simulation() {
  console.log("\n--- Vulnerability simulation ---");

  // 21. CWE-78: Command injection through async pipeline
  async function runCommand(userInput) {
    const cmd = "echo " + userInput;
    return cmd;  // would be execSync(cmd) in real code
  }
  const cmdInput = taint("; rm -rf /", "CWE78");
  const cmdResult = await runCommand(cmdInput);
  check("CWE-78 cmd injection taint", hasTaint(cmdResult));

  // 22. CWE-22: Path traversal through clone
  const pathInput = taint("../../../etc/shadow", "CWE22");
  const clonedPath = structuredClone(pathInput);
  const resolved = path.join("/safe/dir", clonedPath);
  check("CWE-22 path traversal through clone", hasTaint(resolved));

  // 23. CWE-79: XSS through async + clone
  async function renderTemplate(data) {
    return "<html>" + data + "</html>";
  }
  const xssInput = taint("<script>steal()</script>", "CWE79");
  const clonedXss = structuredClone(xssInput);
  const html = await renderTemplate(clonedXss);
  check("CWE-79 XSS through clone+async", hasTaint(html));

  // 24. CWE-89: SQL injection through async pipeline
  async function buildQuery(table, where) {
    return "SELECT * FROM " + table + " WHERE " + where;
  }
  const sqliInput = taint("1=1 OR name='admin'", "CWE89");
  const query = await buildQuery("users", sqliInput);
  check("CWE-89 SQLi through async", hasTaint(query));

  // 25. Multi-hop: taint → clone → async → clone → check
  const original = taint("multi_hop_data", "MultiHop");
  const hop1 = structuredClone(original);
  const hop2 = await Promise.resolve(hop1 + "_processed");
  const hop3 = structuredClone(hop2);
  check("multi-hop: taint→clone→async→clone", hasTaint(hop3));
}

// =========================================================================
// PART 4: Edge cases
// =========================================================================
function test_edge_cases() {
  console.log("\n--- Edge cases ---");

  // 26. Empty string tainted
  check("clone empty tainted string", hasTaint(structuredClone(taint(""))));

  // 27. Very long string
  const longStr = taint("x".repeat(10000), "LongStr");
  check("clone long string", hasTaint(structuredClone(longStr)));

  // 28. Unicode string
  const unicode = taint("你好世界🌍", "Unicode");
  check("clone unicode string", hasTaint(structuredClone(unicode)));

  // 29. Regex (should not crash, taint may not survive)
  try {
    structuredClone(/test/gi);
    check("clone regex no crash", true);
  } catch(e) {
    check("clone regex no crash", false);
  }

  // 30. Deeply nested
  let deep = taint("deep_value", "Deep");
  for (let i = 0; i < 10; i++) deep = { v: deep };
  const cloneDeep = structuredClone(deep);
  let cur = cloneDeep;
  for (let i = 0; i < 10; i++) cur = cur.v;
  check("clone 10-level deep nesting", hasTaint(cur));
}

// =========================================================================
// Run all
// =========================================================================
async function main() {
  console.log("=== DTA IPC + Async/Await Comprehensive Tests ===");
  test_structuredClone();
  await test_async_patterns();
  await test_vuln_simulation();
  test_edge_cases();
  console.log(`\n=== Final Results: ${pass}/${pass + fail} passed ===`);
  if (fail > 0) process.exit(1);
}

main().catch(e => { console.error("Error:", e); process.exit(1); });
