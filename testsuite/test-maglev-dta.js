// test_maglev_taint.js — Test Maglev DTA coverage
// Run: cd TaintSpecDoc && ./node --dta-maglev --allow-natives-syntax ../claudeSpace/test_maglev_taint.js

// ===== Test 1: Binary op taint propagation through hot function =====
function concatStrings(a, b) {
    return a + b;
}

// Warm up with clean values to trigger Maglev
console.log("[Warm-up] concatStrings...");
for (var i = 0; i < 50000; i++) {
    concatStrings("hello_", String(i));
}
console.log("  Done.\n");

console.log("[Test 1] Binary op taint through JIT-compiled concatStrings:");
var tainted1 = %SetTaint("TAINTED_PAYLOAD");
var result1 = concatStrings("prefix_", tainted1);
var tid1 = %GetTaint(result1);
console.log("  result = " + JSON.stringify(result1));
console.log("  taint ID = " + tid1);
console.log("  " + (tid1 > 0 ? "PASS: taint survived Maglev" : "FAIL: taint lost in Maglev"));

// ===== Test 2: Variable assignment propagation =====
function assignThrough(x) {
    var y = x;
    return y;
}

console.log("\n[Warm-up] assignThrough...");
for (var j = 0; j < 50000; j++) {
    assignThrough("val_" + j);
}
console.log("  Done.\n");

console.log("[Test 2] Register move taint through JIT-compiled assignThrough:");
var tainted2 = %SetTaint("TAINTED_VAR");
var result2 = assignThrough(tainted2);
var tid2 = %GetTaint(result2);
console.log("  result = " + JSON.stringify(result2));
console.log("  taint ID = " + tid2);
console.log("  " + (tid2 > 0 ? "PASS: taint survived Maglev" : "FAIL: taint lost in Maglev"));

// ===== Test 3: Property access taint =====
function propAccess(obj) {
    return obj.data;
}

var warmObj = { data: "clean" };
console.log("\n[Warm-up] propAccess...");
for (var k = 0; k < 50000; k++) {
    propAccess(warmObj);
}
console.log("  Done.\n");

console.log("[Test 3] Property load taint through JIT-compiled propAccess:");
var taintedObj = {};
taintedObj.data = %SetTaint("TAINTED_PROP");
var result3 = propAccess(taintedObj);
var tid3 = %GetTaint(result3);
console.log("  result = " + JSON.stringify(result3));
console.log("  taint ID = " + tid3);
console.log("  " + (tid3 > 0 ? "PASS: taint survived Maglev" : "FAIL: taint lost in Maglev"));

// ===== Test 4: Sink detection through hot call path =====
function checkEval(code) {
    eval(code);
}

console.log("\n[Warm-up] checkEval...");
for (var m = 0; m < 50000; m++) {
    checkEval("void 0");
}
console.log("  Done.\n");

console.log("[Test 4] Sink detection (eval) through JIT-compiled checkEval:");
var tainted4 = %SetTaint("console.log('hacked')");
console.log("  Calling checkEval with tainted code...");
checkEval(tainted4);
console.log("  (Check for DTA-ALERT above)");

// ===== Summary =====
console.log("\n=== Summary ===");
console.log("Test 1 (binary op):    " + (tid1 > 0 ? "PASS" : "FAIL"));
console.log("Test 2 (register move):" + (tid2 > 0 ? "PASS" : "FAIL"));
console.log("Test 3 (property load):" + (tid3 > 0 ? "PASS" : "FAIL"));
console.log("Test 4 (sink/eval):    check DTA-ALERT output above");
