// test-var-io-boundary.js — Regression test for Array.prototype.slice taint loss
// Bug: [].slice.call(arguments) loses element taint after Maglev compilation.
// Root cause: ArrayPrototypeSlice shares builtin name 'slice' with StringPrototypeSlice.
// Rule dispatcher picks StringPrototypeSlice (wrong rule, propagates @self not @self[*]).

// Test 1: Direct argument taint (should always work)
function test_direct(cmd) { return %GetTaint(cmd); }
for (var i = 0; i < 1000; i++) test_direct('c');
var t = %SetTaint('evil');
var cmd = 'prefix' + t;
var r1 = test_direct(cmd);
console.log(r1 > 0 ? 'PASS' : 'FAIL', '| direct param after warmup');

// Test 2: [].slice.call(arguments) — CURRENTLY FAILS
function test_slice(cmd) {
    var args = [].slice.call(arguments, 0);
    return %GetTaint(args[0]);
}
for (var i = 0; i < 1000; i++) test_slice('c');
var r2 = test_slice(cmd);
console.log(r2 > 0 ? 'PASS' : 'FAIL', '| [].slice.call(arguments) after warmup');

// Test 3: [...arguments] spread — should work (different codepath)
function test_spread(cmd) {
    var args = [...arguments];
    return %GetTaint(args[0]);
}
for (var i = 0; i < 1000; i++) test_spread('c');
var r3 = test_spread(cmd);
console.log(r3 > 0 ? 'PASS' : 'FAIL', '| [...arguments] spread after warmup');

// Test 4: shelljs pattern (wrap closure + slice + apply)
function wrap(name, fn) {
    return function() {
        var args = [].slice.call(arguments, 0);
        return fn.apply(this, args);
    };
}
function _exec(command) { return %GetTaint(command); }
var exec = wrap('exec', _exec);
for (var i = 0; i < 1000; i++) exec('clean-' + i, {}, function(){});
var r4 = exec(cmd, {}, function(){});
console.log(r4 > 0 ? 'PASS' : 'FAIL', '| shelljs wrap(slice+apply) after warmup');
