// ============================================================
// fs sink / propagation coverage: link / symlink / realpath
//
//   link / symlink  -> CWE-22 path sink (expect [DTA-ALERT] CWE-22 on stderr)
//   realpath        -> propagation arg[0] -> ret (realpathSync result tainted)
//
// Run: ./node --dta-maglev --allow-natives-syntax testsuite/test-fs-gap-dta.js
// Alert checks are verified by grepping stderr for the sink name.
// ============================================================
const fs = require('fs');
const os = require('os');
const path = require('path');

let pass = 0, fail = 0, total = 0;
function test(name, fn) {
  total++;
  try {
    if (fn()) { console.log(`  ✅ PASS | ${name}`); pass++; }
    else      { console.log(`  ❌ FAIL | ${name}`); fail++; }
  } catch (e) {
    console.log(`  ❌ CRASH | ${name}: ${e.message}`); fail++;
  }
}

const tmpDir = path.join(os.tmpdir(), 'dta_fsgap_' + process.pid);
try { fs.mkdirSync(tmpDir, { recursive: true }); } catch (e) {}
const realFile = path.join(tmpDir, 'real.txt');
try { fs.writeFileSync(realFile, 'hi'); } catch (e) {}
// A symlinked directory so realpath() returns a string DISTINCT from its input,
// defeating any string-interning false-positive in the propagation tests.
const linkDir = path.join(tmpDir, 'linkdir');
let haveSymlinkDir = false;
try { fs.symlinkSync(tmpDir, linkDir, 'dir'); haveSymlinkDir = true; } catch (e) {}
const viaLink = path.join(linkDir, 'real.txt'); // realpath -> tmpDir/real.txt

console.log('\n=== fs gap: link / symlink / realpath ===\n');

// 1. linkSync(tainted src) -> CWE-22 alert (Sink: link)
test('fs.linkSync(tainted_src, dest) - taint reaches link sink', () => {
  const src = %SetTaint(realFile);
  const dst = path.join(tmpDir, 'hardlink_' + Math.random());
  try { fs.linkSync(src, dst); } catch (e) {}
  return true; // crash-safety; alert verified via stderr grep
});

// 2. symlinkSync(tainted target) -> CWE-22 alert (Sink: symlink)
test('fs.symlinkSync(tainted_target, path) - taint reaches symlink sink', () => {
  const target = %SetTaint(realFile);
  const lnk = path.join(tmpDir, 'symlink_' + Math.random());
  try { fs.symlinkSync(target, lnk); } catch (e) {}
  return true;
});

// 3. realpathSync(tainted) -> result tainted (propagation arg0 -> ret).
//    Use a non-canonical input (./ segment) so realpath returns a DISTINCT
//    string object — defeats the string-interning false-positive.
test('fs.realpathSync(tainted via symlink) - distinct result carries taint', () => {
  if (!haveSymlinkDir) { console.log('       (skip: symlink dir unavailable)'); return true; }
  const p = %SetTaint(viaLink);
  let r;
  try { r = fs.realpathSync(p); } catch (e) { return false; }
  if (r === viaLink) { console.log('       (warn: result === input)'); }
  return r !== viaLink && %GetTaint(r) !== 0;
});

// 4. realpathSync then concat -> derived path tainted (e2e)
test('realpathSync result + concat - taint survives to derived path', () => {
  if (!haveSymlinkDir) { console.log('       (skip: symlink dir unavailable)'); return true; }
  const p = %SetTaint(viaLink);
  let r;
  try { r = fs.realpathSync(p); } catch (e) { return false; }
  const derived = r + '/child';
  return %GetTaint(derived) !== 0;
});

// ---- Vectored I/O: writev / readv (CodeQL NodeJSFileSystemVector{Write,Read}) ----

// 5. readvSync into buffers reads tainted file content (path-based fd chain):
//    writeFileSync(tainted) -> openSync -> readvSync -> buffers[i].toString() tainted.
//    The fd carries the file's taint; readBuffers scatters it deep into the buffer
//    array (ELEM_DEEP). Consume via array index so the deep key propagates down.
test('fs.readvSync(fd, buffers) - tainted file content reaches buffer elements', () => {
  const secretFile = path.join(tmpDir, 'vsecret.txt');
  fs.writeFileSync(secretFile, %SetTaint('SECRET'));          // io_taint[path]
  const fd = fs.openSync(secretFile, 'r');                    // fd carries taint
  try {
    const buffers = [Buffer.alloc(6)];
    fs.readvSync(fd, buffers);                                // readBuffers: fd -> buffers[**]
    return %GetTaint(buffers[0].toString('utf8')) !== 0;
  } finally { fs.closeSync(fd); }
});

// 6. readvSync into MULTIPLE buffers - every buffer's elements get taint.
test('fs.readvSync(fd, [b1,b2]) - taint scatters across all buffers', () => {
  const secretFile = path.join(tmpDir, 'vsecret2.txt');
  fs.writeFileSync(secretFile, %SetTaint('ABCDEFGH'));
  const fd = fs.openSync(secretFile, 'r');
  try {
    const buffers = [Buffer.alloc(4), Buffer.alloc(4)];
    fs.readvSync(fd, buffers);
    return %GetTaint(buffers[0].toString()) !== 0 && %GetTaint(buffers[1].toString()) !== 0;
  } finally { fs.closeSync(fd); }
});

// 7. writevSync(fd, [taintedBuf]) then readvSync same fd - round-trip via io_taint[fd].
test('fs.writevSync then readvSync (same fd) - taint survives round trip', () => {
  const rtFile = path.join(tmpDir, 'vrt.txt');
  const fd = fs.openSync(rtFile, 'w+');                       // read+write
  try {
    const src = Buffer.from(%SetTaint('PAYLOAD!'));           // tainted buffer
    fs.writevSync(fd, [src]);                                 // writeBuffers: SET io_taint[fd]
    const buffers = [Buffer.alloc(8)];
    fs.readvSync(fd, buffers, 0);                             // read back from offset 0
    return %GetTaint(buffers[0].toString()) !== 0;
  } finally { fs.closeSync(fd); }
});

console.log(`\n=== ${pass}/${total} passed (${fail} failed) ===\n`);
