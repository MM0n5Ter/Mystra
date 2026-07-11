const { performance } = require('perf_hooks');

// 辅助断言函数
function assertTaint(testName, value, expectTainted) {
    const taintId = %GetTaint(value);
    const isTainted = taintId !== 0;
    const status = isTainted === expectTainted ? "✅ PASS" : "❌ FAIL";
    console.log(`${status} | [${testName.padEnd(45, '.')}] - Expected: ${expectTainted}, Actual Taint ID: ${taintId}`);
}

console.log("==================================================");
console.log(" DTA String Builtins Ground Truth Test Suite");
console.log("==================================================\n");

// 0. 生成初始污点数据
let secretStr = %SetTaint("TOP_SECRET_DATA");
let safeStr = "Public_Data";

// =========================================================================
// Group 1: 基础字符串派生 (Direct Derivation & PassThrough)
// 测试规则: slice (Derive), trim (PassThrough), toLowerCase (PassThrough)
// =========================================================================
console.log("--- Group 1: Basic String Derivation ---");
assertTaint("String.slice (self -> ret)", secretStr.slice(0, 5), true);
assertTaint("String.toLowerCase (self => ret)", secretStr.toLowerCase(), true);
let paddedSecret = %SetTaint("  SECRET  ");
assertTaint("String.trim (self => ret)", paddedSecret.trim(), true);
console.log("");

// =========================================================================
// Group 2: 多源派生 (Multi-source Derivation)
// 测试规则: concat (self | argRange -> ret), replace (self | arg[1] -> ret)
// =========================================================================
console.log("--- Group 2: Multi-source Derivation ---");
// 测 arg 被污染
assertTaint("String.concat (safe.concat(tainted))", safeStr.concat(secretStr), true);
// 测 self 被污染
assertTaint("String.concat (tainted.concat(safe))", secretStr.concat(safeStr), true);
// 测替换内容被污染
assertTaint("String.replace (safe.replace(tainted))", safeStr.replace("Public", secretStr), true);
console.log("");


// =========================================================================
// Group 3: Smi 级精度追踪 (Scalar/Smi Taint Tracking)
// 测试规则: charCodeAt (self -> ret), String.fromCharCode (argRange -> ret)
// =========================================================================
console.log("--- Group 3: Smi Scalar Tracking ---");
// 1. 降维：String -> Smi (测试影子寄存器/累加器能否承接数字污点)
let taintedCharCode = secretStr.charCodeAt(0);
assertTaint("String.charCodeAt (String -> Smi)", taintedCharCode, true);

// 2. 升维：Smi -> String (测试能否将 Smi 污点重新吸回对象堆)
let restoredStr = String.fromCharCode(taintedCharCode);
assertTaint("String.fromCharCode (Smi -> String)", restoredStr, true);
console.log("");


// =========================================================================
// Group 4: 结构化通配符逃逸 (Structural Escape & Wildcard)
// 测试规则: split (self -> ret[*]), match (self -> ret[*] AND self -> ret.input)
// =========================================================================
console.log("--- Group 4: Structural Escape (Wildcards) ---");
let csvTainted = %SetTaint("admin,password123");
let splitArray = csvTainted.split(",");
// 验证 ElementWildcard [*] 能否正确污染数组内部元素
assertTaint("String.split (Array Element 0)", splitArray[0], true);
assertTaint("String.split (Array Element 1)", splitArray[1], true);

let matchResult = secretStr.match(/SECRET/);
// 验证双路并发 Sink：同时污染元素 [*] 和指定属性 .input
assertTaint("String.match (Array Element 0)", matchResult[0], true);
assertTaint("String.match (Specific Property .input)", matchResult.input, true);
console.log("");


// =========================================================================
// Group 5: 控制流截断 (Sanitization / Taint Cut-off)
// 测试规则: indexOf, includes, startsWith (~> clear)
// =========================================================================
console.log("--- Group 5: Control-flow Cut-off ---");
assertTaint("String.indexOf (~> clear)", secretStr.indexOf("SECRET"), false);
assertTaint("String.includes (~> clear)", secretStr.includes("DATA"), false);
assertTaint("String.startsWith (~> clear)", secretStr.startsWith("TOP"), false);
console.log("");


// =========================================================================
// Group 6: 高级字面量 (Advanced Template Literals)
// 测试规则: String.raw
// =========================================================================
console.log("--- Group 6: Advanced Literals ---");
// String.raw 的 arg[1] 对应模板字符串插入的变量
let rawResult = String.raw`Data is: ${secretStr}`;
assertTaint("String.raw (Tainted substitution)", rawResult, true);

console.log("\n==================================================");