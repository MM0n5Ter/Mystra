// 辅助函数：格式化打印污点状态
function assertTaint(operation, obj) {
    const taintValue = %GetTaint(obj);
    const status = taintValue > 0 ? "✅ [PASS]" : "❌ [FAIL]";
    console.log(`${status} ${operation.padEnd(45, ' ')} | Taint: ${taintValue}`);
}

console.log("========== DTA Engine: Node.js Buffer Comprehensive Test ==========\n");

// 1. 污点源生成 (Taint Generation)
const rawString = "SENSITIVE_PAYLOAD_DATA";
const taintedStr = %SetTaint(rawString);
console.log(`[INFO] Source String Length: ${taintedStr.length}`);
assertTaint("1. Source String (%SetTaint)", taintedStr);

// 2. 缓冲区的创建与字符串编码 (Creation & Stringification)
const buf1 = Buffer.from(taintedStr, 'utf8');
assertTaint("2a. Buffer.from(taintedStr)", buf1);

const outUtf8 = buf1.toString('utf8');
assertTaint("2b. buf.toString('utf8')", outUtf8);

const outBase64 = buf1.toString('base64');
assertTaint("2c. buf.toString('base64')", outBase64);

const outHex = buf1.toString('hex');
assertTaint("2d. buf.toString('hex')", outHex);

// 3. 内存写入操作 (Write Operations)
const buf2 = Buffer.allocUnsafe(taintedStr.length);
buf2.write(taintedStr);
assertTaint("3a. buf.write(taintedStr)", buf2);
assertTaint("3b. buf2.toString() (after write)", buf2.toString('utf8'));

// 4. 内存拷贝操作 (Copy Operations)
const buf3 = Buffer.alloc(taintedStr.length);
buf1.copy(buf3);
assertTaint("4a. buf1.copy(buf3) -> Target Buffer", buf3);
assertTaint("4b. buf3.toString() (after copy)", buf3.toString('utf8'));

// 5. 视图与切片操作 (Views & Slicing)
const slicedBuf = buf1.slice(0, 9); // 切割出 "SENSITIVE"
assertTaint("5a. buf.slice() (Memory View)", slicedBuf);
assertTaint("5b. slicedBuf.toString()", slicedBuf.toString('utf8'));

// 6. 底层 TypedArray 内存映射桥接测试 (The ArrayBuffer Bridge)
// 验证我们讨论的 "对象指针 -> ArrayBuffer -> 新对象" 的传播链路
const underlyingArrayBuffer = buf1.buffer;
assertTaint("6a. buf.buffer (ArrayBuffer Access)", underlyingArrayBuffer);

const fastBufferView = new Uint8Array(underlyingArrayBuffer, 0, 5);
assertTaint("6b. new Uint8Array(taintedArrayBuffer)", fastBufferView);
