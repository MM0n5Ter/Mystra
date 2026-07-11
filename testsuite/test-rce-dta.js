// test_rce_advanced.js
const cp = require('child_process');
const vm = require('vm');

// 1. 构造恶意 Payload
const malicious_cmd = "echo 'Hacked by OS Command!'";
const malicious_code = "console.log('Hacked by JS Evaluation!');";

// 2. 注入污点：触发 Taint-Driven Activation 引擎苏醒
const tainted_cmd = %SetTaint(malicious_cmd);
const tainted_code = %SetTaint(malicious_code);

// 3. 定义 5 种常规 RCE 测试用例
const rce_tests = [
    {
        name: "1. child_process.execSync (Shell Injection)",
        fn: () => {
            // 最经典的命令拼接注入
            cp.execSync("sh -c " + tainted_cmd);
        }
    },
    {
        name: "2. child_process.spawnSync (Arg Injection)",
        fn: () => {
            // 参数注入
            cp.spawnSync('sh', ['-c', tainted_cmd]);
        }
    },
    {
        name: "3. eval() (Dynamic Execution)",
        fn: () => {
            // 动态代码执行
            eval(tainted_code);
        }
    },
    {
        name: "4. new Function() (Constructor Execution)",
        fn: () => {
            // 通过 Function 构造器执行代码，常用于绕过简单的 eval 静态检查
            let malicious_fn = new Function(tainted_code);
            malicious_fn();
        }
    },
    {
        name: "5. vm.runInThisContext (VM Sandbox Escape)",
        fn: () => {
            // Node.js VM 模块代码执行
            vm.runInThisContext(tainted_code);
        }
    }
];

// 4. 依次触发 Sink
for (let t of rce_tests) {
    console.log(`\n---> [Testing] ${t.name}`);
    try {
        t.fn();
        console.log(`[+] Executed successfully without crashing.`);
    } catch (e) {
        console.error(`[-] Execution threw an error: ${e.message}`);
    }
}

console.log("\n=== Benchmark Finished ===");