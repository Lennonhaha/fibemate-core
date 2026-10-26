# fibemate-core

FIBEMATE 后量子密码学核心原语 — 纯 JavaScript 实现，浏览器 / Node.js 双端可用。

> **Status:** reference implementation (interoperability and teaching). Not production-grade.
> **Warning:** no side-channel hardening. Constant-time idioms are used, but pure JavaScript
> cannot guarantee constant-time execution — the JIT may reorder or eliminate operations.
> Use the WASM/C path in the main repository for anything that needs real timing guarantees.

## 当前版本内容

| 原语 | 标准 | 实现状态 | 说明 |
|------|------|----------|------|
| **ML-KEM-768** | FIPS 203 | ✅ 自研纯 JS（857 行） | 参考实现，零依赖；<b>未做侧信道加固</b> |

> **路线图**：ML-DSA-65（FIPS 204）、SLH-DSA（FIPS 205）、SM2/SM3/SM4（国密）将陆续加入。
> 注意：主仓 `packages/fml-dsa` 目前是 @noble/post-quantum 的封装（非独立实现），
> 独立化完成前不会放入本包。

## 安装

**本地参考实现，未发布到 npm。** 不要写 `npm install fibemate-core`（registry 上没有这个包）。
用它就直接引用本目录：

```bash
cd fibemate-core && npm link      # 或者在使用方用相对路径 require('./fibemate-core')
```

> 注意：本包是**纯 JS 参考实现**（`src/kem/ml-kem-768.js`，无原生依赖）；
> 主仓里同名的 `packages/pqc-kem` 是另一个东西（带 C addon 的生产实现）。

## 使用

### Node.js (CommonJS)

```javascript
const { generateKeypair, encapsulate, decapsulate } = require('fibemate-core');

// 密钥生成
const { publicKey, secretKey } = generateKeypair();   // pk: 1184B, sk: 2400B

// 封装（加密）
const { ciphertext, sharedSecret } = encapsulate(publicKey);  // ct: 1088B, ss: 32B

// 解封装（解密）——注意参数顺序：(secretKey, ciphertext)
const recovered = decapsulate(secretKey, ciphertext);
// recovered === sharedSecret
```

### 浏览器

```html
<script src="src/kem/ml-kem-768.js"></script>
<script>
  const { publicKey, secretKey } = window.MLKEM768.generateKeypair();
</script>
```

## API

### `generateKeypair()`
生成 ML-KEM-768 密钥对。
- **返回** `{ publicKey: Uint8Array(1184), secretKey: Uint8Array(2400) }`

### `encapsulate(publicKey)`
使用公钥封装共享密钥。
- **参数** `publicKey: Uint8Array(1184)`
- **返回** `{ ciphertext: Uint8Array(1088), sharedSecret: Uint8Array(32) }`

### `decapsulate(secretKey, ciphertext)`
解封装恢复共享密钥。
- **注意**：参数顺序为 `(secretKey, ciphertext)`，与其他库（如 `(ciphertext, secretKey)`）不同
- **参数** `secretKey: Uint8Array(2400)`, `ciphertext: Uint8Array(1088)`
- **返回** `Uint8Array(32)` — 共享密钥；若密文被篡改，返回不同值（隐式拒绝）

## 验证

```bash
npm test   # 8 项测试：长度/roundtrip/篡改检测/会话隔离
```

参考实现（`src/kem/ml-kem-768.js`）的防护写法（**尽力而为，不等同于恒定时间保证**）：
- 无分支比较（`ctEqMask`）与选择（`ctSelectU8`）
- 敏感中间值归零（`zeroize*`）
- 错误密文不提前返回（计算双方候选密钥后用掩码选择）

> **为什么不能声称"恒定时间"**：纯 JS 无法约束 JIT 优化、分支预测与数组访问模式。
> 文件内对模运算的处理已明确标注 `WARNING: not truly constant-time in pure JS`。
> 因此本项目**不作**恒定时间保证，也未做 TVLA/侧信道测量以外的任何硬化验证。

## 实现范围

本仓库只有 **JavaScript** 参考实现。C、WebAssembly、FPGA 三端实现位于主仓：
https://github.com/Lennonhaha/fibemate

> Note: This repository contains the JS reference implementation. The C, WebAssembly,
> and FPGA implementations are located in the main FIBEMATE repository.

## 关联项目

- VWZ 形式化验证：https://github.com/Lennonhaha/vwz-formalization
- CBOM 审计与文档数字对账工具：https://github.com/Lennonhaha/fibemate-tools

## 来源与许可

- 来源：https://github.com/Lennonhaha/fibemate （`packages/pqc-kem/src/`）
- 许可：**Apache-2.0**（SPDX）。允许闭源商用，只需保留版权与许可声明。
- 这不是学术基准实现；生产使用请配合独立审计与 KAT 验证。
