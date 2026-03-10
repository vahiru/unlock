# 逆向工程分析报告：Qualcomm ABL 解锁流程分析

## 1. 概述
本文档详细描述了高通 ABL (Android Bootloader) 固件中解锁 token (unlocktoken) 的验证机制。该过程涉及 RSA 公钥解密、结构化数据校验以及设备状态更新。

## 2. 核心函数与逻辑

### 2.1 入口函数：`VerifyUnlockToken` (0x35B04)
负责处理 `flashing unlock` 等 Fastboot 命令的核心逻辑。
- **Token 校验**：调用 `AuthenticateUnlockToken` 进行 RSA 解密和内容校验。
- **状态位处理**：根据返回的状态位掩码执行不同操作：
    - `case 0`: 普通解锁。
    - `case 1`: `unlock_critical`。
    - `case 2`: 获取解锁能力。
- **后续操作**：若验证通过，遍历并擦除敏感分区（如 `modemst1`, `frp`, `keystore` 等）。

### 2.2 核心校验：`AuthenticateUnlockToken` (0x36780)
执行具体的解密和内容比对。
- **RSA 解密**：使用内置的 RSA 公钥（2048-bit）解密 256 字节的加密 token，解密结果存入 96 字节的 `DecryptedTokenBuffer`。
- **结构体布局 (Decrypted Token)**:
    - `0x00`: 魔数 (Magic) - `"PicoNew"` (7 字节)
    - `0x18`: 授权标识 (Auth Type) - `"AUTH"`
    - `0x20`: 序列号 (Serial Number) - 8 字节十六进制字符串（与单板 `CurrentBoardSerialNumber` 匹配）
    - `0x28`: 芯片 ID (Chip ID) - 与设备 `CurrentChipId` 匹配

### 2.3 辅助函数
- `InitializeRSAKey` (0x3B2A4): 初始化 RSA 密钥结构。
- `RSAPublicDecrypt` (0x3B594): 执行 RSA 公钥解密。
- `DisplayUnlockConfirmation` (0x53580): 在屏幕上显示解锁确认警告信息。
- `UpdateUnlockStatus` (0x3664C): 更新设备解锁状态，允许执行 `unlock_critical` 操作。

## 3. 关键全局变量
- `CurrentBoardSerialNumber` (0x9503A): 存储从设备获取的序列号。
- `CurrentChipId` (0x952FA): 存储从硬件读取的芯片 ID。
- `DecryptedTokenBuffer` (0x9533A): 存储解密后的 token 数据。
- `IsFastbootMode` (0x7EDD8): 标识当前是否处于 Fastboot 模式。
- `IsRecoveryMode` (0x7EDDC): 标识当前是否处于 Recovery 模式。

## 4. 安全性分析
- **硬件绑定**：Unlock token 通过序列号和芯片 ID 与特定物理硬件强绑定，防止在不同设备间复用。
- **RSA 保护**：Token 经过 RSA 加密，必须拥有对应的私钥才能生成有效的解锁凭证。
- **用户确认**：物理上的用户交互（屏幕确认）是解锁流程中的关键一环，有效防止了远程或静默攻击。
