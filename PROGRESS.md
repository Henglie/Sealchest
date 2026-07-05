# 密匣 Sealchest · PROGRESS

> 给 AI / 开发者看。接手前先读根目录 `开发规范.md`，再读本文「技术栈红线」+「踩坑记录」两节。
> 本地代号 AnnVeraCrypt（旧文件夹名），对外一律称**密匣 / Sealchest**。
> 原名密匣，因与他人项目重名，2026-07 改称匿匣。英文名 Sealchest、包名 com.henglie.sealchest、仓库地址均不变。

---

## ▍一句话

安卓无 root 加载 VeraCrypt 加密容器，纯用户态解密 + SAF 暴露文件系统。第一版只读 + FAT（FAT12/16/32）。

---

## ▍技术栈红线（本机实测组合，照搬 KarmaWitness，勿擅改）

- **AGP 8.11.1 + Gradle 8.13 + Kotlin 2.1.20**，由 Android Studio JBR 21 跑（非系统 JDK）。
- **compileSdk = 36 / targetSdk = 36 / minSdk = 23**。minSdk 23 = Android 6.0，覆盖 2015 至今（比"2019 起"要求更宽）。本机只装 android-36，故 compileSdk 锁 36。
- **NDK 30.0.14904198 + CMake 3.22.1**，ABI：arm64-v8a / armeabi-v7a / x86_64，C++/C17。
- 包名 `com.henglie.sealchest`，.so 名 `libsealchest.so`。
- Compose + Material3，**用谷歌原生 M3，不套 FairyGlass 玻璃风**（用户明确要求，安卓项目例外）。
- 安卓视觉与代码遵循 `skills/android-native-dev`、`skills/android-project-generator`、`skills/kotlin`。

### 本机环境关键路径（换机需改）

- SDK：`D:/Program Files/Android/Sdk`
- JBR：`D:/Program Files/Android/Android Studio/jbr`（钉进 gradle.properties 的 `org.gradle.java.home`）
- adb：`D:/CTFRe_ToolsBox_ESS/T00Ls/Android_Tools/搞机工具箱11.0.1/adb.exe`（或 SDK platform-tools 自带）
- 本机无 gradle CLI，wrapper jar 从 KarmaWitness 复用。

---

## ▍架构分层

```
Compose UI (M3)  选容器 → 输密码/PIM/PRF → 浏览文件
      │
SAF DocumentsProvider  把解开的 FAT 暴露给系统/他 app
      │
FAT 文件系统层 (Kotlin)  只读解析 FAT12/16/32
      │
JNI 桥 (NativeBridge.kt + native_lib.cpp)  开卷/按扇区解密
      │
VeraCrypt crypto 核心 (纯 C, 移植自 third_party/VeraCrypt)
```

JNI 只暴露三个能力：开卷（验密码、派生密钥、出 CRYPTO_INFO 句柄）、按扇区解密、关卷（销毁密钥）。

---

## ▍第一版范围（已与用户敲定）

- 只读，不写入（写入版二期）。
- 内层文件系统：FAT12 / FAT16 / FAT32。exFAT、NTFS 不做（exFAT 是独立格式，留二期）。
- 加密算法：全套编入（AES/Serpent/Twofish/Camellia/Kuznyechik 级联 + 各哈希/Argon2id），最大化容器兼容性。
- 暴露方式：SAF DocumentsProvider。

---

## ▍移植清单（VeraCrypt C 核心 → src/main/cpp）

来源 `third_party/VeraCrypt/src/`，已勘察确认纯 C 回退路径完整，开 `CRYPTOPP_DISABLE_ASM` 即可 ARM 编译。

**Crypto/**：config.h, cpu.c/h, misc.h, Aes*(.c/h), Serpent, Twofish, Camellia, kuznyechik, Sha2, Whirlpool, Streebog, blake2s, Argon2/。可选 ARM 加速 Aes_hw_armv8.c / sha256_armv8.c。
**Common/**：Tcdefs.h, Crypto.c/h, Volumes.c/h, Pkcs5.c/h, Endian.c/h, GfMul.c/h, Xts.c/h, Crc.c/h, Password.h, EncryptionThreadPool.h（stub）。
**排除**：所有 .asm / *_x86.S / *_x64.S / SSE / SIMD / RNG / jitterentropy / t1ha / wolfCrypt / sm4。

**需 stub 的平台符号**：`CRYPTOPP_DISABLE_ASM`=1、`VirtualLock/Unlock`→空、`GetEncryptionThreadCount`→返 1（强制单线程）、`EncryptionThreadPoolDoWork`→直调 DecryptDataUnitsCurrentThread、`<io.h>` 在 Volumes.c 排除。`ReadVolumeHeaderWithAbort` 吃内存 buffer，不碰文件 I/O。

**卷头格式**：salt 偏移 0 长 64；加密区 64..512（448 字节）；magic "VERA" 0x56455241 在偏移 64；主密钥区偏移 256 长 256。PBKDF2 迭代默认 SHA256 non-boot 500000，PIM≠0 时 15000+pim*1000。

---

## ▍进度

- [x] 建本地 git，克隆 VeraCrypt 源到 third_party/VeraCrypt
- [x] 勘察 VeraCrypt C 核心，确认 ARM 可编译 + 移植清单
- [x] 敲定范围（只读/FAT/全算法/SAF）与命名（密匣 Sealchest）
- [x] 补 README.md / PROGRESS.md
- [x] 生成 Gradle 工程骨架（照搬 KarmaWitness 配置），复用 wrapper jar
- [x] 最小 native 链路（sha256 自检 + NativeBridge）+ 安卓机器人图标
- [x] 首次 `assembleDebug` 跑通：三 ABI 的 libsealchest.so 全编入 APK，工具链命门已验证（`compiled` 态）
- [x] 移植 VeraCrypt C 核心 + 平台 stub，扩 CMakeLists（第二阶段重头）
- [x] 扩 JNI 桥（开卷/解扇区/关卷）+ NativeBridge 对应方法
- [x] 用已知 VeraCrypt 测试容器验证开卷 + 解扇区正确性（官方 test.*.hc 三 PRF 全过，见踩坑）
- [x] FAT 文件系统只读解析层（FAT12/16/32：BPB + 簇链 + 短名/VFAT 长名，见 fs/）
- [x] SAF DocumentsProvider（把解锁卷暴露给系统文件选择器，只读，明文只走进程内管道）
- [x] Compose M3 UI（选容器/输密码/PIM/PRF/解锁/浏览/上锁）
- [x] `assembleDebug` 三 ABI 全过，APK 产出（23MB）
- [x] 真机端到端验收：一加安卓16 经系统文件管理器解锁 + 浏览 + 看文件全通过
- [x] 内置文件浏览器（browse/）：目录栈导航 + 图片/文本内嵌预览 + 导出到手机 + 用其它应用打开。不依赖系统 DocumentsUI，破解老安卓（雷电 7/9）文件管理器不认第三方 SAF 的困局，也是对齐 EDS/VaultExplorer/CryptoContainer 的必备能力
- [x] SAF 通知修复：解锁/上锁后对 roots URI 发 notifyChange，老 DocumentsUI 才会重查看见/隐藏入口
- [ ] 雷电模拟器（安卓7/9）端到端：内置浏览器路径待验（系统文件管理器路径老机型多半仍看不见，属系统侧限制）

### 二期 · FAT 只读 → 写（多 Agent 推进，任务板见 `多Agent协作.md`）

- [x] 双向加解密 native+JNI（`sc_volume_encrypt_units`/`nativeEncryptUnits`）+ `VolumeReader.write` 读改写
- [x] 补 `NativeBridge.nativeEncryptUnits` external 声明（原缺声明致 `assembleDebug` 编译失败）
- [x] T1 加解密自测：`VolumeReader.selfTest` 内存跑往返三判据 + UI「加解密自测」按钮（零写盘，真机点验）
- [x] T2 MountManager 可写挂载（PFD `rw` + `FLAG_GRANT_WRITE`，`writable` 默认 false 零回归）
- [x] T3a FAT 表写 API（`setNextCluster`/`allocCluster`/`freeChain`，双份 FAT 回写）
- [x] T3b 目录项增删 + VFAT 长名生成
- [x] T3c 写入门面（`writeFile`/`deleteFile`/`overwriteFile`，MountManager 加锁域）
- [x] 写入 UI 接线：内置浏览器加导入(FAB)/覆写/删除入口（仅可写挂载显示），经 `withWritableFs`
- [x] 可写挂载默认开：选中容器若拿到 `FLAG_GRANT_WRITE` 则 `mountWritable` 默认 true（读写），拿不到自动回落只读（改前默认只读，用户须手动勾）
- [x] FAT32 FSInfo 失效：写后置 `FSI_Free_Count`/`FSI_Nxt_Free` 为 0xFFFFFFFF（unknown，OS 重算，防 chkdsk 报「空闲空间不符」）
- [x] T4 真机端到端 + 桌面 VeraCrypt 回验（互通唯一判据，两端已验：app 内写/改/删 + 桌面 VC 打开同容器改动可见 + chkdsk 干净）

### 三期 · 容器兼容性补全（对齐上游功能，路线图见 `路线图.md`）

- [x] A1 keyfile 解锁：`KeyfileMixer`（纯 Kotlin 复刻 VC `KeyFilesApply`，CRC32 0xEDB88320 池化模加，字节级一致）+ `MountManager.unlock` 加 `keyfiles` 参数 openVolume 前混入 + 解锁 UI 多选 keyfile 入口（`OpenMultipleDocuments`，当次读入，无需持久权限；有 keyfile 时允许空密码解锁）。编译 46/46 全量过。**待恒烈真机回验**：带 keyfile 的已知容器能开 + 与桌面 VC 同组 keyfile 结果一致。
- [x] A2 卷头备份/恢复（救砖）：`VolumeHeaderTool` 对容器绝对偏移原始 I/O（不经加解密），导出主头组 128KB / 从卷尾内嵌备份头组恢复。安全前置：恢复前先 `verifyOpens`（密码+keyfile 试开备份头，开不了拒写）→ 强制先导出当前主头到救援文件（可逆兜底）→ 才覆盖主头组。解锁区底部低调「卷头工具」入口，救砖需写权限 + 红字警告。编译 46/46 全量过。**待恒烈真机回验**：故意损坏主头后能救回 + 桌面 VC 仍能开。
- [x] 关于页安全信息：`buildConfigField` 注入上游 VC 版本（1.26.29）/ pinned commit / 构建工具链 / ABI，关于页展示，供审计。单一真相源，与实际编译绑定。

---

## ▍踩坑记录

- 本机系统 JDK 是 25，Gradle 8.13 上限 JDK 23 → 必须用 gradle.properties 的 `org.gradle.java.home` 钉死到 Studio JBR 21，否则命令行 gradlew 误用 25 报错。（沿用 KarmaWitness 结论）
- 项目路径含中文「我的项目源码」，AGP 默认拒绝非 ASCII 路径 → gradle.properties 开 `android.overridePathCheck=true`。但 NDK/CMake 对中文路径更敏感，若 native 重编因路径炸，退路是把工程复制到纯英文路径（如桌面）再编。
- 命名红线：TrueCrypt License 3.0 禁止用 TrueCrypt/VeraCrypt 命名衍生品 → 对外名「密匣 Sealchest」完全独立，仅在 NOTICE/README 注明加密核心来源。
- 第二阶段起步坑：`cpp/veracrypt/` 现在是**整棵 Common/+Crypto/ 全量复制**（Common 25 个 .c、Crypto 33 个 .c），含 BootEncryption/EMVCard/Dlgcode/libzip 等大量与解密无关的文件。头文件必须全留（VeraCrypt 内部用 `"Common/Endian.h"`、`"Crypto/cpu.h"` 这种相对 src/ 的 include，结构不能动），但 **CMake 只挑要编的 .c**，没列进 CMakeLists 的 .c 躺着不参与编译、无害。不要试图删文件去"瘦身"，删了会断 include。
- 平台适配落点（已通读 Tcdefs.h/config.h 确认）：NDK 下 `_MSC_VER`/`_WIN32` 均不定义 → Tcdefs.h 自动走第 122 行起的 POSIX 分支，整型/`burn`/`TCalloc`(malloc) 都正确。命门是 `TC_EVENT`/`LONG`/`WORD` 只在 Windows 分支定义，而 Crypto.c include 了 EncryptionThreadPool.h 会用到 → 需写一个 `sc_compat.h`（force include）补这些类型 + `VirtualLock/Unlock` 空宏 + `CRYPTOPP_DISABLE_ASM=1`，并自写单线程 stub 替代 EncryptionThreadPool.c（`GetEncryptionThreadCount`→1、`EncryptionThreadPoolDoWork`→直调 `*DataUnitsCurrentThread`）。
- **XTS 数据单元号是文件绝对偏移，不是数据区相对**。真容器实测坐实：`decryptUnits` 的 `startUnit` = `EncryptedAreaStart/512`（512KB 容器为 256），传 0 解出的是垃圾。原 PROGRESS「数据区起始为 0」的推断是错的。FAT 层按扇区读时，单元号 = 文件字节偏移/512，EncryptedAreaStart 之前的头区不解密。判据：解对的 FAT 引导扇区必 `MSDOS5.0` OEM 名 + 末尾 `55 AA`。
- **SHANI 必须单独关**。`CRYPTOPP_SHANI_AVAILABLE`（config.h:200）只看 `!CRYPTOPP_DISABLE_SHANI` + X64 + clang 版本够高，**与 `DISABLE_ASM` 无关**。sc_compat.h 关了 ASM/SSE2/SSSE3/AESNI/ARM 全家，唯独漏 SHANI → x86_64 上 cpu.c:372 引用未编入的 `TrySHA256`（在排除的 Sha2Intel.c）链接失败。补 `CRYPTOPP_DISABLE_SHANI 1`。这坑只在 x86_64 ABI 暴露（arm64 默认无 `__SHA__`），SHARED 库靠延迟绑定侥幸过、executable 严格暴露 → 发 x86_64 ABI 也受益。
- word64 桩别乱加：`xts_encrypt/decrypt`（用 `word64`）只在 `#ifdef WOLFCRYPT_BACKEND` 分支被调（Xts.c:63/393 的 `#else`），我们没定义它 → 走 `#ifndef` 纯软 `EncryptBufferXTSParallel/NonParallel`，那俩符号根本不被引用。sc_stubs.c 里给它们写桩纯属多余，还因 `word64` 无 typedef 直接编译失败。已删。
- 本机验证宿主 = x86_64 模拟器，非真机 arm。密码学正确性与 CPU 架构无关，交叉编到 `x86_64-linux-android` 推模拟器跑，秒级迭代。测试器 sc_test.c 只 include 纯净门面 sc_volume.h，走与 JNI 同一条 C API；CMake 用 `-DSC_BUILD_TEST=ON` 单独出可执行，gradle 不传此开关 → 不污染 APK 构建。adb push 到 `/data/local/tmp` 必须前置 `MSYS_NO_PATHCONV=1`，否则 MSYS 把路径篡改成 `C:/Program Files/Git/data/...`。
- **纯 `inline` 函数在 Debug(-O0) 链接失败**。cpu.c 的 `CPU_QueryAES`/`CPU_QuerySHA2`（arm64 分支）、`TrySHA256` 等是 C99 纯 `inline`（无 static/extern）→ C99 语义下不产生外部符号，-O0 不内联时 `DetectArmFeatures` 引用它们即 undefined。x86_64 测试用 -O2 内联了没暴露，arm64 Debug 才炸。修：veracrypt_core 加 `-fgnu89-inline`（GNU89 inline 语义让纯 inline 产出外部定义，VeraCrypt 本就假设这套），全 ABI 通用，不动源码。
- **SAF authority 用 `${applicationId}.documents` 占位符，别写死**。debug 构建 applicationId 带 `.debug` 后缀（`applicationIdSuffix`），Manifest 若写死 `com.henglie.sealchest.documents`，而 UI 用 `packageName + ".documents"` 拼出的是 `...debug.documents` → 不匹配，浏览打不开。Manifest authority 用 `${applicationId}.documents`，AGP 按构建类型替换，UI 侧 `packageName` 自然一致。
- 偏移语义收口在 VolumeReader：FAT 层只见「卷内逻辑偏移」(0 = 数据区首字节 = 解密后引导扇区)，VolumeReader 内部换算 `文件绝对偏移 = EncryptedAreaStart + 逻辑偏移`、`XTS 单元号 = 文件绝对偏移/512`，把实测纠正的绝对单元号语义封死一处，上层不重复踩。带 256KB LRU 解密单元缓存扛 FAT 表热点随机访问。
- 明文不落盘：DocumentsProvider `openDocument` 用 `createReliablePipe` + 后台线程流式解密写入管道，直接喂给调用方 app，不写临时明文文件。密钥只在进程内存，进程死即销毁；`onDestroy` 不主动上锁（别的 app 可能仍在读挂载中的文件）。
- **老安卓看不见 SAF 入口 → 必须内置浏览器**。实测：一加安卓16 自带文件管理器能正常从系统里进容器；雷电模拟器（安卓7/9）自带文件管理器太老，多半不认第三方 DocumentsProvider，用户「看不见容器入口」。这不是我们能改的（对方 app 老）。破局＝内置文件浏览器（`browse/BrowserScreen`），自己遍历 FAT + 预览（图片走 BitmapFactory、文本走前 256KB）+ 导出（SAF CreateDocument）+ 用其它应用打开（FileProvider）。SAF Provider 降级为「额外暴露」，内置浏览器才是任何机型都能用的主入口。竞品 EDS/VaultExplorer/CryptoContainer 都有内置浏览器，是必备能力。
- **解锁/上锁后要 `notifyChange` roots URI**。否则老 DocumentsUI 缓存了「无此来源」，解锁后仍不显示入口。`SafNotify.rootsChanged` 对 `content://<authority>/root` 发通知，`MountManager.unlock` 成功后 / `lock` 后各调一次。`lock(context)` 因此要收 context（可空，UI 调时传）。
- 「用其它应用打开」＝明文短暂落 `cacheDir/export`，经 FileProvider 给 content URI（authority `${applicationId}.fileprovider`，别与 documents 那个混）。这是安全权衡：要把文件交给系统看图/PDF 的 app 就无法全程只在内存。上锁 (`onLock`) 和 `onDestroy` 都调 `FileExport.clearExportCache` 清明文。极端敏感场景应只用内置预览、不用「用其它应用打开」。
- **`nativeEncryptUnits` 只有实现没声明会编译失败**。native_lib.cpp 有 `Java_..._nativeEncryptUnits` 实现、`Volume.encryptUnits` 也调了它，独缺 `NativeBridge` 里的 `private external fun nativeEncryptUnits(...)` 声明 → `Unresolved reference`。补声明即过（见 NativeBridge.kt:53 附近，与 `nativeDecryptUnits` 对称）。接手写入版第一坑。
- **加解密往返自测搬进 App 内，不再交叉编 sc_test 推模拟器**（恒烈定：本机不开模拟器，只交付 APK 真机验）。`VolumeReader.selfTest()` 取数据区首单元真实密文，内存跑三判据（往返1 `encrypt(decrypt(C0))==C0` / 加密改变数据 / 往返2 `decrypt(encrypt(X))==X`），全程只读一扇区、绝不写盘，对挂载卷无副作用。UI 在 `MountedPanel` 加「加解密自测」按钮 + 结果弹窗。这是写入互通的地基验证——三判据全过才证明 encrypt 与 decrypt 严格互逆、写回容器后桌面 VC 能打开。`cpp/sc_test.c` 的往返自测保留作 native 侧离线备用。
- **FAT32 FSInfo 空闲计数别精确维护，置 unknown 让 OS 重算**。每次增删都精确改 FSInfo 的 `FSI_Free_Count`/`FSI_Nxt_Free` 易错、算错 chkdsk 反而报「空闲空间不符」。FAT32 规范允许把这俩置 `0xFFFFFFFF`（未知），OS 挂载时自行重算，置未知永远合规。`FatFileSystem.invalidateFsInfo()` 读整 FSInfo 扇区、校验三签名（`0x41615252`@0 / `0x61417272`@484 / `0xAA550000`@508）后只改 @488/@492 两个 u32 为全 F，整扇区 read-modify-write 写回，在 `MountManager.withWritableFs` 收尾统一调（单点覆盖所有写路径）。FSInfo 扇区在保留区，逻辑偏移 = `fsInfoSector*bytesPerSector`（数据区之后连续布局，reader 可寻址）。
- **Read/grep 对含 NUL/非 ASCII 的 .kt 渲染失真会「凭空造代码」**。本会话 Read `FatFileSystem.kt` 写入门面区，行号从真实 885 跳成 903，且「看到」`reader.write(logicalOffset, patch,0,8)` 这种根本不存在的行（幻觉），差点据此改坏正确代码。红线：改写入门面前用 `grep -an` 核真身，Edit 匹配失败别硬改，先 grep 确认真实文本。

---

## ▍许可

加密核心移植自 VeraCrypt（Apache-2.0 + TrueCrypt License 3.0），保留原始版权声明于 third_party/。密匣为独立产品。
