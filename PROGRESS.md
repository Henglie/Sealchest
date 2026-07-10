# 匿匣 Sealchest · PROGRESS

> 给 AI / 开发者看。接手前先读 `路线图.md` + 本文「技术栈红线」「踩坑记录」两节。
> 本地代号 AnnVeraCrypt（旧文件夹名），对外一律称**匿匣 / Sealchest**。
> 原名密匣，因与他人项目重名，2026-07 改称匿匣。英文名 Sealchest、包名 com.henglie.sealchest、仓库地址均不变。

---

## ▍一句话

安卓无 root 加载 VeraCrypt 加密容器，纯用户态解密 + SAF 暴露文件系统。VC「文件容器」这条线功能全复刻，FAT12/16/32 + exFAT + NTFS 全算法/PRF/PIM/keyfile/隐藏卷/创建/改密/救砖全通，辅以 root 可选增强与体验对齐。

---

## ▍当前状态（2026-07-10）

**代码层面 VC 文件容器全功能已复刻完成，全部 `assembleDebug` 三 ABI 编译通过。** 唯一阻塞项：恒烈真机验收（唯一判据 = 桌面 VeraCrypt / Windows / chkdsk 互通）。

- ✅ FAT12/16/32 读写已真机双向互通验收（一加安卓16）
- ✅ 只读全链路 + 加解密往返自测真机点验三判据全过
- ✅ 16 国语言 i18n（中英法德西日韩俄意葡荷阿拉伯印地土波越）
- ◐ 其余功能块均编译过待真机验：exFAT / NTFS（含 B+树整树重建，最高危）/ 隐藏卷 / 创建 / 改密 / keyfile / 卷扩展 / 卷头救砖 / 自动锁定 / 多容器收藏 / 阶段 F root 增强 / X1-X5 体验对齐

验收纪律与指南见 `测试手册.md`。

---

## ▍技术栈红线（本机实测组合，照搬 KarmaWitness，勿擅改）

- **AGP 8.11.1 + Gradle 8.13 + Kotlin 2.1.20**，由 Android Studio JBR 21 跑（非系统 JDK）。
- **compileSdk = 36 / targetSdk = 36 / minSdk = 23**。minSdk 23 = Android 6.0，覆盖 2015 至今。本机只装 android-36，故 compileSdk 锁 36。
- **NDK 30.0.14904198 + CMake 3.22.1**，ABI：arm64-v8a / armeabi-v7a / x86_64，C++/C17。
- 包名 `com.henglie.sealchest`，.so 名 `libsealchest.so`。
- Compose + Material3（谷歌原生 M3，Android 12+ 走 Material You 动态取色），不套玻璃风。
- **版本号纪律**：versionName 固定 "0.1"，versionCode=4。日常开发不动版本号；仅「同步上游 VeraCrypt」且经恒烈同意时才可升。
- **供应链透明**：`buildConfigField` 注入上游 VC 版本（1.26.29）/ pinned commit（21dba20）/ 构建工具链 / ABI，关于页展示供审计。

### 本机环境关键路径（换机需改）

- SDK：`D:/Program Files/Android/Sdk`
- JBR：`D:/Program Files/Android Studio/jbr`（钉进 gradle.properties 的 `org.gradle.java.home`）
- adb：`D:/CTFRe_ToolsBox_ESS/T00Ls/Android_Tools/搞机工具箱11.0.1/adb.exe`
- 本机无 gradle CLI，wrapper jar 从 KarmaWitness 复用。

---

## ▍架构分层

```
Compose UI (M3)  选容器 → 输密码/PIM/PRF → 浏览文件 / 媒体播放 / PIN 门禁
      │
SAF DocumentsProvider + 内置浏览器  把解开的 FS 暴露给系统/本 app
      │
文件系统层 (Kotlin, 自研读写)  FAT12/16/32 · exFAT · NTFS
      │
JNI 桥 (NativeBridge.kt + native_lib.cpp)  开卷/按扇区加解密/建卷/改密/卷扩展
      │
VeraCrypt crypto 核心 (纯 C, 移植自 third_party/VeraCrypt)
```

JNI 暴露能力：开卷（验密码、派生密钥、出 CRYPTO_INFO 句柄）、按扇区加解密、关卷（销毁密钥）、建卷头、改密头、卷扩展头、随机填充、熵池。

---

## ▍能力矩阵（VC 文件容器全复刻）

| 能力 | VC 有 | 同类有 | 匿匣状态 | 阶段 |
|---|---|---|---|---|
| 标准容器解锁（全算法/PRF/PIM） | ✓ | ✓ | ✓ 已真机验收 | 一期 |
| FAT12/16/32 只读/写入 + 两端互通 | ✓ | 部分 | ✓ 已真机验收(T4) | 一/二期 |
| 加解密往返自测（三判据，内存跑零写盘） | — | — | ✓ 真机点验过 | 二期 |
| 内置文件浏览器 + 预览 + 导出 + 用其它应用打开 | — | ✓ | ✓ 已完成 | 二期 |
| keyfile 解锁（字节级复刻 VC KeyFilesApply） | ✓ | ✓ | ◐ 编译过待真机验 | A1 |
| 卷头备份/恢复（救砖，主头+备份头组） | ✓ | ✓ | ◐ 编译过待真机验 | A2 |
| 救援文件双写（用户选 URI + 自动写 app 私有目录） | ✓ | — | ◐ 编译过待真机验 | A2 |
| 创建新容器（含熵对齐+手指涂抹+随机池可视化） | ✓ | 部分 | ◐ 编译过待真机验 | B2 |
| 改密码/PIM/PRF/keyfile（主密钥不变只换头） | ✓ | 部分 | ◐ 编译过待真机验 | B1 |
| 隐藏卷解锁（先主后隐双试） | ✓ | 少数 | ◐ 编译过待真机验 | C1 |
| 隐藏卷创建 + 外层写保护（读外层 FAT 算安全区） | ✓ | 极少 | ◐ 编译过待真机验 | C2 |
| exFAT 读/写/创建（自研，含 NoFatChain 连续分配） | ✓ | 少数 | ◐ 编译过待真机验 | D1 |
| NTFS 读/写/创建（自研，含 B+树整树重建 2 层） | ✓ | 极少 | ◐ 编译过待真机验，**最高危** | D2 |
| 多容器收藏/快速切换/重命名/排序 | — | ✓ | ✓ 编译过待真机验 | E |
| 自动锁定（超时/息屏/切后台三触发） | ✓ | ✓ | ◐ 编译过待真机验 | E |
| 卷扩展（复用主密钥仅改 VolumeSize，仅增大） | ✓ | — | ◐ 编译过待真机验 | 四期 |
| 供应链透明（上游版本入关于页） | — | — | ✓ 已完成 | 安全 |
| **root 块设备/分区加密解锁（只读+可写）** | ✓ | — | ◐ 编译过待 root 真机验 | F2 |
| **root 系统级暴露（同步到目录）** | — | — | ◐ 编译过待 root 真机验 | F3 |
| **root 保活前台服务 + 紧急上锁** | — | — | ◐ 编译过待 root 真机验 | F4 |
| **Material You 动态色** | — | ✓ | ✓ 已完成 | X1 |
| **Argon2id PIN 派生（t=2/m=64MB，EncryptedSharedPreferences）** | — | ✓ | ◐ 编译过待真机验 | X2 |
| **Panic PIN 即时擦除（容器上锁+收藏清空+缓存清空+退出）** | — | ✓ | ◐ 编译过待真机验 | X3 |
| **生物识别解锁（BIOMETRIC_STRONG，Panic 不走指纹防误触）** | — | ✓ | ◐ 编译过待真机验 | X4 |
| **加密相册/媒体播放（图片画廊+Media3 ExoPlayer）** | — | ✓ | ◐ 编译过待真机验 | X5 |
| **16 国语言 i18n（中英法德西日韩俄意葡荷阿拉伯印地土波越）** | — | 部分 | ✓ 已完成 | i18n |

### 不做（安卓形态边界）

- 隐藏操作系统 / 系统盘预引导认证：安卓引导链与桌面根本不同，路线图明确排除。
- 内核级挂载（dm-crypt/FUSE 内核模块）：纯 app 层做不到，F3 用「同步暴露」诚实替代。

---

## ▍移植清单（VeraCrypt C 核心 → src/main/cpp）

来源 `third_party/VeraCrypt/src/`，纯 C 回退路径完整，开 `CRYPTOPP_DISABLE_ASM` 即可 ARM 编译。

**Crypto/**：config.h, cpu.c/h, misc.h, Aes*(.c/h), Serpent, Twofish, Camellia, kuznyechik, Sha2, Whirlpool, Streebog, blake2s, Argon2/。可选 ARM 加速 Aes_hw_armv8.c / sha256_armv8.c。
**Common/**：Tcdefs.h, Crypto.c/h, Volumes.c/h, Pkcs5.c/h, Endian.c/h, GfMul.c/h, Xts.c/h, Crc.c/h, Password.h, EncryptionThreadPool.h（stub）。
**排除**：所有 .asm / *_x86.S / *_x64.S / SSE / SIMD / RNG / jitterentropy / t1ha / wolfCrypt / sm4。

**需 stub 的平台符号**：`CRYPTOPP_DISABLE_ASM`=1、`VirtualLock/Unlock`→空、`GetEncryptionThreadCount`→返 1（强制单线程）、`EncryptionThreadPoolDoWork`→直调 DecryptDataUnitsCurrentThread、`<io.h>` 在 Volumes.c 排除。`ReadVolumeHeaderWithAbort` 吃内存 buffer，不碰文件 I/O。

**卷头格式**：salt 偏移 0 长 64；加密区 64..512（448 字节）；magic "VERA" 0x56455241 在偏移 64；主密钥区偏移 256 长 256。PBKDF2 迭代默认 SHA256 non-boot 500000，PIM≠0 时 15000+pim*1000。

**RNG/熵池**（B2 关键，复刻 VC Random.c）：320B 池 + `RandaddByte` 模加 + 每 16B 触发 `Randmix`（SHA512 分块搅拌整池 XOR 回）+ `RandgetBytes` 前向保密（取字节→反转整池→搅拌→用新池态 XOR 输出）。熵源双层：`SecureRandom` 灌初始熵 + 手指涂抹收集熵。零 Windows stub，不编入 VC `Random.c`，全依赖已编入 SHA512。

---

## ▍关键实现要点

### 偏移语义收口在 VolumeReader

FAT 层只见「卷内逻辑偏移」(0 = 数据区首字节 = 解密后引导扇区)，VolumeReader 内部换算 `文件绝对偏移 = EncryptedAreaStart + 逻辑偏移`、`XTS 单元号 = 文件绝对偏移/512`。上层不重复踩。

### 明文不落盘

DocumentsProvider `openDocument` 用 `createReliablePipe` + 后台线程流式解密写入管道，直接喂调用方 app，不写临时明文文件。密钥只在进程内存，进程死即销毁。媒体播放例外：ExoPlayer 不吃管道，临时写 `cacheDir/encrypted_media_tmp/`，用完即删，上锁清缓存兜底。

### NTFS 诚实边界

不写 $LogFile 日志 → Windows 当未净卸载、挂载时自动重置 $LogFile + chkdsk 补一致性（非内核 NTFS 写工具通行做法）。B+树索引用**整树重建**策略（insert/delete 统一收集全树扁平项 → 增/删 → 排序重建），支持 2 层（~2000 文件），3 层保守拒绝。内存自测全 PASS（驻留 n=6 / 2层 n=110 强制分裂 4 叶回解顺序全对）。NTFS 受实验开关控制（默认关，开启才挂载）。

### 隐藏卷写保护

`FatFileSystem.usedDataAreaUpperBound()` 扫 FAT 找最高已用簇算上界，隐藏卷数据区起点必须 ≥ 此上界否则拒绝创建。**致命 bug 已修**：`Bpb.parse` 开头显式 `require(!NtfsBoot.isNtfs)` + `require(!ExFatBoot.isExFat)` + `require(countOfClusters>0)`，堵 NTFS/exFAT 外层被误判 FAT12 致写保护失效覆盖真实文件。

### 救援文件双写

改密（B1）与头恢复（A2）覆盖主头组前，除写用户选的救援 URI 外，自动再写一份到 app 私有目录。安全关键：救援文件是旧主头组，用旧密码能解密还原。设「救援文件管理」入口可单删/一键清空，红字警告。

### root 增强设计红线（阶段 F）

纯增量——无 root / 用户拒绝时仅隐藏入口，第一层（纯用户态主线）零影响，绝不让主线依赖 root。F2 块设备解锁 `require(devicePath.startsWith("/dev/block/"))` 防越权。F3 是「同步暴露」非内核挂载（诚实边界）。F4 保活非 100%，需提醒用户去系统设置放行（电池优化白名单）。

---

## ▍代码优化记录（2026-07-10）

- **MountManager 回调替代 SealchestApp 轮询**：原 SealchestApp 每秒 Handler 轮询 `isMounted` 驱动前台服务起停（52 行）。改为 MountManager 加 `@Volatile var onMountStateChanged` 回调属性，unlock 成功 / lock 后在 synchronized 块内 `runCatching` 调回调。SealchestApp 精简到 30 行，实时响应 + 零 CPU 开销。非破坏性：业务行为不变，回调异常不影响主流程。
- **MediaViewer ImagePage inSampleSize 降采样防 OOM**：原直接 `decodeByteArray` 解码，大图（5000×5000 JPEG 压缩后 5MB 但解码后 100MB）会 OOM。加 `inJustDecodeBounds` 量真实像素 → `calcInSampleSize` 算降采样比（目标 2048×2048）→ `inSampleSize` 解码，降采样后 Bitmap ≤16MB 安全。

---

## ▍踩坑记录

- 本机系统 JDK 是 25，Gradle 8.13 上限 JDK 23 → 必须用 gradle.properties 的 `org.gradle.java.home` 钉死到 Studio JBR 21，否则命令行 gradlew 误用 25 报错。
- 项目路径含中文「我的项目源码」，AGP 默认拒绝非 ASCII 路径 → gradle.properties 开 `android.overridePathCheck=true`。但 NDK/CMake 对中文路径更敏感，若 native 重编因路径炸，退路是把工程复制到纯英文路径再编。
- 命名红线：TrueCrypt License 3.0 禁止用 TrueCrypt/VeraCrypt 命名衍生品 → 对外名「匿匣 Sealchest」完全独立，仅在 NOTICE/README 注明加密核心来源。
- 第二阶段起步坑：`cpp/veracrypt/` 是整棵 Common/+Crypto/ 全量复制，含大量无关文件。头文件必须全留（相对 include），但 CMake 只挑要编的 .c。不要删文件瘦身，删了断 include。
- 平台适配落点：NDK 下 `_MSC_VER`/`_WIN32` 不定义 → Tcdefs.h 走 POSIX 分支。命门是 `TC_EVENT`/`LONG`/`WORD` 只在 Windows 分支定义 → 需 `sc_compat.h`（force include）补类型 + `VirtualLock/Unlock` 空宏 + `CRYPTOPP_DISABLE_ASM=1`，并自写单线程 stub 替代 EncryptionThreadPool.c。
- **XTS 数据单元号是文件绝对偏移，不是数据区相对**。`decryptUnits` 的 `startUnit` = `EncryptedAreaStart/512`，传 0 解出垃圾。FAT 层按扇区读时单元号 = 文件字节偏移/512，EncryptedAreaStart 之前的头区不解密。判据：解对的 FAT 引导扇区必 `MSDOS5.0` OEM 名 + 末尾 `55 AA`。
- **SHANI 必须单独关**。`CRYPTOPP_SHANI_AVAILABLE` 只看 `!CRYPTOPP_DISABLE_SHANI` + X64 + clang 版本够高，与 `DISABLE_ASM` 无关。sc_compat.h 关了 ASM 全家唯独漏 SHANI → x86_64 链接失败。补 `CRYPTOPP_DISABLE_SHANI 1`。
- word64 桩别乱加：`xts_encrypt/decrypt` 只在 `#ifdef WOLFCRYPT_BACKEND` 分支被调，我们没定义 → 走纯软 `EncryptBufferXTSParallel/NonParallel`，那俩符号根本不被引用。写桩多余且因 `word64` 无 typedef 编译失败，已删。
- 本机验证宿主 = x86_64 模拟器，非真机 arm。测试器 sc_test.c 只 include 纯净门面 sc_volume.h；CMake 用 `-DSC_BUILD_TEST=ON` 单独出可执行，gradle 不传此开关。adb push 到 `/data/local/tmp` 必须前置 `MSYS_NO_PATHCONV=1`。
- **纯 `inline` 函数在 Debug(-O0) 链接失败**。cpu.c 的 `CPU_QueryAES`/`TrySHA256` 等是 C99 纯 `inline` → -O0 不内联时 undefined。修：veracrypt_core 加 `-fgnu89-inline`（GNU89 inline 语义让纯 inline 产出外部定义），全 ABI 通用，不动源码。
- **SAF authority 用 `${applicationId}.documents` 占位符，别写死**。debug 构建 applicationId 带 `.debug` 后缀，Manifest 写死会与 UI 侧 `packageName` 不匹配。
- **老安卓看不见 SAF 入口 → 必须内置浏览器**。雷电模拟器（安卓7/9）自带文件管理器不认第三方 DocumentsProvider。内置浏览器（`browse/BrowserScreen`）是任何机型都能用的主入口。
- **解锁/上锁后要 `notifyChange` roots URI**。否则老 DocumentsUI 缓存「无此来源」。`SafNotify.rootsChanged` 在 unlock 成功 / lock 后各调一次。
- 「用其它应用打开」＝明文短暂落 `cacheDir/export`，经 FileProvider 给 content URI（authority `${applicationId}.fileprovider`）。上锁和 `onDestroy` 都清明文缓存。
- **`nativeEncryptUnits` 只有实现没声明会编译失败**。native_lib.cpp 有实现、`Volume.encryptUnits` 也调了它，独缺 `NativeBridge` 里的 external 声明 → `Unresolved reference`。补声明即过。
- **FAT32 FSInfo 空闲计数别精确维护，置 unknown 让 OS 重算**。规范允许把 `FSI_Free_Count`/`FSI_Nxt_Free` 置 `0xFFFFFFFF`，OS 挂载时自行重算。`FatFileSystem.invalidateFsInfo()` 在 `MountManager.withWritableFs` 收尾统一调。
- **Read/grep 对含 NUL/非 ASCII 的 .kt 渲染失真会「凭空造代码」**。红线：改写代码前用 `grep -an` 核真身，Edit 匹配失败别硬改，先 grep 确认真实文本。
- **TRAE 沙箱白名单限制桌面写操作**。`Remove-Item`/`Copy-Item` 对桌面下文件被沙箱拦截却回显"DELETED"。**结论**：沙箱只允许项目目录+特定缓存目录的写操作。**怎么绕开**：APK/交付物先放项目目录内，让用户手动复制到桌面。
- **PROGRESS「其余低危」4 条经核实均非真 bug，别重复排查**。①exFAT `writeFatEntry` 只写 FAT#0：exFAT 规范单份 FAT，非 bug；②`fillDataArea` 默认不调用：是用户明确要的设计开关；③簇号→偏移无上界校验：宽泛加固项；④VolumeExpander 旧备份头残留：VC 桌面版 ExpandVolume 也不清理。
- **增量构建偶发不重打包资源**。改 `values-zh/strings.xml` 后 `packageDebug` 标 UP-TO-DATE 没重打包。改资源后用 `clean assembleDebug` 强制全量重建。
- **bouncycastle 1.79 与 jspecify 1.0.0 都带 `META-INF/versions/9/OSGI-INF/MANIFEST.MF` 合并冲突**。packaging excludes 补一条 `META-INF/versions/9/OSGI-INF/MANIFEST.MF`。

---

## ▍安全审计结论（2026-07-10，~9400 行四域全审）

两个**致命** bug 已用纯防御性修复（只加拒绝路径，绝不造新损毁）堵死并编译过：
- **★致命 F1**：隐藏卷写保护对非 FAT 外层完全失效（NTFS 引导扇区骗过 `Bpb.parse` 误判 FAT12）→ 覆盖 NTFS/exFAT 外层真实文件。修复：`Bpb.parse` 加 `require(!NtfsBoot.isNtfs)` + `require(!ExFatBoot.isExFat)` + `require(countOfClusters>0)`；`HiddenVolumeCreator.openOuterAndMeasure` 针对性拒绝；MountManager 分发处拦 NTFS。
- **★致命（架构）**：NTFS 读写从未接线是死代码，MountManager 只分发 exFAT/FAT → NTFS 容器被当 FAT12 挂出垃圾。修复：MountManager 读 boot0，`if (NtfsBoot.isNtfs && !ntfsExperimental) throw UnsupportedContainerException`。现已接线（五期完成，开实验开关即走 `NtfsFileSystem.mount`）。

7 个**高危写路径** bug（H1-H4/M1-M3）已全部修复并编译过。FAT/exFAT 三处逻辑可推理确认；NTFS 四处改动 formatter 盘上结构，NTFS 真机验收阶段须整体回归。

核实为正确（免重复排查）：RNG/熵池、加解密映射、改密/救砖兜底序、FAT 写核心、KeyfileMixer、隐藏卷头偏移（对真 FAT 外层）。

---

## ▍许可

加密核心移植自 VeraCrypt（Apache-2.0 + TrueCrypt License 3.0），保留原始版权声明于 third_party/。匿匣为独立产品。
