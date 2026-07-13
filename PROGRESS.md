# 匿匣 Sealchest · PROGRESS

> 项目单一真相源。接手前先读本文「技术栈红线」「踩坑记录」「安全审计」三节。
> 本地代号 AnnVeraCrypt（旧文件夹名），对外一律称 **匿匣 / Sealchest**（原名密匣，因重名于 2026-07 改称，英文名/包名/仓库不变）。
> 关键文档只剩 3 个：本文（PROGRESS，含路线图+测试+供应链）、README（中英）、多Agent协作.md（任务池，已 gitignore）。

---

## ▍一句话

安卓无 root 加载 VeraCrypt 加密容器，纯用户态解密 + SAF 暴露文件系统。VC「文件容器」这条线功能全复刻，FAT12/16/32 + exFAT + NTFS 全算法/PRF/PIM/keyfile/隐藏卷/创建/改密/救砖全通，辅以 root 可选增强与体验对齐。

**守本心**：匿匣是严格的 VeraCrypt 容器安卓解析器。加解密与卷格式行为必须与桌面 VC **字节级一致**，唯一判据是**互通**（匿匣写的容器桌面 VC 能开、桌面 VC 写的匿匣能读）。密码学实现只采用上游 VC 的 C 源码，不自写不魔改；只有卷格式规范（keyfile 混入、卷头布局）允许 Kotlin 复刻，且注释标明上游出处。

---

## ▍当前状态

**v0.2 发布候选版（versionCode=5, versionName="0.2"）。** `assembleRelease` 三 ABI 编译通过。安全审计（五域全审 2026-07-12）挖出的 3 处★致命 + 5 处高危 + 若干中危已全部代码+编译修复，最新 debug APK（32MB, 07/12）含全部 12 项修复。

- ✅ 已真机验收：标准解锁（全算法/PRF/PIM）、FAT12/16/32 只读+写入+两端互通(T4)、加解密往返自测三判据、内置浏览器+预览+导出
- ✅ 用户报告 FAT/exFAT 容器读写成功；NTFS 能读写（有已知一致性边界）
- ◐ 其余功能块均编译过待真机验（见能力矩阵）
- ⚠️ 审计修复项均为**代码级+编译通过，尚未出新 APK 做真机/桌面 VC 回验**。若此前真机验证针对 v0.2 旧版（修复前），需用修复后新 APK 重验致命路径才算数。

---

## ▍第二轮接手审计修复（2026-07-12，独立核实非盲信文档）

> 教训（红线）：本仓库 .kt 含 NUL/CJK，**Read/Edit 渲染会失真、python3 不可用**。改代码一律 `sed -n`/`grep -an` 核真身，Edit 后用 `grep` 复验落盘，别信 Read 回显与 Edit "success"。

### 独立核实：PROGRESS 声称的修复大多真实落地
- NTFS removeIndexEntry 排序：✅ 真实且更彻底（排序内聚进 `rebuildDirIndex` 入口，任何调用方漏排都兜住）
- NTFS collation COLLATION_FILENAME：✅ 真实（逐 UTF-16 码元、$UpCase 同口径无符号比较）
- NTFS deleteFile 安全序：✅ 真实（removeIndexEntry→writeMftRecord→freeMftRecord→freeClusters，dirty-first）
- Kotlin 自动锁清缓存：✅ 真实（AutoLock.onLock→MountManager.lock()→清 export+media temp）
- native 随机池快照：✅ 泄漏已消除（SHA-512 版已接线）；旧死函数 `sc_random_snapshot` 未删（卫生问题，低危）

### 本轮新修（代码+编译过，未真机回验）
| # | 级别 | 问题 | 文件 | 状态 |
|---|---|---|---|---|
| A | ★致命 | NTFS 属性头 flags(0x0C)/instance(0x0E) 全错位——运行时把 attr-id 写进 flags 位，非驻留 $DATA flags=6 被 Windows 当压缩流解析→读出垃圾+chkdsk 报错。**这是"NTFS 能写但桌面有问题"的核心根因，AUDIT-2a 漏掉（只核造盘侧 RecBuilder，未核运行时属性写入器）** | NtfsDataOps.kt(286/303/322/345)+NtfsIndex.kt(6处)+origIndexRootId 读位置(0x0C→0x0E) | ✅编译 |
| B | ★致命 | FAT 判型不自洽——写侧用 FAT12 布局簇数判型、读侧按实际布局重算，4085/65525 附近窄带+override 小簇大卷写读判型分裂→簇链错位报废 | FatFormatter.kt（resolveFatType 逐型自校验 readClusters12/16/32 + 三 buildFatXX 入口 require 兜底） | ✅编译 |
| C | 高危 | exFAT readFile 依赖 chainHint，SAF openDocument 按 docId 直读不经 listDir→NoFatChain 大文件只读首簇读出零 | ExFatFileSystem.kt:288（hint 缺失时探测首簇 FAT 项<2 判 NoFatChain） | ✅编译 |
| D | 高危(可用性) | NTFS MFT 仅 32 记录→扣元数据保留 0..23 只剩 8 个用户文件额度，测试手册"塞 50+ 文件"第9个即失败 | NtfsFormatter.kt:MFT_INITIAL_RECORDS 32→256（位图/结构自适应，余 232） | ✅编译 |
| E | 需求 | 移除"NTFS 实验"开关，NTFS 默认启用 | MountManager.kt+BlockDeviceUnlocker.kt 删 gate、SettingsScreen.kt 删 UI 卡+ntfsExp 变量 | ✅编译 |

### 用户 4 需求 + 协议（本轮全落地，✅编译+出 APK）
| # | 需求 | 根因 / 做法 | 状态 |
|---|------|-------------|------|
| ① | 随机池 hex 要持续跳动（现静止不跳） | 排查发现已实现：CreateVolumeScreen.kt:647 空闲微搅动每 200ms 喂真时间抖动熵→native randmix 搅池→80ms 轮询快照→hex 跳。手指停也动。非假动画。 | ✅已在 |
| ② | 可写挂载改多选框 | MainActivity.kt:1020 FilterChip→Checkbox+Row（点整行切换，uriWritable 门控），import Checkbox | ✅编译 |
| ③ | i18n 依旧不能用（根因） | 根因：MainActivity 继承 FragmentActivity（非 AppCompatActivity）+ 主题 parent 是 android:Theme.Material（非 AppCompat）→ setApplicationLocales 的 locale overlay 靠 AppCompat delegate 在 attachBaseContext 注入，API<33 下 FragmentActivity 根本走不到。改：MainActivity→AppCompatActivity；themes.xml parent→Theme.AppCompat.DayNight.NoActionBar | ✅编译 |
| ④ | 许可证改 Apache 2.0 | 新建根目录 LICENSE（Apache 2.0 全文，Copyright 2026 Henglie/EternalBlaze）；README 许可节区分本项目自身(Apache 2.0)与上游继承双许可 | ✅ |

### 审计真 bug 修复（本轮全落地，✅编译+出 APK）
| # | 严重度 | 问题 | 做法 | 状态 |
|---|--------|------|------|------|
| H1 | 高危(丢数据) | NTFS overwriteFile 先删后写：近满容器写新失败→旧数据一并丢 | NtfsFileSystem.kt overwriteFile 改「先以临时名写新→成功后删旧→改名回目标名」。临时名 padTmp 到 ≥目标名长→末步 rename 是收缩(delta≤0)必放得下→末步不因空间失败。任一步失败旧文件完好 | ✅编译 |
| H2 | 高危(损坏) | NTFS 备份 VBR 簇未在 $Bitmap 标 used→被 allocContiguousClusters 当空闲分配覆盖→chkdsk 报「备份引导扇区无效」 | NtfsFormatter.kt usedLcns 加 backupVbrLcn=(totalSectors-1)/spc；标记循环加 lcn<totalClusters 边界 guard 防非簇对齐越界 | ✅编译 |
| — | 潜伏(损坏) | VolumeReader.write 短写/写0 静默 break→上层误判成功→加密单元残缺 | write 内 `if(n<=0) throw IOException`，让写操作明确失败 | ✅编译 |
| M1 | 中危(泄密) | MountManager.unlock 成功路径不抹 password 明文副本 | return mount 前加 password.fill(0)（与 catch 路径一致，与调用方双抹幂等） | ✅编译 |

### NTFS「别 chkdsk」完整化（本轮，✅编译+子代理逐字节复核+出 APK）

目标：从「靠 dirty 位 + chkdsk 兜底」的诚实边界，升级为 Windows 挂载时**直接干净、零触发 chkdsk**。三阶段：

| 阶段 | 问题 | 根因 / 做法 | 状态 |
|------|------|-------------|------|
| P1 MFT 扩容 | `MFT_INITIAL_RECORDS=32` 仍在盘（前轮「改 256」的 Edit 从未落地，本仓 CJK/NUL 渲染致 Edit 静默失败的老坑）→ 仅 8 个用户文件额度 | NtfsFormatter.kt 32→256（256KB $MFT，扣元数据 0..11+保留 12..23，余 232）。**sed 逐字节复验真身落盘** | ✅编译 |
| P3 dirty 生命周期（chkdsk 杀手） | Windows 挂载时触发 chkdsk 的**唯一开关是 dirty 位，不是 $LogFile**（ntfs-3g 出的卷 0xFF $LogFile + dirty=0 就干净挂载）。原码：出生即脏（buildVolumeInfoContent flags=1）+ 每次写置脏 + **从不清脏** → 每次挂载必 chkdsk | ①出生干净：flags 1→0（=ntfs-3g 输出）②新增 `clearVolumeDirty()`（记录 3<4，writeMftRecord 自动同步 $MFTMirr）③VolumeFs 加 `clearDirtyFlag()` 默认空操作，NtfsFileSystem override④MountManager.withWritableFs 改**两次 flush 提交协议**：flush①落数据+dirty=1 → 仅成功才 clearDirtyFlag → flush②落 clean。dirty-first 不变式保持：清脏前任何崩溃都停在 dirty=1，chkdsk 兜底 | ✅编译 |
| P2 $Secure + security_id | $Secure 是空壳（无 $SDS/$SDH/$SII）+ 所有文件 security_id=0 → 手动跑 chkdsk 会逐文件补 ACL | 新建 NtfsSecure.kt（纯 ASCII 避 CJK 坑）：单个共享 SD（security_id=0x100，Everyone:FullControl）+ $SDS 数据流（主副本@0 + 镜像@0x40000）+ $SDH(collation 0x12)/$SII(collation 0x10) 驻留视图索引。ntfs_security_hash（ROL3+加）逐字节复刻。buildStdInfo/writeStdInfo 均在内容偏移 0x34 写 security_id=0x100（元数据记录 + 运行时新建文件）。buildSecureRecord 重建带 $SDS/$SDH/$SII。buildEmpty 分配 $SDS 簇+标位图+发流 | ✅编译，**子代理按 ntfs-3g layout.h/mkntfs/[MS-DTYP] 逐字节复核 A–H+security_id 全 VERIFIED-CORRECT，无 bug** |

**风险边界（诚实交代）**：$Secure 字节布局无真 Windows 可测，仅子代理对规范复核。但 NTFS 驱动惰性解析 security、查不到即降级默认 SD → 即使 $Secure 有细微字节错也**不会阻止挂载**，最坏「不比 security_id=0 更差」，故这步是有界安全的赌注。已知简化（$SDH/$SII 驻留无 $INDEX_ALLOCATION、单共享 SD、$SDS 只镜像不含 Win 默认 4 SD）自洽，chkdsk 只校验自洽性。

### NTFS 集成链路审查（2026-07-12，两子代理并行核集成层，非单文件字节）

单文件字节此前已核（NtfsSecure），本轮补核**集成一致性**——造盘布局↔运行时读写↔提交协议是否自洽。挖出 2 处真 bug，均编译修复：

| # | 级别 | 问题 | 文件 | 做法 | 状态 |
|---|------|------|------|------|------|
| BUG-1 | 中高危(静默损坏) | withWritableFs 成功路径 flush① 用 runCatching 吞异常后**仍清脏**：fsync 失败(数据未落盘)却写 dirty=0 + flush② → Windows 不跑 chkdsk 的静默不一致。破坏「清脏必以数据落盘为前提」不变式 | MountManager.kt:280 + VolumeReader.kt:213 | VolumeReader 加 `flushChecked():Boolean`（force 成功返 true）；成功路径改「flush① 确认 true 才 clearDirtyFlag+flush②，false 则跳过保 dirty=1 退化 chkdsk」 | ✅编译 |
| BUG-2 | ★致命(chkdsk 必报) | `writeFileNameAttr` 属性头错位——`off+12`(0x0C flags) 被写 attr-id=1、`off+14`(0x0E instance) 从没写=0。**是上轮「flags/instance 全错位」修复的漏网一处**。后果①$FILE_NAME flags=1=ATTR_IS_COMPRESSED 非法结构②instance 与 STD 都=0 重复。运行时每建一个文件/目录都写坏记录，chkdsk 必报「属性 flags 无效+重复属性实例」 | NtfsDataOps.kt:288-289 | flags(0x0C)→0；instance(0x0E)→1。记录内 instance 唯一性核过：STD=0/$FILE_NAME=1/$DATA=6/目录$INDEX_ROOT=2，头 0x28 nextInstance=7 兜住 | ✅编译 |

集成层其余核对**一致**（免重复排查）：簇布局严格顺序递增无重叠（boot→mft→logFile→bitmap→upcase→attrDef→sds→mftBitmap→mftMirr）；security_id 造盘/运行时都在 $STD 内容 0x34 写 0x100；$Secure 属性序 type 升序 + $SDH<$SII；$SDS run 长度/LCN 参数序正确且 realSize 两侧同源、已标 $Bitmap；7 个写方法全 markVolumeDirty、清脏集中提交、幂等短路、异常保 dirty=1。观察项（不触发 chkdsk，未改）：overwriteFile「删旧后改名前」崩溃→文件留 .sctmp~ 名不丢数据；buildStdInfo dos_flags 造盘 SYSTEM/运行时 ARCHIVE 语义差异。

### UI 收尾：主题色/夜间模式 + README（本轮，✅编译+出 APK）

| # | 需求 | 根因 / 做法 | 状态 |
|---|------|-------------|------|
| U1 | 主题色跟随系统（现「系统色和主题色同时存在」割裂） | 根因：`SealchestTheme` 默认 `dynamicColor=true`，API≥31 先算动态取色（系统色）再被 `primaryColor`（酒红，恒非 null）覆盖 primary → 动态色其余角色 + 酒红 primary 混叠。做法：主题色加「跟随系统」项（argb=0，居首）；Theme.kt 改 `primaryColor==0` → 走纯动态取色/兜底整套一致、不覆盖 primary，`!=0` → 关动态色用预设纯色覆盖。二选一不叠加。swatch argb=0 用当前 primary 实色圈+内环标记渲染（透明色渲染不出的坑） | ✅编译 |
| U2 | 夜间模式可切回来（此前只能跟随系统） | 根因：MainActivity 调 `SealchestTheme` 没传 darkTheme/没读 themeMode，`darkTheme` 恒=isSystemInDarkTheme()；Settings 无 themeMode 持久化。做法：Settings 加 `themeMode`（0 跟随/1 浅/2 深）；MainActivity 按 themeMode 定 darkTheme（import isSystemInDarkTheme）；SettingsScreen 加夜间模式卡片（OutlinedButton 三选，recreate 即时生效）。3 键 settings_theme_mode/theme_mode_light/theme_mode_dark 补全 16 语言 | ✅编译 |
| U3 | README 做成带 star/fork 徽章的界面（参照桌面样例） | 重写中英 README：居中标题 + shields.io 徽章（stars/forks/release/license/issues/PR/Android 6.0+）+ WARNING 提示块 + 目录 + starchart.cc 星标趋势图。同步更新过时内容（exFAT/NTFS 已实现非路线图、16 语言非中英双语）。徽章/图表全指向 Henglie/Sealchest | ✅ |

### 功能状态总览（2026-07-12 收尾，压缩上下文前快照）
| 模块 | 状态 | 说明 |
|------|------|------|
| 解锁/挂载 | ✅ 编译，部分真机验 | 全算法/PRF/PIM/keyfile/隐藏卷；FAT12/16/32 已真机读写+互通 |
| FAT12/16/32 读写 | ✅ 真机验 | 造盘 resolveFatType 自校验（修 B）；readFile/writeFile/mkdir/删/改名/移动 |
| exFAT 读写 | ✅ 编译 | 造盘 ExFatFormatter；readFile SAF 直读路径修复（修 C）|
| NTFS 读 | ✅ 编译 | 目录索引 B+树 2 层、data run、USA、卷标 |
| NTFS 写 | ✅ 编译，未真机 | 属性头 flags/instance 修复（修 A 致命）；overwriteFile 崩溃安全（H1）；dirty-first |
| NTFS 免 chkdsk | ✅ 编译，未真机 | P1 MFT 32→256（232 文件额度）+ P2 $Secure/security_id + P3 dirty 生命周期（born-clean + 两次 flush 提交）|
| 创建容器 | ✅ 编译，部分真机 | 熵采集（手指涂抹+传感器+空闲微搅动）；FAT/exFAT/NTFS 造盘；随机池 hex 持续跳动（需求①）|
| 隐藏卷/改密/扩容 | ✅ 编译 | HiddenVolumeCreator/PasswordChanger/VolumeExpander |
| root 增强 | ◐ PoC | 块设备枚举/解锁（BlockDeviceUnlocker），只读优先 |
| i18n 16 语言 | ✅ 编译，未真机 | 根因修复：AppCompatActivity + AppCompat 主题（需求③）|
| UI（可写多选框/主题色/基准） | ✅ 编译 | 可写挂载 Checkbox（需求②）；自动锁/前台服务保活 |
| 许可证 | ✅ | 自身 Apache 2.0（LICENSE + README）|

### 仍待处理（下一步）
- **未做真机回验**：本轮 A-E + ①-④ + H1/H2/短写/M1 + NTFS P1/P2/P3 全部只到编译/出 APK，需真机+桌面 VC+chkdsk 回验。i18n 尤其需真机切语言验证（AppCompatActivity 改动运行时才最终确认）；H1/H2 需近满容器场景专项验；**NTFS 三阶段需真机建 NTFS 容器→桌面 VC 挂载→确认 Windows 零 chkdsk 弹窗 + 手动 chkdsk 干净**

## ▍技术栈红线（本机实测组合，照搬 KarmaWitness，勿擅改）

- **AGP 8.11.1 + Gradle 8.13 + Kotlin 2.1.20**，由 Android Studio JBR 21 跑（非系统 JDK）。
- **compileSdk=36 / targetSdk=36 / minSdk=23**（Android 6.0，覆盖 2015 至今）。本机只装 android-36。
- **NDK 30.0.14904198 + CMake 3.22.1**，ABI：arm64-v8a / armeabi-v7a / x86_64，C11/C++17。
- 包名 `com.henglie.sealchest`，.so 名 `libsealchest.so`。
- Compose + Material3（Android 12+ 走 Material You 动态取色），不套玻璃风。
- 关键编译宏：`CRYPTOPP_DISABLE_ASM=1`、`CRYPTOPP_DISABLE_SHANI=1`、`-fgnu89-inline`。

### 本机环境关键路径（换机需改）

- SDK：`D:/Program Files/Android/Sdk`
- JBR：`D:/Program Files/Android Studio/jbr`（钉进 gradle.properties 的 `org.gradle.java.home`）
- adb：`D:/CTFRe_ToolsBox_ESS/T00Ls/Android_Tools/搞机工具箱11.0.1/adb.exe`
- 本机无 gradle CLI，wrapper jar 从 KarmaWitness 复用。项目路径含中文 → gradle.properties 开 `android.overridePathCheck=true`。

### 版本号纪律（红线）

- `versionName` 固定 `"0.2"`。**未经恒烈明确授权，任何情况不得改动 versionName**。日常开发/修 bug/审计/重构一律不碰版本号。
- 只有「同步上游 VeraCrypt」这一场景可能升版，且改前必须先问恒烈。
- `versionCode` 可随构建递增，只增不减（降级致真机拒绝覆盖安装）。

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

JNI 能力：开卷（验密码、派生密钥、出 CRYPTO_INFO 句柄）、按扇区加解密、关卷（销毁密钥）、建卷头、改密头、卷扩展头、随机填充、熵池。

### 关键文件索引

- 主入口：`app/src/main/java/com/henglie/sealchest/MainActivity.kt`
- 设置：`SettingsScreen.kt`
- 基准测试：`benchmark/`（BenchmarkRunner.kt + BenchmarkScreen.kt）
- 文件系统层：`fs/`（FAT/exFAT/NTFS + VolumeReader + MountManager + VolumeCreator/Expander + PasswordChanger + HiddenVolumeCreator + VolumeHeaderTool）
- NTFS（拆 5 文件）：`NtfsRecordCodec.kt`（无状态原语）+ `NtfsMftManager.kt`（$MFT/位图）+ `NtfsIndex.kt`（B+树）+ `NtfsDataOps.kt`（读写删）+ `NtfsFileSystem.kt`（138 行薄壳）；另 NtfsBoot/NtfsFormatter/NtfsRecords/NtfsTables
- 加密桥：`crypto/NativeBridge.kt` + `cpp/native_lib.cpp`
- 熵池：`cpp/sc_random.c`
- 主题：`ui/theme/Theme.kt`；配置：`core/Settings.kt`

---

## ▍能力矩阵（VC 文件容器全复刻）

| 能力 | 匿匣状态 | 阶段 |
|---|---|---|
| 标准容器解锁（全算法/PRF/PIM） | ✓ 已真机验收 | 一期 |
| FAT12/16/32 只读/写入 + 两端互通 | ✓ 已真机验收(T4) | 一/二期 |
| 加解密往返自测（三判据，内存跑零写盘） | ✓ 真机点验 | 二期 |
| 内置文件浏览器 + 预览 + 导出 + 用其它应用打开 | ✓ 已完成 | 二期 |
| keyfile 解锁（字节级复刻 VC KeyFilesApply） | ◐ 待真机验 | A1 |
| 卷头备份/恢复（救砖）+ 救援文件双写 | ◐ 待真机验 | A2 |
| 创建新容器（熵对齐+手指涂抹+随机池可视化） | ◐ 待真机验 | B2 |
| 改密码/PIM/PRF/keyfile（主密钥不变只换头） | ◐ 待真机验 | B1 |
| 隐藏卷解锁（先主后隐双试） | ◐ 待真机验 | C1 |
| 隐藏卷创建 + 外层写保护 | ◐ 待真机验 | C2 |
| exFAT 读/写/创建（自研，NoFatChain 连续分配） | ◐ 待真机验 | D1 |
| NTFS 读/写/创建（自研，B+树整树重建 2 层） | ◐ 待真机验，**最高危** | D2 |
| 多容器收藏/快速切换/重命名/排序 | ◐ 待真机验 | E |
| 自动锁定（超时/息屏/切后台） | ◐ 待真机验 | E |
| 卷扩展（复用主密钥仅改 VolumeSize，仅增大） | ◐ 待真机验 | 四期 |
| 供应链透明（上游版本入关于页） | ✓ 已完成 | 安全 |
| root 块设备/分区加密解锁（只读+可写） | ◐ 待 root 真机验 | F2 |
| root 系统级暴露（同步到目录） | ◐ 待 root 真机验 | F3 |
| root 保活前台服务 + 紧急上锁 | ◐ 待 root 真机验 | F4 |
| Material You 动态色 | ✓ 已完成 | X1 |
| Argon2id PIN 派生（EncryptedSharedPreferences） | ◐ 待真机验 | X2 |
| Panic PIN 即时擦除 | ◐ 待真机验 | X3 |
| 生物识别解锁（BIOMETRIC_STRONG） | ◐ 待真机验 | X4 |
| 加密相册/媒体播放（画廊+Media3 ExoPlayer） | ◐ 待真机验 | X5 |
| 16 国语言 i18n（中英法德西日韩俄意葡荷阿拉伯印地土波越） | ✓ 已完成（根因修复：MainActivity FragmentActivity→AppCompatActivity + 主题→Theme.AppCompat.DayNight，setApplicationLocales 方生效） | i18n |

### 不做（安卓形态边界）

- 隐藏操作系统 / 系统盘预引导认证：安卓引导链与桌面根本不同，排除。
- 内核级挂载（dm-crypt/FUSE 内核模块）：纯 app 层做不到，F3 用「同步暴露」诚实替代。

---

## ▍root 可选增强（阶段 F，最后做）

设计红线：纯增量——无 root / 用户拒绝时仅隐藏入口，第一层（纯用户态主线）零影响，绝不让主线依赖 root，绝不在未告知取得同意前请求 root。

- **必须走真 root，Shizuku/adb 不够**：块设备/整盘/系统级挂载需真 root（Magisk/su），Shizuku 只给 shell 级权限读不了 `/dev/block`。
- **保活尽力非保证**：现代激进杀后台 ROM 无可靠"进程将死"信号。策略=挂载期前台服务 + onTrimMemory/onTaskRemoved 紧急上锁。必须提醒用户去系统设置放行（电池优化白名单）。
- F2 块设备解锁 `require(devicePath.startsWith("/dev/block/"))` 防越权。F3 是「同步暴露」非内核挂载（默认关、知情同意才开）。

---

## ▍移植清单（VeraCrypt C 核心 → src/main/cpp）

来源 `third_party/VeraCrypt/src/`，纯 C 回退路径完整，开 `CRYPTOPP_DISABLE_ASM` 即可 ARM 编译。

- **Crypto/**：config.h, cpu.c/h, misc.h, Aes*, Serpent, Twofish, Camellia, kuznyechik, Sha2, Whirlpool, Streebog, blake2s, Argon2/。
- **Common/**：Tcdefs.h, Crypto.c/h, Volumes.c/h, Pkcs5.c/h, Endian.c/h, GfMul.c/h, Xts.c/h, Crc.c/h, Password.h, EncryptionThreadPool.h（stub）。
- **排除**：所有 .asm / *_x86.S / SSE / SIMD / RNG / jitterentropy / t1ha / wolfCrypt / sm4。
- **需 stub 的平台符号**：`CRYPTOPP_DISABLE_ASM`=1、`VirtualLock/Unlock`→空、`GetEncryptionThreadCount`→返 1、`EncryptionThreadPoolDoWork`→直调 DecryptDataUnitsCurrentThread。`ReadVolumeHeaderWithAbort` 吃内存 buffer 不碰文件 I/O。

**卷头格式**：salt 偏移 0 长 64；加密区 64..512（448 字节）；magic "VERA" 0x56455241 在偏移 64；主密钥区偏移 256 长 256。PBKDF2 迭代默认 SHA256 non-boot 500000，PIM≠0 时 15000+pim*1000。

**RNG/熵池**（复刻 VC Random.c）：320B 池 + `RandaddByte` 模加 + 每 16B 触发 `Randmix`（SHA512 分块搅拌整池 XOR 回）+ `RandgetBytes` 前向保密。熵源双层：`SecureRandom` 灌初始熵 + 手指涂抹收集熵。零 Windows stub。

---

## ▍供应链锁定版本（每次同步上游必改）

| 项 | 值 |
|---|---|
| 上游仓库 | https://github.com/veracrypt/VeraCrypt |
| 锁定 commit | `21dba20af41101e59c36bf9a29c26af2870d30b3` |
| 对应版本 | VeraCrypt **1.26.29** |
| commit 日期 | 2026-06-26 |
| 本地副本 | `third_party/VeraCrypt/`（完整 git，可 fetch 比对，不编译） |
| 编入子集 | `app/src/main/cpp/veracrypt/`（实际编译见 CMakeLists） |

**源码分层判定**：`cpp/veracrypt/` 下 = 上游代码，改动只能来自同步（本地改动是红线）；其余 `cpp/*`（sc_compat.h / sc_stubs.c / sc_volume.c / native_lib.cpp / shim/）= 我们的适配层，可改但不得触碰算法语义。

**供应链威胁模型**：加密工具最危险的攻击面是「你以为在用的代码」与「实际编进去的代码」之间的缝隙——旧版已知漏洞 / 上游被投毒 / 同步夹带 / 不可复现构建。对抗：版本锁定入关于页可核 + 只从官方 GitHub 取源校验 GPG + 每次同步只动 cpp/veracrypt 且 diff 逐条记录 + 更新必过验证闸门。

---

## ▍验证闸门（同步上游后 / 发版前，必须全过）

1. **三 ABI 编译通过**（arm64-v8a / armeabi-v7a / x86_64 全绿）。
2. **加解密自测三判据**（App 内按钮，VolumeReader.selfTest）：往返1 `encrypt(decrypt(C0))==C0` + 加密确实改变数据 + 往返2 `decrypt(encrypt(X))==X`。
3. **已知容器开卷**：已知密码 VC 测试容器（多 PRF）真机开卷，FAT 引导扇区解出 `MSDOS5.0` OEM 名 + 末尾 `55 AA`。
4. **两端互通回验**：匿匣写/改/删 → 桌面 VC 打开改动可见 + `chkdsk` 干净。
5. **keyfile 回验**（若涉及）：带 keyfile 已知容器能开，与桌面 VC 同组 keyfile 结果一致。

闸门 3-5 需真机 + 桌面 VC。任一不过 → 回滚 pinned commit，不发版。**匿匣的信任 = 与桌面 VC 字节级互通，永不为"方便"牺牲兼容。**

---

## ▍关键实现要点

### 偏移语义收口在 VolumeReader

FAT 层只见「卷内逻辑偏移」(0 = 数据区首字节 = 解密后引导扇区)，VolumeReader 内部换算 `文件绝对偏移 = EncryptedAreaStart + 逻辑偏移`、`XTS 单元号 = 文件绝对偏移/512`。上层不重复踩。

### 明文不落盘

DocumentsProvider `openDocument` 用 `createReliablePipe` + 后台线程流式解密写入管道，直接喂调用方 app，不写临时明文。密钥只在进程内存，进程死即销毁。媒体播放例外：ExoPlayer 临时写 `cacheDir/encrypted_media_tmp/`，用完即删，上锁清缓存兜底。

### NTFS 诚实边界

不写 $LogFile 日志 → Windows 当未净卸载、挂载时自动重置 $LogFile + chkdsk 补一致性（非内核 NTFS 写工具通行做法，每次手机编辑后 Windows 首次挂载会弹 chkdsk）。完整日志仿真需移植 ntfs-3g 日志子系统（等于重写半个 NTFS 驱动），不做。B+树索引用**整树重建**（insert/delete 收集全树扁平项 → 增删 → 排序重建），支持 2 层（~2000 文件），3 层保守拒绝。NTFS 受实验开关控制（默认关，开启才挂载）。

### 隐藏卷写保护

`FatFileSystem.usedDataAreaUpperBound()` 扫 FAT 找最高已用簇算上界，隐藏卷数据区起点必须 ≥ 此上界否则拒绝创建。致命 bug 已修：`Bpb.parse` 开头 `require(!NtfsBoot.isNtfs)` + `require(!ExFatBoot.isExFat)` + `require(countOfClusters>0)`，堵 NTFS/exFAT 外层被误判 FAT12 致写保护失效。

### 救援文件双写

改密（B1）与头恢复（A2）覆盖主头组前，除写用户选的救援 URI 外自动再写一份到 app 私有目录。救援文件是旧主头组，用旧密码能解密还原。设「救援文件管理」入口可单删/一键清空。

---

## ▍踩坑记录（技术财富，勿删）

- 本机系统 JDK 25，Gradle 8.13 上限 JDK 23 → 必须 gradle.properties 钉死到 Studio JBR 21，否则命令行 gradlew 误用 25 报错。
- 项目路径含中文 → gradle.properties 开 `android.overridePathCheck=true`。NDK/CMake 对中文路径更敏感，native 重编因路径炸则退路是复制到纯英文路径。
- 命名红线：TrueCrypt License 3.0 禁止用 TrueCrypt/VeraCrypt 命名衍生品 → 对外名「匿匣 Sealchest」完全独立，仅 NOTICE/README 注明加密核心来源。
- `cpp/veracrypt/` 是整棵 Common/+Crypto/ 全量复制，头文件必须全留（相对 include），CMake 只挑要编的 .c。**不要删文件瘦身，删了断 include。**
- 平台适配：NDK 下 `_MSC_VER`/`_WIN32` 不定义 → Tcdefs.h 走 POSIX。命门 `TC_EVENT`/`LONG`/`WORD` 只在 Windows 分支定义 → 需 `sc_compat.h`（force include）补类型 + `VirtualLock/Unlock` 空宏 + `CRYPTOPP_DISABLE_ASM=1`，并自写单线程 stub 替代 EncryptionThreadPool.c。
- **XTS 数据单元号是文件绝对偏移，不是数据区相对**。`decryptUnits` 的 `startUnit`=`EncryptedAreaStart/512`，传 0 解出垃圾。判据：解对的 FAT 引导扇区必 `MSDOS5.0` OEM 名 + 末尾 `55 AA`。
- **SHANI 必须单独关**。`CRYPTOPP_SHANI_AVAILABLE` 与 `DISABLE_ASM` 无关，只看 `!CRYPTOPP_DISABLE_SHANI` + X64 + clang 版本 → x86_64 链接失败。补 `CRYPTOPP_DISABLE_SHANI 1`。
- word64 桩别乱加：`xts_encrypt/decrypt` 只在 `#ifdef WOLFCRYPT_BACKEND` 分支被调，我们没定义 → 走纯软 `EncryptBufferXTS*`，那俩符号不被引用。写桩多余且因 `word64` 无 typedef 编译失败，已删。
- 本机验证宿主 = x86_64 模拟器，非真机 arm。sc_test.c 只 include 纯净门面 sc_volume.h；CMake 用 `-DSC_BUILD_TEST=ON` 单独出可执行。adb push 到 `/data/local/tmp` 必须前置 `MSYS_NO_PATHCONV=1`。
- **纯 `inline` 函数在 Debug(-O0) 链接失败**。cpu.c 的 `CPU_QueryAES`/`TrySHA256` 是 C99 纯 inline → -O0 不内联时 undefined。修：veracrypt_core 加 `-fgnu89-inline`（全 ABI 通用，不动源码）。
- **SAF authority 用 `${applicationId}.documents` 占位符，别写死**。debug 构建 applicationId 带 `.debug` 后缀。
- **老安卓看不见 SAF 入口 → 必须内置浏览器**。雷电模拟器（安卓7/9）自带文件管理器不认第三方 DocumentsProvider。内置浏览器是任何机型都能用的主入口。
- **解锁/上锁后要 `notifyChange` roots URI**。否则老 DocumentsUI 缓存「无此来源」。`SafNotify.rootsChanged` 在 unlock 成功 / lock 后各调一次。
- 「用其它应用打开」＝明文短暂落 `cacheDir/export`，经 FileProvider 给 content URI（authority `${applicationId}.fileprovider`）。上锁和 onDestroy 都清明文缓存。
- **`nativeEncryptUnits` 只有实现没声明会编译失败**。补 NativeBridge 里的 external 声明即过。
- **FAT32 FSInfo 空闲计数别精确维护，置 unknown 让 OS 重算**。`FSI_Free_Count`/`FSI_Nxt_Free` 置 `0xFFFFFFFF`。`FatFileSystem.invalidateFsInfo()` 在 `MountManager.withWritableFs` 收尾统一调。
- **Read/grep 对含 NUL/非 ASCII 的 .kt 渲染失真会「凭空造代码」**。红线：改写代码前用 `grep -an` 核真身，Edit 匹配失败别硬改，先 grep 确认真实文本。
- **TRAE/沙箱白名单限制桌面写操作**（`Remove-Item`/`Copy-Item` 对桌面文件被拦却回显 DELETED）。结论：只允许项目目录+特定缓存目录写。绕开：APK/交付物先放项目目录内，让用户手动复制到桌面。
- **PROGRESS「其余低危」4 条经核实均非真 bug，别重复排查**：①exFAT `writeFatEntry` 只写 FAT#0（exFAT 单份 FAT 规范）；②`fillDataArea` 默认不调用（用户明确要的设计开关）；③簇号→偏移无上界校验（宽泛加固项）；④VolumeExpander 旧备份头残留（VC 桌面版 ExpandVolume 也不清理）。
- **增量构建偶发不重打包资源**。改 `values-*/strings.xml` 后 `packageDebug` 标 UP-TO-DATE 没重打包。改资源后用 `clean assembleDebug` 强制全量重建。
- **bouncycastle 1.79 与 jspecify 1.0.0 都带 `META-INF/versions/9/OSGI-INF/MANIFEST.MF` 合并冲突**。packaging excludes 补一条。
- **多语言除中文外调不了**：`build.gradle.kts` 的 `localeFilters += listOf("en","zh")` 把其他 14 国资源整体剥离！删掉过滤，16 国语言全打包。

---

## ▍安全审计修复总表（五域全审 2026-07-12 收官）

四域派卡（Kotlin 应用层、native/JNI+熵、FAT/exFAT 写路径、NTFS），NTFS 拆 2a/2b/2c 分阶段。回执落 `多Agent协作.md`。共挖出 3 处★致命 + 5 处高危 + 若干中低危。全程只读审计。修复须走子代理 + 编译 + 字节级论证，写路径改动真机+桌面 VC+chkdsk 回验。

| # | 级别 | 问题 | 文件 | 状态 |
|---|---|---|---|---|
| 1 | ★致命 | FAT 小卷 FAT16/FAT12 误判报废（256KB..8MB 建 FAT16 布局却被判 FAT12，簇链错位） | FatFormatter.kt + Bpb.kt + VolumeCreator.kt | ✅代码+编译 |
| 2 | ★致命 | NTFS removeIndexEntry 漏排序 → 2 层目录索引乱序损坏 | NtfsIndex.kt | ✅代码+编译 |
| 3 | 高危 | NTFS deleteFile 先释放簇后删索引无回滚 → 交叉损坏 | NtfsDataOps.kt | ✅代码+编译 |
| 4 | 高危 | 自动锁定（超时/切后台/息屏）不清明文缓存 | MountManager.kt + MainActivity.kt + MediaViewer.kt | ✅代码+编译 |
| 5 | 高危 | NTFS collation 用 Kotlin ignoreCase 非 COLLATION_FILENAME | NtfsIndex.kt (collationCompare) | ✅代码+编译 |
| 6 | 高危 | exFAT 子目录扩簇不更新流扩展 DataLength/NoFatChain | ExFatFileSystem.kt (fixSubDirStreamExt) | ✅代码+编译 |
| 7 | 中危 | NTFS dirty-last→dirty-first（崩溃兜底失效） | NtfsFileSystem.kt 薄壳所有写方法 | ✅代码+编译 |
| 8 | 中危 | NTFS resident $MFT $BITMAP 静默吞写 → 记录重复分配 | NtfsMftManager.kt (writeMftBitmapByte) | ✅代码+编译 |
| 9 | 中危 | NTFS 贪心分区产生空尾叶 | NtfsIndex.kt (rebuildDirIndex) | ✅代码+编译 |
| 10 | 中危 | NTFS 备份引导扇区缺失（TotalSectors=N 应 N-1，卷尾无 VBR 副本） | NtfsFormatter.kt | ✅代码+编译 |
| 11 | 中危 | native 随机池快照可反推主密钥 | native_lib.cpp + sc_random.c + sc_volume.h + NativeBridge.kt + CreateVolumeScreen.kt | ✅代码+编译 |
| 12 | ★致命 | FAT 创建乱码（元数据区未清零，Android 新文件不保证零填充） | FatFormatter.kt (metadataClearRegions) + VolumeCreator.kt | ✅代码+编译+APK |

### 已核实正确（免重复排查）

- **FAT/exFAT**：双表回写、FAT12 半字节拆位、FAT32 高 4 位保留、簇链先建后拆事务序、LFN 校验和/短名去重/`..` 簇号、exFAT 三套校验和+NameHash+upcase 编解码、read-modify-write 走 VolumeReader.write、clusterToOffset 无 32 位溢出。
- **NTFS**：接线完整无死代码（BrowserScreen→withWritableFs→VolumeFs 多态可达，mount 走 NtfsFileSystem.mount）、H2 记录 0..23 位图置位、H4 indexBufferCode 编解码对称、M1 $MFTMirr 读记录 1、fixup 三函数对称、runlist 编解码对称、三 size 自洽越界回滚、VCN 映射/$BITMAP 一致性/2-3 层边界保守拒绝、索引项 flags 与子节点指针。
- **native/熵池**：create/rekey/expand/hidden 的 cleanup 无 double-free/泄漏、缓冲区无越界、整数无溢出、burn 抹密钥、JNI 引用干净、熵安全闸（未灌种返 FALSE 绝不吐弱随机）、搅拌/前向保密字节级对齐上游、隐藏卷几何对齐 Format.c。
- **Kotlin 应用层**：隐藏卷写保护三重拦截、PasswordChanger 兜底序、KeyfileMixer 回绕、密码 fill(0)、PinManager(Argon2id+EncryptedSharedPreferences+常量时间)、MountManager 并发(synchronized+@Volatile+mountId 防 UAF)。

### 剩余低危（不影响功能，待排期）

- 死代码方法/注释清理（tryInsertRootEntry 等已在拆分时删）、自测判据重言式、entryFileName 空名降级、freeMftRecord 无 recordNo<24 下界、applyUsaFixup 撕裂静默容忍、native 口令副本用 memset（建议 explicit_bzero）、currentLsn 每次 mount 从 0（二期真日志才需改）。

---

## ▍真机验收路径（给恒烈，唯一判据=桌面 VC 字节级互通）

### 环境
- 一加手机（安卓 16）装本轮 APK；电脑桌面 VC 1.26.x（与上游 pin 1.26.29 同代）；Windows 跑 `chkdsk X:`。
- 测试用密码别用真实密码，测试容器建小的（10-50MB）。**写入类测试前先在电脑完整复制一份容器备着。**
- 写入类入口（改密/建隐藏卷/救砖/删改）只在「选中容器 URI 拿到持久写权限」时显示，拿不到不出现（非 bug）。
- 算法编号：AES=1/Serpent=2/Twofish=3/Camellia=4/Kuznyechik=5；PRF：SHA512=1/Whirlpool=2/SHA256=3/BLAKE2s=4/Streebog=5。

### 最小化全功能验收路径（5 容器覆盖全部）

准备 4 个桌面 VC 容器 + 1 个 app 自建：
- 容器①：FAT 30MB，带 keyfile（2 个）+ 隐藏卷 → A1+C1
- 容器②：exFAT 50MB，塞 20MB 大文件 → D2 + 簇泄漏回归 + X5 媒体 + E 自动锁
- 容器③：NTFS 50MB → D3（需先开设置「NTFS 实验」开关）
- 容器④：FAT 30MB 废容器 → A2 救砖 + B1 改密（破坏性）
- app 自建：B2 创建 + D4 回验

无容器功能（最快先测）：X1 动态色 / X2 PIN 门禁 / X4 生物识别 / X3 Panic PIN / 16 国语言（重点看阿拉伯语 RTL）。测完清掉 PIN/Panic PIN。

### 本轮修复重点回验（针对性，FAT/exFAT 基本读写已验过不用重复）

- **测试 1（致命#1 FAT 小卷 FAT12）**：建 2MB FAT 容器→写文件→重挂→桌面 VC 读
- **测试 2（致命#2+高危#5 NTFS 大目录删）**：建 NTFS 容器→subdir 塞 50+ 文件→删 5-10 个→重挂→chkdsk 无 unordered
- **测试 3（高危#3 NTFS 删后写）**：删大文件→写新文件→重挂→chkdsk
- **测试 4（高危#6 exFAT 扩簇）**：exFAT 容器→subdir 塞 130+ 文件→重挂→chkdsk
- **测试 5（高危#4 自动锁清缓存）**：导出文件→等自动锁→查缓存目录空
- **测试 6（中危#10 NTFS 备份引导扇区）**：建 NTFS→挂 Windows→chkdsk 不报备份引导扇区错误

出问题记：哪功能哪步 / 容器桌面建还是手机建+大小+算法+PRF+文件系统 / 桌面 VC 报错原文 / chkdsk 原文 / 写入类保留「救援文件」别删。

---

## ▍编译 & 交付

```bash
# 关闭 Android Studio（否则 APK 被锁）后：
./gradlew.bat assembleDebug     # 产物 app/build/outputs/apk/debug/app-debug.apk
./gradlew.bat assembleRelease   # 产物 app/build/outputs/apk/release/app-release.apk（暂用 debug 签名）
```

- build.gradle.kts release 块暂用 `signingConfig = signingConfigs.getByName("debug")`，发行时换正式 keystore。
- 沙箱限制桌面写 → APK 在项目 build 目录，需手动复制到桌面。
- F-Droid 上架待办：正式签名 + Fastlane Metadata（`fastlane/metadata/android/`）+ reproducible build。

---

## ▍许可

加密核心移植自 VeraCrypt（Apache-2.0 + TrueCrypt License 3.0），保留原始版权声明于 `third_party/`。匿匣为独立产品，不隶属也不冒充 VeraCrypt/TrueCrypt。
