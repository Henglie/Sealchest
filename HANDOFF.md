# 密匣 Sealchest · 接手交接

> 给下一个接手的 AI / 开发者。**先读根目录 `开发规范.md` + 本项目 `PROGRESS.md` 的「技术栈红线」「踩坑记录」两节**，再读本文。
> 本文只讲「现在到哪了、下一步干什么、有哪些活雷区」，细节以 PROGRESS 为准。

---

## ▍一句话现状

安卓无 root 打开 VeraCrypt 容器。**只读全链路已闭环并真机验收通过**（解锁 → 内置浏览器浏览 / 预览 / 导出）。
双向加解密的 **native + JNI + VolumeReader 写方法已打通并编译通过**，但**写入互通整条链还没接完、一次都没测过**。

当前 HEAD：`a1f3e9c 打通双向加解密链路`。

---

## ▍已完成（可信，构建验证过）

- VeraCrypt C 核心移植（全算法 + 6 PRF），三 ABI 编入 `libsealchest.so`。
- 开卷 / 解扇区**真容器实测通过**（官方 test.*.hc 三 PRF）。
- FAT12/16/32 只读解析（`fs/FatFileSystem.kt` + `Bpb.kt`）。
- SAF DocumentsProvider（`saf/`）+ 内置文件浏览器（`browse/`）。
- Compose UI 全流程（`MainActivity.kt`）。
- **双向加解密链路**：`sc_volume_encrypt_units`（C）→ `nativeEncryptUnits`（JNI）→
  `NativeBridge.Volume.encryptUnits` → `VolumeReader.write*`。**已编译，未运行验证**。

真机验收：只读 OK。写入：**从未运行**。

---

## ▍下一步（写入互通，按风险从低到高）

**目标**：手机往容器里加 / 改 / 删文件后，VeraCrypt 桌面端仍能正常打开——这才叫「互通」，只读只是「兼容读」。

1. **先验加解密对称性**（零风险，已备好工具没跑）：
   - `sc_test.c` 已加往返自测（解密→重加密→比对复现原始密文）。
   - 交叉编 + 推模拟器跑：见 PROGRESS「验证宿主」段（`-DSC_BUILD_TEST=ON`，
     `x86_64-linux-android`，`adb push` 前置 `MSYS_NO_PATHCONV=1`）。
   - **没过就别往下做**，说明 encrypt 方向有问题。

2. **原地覆盖写**（低风险）：只改已有文件内容、大小不变，**不动 FAT 表 / 目录项**。
   - `MountManager.unlock` 现在用 `"r"` 打开 PFD，写要改 `"rw"`（SAF URI 需可写权限，
     选文件时 `takePersistableUriPermission` 要带 `FLAG_GRANT_WRITE`）。
   - 写完立刻用桌面 VeraCrypt 打开验证没损坏。

3. **完整 FAT 写入**（高风险）：簇分配、FAT 表更新（两份 FAT 都要写）、目录项增删、
   VFAT 长名生成、目录扩簇。任一处写错整个容器可能报废——**每步都要桌面 VC 回验**。

---

## ▍活雷区（会咬人）

- **XTS 单元号 = 文件绝对偏移 / 512，不是数据区相对**。血泪坑，已封在 `VolumeReader`，
  写方向同一套映射别再推断。见 PROGRESS 踩坑。
- **FAT 表有两份副本**（numFats 通常 2），写必须两份都更新，否则 chkdsk / VC 报错。
- **改文件必须走 read-modify-write**：XTS 以 512B 单元为粒度，不能只写半个单元。
  `VolumeReader.write` 已处理，别绕过它直接碰 channel。
- **本机构建坑**（每次都会踩）：
  - cwd 每次 bash 调用重置到桌面，**用绝对路径**。
  - 构建判真伪：**写日志文件再读，别信内联 echo**（EXIT 码会骗人）。
  - 增量编译偶发缓存假报错，改完 external 声明后 clean 重建再判。
  - `gradlew.bat assembleDebug`，JBR 21 已钉死在 gradle.properties。
- **文件编辑失真**：本会话多次出现 Edit 锚点对不上 / 读取渲染失真。
  改完关键文件后用 `grep -n` 精确核对真实落地内容，别信单次 Read。

---

## ▍收尾铁律（违反即返工）

- 提交用 `Henglie <ebhenglie@gmail.com>`，中文信息，**绝无任何 AI 痕迹**（无 Co-Authored-By）。
- 删文件送回收站，不硬删。
- 干完只更新 `PROGRESS.md` 状态行 + 踩坑记录（结论+为什么+怎么绕开三句），不写流水账。
- 桌面已放 `密匣Sealchest-v0.2-debug.apk`，是只读版验收包。
