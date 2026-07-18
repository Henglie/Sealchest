<p align="center">
  <img src="assets/logo.svg" width="120" height="120" alt="匿匣 Sealchest logo" />
</p>

<h1 align="center">匿匣 Sealchest</h1>

<p align="center">
  安卓上<b>无 root</b> 加载 VeraCrypt / TrueCrypt 加密容器的工具。证据级隐私，纯用户态，明文不落盘。
</p>

<p align="center">
  <a href="https://github.com/Henglie/Sealchest/stargazers"><img src="https://img.shields.io/github/stars/Henglie/Sealchest?style=flat-square" alt="GitHub stars" /></a>
  <a href="https://github.com/Henglie/Sealchest/network/members"><img src="https://img.shields.io/github/forks/Henglie/Sealchest?style=flat-square" alt="GitHub forks" /></a>
  <a href="https://github.com/Henglie/Sealchest/releases"><img src="https://img.shields.io/github/v/release/Henglie/Sealchest?style=flat-square" alt="GitHub release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Henglie/Sealchest?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="https://github.com/Henglie/Sealchest/issues"><img src="https://img.shields.io/github/issues/Henglie/Sealchest?style=flat-square" alt="GitHub issues" /></a>
  <a href="https://github.com/Henglie/Sealchest/pulls"><img src="https://img.shields.io/github/issues-pr/Henglie/Sealchest?style=flat-square" alt="GitHub pull requests" /></a>
  <img src="https://img.shields.io/badge/Android-6.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white" alt="Android 6.0+" />
</p>

<p align="center">
  <a href="README.en.md">English README</a>
</p>

> [!WARNING]
> 加密工具的信任建立在互通验证之上——请务必在**桌面 VeraCrypt** 中回验匿匣写出的容器，重要数据先备份。如果遇到 Bug、兼容性问题或异常行为，请及时反馈，欢迎提交 Issue，最好附上复现步骤、日志、截图和系统版本。

匿匣是一款安卓应用，让你在**没有 root** 的手机上打开 VeraCrypt / TrueCrypt 加密容器，浏览、读写里面的文件。

---

## ✨ 特色与优势

> 以下每一条都是匿匣区别于同类安卓加密工具的**核心差异化能力**，经实测验证。

### 🚀 无 root · 纯用户态
绝大多数安卓 VeraCrypt 方案要靠 root + 内核驱动（dm-crypt/FUSE）才能挂容器。匿匣**完全不需要**——纯用户态解析卷头、按需解密扇区、自研文件系统读写，任何 Android 6.0+ 设备开箱即用。

### 🔐 全套 VeraCrypt 密码学
**6 种加密算法**（AES / Serpent / Twofish / Camellia / Kuznyechik）+ **5 种级联组合**，**6 种哈希/KDF**（SHA-256 / SHA-512 / Whirlpool / Streebog / BLAKE2s / Argon2id）。密码学实现**直接采用 VeraCrypt 上游 C 源码**，不自写不魔改，保证字节级一致。

### 📁 FAT / exFAT / NTFS 三种文件系统全自研
不依赖任何第三方 FS 库——FAT12/16/32、exFAT、NTFS 读写**全部从零实现**。其中 **NTFS 造盘**按 MS 规范 + ntfs-3g 公开实现自研，是安卓平台上罕见的完整 NTFS 创建能力（含 512B~64KB 全簇大小，通过 Windows chkdsk 校验）。

### 🔄 桌面 VeraCrypt 字节级互通
匿匣写的容器 → 桌面 VeraCrypt 直接打开；桌面 VeraCrypt 写的容器 → 匿匣直接读写。**唯一判据是互通**：加解密、卷头布局、keyfile 混入、文件系统结构全部与桌面 VeraCrypt 字节级对齐。

### 📱 SAF DocumentsProvider 原生暴露
通过安卓 **SAF** 把容器内文件系统暴露给系统文件管理器和任意支持 SAF 的应用——无需导出中转，其它应用可直接读取容器内文件。

### 🛡️ 安全增强一应俱全
Argon2id PIN 门禁、Panic PIN 即时擦除、生物识别解锁、自动锁定（超时/息屏/切后台）、挂载期前台服务保活、明文不落盘（按扇区解密，整个容器不解开到磁盘）。

### 🎨 Material You + 16 国语言
动态取色 + 6 种主题色 + 夜间模式；16 国语言含阿拉伯语 RTL。

### 🆓 完全开源 · 完全免费
**Apache 2.0** 开源协议，代码公开可审计，无付费版、无内购、无广告。

---

## 它怎么做到无 root 的

桌面版 VeraCrypt 靠内核驱动把容器挂成虚拟盘，安卓无 root 做不到。匿匣换一条纯用户态的路：

1. 在 app 内解析卷头——读盐、用 PBKDF2 派生头密钥、解密卷头、取出主密钥，建立 XTS 解密上下文；
2. 容器内部是个普通文件系统，匿匣在用户态自己读写这个文件系统；
3. 通过内置文件浏览器直接浏览 / 预览 / 导出，并额外通过安卓 **SAF（Storage Access Framework）DocumentsProvider** 把文件系统暴露给系统文件管理器和其它应用。

扇区按需解密——读哪个扇区才解哪个，整个容器不落地、不解开到磁盘。这是无 root 方案的核心。

## 守本心

匿匣是严格的 VeraCrypt 容器安卓解析器。加解密与卷格式行为必须与桌面 VeraCrypt **字节级一致**，唯一判据是**互通**：匿匣写的容器桌面 VeraCrypt 能开、桌面 VeraCrypt 写的匿匣能读。密码学实现只采用上游 VeraCrypt 的 C 源码，不自写不魔改；仅卷格式规范（keyfile 混入、卷头布局、文件系统结构）允许 Kotlin 复刻，且注释标明上游出处。

## 当前能力

- **打开容器**：读 + 写（新建 / 改写 / 删除文件，改动加密写回容器，桌面 VeraCrypt 可正常打开）
- **内层文件系统**：FAT12 / FAT16 / FAT32 · exFAT · NTFS（全部自研读写，无第三方 FS 库）
- **加密算法**：AES、Serpent、Twofish、Camellia、Kuznyechik 及其级联组合（全套编入）
- **哈希 / KDF**：SHA-256、SHA-512、Whirlpool、Streebog、BLAKE2s、Argon2id
- **卷操作**：创建新容器（熵采集 + 手指涂抹 + 随机池可视化）、改密码 / PIM / PRF / keyfile、隐藏卷解锁与创建、卷头备份恢复（救砖）、卷扩展
- **keyfile 解锁**：字节级复刻 VeraCrypt KeyFilesApply
- **内置文件浏览器**：目录导航、图片 / 文本预览、加密相册与媒体播放、导出到手机、用其它应用打开
- **SAF 暴露**：任意支持 SAF 的应用可读取容器内文件
- **安全增强**：Argon2id PIN 门禁、Panic PIN 即时擦除、生物识别解锁、自动锁定（超时 / 息屏 / 切后台）、挂载期前台服务保活
- **界面**：Material You 动态取色 + 可选主题色 + 夜间模式；**16 国语言**（中英法德西日韩俄意葡荷阿拉伯印地土波越，含阿拉伯语 RTL）

---

## 📋 同类产品对比

> 基于公开信息与实测。为客观起见，竞品不具名，以「产品 A」「产品 B」代称。
>
> - **产品 A**：某商业加密容器应用（付费，闭源，支持多种加密格式）
> - **产品 B**：某开源 VeraCrypt 安卓端口（需 root）

| 能力维度 | 匿匣 Sealchest | 产品 A | 产品 B |
|:---|:---:|:---:|:---:|
| **无需 root** | ✅ 完全纯用户态 | ⚠️ 部分场景需 root | ❌ 依赖 root |
| **VeraCrypt 容器读写** | ✅ 完整读写 | ✅ | ⚠️ 有限/只读 |
| **NTFS 读写（自研）** | ✅ 含造盘 + 全簇大小 | ❌ 依赖第三方库 | ❌ |
| **exFAT 读写（自研）** | ✅ | ⚠️ | ❌ |
| **FAT12/16/32 读写** | ✅ 自研 | ✅ | ✅ |
| **桌面 VeraCrypt 字节级互通** | ✅ 已验证 | ✅ | ⚠️ 部分 |
| **6 种加密算法 + 5 种级联** | ✅ 全套 | ✅ | ⚠️ 部分 |
| **6 种哈希/KDF（含 Argon2id）** | ✅ 全套 | ✅ | ⚠️ 部分 |
| **隐藏卷** | ✅ 解锁 + 创建 | ✅ | ❌ |
| **Keyfile** | ✅ 字节级复刻 | ✅ | ⚠️ |
| **SAF DocumentsProvider** | ✅ 原生暴露 | ⚠️ 有限 | ❌ |
| **明文不落盘** | ✅ 按扇区解密 | ✅ | ✅ |
| **Argon2id PIN 门禁** | ✅ | ❌ | ❌ |
| **Panic PIN 即时擦除** | ✅ | ⚠️ | ❌ |
| **生物识别解锁** | ✅ | ⚠️ | ❌ |
| **自动锁定（超时/息屏/后台）** | ✅ | ✅ | ❌ |
| **Material You 动态取色** | ✅ | ❌ | ❌ |
| **多语言** | 16 国 | 有限 | 有限 |
| **开源协议** | ✅ Apache 2.0 | ❌ 闭源 | ✅ |
| **价格** | 免费 | 付费 / Lite 版 | 免费 |

> **小结**：匿匣在「无 root + 全自研文件系统 + 桌面字节级互通 + 完全开源免费」四项上具有明确的差异化优势。产品 A 功能面广但闭源付费；产品 B 开源但依赖 root、能力有限。

---

## 兼容性

- 最低 Android 6.0（API 23），覆盖 2015 年至今的设备
- ABI：arm64-v8a、armeabi-v7a、x86_64（模拟器）

## 不做（安卓形态边界）

- 隐藏操作系统 / 系统盘预引导认证：安卓引导链与桌面根本不同，排除。
- 内核级挂载（dm-crypt / FUSE 内核模块）：纯 app 层做不到。

## 许可

匿匣自身代码采用 **Apache License 2.0**，全文见根目录 [`LICENSE`](LICENSE)。

加解密核心移植自开源的 [VeraCrypt](https://www.veracrypt.fr/)（`src/Crypto`、`src/Volume`、`src/Common` 的纯 C 实现），该部分遵循 VeraCrypt 原有双许可：

- **Apache License 2.0**（AM Crypto 修改部分）
- **TrueCrypt License 3.0**（继承自 TrueCrypt 7.1a 部分）

匿匣是独立产品，不隶属于、也不冒充 VeraCrypt 或 TrueCrypt 项目。所有原始版权声明保留于 `third_party/VeraCrypt`。

## 作者

恒烈 / EternalBlaze

项目地址：<https://github.com/Henglie/Sealchest>

---

<sub>关键词 / Keywords：VeraCrypt Android · TrueCrypt Android · 安卓 VeraCrypt · 无 root 挂载 · no-root mount · 加密容器 · encrypted container · XTS · 隐藏卷 hidden volume · keyfile · exFAT NTFS FAT · SAF DocumentsProvider · 明文不落盘 · on-the-fly decryption · 隐私加密 · privacy · Kuznyechik Serpent Twofish Camellia · Argon2id · 移动加密盘 · mobile crypto volume</sub>
