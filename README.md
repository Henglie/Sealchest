# 匿匣 Sealchest

> 安卓上无 root 加载 VeraCrypt 加密容器的工具。证据级隐私，纯用户态。
> [English README](README.en.md)

匿匣是一款安卓应用，让你在**没有 root** 的手机上打开 VeraCrypt / TrueCrypt 加密容器，浏览、读写里面的文件。

## 它怎么做到无 root 的

桌面版 VeraCrypt 靠内核驱动把容器挂成虚拟盘，安卓无 root 做不到。匿匣换一条纯用户态的路：

1. 在 app 内解析卷头——读盐、用 PBKDF2 派生头密钥、解密卷头、取出主密钥，建立 XTS 解密上下文；
2. 容器内部是个普通文件系统，匿匣在用户态自己读写这个文件系统；
3. 通过内置文件浏览器直接浏览 / 预览 / 导出，并额外通过安卓 **SAF（Storage Access Framework）DocumentsProvider** 把文件系统暴露给系统文件管理器和其它应用。

扇区按需解密——读哪个扇区才解哪个，整个容器不落地、不解开到磁盘。这是无 root 方案的核心。

## 当前能力

- 打开容器：读 + 写（新建 / 改写 / 删除文件，改动加密写回容器，桌面 VeraCrypt 可正常打开）
- 内层文件系统：FAT12 / FAT16 / FAT32（exFAT、NTFS 在路线图上）
- 加密算法：AES、Serpent、Twofish、Camellia、Kuznyechik 及其级联组合（全套编入）
- 哈希 / KDF：SHA-256、SHA-512、Whirlpool、Streebog、BLAKE2s、Argon2id
- 内置文件浏览器：目录导航、图片 / 文本预览、导出到手机、用其它应用打开
- 通过 SAF 暴露给系统，任意支持 SAF 的应用可读取容器内文件
- 界面中英双语，跟随系统语言（系统为中文用中文，其余用英文）

## 兼容性

- 最低 Android 6.0（API 23），覆盖 2015 年至今的设备
- ABI：arm64-v8a、armeabi-v7a、x86_64（模拟器）

## 加密核心来源与许可

匿匣的加解密核心移植自开源的 [VeraCrypt](https://www.veracrypt.fr/)（`src/Crypto`、`src/Volume`、`src/Common` 的纯 C 实现），遵循其双许可：

- **Apache License 2.0**（AM Crypto 修改部分）
- **TrueCrypt License 3.0**（继承自 TrueCrypt 7.1a 部分）

匿匣是独立产品，不隶属于、也不冒充 VeraCrypt 或 TrueCrypt 项目。所有原始版权声明保留于 `third_party/VeraCrypt`。

## 作者

恒烈 / EternalBlaze

项目地址：https://github.com/Henglie/Sealchest
